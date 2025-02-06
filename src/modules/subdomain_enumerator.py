import subprocess
import socket
from typing import List, Dict, Optional
import os
import httpx
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time

class SubdomainEnumerator:
    def __init__(self, domain: str, use_tools: bool = True, save_to_files: bool = True):
        self.domain = domain
        self.use_tools = use_tools
        self.save_to_files = save_to_files
        self.reports_dir = 'reports'
        self.http_timeout = 10  # Seconds
        self.batch_size = 100   # Initial batch size, will adjust dynamically
        self.max_connections = 50  # Max concurrent HTTP connections
        self.retries = 2        # Number of HTTP retries
        self.rate_limit_delay = 0.1  # Delay between batches to avoid rate limiting

        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def _run_subfinder(self) -> List[str]:
        """Run subfinder tool to discover subdomains."""
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent'], 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            return result.stdout.decode().splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error running subfinder: {e}")
            return []

    def _run_assetfinder(self) -> List[str]:
        """Run assetfinder tool to discover subdomains."""
        try:
            result = subprocess.run(
                ['assetfinder', '-subs-only', self.domain], 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            return result.stdout.decode().splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error running assetfinder: {e}")
            return []

    async def _check_http_status(self, subdomain: str, client: httpx.AsyncClient) -> bool:
        """Check if subdomain is alive with retries."""
        url = f"http://{subdomain}"
        for attempt in range(self.retries + 1):
            try:
                response = await client.get(url, follow_redirects=True, timeout=self.http_timeout)
                if response.status_code < 400:
                    return True
            except (httpx.RequestError, httpx.TooManyRedirects, httpx.TimeoutException):
                if attempt == self.retries:
                    return False
                await asyncio.sleep(1)
        return False

    async def check_alive_subdomains(self, subdomains: List[str]) -> List[str]:
        """Check subdomains in concurrent batches with connection pooling."""
        alive_subdomains = []
        limits = httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_connections
        )

        async with httpx.AsyncClient(
            limits=limits,
            timeout=self.http_timeout,
            verify=False  # Warning: Disables SSL verification - use with caution
        ) as client:
            for i in range(0, len(subdomains), self.batch_size):
                batch = subdomains[i:i + self.batch_size]
                tasks = [self._check_http_status(sd, client) for sd in batch]
                results = await asyncio.gather(*tasks)
                
                alive_batch = [sd for sd, alive in zip(batch, results) if alive]
                alive_subdomains.extend(alive_batch)
                print(f"Checked {i + len(batch)}/{len(subdomains)} | Alive: {len(alive_batch)}")

                # Adjust batch size dynamically based on response times
                if len(alive_batch) / len(batch) < 0.1:  # If less than 10% are alive, reduce batch size
                    self.batch_size = max(50, self.batch_size // 2)
                elif len(alive_batch) / len(batch) > 0.9:  # If more than 90% are alive, increase batch size
                    self.batch_size = min(200, self.batch_size * 2)

                await asyncio.sleep(self.rate_limit_delay)  # Respect rate limits

        print(f"Total alive subdomains: {len(alive_subdomains)}")
        return alive_subdomains

    def _resolve_dns(self, subdomain: str) -> Optional[Dict]:
        """Resolve DNS records for a subdomain."""
        try:
            ipv4 = socket.gethostbyname(subdomain)
            return {'subdomain': subdomain, 'ipv4': ipv4}
        except socket.gaierror:
            return None

    async def resolve_subdomains(self, subdomains: List[str]) -> List[Dict]:
        """Resolve DNS for all subdomains using thread pool."""
        with ThreadPoolExecutor(max_workers=50) as executor:
            loop = asyncio.get_event_loop()
            futures = [
                loop.run_in_executor(executor, self._resolve_dns, sd)
                for sd in subdomains
            ]
            results = await asyncio.gather(*futures)
            return [res for res in results if res]

    def _save_subdomains_to_file(self, subdomains: List[str], filename: str):
        """Save subdomains to a text file."""
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, 'w') as f:
            f.write('\n'.join(subdomains))
        print(f"Saved {len(subdomains)} subdomains to {filepath}")

    def _combine_subdomains(self) -> List[str]:
        """Combine and deduplicate subdomains from different sources."""
        combined = set()
        for file in ['subfinder.txt', 'assetfinder.txt']:
            path = os.path.join(self.reports_dir, file)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    combined.update(f.read().splitlines())
        return sorted(combined)

    async def enumerate(self) -> Dict:
        """Main enumeration workflow with progress tracking."""
        start_time = time.time()
        
        # Run enumeration tools
        if self.use_tools:
            print("Starting subdomain discovery...")
            subfinder_results = await asyncio.to_thread(self._run_subfinder)
            assetfinder_results = await asyncio.to_thread(self._run_assetfinder)
            
            if self.save_to_files:
                self._save_subdomains_to_file(subfinder_results, "subfinder.txt")
                self._save_subdomains_to_file(assetfinder_results, "assetfinder.txt")

        # Combine and check subdomains
        print("\nCombining results...")
        combined = self._combine_subdomains()
        print(f"Total unique subdomains found: {len(combined)}")

        print("\nChecking alive subdomains...")
        alive = await self.check_alive_subdomains(combined)

        print("\nResolving DNS records...")
        resolved = await self.resolve_subdomains(alive)

        # Save final results
        results = {
            'alive_subdomains': alive,
            'resolved_subdomains': resolved,
            'stats': {
                'total_subdomains': len(combined),
                'alive_count': len(alive),
                'scan_duration': round(time.time() - start_time, 2)
            }
        }

        if self.save_to_files:
            json_path = os.path.join(self.reports_dir, 'results.json')
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2)
            self._save_subdomains_to_file(alive, 'alive.txt')
            print(f"\nFull results saved to {json_path}")

        return results
