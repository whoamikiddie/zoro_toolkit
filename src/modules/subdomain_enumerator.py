import asyncio
import dns.resolver
import socket
from typing import List, Dict, Any, Set
from datetime import datetime
import aiohttp
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class SubdomainEnumerator:
    def __init__(self, target: str, rate_limiter, concurrent_tasks: int = 50):
        self.target = target
        self.rate_limiter = rate_limiter
        self.concurrent_tasks = concurrent_tasks
        self.subdomains: Set[str] = set()
        self.session = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    async def enumerate(self) -> Dict[str, Any]:
        """Main enumeration method combining all techniques"""
        self.session = aiohttp.ClientSession()
        try:
            tasks = [
                self._dns_enumeration(),
                self._certificate_search(),
                self._search_engine_discovery(),
                self._wayback_machine_search(),
                self._github_dorks(),
                self._bruteforce_enumeration(),
                self._permutation_scan(),
                self._recursive_dns_search(),
                self._web_archive_search(),
                self._rapid_dns_search()
            ]
            
            await asyncio.gather(*tasks)
            
            # Validate all discovered subdomains
            valid_subdomains = await self._validate_subdomains()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "target": self.target,
                "total_discovered": len(self.subdomains),
                "valid_subdomains": len(valid_subdomains),
                "subdomains": list(valid_subdomains),
                "techniques_used": [
                    "DNS Enumeration",
                    "Certificate Search",
                    "Search Engine Discovery",
                    "Wayback Machine",
                    "GitHub Dorks",
                    "Bruteforce",
                    "Permutation Scanning",
                    "Recursive DNS",
                    "Web Archive",
                    "RapidDNS"
                ]
            }
        finally:
            await self.session.close()

    async def _dns_enumeration(self):
        """Advanced DNS enumeration with multiple record types"""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.target, record_type)
                for rdata in answers:
                    if record_type in ['NS', 'MX', 'CNAME']:
                        subdomain = str(rdata.target).rstrip('.')
                        if self.target in subdomain:
                            self.subdomains.add(subdomain)
            except Exception:
                continue

    async def _certificate_search(self):
        """Search certificate transparency logs"""
        sources = [
            f"https://crt.sh/?q=%.{self.target}&output=json",
            f"https://certspotter.com/api/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names"
        ]
        
        for url in sources:
            try:
                await self.rate_limiter.wait()
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "crt.sh" in url:
                            for cert in data:
                                self._extract_domains(cert.get('name_value', ''))
                        else:
                            for cert in data:
                                self._extract_domains(','.join(cert.get('dns_names', [])))
            except Exception:
                continue

    async def _search_engine_discovery(self):
        """Use various search engines to discover subdomains"""
        dorks = [
            f"site:*.{self.target}",
            f"site:*.*.{self.target}",
            f"-site:www.{self.target} site:*.{self.target}"
        ]
        
        engines = {
            "google": "https://www.google.com/search?q={}&num=100",
            "bing": "https://www.bing.com/search?q={}&count=50",
            "yahoo": "https://search.yahoo.com/search?p={}&n=100"
        }
        
        for engine, url in engines.items():
            for dork in dorks:
                try:
                    await self.rate_limiter.wait()
                    async with self.session.get(url.format(dork)) as response:
                        if response.status == 200:
                            text = await response.text()
                            self._extract_domains(text)
                except Exception:
                    continue

    async def _wayback_machine_search(self):
        """Search Internet Archive's Wayback Machine"""
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original&collapse=urlkey"
        try:
            await self.rate_limiter.wait()
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data[1:]:  # Skip header row
                        self._extract_domains(entry[0])
        except Exception:
            pass

    async def _github_dorks(self):
        """Search GitHub for exposed subdomains"""
        dorks = [
            f"domain:{self.target}",
            f"site:{self.target}",
            f"*.{self.target}"
        ]
        
        for dork in dorks:
            url = f"https://api.github.com/search/code?q={dork}"
            try:
                await self.rate_limiter.wait()
                headers = {"Accept": "application/vnd.github.v3+json"}
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get('items', []):
                            self._extract_domains(str(item))
            except Exception:
                continue

    def _extract_domains(self, text: str):
        """Extract valid subdomains from text"""
        pattern = f"[a-zA-Z0-9_-]+\.{self.target}"
        for match in re.finditer(pattern, text):
            subdomain = match.group(0)
            if self._is_valid_subdomain(subdomain):
                self.subdomains.add(subdomain)

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain or '..' in subdomain:
            return False
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return all(re.match(pattern, label) for label in subdomain.split('.'))

    async def _validate_subdomains(self) -> Set[str]:
        """Validate discovered subdomains"""
        valid_subdomains = set()
        tasks = []
        
        async def validate(subdomain: str):
            try:
                await self.rate_limiter.wait()
                ip = await self._resolve_domain(subdomain)
                if ip:
                    valid_subdomains.add(subdomain)
            except Exception:
                pass

        for subdomain in self.subdomains:
            tasks.append(validate(subdomain))

        await asyncio.gather(*tasks)
        return valid_subdomains

    async def _resolve_domain(self, domain: str) -> str:
        """Resolve domain to IP address"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return str(answers[0])
        except Exception:
            return ''