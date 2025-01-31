import asyncio
import aiohttp
from typing import List, Dict, Any
from datetime import datetime

class CertificateScanner:
    def __init__(self, sources: List[str], concurrent_queries: int = 5):
        self.sources = sources # -->  fetch certificate data
        self.concurrent_queries = concurrent_queries
        self.session = None # -->  aiohttp session to make a request

    async def scan(self, domain: str) -> Dict[str, Any]:
        """Scan certificate transparency logs for the domain"""
        results = {
            "timestamp": datetime.now().isoformat(), # -->  timestamp
            "domain": domain, # -->  domain being scanned
            "certificates": [] # -->  list of certificates found
        }

        # --> Creating a new aiohttp session
        async with aiohttp.ClientSession() as self.session:
            tasks = []
            for source in self.sources:
                if source == "crt.sh":
                    tasks.append(self._scan_crtsh(domain)) # --> add task for crt.sh 
                elif source == "censys":
                    tasks.append(self._scan_censys(domain)) # --> add task for censys
                elif source == "certspotter":
                    tasks.append(self._scan_certspotter(domain)) # --> add task for certspotter

            cert_results = await asyncio.gather(*tasks)
            for result in cert_results:
                results["certificates"].extend(result)

        return results

    async def _scan_crtsh(self, domain: str) -> List[Dict[str, Any]]:
        """Scan crt.sh for certificates"""
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            # --> perform the http request to crt.sh 
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return [{
                        "source": "crt.sh",
                        "common_name": cert.get("common_name"),
                        "name_value": cert.get("name_value"),
                        "issuer_name": cert.get("issuer_name"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after")
                    } for cert in data]
        except Exception as e:
            return [{"source": "crt.sh", "error": str(e)}]
        return []

    async def _scan_censys(self, domain: str) -> List[Dict[str, Any]]:
        """Scan Censys for certificates"""
        # Implementation for Censys API
        return []

    async def _scan_certspotter(self, domain: str) -> List[Dict[str, Any]]:
        """Scan CertSpotter for certificates"""
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names"
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return [{
                        "source": "certspotter",
                        "dns_names": cert.get("dns_names", []),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after")
                    } for cert in data]
        except Exception as e:
            return [{"source": "certspotter", "error": str(e)}]
        return []