import concurrent.futures
import socket
from typing import List, Dict
from ..utils.logger import Logger

class SubdomainEnumerator:
    def __init__(self, wordlist: List[str] = None):
        self.logger = Logger()
        self.wordlist = wordlist or self._get_default_wordlist()

    def _get_default_wordlist(self) -> List[str]:
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
            "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
            "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
            "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists"
        ]

    def check_subdomain(self, subdomain: str, domain: str) -> Dict:
        full_domain = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return {
                "subdomain": full_domain,
                "ip": ip,
                "status": "active"
            }
        except socket.gaierror:
            return None

    def enumerate(self, domain: str) -> List[Dict]:
        valid_subdomains = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, subdomain, domain): subdomain 
                for subdomain in self.wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    valid_subdomains.append(result)
                    self.logger.info(f"Found subdomain: {result['subdomain']} ({result['ip']})")

        return valid_subdomains