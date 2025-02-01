import socket
from typing import List, Dict
from ..utils.logger import Logger

class DNSEnumerator:
    def __init__(self):
        self.logger = Logger()

    def resolve_domain(self, domain: str) -> Dict:
        try:
            ip = socket.gethostbyname(domain)
            return {
                "domain": domain,
                "ip": ip,
                "status": "success"
            }
        except socket.gaierror as e:
            self.logger.error(f"DNS resolution failed for {domain}: {str(e)}")
            return {
                "domain": domain,
                "ip": None,
                "status": "failed",
                "error": str(e)
            }

    def get_dns_info(self, domain: str) -> Dict:
        try:
            records = {}
            # A Record
            records["a"] = socket.gethostbyname_ex(domain)
            # Try to get MX records if possible
            try:
                import dns.resolver
                mx = dns.resolver.resolve(domain, 'MX')
                records["mx"] = [str(x.exchange) for x in mx]
            except:
                records["mx"] = []
                
            return {
                "domain": domain,
                "records": records,
                "status": "success"
            }
        except Exception as e:
            self.logger.error(f"Error getting DNS info for {domain}: {str(e)}")
            return {
                "domain": domain,
                "records": {},
                "status": "failed",
                "error": str(e)
            }