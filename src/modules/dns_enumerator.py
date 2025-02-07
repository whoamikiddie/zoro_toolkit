# src/modules/dns_enumerator.py
import socket
from typing import Dict, List, Optional
import dns.resolver # type: ignore
from ..utils.logger import Logger

class DNSEnumerator:
    def __init__(self):
        self.logger = Logger()

    def resolve_domain(self, domain: str) -> Dict:
        """
        Resolves the given domain to its corresponding IP address.

        :param domain: The domain name to resolve.
        :return: A dictionary containing the domain, IP, status, and error (if any).
        """
        try:
            ip_address = socket.gethostbyname(domain)
            return {
                "domain": domain,
                "ip": ip_address,
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

    def get_mx_records(self, domain: str) -> List[str]:
        """
        Retrieves the MX records for the given domain.

        :param domain: The domain name to query for MX records.
        :return: A list of MX records.
        """
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(record.exchange) for record in mx_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.warning(f"Failed to retrieve MX records for {domain}: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error retrieving MX records for {domain}: {str(e)}")
            return []

    def get_dns_info(self, domain: str) -> Dict:
        """
        Retrieves DNS information for the given domain, including A and MX records.

        :param domain: The domain name to query for DNS information.
        :return: A dictionary containing the domain, DNS records, status, and error (if any).
        """
        try:
            dns_records = {}

            # A Record
            try:
                a_records = socket.gethostbyname_ex(domain)
                dns_records["a"] = a_records
            except socket.gaierror as e:
                self.logger.error(f"Failed to retrieve A records for {domain}: {str(e)}")
                dns_records["a"] = []

            # MX Records
            dns_records["mx"] = self.get_mx_records(domain)

            return {
                "domain": domain,
                "records": dns_records,
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