import asyncio
import socket
import whois
from datetime import datetime
from typing import Dict, Any

class WhoisScanner:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def scan(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for the domain"""
        try:
            w = whois.whois(domain)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": self._format_date(w.creation_date),
                "expiration_date": self._format_date(w.expiration_date),
                "updated_date": self._format_date(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "name": w.name,
                "org": w.org,
                "address": w.address,
                "city": w.city,
                "state": w.state,
                "zipcode": w.zipcode,
                "country": w.country
            }
        except Exception as e:
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def _format_date(self, date) -> str:
        """Format date objects to ISO format string"""
        if isinstance(date, list):
            date = date[0]
        if date:
            return date.isoformat()
        return None