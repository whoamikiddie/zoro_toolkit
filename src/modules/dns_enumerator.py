import asyncio
import dns.resolver
from typing import Dict, List, Any
from datetime import datetime
import socket

class DNSEnumerator:
    def __init__(self, resolvers: List[str], record_types: List[str]):
        self.resolvers = resolvers
        self.record_types = record_types
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [socket.gethostbyname(r) for r in resolvers]

    async def enumerate(self, domain: str) -> Dict[str, Any]:
        """Perform DNS enumeration for all specified record types"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "records": {}
        }

        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results["records"][record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results["records"][record_type] = []
            except dns.resolver.NXDOMAIN:
                results["records"][record_type] = ["NXDOMAIN"]
            except Exception as e:
                results["records"][record_type] = [f"Error: {str(e)}"]

        return results