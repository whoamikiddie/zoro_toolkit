import asyncio
import socket
from typing import Dict, List, Set

from ..utils.rate_limit import RateLimiter

class PortScanner:
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
    
    async def scan_multiple(self, targets: List[str]) -> Dict[str, Dict[int, str]]:
        """Scan multiple targets concurrently"""
        results = {}
        tasks = [self.scan_target(target) for target in targets]
        scan_results = await asyncio.gather(*tasks)
        
        for target, ports in zip(targets, scan_results):
            results[target] = ports
        
        return results
    
    async def scan_target(self, target: str) -> Dict[int, str]:
        """Scan a single target for open ports"""
        results = {}
        
        async def scan_port(port: int):
            try:
                await self.rate_limiter.wait()
                
                # Create socket with timeout
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Connect to the port
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self._identify_service(sock)
                    results[port] = service
                
                sock.close()
                
            except (socket.gaierror, socket.error):
                pass
        
        # Scan ports concurrently
        tasks = [scan_port(port) for port in self.common_ports]
        await asyncio.gather(*tasks)
        
        return dict(sorted(results.items()))
    
    def _identify_service(self, sock: socket.socket) -> str:
        """Attempt to identify the service running on the port"""
        try:
            service = socket.getservbyport(sock.getpeername()[1])
            return service
        except (socket.error, OSError):
            return "unknown"