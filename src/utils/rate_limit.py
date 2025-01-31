import asyncio
import time
from typing import Optional

class RateLimiter:
    def __init__(self, requests_per_second: int = 10, burst: int = 20):
        self.rate = requests_per_second
        self.burst = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire a token for rate limiting"""
        async with self.lock:
            while self.tokens <= 0:
                now = time.monotonic()
                time_passed = now - self.last_update
                self.tokens = min(
                    self.burst,
                    self.tokens + time_passed * self.rate
                )
                self.last_update = now
                if self.tokens <= 0:
                    await asyncio.sleep(1.0 / self.rate)
            
            self.tokens -= 1
    
    async def wait(self):
        """Wait for rate limit"""
        await self.acquire()