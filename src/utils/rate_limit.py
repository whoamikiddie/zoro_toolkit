import time
import asyncio
from threading import Lock
from typing import Optional
from .exceptions import RateLimitExceededError

class RateLimiter:
    
    def __init__(self, requests_per_second: int = 10, burst_size: int = 20):
        self.rate = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.monotonic()
        self._lock = Lock()
        self._last_warning = 0
        
    def _update_tokens(self) -> None:
        """Update token bucket."""
        now = time.monotonic()
        time_passed = now - self.last_update
        self.tokens = min(
            self.burst_size,
            self.tokens + time_passed * self.rate
        )
        self.last_update = now
        
    def wait(self, tokens: int = 1) -> None:

        with self._lock:
            self._update_tokens()
            
            if self.tokens < tokens:
                # Calculate wait time
                wait_time = (tokens - self.tokens) / self.rate
                now = time.monotonic()
                
                # Warn if waiting too long
                if now - self._last_warning > 5.0 and wait_time > 1.0:
                    self._last_warning = now
                    print(f"Rate limit reached, waiting {wait_time:.2f}s")
                
                time.sleep(wait_time)
                self._update_tokens()
            
            self.tokens -= tokens
            
    async def async_wait(self, tokens: int = 1) -> None:

        with self._lock:
            self._update_tokens()
            
            if self.tokens < tokens:
                wait_time = (tokens - self.tokens) / self.rate
                now = time.monotonic()
                
                if now - self._last_warning > 5.0 and wait_time > 1.0:
                    self._last_warning = now
                    print(f"Rate limit reached, waiting {wait_time:.2f}s")
                
                await asyncio.sleep(wait_time)
                self._update_tokens()
            
            self.tokens -= tokens