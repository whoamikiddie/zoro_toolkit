# src/utils/rate_limit.py
import time
from threading import Lock

class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.rate = requests_per_second
        self.last_check = time.time()
        self.allowance = requests_per_second
        self._lock = Lock()

    def wait(self):
        """Token bucket algorithm for rate limiting"""
        with self._lock:
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current
            self.allowance += time_passed * self.rate

            if self.allowance > self.rate:
                self.allowance = self.rate

            if self.allowance < 1.0:
                time.sleep((1.0 - self.allowance) / self.rate)
                self.allowance = 0.0
            else:
                self.allowance -= 1.0