# src/core/engine.py
import asyncio
import threading
from queue import Queue
from typing import List, Callable, Any, Dict, Optional, Union
from concurrent.futures import ThreadPoolExecutor
from ..utils.logger import Logger
from ..utils.rate_limit import RateLimiter
from ..utils.exceptions import TaskExecutionError

class Engine:
    """
    Advanced task execution engine with support for both threaded and async execution.
    """
    def __init__(self, thread_count: int = 10, timeout: int = 30):
        self.thread_count = thread_count
        self.timeout = timeout
        self.queue: Queue = Queue()
        self.results: List[Dict] = []
        self.logger = Logger()
        self.rate_limiter = RateLimiter()
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=thread_count)
        self._stop_event = threading.Event()

    async def execute_async(self, task: Callable, *args, **kwargs) -> Optional[Dict]:
        """Execute a task asynchronously with timeout and error handling."""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    self._executor,
                    lambda: task(*args, **kwargs)
                ),
                timeout=self.timeout
            )
            return result
        except asyncio.TimeoutError:
            self.logger.error(f"Task timed out after {self.timeout} seconds")
            return {"status": "timeout", "error": f"Task timed out after {self.timeout} seconds"}
        except Exception as e:
            self.logger.error(f"Task execution failed: {str(e)}")
            return {"status": "error", "error": str(e)}

    def add_task(self, task: Callable, *args, **kwargs) -> None:
        """Add a task to the execution queue with priority support."""
        priority = kwargs.pop('priority', 0)
        self.queue.put((priority, task, args, kwargs))

    def worker(self) -> None:
        """Enhanced worker with priority handling and graceful shutdown."""
        while not self._stop_event.is_set():
            try:
                priority, task, args, kwargs = self.queue.get_nowait()
                with self._lock:
                    self.rate_limiter.wait()
                    try:
                        result = task(*args, **kwargs)
                        if result:
                            self.results.append({
                                "priority": priority,
                                "status": "success",
                                "result": result
                            })
                    except Exception as e:
                        self.logger.error(f"Task execution failed: {str(e)}")
                        self.results.append({
                            "priority": priority,
                            "status": "error",
                            "error": str(e)
                        })
            except Queue.Empty:
                break
            finally:
                self.queue.task_done()

    async def run_async(self) -> List[Dict]:
        """Run tasks asynchronously with enhanced error handling."""
        tasks = []
        while not self.queue.empty():
            priority, task, args, kwargs = self.queue.get()
            tasks.append(self.execute_async(task, *args, **kwargs))
            self.queue.task_done()

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r is not None]

    def run(self, async_mode: bool = False) -> List[Dict]:
        """
        Run tasks with support for both synchronous and asynchronous execution.
        
        Args:
            async_mode: If True, runs tasks asynchronously
        """
        if async_mode:
            return asyncio.run(self.run_async())

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        self.queue.join()
        self._stop_event.set()
        for t in threads:
            t.join()

        return self.results

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._executor.shutdown(wait=True)