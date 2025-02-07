# src/core/engine.py 
import asyncio
import threading
from queue import PriorityQueue, Empty
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
        self.queue: PriorityQueue = PriorityQueue()  # --> Using PriorityQueue instead of Queue
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
            task_timeout = kwargs.pop('timeout', self.timeout)  # --> Custom task timeout

            result = await asyncio.wait_for(
                loop.run_in_executor(
                    self._executor,
                    lambda: task(*args, **kwargs)
                ),
                timeout=task_timeout
            )
            return result
        except asyncio.TimeoutError:
            error_msg = f"Task timed out after {task_timeout} seconds"
            self.logger.error(error_msg)
            return {"status": "timeout", "error": error_msg}
        except Exception as e:
            error_msg = f"Task execution failed: {str(e)}"
            self.logger.error(error_msg)
            return {"status": "error", "error": str(e)}

    def add_task(self, task: Callable, *args, **kwargs) -> None:
        """Add a task to the execution queue with priority support."""
        priority = kwargs.pop('priority', 0)
        max_retries = kwargs.pop('max_retries', 3)
        timeout = kwargs.pop('timeout', self.timeout)
        self.queue.put((priority, task, args, kwargs, max_retries, timeout))

    def worker(self) -> None:
        """Enhanced worker with priority handling and graceful shutdown."""
        while not self._stop_event.is_set():
            try:
                priority, task, args, kwargs, max_retries, timeout = self.queue.get_nowait()
                with self._lock:
                    self.rate_limiter.wait()
                    self._execute_task(priority, task, args, kwargs, max_retries, timeout)
            except Empty:
                break
            except Exception as e:
                self.logger.error(f"Worker encountered an error: {str(e)}")
            finally:
                self.queue.task_done()

    def _execute_task(self, priority: int, task: Callable, args: tuple, kwargs: dict, max_retries: int, timeout: int) -> None:
        """Execute task and store result, with retry logic."""
        retries = 0
        while retries <= max_retries:
            try:
                result = task(*args, **kwargs)
                if result:
                    self.results.append({
                        "priority": priority,
                        "status": "success",
                        "result": result
                    })
                break
            except Exception as e:
                retries += 1
                if retries > max_retries:
                    self.logger.error(f"Task failed after {retries} retries: {str(e)}")
                    self.results.append({
                        "priority": priority,
                        "status": "error",
                        "error": str(e)
                    })
                else:
                    self.logger.warning(f"Task failed, retrying... (Attempt {retries}/{max_retries})")
                if retries <= max_retries:
                    continue

    async def run_async(self) -> List[Dict]:
        """Run tasks asynchronously with enhanced error handling."""
        tasks = []
        while not self.queue.empty():
            priority, task, args, kwargs, max_retries, timeout = self.queue.get()
            tasks.append(self.execute_async(task, *args, **kwargs, timeout=timeout))
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
