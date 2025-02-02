# ssrc/utils/exceptions.py
class ZoroToolkitError(Exception):
    """Base exception for Zoro Toolkit."""
    pass

class TaskExecutionError(ZoroToolkitError):
    """Raised when a task fails to execute."""
    pass

class RateLimitExceededError(ZoroToolkitError):
    """Raised when rate limit is exceeded."""
    pass

class NetworkError(ZoroToolkitError):
    """Raised when network operations fail."""
    pass

class ConfigurationError(ZoroToolkitError):
    """Raised when there's a configuration error."""
    pass