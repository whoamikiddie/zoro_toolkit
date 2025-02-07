import logging
import traceback

logging.basicConfig(
    filename='logs/zoro_toolkit_errors.log', 
    level=logging.ERROR, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_error_details(exception, additional_context=None):
    error_details = f"Exception: {exception.__class__.__name__}\n"
    error_details += f"Message: {str(exception)}\n"
    error_details += f"Traceback: {traceback.format_exc()}\n"
    if additional_context:
        error_details += f"Context: {additional_context}\n"
    logging.error(error_details)

class ZoroToolkitError(Exception):
    def __init__(self, message="An error occurred in the Zoro Toolkit", error_code=None, context=None):
        self.message = message
        self.error_code = error_code
        self.context = context  
        super().__init__(self.message)

    def log_error(self):
        # Log the error with additional context
        log_error_details(self, {"error_code": self.error_code, "context": self.context})

class TaskExecutionError(ZoroToolkitError):
    def __init__(self, message="Task failed to execute", error_code=1001, task_id=None):
        super().__init__(message, error_code, context={"task_id": task_id})
        self.log_error()

class RateLimitExceededError(ZoroToolkitError):
    def __init__(self, message="Rate limit exceeded", error_code=1002, user_id=None):
        super().__init__(message, error_code, context={"user_id": user_id})
        self.log_error()

class NetworkError(ZoroToolkitError):
    def __init__(self, message="Network operation failed", error_code=1003, operation=None):
        super().__init__(message, error_code, context={"operation": operation})
        self.log_error()

class ConfigurationError(ZoroToolkitError):
    def __init__(self, message="Configuration error occurred", error_code=1004, config_key=None):
        super().__init__(message, error_code, context={"config_key": config_key})
        self.log_error()

def handle_exception(exception):
    exception.log_error()  # Log the exception details