# utils/exceptions.py
import logging
import traceback

logging.basicConfig(
    filename='logs/zoro_toolkit_errors.log', 
    level=logging.ERROR, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_error_details(exception):
    error_details = f"Exception: {exception.__class__.__name__}\n"
    error_details += f"Message: {str(exception)}\n"
    error_details += f"Traceback: {traceback.format_exc()}"
    logging.error(error_details)

class ZoroToolkitError(Exception):
    def __init__(self, message="An error occurred in the Zoro Toolkit", error_code=None, context=None):
        self.message = message
        self.error_code = error_code
        self.context = context  
        log_error_details(self)  
        super().__init__(self.message)

class TaskExecutionError(ZoroToolkitError):
    def __init__(self, message="Task failed to execute", error_code=1001, task_id=None):
        super().__init__(message, error_code, context={"task_id": task_id})

class RateLimitExceededError(ZoroToolkitError):
    def __init__(self, message="Rate limit exceeded", error_code=1002, user_id=None):
        super().__init__(message, error_code, context={"user_id": user_id})

class NetworkError(ZoroToolkitError):
    def __init__(self, message="Network operation failed", error_code=1003, operation=None):
        super().__init__(message, error_code, context={"operation": operation})

class ConfigurationError(ZoroToolkitError):
    def __init__(self, message="Configuration error occurred", error_code=1004, config_key=None):
        super().__init__(message, error_code, context={"config_key": config_key})

def handle_exception(exception):
    log_error_details(exception)

try:
    raise TaskExecutionError("The task execution failed due to an unexpected error.", task_id="12345")
except TaskExecutionError as e:
    handle_exception(e)

try:
    raise RateLimitExceededError("User has exceeded the allowed request limit.", user_id="user123")
except RateLimitExceededError as e:
    handle_exception(e)

try:
    raise NetworkError("Failed to connect to external service.", operation="API call")
except NetworkError as e:
    handle_exception(e)

try:
    raise ConfigurationError("Missing configuration key.", config_key="API_KEY")
except ConfigurationError as e:
    handle_exception(e)
