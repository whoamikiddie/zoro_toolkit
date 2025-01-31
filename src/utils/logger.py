import logging
import sys
from typing import Optional

def setup_logger(silent: bool = False) -> logging.Logger:
    """Configure and return the logger instance"""
    logger = logging.getLogger("zoro")
    
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Console handler
        if not silent:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler("zoro.log")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_logger() -> logging.Logger:
    """Get the configured logger instance"""
    return logging.getLogger("zoro")