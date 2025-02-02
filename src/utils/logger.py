# src/utils/logger.py
import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import json

# Define custom log level for SUCCESS
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")

class Logger:
    def __init__(self, name: str = "ZoroToolkit"):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            
            # Create logs directory if it doesn't exist
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            
            # Console Handler with colored output
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            
            # Custom formatter with colors and symbols
            class ColoredFormatter(logging.Formatter):
                COLORS = {
                    'INFO': '\033[96m',     # Cyan
                    'SUCCESS': '\033[92m',  # Green
                    'WARNING': '\033[93m',  # Yellow
                    'ERROR': '\033[91m',    # Red
                    'DEBUG': '\033[94m',    # Blue
                    'CRITICAL': '\033[95m', # Magenta
                    'RESET': '\033[0m'
                }
                
                SYMBOLS = {
                    'INFO': 'ℹ',
                    'SUCCESS': '✓',
                    'WARNING': '⚠',
                    'ERROR': '✗',
                    'DEBUG': '🔍',
                    'CRITICAL': '⚡'
                }

                def format(self, record):
                    color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
                    symbol = self.SYMBOLS.get(record.levelname, '')
                    record.msg = f"{color}{symbol} {record.msg}{self.COLORS['RESET']}"
                    return super().format(record)
            
            console_formatter = ColoredFormatter(
                '%(asctime)s - %(message)s',
                datefmt='%H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            
            # File Handler with JSON formatting
            log_file = logs_dir / f"zoro_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            
            class JSONFormatter(logging.Formatter):
                def format(self, record):
                    log_entry = {
                        'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                        'level': record.levelname,
                        'message': record.getMessage(),
                        'module': record.module,
                        'function': record.funcName,
                        'line': record.lineno
                    }
                    if hasattr(record, 'scan_data'):
                        log_entry['scan_data'] = record.scan_data
                    return json.dumps(log_entry)
            
            file_handler.setFormatter(JSONFormatter())
            
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    def _log_with_data(self, level: str, message: str, scan_data: Optional[dict] = None):
        """Internal method to log messages with optional scan data"""
        if scan_data:
            extra = {'scan_data': scan_data}
            self.logger.log(getattr(logging, level), message, extra=extra)
        else:
            self.logger.log(getattr(logging, level), message)

    def info(self, message: str, scan_data: Optional[dict] = None):
        self._log_with_data('INFO', message, scan_data)

    def success(self, message: str, scan_data: Optional[dict] = None):
        """Custom success level with green color"""
        self.logger.log(SUCCESS_LEVEL_NUM, message, extra={'scan_data': scan_data} if scan_data else {})

    def warning(self, message: str, scan_data: Optional[dict] = None):
        self._log_with_data('WARNING', message, scan_data)

    def error(self, message: str, scan_data: Optional[dict] = None):
        self._log_with_data('ERROR', message, scan_data)

    def debug(self, message: str, scan_data: Optional[dict] = None):
        self._log_with_data('DEBUG', message, scan_data)

    def critical(self, message: str, scan_data: Optional[dict] = None):
        self._log_with_data('CRITICAL', message, scan_data)

    def progress(self, current: int, total: int, prefix: str = ''):
        """Display a progress bar in the console"""
        bar_length = 50
        filled_length = int(round(bar_length * current / float(total)))
        percents = round(100.0 * current / float(total), 1)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        sys.stdout.write(f'\r{prefix} |{bar}| {percents}%')
        if current == total:
            sys.stdout.write('\n')
        sys.stdout.flush()