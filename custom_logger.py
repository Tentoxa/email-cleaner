import logging
import sys
import threading
import os


class FileOnlyFilter(logging.Filter):
    def __init__(self, file_only_marker="_FILE_ONLY_"):
        super().__init__()
        self.file_only_marker = file_only_marker

    def filter(self, record):
        message = record.getMessage()
        if message.startswith(self.file_only_marker):
            # Clean the message for file output
            record.msg = message[len(self.file_only_marker):]
            record.args = ()
            return False  # Exclude from console
        return True  # Include in console


class CustomFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""

    COLORS = {
        'DEBUG': '\033[94m',  # Blue
        'INFO': '\033[92m',  # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',  # Red
        'CRITICAL': '\033[95m',  # Magenta
        'RESET': '\033[0m'  # Reset
    }

    def format(self, record):
        # Save original levelname to restore it after formatting
        original_levelname = record.levelname

        # Add color to levelname
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"

        # Simplify thread name display
        thread = threading.current_thread()
        if thread.name == "MainThread":
            record.threadName = "Main"
        else:
            # Extract thread number or use a counter
            thread_id = getattr(thread, 'ident', '?')
            try:
                # Try to extract a numeric ID from thread name if it follows pattern "Thread-X"
                if thread.name.startswith("Thread-"):
                    thread_num = thread.name.split("-")[1].split()[0]
                    record.threadName = f"T-{thread_num}"
                else:
                    record.threadName = f"T-{thread_id % 1000}"
            except (IndexError, ValueError):
                record.threadName = f"T-{thread_id % 1000}"

        # Format the message
        result = super().format(record)

        # Restore original levelname
        record.levelname = original_levelname

        return result


def setup_logger(name=None, log_file=None, level=logging.INFO):
    """Set up and configure logger

    Args:
        name: Logger name (defaults to root logger if None)
        log_file: Path to log file if file logging is desired
        level: Minimum logging level

    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent propagation to avoid duplicate messages
    logger.propagate = False

    # Clear existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # Create formatter
    log_format = '%(asctime)s | %(threadName)s | %(levelname)s | %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Add color formatting for console
    color_formatter = CustomFormatter(log_format, datefmt=date_format)
    console_handler.setFormatter(color_formatter)
    logger.addHandler(console_handler)

    console_filter = FileOnlyFilter()
    console_handler.addFilter(console_filter)
    console_handler.setFormatter(color_formatter)
    logger.addHandler(console_handler)

    # Add file handler if log_file is provided
    if log_file:
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)

        # Use plain formatter without colors for file
        file_formatter = logging.Formatter(log_format, datefmt=date_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger
