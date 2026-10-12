import logging
import sys
from pathlib import Path
import logstash

# Create logs directory if it doesn't exist
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# Configure logger
logger = logging.getLogger("memguard")
logger.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Console Handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# File Handler
file_handler = logging.FileHandler(log_dir / "memguard.log")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

try:
    logstash_handler = logstash.TCPLogstashHandler('127.0.0.1', 5000, version=1)
    logger.addHandler(logstash_handler)
except Exception as e:
    pass

def get_logger():
    return logger
