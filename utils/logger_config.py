# utils/logger_config.py
import sys
from pathlib import Path

from loguru import logger


def setup_logger(log_file: str = "logs/thirdeye.log", level: str = "INFO") -> None:
    """
    Configure loguru with console and rotating file output.

    Args:
        log_file: Path to the log file.
        level:    Logging level — DEBUG, INFO, WARNING, ERROR, CRITICAL.
    """
    # Remove any existing handlers to avoid duplicates on repeated calls
    logger.remove()

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Console — coloured, human-readable
    logger.add(
        sys.stdout,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        level=level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # File — rotating, compressed
    logger.add(
        log_file,
        rotation="10 MB",
        retention="5 files",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {module}:{function}:{line} - {message}",
        level=level,
        backtrace=True,
        diagnose=True,
    )

    logger.info(f"Logger initialised — file: {log_file}, level: {level}")
