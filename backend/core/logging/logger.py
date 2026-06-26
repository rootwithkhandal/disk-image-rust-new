"""
ForgeLens logging framework.

Uses loguru for structured, leveled logging with:
- Console output (colored, human-readable)
- Rotating file output (JSON-structured for audit trails)
- Separate acquisition log per session
"""

import sys
from pathlib import Path

from loguru import logger

# ── Default log directory ────────────────────────────────────────────────────
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)


def setup_logger(
    log_level: str = "INFO",
    log_dir: Path = LOGS_DIR,
    session_id: str | None = None,
) -> None:
    """
    Configure the global logger.

    Args:
        log_level:  Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir:    Directory where log files are written.
        session_id: Optional acquisition session ID for per-session log files.
    """
    logger.remove()  # Remove default handler

    # ── Console handler ──────────────────────────────────────────────────────
    logger.add(
        sys.stderr,
        level=log_level,
        colorize=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
    )

    # ── General rotating file handler (JSON) ─────────────────────────────────
    logger.add(
        log_dir / "forgelens.log",
        level=log_level,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        serialize=True,  # JSON output for audit trails
        enqueue=True,  # Thread-safe
    )

    # ── Per-session acquisition log ──────────────────────────────────────────
    if session_id:
        logger.add(
            log_dir / f"acquisition_{session_id}.log",
            level="DEBUG",
            rotation=None,
            serialize=True,
            enqueue=True,
            filter=lambda record: "acquisition" in record["extra"],
        )

    logger.info("Logger initialized | level={} | log_dir={}", log_level, log_dir)


def get_acquisition_logger(session_id: str):
    """Return a logger bound to a specific acquisition session."""
    return logger.bind(acquisition=True, session_id=session_id)
