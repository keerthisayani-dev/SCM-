import logging
from pathlib import Path

APP_LOGGER_NAME = "scmxpertlite"
DEFAULT_LOG_FILE = Path("logs/app.log")
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

logger = logging.getLogger(APP_LOGGER_NAME)


def configure_logging() -> None:
    log_file_path = DEFAULT_LOG_FILE
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        filename=str(log_file_path),
        level=DEFAULT_LOG_LEVEL,
        format=DEFAULT_LOG_FORMAT,
        force=True,
    )


def get_logger(name: str | None = None) -> logging.Logger:
    if not name:
        return logger
    return logging.getLogger(name)
