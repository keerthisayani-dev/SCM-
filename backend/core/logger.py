import logging
from pathlib import Path

from backend.config import get_settings


def configure_logging() -> None:
    settings = get_settings()
    log_file_path = Path(settings.log_file)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        filename=str(log_file_path),
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format=settings.log_format,
        force=True,
    )
