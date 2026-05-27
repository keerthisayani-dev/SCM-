import logging

logger = logging.getLogger(__name__.split(".", 1)[0])


def configure_logging() -> None:
    logging.basicConfig(
        force=True,
    )


def get_logger(name: str | None = None) -> logging.Logger:
    if not name:
        return logger
    return logging.getLogger(name)
