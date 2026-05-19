import uvicorn

from backend.config import get_settings


if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.app_host,
        port=settings.port,
        reload=settings.app_reload,
    )
