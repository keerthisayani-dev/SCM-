import time

from fastapi import Depends, FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import Settings, get_settings
from backend.core.logger import configure_logging
from backend.database.mongo import close_mongo_connection, get_db, get_db_health, prepare_database, seed_default_admin
from backend.middleware.request_context import RequestContextMiddleware
from backend.routes.auth import router as auth_router
from backend.routes.shipment_routes import router as shipment_router

configure_logging()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        description=settings.app_description,
    )

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.frontend_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router, prefix="/api", tags=["auth"])
    app.include_router(shipment_router, prefix="/api", tags=["shipments"])
    app.state.started_at = time.time()

    @app.on_event("startup")
    async def startup() -> None:
        await prepare_database()
        await seed_default_admin()

    @app.on_event("shutdown")
    async def shutdown() -> None:
        close_mongo_connection()

    @app.get("/", tags=["default"], summary="Home")
    async def home() -> dict[str, str]:
        return {"message": f"{settings.app_title} is running"}

    @app.get("/health", tags=["health"], summary="Health")
    async def health() -> JSONResponse:
        uptime_seconds = round(time.time() - app.state.started_at, 2)
        checks: dict[str, dict[str, object]] = {
            "api": {
                "status": "up",
                "uptime_seconds": uptime_seconds,
            }
        }

        http_status = status.HTTP_200_OK
        overall_status = "healthy"

        try:
            checks["database"] = await get_db_health()
        except Exception as exc:
            checks["database"] = {
                "status": "down",
                "error": str(exc),
            }
            overall_status = "degraded"
            http_status = status.HTTP_503_SERVICE_UNAVAILABLE

        return JSONResponse(
            status_code=http_status,
            content={
                "status": overall_status,
                "service": app.title,
                "version": app.version,
                "checks": checks,
            },
        )

    @app.get("/info", tags=["info"], summary="App info")
    async def info(app_settings: Settings = Depends(get_settings)) -> dict[str, str]:
        return {
            "environment": app_settings.environment,
            "version": app_settings.app_version,
            "service": app_settings.app_title,
        }

    @app.get("/ping-db", tags=["health"], summary="Ping database")
    async def ping_db(db=Depends(get_db)) -> dict[str, str]:
        await db.command("ping")
        return {"db": "connected"}

    return app


app = create_app()
