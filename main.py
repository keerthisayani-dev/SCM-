from contextlib import asynccontextmanager
from pathlib import Path
import time

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION
from backend.core.logger import configure_logging, get_logger
from backend.database.mongo import close_mongo_connection, get_db, get_db_health
from backend.middleware.request_context import RequestContextMiddleware
from backend.routes.auth import router as auth_router
from backend.routes.device_routes import router as device_router
from backend.routes.shipment_routes import router as shipment_router

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
FRONTEND_INDEX = FRONTEND_DIR / "html_files" / "index.html"
FRONTEND_LOGIN = FRONTEND_DIR / "html_files" / "login.html"
FRONTEND_DASHBOARD = FRONTEND_DIR / "html_files" / "dashboard.html"
configure_logging()
logger = get_logger(__name__)


def _html_file_response(path: Path) -> FileResponse:
    return FileResponse(
        path,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.startup_warnings = []
    try:
        yield
    finally:
        close_mongo_connection()


app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    lifespan=lifespan,
)

app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api", tags=["auth"])
app.include_router(device_router, prefix="/api", tags=["devices"])
app.include_router(shipment_router, prefix="/api", tags=["shipments"])
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
app.state.started_at = time.time()


@app.get("/", tags=["default"], summary="Home", response_model=None)
async def home(request: Request) -> Response:
    if "text/html" in request.headers.get("accept", ""):
        return _html_file_response(FRONTEND_INDEX)

    return {"message": f"{APP_TITLE} is running"}


@app.get("/login", tags=["default"], summary="Login page", response_model=None)
@app.get("/login/", tags=["default"], summary="Login page", response_model=None, include_in_schema=False)
@app.get("/login.html", tags=["default"], summary="Login page", response_model=None, include_in_schema=False)
async def login_page() -> Response:
    return _html_file_response(FRONTEND_LOGIN)


@app.get("/dashboard", tags=["default"], summary="Dashboard page", response_model=None)
@app.get("/dashboard/", tags=["default"], summary="Dashboard page", response_model=None, include_in_schema=False)
@app.get("/dashboard.html", tags=["default"], summary="Dashboard page", response_model=None, include_in_schema=False)
async def dashboard_page() -> Response:
    return _html_file_response(FRONTEND_DASHBOARD)


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
            "startup_warnings": app.state.startup_warnings,
        },
    )


@app.get("/info", tags=["info"], summary="App info")
async def info() -> dict[str, str]:
    return {
        "version": APP_VERSION,
        "service": APP_TITLE,
    }


@app.get("/ping-db", tags=["health"], summary="Ping database")
async def ping_db(db=Depends(get_db)) -> dict[str, str]:
    await db.command("ping")
    return {"db": "connected"}
