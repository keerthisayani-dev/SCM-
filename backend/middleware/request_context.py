from contextvars import ContextVar
import logging
from time import perf_counter
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


request_id_context: ContextVar[str] = ContextVar("request_id", default="-")
request_path_context: ContextVar[str] = ContextVar("request_path", default="-")
request_method_context: ContextVar[str] = ContextVar("request_method", default="-")
logger = logging.getLogger(__name__)


def get_request_context() -> dict[str, str]:
    return {
        "request_id": request_id_context.get(),
        "path": request_path_context.get(),
        "method": request_method_context.get(),
    }


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        request_id_context.set(request_id)
        request_path_context.set(request.url.path)
        request_method_context.set(request.method)

        started = perf_counter()
        response = await call_next(request)
        duration_ms = round((perf_counter() - started) * 1000, 2)

        logger.info(
            "request completed",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "duration_ms": duration_ms,
                "status_code": response.status_code,
            },
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = str(duration_ms)
        return response
