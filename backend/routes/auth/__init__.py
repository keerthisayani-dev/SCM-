from fastapi import APIRouter

from backend.routes.auth.admin_auth_routes import router as admin_router
from backend.routes.auth.user_auth_routes import router as user_router

router = APIRouter()
router.include_router(user_router)
router.include_router(admin_router)

__all__ = ["router"]
