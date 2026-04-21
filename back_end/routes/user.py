from collections.abc import Callable
from pathlib import Path
import sys
from typing import Any

from fastapi import APIRouter, Depends, Header

if __package__ is None or __package__ == "":
    project_root = Path(__file__).resolve().parents[2]
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

from back_end.models.user_models import (
    PasswordChangeRequest,
    PasswordVerifyRequest,
    PasswordVerifyResponse,
    TokenResponse,
    UserData,
    UserLogin,
    UserSignup,
)
from back_end.services.auth_service import AuthService
from database.user_repository import UserRepository


CurrentUser = dict[str, Any]


def build_auth_router(
    get_user_repository: Callable[..., UserRepository],
    verify_api_key: Callable[..., None],
) -> APIRouter:
    router = APIRouter()

    def get_auth_service(
        user_repository: UserRepository = Depends(get_user_repository),
    ) -> AuthService:
        return AuthService(user_repository)

    async def get_current_user(
        authorization: str | None = Header(default=None, alias="Authorization"),
        auth_service: AuthService = Depends(get_auth_service),
    ) -> CurrentUser:
        return await auth_service.get_current_user(authorization)

    @router.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.post("/signup", tags=["auth"], dependencies=[Depends(verify_api_key)])
    async def signup(
        user: UserSignup,
        auth_service: AuthService = Depends(get_auth_service),
    ) -> TokenResponse:
        return await auth_service.signup(user)

    @router.post("/login", tags=["auth"], dependencies=[Depends(verify_api_key)])
    async def login(
        user: UserLogin,
        auth_service: AuthService = Depends(get_auth_service),
    ) -> TokenResponse:
        return await auth_service.login(user)

    @router.get("/me", tags=["auth"], dependencies=[Depends(verify_api_key)])
    async def get_user_data(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> UserData:
        return UserData(
            name=current_user["name"],
            email=current_user["email"],
            phone=current_user["phone"],
        )

    @router.post(
        "/verify-password",
        tags=["auth"],
        dependencies=[Depends(verify_api_key)],
    )
    async def verify_user_password(
        payload: PasswordVerifyRequest,
        current_user: CurrentUser = Depends(get_current_user),
        auth_service: AuthService = Depends(get_auth_service),
    ) -> PasswordVerifyResponse:
        return auth_service.verify_user_password(payload.password, current_user)

    @router.post(
        "/change-password",
        tags=["auth"],
        dependencies=[Depends(verify_api_key)],
    )
    async def change_user_password(
        payload: PasswordChangeRequest,
        current_user: CurrentUser = Depends(get_current_user),
        auth_service: AuthService = Depends(get_auth_service),
    ) -> dict[str, str]:
        return await auth_service.change_password(payload, current_user)

    return router


if __name__ == "__main__":
    print("back_end.routes.user loaded successfully")
