import os
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException

from back_end.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    parse_iso_datetime,
    verify_password,
)
from back_end.models.user_models import (
    PasswordChangeRequest,
    PasswordVerifyResponse,
    TokenResponse,
    UserData,
    UserLogin,
    UserSignup,
)
from database.user_repository import UserRepository


MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCK_MINUTES = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))


class AuthService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def get_current_user(self, authorization: str | None) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header",
            )

        token = authorization.removeprefix("Bearer ").strip()

        try:
            payload = decode_access_token(token)
        except Exception as exc:  # pragma: no cover - mapped below
            self._raise_token_error(exc)

        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        user = await self.user_repository.get_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        token_issued_at = payload.get("iat")
        if token_issued_at is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        if isinstance(token_issued_at, (int, float)):
            issued_at = datetime.fromtimestamp(token_issued_at, tz=UTC)
        else:
            issued_at = parse_iso_datetime(str(token_issued_at))

        if issued_at is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        password_changed_at = parse_iso_datetime(user.get("password_changed_at"))
        if password_changed_at and issued_at < password_changed_at:
            raise HTTPException(
                status_code=401,
                detail="Token is no longer valid after password change",
            )

        return user

    async def signup(self, user: UserSignup) -> TokenResponse:
        if await self.user_repository.get_by_email(user.email):
            raise HTTPException(status_code=400, detail="User already exists")

        user_data = {
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "password": hash_password(user.password),
            "failed_login_attempts": 0,
            "login_locked_until": None,
            "password_changed_at": None,
        }
        await self.user_repository.create_user(user_data)

        return TokenResponse(
            message="User registered successfully",
            access_token=create_access_token(user.email),
            user=UserData(
                name=user.name,
                email=user.email,
                phone=user.phone,
            ),
        )

    async def login(self, user: UserLogin) -> TokenResponse:
        stored_user = await self.user_repository.get_by_email(user.email)
        if not stored_user:
            raise HTTPException(status_code=404, detail="User not found")

        locked_until = parse_iso_datetime(stored_user.get("login_locked_until"))
        now = datetime.now(UTC)
        if locked_until and locked_until > now:
            raise HTTPException(
                status_code=429,
                detail=(
                    "Too many failed login attempts. "
                    f"Try again after {locked_until.isoformat()}"
                ),
            )

        if not verify_password(user.password, stored_user["password"]):
            # Avoid leaking whether the stored password hash is malformed.
            failed_attempts = int(stored_user.get("failed_login_attempts", 0)) + 1
            next_locked_until = None
            if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                next_locked_until = (
                    now + timedelta(minutes=LOGIN_LOCK_MINUTES)
                ).isoformat()

            await self.user_repository.update_login_failure_state(
                stored_user["email"],
                failed_attempts,
                next_locked_until,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        await self.user_repository.reset_login_failure_state(stored_user["email"])

        return TokenResponse(
            message="Login successful",
            access_token=create_access_token(stored_user["email"]),
            user=UserData(
                name=stored_user["name"],
                email=stored_user["email"],
                phone=stored_user["phone"],
            ),
        )

    def verify_user_password(
        self,
        password: str,
        current_user: dict,
    ) -> PasswordVerifyResponse:
        is_valid = verify_password(password, current_user["password"])
        return PasswordVerifyResponse(
            message="Password verified" if is_valid else "Password does not match",
            is_valid=is_valid,
        )

    async def change_password(
        self,
        payload: PasswordChangeRequest,
        current_user: dict,
    ) -> dict[str, str]:
        current_password_matches = verify_password(
            payload.current_password,
            current_user["password"],
        )
        if not current_password_matches:
            raise HTTPException(status_code=401, detail="Current password is incorrect")

        if payload.new_password == payload.current_password:
            raise HTTPException(
                status_code=400,
                detail="New password must be different from the current password",
            )

        password_changed_at = datetime.now(UTC).isoformat()
        await self.user_repository.update_password(
            current_user["email"],
            hash_password(payload.new_password),
            password_changed_at,
        )
        return {"message": "Password updated successfully. Please log in again."}

    @staticmethod
    def _raise_token_error(exc: Exception) -> None:
        import jwt

        if isinstance(exc, jwt.ExpiredSignatureError):
            raise HTTPException(status_code=401, detail="Token has expired") from exc
        if isinstance(exc, jwt.InvalidTokenError):
            raise HTTPException(status_code=401, detail="Invalid token") from exc
        raise exc
