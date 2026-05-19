from datetime import datetime, timezone
import logging

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from pymongo.errors import DuplicateKeyError, PyMongoError

from backend.auth.access_control import require_role
from backend.database.mongo import users_collection
from backend.middleware.auth import get_current_user
from backend.models.auth_models import UserCreate, UserOut
from backend.models.user_model import (
    PasswordChangeRequest,
    PasswordCheckRequest,
    PasswordCheckResponse,
    RoleEnum,
    UserLoginRequest,
    UserProfileResponse,
    UserSignupRequest,
)
from backend.services.auth_service import authenticate_user, build_user_document, ensure_unique_identity
from backend.utils.auth import create_access_token, hash_password, verify_password

logger = logging.getLogger(__name__)


class AuthUserSummary(BaseModel):
    id: str
    username: str
    email: str
    role: RoleEnum


class AuthResponse(BaseModel):
    message: str
    token_type: str = "bearer"
    access_token: str
    user: AuthUserSummary


router = APIRouter()
require_user = require_role(RoleEnum.USER)
require_super_admin = require_role(RoleEnum.SUPER_ADMIN)


def _build_auth_response(user: dict, message: str) -> AuthResponse:
    role = RoleEnum(user.get("role", RoleEnum.USER.value))
    return AuthResponse(
        message=message,
        access_token=create_access_token(user["uid"], user["email"], role.value),
        user=AuthUserSummary(
            id=user["uid"],
            username=user["username"],
            email=user["email"],
            role=role,
        ),
    )


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Create raw user")
async def create_user(payload: UserCreate) -> UserOut:
    email = str(payload.email)
    try:
        logger.info("manual user creation requested", extra={"email": email, "user_name": payload.name})
        existing_user = await users_collection.find_one({"email": email})
        if existing_user is not None:
            logger.warning("manual user creation rejected due to duplicate email", extra={"email": email})
            raise HTTPException(status_code=409, detail="Email is already registered")

        document = payload.model_dump()
        document["email"] = email
        document["created_at"] = datetime.now(timezone.utc)
        result = await users_collection.insert_one(document)
        logger.info("manual user created successfully", extra={"email": email, "user_id": str(result.inserted_id)})
        return UserOut(
            id=str(result.inserted_id),
            name=document["name"],
            email=document["email"],
            created_at=document["created_at"],
        )
    except DuplicateKeyError as exc:
        logger.warning("manual user creation hit duplicate key at insert time", extra={"email": email})
        raise HTTPException(status_code=409, detail="Email is already registered") from exc
    except HTTPException:
        raise
    except PyMongoError as exc:
        logger.exception("manual user creation failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while creating the user") from exc


@router.get("/users/{user_id}", response_model=UserOut, summary="Get user by id")
async def get_user(user_id: str) -> UserOut:
    try:
        object_id = ObjectId(user_id)
    except InvalidId as exc:
        logger.warning("manual user lookup rejected due to invalid object id", extra={"user_id": user_id})
        raise HTTPException(status_code=400, detail="Invalid user id") from exc

    try:
        logger.info("manual user lookup requested", extra={"user_id": user_id})
        user = await users_collection.find_one(
            {"_id": object_id},
            {"_id": 0, "name": 1, "email": 1, "created_at": 1},
        )
    except PyMongoError as exc:
        logger.exception("manual user lookup failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while fetching the user") from exc

    if user is None:
        logger.warning("manual user lookup failed because user was not found", extra={"user_id": user_id})
        raise HTTPException(status_code=404, detail="User not found")

    logger.info("manual user lookup completed", extra={"user_id": user_id})
    return UserOut(id=user_id, **user)


@router.post("/auth/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED, summary="Create account")
async def signup(payload: UserSignupRequest) -> AuthResponse:
    try:
        logger.info("signup requested", extra={"email": str(payload.email), "username": payload.username})
        await ensure_unique_identity(str(payload.email), payload.username, payload.phone_number)
        document = build_user_document(
            payload.username,
            str(payload.email),
            payload.phone_number,
            payload.password,
            RoleEnum.USER,
        )
        await users_collection.insert_one(document)
        logger.info("signup completed", extra={"email": str(payload.email), "user_id": document["uid"]})
    except DuplicateKeyError as exc:
        logger.warning("signup failed due to duplicate key", extra={"email": str(payload.email)})
        raise HTTPException(
            status_code=409,
            detail="A user with this email or username already exists",
        ) from exc
    except HTTPException:
        logger.warning("signup rejected by validation or business rule", extra={"email": str(payload.email)})
        raise
    except PyMongoError as exc:
        logger.exception("signup failed due to database error")
        raise HTTPException(
            status_code=500,
            detail="Database error occurred while creating the account",
        ) from exc
    except Exception as exc:
        logger.exception("signup failed unexpectedly")
        raise HTTPException(status_code=500, detail=f"Signup failed: {exc}") from exc

    created_user = {
        "uid": document["uid"],
        "username": payload.username,
        "email": str(payload.email),
        "role": RoleEnum.USER.value,
    }
    return _build_auth_response(created_user, "Account created successfully")


@router.post("/auth/login", response_model=AuthResponse, summary="Login with JSON body")
async def login(payload: UserLoginRequest) -> AuthResponse:
    try:
        logger.info("login requested", extra={"email": str(payload.email)})
        user = await authenticate_user(str(payload.email), payload.password)
        logger.info("login completed", extra={"email": str(payload.email), "user_id": user["uid"]})
        return _build_auth_response(user, "Login successful")
    except HTTPException:
        logger.warning("login rejected", extra={"email": str(payload.email)})
        raise
    except PyMongoError as exc:
        logger.exception("login failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred during login") from exc
    except Exception as exc:
        logger.exception("login failed unexpectedly")
        raise HTTPException(status_code=500, detail=f"Login failed: {exc}") from exc


@router.get("/auth/me", response_model=UserProfileResponse, summary="Get current user")
async def me(current_user: dict = Depends(get_current_user)) -> UserProfileResponse:
    try:
        logger.info("current user profile requested", extra={"user_id": current_user["uid"]})
        return UserProfileResponse(
            id=current_user["uid"],
            username=current_user["username"],
            email=current_user["email"],
            role=RoleEnum(current_user.get("role", RoleEnum.USER.value)),
        )
    except KeyError as exc:
        logger.exception("current user profile response missing expected fields")
        raise HTTPException(status_code=500, detail=f"Missing user field: {exc}") from exc


@router.post("/auth/verify-password", response_model=PasswordCheckResponse, summary="Check current password")
async def verify_user_password(
    payload: PasswordCheckRequest,
    current_user: dict = Depends(get_current_user),
) -> PasswordCheckResponse:
    try:
        logger.info("password verification requested", extra={"user_id": current_user["uid"]})
        is_valid = verify_password(payload.password, current_user["hashed_password"])
        return PasswordCheckResponse(
            valid=is_valid,
            message="Password matches" if is_valid else "Password does not match",
        )
    except KeyError as exc:
        logger.exception("password verification failed due to missing user field")
        raise HTTPException(status_code=500, detail=f"Missing user field: {exc}") from exc


@router.post("/auth/change-password", summary="Change password")
async def change_password(
    payload: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    try:
        logger.info("password change requested", extra={"user_id": current_user["uid"]})
        if not verify_password(payload.current_password, current_user["hashed_password"]):
            logger.warning("password change rejected due to incorrect current password", extra={"user_id": current_user["uid"]})
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        if payload.current_password == payload.new_password:
            logger.warning("password change rejected because new password matches current password", extra={"user_id": current_user["uid"]})
            raise HTTPException(status_code=400, detail="New password must be different from the current password")

        result = await users_collection.update_one(
            {"_id": current_user["_id"]},
            {
                "$set": {
                    "hashed_password": hash_password(payload.new_password),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
        if result.matched_count == 0:
            logger.warning("password change failed because user was not found", extra={"user_id": current_user["uid"]})
            raise HTTPException(status_code=404, detail="User not found")
        logger.info("password changed successfully", extra={"user_id": current_user["uid"]})
        return {"message": "Password updated successfully"}
    except HTTPException:
        raise
    except KeyError as exc:
        logger.exception("password change failed due to missing user field")
        raise HTTPException(status_code=500, detail=f"Missing user field: {exc}") from exc
    except PyMongoError as exc:
        logger.exception("password change failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while updating password") from exc


@router.get("/auth/user-area", summary="User area")
async def user_area(current_user: dict = Depends(require_user)) -> dict[str, str]:
    logger.info("user area accessed", extra={"user_id": current_user["uid"], "role": current_user["role"]})
    return {"message": f"Welcome {current_user['role']} to the user area."}


@router.get("/auth/admin-area", summary="Admin area")
async def admin_area(current_user: dict = Depends(require_role(RoleEnum.ADMIN))) -> dict[str, str]:
    logger.info("admin area accessed", extra={"user_id": current_user["uid"], "role": current_user["role"]})
    return {"message": f"Welcome {current_user['role']} to the admin area."}


@router.get("/auth/super-admin-area", summary="Super admin area")
async def super_admin_area(current_user: dict = Depends(require_super_admin)) -> dict[str, str]:
    logger.info("super admin area accessed", extra={"user_id": current_user["uid"], "role": current_user["role"]})
    return {"message": "Welcome super_admin to the super admin area."}
