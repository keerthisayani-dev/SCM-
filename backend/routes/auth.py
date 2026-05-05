import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from bson import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pymongo.errors import DuplicateKeyError

from backend.database.mongo import users_collection
from backend.models.user_model import (
    AuthResponse,
    AuthUserSummary,
    PasswordChangeRequest,
    PasswordCheckRequest,
    PasswordCheckResponse,
    UserLoginRequest,
    UserProfileResponse,
    UserSignupRequest,
)

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=ENV_PATH)

router = APIRouter()
bearer_scheme = HTTPBearer(auto_error=False)
ACCESS_TOKEN_SECRET = os.getenv("JWT_SECRET_KEY")
ACCESS_TOKEN_ALGORITHM = os.getenv("JWT_ALGORITHM")
ACCESS_TOKEN_TTL_MINUTES = os.getenv("JWT_EXPIRE_MINUTES")
BCRYPT_ROUNDS = os.getenv("BCRYPT_ROUNDS")

if not ACCESS_TOKEN_SECRET:
    raise ValueError("JWT_SECRET_KEY is required in the environment.")
if not ACCESS_TOKEN_ALGORITHM:
    raise ValueError("JWT_ALGORITHM is required in the environment.")
if not ACCESS_TOKEN_TTL_MINUTES:
    raise ValueError("JWT_EXPIRE_MINUTES is required in the environment.")
if not BCRYPT_ROUNDS:
    raise ValueError("BCRYPT_ROUNDS is required in the environment.")

ACCESS_TOKEN_TTL_MINUTES = int(ACCESS_TOKEN_TTL_MINUTES)
BCRYPT_ROUNDS = int(BCRYPT_ROUNDS)

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(user_id: str, email: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)
    payload = {"sub": user_id, "email": email, "exp": expires_at}
    return jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm=ACCESS_TOKEN_ALGORITHM)


async def authenticate_user(email: str, password: str) -> dict:
    user = await users_collection.find_one({"email": email})
    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return user


def _to_object_id(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except InvalidId as exc:
        raise credentials_exception from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None:
        raise credentials_exception

    try:
        payload = jwt.decode(
            credentials.credentials,
            ACCESS_TOKEN_SECRET,
            algorithms=[ACCESS_TOKEN_ALGORITHM],
        )
    except JWTError as exc:
        raise credentials_exception from exc

    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception

    user = await users_collection.find_one({"_id": _to_object_id(user_id)})
    if user is None:
        raise credentials_exception
    return user


def _build_auth_response(user: dict, message: str) -> AuthResponse:
    return AuthResponse(
        message=message,
        access_token=create_access_token(str(user["_id"]), user["email"]),
        user=AuthUserSummary(
            id=str(user["_id"]),
            username=user["username"],
            email=user["email"],
        ),
    )


async def _ensure_unique_identity(email: str, username: str) -> None:
    duplicate = await users_collection.find_one({"$or": [{"email": email}, {"username": username}]})
    if duplicate is None:
        return
    if duplicate.get("email") == email:
        raise HTTPException(status_code=400, detail="Email is already registered")
    raise HTTPException(status_code=400, detail="Username is already taken")


@router.post("/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED, summary="Create account")
async def signup(payload: UserSignupRequest) -> AuthResponse:
    await _ensure_unique_identity(payload.email, payload.username)

    document = {
        "username": payload.username,
        "email": payload.email,
        "hashed_password": hash_password(payload.password),
        "created_at": datetime.now(timezone.utc),
    }

    try:
        result = await users_collection.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail="A user with this email or username already exists",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Signup failed: {exc}",
        ) from exc

    created_user = {
        "_id": result.inserted_id,
        "username": payload.username,
        "email": payload.email,
    }
    return _build_auth_response(created_user, "Account created successfully")


@router.post("/login", response_model=AuthResponse, summary="Login with JSON body")
async def login(payload: UserLoginRequest) -> AuthResponse:
    user = await authenticate_user(payload.email, payload.password)
    return _build_auth_response(user, "Login successful")


@router.get("/me", response_model=UserProfileResponse, summary="Get current user")
async def me(current_user: dict = Depends(get_current_user)) -> UserProfileResponse:
    return UserProfileResponse(
        id=str(current_user["_id"]),
        username=current_user["username"],
        email=current_user["email"],
    )


@router.post("/verify-password", response_model=PasswordCheckResponse, summary="Check current password")
async def verify_user_password(
    payload: PasswordCheckRequest,
    current_user: dict = Depends(get_current_user),
) -> PasswordCheckResponse:
    is_valid = verify_password(payload.password, current_user["hashed_password"])
    return PasswordCheckResponse(
        valid=is_valid,
        message="Password matches" if is_valid else "Password does not match",
    )


@router.post("/change-password", summary="Change password")
async def change_password(
    payload: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    if not verify_password(payload.current_password, current_user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from the current password")

    await users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"hashed_password": hash_password(payload.new_password)}},
    )
    return {"message": "Password updated successfully"}
