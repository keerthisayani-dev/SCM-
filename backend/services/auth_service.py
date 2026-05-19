import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException

from backend.database.mongo import users_collection
from backend.models.user_model import RoleEnum
from backend.utils.auth import hash_password, verify_password

logger = logging.getLogger(__name__)


async def authenticate_user(email: str, password: str) -> dict:
    logger.info("authenticating user", extra={"email": email})
    user = await users_collection.find_one({"email": email})
    if not user or not verify_password(password, user["hashed_password"]):
        logger.warning("authentication failed", extra={"email": email})
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if "role" not in user or not user["role"]:
        logger.warning("user record missing role; defaulting to user", extra={"email": email, "user_id": user.get("uid")})
        user["role"] = RoleEnum.USER.value
        await users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"role": RoleEnum.USER.value, "updated_at": datetime.now(timezone.utc)}},
        )
    logger.info("authentication succeeded", extra={"email": email, "user_id": user["uid"]})
    return user


async def ensure_unique_identity(email: str, username: str, phone_number: str) -> None:
    logger.info("checking unique identity", extra={"email": email, "username": username})
    duplicate = await users_collection.find_one(
        {"$or": [{"email": email}, {"username": username}, {"phone_number": phone_number}]}
    )
    if duplicate is None:
        logger.info("identity is unique", extra={"email": email, "username": username})
        return
    if duplicate.get("email") == email:
        logger.warning("duplicate email detected", extra={"email": email})
        raise HTTPException(status_code=409, detail="Email is already registered")
    if duplicate.get("phone_number") == phone_number:
        logger.warning("duplicate phone number detected", extra={"phone_number": phone_number})
        raise HTTPException(status_code=409, detail="Phone number is already registered")
    logger.warning("duplicate username detected", extra={"username": username})
    raise HTTPException(status_code=409, detail="Username is already taken")


def build_user_document(username: str, email: str, phone_number: str, password: str, role: RoleEnum) -> dict:
    now = datetime.now(timezone.utc)
    document = {
        "uid": uuid4().hex,
        "username": username,
        "email": email,
        "phone_number": phone_number,
        "role": role.value,
        "hashed_password": hash_password(password),
        "created_at": now,
        "updated_at": now,
        "is_active": True,
    }
    logger.info("built user document", extra={"email": email, "username": username, "role": role.value})
    return document
