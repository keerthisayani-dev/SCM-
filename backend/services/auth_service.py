import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException

from backend.database.mongo import auth_events_collection, login_details_collection, users_collection
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


async def record_successful_login(user_uid: str, client_source: str) -> None:
    now = datetime.now(timezone.utc)
    await users_collection.update_one(
        {"uid": user_uid},
        {
            "$set": {
                "last_login_at": now,
                "last_login_via": client_source,
                "updated_at": now,
            },
            "$inc": {"login_count": 1},
        },
    )
    logger.info("login activity recorded", extra={"user_id": user_uid, "client_source": client_source})


async def record_auth_event(
    *,
    event_type: str,
    email: str,
    client_source: str,
    user_uid: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    await auth_events_collection.insert_one(
        {
            "uid": str(uuid4()),
            "event_type": event_type,
            "user_uid": user_uid,
            "email": email,
            "client_source": client_source,
            "created_at": now,
        }
    )
    logger.info("auth event recorded", extra={"event_type": event_type, "user_id": user_uid, "client_source": client_source})


async def record_login_detail(
    *,
    user_uid: str,
    username: str,
    email: str,
    role: str,
    client_source: str,
) -> None:
    now = datetime.now(timezone.utc)
    await login_details_collection.insert_one(
        {
            "uid": str(uuid4()),
            "user_uid": user_uid,
            "username": username,
            "email": email,
            "role": role,
            "client_source": client_source,
            "logged_in_at": now,
        }
    )
    logger.info("login detail recorded", extra={"user_id": user_uid, "client_source": client_source})


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
        "uid": str(uuid4()),
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
