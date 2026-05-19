import logging
import time
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ASCENDING
from pymongo.errors import PyMongoError

from backend.config import get_settings
from backend.models.user_model import RoleEnum
from backend.utils.auth import hash_password

settings = get_settings()
logger = logging.getLogger(__name__)

mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
database: AsyncIOMotorDatabase = mongo_client[settings.mongodb_db_name]

users_collection: AsyncIOMotorCollection = database[settings.users_collection_name]
devices_collection: AsyncIOMotorCollection = database[settings.devices_collection_name]
shipments_collection: AsyncIOMotorCollection = database[settings.shipments_collection_name]


def get_db() -> AsyncIOMotorDatabase:
    return database


def close_mongo_connection() -> None:
    logger.info("closing MongoDB connection")
    mongo_client.close()


async def check_database_connection() -> float:
    started = time.perf_counter()
    try:
        await database.command("dbStats")
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info("database connection check succeeded", extra={"duration_ms": latency_ms})
        return latency_ms
    except PyMongoError as exc:
        logger.exception("database connection check failed")
        raise RuntimeError(f"Failed to connect to MongoDB: {exc}") from exc


async def prepare_database() -> None:
    try:
        logger.info("preparing database indexes")
        await check_database_connection()
        await users_collection.create_index(
            [("uid", ASCENDING)],
            name="uid_unique_if_string",
            unique=True,
            partialFilterExpression={"uid": {"$type": "string"}},
        )
        await users_collection.create_index(
            [("email", ASCENDING)],
            name="email_unique_if_string",
            unique=True,
            partialFilterExpression={"email": {"$type": "string"}},
        )
        await users_collection.create_index(
            [("username", ASCENDING)],
            name="username_unique_if_string",
            unique=True,
            partialFilterExpression={"username": {"$type": "string"}},
        )
        await users_collection.create_index(
            [("phone_number", ASCENDING)],
            name="phone_number_unique_if_string",
            unique=True,
            partialFilterExpression={"phone_number": {"$type": "string"}},
        )
        await devices_collection.create_index(
            [("device_id", ASCENDING)],
            name="device_id_unique_if_string",
            unique=True,
            partialFilterExpression={"device_id": {"$type": "string"}},
        )
        await shipments_collection.create_index(
            [("tracking_id", ASCENDING)],
            name="tracking_id_unique_if_string",
            unique=True,
            partialFilterExpression={"tracking_id": {"$type": "string"}},
        )
        await shipments_collection.create_index(
            [("owner_id", ASCENDING)],
            name="shipment_owner_lookup",
            partialFilterExpression={"owner_id": {"$type": "string"}},
        )
        await users_collection.create_index(
            [("role", ASCENDING)],
            name="user_role_lookup",
            partialFilterExpression={"role": {"$type": "string"}},
        )
        logger.info("database indexes prepared successfully")
    except PyMongoError as exc:
        logger.exception("database index preparation failed")
        raise RuntimeError(f"Failed to prepare MongoDB indexes: {exc}") from exc


async def seed_default_admin() -> None:
    try:
        existing_admin = await users_collection.find_one({"role": {"$in": [RoleEnum.ADMIN.value, RoleEnum.SUPER_ADMIN.value]}})
        if existing_admin is not None:
            logger.info("default admin seed skipped because admin already exists")
            return

        now = datetime.now(timezone.utc)
        await users_collection.insert_one(
            {
                "uid": "default-admin",
                "username": settings.admin_username,
                "email": settings.admin_email,
                "phone_number": settings.admin_phone_number,
                "role": RoleEnum.ADMIN.value,
                "hashed_password": hash_password(settings.admin_password),
                "created_at": now,
                "updated_at": now,
                "is_active": True,
            }
        )
        logger.info("default admin seeded successfully")
    except PyMongoError as exc:
        logger.exception("default admin seeding failed")
        raise RuntimeError(f"Failed to seed default admin: {exc}") from exc


async def get_db_health() -> dict[str, object]:
    try:
        health = {
            "status": "up",
            "database": settings.mongodb_db_name,
            "collection": settings.users_collection_name,
            "latency_ms": await check_database_connection(),
        }
        logger.info("database health check returned up")
        return health
    except RuntimeError as exc:
        logger.warning("database health check returned down")
        return {
            "status": "down",
            "database": settings.mongodb_db_name,
            "collection": settings.users_collection_name,
            "detail": str(exc),
        }
