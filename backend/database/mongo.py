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
        logger.info("database connection check succeeded")
        return latency_ms
    except PyMongoError:
        logger.exception("database connection check failed")
        raise RuntimeError("Failed to connect to MongoDB") from None


async def prepare_database() -> None:
    try:
        logger.info("preparing database indexes")
        await check_database_connection()
        index_definitions = [
            (
                users_collection,
                [("uid", ASCENDING)],
                {
                    "name": "uid_unique_if_string",
                    "unique": True,
                    "partialFilterExpression": {"uid": {"$type": "string"}},
                },
            ),
            (
                users_collection,
                [("email", ASCENDING)],
                {
                    "name": "email_unique_if_string",
                    "unique": True,
                    "partialFilterExpression": {"email": {"$type": "string"}},
                },
            ),
            (
                users_collection,
                [("username", ASCENDING)],
                {
                    "name": "username_unique_if_string",
                    "unique": True,
                    "partialFilterExpression": {"username": {"$type": "string"}},
                },
            ),
            (
                users_collection,
                [("phone_number", ASCENDING)],
                {
                    "name": "phone_number_unique_if_string",
                    "unique": True,
                    "partialFilterExpression": {"phone_number": {"$type": "string"}},
                },
            ),
            (
                devices_collection,
                [("device_id", ASCENDING)],
                {
                    "name": "device_id_unique_if_string",
                    "unique": True,
                    "partialFilterExpression": {"device_id": {"$type": "string"}},
                },
            ),
            (
                shipments_collection,
                [("tracking_id", ASCENDING)],
                {
                    "name": "tracking_id_unique_if_string",
                    "unique": True,
                    "partialFilterExpression": {"tracking_id": {"$type": "string"}},
                },
            ),
            (
                shipments_collection,
                [("owner_id", ASCENDING)],
                {
                    "name": "shipment_owner_lookup",
                    "partialFilterExpression": {"owner_id": {"$type": "string"}},
                },
            ),
            (
                users_collection,
                [("role", ASCENDING)],
                {
                    "name": "user_role_lookup",
                    "partialFilterExpression": {"role": {"$type": "string"}},
                },
            ),
        ]

        for collection, keys, options in index_definitions:
            await collection.create_index(keys, **options)
        logger.info("database indexes prepared successfully")
    except PyMongoError:
        logger.exception("database index preparation failed")
        raise RuntimeError("Failed to prepare MongoDB indexes") from None


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
    except PyMongoError:
        logger.exception("default admin seeding failed")
        raise RuntimeError("Failed to seed default admin") from None


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
