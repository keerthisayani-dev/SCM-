import logging
import time

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo.errors import PyMongoError

from backend.config import (
    AUTH_EVENTS_COLLECTION_NAME,
    DEVICES_COLLECTION_NAME,
    LOGIN_DETAILS_COLLECTION_NAME,
    MONGODB_DB_NAME,
    MONGODB_URI,
    SHIPMENTS_COLLECTION_NAME,
    USERS_COLLECTION_NAME,
)

logger = logging.getLogger(__name__)

DATABASE_NAME = MONGODB_DB_NAME

mongo_client: AsyncIOMotorClient = AsyncIOMotorClient(MONGODB_URI)
database: AsyncIOMotorDatabase = mongo_client[DATABASE_NAME]
db: AsyncIOMotorDatabase = database

users_collection: AsyncIOMotorCollection = database[USERS_COLLECTION_NAME]
auth_events_collection: AsyncIOMotorCollection = database[AUTH_EVENTS_COLLECTION_NAME]
login_details_collection: AsyncIOMotorCollection = database[LOGIN_DETAILS_COLLECTION_NAME]
devices_collection: AsyncIOMotorCollection = database[DEVICES_COLLECTION_NAME]
shipments_collection: AsyncIOMotorCollection = database[SHIPMENTS_COLLECTION_NAME]


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


async def get_db_health() -> dict[str, object]:
    try:
        health = {
            "status": "up",
            "database": DATABASE_NAME,
            "collection": USERS_COLLECTION_NAME,
            "latency_ms": await check_database_connection(),
        }
        logger.info("database health check returned up")
        return health
    except RuntimeError as exc:
        logger.warning("database health check returned down")
        return {
            "status": "down",
            "database": DATABASE_NAME,
            "collection": USERS_COLLECTION_NAME,
            "detail": str(exc),
        }
