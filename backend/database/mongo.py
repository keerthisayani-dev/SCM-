import os
import time
from pathlib import Path

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ASCENDING

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=ENV_PATH)


def _read_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise ValueError(f"{name} is required in the environment.")
    return value


MONGO_URI = _read_env("MONGODB_URI")
DATABASE_NAME = _read_env("MONGODB_DB_NAME")

mongo_client = AsyncIOMotorClient(MONGO_URI)
database: AsyncIOMotorDatabase = mongo_client[DATABASE_NAME]

users_collection: AsyncIOMotorCollection = database["users"]


async def ping_database() -> float:
    started = time.perf_counter()
    await mongo_client.admin.command("ping")
    return round((time.perf_counter() - started) * 1000, 2)


async def prepare_database() -> None:
    await ping_database()
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


async def get_db_health() -> dict[str, object]:
    return {
        "status": "up",
        "database": DATABASE_NAME,
        "latency_ms": await ping_database(),
    }
