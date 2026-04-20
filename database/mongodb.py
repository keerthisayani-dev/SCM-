import os

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase


def create_client() -> AsyncIOMotorClient:
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        raise RuntimeError(
            "MONGODB_URI is not set. Add it to your environment or .env file."
        )

    return AsyncIOMotorClient(mongo_uri)


def get_database(client: AsyncIOMotorClient) -> AsyncIOMotorDatabase:
    db_name = os.getenv("MONGODB_DB_NAME", "scm_project")
    return client[db_name]
