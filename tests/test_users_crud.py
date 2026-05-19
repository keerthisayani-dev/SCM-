import asyncio
from datetime import datetime, timezone

from bson import ObjectId
from fastapi.testclient import TestClient
from pymongo import ASCENDING

import main
from backend.database import mongo
from backend.routes.auth import user_auth_routes


class FakeInsertResult:
    def __init__(self, inserted_id: ObjectId) -> None:
        self.inserted_id = inserted_id


class FakeUsersCollection:
    def __init__(self, documents: list[dict] | None = None) -> None:
        self.documents = documents or []

    async def find_one(self, filter_query: dict, projection: dict | None = None) -> dict | None:
        document = None
        if "email" in filter_query:
            document = next((item for item in self.documents if item.get("email") == filter_query["email"]), None)
        elif "_id" in filter_query:
            document = next((item for item in self.documents if item.get("_id") == filter_query["_id"]), None)

        if document is None:
            return None
        if projection is None:
            return dict(document)

        included_fields = [field for field, value in projection.items() if value == 1]
        if included_fields:
            return {field: document[field] for field in included_fields if field in document}

        return {field: value for field, value in document.items() if projection.get(field) != 0}

    async def insert_one(self, document: dict) -> FakeInsertResult:
        inserted_id = ObjectId()
        stored_document = {"_id": inserted_id, **document}
        self.documents.append(stored_document)
        return FakeInsertResult(inserted_id)


class FakeIndexedCollection:
    def __init__(self) -> None:
        self.calls: list[tuple[list[tuple[str, int]], dict]] = []

    async def create_index(self, keys: list[tuple[str, int]], **kwargs) -> str:
        self.calls.append((keys, kwargs))
        return kwargs.get("name", "index")


async def _skip_startup_task() -> None:
    return None


def test_post_users_creates_user_and_second_post_returns_409(monkeypatch) -> None:
    fake_collection = FakeUsersCollection()
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)
    monkeypatch.setattr(user_auth_routes, "users_collection", fake_collection)

    with TestClient(main.app) as client:
        first_response = client.post(
            "/api/users",
            json={"name": "Alice", "email": "alice@example.com", "password": "password123"},
        )
        second_response = client.post(
            "/api/users",
            json={"name": "Alice", "email": "alice@example.com", "password": "password123"},
        )

    assert first_response.status_code == 201
    first_body = first_response.json()
    assert first_body["name"] == "Alice"
    assert first_body["email"] == "alice@example.com"
    assert "id" in first_body
    assert "_id" not in first_body
    assert "password" not in first_body
    assert isinstance(datetime.fromisoformat(first_body["created_at"].replace("Z", "+00:00")), datetime)

    assert second_response.status_code == 409
    assert second_response.json()["detail"] == "Email is already registered"


def test_get_user_returns_user_without_password_or_internal_id(monkeypatch) -> None:
    user_id = ObjectId()
    fake_collection = FakeUsersCollection(
        [
            {
                "_id": user_id,
                "name": "Alice",
                "email": "alice@example.com",
                "password": "password123",
                "created_at": datetime(2030, 1, 1, tzinfo=timezone.utc),
            }
        ]
    )
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)
    monkeypatch.setattr(user_auth_routes, "users_collection", fake_collection)

    with TestClient(main.app) as client:
        response = client.get(f"/api/users/{user_id}")

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user_id),
        "name": "Alice",
        "email": "alice@example.com",
        "created_at": "2030-01-01T00:00:00Z",
    }


def test_get_user_rejects_invalid_object_id(monkeypatch) -> None:
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)

    with TestClient(main.app) as client:
        response = client.get("/api/users/not-a-valid-object-id")

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid user id"


def test_prepare_database_keeps_unique_email_index_on_users(monkeypatch) -> None:
    fake_users_collection = FakeIndexedCollection()
    fake_devices_collection = FakeIndexedCollection()
    fake_shipments_collection = FakeIndexedCollection()

    async def fake_check_database_connection() -> float:
        return 1.23

    monkeypatch.setattr(mongo, "check_database_connection", fake_check_database_connection)
    monkeypatch.setattr(mongo, "users_collection", fake_users_collection)
    monkeypatch.setattr(mongo, "devices_collection", fake_devices_collection)
    monkeypatch.setattr(mongo, "shipments_collection", fake_shipments_collection)

    asyncio.run(mongo.prepare_database())

    assert (
        [("email", ASCENDING)],
        {
            "name": "email_unique_if_string",
            "unique": True,
            "partialFilterExpression": {"email": {"$type": "string"}},
        },
    ) in fake_users_collection.calls
