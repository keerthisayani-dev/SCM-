from datetime import datetime

from fastapi.testclient import TestClient

import main
from backend.middleware.auth import get_current_user
from backend.routes import shipment_routes


class FakeInsertResult:
    inserted_id = "shipment-1"


class FakeShipmentsCollection:
    def __init__(self) -> None:
        self.inserted_documents: list[dict] = []

    async def insert_one(self, document: dict) -> FakeInsertResult:
        self.inserted_documents.append(document)
        return FakeInsertResult()


async def _skip_startup_task() -> None:
    return None


def test_authenticated_user_can_create_shipment(monkeypatch) -> None:
    fake_collection = FakeShipmentsCollection()
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)
    monkeypatch.setattr(shipment_routes, "shipments_collection", fake_collection)
    monkeypatch.setattr(shipment_routes, "generate_tracking_id", lambda: "SCM-ABC12345")

    async def current_customer() -> dict:
        return {
            "uid": "customer-123",
            "username": "customer",
            "email": "customer@example.com",
            "role": "user",
        }

    main.app.dependency_overrides[get_current_user] = current_customer

    with TestClient(main.app) as client:
        response = client.post(
            "/api/shipments",
            json={
                "sender": "Alice",
                "receiver": "Bob",
                "origin": "Chennai",
                "destination": "Bengaluru",
                "weight_kg": 12.5,
                "expected_delivery": "2030-01-15T10:30:00Z",
            },
        )

    main.app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json()["tracking_id"] == "SCM-ABC12345"
    assert response.json()["status"] == "PENDING"
    assert response.json()["owner_id"] == "customer-123"
    assert fake_collection.inserted_documents[0]["tracking_id"] == "SCM-ABC12345"
    assert fake_collection.inserted_documents[0]["status"] == "PENDING"
    assert fake_collection.inserted_documents[0]["owner_id"] == "customer-123"
    assert isinstance(datetime.fromisoformat(response.json()["created_at"].replace("Z", "+00:00")), datetime)


def test_client_cannot_spoof_server_generated_shipment_fields(monkeypatch) -> None:
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)

    async def current_customer() -> dict:
        return {
            "uid": "customer-123",
            "username": "customer",
            "email": "customer@example.com",
            "role": "user",
        }

    main.app.dependency_overrides[get_current_user] = current_customer

    with TestClient(main.app) as client:
        response = client.post(
            "/api/shipments",
            json={
                "sender": "Alice",
                "receiver": "Bob",
                "origin": "Chennai",
                "destination": "Bengaluru",
                "weight_kg": 12.5,
                "expected_delivery": "2030-01-15T10:30:00Z",
                "tracking_id": "SCM-SPOOFED",
                "status": "DELIVERED",
                "owner_id": "attacker-1",
            },
        )

    main.app.dependency_overrides.clear()

    assert response.status_code == 422
