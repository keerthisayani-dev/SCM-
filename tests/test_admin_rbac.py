from fastapi.testclient import TestClient

import main
from backend.middleware.auth import get_current_user
from backend.routes.auth import admin_auth_routes


class FakeCursor:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = documents

    async def to_list(self, length: int) -> list[dict]:
        return self.documents[:length]


class FakeUsersCollection:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = documents

    def find(self, *args, **kwargs) -> FakeCursor:
        return FakeCursor(self.documents)


async def _skip_startup_task() -> None:
    return None


def test_customer_gets_403_on_admin_users(monkeypatch) -> None:
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)

    async def current_customer() -> dict:
        return {
            "uid": "customer-1",
            "username": "customer",
            "email": "customer@example.com",
            "role": "user",
        }

    main.app.dependency_overrides[get_current_user] = current_customer

    with TestClient(main.app) as client:
        response = client.get("/api/admin/users")

    main.app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json()["detail"] == "You do not have permission to access this resource."


def test_admin_gets_200_on_admin_users(monkeypatch) -> None:
    monkeypatch.setattr(main, "prepare_database", _skip_startup_task)
    monkeypatch.setattr(main, "seed_default_admin", _skip_startup_task)
    monkeypatch.setattr(
        admin_auth_routes,
        "users_collection",
        FakeUsersCollection(
            [
                {
                    "uid": "admin-1",
                    "username": "scm_admin",
                    "email": "admin@example.com",
                    "role": "admin",
                    "is_active": True,
                }
            ]
        ),
    )

    async def current_admin() -> dict:
        return {
            "uid": "admin-1",
            "username": "scm_admin",
            "email": "admin@example.com",
            "role": "admin",
        }

    main.app.dependency_overrides[get_current_user] = current_admin

    with TestClient(main.app) as client:
        response = client.get("/api/admin/users")

    main.app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": "admin-1",
            "username": "scm_admin",
            "email": "admin@example.com",
            "role": "admin",
            "is_active": True,
        }
    ]
