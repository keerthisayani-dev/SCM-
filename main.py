import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
import uvicorn

from back_end.routes.user import build_auth_router
from database.mongodb import create_client, get_database
from database.user_repository import UserRepository

load_dotenv()
API_KEY_HEADER_NAME = "x-api-key"
APP_API_KEY = os.getenv("APP_API_KEY")


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = create_client()
    await client.admin.command("ping")

    database = get_database(client)
    user_repository = UserRepository(database["users"])
    await user_repository.create_indexes()

    app.state.mongo_client = client
    app.state.user_repository = user_repository

    try:
        yield
    finally:
        client.close()


app = FastAPI(title="Signup and Login API", lifespan=lifespan)


def get_user_repository(request: Request) -> UserRepository:
    return request.app.state.user_repository


def verify_api_key(
    api_key: str | None = Header(default=None, alias=API_KEY_HEADER_NAME),
) -> None:
    if APP_API_KEY and api_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


app.include_router(build_auth_router(get_user_repository, verify_api_key))


@app.get("/")
async def home():
    return {
        "message": "Signup and Login API is running",
        "security": {
            "api_key_header": API_KEY_HEADER_NAME,
            "api_key_required": bool(APP_API_KEY),
            "authorization_header": "Bearer <jwt_token>",
        },
        "endpoints": {
            "health": "GET /health",
            "signup": "POST /signup",
            "login": "POST /login",
            "me": "GET /me",
            "verify_password": "POST /verify-password",
            "change_password": "POST /change-password",
            "docs": "/docs",
        },
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
