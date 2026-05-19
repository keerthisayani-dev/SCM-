from functools import lru_cache

from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field(alias="ENVIRONMENT", default="development")
    app_host: str = Field(alias="APP_HOST", default="127.0.0.1")
    port: int = Field(alias="PORT", default=8001)
    app_title: str = Field(alias="APP_TITLE", default="SCMXPertLite")
    app_description: str = Field(
        alias="APP_DESCRIPTION",
        default="Backend services for SCMXPertLite.",
    )
    app_version: str = Field(alias="APP_VERSION", default="0.1.0")
    app_reload: bool = Field(alias="APP_RELOAD", default=True)
    frontend_origins: Annotated[list[str], NoDecode] = Field(
        alias="FRONTEND_ORIGINS",
        default_factory=lambda: ["http://127.0.0.1:8001"],
    )

    mongodb_uri: str = Field(alias="MONGODB_URI")
    mongodb_db_name: str = Field(alias="MONGODB_DB_NAME")
    users_collection_name: str = Field(alias="USERS_COLLECTION_NAME", default="users")
    devices_collection_name: str = Field(alias="DEVICES_COLLECTION_NAME", default="devices")
    shipments_collection_name: str = Field(alias="SHIPMENTS_COLLECTION_NAME", default="shipments")

    jwt_secret_key: str = Field(alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(alias="JWT_ALGORITHM", default="HS256")
    jwt_expire_minutes: int = Field(alias="JWT_EXPIRE_MINUTES", default=30)
    bcrypt_rounds: int = Field(alias="BCRYPT_ROUNDS", default=12)

    admin_email: str = Field(alias="ADMIN_EMAIL")
    admin_password: str = Field(alias="ADMIN_PASSWORD")
    admin_username: str = Field(alias="ADMIN_USERNAME")
    admin_phone_number: str = Field(alias="ADMIN_PHONE_NUMBER")

    @field_validator("frontend_origins", mode="before")
    @classmethod
    def parse_frontend_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, list):
            return value
        return [origin.strip() for origin in value.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
