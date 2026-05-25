from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    mongodb_uri: str = Field(alias="MONGODB_URI")
    mongodb_db_name: str = Field(alias="MONGODB_DB_NAME")
    users_collection_name: str = Field(alias="USERS_COLLECTION_NAME", default="users")
    devices_collection_name: str = Field(alias="DEVICES_COLLECTION_NAME", default="devices")
    shipments_collection_name: str = Field(alias="SHIPMENTS_COLLECTION_NAME", default="shipments")
    shipment_tracking_prefix: str = Field(alias="SHIPMENT_TRACKING_PREFIX", default="SCM-")

    jwt_secret_key: str = Field(alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(alias="JWT_ALGORITHM", default="HS256")
    jwt_expire_minutes: int = Field(alias="JWT_EXPIRE_MINUTES", default=30)
    oauth_token_url: str = Field(alias="OAUTH_TOKEN_URL", default="/api/auth/token")
    bcrypt_rounds: int = Field(alias="BCRYPT_ROUNDS", default=12)

    default_admin_uid: str = Field(alias="DEFAULT_ADMIN_UID", default="00000000-0000-0000-0000-000000000001")
    admin_email: str = Field(alias="ADMIN_EMAIL")
    admin_password: str = Field(alias="ADMIN_PASSWORD")
    admin_username: str = Field(alias="ADMIN_USERNAME")
    admin_phone_number: str = Field(alias="ADMIN_PHONE_NUMBER")

@lru_cache
def get_settings() -> Settings:
    return Settings()
