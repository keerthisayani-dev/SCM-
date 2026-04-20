import os
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt


JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-me-in-env")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, stored_password: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_password.encode("utf-8"),
    )


def create_access_token(email: str) -> str:
    issued_at = datetime.now(UTC)
    expire_at = issued_at + timedelta(minutes=JWT_EXPIRY_MINUTES)
    payload = {
        "sub": email,
        "iat": issued_at,
        "exp": expire_at,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
