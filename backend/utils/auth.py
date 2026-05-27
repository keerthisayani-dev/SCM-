import logging
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import jwt

from backend.config import BCRYPT_ROUNDS, JWT_ALGORITHM, JWT_EXPIRE_MINUTES, JWT_SECRET_KEY

logger = logging.getLogger(__name__)
ACCESS_TOKEN_SECRET = JWT_SECRET_KEY
ACCESS_TOKEN_ALGORITHM = JWT_ALGORITHM
ACCESS_TOKEN_TTL_MINUTES = JWT_EXPIRE_MINUTES


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        password_bytes = plain_password.encode("utf-8")
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except (AttributeError, ValueError) as exc:
        logger.warning("stored password hash is invalid", exc_info=exc)
        return False


def create_access_token(user_id: str, email: str, role: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)
    payload = {"sub": user_id, "email": email, "role": role, "exp": expires_at}
    return jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm=ACCESS_TOKEN_ALGORITHM)
