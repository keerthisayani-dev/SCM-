from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pymongo.errors import PyMongoError

from backend.config import OAUTH_TOKEN_URL
from backend.database.mongo import users_collection
from backend.utils.auth import ACCESS_TOKEN_ALGORITHM, ACCESS_TOKEN_SECRET

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=OAUTH_TOKEN_URL,
    scheme_name="OAuth2PasswordBearer",
    auto_error=False,
    description="Use your email in the Swagger 'username' field and your account password to authorize.",
)


def _credentials_exception(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
) -> dict:
    if token is None:
        raise _credentials_exception(
            "Missing bearer token. Login first, then use Authorize in Swagger with your email and password.",
        )

    try:
        payload = jwt.decode(
            token,
            ACCESS_TOKEN_SECRET,
            algorithms=[ACCESS_TOKEN_ALGORITHM],
        )
    except JWTError as exc:
        raise _credentials_exception("Invalid or expired bearer token.") from exc

    user_id = payload.get("sub")
    if not user_id:
        raise _credentials_exception("Invalid bearer token payload.")

    try:
        user = await users_collection.find_one({"uid": user_id})
    except PyMongoError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        ) from exc
    if user is None:
        raise _credentials_exception("Authenticated user was not found.")
    return user
