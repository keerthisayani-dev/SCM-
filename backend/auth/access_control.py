from fastapi import Depends, HTTPException, status

from backend.middleware.auth import get_current_user
from backend.models.user_model import RoleEnum


ROLE_HIERARCHY: dict[RoleEnum, int] = {
    RoleEnum.USER: 1,
    RoleEnum.ADMIN: 2,
    RoleEnum.SUPER_ADMIN: 3,
}


def _normalize_role(role: str | RoleEnum | None) -> RoleEnum | None:
    if isinstance(role, RoleEnum):
        return role
    if role is None:
        return None
    try:
        return RoleEnum(role)
    except ValueError:
        return None


def role_allows(user_role: str | RoleEnum | None, required_role: RoleEnum) -> bool:
    normalized_role = _normalize_role(user_role)
    if normalized_role is None:
        return False
    return ROLE_HIERARCHY[normalized_role] >= ROLE_HIERARCHY[required_role]


def require_role(required_role: RoleEnum | str):
    normalized_required_role = _normalize_role(required_role)
    if normalized_required_role is None:
        raise ValueError(f"Unsupported role dependency: {required_role}")

    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if not role_allows(current_user.get("role"), normalized_required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )
        return current_user

    return role_checker


require_admin = require_role(RoleEnum.ADMIN)
