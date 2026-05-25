from fastapi import Depends, HTTPException, status

from backend.middleware.auth import get_current_user
from backend.models.user_model import RoleEnum

Permission = str

VIEW_INVENTORY: Permission = "view_inventory"
EDIT_INVENTORY: Permission = "edit_inventory"
MANAGE_ADMINS: Permission = "manage_admins"
DELETE_SYSTEM_LOGS: Permission = "delete_system_logs"

ROLE_PERMISSIONS: dict[RoleEnum, set[Permission]] = {
    RoleEnum.USER: {
        VIEW_INVENTORY,
    },
    RoleEnum.ADMIN: {
        VIEW_INVENTORY,
        EDIT_INVENTORY,
    },
    RoleEnum.SUPER_ADMIN: {
        VIEW_INVENTORY,
        EDIT_INVENTORY,
        MANAGE_ADMINS,
        DELETE_SYSTEM_LOGS,
    },
}

ROLE_ACCESS_REQUIREMENTS: dict[RoleEnum, set[Permission]] = {
    RoleEnum.USER: {
        VIEW_INVENTORY,
    },
    RoleEnum.ADMIN: {
        EDIT_INVENTORY,
    },
    RoleEnum.SUPER_ADMIN: {
        MANAGE_ADMINS,
    },
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

    user_permissions = ROLE_PERMISSIONS.get(normalized_role, set())
    required_permissions = ROLE_ACCESS_REQUIREMENTS.get(required_role, set())
    return required_permissions.issubset(user_permissions)


def check_permission(user_role: str | RoleEnum | None, required_action: Permission) -> bool:
    normalized_role = _normalize_role(user_role)
    if normalized_role is None:
        return False
    return required_action in ROLE_PERMISSIONS.get(normalized_role, set())


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


def require_permission(required_action: Permission):
    async def permission_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if not check_permission(current_user.get("role"), required_action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You do not have permission to perform '{required_action}'.",
            )
        return current_user

    return permission_checker


require_admin = require_role(RoleEnum.ADMIN)
require_super_admin = require_role(RoleEnum.SUPER_ADMIN)
