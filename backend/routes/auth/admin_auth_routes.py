from datetime import datetime, timezone
import logging

from fastapi import APIRouter, Depends, HTTPException
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from backend.auth.access_control import require_admin
from backend.database.mongo import users_collection
from backend.models.user_model import AdminUserSummary, RoleEnum, UserRoleUpdateRequest

logger = logging.getLogger(__name__)

router = APIRouter()


def _build_admin_user_summary(user: dict) -> AdminUserSummary:
    return AdminUserSummary(
        id=user["uid"],
        username=user["username"],
        email=user["email"],
        role=RoleEnum(user.get("role", RoleEnum.USER.value)),
        is_active=user.get("is_active", True),
    )


@router.get("/admin/users", response_model=list[AdminUserSummary], summary="List users")
async def list_users(current_user: dict = Depends(require_admin)) -> list[AdminUserSummary]:
    try:
        logger.info("admin user list requested", extra={"user_id": current_user["uid"]})
        users = await users_collection.find({}, {"_id": 0, "hashed_password": 0}).to_list(length=500)
        return [_build_admin_user_summary(user) for user in users]
    except PyMongoError as exc:
        logger.exception("listing users failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while listing users") from exc


@router.patch("/admin/users/{user_id}/role", response_model=AdminUserSummary, summary="Update user role")
async def update_user_role(
    user_id: str,
    payload: UserRoleUpdateRequest,
    current_user: dict = Depends(require_admin),
) -> AdminUserSummary:
    try:
        logger.info(
            "admin role update requested",
            extra={"admin_user_id": current_user["uid"], "target_user_id": user_id, "new_role": payload.role.value},
        )
        result = await users_collection.find_one_and_update(
            {"uid": user_id},
            {
                "$set": {
                    "role": payload.role.value,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            return_document=ReturnDocument.AFTER,
        )
    except PyMongoError as exc:
        logger.exception("updating user role failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while updating the role") from exc

    if result is None:
        logger.warning("role update failed because user was not found", extra={"target_user_id": user_id})
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("user role updated successfully", extra={"target_user_id": user_id, "new_role": payload.role.value})
    return _build_admin_user_summary(result)


@router.delete("/admin/users/{user_id}", summary="Delete user")
async def delete_user(
    user_id: str,
    current_user: dict = Depends(require_admin),
) -> dict[str, str]:
    try:
        logger.info("admin delete user requested", extra={"admin_user_id": current_user["uid"], "target_user_id": user_id})
        result = await users_collection.delete_one({"uid": user_id})
    except PyMongoError as exc:
        logger.exception("deleting user failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while deleting the user") from exc

    if result.deleted_count == 0:
        logger.warning("delete user failed because user was not found", extra={"target_user_id": user_id})
        raise HTTPException(status_code=404, detail="User not found")
    logger.info("user deleted successfully", extra={"target_user_id": user_id})
    return {"message": "User deleted successfully"}
