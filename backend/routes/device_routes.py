from datetime import datetime, timezone
import logging
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

from backend.database.mongo import devices_collection
from backend.middleware.auth import get_current_user
from backend.models.device_model import DeviceCreate, DeviceOut, DeviceUpdate

logger = logging.getLogger(__name__)

router = APIRouter()


def _device_response(document: dict) -> DeviceOut:
    return DeviceOut(
        device_id=document["device_id"],
        battery_level=document["battery_level"],
        first_sensor_temperature=document["first_sensor_temperature"],
        route_from=document["route_from"],
        route_to=document["route_to"],
        timestamp=document["timestamp"],
        created_at=document.get("created_at"),
        updated_at=document.get("updated_at"),
    )


@router.post("/devices", response_model=DeviceOut, status_code=status.HTTP_201_CREATED, summary="Create device")
async def create_device(
    payload: DeviceCreate,
    current_user: dict = Depends(get_current_user),
) -> DeviceOut:
    document = payload.model_dump()
    document["uid"] = str(uuid4())
    now = datetime.now(timezone.utc)
    document["created_at"] = now
    document["updated_at"] = now

    try:
        logger.info("device creation requested", extra={"user_id": current_user["uid"], "device_id": payload.device_id})
        await devices_collection.insert_one(document)
        logger.info("device created successfully", extra={"user_id": current_user["uid"], "device_id": payload.device_id})
        return _device_response(document)
    except DuplicateKeyError as exc:
        logger.warning("device creation rejected due to duplicate device id", extra={"device_id": payload.device_id})
        raise HTTPException(status_code=409, detail="Device ID already exists") from exc
    except PyMongoError as exc:
        logger.exception("device creation failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while creating the device") from exc


@router.get("/devices", response_model=list[DeviceOut], summary="List devices")
async def list_devices(current_user: dict = Depends(get_current_user)) -> list[DeviceOut]:
    try:
        logger.info("device list requested", extra={"user_id": current_user["uid"]})
        devices = await devices_collection.find({}, {"_id": 0}).to_list(length=500)
        return [_device_response(device) for device in devices]
    except PyMongoError as exc:
        logger.exception("device listing failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while listing devices") from exc


@router.get("/devices/{device_id}", response_model=DeviceOut, summary="Get device")
async def get_device(device_id: str, current_user: dict = Depends(get_current_user)) -> DeviceOut:
    try:
        logger.info("device lookup requested", extra={"user_id": current_user["uid"], "device_id": device_id})
        device = await devices_collection.find_one({"device_id": device_id}, {"_id": 0})
    except PyMongoError as exc:
        logger.exception("device lookup failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while fetching the device") from exc

    if device is None:
        logger.warning("device lookup failed because device was not found", extra={"device_id": device_id})
        raise HTTPException(status_code=404, detail="Device not found")

    return _device_response(device)


@router.patch("/devices/{device_id}", response_model=DeviceOut, summary="Update device")
async def update_device(
    device_id: str,
    payload: DeviceUpdate,
    current_user: dict = Depends(get_current_user),
) -> DeviceOut:
    update_data = payload.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    update_data["updated_at"] = datetime.now(timezone.utc)

    try:
        logger.info(
            "device update requested",
            extra={"user_id": current_user["uid"], "device_id": device_id, "fields": sorted(update_data)},
        )
        device = await devices_collection.find_one_and_update(
            {"device_id": device_id},
            {"$set": update_data},
            projection={"_id": 0},
            return_document=ReturnDocument.AFTER,
        )
    except PyMongoError as exc:
        logger.exception("device update failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while updating the device") from exc

    if device is None:
        logger.warning("device update failed because device was not found", extra={"device_id": device_id})
        raise HTTPException(status_code=404, detail="Device not found")

    return _device_response(device)


@router.delete("/devices/{device_id}", summary="Delete device")
async def delete_device(device_id: str, current_user: dict = Depends(get_current_user)) -> dict[str, str]:
    try:
        logger.info("device deletion requested", extra={"user_id": current_user["uid"], "device_id": device_id})
        result = await devices_collection.delete_one({"device_id": device_id})
    except PyMongoError as exc:
        logger.exception("device deletion failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while deleting the device") from exc

    if result.deleted_count == 0:
        logger.warning("device deletion failed because device was not found", extra={"device_id": device_id})
        raise HTTPException(status_code=404, detail="Device not found")

    return {"message": "Device deleted successfully"}
