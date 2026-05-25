from datetime import datetime, timezone
import logging
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

from backend.config import get_settings
from backend.database.mongo import shipments_collection
from backend.models.shipment_model import ShipmentCreate, ShipmentInDB, ShipmentOut, ShipmentStatus, ShipmentUpdate

settings = get_settings()
logger = logging.getLogger(__name__)

router = APIRouter()


def generate_tracking_id() -> str:
    return f"{settings.shipment_tracking_prefix}{uuid4().hex[:8].upper()}"


def _active_shipments_filter() -> dict[str, dict[str, bool]]:
    return {"is_deleted": {"$ne": True}}


def _active_shipment_filter(tracking_id: str) -> dict[str, object]:
    return {"tracking_id": tracking_id, "is_deleted": {"$ne": True}}


@router.post("/shipments", response_model=ShipmentOut, status_code=status.HTTP_201_CREATED, summary="Create shipment")
async def create_shipment(payload: ShipmentCreate) -> ShipmentOut:
    for attempt in range(3):
        now = datetime.now(timezone.utc)
        shipment = ShipmentInDB(
            uid=str(uuid4()),
            tracking_id=generate_tracking_id(),
            shipment_number=payload.shipment_number,
            container_number=payload.container_number,
            route_details=payload.route_details,
            goods_type=payload.goods_type,
            device_id=payload.device_id,
            expected_delivery_date=payload.expected_delivery_date,
            po_number=payload.po_number,
            delivery_number=payload.delivery_number,
            ndc_number=payload.ndc_number,
            batch_id=payload.batch_id,
            serial_number_of_goods=payload.serial_number_of_goods,
            shipment_description=payload.shipment_description,
            status=ShipmentStatus.PENDING,
            created_at=now,
            updated_at=now,
            is_deleted=False,
            deleted_at=None,
        )

        try:
            logger.info(
                "shipment creation requested",
                extra={"tracking_id": shipment.tracking_id, "attempt": attempt + 1},
            )
            await shipments_collection.insert_one(shipment.model_dump())
            logger.info(
                "shipment created successfully",
                extra={"tracking_id": shipment.tracking_id},
            )
            return ShipmentOut(**shipment.model_dump())
        except DuplicateKeyError:
            logger.warning(
                "shipment tracking id collision encountered",
                extra={"tracking_id": shipment.tracking_id, "attempt": attempt + 1},
            )
            continue
        except PyMongoError as exc:
            logger.exception("shipment creation failed due to database error")
            raise HTTPException(status_code=500, detail="Database error occurred while creating the shipment") from exc

    raise HTTPException(status_code=500, detail="Could not generate a unique tracking ID")


@router.get("/shipments", response_model=list[ShipmentOut], summary="List shipments")
async def list_shipments() -> list[ShipmentOut]:
    try:
        logger.info("shipment list requested")
        shipments = await shipments_collection.find(_active_shipments_filter(), {"_id": 0}).to_list(length=500)
        return [ShipmentOut(**shipment) for shipment in shipments]
    except PyMongoError as exc:
        logger.exception("shipment listing failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while listing shipments") from exc


@router.get("/shipments/{tracking_id}", response_model=ShipmentOut, summary="Get shipment")
async def get_shipment(tracking_id: str) -> ShipmentOut:
    try:
        logger.info("shipment lookup requested", extra={"tracking_id": tracking_id})
        shipment = await shipments_collection.find_one(_active_shipment_filter(tracking_id), {"_id": 0})
    except PyMongoError as exc:
        logger.exception("shipment lookup failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while fetching the shipment") from exc

    if shipment is None:
        logger.warning("shipment lookup failed because shipment was not found", extra={"tracking_id": tracking_id})
        raise HTTPException(status_code=404, detail="Shipment not found")

    return ShipmentOut(**shipment)


@router.patch("/shipments/{tracking_id}", response_model=ShipmentOut, summary="Update shipment")
async def update_shipment(
    tracking_id: str,
    payload: ShipmentUpdate,
) -> ShipmentOut:
    update_data = payload.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided for update")
    update_data["updated_at"] = datetime.now(timezone.utc)

    try:
        logger.info(
            "shipment update requested",
            extra={"tracking_id": tracking_id, "fields": sorted(update_data)},
        )
        shipment = await shipments_collection.find_one_and_update(
            _active_shipment_filter(tracking_id),
            {"$set": update_data},
            projection={"_id": 0},
            return_document=ReturnDocument.AFTER,
        )
    except PyMongoError as exc:
        logger.exception("shipment update failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while updating the shipment") from exc

    if shipment is None:
        logger.warning("shipment update failed because shipment was not found", extra={"tracking_id": tracking_id})
        raise HTTPException(status_code=404, detail="Shipment not found")

    return ShipmentOut(**shipment)


@router.delete("/shipments/{tracking_id}", summary="Delete shipment")
async def delete_shipment(tracking_id: str) -> dict[str, str]:
    deleted_at = datetime.now(timezone.utc)
    try:
        logger.info("shipment deletion requested", extra={"tracking_id": tracking_id})
        result = await shipments_collection.update_one(
            _active_shipment_filter(tracking_id),
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": deleted_at,
                    "updated_at": deleted_at,
                }
            },
        )
    except PyMongoError as exc:
        logger.exception("shipment deletion failed due to database error")
        raise HTTPException(status_code=500, detail="Database error occurred while deleting the shipment") from exc

    if result.matched_count == 0:
        logger.warning("shipment deletion failed because shipment was not found", extra={"tracking_id": tracking_id})
        raise HTTPException(status_code=404, detail="Shipment not found")

    return {"message": "Shipment deleted successfully"}
