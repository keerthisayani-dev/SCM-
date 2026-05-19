from datetime import datetime, timezone
import logging
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError, PyMongoError

from backend.database.mongo import shipments_collection
from backend.middleware.auth import get_current_user
from backend.models.shipment_model import ShipmentCreate, ShipmentInDB, ShipmentOut, ShipmentStatus

logger = logging.getLogger(__name__)

router = APIRouter()


def generate_tracking_id() -> str:
    return f"SCM-{uuid4().hex[:8].upper()}"


@router.post("/shipments", response_model=ShipmentOut, status_code=status.HTTP_201_CREATED, summary="Create shipment")
async def create_shipment(
    payload: ShipmentCreate,
    current_user: dict = Depends(get_current_user),
) -> ShipmentOut:
    for attempt in range(3):
        shipment = ShipmentInDB(
            tracking_id=generate_tracking_id(),
            sender=payload.sender,
            receiver=payload.receiver,
            origin=payload.origin,
            destination=payload.destination,
            weight_kg=payload.weight_kg,
            expected_delivery=payload.expected_delivery,
            status=ShipmentStatus.PENDING,
            owner_id=current_user["uid"],
            created_at=datetime.now(timezone.utc),
        )

        try:
            logger.info(
                "shipment creation requested",
                extra={"owner_id": current_user["uid"], "tracking_id": shipment.tracking_id, "attempt": attempt + 1},
            )
            await shipments_collection.insert_one(shipment.model_dump())
            logger.info(
                "shipment created successfully",
                extra={"owner_id": current_user["uid"], "tracking_id": shipment.tracking_id},
            )
            return ShipmentOut(**shipment.model_dump())
        except DuplicateKeyError:
            logger.warning(
                "shipment tracking id collision encountered",
                extra={"owner_id": current_user["uid"], "tracking_id": shipment.tracking_id, "attempt": attempt + 1},
            )
            continue
        except PyMongoError as exc:
            logger.exception("shipment creation failed due to database error")
            raise HTTPException(status_code=500, detail="Database error occurred while creating the shipment") from exc

    raise HTTPException(status_code=500, detail="Could not generate a unique tracking ID")
