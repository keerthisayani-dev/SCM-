from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ShipmentStatus(str, Enum):
    PENDING = "PENDING"
    IN_TRANSIT = "IN_TRANSIT"
    OUT_FOR_DELIVERY = "OUT_FOR_DELIVERY"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"


class ShipmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: str = Field(..., min_length=1)
    receiver: str = Field(..., min_length=1)
    origin: str = Field(..., min_length=1)
    destination: str = Field(..., min_length=1)
    weight_kg: float = Field(..., gt=0)
    expected_delivery: datetime

    @field_validator("sender", "receiver", "origin", "destination")
    @classmethod
    def validate_non_blank_text(cls, value: str) -> str:
        cleaned_value = value.strip()
        if not cleaned_value:
            raise ValueError("Field must contain at least one non-space character.")
        return cleaned_value


class ShipmentOut(BaseModel):
    tracking_id: str
    sender: str
    receiver: str
    origin: str
    destination: str
    weight_kg: float
    expected_delivery: datetime
    status: ShipmentStatus
    owner_id: str
    created_at: datetime


class ShipmentInDB(ShipmentOut):
    model_config = ConfigDict(extra="forbid")
