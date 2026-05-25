from datetime import date, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ShipmentStatus(str, Enum):
    PENDING = "PENDING"
    IN_TRANSIT = "IN_TRANSIT"
    OUT_FOR_DELIVERY = "OUT_FOR_DELIVERY"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"


def _validate_required_text(value: str) -> str:
    cleaned_value = value.strip()
    if not cleaned_value:
        raise ValueError("Field must contain at least one non-space character.")
    return cleaned_value


def _validate_optional_text(value: str | None) -> str | None:
    if value is None:
        return value
    return _validate_required_text(value)


class ShipmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shipment_number: str = Field(..., min_length=1)
    container_number: str = Field(..., min_length=1)
    route_details: str = Field(..., min_length=1)
    goods_type: str = Field(..., min_length=1)
    device_id: str = Field(..., min_length=1)
    expected_delivery_date: date
    po_number: str = Field(..., min_length=1)
    delivery_number: str = Field(..., min_length=1)
    ndc_number: str = Field(..., min_length=1)
    batch_id: str = Field(..., min_length=1)
    serial_number_of_goods: str = Field(..., min_length=1)
    shipment_description: str = Field(..., min_length=1)

    @field_validator(
        "shipment_number",
        "container_number",
        "route_details",
        "goods_type",
        "device_id",
        "po_number",
        "delivery_number",
        "ndc_number",
        "batch_id",
        "serial_number_of_goods",
        "shipment_description",
    )
    @classmethod
    def validate_non_blank_text(cls, value: str) -> str:
        return _validate_required_text(value)


class ShipmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shipment_number: str | None = Field(default=None, min_length=1)
    container_number: str | None = Field(default=None, min_length=1)
    route_details: str | None = Field(default=None, min_length=1)
    goods_type: str | None = Field(default=None, min_length=1)
    device_id: str | None = Field(default=None, min_length=1)
    expected_delivery_date: date | None = None
    po_number: str | None = Field(default=None, min_length=1)
    delivery_number: str | None = Field(default=None, min_length=1)
    ndc_number: str | None = Field(default=None, min_length=1)
    batch_id: str | None = Field(default=None, min_length=1)
    serial_number_of_goods: str | None = Field(default=None, min_length=1)
    shipment_description: str | None = Field(default=None, min_length=1)
    status: ShipmentStatus | None = None

    @field_validator(
        "shipment_number",
        "container_number",
        "route_details",
        "goods_type",
        "device_id",
        "po_number",
        "delivery_number",
        "ndc_number",
        "batch_id",
        "serial_number_of_goods",
        "shipment_description",
    )
    @classmethod
    def validate_optional_non_blank_text(cls, value: str | None) -> str | None:
        return _validate_optional_text(value)


class ShipmentOut(BaseModel):
    tracking_id: str
    shipment_number: str
    container_number: str
    route_details: str
    goods_type: str
    device_id: str
    expected_delivery_date: date
    po_number: str
    delivery_number: str
    ndc_number: str
    batch_id: str
    serial_number_of_goods: str
    shipment_description: str
    status: ShipmentStatus
    created_at: datetime
    updated_at: datetime


class ShipmentInDB(ShipmentOut):
    model_config = ConfigDict(extra="forbid")
    uid: str
    is_deleted: bool = False
    deleted_at: datetime | None = None
