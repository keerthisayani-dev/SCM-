from datetime import date, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    sender: str | None = Field(default=None, min_length=1)
    receiver: str | None = Field(default=None, min_length=1)
    origin: str | None = Field(default=None, min_length=1)
    destination: str | None = Field(default=None, min_length=1)
    weight_kg: float | None = None
    expected_delivery: datetime | None = None

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
        "sender",
        "receiver",
        "origin",
        "destination",
    )
    @classmethod
    def validate_non_blank_text(cls, value: str | None) -> str | None:
        return _validate_optional_text(value)

    @model_validator(mode="after")
    def validate_shipment_shape(self) -> "ShipmentCreate":
        has_current_shape = all(
            value is not None
            for value in (
                self.shipment_number,
                self.container_number,
                self.route_details,
                self.goods_type,
                self.device_id,
                self.expected_delivery_date,
                self.po_number,
                self.delivery_number,
                self.ndc_number,
                self.batch_id,
                self.serial_number_of_goods,
                self.shipment_description,
            )
        )
        has_legacy_shape = all(
            value is not None
            for value in (
                self.sender,
                self.receiver,
                self.origin,
                self.destination,
                self.weight_kg,
                self.expected_delivery,
            )
        )
        if not (has_current_shape or has_legacy_shape):
            raise ValueError(
                "Provide either the current shipment fields or the legacy sender/receiver/origin/destination fields."
            )
        return self


class ShipmentBase(ShipmentCreate):
    pass


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
    sender: str | None = Field(default=None, min_length=1)
    receiver: str | None = Field(default=None, min_length=1)
    origin: str | None = Field(default=None, min_length=1)
    destination: str | None = Field(default=None, min_length=1)
    weight_kg: float | None = None
    expected_delivery: datetime | None = None

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
        "sender",
        "receiver",
        "origin",
        "destination",
    )
    @classmethod
    def validate_optional_non_blank_text(cls, value: str | None) -> str | None:
        return _validate_optional_text(value)


class ShipmentOut(ShipmentBase):
    tracking_id: str
    status: ShipmentStatus
    created_at: datetime
    updated_at: datetime


class ShipmentInDB(ShipmentOut):
    model_config = ConfigDict(extra="forbid")
    uid: str
    is_deleted: bool = False
    deleted_at: datetime | None = None
