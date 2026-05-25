from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_required_text(value: str) -> str:
    cleaned_value = value.strip()
    if not cleaned_value:
        raise ValueError("Field must contain at least one non-space character.")
    return cleaned_value


def _validate_optional_text(value: str | None) -> str | None:
    if value is None:
        return value
    return _validate_required_text(value)


class DeviceBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1)
    battery_level: float = Field(..., ge=0, le=100)
    first_sensor_temperature: float
    route_from: str = Field(..., min_length=1)
    route_to: str = Field(..., min_length=1)
    timestamp: datetime

    @field_validator("device_id", "route_from", "route_to")
    @classmethod
    def validate_non_blank_text(cls, value: str) -> str:
        return _validate_required_text(value)


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    battery_level: float | None = Field(default=None, ge=0, le=100)
    first_sensor_temperature: float | None = None
    route_from: str | None = Field(default=None, min_length=1)
    route_to: str | None = Field(default=None, min_length=1)
    timestamp: datetime | None = None

    @field_validator("route_from", "route_to")
    @classmethod
    def validate_optional_non_blank_text(cls, value: str | None) -> str | None:
        return _validate_optional_text(value)


class DeviceOut(DeviceBase):
    created_at: datetime | None = None
    updated_at: datetime | None = None
