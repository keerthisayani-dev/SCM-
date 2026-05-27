from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    battery_level: float | None = Field(default=None, ge=0, le=100)
    first_sensor_temperature: float | None = None
    route_from: str | None = Field(default=None, min_length=1)
    route_to: str | None = Field(default=None, min_length=1)
    timestamp: datetime | None = None
    name: str | None = Field(default=None, min_length=1)
    status: str | None = Field(default=None, min_length=1)

    @field_validator("device_id")
    @classmethod
    def validate_non_blank_text(cls, value: str) -> str:
        return _validate_required_text(value)

    @field_validator("route_from", "route_to", "name", "status")
    @classmethod
    def validate_optional_non_blank_text(cls, value: str | None) -> str | None:
        return _validate_optional_text(value)

    @model_validator(mode="after")
    def validate_device_shape(self) -> "DeviceBase":
        has_current_shape = all(
            value is not None
            for value in (
                self.battery_level,
                self.first_sensor_temperature,
                self.route_from,
                self.route_to,
                self.timestamp,
            )
        )
        has_legacy_shape = self.name is not None and self.status is not None
        if not (has_current_shape or has_legacy_shape):
            raise ValueError(
                "Provide either battery_level, first_sensor_temperature, route_from, route_to, and timestamp "
                "or the legacy name and status fields."
            )
        return self


class SensorData(DeviceBase):
    pass


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    battery_level: float | None = Field(default=None, ge=0, le=100)
    first_sensor_temperature: float | None = None
    route_from: str | None = Field(default=None, min_length=1)
    route_to: str | None = Field(default=None, min_length=1)
    timestamp: datetime | None = None
    name: str | None = Field(default=None, min_length=1)
    status: str | None = Field(default=None, min_length=1)

    @field_validator("route_from", "route_to", "name", "status")
    @classmethod
    def validate_optional_non_blank_text(cls, value: str | None) -> str | None:
        return _validate_optional_text(value)


class DeviceOut(DeviceBase):
    created_at: datetime | None = None
    updated_at: datetime | None = None
