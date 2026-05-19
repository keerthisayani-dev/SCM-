from datetime import datetime

from pydantic import BaseModel, Field


class DeviceBase(BaseModel):
    device_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)
    status: str = "available"


class DeviceCreate(DeviceBase):
    pass


class DeviceOut(DeviceBase):
    created_at: datetime | None = None
    updated_at: datetime | None = None
