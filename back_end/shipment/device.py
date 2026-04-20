from pydantic import BaseModel


class ShipmentDevice(BaseModel):
    device_id: str
    device_name: str
    status: str
