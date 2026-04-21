from pydantic import BaseModel


class ShipmentDevice(BaseModel):
    device_id: str
    device_name: str
    status: str


if __name__ == "__main__":
    print("back_end.shipment.device loaded successfully")
