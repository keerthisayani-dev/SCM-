from pydantic import BaseModel


class ShipmentUser(BaseModel):
    user_id: str
    name: str
    email: str
    phone: str


if __name__ == "__main__":
    print("back_end.shipment.user loaded successfully")
