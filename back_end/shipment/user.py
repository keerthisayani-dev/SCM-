from pydantic import BaseModel


class ShipmentUser(BaseModel):
    user_id: str
    name: str
    email: str
    phone: str
