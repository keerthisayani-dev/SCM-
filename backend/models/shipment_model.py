from pydantic import BaseModel


class ShipmentModuleStatus(BaseModel):
    module: str
    ready: bool
    message: str
