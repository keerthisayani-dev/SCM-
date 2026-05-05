from pydantic import BaseModel


class DeviceModuleStatus(BaseModel):
    module: str
    ready: bool
    message: str
