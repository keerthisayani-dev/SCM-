"""Shipment package."""

from back_end.shipment.device import ShipmentDevice
from back_end.shipment.user import ShipmentUser

__all__ = ["ShipmentDevice", "ShipmentUser"]


if __name__ == "__main__":
    print("back_end.shipment package loaded successfully")
