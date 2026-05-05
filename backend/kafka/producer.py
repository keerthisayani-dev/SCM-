import os
from datetime import datetime, timezone

from kafka import KafkaProducer

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
SHIPMENT_TOPIC = os.getenv("KAFKA_SHIPMENT_TOPIC", "shipment-events")


def create_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: value.encode("utf-8"),
    )


def build_shipment_event(event_name: str, shipment_id: str) -> str:
    return (
        f'{{"event":"{event_name}","shipment_id":"{shipment_id}",'
        f'"created_at":"{datetime.now(timezone.utc).isoformat()}"}}'
    )
