import os

from kafka import KafkaConsumer

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
SHIPMENT_TOPIC = os.getenv("KAFKA_SHIPMENT_TOPIC", "shipment-events")


def create_consumer() -> KafkaConsumer:
    return KafkaConsumer(
        SHIPMENT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda value: value.decode("utf-8"),
    )
