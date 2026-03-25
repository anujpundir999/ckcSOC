# kafka/producer.py
import json, uuid
from datetime import datetime, timezone
from kafka.topics import BOOTSTRAP, ALLOWED_SOURCES

_producer = None
_use_memory_bus = False
_memory_bus = None

def set_memory_bus(bus):
    """Switch to in-memory bus for testing/demo mode."""
    global _use_memory_bus, _memory_bus
    _use_memory_bus = True
    _memory_bus = bus

def get_producer():
    global _producer
    if _use_memory_bus:
        return _memory_bus
    if _producer is None:
        try:
            from kafka import KafkaProducer
            _producer = KafkaProducer(
                bootstrap_servers=[BOOTSTRAP],
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                acks='all',
                retries=3
            )
        except Exception:
            raise RuntimeError('Kafka unavailable — run docker-compose up kafka')
    return _producer

def publish(source_system: str, payload: dict) -> dict:
    if source_system not in ALLOWED_SOURCES and not source_system.endswith('_dlq_bypass'):
        raise ValueError(f'Unknown source_system: {source_system}')
    envelope = {
        'message_id':      str(uuid.uuid4()),
        'event_time_utc':  datetime.now(timezone.utc).isoformat(),
        'source_system':   source_system,
        'payload_version': 'v1',
        'payload':         payload
    }
    topic = f'{source_system}_events' if not source_system.endswith('_dlq_bypass') else source_system
    if _use_memory_bus:
        _memory_bus.publish(topic, envelope)
    else:
        get_producer().send(topic, value=envelope).get(timeout=10)
    return envelope
