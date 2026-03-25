# kafka/consumer.py
import json
from kafka.topics import BOOTSTRAP

_use_memory_bus = False
_memory_bus = None

def set_memory_bus(bus):
    """Switch to in-memory bus for testing/demo mode."""
    global _use_memory_bus, _memory_bus
    _use_memory_bus = True
    _memory_bus = bus

def consume(topic: str, group_id: str = 'soc-pipeline', timeout_ms: int = 5000) -> list:
    if _use_memory_bus:
        return _memory_bus.consume(topic)
    try:
        from kafka import KafkaConsumer
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=[BOOTSTRAP],
            group_id=group_id,
            auto_offset_reset='earliest',
            consumer_timeout_ms=timeout_ms,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        messages = [msg.value for msg in consumer]
        consumer.close()
        return messages
    except Exception as e:
        print(f'[CONSUMER] Error consuming {topic}: {e}')
        return []
