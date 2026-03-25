# kafka/bus.py — used in tests + dry runs (no real Kafka needed)
from collections import defaultdict

class InMemoryKafkaBus:
    def __init__(self):
        self._topics = defaultdict(list)
        self._offsets = defaultdict(int)

    def publish(self, topic: str, message: dict):
        self._topics[topic].append(message)

    def consume(self, topic: str, from_offset: int = 0) -> list:
        msgs = self._topics[topic][from_offset:]
        self._offsets[topic] = len(self._topics[topic])
        return msgs

    def count(self, topic: str) -> int:
        return len(self._topics[topic])

    def dlq_count(self, topic: str) -> int:
        return len(self._topics.get(topic + '_dlq', []))

    def reset(self):
        self._topics.clear()
        self._offsets.clear()
