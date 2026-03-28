#!/usr/bin/env python3
# push_hetero_logs.py
"""
Pushes heterogeneous raw log lines to real Kafka topics.
Run from project root:
    python push_hetero_logs.py
    python push_hetero_logs.py --rate 500 --topic auth_events
"""
import json, time, argparse, sys
from pathlib import Path

BOOTSTRAP     = 'localhost:9092'
SOURCE_TOPICS = ['auth_events','edr_events','network_events',
                 'db_events','email_events','siem_events']


def _get_producer():
    """Get KafkaProducer — works even when kafka/ local folder exists."""
    # Temporarily remove project root from sys.path so kafka-python
    # in site-packages takes priority over our local kafka/ folder
    project_root = str(Path(__file__).parent)
    filtered = [p for p in sys.path if p != project_root and p != '']
    orig = sys.path[:]
    sys.path = filtered
    # Remove any cached reference to our local kafka module
    for key in list(sys.modules.keys()):
        if key == 'kafka' or key.startswith('kafka.'):
            del sys.modules[key]
    try:
        from kafka import KafkaProducer
        return KafkaProducer
    except ImportError:
        return None
    finally:
        sys.path = orig


def _get_consumer():
    project_root = str(Path(__file__).parent)
    filtered = [p for p in sys.path if p != project_root and p != '']
    orig = sys.path[:]
    sys.path = filtered
    for key in list(sys.modules.keys()):
        if key == 'kafka' or key.startswith('kafka.'):
            del sys.modules[key]
    try:
        from kafka import KafkaConsumer
        return KafkaConsumer
    except ImportError:
        return None
    finally:
        sys.path = orig


def push(rate_per_sec=500, topic_filter=None):
    KafkaProducer = _get_producer()
    if KafkaProducer is None:
        print('ERROR: kafka-python not installed. Run: pip install kafka-python')
        sys.exit(1)

    producer = KafkaProducer(
        bootstrap_servers=[BOOTSTRAP],
        value_serializer=lambda v: (v if isinstance(v, bytes) else v.encode('utf-8')),
        acks='all', retries=3,
    )

    hetero_dir = Path('datasets/hetero')
    if not hetero_dir.exists():
        print('ERROR: Run python datasets/hetero_dataset_builder.py first')
        sys.exit(1)

    delay = 1.0 / rate_per_sec
    total_sent = 0
    topic_counts = {}

    print(f'[PUSHER] Pushing to Kafka @ {BOOTSTRAP} | {rate_per_sec} msg/s')
    for topic in SOURCE_TOPICS:
        if topic_filter and topic != topic_filter:
            continue
        topic_file = hetero_dir / f'{topic}.jsonl'
        if not topic_file.exists():
            print(f'[PUSHER] No file for {topic} — skipping')
            continue

        topic_counts[topic] = 0
        for line in topic_file.read_text().strip().splitlines():
            raw = json.loads(line)['raw']
            producer.send(topic, value=raw)
            topic_counts[topic] += 1
            total_sent += 1
            if total_sent % 100 == 0:
                print(f'[PUSHER]   Sent {total_sent} msgs...')
            time.sleep(delay)

        producer.flush()
        print(f'[PUSHER] ✓ {topic}: {topic_counts[topic]} msgs pushed')

    producer.close()
    print(f'\n[PUSHER] Done. Total: {total_sent} across {len(topic_counts)} topics')
    for t, c in topic_counts.items():
        print(f'  {t}: {c}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--rate',  type=int, default=500)
    ap.add_argument('--topic', default=None)
    args = ap.parse_args()
    push(args.rate, args.topic)
