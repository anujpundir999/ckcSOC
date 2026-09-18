#!/usr/bin/env python3
# kafka/hetero_pusher.py
"""
Pushes heterogeneous log lines (JSON/CSV/Syslog/KV) to real Kafka topics.
Simulates a live ingestion stream from multiple log sources.

Usage:
    python -m kafka.hetero_pusher                    # push all topics
    python -m kafka.hetero_pusher --rate 50          # 50 msgs/sec
    python -m kafka.hetero_pusher --topic auth_events  # single topic
"""
import json, time, argparse, sys, importlib
from pathlib import Path

# Avoid our local kafka/ folder shadowing kafka-python package
# We need to import from site-packages directly
def _get_kafka_producer():
    import subprocess, sys
    # Try importing KafkaProducer — if it fails, install kafka-python
    for pkg in ['kafka.producer', 'kafka']:
        try:
            import importlib.util
            # Use site-packages path directly
            import site
            for sp in site.getsitepackages():
                import os, pkgutil
                for finder, name, ispkg in pkgutil.iter_modules([sp]):
                    if name == 'kafka':
                        spec = importlib.util.spec_from_file_location(
                            'kafka_lib',
                            os.path.join(sp, 'kafka', '__init__.py'))
                        break
            break
        except Exception:
            pass

    # Direct approach: temporarily remove our kafka/ from path
    orig_path = sys.path.copy()
    # Remove paths that contain our local kafka/ dir
    sys.path = [p for p in sys.path if 'ckcSOC' not in p or 'site-packages' in p]
    try:
        from kafka import KafkaProducer as KP
        System_KafkaProducer = KP
    except ImportError:
        System_KafkaProducer = None
    finally:
        sys.path = orig_path
    return System_KafkaProducer

from kafka.topics import BOOTSTRAP, SOURCE_TOPICS


def push_to_kafka(rate_per_sec=100, topic_filter=None):
    """Push heterogeneous raw log lines to Kafka topics."""
    try:
        from kafka import KafkaProducer
    except ImportError:
        print('[PUSHER] ERROR: kafka-python not installed. Run: pip install kafka-python')
        return

    producer = KafkaProducer(
        bootstrap_servers=[BOOTSTRAP],
        value_serializer=lambda v: v if isinstance(v, bytes) else v.encode('utf-8'),
        acks='all',
        retries=3,
    )

    hetero_dir = Path('datasets/hetero')
    if not hetero_dir.exists():
        print('[PUSHER] ERROR: Run python datasets/hetero_dataset_builder.py first')
        return

    delay = 1.0 / rate_per_sec
    total_sent = 0
    topic_counts = {}

    print(f'[PUSHER] Pushing to Kafka @ {BOOTSTRAP} | rate={rate_per_sec} msg/s')
    print(f'[PUSHER] Kafka topics: {SOURCE_TOPICS}')

    for topic in SOURCE_TOPICS:
        if topic_filter and topic != topic_filter:
            continue

        topic_file = hetero_dir / f'{topic}.jsonl'
        if not topic_file.exists():
            print(f'[PUSHER] No file for {topic} — skipping')
            continue

        lines = topic_file.read_text().strip().splitlines()
        topic_counts[topic] = 0

        for line in lines:
            item = json.loads(line)
            raw_log = item['raw']      # raw log string in original format
            fmt     = item['fmt']

            # Push the RAW format string — Phase 1 will auto-detect format
            producer.send(topic, value=raw_log)
            topic_counts[topic] += 1
            total_sent += 1

            if total_sent % 50 == 0:
                print(f'[PUSHER] Sent {total_sent} msgs across topics...')

            time.sleep(delay)

        producer.flush()
        print(f'[PUSHER] ✓ {topic}: {topic_counts[topic]} messages pushed')

    producer.close()
    print(f'\n[PUSHER] Done. Total: {total_sent} messages pushed to Kafka')
    for t, c in topic_counts.items():
        print(f'  {t}: {c}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Push hetero logs to Kafka')
    ap.add_argument('--rate',  type=int, default=200, help='Messages per second')
    ap.add_argument('--topic', default=None, help='Push to single topic only')
    args = ap.parse_args()
    push_to_kafka(rate_per_sec=args.rate, topic_filter=args.topic)
