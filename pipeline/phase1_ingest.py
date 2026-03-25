# pipeline/phase1_ingest.py
"""Layer 1 — Event ingestion with schema validation.

Production: reads from JSON dataset (batch) or Kafka topics (--serve streaming).
Validates every event against schemas/v1/raw_event.json.
Invalid events routed to DLQ.
"""
import json
from pathlib import Path
from schemas.schema_validation import validate_payload

def run(state: dict) -> list:
    """Batch ingest — read events from dataset file with schema validation."""
    dataset = state['runtime_meta'].get('dataset', 'datasets/all_events.json')
    raw_events = json.loads(Path(dataset).read_text())

    valid, invalid = [], []
    for env in raw_events:
        ok, err = validate_payload('raw_event', env)
        if ok:
            valid.append(env)
        else:
            invalid.append({'envelope': env, 'error': err})

    if invalid:
        # Persist DLQ for audit
        dlq_path = Path('state/dlq_events.json')
        dlq_path.parent.mkdir(exist_ok=True)
        existing = json.loads(dlq_path.read_text()) if dlq_path.exists() else []
        existing.extend(invalid)
        dlq_path.write_text(json.dumps(existing[-1000:], indent=2))  # Keep last 1000

    print(f'[PHASE 1] Ingested: {len(valid)} valid, {len(invalid)} DLQ')
    return valid


def serve():
    """Continuous Kafka consumer mode for docker-compose service."""
    import time
    from kafka.consumer import consume
    from kafka.topics import SOURCE_TOPICS
    print('[PHASE 1] Starting ingestor service (--serve mode)...')
    while True:
        for topic in SOURCE_TOPICS:
            messages = consume(topic, timeout_ms=2000)
            if messages:
                valid = []
                for env in messages:
                    ok, err = validate_payload('raw_event', env)
                    if ok:
                        valid.append(env)
                    else:
                        print(f'[PHASE 1] DLQ: {err}')
                print(f'[PHASE 1] Consumed {len(valid)} from {topic}')
        time.sleep(1)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--serve', action='store_true')
    args = ap.parse_args()
    if args.serve:
        serve()
    else:
        print('[PHASE 1] Use --serve for continuous mode or import run() for batch')
