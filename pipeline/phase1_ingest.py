# pipeline/phase1_ingest.py
"""Layer 1 — Event ingestion with multi-format support and schema validation.

Production: reads from JSON dataset (batch) or Kafka topics (--serve streaming).
Accepts: JSON, CSV, Syslog (RFC 3164/5424), Key=Value pairs.
Invalid events are soft-rejected (warn mode) — routed to DLQ but pipeline continues.
"""
import json
from pathlib import Path
from schemas.schema_validation import validate_payload
from pipeline.format_detector import detect_and_parse


def _drain_kafka(verbose=False) -> list:
    """Drain all pending messages from all Kafka source topics.
    Each raw message (any format) is passed through format_detector."""
    import os
    # When running natively (outside Docker), use the external listener port 9093
    # When running inside Docker, KAFKA_BOOTSTRAP env var points to kafka:9092
    bootstrap = os.environ.get('KAFKA_BOOTSTRAP_HOST',
                os.environ.get('KAFKA_BOOTSTRAP', 'localhost:9092'))
    from kafka.topics import SOURCE_TOPICS
    try:
        # Remove project root from path so kafka-python wins over local kafka/ folder
        import sys as _sys, pathlib as _pl
        _proj = str(_pl.Path(__file__).parent.parent)
        _clean = [p for p in _sys.path if p != _proj and p != '']
        _orig  = _sys.path[:]
        _sys.path = _clean
        for k in list(_sys.modules.keys()):
            if k == 'kafka' or k.startswith('kafka.'):
                del _sys.modules[k]
        from kafka import KafkaConsumer
        _sys.path = _orig
    except ImportError:
        print('[PHASE 1] kafka-python not installed — falling back to file mode')
        return []

    import uuid as _uuid
    run_group = f'soc-ingestor-{_uuid.uuid4().hex[:8]}'  # fresh group = read from start
    all_events = []
    for topic in SOURCE_TOPICS:
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=[bootstrap],
                group_id=run_group,
                auto_offset_reset='earliest',
                consumer_timeout_ms=5000,        # stop when no messages for 5s
                value_deserializer=lambda m: m,  # keep as raw bytes
            )
            topic_events = []
            for msg in consumer:
                raw = msg.value  # raw bytes — could be JSON, CSV, syslog, KV
                parsed = detect_and_parse(raw)
                topic_events.extend(parsed)
                if verbose and len(topic_events) % 20 == 0:
                    print(f'  [INGEST KAFKA] {topic}: {len(topic_events)} so far...')
            consumer.close()
            all_events.extend(topic_events)
            print(f'[PHASE 1] Kafka drained: {topic} → {len(topic_events)} events')
        except Exception as e:
            print(f'[PHASE 1] Kafka error on {topic}: {e}')

    return all_events


def run(state: dict) -> list:
    """Batch ingest — file or Kafka source, multi-format, warn-mode schema."""
    dataset = state['runtime_meta'].get('dataset', 'datasets/all_events.json')
    limit   = state['runtime_meta'].get('limit')
    verbose = state['runtime_meta'].get('verbose', False)
    source  = state['runtime_meta'].get('source', 'file')  # 'file' | 'kafka'

    if source == 'kafka':
        print('[PHASE 1] Source: KAFKA — draining all topics...')
        raw_events = _drain_kafka(verbose=verbose)
    else:
        raw_content = Path(dataset).read_bytes()
        raw_events  = detect_and_parse(raw_content)

    # Cap events if limit is set
    if limit:
        raw_events = raw_events[:limit]


    valid, invalid = [], []
    for i, env in enumerate(raw_events):
        ok, err = validate_payload('raw_event', env)
        if ok:
            valid.append(env)
            if verbose:
                src   = env.get('source_system', '?')
                eid   = env.get('message_id', '?')[:8]
                etype = env.get('payload', {}).get('event_type') \
                     or env.get('payload', {}).get('event', '?')
                user  = env.get('payload', {}).get('user', '?')
                fmt   = '(converted)' if env.get('_format_detected') else ''
                print(f'  [INGEST #{i+1:04d}] id={eid} src={src:8s} type={etype:25s} user={user} {fmt}')
        else:
            # WARN mode: log to DLQ but don't drop the event — try to salvage it
            if verbose:
                print(f'  [INGEST WARN #{i+1:04d}] schema-warn: {err} — salvaging event')
            # Salvage: if we have a payload, accept it with a warning flag
            env['_schema_warn'] = err
            valid.append(env)
            invalid.append({'envelope': env, 'error': err})  # still audit it

    if invalid:
        dlq_path = Path('state/dlq_events.json')
        dlq_path.parent.mkdir(exist_ok=True)
        existing = json.loads(dlq_path.read_text()) if dlq_path.exists() else []
        existing.extend(invalid)
        dlq_path.write_text(json.dumps(existing[-1000:], indent=2))

    warn_count = len(invalid)
    print(f'[PHASE 1] Ingested: {len(valid)} valid, {warn_count} schema-warnings (DLQ audited)')
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
                # detect_and_parse handles any format coming off the wire
                parsed = detect_and_parse(messages)
                print(f'[PHASE 1] Consumed {len(parsed)} from {topic}')
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
