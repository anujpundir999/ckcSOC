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


def run(state: dict) -> list:
    """Batch ingest — read events from dataset file with schema validation."""
    dataset = state['runtime_meta'].get('dataset', 'datasets/all_events.json')
    limit   = state['runtime_meta'].get('limit')
    verbose = state['runtime_meta'].get('verbose', False)

    raw_content = Path(dataset).read_bytes()  # read as bytes — format_detector handles decode

    # Auto-detect format and parse to canonical envelopes
    raw_events = detect_and_parse(raw_content)

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
