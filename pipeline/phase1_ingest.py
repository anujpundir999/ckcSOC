# pipeline/phase1_ingest.py
"""Layer 1 — Event ingestion with multi-format support and schema validation.

Production: reads from JSON dataset (batch) or Kafka topics (--serve streaming).
Accepts: JSON, CSV, Syslog (RFC 3164/5424), Key=Value pairs.
Invalid events are soft-rejected (warn mode) — routed to DLQ but pipeline continues.
"""
import json
import re
import uuid
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



SOURCE_SYSTEM_MAP = {
    'auth': 'auth',
    'azure_ad': 'auth',
    'windows_security': 'auth',
    'okta': 'auth',
    'adfs': 'auth',
    'office365': 'email',
    'exchange': 'email',
    'o365': 'email',
    'sysmon': 'edr',
    'edr': 'edr',
    'zeek': 'network',
    'firewall': 'network',
    'cloud_waf': 'network',
    'waf': 'network',
    'sharepoint': 'db',
    'mssql': 'db',
    'postgres': 'db',
    'siem': 'siem',
    'splunk': 'siem',
}


def _detect_source_system(raw: dict) -> str:
    src = str(raw.get('source') or raw.get('log_source') or '').strip().lower()
    return SOURCE_SYSTEM_MAP.get(src, 'siem')


def _detect_timestamp(raw: dict) -> str:
    ts = raw.get('event_time_utc') or raw.get('timestamp') or raw.get('UtcTime')
    if not ts:
        return '1970-01-01T00:00:00Z'
    ts = str(ts).strip().replace(' ', 'T')
    if ts.endswith('Z') or '+' in ts:
        return ts
    return f'{ts}Z'


def _wrap_as_envelope(raw: dict) -> dict:
    return {
        'message_id': str(raw.get('message_id') or raw.get('log_id') or uuid.uuid4()),
        'event_time_utc': _detect_timestamp(raw),
        'source_system': _detect_source_system(raw),
        'payload_version': 'v1',
        'payload': raw,
    }


def _sanitize_json_text(text: str) -> str:
    # Remove trailing commas before ] or } and at EOF.
    s = text.lstrip('\ufeff').strip()
    s = re.sub(r',\s*(\]|\})', r'\1', s)
    s = re.sub(r',\s*$', '', s)
    return s


def _extract_object_chunks(text: str) -> list:
    chunks = []
    depth = 0
    start = None
    in_str = False
    escape = False

    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue

        if ch == '\\':
            escape = True
            continue

        if ch == '"':
            in_str = not in_str
            continue

        if in_str:
            continue

        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    chunks.append(text[start:i + 1])
                    start = None

    return chunks


def _load_with_recovery(text: str, path: Path) -> list:
    recovered = []
    dropped = 0
    for chunk in _extract_object_chunks(text):
        candidate = _sanitize_json_text(chunk)
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                recovered.append(obj)
            elif isinstance(obj, list):
                recovered.extend(x for x in obj if isinstance(x, dict))
        except Exception:
            dropped += 1

    if recovered:
        print(f'[PHASE 1] Recovered {len(recovered)} records from malformed JSON: {path} (dropped {dropped} chunks)')
    return recovered


def _load_mixed_json(path: Path) -> list:
    text = path.read_text().strip()
    if not text:
        return []

    # Fast path: proper JSON array or object.
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except Exception:
        pass

    # Fallback: concatenated objects or object list without outer brackets.
    try:
        wrapped = _sanitize_json_text(f'[{text}]')
        data = json.loads(wrapped)
        if isinstance(data, list):
            return data
    except Exception:
        pass

    # Recovery path: salvage valid object chunks from malformed files.
    recovered = _load_with_recovery(text, path)
    if recovered:
        return recovered

    raise ValueError('Unable to parse JSON content with recovery')


def _normalize_envelopes(events: list) -> list:
    out = []
    for evt in events:
        if not isinstance(evt, dict):
            continue
        if all(k in evt for k in ('message_id', 'event_time_utc', 'source_system', 'payload_version', 'payload')):
            out.append(evt)
        else:
            out.append(_wrap_as_envelope(evt))
    return out


def _load_dataset_events(dataset_path: Path) -> list:
    # Accept either a single JSON file or a directory of JSON files.
    if dataset_path.is_dir():
        events = []
        for fp in sorted(dataset_path.rglob('*.json')):
            try:
                events.extend(_load_mixed_json(fp))
            except Exception as e:
                print(f'[PHASE 1] Skipping invalid JSON file: {fp} ({e})')
        return events
    return _load_mixed_json(dataset_path)

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
