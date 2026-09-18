# pipeline/phase1_ingest.py
"""Layer 1 — Event ingestion with schema validation.

Production: reads from JSON dataset (batch) or Kafka topics (--serve streaming).
Validates every event against schemas/v1/raw_event.json.
Invalid events routed to DLQ.
"""
import json
import re
import uuid
from pathlib import Path
from schemas.schema_validation import validate_payload


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
    """Batch ingest — read events from dataset file with schema validation."""
    dataset = state['runtime_meta'].get('dataset', 'datasets/all_events.json')
    raw_events = _normalize_envelopes(_load_dataset_events(Path(dataset)))

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
