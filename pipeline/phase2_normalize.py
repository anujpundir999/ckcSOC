# pipeline/phase2_normalize.py
import os, re
from datetime import datetime, timezone

os.environ.setdefault('HF_HOME', 'models/hf_ner')

_ner = None

def _get_ner():
    global _ner
    if _ner is None:
        try:
            from transformers import pipeline
            _ner = pipeline('ner', model='dslim/bert-base-NER',
                            aggregation_strategy='simple')
        except Exception:
            _ner = False  # Fallback to regex-only
    return _ner

EVENT_CATEGORY_MAP = {
    'login_failure':'authentication','login_success':'authentication',
    'mfa_bypass':'authentication','device_change':'endpoint',
    'privilege_escalation':'privilege','process_create':'endpoint',
    'db_access':'data_access','db_export':'data_access',
    'email_alert':'communication','network_transfer':'network',
    'siem_alert':'alert',
}

_RE_IP   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_PRIV = re.compile(r'\b(sudo|admin|root|sa_|SYSTEM|Administrator)\b', re.I)

def _risk_hints(payload, ts_str):
    hints = []
    try:
        h = int(ts_str[11:13])
        if h < 7 or h > 21: hints.append('off_hours')
    except:
        pass
    if payload.get('event') == 'login_failure': hints.append('repeated_failure')
    if int(payload.get('rows_accessed', 0)) > 1000: hints.append('data_spike')
    if _RE_PRIV.search(str(payload)): hints.append('privilege_escalation')
    if payload.get('device','').startswith('UNKNOWN'): hints.append('new_device')
    return list(set(hints))

def normalize_one(envelope: dict) -> dict:
    p  = envelope['payload']
    ts = envelope['event_time_utc']
    desc = f"{p.get('user','')} {p.get('event','')} {p.get('ip','')} {p.get('device','')}"

    ner = _get_ner()
    user_ner = None
    if ner and ner is not False:
        try:
            ents = ner(desc)
            pers = [e['word'] for e in ents if e['entity_group']=='PER']
            user_ner = pers[0] if pers else None
        except Exception:
            pass

    return {
        'normalized_timestamp': ts,
        'user':            p.get('user') or user_ner or 'unknown',
        'ip':              p.get('ip'),
        'device':          p.get('device'),
        'event_type':      p.get('event','unknown'),
        'event_category':  EVENT_CATEGORY_MAP.get(p.get('event',''),'misc'),
        'source_system':   envelope['source_system'],
        'risk_hints':      _risk_hints(p, ts),
        'privilege_indicator': bool(_RE_PRIV.search(str(p))),
        'is_anomalous':    p.get('is_anomalous', None),
        'raw_payload':     p
    }

def run(state: dict) -> list:
    result = [normalize_one(e) for e in state['raw_logs']]
    print(f'[PHASE 2] Normalized: {len(result)} events')
    return result


def serve():
    """Continuous Kafka consumer mode for docker-compose service."""
    import time
    from kafka.consumer import consume
    print('[PHASE 2] Starting normalizer service (--serve mode)...')
    while True:
        messages = consume('ingested_events', timeout_ms=2000)
        if messages:
            normalized = [normalize_one(m) for m in messages]
            print(f'[PHASE 2] Normalized {len(normalized)} events')
        time.sleep(1)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--serve', action='store_true')
    args = ap.parse_args()
    if args.serve:
        serve()
    else:
        print('[PHASE 2] Use --serve for continuous mode or import run() for batch')

