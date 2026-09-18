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


def _to_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_external_email(addr: str) -> bool:
    if not addr or '@' not in addr:
        return False
    return not addr.lower().endswith('@bank.local')


def _infer_event_type(payload: dict) -> str:
    # Native synthetic dataset path keeps the original event key.
    ev = payload.get('event')
    if ev:
        return str(ev)

    op = (payload.get('OperationName') or payload.get('Operation') or '').lower()
    if 'sign-in' in op:
        return 'login_success'
    if op == 'new-inboxrule':
        return 'email_alert'
    if op == 'mailitemsaccessed':
        return 'email_alert'
    if op == 'filedownloaded':
        return 'db_access'
    if op == 'send':
        return 'network_transfer'
    return 'unknown'


def _infer_is_anomalous(payload: dict, event_type: str) -> tuple[bool, list]:
    explicit = payload.get('is_anomalous')
    if isinstance(explicit, bool):
        return explicit, []

    score = 0
    reasons = []

    risk_state = str(payload.get('RiskState', '')).lower()
    risk_level = str(payload.get('RiskLevel', '')).lower()
    risk_events = payload.get('RiskEventTypes')
    if risk_state and risk_state != 'none':
        score += 2
        reasons.append('identity_risk_state')
    if risk_level in {'high', 'medium'}:
        score += 2 if risk_level == 'high' else 1
        reasons.append(f'identity_risk_{risk_level}')
    if risk_events:
        score += 2
        reasons.append('identity_risk_events')

    op = str(payload.get('OperationName') or payload.get('Operation') or '').lower()
    if op == 'new-inboxrule':
        params = payload.get('Parameters') or {}
        fwd = str(params.get('ForwardTo', '')).strip()
        if _is_external_email(fwd):
            score += 3
            reasons.append('external_forwarding_rule')
        if params.get('DeleteMessage') is True:
            score += 2
            reasons.append('inbox_rule_delete_message')
        words = [str(w).lower() for w in _to_list(params.get('SubjectContainsWords'))]
        if any(w in {'invoice', 'wire transfer', 'payment'} for w in words):
            score += 1
            reasons.append('finance_keyword_rule')

    if op == 'send':
        recipients = [str(r).strip() for r in _to_list(payload.get('Recipients'))]
        if any(_is_external_email(r) for r in recipients):
            score += 1
            reasons.append('external_email_recipient')

    if event_type == 'network_transfer' and payload.get('ClientIP') and payload.get('UserId'):
        score += 1
        reasons.append('cross_tenant_transfer_signal')

    return score >= 2, reasons


def _infer_explicit_severity(payload: dict, event_type: str, hints: list, anomaly_reasons: list):
    score = 0.0
    reasons = []

    risk_level = str(payload.get('RiskLevel', '')).lower()
    if risk_level == 'high':
        score += 0.65
        reasons.append('risklevel_high')
    elif risk_level == 'medium':
        score += 0.40
        reasons.append('risklevel_medium')

    op = str(payload.get('OperationName') or payload.get('Operation') or '').lower()
    if op == 'new-inboxrule' and any(x in hints for x in ('external_forwarding_rule', 'inbox_auto_delete_rule')):
        score += 0.60
        reasons.append('suspicious_inbox_rule')

    event_id = str(payload.get('EventID', '')).strip()
    cmd = str(payload.get('CommandLine') or '').lower()
    image = str(payload.get('Image') or payload.get('TargetImage') or '').lower()
    uri = str(payload.get('http_uri') or '').lower()

    if event_id == '10' and 'lsass' in image:
        score += 0.70
        reasons.append('lsass_access_attempt')
    if 'vssadmin' in cmd and 'delete shadows' in cmd:
        score += 0.70
        reasons.append('shadow_copy_deletion')
    if any(k in cmd for k in ('invoke-webrequest', 'certutil', 'curl -s', 'xp_cmdshell')):
        score += 0.55
        reasons.append('remote_payload_or_command_exec')
    if any(k in uri for k in ('xp_cmdshell', 'union select', ' or 1=1', 'sp_configure')):
        score += 0.70
        reasons.append('web_injection_pattern')

    orig_bytes = int(payload.get('orig_bytes', 0) or 0)
    if orig_bytes >= 1_000_000_000:
        score += 0.45
        reasons.append('large_data_transfer')

    if event_type == 'network_transfer' and 'external_email_recipient' in anomaly_reasons:
        score += 0.30
        reasons.append('external_exfil_signal')

    score = min(score, 1.0)
    if score >= 0.70:
        label = 'high'
    elif score >= 0.40:
        label = 'medium'
    else:
        label = 'low'
    return score, label, reasons

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

    risk_state = str(payload.get('RiskState', '')).lower()
    risk_level = str(payload.get('RiskLevel', '')).lower()
    if risk_state and risk_state != 'none':
        hints.append('identity_risk_state')
    if risk_level in {'high', 'medium'}:
        hints.append(f'identity_risk_{risk_level}')
    if payload.get('RiskEventTypes'):
        hints.append('identity_risk_events')

    op = str(payload.get('OperationName') or payload.get('Operation') or '').lower()
    if op == 'new-inboxrule':
        params = payload.get('Parameters') or {}
        if _is_external_email(str(params.get('ForwardTo', '')).strip()):
            hints.append('external_forwarding_rule')
        if params.get('DeleteMessage') is True:
            hints.append('inbox_auto_delete_rule')

    return list(set(hints))

def normalize_one(envelope: dict) -> dict:
    p  = envelope['payload']
    ts = envelope['event_time_utc']

    # Fast path: user field present — skip expensive BERT NER entirely
    user = (
        p.get('user')
        or p.get('username')
        or p.get('actor')
        or p.get('UserPrincipalName')
        or p.get('UserId')
    )

    # Only call BERT NER when user is genuinely unknown (rare edge case)
    if not user:
        ner = _get_ner()
        if ner and ner is not False:
            try:
                desc = f"{p.get('event','')} {p.get('ip','')} {p.get('device','')}"
                ents = ner(desc)
                pers = [e['word'] for e in ents if e['entity_group'] == 'PER']
                user = pers[0] if pers else 'unknown'
            except Exception:
                user = 'unknown'
        else:
            user = 'unknown'

    event_type = _infer_event_type(p)
    inferred_anom, anomaly_reasons = _infer_is_anomalous(p, event_type)
    hints = _risk_hints(p, ts)
    hints.extend(anomaly_reasons)
    sev_score, sev_label, sev_reasons = _infer_explicit_severity(p, event_type, list(set(hints)), anomaly_reasons)

    return {
        'normalized_timestamp': ts,
        'user':            user,
        'ip':              p.get('ip') or p.get('IpAddress') or p.get('ClientIP'),
        'device':          p.get('device') or p.get('ClientAppUsed'),
        'event_type':      event_type,
        'event_category':  EVENT_CATEGORY_MAP.get(event_type, 'misc'),
        'source_system':   envelope['source_system'],
        'risk_hints':      list(set(hints)),
        'privilege_indicator': bool(_RE_PRIV.search(str(p))),
        'is_anomalous':    inferred_anom,
        'explicit_severity_score': sev_score,
        'explicit_severity_label': sev_label,
        'explicit_severity_reasons': sev_reasons,
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
