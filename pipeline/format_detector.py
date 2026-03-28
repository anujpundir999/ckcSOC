# pipeline/format_detector.py
"""
Multi-format log parser — converts heterogeneous inputs to canonical JSON envelope.

Supports:
  - JSON  (native format)
  - CSV   (comma-separated, any field names)
  - Syslog (RFC 3164 / RFC 5424)
  - Key=Value pairs (CEF, LEEF subset)

All outputs are normalized to the canonical SOC envelope:
  {message_id, event_time_utc, source_system, payload_version, payload}
"""
import re, csv, uuid, io, json
from datetime import datetime, timezone

# ── Field name aliases ────────────────────────────────────────────
# Maps non-standard field names → our canonical field names
FIELD_ALIASES = {
    # User field variants
    'username':   'user', 'actor':       'user', 'uid':        'user',
    'userid':     'user', 'account':     'user', 'principal':  'user',
    'subject':    'user', 'src_user':    'user', 'initiator':  'user',
    # Event type variants
    'event':      'event', 'action':     'event', 'event_type': 'event',
    'eventtype':  'event', 'type':       'event', 'category':   'event',
    'msg':        'event', 'eventid':    'event',
    # IP variants
    'src_ip':     'ip', 'source_ip':    'ip', 'srcip':      'ip',
    'client_ip':  'ip', 'remote_addr':  'ip', 'ipaddress':  'ip',
    # Device variants
    'hostname':   'device', 'host':      'device', 'machine':   'device',
    'endpoint':   'device', 'computer':  'device', 'workstation':'device',
    # Timestamp variants
    'timestamp':  'event_time_utc', 'time': 'event_time_utc',
    'datetime':   'event_time_utc', 'date': 'event_time_utc',
    'ts':         'event_time_utc', 'log_time': 'event_time_utc',
    # Source variants
    'source':     'source_system', 'src':  'source_system',
    'facility':   'source_system', 'app':  'source_system',
}

# Map free-text source names → our canonical source_system values
SOURCE_MAP = {
    'authentication': 'auth', 'login': 'auth', 'activeDirectory': 'auth', 'ad': 'auth',
    'endpoint':       'edr',  'antivirus': 'edr', 'crowdstrike': 'edr', 'carbon_black': 'edr',
    'firewall':       'network', 'netflow': 'network', 'proxy': 'network', 'ids': 'network',
    'database':       'db', 'oracle': 'db', 'mssql': 'db', 'mysql': 'db',
    'mail':           'email', 'smtp': 'email', 'exchange': 'email', 'office365': 'email',
    'siem':           'siem', 'splunk': 'siem', 'qradar': 'siem', 'sentinel': 'siem',
}
KNOWN_SOURCES = {'auth', 'edr', 'network', 'db', 'email', 'siem'}

# ── Syslog regex ─────────────────────────────────────────────────
# RFC 3164: <PRI>Mon DD HH:MM:SS hostname tag: message
_SYSLOG_3164 = re.compile(
    r'^(?:<\d+>)?'
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<prog>\S+?):\s*(?P<msg>.*)$'
)
# RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID ...
_SYSLOG_5424 = re.compile(
    r'^<\d+>1\s+'
    r'(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<msg>.*)$'
)
# Key=Value pairs
_KV_PAIR = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _now_utc():
    return datetime.now(timezone.utc).isoformat()


def _normalize_source(raw: str) -> str:
    """Map any source string to a known source_system value."""
    if not raw:
        return 'siem'
    raw_lower = raw.lower().strip()
    if raw_lower in KNOWN_SOURCES:
        return raw_lower
    for key, val in SOURCE_MAP.items():
        if key in raw_lower:
            return val
    return 'siem'  # fallback — goes to SIEM bucket


def _remap_fields(d: dict) -> dict:
    """Remap aliased field names to canonical names."""
    out = {}
    for k, v in d.items():
        canonical = FIELD_ALIASES.get(k.lower().strip(), k.lower().strip())
        out[canonical] = v
    return out


def _make_envelope(payload: dict, source_raw: str = None, ts: str = None) -> dict:
    """Wrap a parsed payload dict into a canonical SOC envelope."""
    # Extract + remove meta fields from payload before wrapping
    source = _normalize_source(source_raw or payload.pop('source_system', None) or '')
    event_time = ts or payload.pop('event_time_utc', None) or _now_utc()

    return {
        'message_id':      str(uuid.uuid4()),
        'event_time_utc':  event_time,
        'source_system':   source,
        'payload_version': 'v1',
        'payload':         payload,
        '_format_detected': True,   # flag so we know it was auto-detected
    }


# ── Format parsers ────────────────────────────────────────────────

def _parse_json(raw: str) -> list:
    """Parse JSON — single object or array."""
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    return [data]


def _parse_csv(raw: str) -> list:
    """Parse CSV with arbitrary headers → canonical envelopes."""
    reader = csv.DictReader(io.StringIO(raw.strip()))
    result = []
    for row in reader:
        d = _remap_fields({k: v for k, v in row.items() if v.strip()})
        result.append(_make_envelope(d))
    return result


def _parse_syslog_line(line: str) -> dict | None:
    """Parse a single syslog line (RFC 3164 or 5424)."""
    line = line.strip()
    if not line:
        return None

    # Try RFC 5424 first
    m = _SYSLOG_5424.match(line)
    if m:
        payload = {'event': m.group('msg'), 'device': m.group('host')}
        # Try to extract KV pairs from message
        for k, v in _KV_PAIR.findall(m.group('msg')):
            payload[_remap_fields({k: v}).popitem()[0]] = v.strip('"')
        return _make_envelope(_remap_fields(payload),
                              source_raw=m.group('app'),
                              ts=m.group('ts'))

    # Try RFC 3164
    m = _SYSLOG_3164.match(line)
    if m:
        payload = {
            'event':  m.group('msg'),
            'device': m.group('host'),
        }
        # Try KV extraction from message body
        for k, v in _KV_PAIR.findall(m.group('msg')):
            payload[_remap_fields({k: v}).popitem()[0]] = v.strip('"')
        ts = f"2026-{m.group('month')}-{m.group('day').zfill(2)}T{m.group('time')}Z"
        return _make_envelope(_remap_fields(payload),
                              source_raw=m.group('prog'),
                              ts=ts)

    # Fallback: treat whole line as unstructured syslog message
    payload = {'event': line}
    return _make_envelope(payload, source_raw='siem')


def _parse_syslog(raw: str) -> list:
    return [e for line in raw.strip().splitlines()
            if (e := _parse_syslog_line(line)) is not None]


def _parse_kv(raw: str) -> list:
    """Parse key=value format (CEF/LEEF subset)."""
    result = []
    for line in raw.strip().splitlines():
        pairs = dict(_KV_PAIR.findall(line))
        if pairs:
            d = _remap_fields({k: v.strip('"') for k, v in pairs.items()})
            result.append(_make_envelope(d))
    return result


# ── Auto-detector ─────────────────────────────────────────────────

def detect_and_parse(raw: str | bytes | list | dict) -> list:
    """
    Auto-detect the format of raw log input and parse to canonical envelopes.

    Accepts:
      - Already-parsed list of dicts (passthrough)
      - Already-parsed single dict (wrapped in list)
      - Raw string in JSON, CSV, Syslog, or KV format
      - Bytes (decoded as UTF-8)

    Returns: list of canonical envelope dicts
    """
    # Already parsed Python objects
    if isinstance(raw, list):
        if all(isinstance(e, dict) for e in raw):
            return raw   # already canonical — passthrough
    if isinstance(raw, dict):
        return [raw]

    # Bytes → string
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', errors='replace')

    raw = raw.strip()
    if not raw:
        return []

    # ── JSON detection ──
    if raw.startswith(('{', '[')):
        try:
            items = _parse_json(raw)
            # If already canonical (has message_id), pass through
            if items and 'payload' in items[0]:
                return items
            # Otherwise wrap each dict as an envelope
            return [_make_envelope(_remap_fields(item)) for item in items]
        except json.JSONDecodeError:
            pass   # fall through to next format

    # ── CSV detection ── (has comma-separated header row)
    first_line = raw.splitlines()[0] if raw.splitlines() else ''
    if ',' in first_line and not first_line.startswith('<') and '=' not in first_line:
        try:
            result = _parse_csv(raw)
            if result:
                return result
        except Exception:
            pass

    # ── Syslog detection ── (starts with <PRI> or month abbreviation)
    if (raw.startswith('<') or
            re.match(r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s', raw)):
        result = _parse_syslog(raw)
        if result:
            return result

    # ── KV detection ── (majority of tokens contain '=')
    kv_count = raw.count('=')
    if kv_count >= 2:
        result = _parse_kv(raw)
        if result:
            return result

    # ── Last resort: treat each line as unstructured message ──
    return [_make_envelope({'event': line.strip()})
            for line in raw.splitlines() if line.strip()]
