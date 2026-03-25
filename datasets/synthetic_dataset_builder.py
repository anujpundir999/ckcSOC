# datasets/synthetic_dataset_builder.py
import json, uuid, random, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from argparse import ArgumentParser

random.seed(42)

# ── Constants ──
TOTAL_EVENTS   = 10_000
NORMAL_RATIO   = 0.95
BASE_TIME      = datetime(2026, 3, 15, 9, 0, 0, tzinfo=timezone.utc)
NORMAL_USERS   = [f'user_{i:03d}' for i in range(1, 101)]
ATTACKER_USERS = ['ashum', 'rkowalski', 'jpatel', 'mchen', 'asingh']
CORP_IPS       = [f'192.168.{r}.{h}' for r in range(1,5) for h in range(1,51)]
EVIL_IPS       = ['10.0.0.99','185.220.101.5','91.108.4.100']
DEVICES_NORMAL = lambda u: f'CORP-{u.upper()}-LT'
DEVICE_UNKNOWN = 'UNKNOWN-DEVICE-XYZ'

# ── Attack Chains ──
ATTACK_CHAINS = {
  'credential_compromise': [
    ('login_failure','auth'),('login_failure','auth'),('login_failure','auth'),
    ('login_failure','auth'),('login_failure','auth'),('login_success','auth'),
    ('device_change','edr'),('db_access','db'),('db_access','db'),
    ('email_alert','email'),('email_alert','email'),('network_transfer','network'),
    ('process_create','edr'),('siem_alert','siem'),('login_failure','auth')
  ],
  'insider_threat': [
    ('login_success','auth'),('privilege_escalation','edr'),
    ('db_export','db'),('db_export','db'),('db_export','db'),
    ('db_export','db'),('siem_alert','siem'),('network_transfer','network'),
    ('email_alert','email'),('login_success','auth'),('db_access','db'),
    ('process_create','edr'),('siem_alert','siem'),('network_transfer','network'),
    ('login_failure','auth')
  ],
  'phishing_lateral': [
    ('email_alert','email'),('email_alert','email'),('login_success','auth'),
    ('device_change','edr'),('process_create','edr'),('db_access','db'),
    ('db_access','db'),('network_transfer','network'),('siem_alert','siem'),
    ('login_failure','auth'),('login_failure','auth'),('email_alert','email'),
    ('db_export','db'),('privilege_escalation','edr'),('siem_alert','siem')
  ],
  'brute_force_mfa': [
    ('login_failure','auth'),('login_failure','auth'),('login_failure','auth'),
    ('login_failure','auth'),('login_failure','auth'),('login_failure','auth'),
    ('login_failure','auth'),('login_failure','auth'),('login_failure','auth'),
    ('login_failure','auth'),('mfa_bypass','auth'),('login_success','auth'),
    ('privilege_escalation','edr'),('db_access','db'),('siem_alert','siem')
  ],
}

def make_envelope(source_system, payload, t_offset_minutes=0):
    ts = (BASE_TIME + timedelta(minutes=t_offset_minutes)).isoformat()
    return {
        'message_id':      str(uuid.uuid4()),
        'event_time_utc':  ts,
        'source_system':   source_system,
        'payload_version': 'v1',
        'payload':         payload
    }

def make_normal_event(user, day_offset, minute_offset):
    hour   = random.randint(9, 17)       # 9AM-5PM
    minute = random.randint(0, 59)
    t_off  = day_offset * 1440 + hour * 60 + minute
    events = ['login_success','login_success','login_success',
              'db_access','process_create','email_alert']
    ev = random.choice(events)
    src_map = {
        'login_success':  'auth',
        'db_access':      'db',
        'process_create': 'edr',
        'email_alert':    'email',
    }
    return make_envelope(src_map.get(ev, 'siem'), {
        'user':   user,
        'event':  ev,
        'ip':     random.choice(CORP_IPS),
        'device': DEVICES_NORMAL(user),
        'is_anomalous': False
    }, t_off)

def make_attack_chain(attacker, chain_type, day_offset):
    chain   = ATTACK_CHAINS[chain_type]
    start_h = random.choice([1, 2, 3, 22, 23])  # off-hours
    t_base  = day_offset * 1440 + start_h * 60
    events  = []
    for i, (ev_type, source) in enumerate(chain):
        payload = {
            'user':         attacker,
            'event':        ev_type,
            'ip':           random.choice(EVIL_IPS),
            'device':       DEVICE_UNKNOWN,
            'is_anomalous': True,
            'rows_accessed': random.randint(5000, 20000) if 'db' in ev_type else 0
        }
        events.append(make_envelope(source, payload, t_base + i))
    return events

def build(output_dir='datasets'):
    Path(output_dir).mkdir(exist_ok=True)
    all_events = []

    # Normal events — 9500
    normal_count = int(TOTAL_EVENTS * NORMAL_RATIO)
    for _ in range(normal_count):
        user = random.choice(NORMAL_USERS)
        day  = random.randint(0, 6)  # 7 day spread
        all_events.append(make_normal_event(user, day, 0))

    # Attack chains — ~33 chains × 15 events = 495 events
    chain_types = list(ATTACK_CHAINS.keys())
    for i in range(33):
        attacker   = random.choice(ATTACKER_USERS)
        chain_type = chain_types[i % len(chain_types)]
        day        = random.randint(0, 6)
        all_events.extend(make_attack_chain(attacker, chain_type, day))

    random.shuffle(all_events)

    # Write per source type
    by_source = {}
    for e in all_events:
        s = e['source_system']
        by_source.setdefault(s, []).append(e)

    for src, evs in by_source.items():
        path = Path(output_dir) / f'synthetic_{src}_events.json'
        path.write_text(json.dumps(evs, indent=2))
        print(f'  {src}: {len(evs)} events -> {path}')

    # Combined file
    combined = Path(output_dir) / 'all_events.json'
    combined.write_text(json.dumps(all_events, indent=2))
    print(f'  Total: {len(all_events)} events -> {combined}')
    return all_events

if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument('--output-dir', default='datasets')
    args = ap.parse_args()
    build(args.output_dir)
