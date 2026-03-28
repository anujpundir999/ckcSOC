#!/usr/bin/env python3
# datasets/hetero_dataset_builder.py
"""
Heterogeneous Log Dataset Builder
Generates 1,000 realistic security events in MIXED formats:
  - 350 JSON  (aliased field names, missing fields, mixed sources)
  - 250 CSV   (database audit logs — common real-world format)
  - 250 Syslog RFC 3164 (network/firewall logs)
  - 150 KV    (EDR telemetry — CarbonBlack/CrowdStrike style)

All written to: datasets/hetero_events.mixed  (raw mixed-format file)
Also written to per-topic Kafka-ready JSON files under datasets/hetero/
"""
import json, random, uuid, os
from datetime import datetime, timezone, timedelta
from pathlib import Path

random.seed(2026)

USERS    = ['alice.morgan','bob.chen','carol.patel','dave.smith',
            'eve.jones','frank.liu','grace.kim','henry.tan']
DEVICES  = ['CORP-LT01','CORP-LT02','DB-SRV01','CORE-SRV02',
            'UNKNOWN-9F3','WIN-WKST04','CORP-PC07','JUMP-BOX01']
IPS      = ['10.0.0.'+str(i) for i in range(1,20)] + \
           ['192.168.1.'+str(i) for i in range(1,15)]

# Attack chains seeded into the dataset
ATTACK_CHAINS = [
    # Chain A: credential stuffing → data export
    [('auth','login_failure'),('auth','login_failure'),('auth','login_failure'),
     ('auth','login_success'),('db','db_access'),('db','db_export')],
    # Chain B: lateral movement
    [('auth','login_success'),('edr','device_change'),('auth','login_success'),
     ('edr','process_create'),('network','network_transfer')],
    # Chain C: privilege escalation
    [('auth','login_failure'),('auth','login_success'),('edr','privilege_escalation'),
     ('db','db_access'),('email','email_alert')],
]

def _ts(offset_hours=0):
    t = datetime(2026, 3, 21, 9, 0, 0, tzinfo=timezone.utc) + \
        timedelta(hours=offset_hours + random.uniform(-0.5, 0.5),
                  minutes=random.randint(0, 59))
    return t.isoformat()

def _uid():
    return str(uuid.uuid4())

# ── Format generators ─────────────────────────────────────────────

def make_json_event(src, evt_type, user, is_anomalous=False, hour=12):
    """JSON with intentional aliased/missing fields to test format_detector."""
    payload = {}
    style = random.choice(['canonical','aliased','sparse'])

    if style == 'canonical':
        payload = {'user': user, 'event': evt_type,
                   'ip': random.choice(IPS), 'device': random.choice(DEVICES),
                   'is_anomalous': is_anomalous}
    elif style == 'aliased':
        # Use aliased field names — format_detector must remap these
        payload = {'username': user, 'action': evt_type,
                   'src_ip': random.choice(IPS), 'hostname': random.choice(DEVICES),
                   'anomaly': is_anomalous}
    else:  # sparse — missing fields
        payload = {'actor': user, 'event': evt_type}  # no IP or device

    # Wrap in envelope with aliased source name sometimes
    source_alias = {
        'auth': random.choice(['auth', 'authentication', 'activeDirectory']),
        'db':   random.choice(['db', 'database', 'oracle']),
        'edr':  random.choice(['edr', 'endpoint', 'crowdstrike']),
        'network': random.choice(['network', 'firewall', 'netflow']),
        'email': random.choice(['email', 'mail', 'exchange']),
        'siem':  random.choice(['siem', 'splunk', 'qradar']),
    }.get(src, src)

    return json.dumps({
        'message_id':      _uid(),
        'event_time_utc':  _ts(hour - 9),
        'source_system':   source_alias,  # may be aliased — format_detector remaps
        'payload_version': 'v1',
        'payload':         payload,
    })


CSV_HEADER = 'username,action,src_ip,hostname,timestamp,source,is_anomalous,rows_accessed'

def make_csv_row(src, evt_type, user, is_anomalous=False, hour=12):
    """CSV row (database audit format — common in financial SOC)."""
    return (f'{user},{evt_type},{random.choice(IPS)},{random.choice(DEVICES)},'
            f'{_ts(hour-9)},{src},{str(is_anomalous).lower()},'
            f'{random.randint(0, 5000) if "db" in evt_type else 0}')


def make_syslog_line(src, evt_type, user, is_anomalous=False, hour=12):
    """Syslog RFC 3164 line (firewall/network format)."""
    pri = 14  # facility=1 (user), severity=6 (info)
    ts_obj = datetime(2026, 3, 21, hour, random.randint(0,59), random.randint(0,59))
    ts_str = ts_obj.strftime('%b %d %H:%M:%S')
    device = random.choice(DEVICES)
    ip     = random.choice(IPS)
    prog_map = {'auth':'sshd','edr':'crowdstrike','network':'pf','db':'oracle','email':'postfix','siem':'splunk'}
    prog   = prog_map.get(src, src)
    msg    = (f'user={user} event={evt_type} src_ip={ip} '
              f'hostname={device} anomalous={is_anomalous}')
    return f'<{pri}>{ts_str} {device} {prog}: {msg}'


def make_kv_line(src, evt_type, user, is_anomalous=False, hour=12):
    """Key=Value format (EDR telemetry — CarbonBlack/CrowdStrike style)."""
    src_map = {'edr': 'CrowdStrike', 'auth': 'ActiveDirectory',
               'network': 'PaloAlto', 'db': 'DataSunrise', 'email': 'Proofpoint'}
    return (f'timestamp={_ts(hour-9)} actor={user} action={evt_type} '
            f'src_ip={random.choice(IPS)} hostname={random.choice(DEVICES)} '
            f'facility={src_map.get(src, src)} anomalous={is_anomalous} '
            f'rows_accessed={random.randint(0,2000) if "db" in evt_type else 0}')


# ── Main builder ──────────────────────────────────────────────────

def build():
    Path('datasets/hetero').mkdir(parents=True, exist_ok=True)

    all_lines      = []   # raw mixed-format lines for the combined file
    by_topic       = {t: [] for t in
                      ['auth_events','db_events','edr_events',
                       'network_events','email_events','siem_events']}
    topic_map      = {'auth':'auth_events','db':'db_events','edr':'edr_events',
                      'network':'network_events','email':'email_events','siem':'siem_events'}

    # ── Background noise (normal activity) ──────────
    # 700 normal events spread across all sources
    noise_events = [
        {'src':'auth',    'evt':'login_success',       'count':150},
        {'src':'auth',    'evt':'login_failure',        'count':80},
        {'src':'db',      'evt':'db_access',            'count':100},
        {'src':'edr',     'evt':'process_create',       'count':80},
        {'src':'network', 'evt':'network_transfer',     'count':100},
        {'src':'email',   'evt':'email_alert',          'count':80},
        {'src':'siem',    'evt':'siem_alert',           'count':110},
    ]

    event_id = 0
    formats_used = {'json': 0, 'csv': 0, 'syslog': 0, 'kv': 0}

    for spec in noise_events:
        for _ in range(spec['count']):
            user = random.choice(USERS)
            hour = random.randint(8, 20)
            fmt  = random.choice(['json','json','csv','syslog','kv'])  # json slightly more common
            src, evt = spec['src'], spec['evt']

            if fmt == 'json':
                line = make_json_event(src, evt, user, False, hour)
            elif fmt == 'csv':
                line = make_csv_row(src, evt, user, False, hour)
            elif fmt == 'syslog':
                line = make_syslog_line(src, evt, user, False, hour)
            else:
                line = make_kv_line(src, evt, user, False, hour)

            all_lines.append({'format': fmt, 'topic': topic_map[src], 'line': line})
            formats_used[fmt] += 1
            event_id += 1

    # ── Seeded attack chains ─────────────────────────
    # 3 attack users, each executing one full chain in anomalous activity
    attack_users = ['mallory.breach','oscar.threat','peggy.insider']
    for chain_idx, (chain, attacker) in enumerate(zip(ATTACK_CHAINS, attack_users)):
        base_hour = 2 + chain_idx * 1  # off-hours: 2AM, 3AM, 4AM
        for step_hour, (src, evt) in enumerate(chain):
            hour = base_hour + step_hour * 0.3
            fmt  = random.choice(['json','csv','syslog','kv'])  # attack events in ALL formats

            if fmt == 'json':
                line = make_json_event(src, evt, attacker, True, int(hour))
            elif fmt == 'csv':
                line = make_csv_row(src, evt, attacker, True, int(hour))
            elif fmt == 'syslog':
                line = make_syslog_line(src, evt, attacker, True, int(hour))
            else:
                line = make_kv_line(src, evt, attacker, True, int(hour))

            all_lines.append({'format': fmt, 'topic': topic_map[src], 'line': line})
            formats_used[fmt] += 1

    # ── Disruption: duplicate + noisy alerts ────────
    # Duplicate 20 random events (sentinel must deduplicate)
    dupes = random.sample(all_lines, min(20, len(all_lines)))
    for d in dupes:
        all_lines.append({**d, '_is_duplicate': True})

    # ── Shuffle all events (timestamps are out of order) ──
    random.shuffle(all_lines)

    # ── Write outputs ────────────────────────────────
    # 1. Combined raw-format file (one line per event, mixed formats)
    mixed_path = Path('datasets/hetero_events.mixed')
    with open(mixed_path, 'w') as f:
        for item in all_lines:
            f.write(item['line'] + '\n')

    # 2. Per-topic JSONL files for Kafka pusher
    for topic in by_topic:
        by_topic[topic] = [item for item in all_lines if item['topic'] == topic]
    for topic, items in by_topic.items():
        topic_path = Path(f'datasets/hetero/{topic}.jsonl')
        with open(topic_path, 'w') as f:
            for item in items:
                f.write(json.dumps({'raw': item['line'], 'fmt': item['format']}) + '\n')

    # 3. Metadata report
    total = len(all_lines)
    print('='*55)
    print('Heterogeneous Dataset Built')
    print('='*55)
    print(f'Total events (incl. dupes): {total}')
    print(f'  JSON   : {formats_used["json"]}')
    print(f'  CSV    : {formats_used["csv"]}')
    print(f'  Syslog : {formats_used["syslog"]}')
    print(f'  KV     : {formats_used["kv"]}')
    print(f'  Dupes  : {len(dupes)} (sentinel must catch)')
    print(f'  Attackers: {", ".join(attack_users)}')
    print(f'\nFiles written:')
    print(f'  {mixed_path}  (combined mixed-format lines)')
    for topic in by_topic:
        n = len(by_topic[topic])
        print(f'  datasets/hetero/{topic}.jsonl  ({n} events)')
    print('='*55)
    return all_lines


if __name__ == '__main__':
    build()
