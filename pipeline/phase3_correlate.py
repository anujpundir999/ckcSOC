# pipeline/phase3_correlate.py
import uuid, networkx as nx
import os
from collections import defaultdict
from datetime import datetime, timezone

# Correlation window is configurable for sparse datasets.
# Default: 30 minutes (was 7 minutes).
WINDOW_SECONDS = int(os.environ.get('CORRELATION_WINDOW_SECONDS', '1800'))

ESCALATION_PATTERNS = {
    'failure_then_data_access':    [['login_failure','db_access'],['login_failure','login_success','db_access']],
    'email_exfiltration_risk':     [['db_access','email_alert'],['db_export','email_alert']],
    'lateral_movement_suspected':  [['login_success','device_change','login_success']],
    'credential_then_privilege':   [['login_failure','login_success','privilege_escalation']],
    'possible_compromise':         [['login_failure','login_failure','login_success']],
}

def _is_subseq(needle, haystack):
    it = iter(haystack)
    return all(x in it for x in needle)

def _detect_flags(seq):
    return [k for k,pats in ESCALATION_PATTERNS.items()
            if any(_is_subseq(p, seq) for p in pats)]

CRITICAL_FLAGS = {'credential_then_privilege','lateral_movement_suspected'}
HIGH_FLAGS     = {'failure_then_data_access','email_exfiltration_risk', 'multi_user_shared_ip_campaign'}

def _priority(flags, systems, anom):
    f = set(flags)
    if f & CRITICAL_FLAGS: return 'critical'
    if f & HIGH_FLAGS:     return 'high'
    if systems >= 3 and anom >= 3: return 'high'
    if f or systems >= 2:  return 'medium'
    return 'low'

def _build_graph(events):
    G = nx.DiGraph()
    for i, e in enumerate(events):
        eid = f'evt-{i}'
        G.add_node(eid, event_type=e['event_type'], source=e['source_system'])
        if i > 0: G.add_edge(f'evt-{i-1}', eid)
    return nx.to_dict_of_lists(G)


def _parse_ts(ts: str):
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _split_by_window(evts, max_gap_seconds=WINDOW_SECONDS):
    if not evts:
        return []
    windows = [[evts[0]]]
    prev = _parse_ts(evts[0]['normalized_timestamp'])
    for ev in evts[1:]:
        cur = _parse_ts(ev['normalized_timestamp'])
        if (cur - prev).total_seconds() > max_gap_seconds:
            windows.append([ev])
        else:
            windows[-1].append(ev)
        prev = cur
    return windows


def _sequence_risk(seq, flags):
    score = 0.0
    flag_set = set(flags)
    if flag_set & CRITICAL_FLAGS:
        score += 0.55
    elif flag_set & HIGH_FLAGS:
        score += 0.35

    if _is_subseq(['login_success', 'email_alert', 'network_transfer'], seq):
        score += 0.25
    if _is_subseq(['login_failure', 'login_success'], seq):
        score += 0.15
    if _is_subseq(['db_access', 'network_transfer'], seq) or _is_subseq(['db_access', 'email_alert'], seq):
        score += 0.20
    return min(score, 1.0)


def _entity_risk(evts):
    ips = [str(e.get('ip') or '') for e in evts if e.get('ip')]
    devices = [str(e.get('device') or '') for e in evts if e.get('device')]
    hints = [h for e in evts for h in e.get('risk_hints', [])]

    score = 0.0
    if len(set(ips)) >= 2:
        score += 0.20
    if len(set(devices)) >= 2:
        score += 0.10
    if any('identity_risk' in h for h in hints):
        score += 0.30
    if any(h in {'external_forwarding_rule', 'inbox_auto_delete_rule'} for h in hints):
        score += 0.30
    if any(h == 'off_hours' for h in hints):
        score += 0.10
    return min(score, 1.0)


def _campaign_cluster(ip, evts):
    users = sorted({str(e.get('user') or 'unknown') for e in evts})
    seq = [e['event_type'] for e in evts]
    flags = _detect_flags(seq)
    if len(users) >= 2:
        flags = list(dict.fromkeys(flags + ['multi_user_shared_ip_campaign']))

    systems = list(set(e['source_system'] for e in evts))
    anom = sum(1 for e in evts if e.get('is_anomalous'))
    hints = list(set(h for e in evts for h in e.get('risk_hints', [])))
    hints = list(dict.fromkeys(hints + ['shared_ip_campaign']))

    seq_risk = _sequence_risk(seq, flags)
    base_ent_risk = _entity_risk(evts)
    user_spread = min((len(users) - 1) * 0.25, 0.5)
    ent_risk = min(base_ent_risk + user_spread, 1.0)
    corr_risk = round((0.55 * seq_risk) + (0.45 * ent_risk), 4)
    sev_vals = [float(e.get('explicit_severity_score', 0.0) or 0.0) for e in evts]
    sev_max = max(sev_vals) if sev_vals else 0.0
    sev_avg = round(sum(sev_vals) / max(len(sev_vals), 1), 4)

    return {
        'cluster_id':             f'CLC-{uuid.uuid4().hex[:6].upper()}',
        'cluster_kind':           'ip_campaign',
        'primary_user':           f'campaign:{ip}',
        'campaign_users':         users,
        'shared_iocs':            {'ip': [ip]},
        'start_time':             evts[0]['normalized_timestamp'],
        'end_time':               evts[-1]['normalized_timestamp'],
        'source_systems':         systems,
        'event_sequence':         seq,
        'event_sequence_compact': '→'.join(dict.fromkeys(seq)),
        'escalation_flags':       flags,
        'risk_hint_summary':      hints,
        'priority':               _priority(flags, len(systems), anom),
        'log_count':              len(evts),
        'anomalous_count':        anom,
        'has_anomalous':          anom > 0,
        'sequence_risk':          seq_risk,
        'entity_risk':            ent_risk,
        'correlation_score':      corr_risk,
        'explicit_severity_max':  sev_max,
        'explicit_severity_avg':  sev_avg,
        'cluster_graph':          _build_graph(evts),
        'logs':                   evts,
    }

def _cluster(user, evts):
    seq    = [e['event_type'] for e in evts]
    flags  = _detect_flags(seq)
    systems= list(set(e['source_system'] for e in evts))
    anom   = sum(1 for e in evts if e.get('is_anomalous'))
    hints  = list(set(h for e in evts for h in e.get('risk_hints',[])))
    seq_risk = _sequence_risk(seq, flags)
    ent_risk = _entity_risk(evts)
    corr_risk = round((0.6 * seq_risk) + (0.4 * ent_risk), 4)
    sev_vals = [float(e.get('explicit_severity_score', 0.0) or 0.0) for e in evts]
    sev_max = max(sev_vals) if sev_vals else 0.0
    sev_avg = round(sum(sev_vals) / max(len(sev_vals), 1), 4)
    return {
        'cluster_id':           f'CLC-{uuid.uuid4().hex[:6].upper()}',
        'primary_user':         user,
        'start_time':           evts[0]['normalized_timestamp'],
        'end_time':             evts[-1]['normalized_timestamp'],
        'source_systems':       systems,
        'event_sequence':       seq,
        'event_sequence_compact': '→'.join(dict.fromkeys(seq)),
        'escalation_flags':     flags,
        'risk_hint_summary':    hints,
        'priority':             _priority(flags, len(systems), anom),
        'log_count':            len(evts),
        'anomalous_count':      anom,
        'has_anomalous':        anom > 0,
        'sequence_risk':        seq_risk,
        'entity_risk':          ent_risk,
        'correlation_score':    corr_risk,
        'explicit_severity_max': sev_max,
        'explicit_severity_avg': sev_avg,
        'cluster_graph':        _build_graph(evts),
        'logs':                 evts
    }

def run(state: dict) -> list:
    normalized = sorted(state['normalized'], key=lambda x: x['normalized_timestamp'])

    by_user = defaultdict(list)
    for e in normalized:
        by_user[e['user']].append(e)

    clusters = []
    for user, evts in by_user.items():
        for window in _split_by_window(evts):
            if len(window) >= 3:
                clusters.append(_cluster(user, window))
                continue

            # Keep tiny windows if they still carry strong risk signals.
            if len(window) >= 2:
                c = _cluster(user, window)
                if c['has_anomalous'] or c['correlation_score'] >= 0.45:
                    clusters.append(c)

    # Secondary pass: correlate shared-IP campaigns across multiple users.
    by_ip = defaultdict(list)
    for e in normalized:
        ip = str(e.get('ip') or '').strip()
        if ip:
            by_ip[ip].append(e)

    for ip, evts in by_ip.items():
        for window in _split_by_window(evts):
            users = {str(e.get('user') or 'unknown') for e in window}
            if len(users) < 2:
                continue

            campaign = _campaign_cluster(ip, window)
            if campaign['log_count'] >= 3 or campaign['has_anomalous'] or campaign['correlation_score'] >= 0.5:
                clusters.append(campaign)

    print(f'[PHASE 3] Clusters: {len(clusters)}')
    return clusters
