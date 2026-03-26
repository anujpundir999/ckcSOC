# pipeline/phase3_correlate.py
import uuid, networkx as nx
from collections import defaultdict
from datetime import datetime, timezone

WINDOW_SECONDS = 420

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
HIGH_FLAGS     = {'failure_then_data_access','email_exfiltration_risk'}

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

def _cluster(user, evts):
    seq    = [e['event_type'] for e in evts]
    flags  = _detect_flags(seq)
    systems= list(set(e['source_system'] for e in evts))
    anom   = sum(1 for e in evts if e.get('is_anomalous'))
    hints  = list(set(h for e in evts for h in e.get('risk_hints',[])))
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
        'cluster_graph':        _build_graph(evts),
        'logs':                 evts
    }

def run(state: dict) -> list:
    by_user = defaultdict(list)
    for e in sorted(state['normalized'], key=lambda x: x['normalized_timestamp']):
        by_user[e['user']].append(e)
    clusters = []
    for user, evts in by_user.items():
        if len(evts) >= 3:
            clusters.append(_cluster(user, evts))
    print(f'[PHASE 3] Clusters: {len(clusters)}')
    return clusters
