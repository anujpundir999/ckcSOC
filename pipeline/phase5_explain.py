# pipeline/phase5_explain.py
"""Layer 5 — Explainability: deviation tables, narrative stories, and optional heatmaps."""
import json
from collections import Counter

def _deviation_table(cluster):
    """Build a deviation summary comparing cluster to baseline patterns."""
    logs = cluster.get('logs', [])
    event_counts = Counter(l['event_type'] for l in logs)
    system_counts = Counter(l['source_system'] for l in logs)

    deviations = []
    # High login failure ratio
    fail_ratio = event_counts.get('login_failure', 0) / max(len(logs), 1)
    if fail_ratio > 0.3:
        deviations.append({
            'indicator': 'login_failure_ratio',
            'value': round(fail_ratio, 3),
            'threshold': 0.3,
            'status': 'ANOMALOUS'
        })

    # Multi-system involvement
    if len(system_counts) >= 3:
        deviations.append({
            'indicator': 'multi_system_spread',
            'value': len(system_counts),
            'threshold': 3,
            'status': 'ELEVATED'
        })

    # Data access spikes
    data_events = event_counts.get('db_access', 0) + event_counts.get('db_export', 0)
    if data_events > 3:
        deviations.append({
            'indicator': 'data_access_volume',
            'value': data_events,
            'threshold': 3,
            'status': 'ANOMALOUS'
        })

    # Off-hours activity
    off_hours = sum(1 for l in logs
                    for h in l.get('risk_hints', [])
                    if h == 'off_hours')
    if off_hours > 0:
        deviations.append({
            'indicator': 'off_hours_activity',
            'value': off_hours,
            'threshold': 0,
            'status': 'SUSPICIOUS'
        })

    return deviations

def _narrative(cluster, scored):
    """Generate a human-readable incident story."""
    user = cluster['primary_user']
    sev = scored.get('severity', 'Unknown')
    flags = ', '.join(cluster.get('escalation_flags', [])) or 'none'
    systems = ', '.join(cluster.get('source_systems', []))
    n_events = cluster.get('log_count', 0)
    seq = cluster.get('event_sequence_compact', '')

    story = (
        f"User '{user}' triggered {n_events} events across {systems}. "
        f"Severity: {sev}. Escalation flags: {flags}. "
        f"Event flow: {seq}. "
    )

    if scored.get('anomaly_score', 0) > 0.6:
        story += f"Anomaly score {scored['anomaly_score']} exceeds threshold. "
    if scored.get('fidelity_score', 0) > 0.5:
        story += f"Multi-signal fidelity {scored['fidelity_score']} confirms high confidence. "

    return story

def explain_one(cluster, scored):
    return {
        'cluster_id':      cluster['cluster_id'],
        'severity':        scored.get('severity', 'Unknown'),
        'deviation_table': _deviation_table(cluster),
        'narrative':       _narrative(cluster, scored),
        'top_risk_hints':  cluster.get('risk_hint_summary', [])[:5],
        'escalation_flags': cluster.get('escalation_flags', []),
    }

def run(state: dict) -> list:
    scored = state.get('scored', [])
    explanations = [explain_one(s, s) for s in scored]
    print(f'[PHASE 5] Explanations: {len(explanations)}')
    return explanations
