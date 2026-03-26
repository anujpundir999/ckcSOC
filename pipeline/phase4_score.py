# pipeline/phase4_score.py
import numpy as np, hashlib, json
from scipy.special import expit
from pyod.models.iforest import IForest

_model = None
_baseline_mean = None
_baseline_std  = None

def _fv(cluster):
    logs = cluster['logs']
    n    = max(len(logs), 1)
    cnt  = lambda ev: sum(1 for l in logs if l['event_type']==ev)
    return [
        cnt('login_failure'), cnt('login_success'), cnt('device_change'),
        cnt('db_access') + cnt('db_export'), cnt('email_alert'),
        len(set(l['source_system'] for l in logs)),
        cluster['anomalous_count'],
        cluster['anomalous_count'] / n,
        max((len(cluster['escalation_flags']), 0))
    ]

def _zscore_score(fv, mean, std):
    z = np.abs((np.array(fv) - mean) / (std + 1e-9))
    return float(expit(2 * (z.mean() - 1)))

def _fidelity(cluster):
    sys_s  = min(len(cluster['source_systems']) / 6, 1.0)
    flag_s = min(len(cluster['escalation_flags']) / 3, 1.0)
    hint_s = min(len(cluster['risk_hint_summary']) / 5, 1.0)
    ratio  = cluster['anomalous_count'] / max(cluster['log_count'], 1)
    return round(0.35*sys_s + 0.30*flag_s + 0.20*hint_s + 0.15*ratio, 4)

def _severity(score):
    if score >= 0.65: return 'High'
    if score >= 0.35: return 'Medium'
    return 'Low'

def _train_baseline(clusters):
    global _model, _baseline_mean, _baseline_std
    normal = [_fv(c) for c in clusters if not c['has_anomalous']]
    if not normal: normal = [_fv(c) for c in clusters]
    X = np.array(normal)
    _baseline_mean = X.mean(0)
    _baseline_std  = X.std(0) + 1e-9
    _model = IForest(contamination=0.1, random_state=42)
    _model.fit(X)

def score_cluster(cluster):
    fv = _fv(cluster)
    z_score  = _zscore_score(fv, _baseline_mean, _baseline_std)
    if_score = float(expit(_model.decision_function([fv])[0] * -3))
    anomaly  = (z_score + if_score) / 2
    fidelity = _fidelity(cluster)
    combined = round(0.6 * anomaly + 0.4 * fidelity, 4)
    return {**cluster,
        'feature_vector': fv,
        'anomaly_score':  round(anomaly, 4),
        'fidelity_score': fidelity,
        'combined_score': combined,
        'final_score':    combined,
        'severity':       _severity(combined),
    }

def run(state: dict) -> list:
    clusters = state['clusters']
    _train_baseline(clusters)
    scored = [score_cluster(c) for c in clusters]
    high = sum(1 for s in scored if s['severity']=='High')
    print(f'[PHASE 4] Scored: {len(scored)} | High severity: {high}')
    return scored
