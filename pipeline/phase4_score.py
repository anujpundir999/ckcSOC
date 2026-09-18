# pipeline/phase4_score.py
"""Layer 4 — Hybrid anomaly scoring: tsfresh + PyOD IsolationForest + z-score + fidelity.

tsfresh feature extraction:
  - Extracts 77 rolling statistical features per cluster from the event time series:
    mean, variance, std, skewness, kurtosis, min/max, median, sum,
    autocorrelation (lags 1–5), linear trend, approximate entropy, etc.
  - These capture temporal dynamics that a hand-crafted vector cannot.
  - Falls back to 9-dim manual vector if tsfresh unavailable or cluster too small.

Scoring pipeline:
  1. tsfresh 77-dim feature vector (or 9-dim fallback)
  2. IsolationForest (PyOD, contamination=0.1)
  3. Z-score against baseline distribution
  4. Fidelity score (multi-source coverage, flags, hints, anomaly ratio)
  5. Final = 0.6 * anomaly_hybrid + 0.4 * fidelity
"""
import numpy as np, json
from scipy.special import expit
from pathlib import Path

# ── tsfresh (optional) ──────────────────────────────────────
_TSFRESH_OK = False
try:
    import pandas as pd
    from tsfresh import extract_features
    from tsfresh.feature_extraction import EfficientFCParameters
    _TSFRESH_OK = True
except ImportError:
    pass

# ── PyOD IsolationForest ────────────────────────────────────
from pyod.models.iforest import IForest

_model         = None
_baseline_mean = None
_baseline_std  = None
_baseline_median = None
_baseline_mad = None
_feature_dim   = 9  # fallback if tsfresh unavailable
_small_sample_mode = False
_small_sample_cutoff = 20

# ── Feature Extraction ───────────────────────────────────────

def _event_to_value(event_type: str) -> float:
    """Map event type to ordinal severity score for time-series encoding."""
    MAP = {
        'login_success':       1.0,
        'device_change':       2.0,
        'login_failure':       3.0,
        'email_alert':         3.5,
        'network_transfer':    4.0,
        'process_create':      4.5,
        'db_access':           5.0,
        'privilege_escalation':6.5,
        'mfa_bypass':          7.0,
        'db_export':           7.5,
        'siem_alert':          8.0,
    }
    return MAP.get(event_type, 2.5)

def _tsfresh_fv(cluster) -> list:
    """Extract rich statistical features using tsfresh (77 features)."""
    logs = cluster['logs']
    if not _TSFRESH_OK or len(logs) < 3:
        return None  # Fall back to manual

    try:
        # Build time series: event severity values over sequence
        values = [_event_to_value(l['event_type']) for l in logs]
        # Also encode anomaly flag as a second series
        anomaly_series = [1.0 if l.get('is_anomalous') else 0.0 for l in logs]

        df = pd.DataFrame({
            'id': [0] * len(logs),
            'time': list(range(len(logs))),
            'event_severity': values,
            'anomaly_flag': anomaly_series,
        })

        extracted = extract_features(
            df,
            column_id='id',
            column_sort='time',
            column_value=None,
            default_fc_parameters=EfficientFCParameters(),
            disable_progressbar=True,
            n_jobs=1,   # n_jobs=-1 causes silent multiprocessing failure on macOS Python 3.13
        )

        # Drop all-NaN / constant columns
        extracted = extracted.dropna(axis=1)
        extracted = extracted.loc[:, extracted.std() > 0] if len(extracted) > 1 else extracted.dropna(axis=1)

        fv = extracted.values[0].tolist()

        # Safety: cap at 300 features to avoid OOM
        return fv[:300] if len(fv) > 300 else fv

    except Exception:
        return None  # Fall back to manual vector

def _manual_fv(cluster) -> list:
    """9-dim hand-crafted feature vector (fallback)."""
    logs = cluster['logs']
    n    = max(len(logs), 1)
    cnt  = lambda ev: sum(1 for l in logs if l['event_type'] == ev)
    return [
        cnt('login_failure'),
        cnt('login_success'),
        cnt('device_change'),
        cnt('db_access') + cnt('db_export'),
        cnt('email_alert'),
        len(set(l['source_system'] for l in logs)),
        cluster['anomalous_count'],
        cluster['anomalous_count'] / n,
        max(len(cluster['escalation_flags']), 0),
    ]

def _fv(cluster) -> list:
    """Get feature vector — tsfresh preferred, manual fallback."""
    ts = _tsfresh_fv(cluster)
    return ts if ts is not None else _manual_fv(cluster)

# ── Scoring ──────────────────────────────────────────────────

def _zscore_score(fv, mean, std):
    fv_arr = np.array(fv)
    n = min(len(fv_arr), len(mean))
    z = np.abs((fv_arr[:n] - mean[:n]) / (std[:n] + 1e-9))
    return float(expit(2 * (z.mean() - 1)))


def _mad_score(fv, median, mad):
    fv_arr = np.array(fv)
    n = min(len(fv_arr), len(median))
    robust_z = np.abs((fv_arr[:n] - median[:n]) / (mad[:n] + 1e-9))
    return float(expit(1.8 * (robust_z.mean() - 1)))


def _small_batch_signal(cluster):
    flag_set = set(cluster.get('escalation_flags', []))
    critical = {'credential_then_privilege', 'lateral_movement_suspected'}
    high = {'failure_then_data_access', 'email_exfiltration_risk'}

    score = 0.0
    if flag_set & critical:
        score += 0.45
    elif flag_set & high:
        score += 0.30

    hints = len(cluster.get('risk_hint_summary', []))
    score += min(hints * 0.06, 0.24)

    ratio = cluster.get('anomalous_count', 0) / max(cluster.get('log_count', 1), 1)
    score += min(ratio, 1.0) * 0.25

    corr = float(cluster.get('correlation_score', 0.0))
    score += min(corr, 1.0) * 0.35

    sev = float(cluster.get('explicit_severity_max', 0.0))
    score += min(sev, 1.0) * 0.40
    return min(score, 1.0)

def _fidelity(cluster):
    sys_s  = min(len(cluster['source_systems']) / 6, 1.0)
    flag_s = min(len(cluster['escalation_flags']) / 3, 1.0)
    hint_s = min(len(cluster['risk_hint_summary']) / 5, 1.0)
    ratio  = cluster['anomalous_count'] / max(cluster['log_count'], 1)
    corr = min(float(cluster.get('correlation_score', 0.0)), 1.0)
    sev = min(float(cluster.get('explicit_severity_max', 0.0)), 1.0)
    return round(0.24*sys_s + 0.20*flag_s + 0.16*hint_s + 0.08*ratio + 0.17*corr + 0.15*sev, 4)

def _severity(score):
    if score >= 0.65: return 'High'
    if score >= 0.35: return 'Medium'
    return 'Low'

def _pad(fv, target_len):
    """Pad or truncate feature vector to consistent dimension."""
    if len(fv) < target_len:
        return fv + [0.0] * (target_len - len(fv))
    return fv[:target_len]

def _train_baseline(clusters):
    global _model, _baseline_mean, _baseline_std, _feature_dim
    normal = [_fv(c) for c in clusters if not c.get('has_anomalous', False)]
    if not normal:
        # All clusters anomalous (e.g. attack-heavy dataset) — use all clusters
        normal = [_fv(c) for c in clusters]

    # Filter out empty vectors before computing max dimension
    normal = [v for v in normal if v]
    if not normal:
        # Absolute fallback: synthesize a minimal baseline vector
        normal = [[0.0] * 9]

    # Ensure consistent feature dimension
    _feature_dim = max(len(v) for v in normal)
    normal_padded = [_pad(v, _feature_dim) for v in normal]

    X = np.array(normal_padded)
    _baseline_mean = X.mean(0)
    _baseline_std  = X.std(0) + 1e-9
    _baseline_median = np.median(X, axis=0)
    _baseline_mad = np.median(np.abs(X - _baseline_median), axis=0) + 1e-9

    _small_sample_mode = len(normal_padded) < _small_sample_cutoff

    if _small_sample_mode:
        _model = None
        ts_mode = "tsfresh" if _TSFRESH_OK else "manual"
        print(f'[PHASE 4] Baseline trained on {len(normal)} clusters | '
              f'Feature dim: {_feature_dim} | Mode: {ts_mode} | Scorer: small-sample-robust')
        return

    # IsolationForest with tsfresh-level features
    _model = IForest(
        contamination=0.1,
        random_state=42,
        n_estimators=200,    # More trees for richer feature space
        max_samples='auto',
    )
    _model.fit(X)

    ts_mode = "tsfresh" if _TSFRESH_OK else "manual"
    print(f'[PHASE 4] Baseline trained on {len(normal)} clusters | '
          f'Feature dim: {_feature_dim} | Mode: {ts_mode}')

def score_cluster(cluster):
    raw_fv  = _fv(cluster)
    fv      = _pad(raw_fv, _feature_dim)

    explicit_severity = min(float(cluster.get('explicit_severity_max', 0.0)), 1.0)

    if _small_sample_mode or _model is None:
        robust = _mad_score(fv, _baseline_median, _baseline_mad)
        z_score = _zscore_score(fv, _baseline_mean, _baseline_std)
        signal = _small_batch_signal(cluster)
        anomaly = (0.30 * robust) + (0.15 * z_score) + (0.40 * signal) + (0.15 * explicit_severity)
    else:
        z_score  = _zscore_score(fv, _baseline_mean, _baseline_std)
        if_score = float(expit(_model.decision_function([fv])[0] * -3))
        anomaly  = ((z_score + if_score) / 2)
        anomaly  = (0.85 * anomaly) + (0.15 * explicit_severity)

    fidelity = _fidelity(cluster)
    combined = round(0.6 * anomaly + 0.4 * fidelity, 4)
    severity = _severity(combined)
    if explicit_severity >= 0.85 and combined >= 0.5:
        severity = 'High'

    return {**cluster,
        'feature_vector':  raw_fv[:9],   # Keep 9-dim for Sentinel (schema compat)
        'feature_dim':     len(raw_fv),
        'anomaly_score':   round(anomaly, 4),
        'fidelity_score':  fidelity,
        'combined_score':  combined,
        'final_score':     combined,
        'severity':        severity,
        'explicit_severity': round(explicit_severity, 4),
        'event_sequence':  [l['event_type'] for l in cluster['logs']],
    }

def run(state: dict) -> list:
    clusters = state['clusters']
    _train_baseline(clusters)
    scored = [score_cluster(c) for c in clusters]
    high   = sum(1 for s in scored if s['severity'] == 'High')
    print(f'[PHASE 4] Scored: {len(scored)} | High severity: {high}')
    return scored
