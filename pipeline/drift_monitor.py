# pipeline/drift_monitor.py
"""Model drift monitoring — compares live scoring distributions against baseline."""
import json, time, math
import numpy as np
from pathlib import Path
from datetime import datetime, timezone

BASELINE_PATH = Path('state/scoring_baseline.json')
DRIFT_LOG_PATH = Path('state/drift_log.json')
CHECK_INTERVAL = 300  # seconds between drift checks

def _load_baseline():
    if BASELINE_PATH.exists():
        return json.loads(BASELINE_PATH.read_text())
    return None

def _save_baseline(stats):
    BASELINE_PATH.parent.mkdir(exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(stats, indent=2))

def _load_drift_log():
    DRIFT_LOG_PATH.parent.mkdir(exist_ok=True)
    if DRIFT_LOG_PATH.exists():
        return json.loads(DRIFT_LOG_PATH.read_text())
    return []

def _save_drift_log(records):
    DRIFT_LOG_PATH.write_text(json.dumps(records, indent=2))

def compute_stats(scores: list) -> dict:
    """Compute distribution statistics for a list of scores."""
    if not scores:
        return {'mean': 0, 'std': 0, 'p50': 0, 'p95': 0, 'count': 0}
    arr = np.array(scores)
    return {
        'mean':  round(float(arr.mean()), 4),
        'std':   round(float(arr.std()), 4),
        'p50':   round(float(np.percentile(arr, 50)), 4),
        'p95':   round(float(np.percentile(arr, 95)), 4),
        'count': len(scores),
    }

def psi(expected: list, actual: list, bins: int = 10) -> float:
    """Population Stability Index — measures distribution shift."""
    if not expected or not actual:
        return 0.0
    e_hist, bin_edges = np.histogram(expected, bins=bins, density=True)
    a_hist, _ = np.histogram(actual, bins=bin_edges, density=True)
    # Add small epsilon to avoid division by zero
    eps = 1e-6
    e_hist = e_hist + eps
    a_hist = a_hist + eps
    # Normalize
    e_hist = e_hist / e_hist.sum()
    a_hist = a_hist / a_hist.sum()
    return float(np.sum((a_hist - e_hist) * np.log(a_hist / e_hist)))

def ks_statistic(expected: list, actual: list) -> float:
    """Kolmogorov-Smirnov statistic — max distance between CDFs."""
    if not expected or not actual:
        return 0.0
    from scipy.stats import ks_2samp
    stat, _ = ks_2samp(expected, actual)
    return round(float(stat), 4)

def check_drift(current_scores: list, threshold_psi: float = 0.2,
                threshold_ks: float = 0.15) -> dict:
    """Compare current scoring distribution against baseline."""
    baseline = _load_baseline()

    if baseline is None:
        # First run — establish baseline
        stats = compute_stats(current_scores)
        _save_baseline({
            'scores': current_scores[:1000],  # Keep up to 1000 for comparison
            'stats': stats,
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        })
        return {
            'status': 'baseline_established',
            'stats': stats,
            'drift_detected': False,
        }

    baseline_scores = baseline.get('scores', [])
    current_stats = compute_stats(current_scores)
    baseline_stats = baseline.get('stats', {})

    # Compute drift metrics
    psi_value = psi(baseline_scores, current_scores)
    ks_value = ks_statistic(baseline_scores, current_scores)
    mean_shift = abs(current_stats['mean'] - baseline_stats.get('mean', 0))

    drift_detected = psi_value > threshold_psi or ks_value > threshold_ks

    result = {
        'status': 'drift_detected' if drift_detected else 'stable',
        'psi': round(psi_value, 4),
        'ks_statistic': ks_value,
        'mean_shift': round(mean_shift, 4),
        'threshold_psi': threshold_psi,
        'threshold_ks': threshold_ks,
        'drift_detected': drift_detected,
        'current_stats': current_stats,
        'baseline_stats': baseline_stats,
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
    }

    # Log drift check
    drift_log = _load_drift_log()
    drift_log.append(result)
    _save_drift_log(drift_log[-100:])  # Keep last 100 checks

    if drift_detected:
        print(f'[DRIFT MONITOR] ⚠️  DRIFT DETECTED — PSI: {psi_value:.4f}, KS: {ks_value:.4f}')
        print(f'[DRIFT MONITOR] Baseline mean: {baseline_stats.get("mean")}, Current mean: {current_stats["mean"]}')
    else:
        print(f'[DRIFT MONITOR] ✓ Stable — PSI: {psi_value:.4f}, KS: {ks_value:.4f}')

    return result

def run_continuous():
    """Continuous monitoring loop for Docker service."""
    print('[DRIFT MONITOR] Starting continuous monitoring...')
    while True:
        try:
            sentinel_path = Path('state/sentinel_memory.json')
            if sentinel_path.exists():
                records = json.loads(sentinel_path.read_text())
                scores = [r.get('feature_vector', [0])[0] for r in records if r.get('feature_vector')]
                if len(scores) >= 5:
                    check_drift(scores)
                else:
                    print(f'[DRIFT MONITOR] Waiting for data ({len(scores)} records)...')
            else:
                print('[DRIFT MONITOR] No sentinel data yet...')
        except Exception as e:
            print(f'[DRIFT MONITOR] Error: {e}')
        time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--once', action='store_true', help='Run single check')
    args = ap.parse_args()
    if args.once:
        sentinel_path = Path('state/sentinel_memory.json')
        if sentinel_path.exists():
            records = json.loads(sentinel_path.read_text())
            scores = [r.get('feature_vector', [0])[0] for r in records if r.get('feature_vector')]
            result = check_drift(scores)
            print(json.dumps(result, indent=2))
    else:
        run_continuous()
