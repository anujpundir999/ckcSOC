# pipeline/phase11_retrain.py
"""Layer 11 — Feedback loop and model retraining trigger."""
import json, hashlib
from datetime import datetime, timezone
from pathlib import Path

MODEL_VERSION_PATH = Path('models/active_version.txt')

def _current_version():
    if MODEL_VERSION_PATH.exists():
        return MODEL_VERSION_PATH.read_text().strip()
    return 'not_loaded'

def _stamp_new_version():
    ts = datetime.now(timezone.utc).strftime('%Y%m%d')
    new_version = f'{ts}_retrained'
    MODEL_VERSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_VERSION_PATH.write_text(new_version)
    return new_version

def _collect_feedback(state):
    """Collect outcome feedback from approvals for retraining signal."""
    feedback = []
    for approval in state.get('approvals', []):
        feedback.append({
            'cluster_id':       approval.get('cluster_id'),
            'status':           approval.get('status'),
            'outcome':          approval.get('outcome'),
            'approved_actions': len(approval.get('approved_actions', [])),
            'timestamp_utc':    approval.get('timestamp_utc'),
        })
    return feedback

def _should_retrain(feedback):
    """Determine if retraining is warranted based on feedback signals."""
    if not feedback:
        return False
    rejected = sum(1 for f in feedback if f['status'] == 'rejected')
    total = len(feedback)
    # Retrain if >30% of playbooks were rejected (model drift signal)
    return rejected / max(total, 1) > 0.3

def run(state: dict) -> dict:
    feedback = _collect_feedback(state)
    retrain = _should_retrain(feedback)

    current = _current_version()
    new_version = None

    if retrain:
        new_version = _stamp_new_version()
        print(f'[PHASE 11] Retraining triggered: {current} → {new_version}')
    else:
        print(f'[PHASE 11] No retrain needed. Current model: {current}. Feedback: {len(feedback)} records')

    return {
        'feedback_count':   len(feedback),
        'retrain_triggered': retrain,
        'previous_version': current,
        'new_version':      new_version,
    }
