# api/dashboard_api.py
"""Dashboard data API — serves pipeline state to the web console."""
import json
from pathlib import Path
from fastapi import FastAPI, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

router = APIRouter(prefix='/api/dashboard', tags=['dashboard'])

STATE_DIR = Path('state')
DATASETS_DIR = Path('datasets')


def _read_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return default if default is not None else []


@router.get('/summary')
def pipeline_summary():
    """Overall pipeline status summary."""
    sentinel = _read_json(STATE_DIR / 'sentinel_memory.json', [])
    audit = _read_json(STATE_DIR / 'audit_log.json', [])
    drift = _read_json(STATE_DIR / 'drift_log.json', [])
    model_path = Path('models/active_version.txt')
    model_version = model_path.read_text().strip() if model_path.exists() else 'not_loaded'

    return {
        'pipeline_name': 'ckcSOC — 11-Layer Cyber Incident Response',
        'model_version': model_version,
        'total_incidents': len(sentinel),
        'total_approvals': len(audit),
        'drift_checks': len(drift),
        'latest_drift': drift[-1] if drift else None,
        'phases': [
            {'id': 1, 'name': 'Ingest', 'status': 'active'},
            {'id': 2, 'name': 'Normalize', 'status': 'active'},
            {'id': 3, 'name': 'Correlate', 'status': 'active'},
            {'id': 4, 'name': 'Score', 'status': 'active'},
            {'id': 5, 'name': 'Explain', 'status': 'active'},
            {'id': 6, 'name': 'Playbook', 'status': 'active'},
            {'id': 7, 'name': 'AEGIS', 'status': 'active'},
            {'id': 8, 'name': 'Approval', 'status': 'active'},
            {'id': 9, 'name': 'Sentinel', 'status': 'active'},
            {'id': 10, 'name': 'Attack Path', 'status': 'active'},
            {'id': 11, 'name': 'Feedback', 'status': 'active'},
        ]
    }


@router.get('/incidents')
def get_incidents():
    """Sentinel memory — stored incidents."""
    sentinel = _read_json(STATE_DIR / 'sentinel_memory.json', [])
    return {'count': len(sentinel), 'incidents': sentinel}


@router.get('/audit')
def get_audit():
    """Audit trail — all approval decisions."""
    audit = _read_json(STATE_DIR / 'audit_log.json', [])
    return {'count': len(audit), 'records': audit}


@router.get('/severity-distribution')
def severity_distribution():
    """Severity breakdown for charts."""
    sentinel = _read_json(STATE_DIR / 'sentinel_memory.json', [])
    # Count by approval status
    approved = sum(1 for r in sentinel if r.get('approval_status', '').startswith('approved'))
    rejected = sum(1 for r in sentinel if r.get('approval_status') == 'rejected')
    pending = sum(1 for r in sentinel if r.get('approval_status') == 'pending')
    # Count by escalation flags
    flag_counts = {}
    for r in sentinel:
        for flag in r.get('escalation_flags', []):
            flag_counts[flag] = flag_counts.get(flag, 0) + 1
    return {
        'total': len(sentinel),
        'by_status': {'approved': approved, 'rejected': rejected, 'pending': pending},
        'by_flag': flag_counts,
    }


@router.get('/drift')
def get_drift():
    """Model drift monitoring log."""
    drift = _read_json(STATE_DIR / 'drift_log.json', [])
    baseline = _read_json(STATE_DIR / 'scoring_baseline.json')
    return {
        'checks': len(drift),
        'latest': drift[-1] if drift else None,
        'baseline_exists': baseline is not None,
        'history': drift[-20:],  # Last 20 checks
    }


@router.get('/dataset-stats')
def dataset_stats():
    """Dataset statistics."""
    all_events = _read_json(DATASETS_DIR / 'all_events.json', [])
    by_source = {}
    for e in all_events:
        src = e.get('source_system', 'unknown')
        by_source[src] = by_source.get(src, 0) + 1
    anomalous = sum(1 for e in all_events if e.get('payload', {}).get('is_anomalous', False))
    return {
        'total_events': len(all_events),
        'by_source': by_source,
        'anomalous_count': anomalous,
        'normal_count': len(all_events) - anomalous,
    }


def mount_dashboard(app: FastAPI):
    """Mount the dashboard routes and static files on an existing FastAPI app."""
    app.include_router(router)
    dashboard_dir = Path(__file__).parent.parent / 'dashboard'
    if dashboard_dir.exists():
        app.mount('/dashboard', StaticFiles(directory=str(dashboard_dir), html=True), name='dashboard')
