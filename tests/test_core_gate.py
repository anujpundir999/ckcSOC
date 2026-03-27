# tests/test_core_gate.py
"""8 core pipeline tests — must all pass."""
import sys, os
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline.phase2_normalize import normalize_one, EVENT_CATEGORY_MAP
from pipeline.phase3_correlate import _detect_flags, _is_subseq, _priority
from pipeline.phase4_score import _fv, _severity
from pipeline.phase7_aegis import evaluate_action
from pipeline.phase10_attack_path import map_cluster


# ── Test 1: Normalize preserves user ──
def test_normalize_preserves_user():
    envelope = {
        'event_time_utc': '2026-03-15T10:00:00+00:00',
        'source_system': 'auth',
        'payload': {
            'user': 'testuser',
            'event': 'login_success',
            'ip': '192.168.1.1',
            'device': 'CORP-TESTUSER-LT',
            'is_anomalous': False
        }
    }
    result = normalize_one(envelope)
    assert result['user'] == 'testuser'
    assert result['event_type'] == 'login_success'
    assert result['event_category'] == 'authentication'


# ── Test 2: Event category mapping complete ──
def test_event_category_mapping():
    expected_events = ['login_failure','login_success','mfa_bypass','device_change',
                       'privilege_escalation','process_create','db_access','db_export',
                       'email_alert','network_transfer','siem_alert']
    for ev in expected_events:
        assert ev in EVENT_CATEGORY_MAP, f'{ev} missing from category map'


# ── Test 3: Escalation flag detection ──
def test_escalation_flag_detection():
    seq = ['login_failure','login_failure','login_success','db_access']
    flags = _detect_flags(seq)
    assert 'failure_then_data_access' in flags
    assert 'possible_compromise' in flags


# ── Test 4: Subsequence checker ──
def test_subsequence_checker():
    assert _is_subseq(['a','b'], ['a','x','b','y']) is True
    assert _is_subseq(['b','a'], ['a','b']) is False


# ── Test 5: Priority assignment ──
def test_priority_assignment():
    # Critical flags → critical
    assert _priority(['credential_then_privilege'], 2, 1) == 'critical'
    # High flags → high
    assert _priority(['failure_then_data_access'], 2, 1) == 'high'
    # No flags, multi-system + high anomaly → high
    assert _priority([], 3, 4) == 'high'
    # No flags, single system → low
    assert _priority([], 1, 0) == 'low'


# ── Test 6: Feature vector shape ──
def test_feature_vector_shape():
    cluster = {
        'logs': [
            {'event_type': 'login_failure', 'source_system': 'auth', 'is_anomalous': True},
            {'event_type': 'db_access', 'source_system': 'db', 'is_anomalous': False},
        ],
        'anomalous_count': 1,
        'escalation_flags': ['failure_then_data_access'],
    }
    fv = _fv(cluster)
    assert len(fv) == 9, f'Feature vector must be 9-dim, got {len(fv)}'


# ── Test 7: Severity thresholds ──
def test_severity_thresholds():
    assert _severity(0.70) == 'High'
    assert _severity(0.50) == 'Medium'
    assert _severity(0.20) == 'Low'


# ── Test 8: AEGIS allows non-disruptive action ──
def test_aegis_allows_nondisruptive():
    result = evaluate_action('monitor user activity', 'email-gw')
    assert result['decision'] == 'allow'
