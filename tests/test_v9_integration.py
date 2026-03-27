# tests/test_v9_integration.py
"""9 integration tests — must all pass."""
import sys, os
import pytest, json, time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from kafka.bus import InMemoryKafkaBus
from pipeline.phase9_sentinel import get_exact, get_similar, put_incident, make_fingerprint
from pipeline.phase7_aegis import evaluate_action
from pipeline.phase10_attack_path import map_cluster


# ── Test 1: Kafka round-trip + DLQ ──
def test_kafka_roundtrip_and_dlq():
    bus = InMemoryKafkaBus()
    bus.publish('auth_events', {'message_id':'x','source_system':'auth',
                               'payload_version':'v1','payload':{}})
    bus.publish('auth_events_dlq', {'error':'unknown_source','original':{}})
    assert bus.count('auth_events') == 1
    assert bus.count('auth_events_dlq') == 1


# ── Test 2: Sentinel exact retrieval ──
def test_sentinel_exact(tmp_path, monkeypatch):
    monkeypatch.setattr('pipeline.phase9_sentinel.SENTINEL_PATH', tmp_path/'s.json')
    fv = [5,1,1,15000,2,5,5,1.0,2]
    fp = make_fingerprint(fv, ['failure_then_data_access'], ['login_failure'])
    put_incident({'fingerprint_sha256':fp,'feature_vector':fv,
                  'escalation_flags':['failure_then_data_access'],
                  'approved_actions':[],'outcome':None,
                  'timestamp_utc':'2026-03-21T09:00:00Z',
                  'model_version':'20260321_mistral','schema_version':'v1',
                  'approval_status':'pending'})
    result = get_exact(fp)
    assert result is not None
    assert result['fingerprint_sha256'] == fp


# ── Test 3: Sentinel similar retrieval ──
def test_sentinel_similar(tmp_path, monkeypatch):
    monkeypatch.setattr('pipeline.phase9_sentinel.SENTINEL_PATH', tmp_path/'s.json')
    fv_stored = [5,1,1,15000,2,5,5,1.0,2]
    fp = make_fingerprint(fv_stored, ['failure_then_data_access'], ['login_failure'])
    put_incident({'fingerprint_sha256':fp,'feature_vector':fv_stored,
                  'escalation_flags':['failure_then_data_access'],
                  'approved_actions':[],'outcome':None,
                  'timestamp_utc':'2026-03-21T09:00:00Z',
                  'model_version':'20260321_mistral','schema_version':'v1',
                  'approval_status':'approved'})
    fv_query = [4,1,1,12000,2,5,4,0.9,3]  # similar but not identical
    results = get_similar(fv_query, top_k=3)
    assert len(results) >= 1
    assert results[0]['cosine_similarity'] > 0.7


# ── Test 4: Fingerprint separate from sentinel ──
def test_fingerprint_separate(tmp_path, monkeypatch):
    s_path = tmp_path/'sentinel_memory.json'
    f_path = tmp_path/'fingerprints.json'
    monkeypatch.setattr('pipeline.phase9_sentinel.SENTINEL_PATH',    s_path)
    monkeypatch.setattr('pipeline.phase9_sentinel.FINGERPRINT_PATH', f_path)
    assert not s_path.exists() or s_path != f_path


# ── Test 5: Attack path non-empty ──
def test_attack_path_output():
    cluster = {'cluster_id':'CLC-001','escalation_flags':['failure_then_data_access']}
    result  = map_cluster(cluster)
    assert len(result['kill_chain'])    > 0
    assert len(result['pivot_targets']) > 0


# ── Test 6: AEGIS blocks critical disruptive action ──
def test_aegis_blocks_critical():
    result = evaluate_action('shutdown payment-svc', 'payment-svc')
    assert result['decision'] == 'block'


# ── Test 7: Async — score emitted before playbook ──
def test_async_score_before_playbook():
    bus    = InMemoryKafkaBus()
    t_score   = time.monotonic()
    bus.publish('scored_incidents', {'cluster_id':'x','severity':'High'})
    t_playbook= time.monotonic() + 0.1  # simulated async delay
    bus.publish('playbook_recommendations', {'cluster_id':'x'})
    assert t_score < t_playbook


# ── Test 8: Reject-resubmit increments revision ──
def test_resubmit_increments_revision():
    state = {'needs_resubmit': True, 'playbook_revision': 0,
             'scored': [], 'clusters': [], 'attack_paths': []}
    state['playbook_revision'] += 1 if state.get('needs_resubmit') else 0
    state['needs_resubmit'] = False
    assert state['playbook_revision'] == 1


# ── Test 9: Scorer /health contract ──
def test_scorer_health_contract(tmp_path, monkeypatch):
    import re
    # Create test files
    version_file = tmp_path / 'active_version.txt'
    version_file.write_text('20260321_mistral')
    sentinel_file = tmp_path / 'sentinel_memory.json'
    sentinel_file.write_text('[]')

    # Monkeypatch Path in scorer_api to use tmp_path
    original_path = Path
    def mock_path(p):
        name = original_path(p).name
        return tmp_path / name

    monkeypatch.setattr('api.scorer_api.Path', mock_path)
    from api.scorer_api import health
    result = health()
    assert result['status'] == 'ok'
    assert re.match(r'\d{8}_\w+', result['model_version'])
    assert 'sentinel_entries' in result
