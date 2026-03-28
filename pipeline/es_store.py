# pipeline/es_store.py
"""Elasticsearch integration — index incidents and playbooks for searchability."""
import os, json
from datetime import datetime, timezone

ES_URL = os.environ.get('ES_URL', 'http://localhost:9200')

_es_client = None
_es_available = None

def _get_es():
    global _es_client, _es_available
    if _es_available is False:
        return None
    if _es_client is None:
        try:
            from elasticsearch import Elasticsearch
            _es_client = Elasticsearch(
                [ES_URL],
                request_timeout=10,
                max_retries=2
            )
            if _es_client.ping():
                _es_available = True
                print('[ES] Connected to Elasticsearch')
            else:
                _es_available = False
                _es_client = None
                print('[ES] Elasticsearch not responding — indexing disabled')
        except Exception as e:
            _es_available = False
            _es_client = None
            print(f'[ES] Elasticsearch unavailable: {e}')
    return _es_client

def _index_name(prefix: str) -> str:
    """Generate time-based index name: soc-incidents-2026.03"""
    now = datetime.now(timezone.utc)
    return f'{prefix}-{now.strftime("%Y.%m")}'

def index_incident(scored_cluster: dict) -> bool:
    """Index a scored incident cluster to Elasticsearch."""
    es = _get_es()
    if not es:
        return False
    try:
        doc = {
            'cluster_id':      scored_cluster.get('cluster_id'),
            'primary_user':    scored_cluster.get('primary_user'),
            'severity':        scored_cluster.get('severity'),
            'anomaly_score':   scored_cluster.get('anomaly_score'),
            'fidelity_score':  scored_cluster.get('fidelity_score'),
            'final_score':     scored_cluster.get('final_score'),
            'source_systems':  scored_cluster.get('source_systems', []),
            'escalation_flags':scored_cluster.get('escalation_flags', []),
            'event_count':     scored_cluster.get('log_count', 0),
            'priority':        scored_cluster.get('priority'),
            'timestamp_utc':   datetime.now(timezone.utc).isoformat(),
        }
        es.index(index=_index_name('soc-incidents'), body=doc)
        return True
    except Exception as e:
        print(f'[ES] Index error: {e}')
        return False

def index_playbook(playbook: dict) -> bool:
    """Index a playbook to Elasticsearch."""
    es = _get_es()
    if not es:
        return False
    try:
        doc = {
            'cluster_id':  playbook.get('cluster_id'),
            'severity':    playbook.get('severity'),
            'confidence':  playbook.get('confidence'),
            'source':      playbook.get('source'),
            'revision':    playbook.get('revision'),
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        }
        es.index(index=_index_name('soc-playbooks'), body=doc)
        return True
    except Exception as e:
        print(f'[ES] Playbook index error: {e}')
        return False

def search_incidents(query: str = '*', severity: str = None, size: int = 50) -> list:
    """Search indexed incidents."""
    es = _get_es()
    if not es:
        return []
    try:
        body = {'query': {'bool': {'must': []}}}
        if query != '*':
            body['query']['bool']['must'].append({'query_string': {'query': query}})
        if severity:
            body['query']['bool']['must'].append({'term': {'severity.keyword': severity}})
        if not body['query']['bool']['must']:
            body = {'query': {'match_all': {}}}
        result = es.search(index=_index_name('soc-incidents'), body=body, size=size)
        return [hit['_source'] for hit in result['hits']['hits']]
    except Exception as e:
        print(f'[ES] Search error: {e}')
        return []

def bulk_index(scored_clusters: list, playbooks: list) -> dict:
    """Bulk index scored clusters and playbooks."""
    indexed_incidents = sum(1 for s in scored_clusters if index_incident(s))
    indexed_playbooks = sum(1 for p in playbooks if index_playbook(p))
    print(f'[ES] Indexed: {indexed_incidents} incidents, {indexed_playbooks} playbooks')
    return {'incidents': indexed_incidents, 'playbooks': indexed_playbooks}
