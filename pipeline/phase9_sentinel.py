# pipeline/phase9_sentinel.py
import json, math, hashlib
from datetime import datetime, timezone
from pathlib import Path

SENTINEL_PATH    = Path('state/sentinel_memory.json')
FINGERPRINT_PATH = Path('state/fingerprints.json')

def _load_sentinel():
    SENTINEL_PATH.parent.mkdir(exist_ok=True)
    return json.loads(SENTINEL_PATH.read_text()) if SENTINEL_PATH.exists() else []

def _save_sentinel(records):
    SENTINEL_PATH.write_text(json.dumps(records, indent=2))

def _cosine(a, b):
    if len(a) != len(b) or not a or not b:
        return 0.0
    dot = sum(x*y for x,y in zip(a,b))
    ma  = math.sqrt(sum(x*x for x in a))
    mb  = math.sqrt(sum(x*x for x in b))
    return dot/(ma*mb) if ma and mb else 0.0

def make_fingerprint(fv, flags, seq):
    data = json.dumps({'fv':[round(x,3) for x in sorted(fv)],
                       'flags':sorted(flags),'seq':seq[:5]}, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()

def get_exact(fp):
    return next((r for r in _load_sentinel() if r['fingerprint_sha256']==fp), None)

def get_similar(fv, top_k=3):
    results = [dict(**r, cosine_similarity=_cosine(fv, r.get('feature_vector',[])))
               for r in _load_sentinel()]
    return sorted(results, key=lambda x: x['cosine_similarity'], reverse=True)[:top_k]

def put_incident(record):
    records = _load_sentinel()
    for i,r in enumerate(records):
        if r['fingerprint_sha256']==record['fingerprint_sha256']:
            records[i] = record
            _save_sentinel(records)
            return
    records.append(record)
    _save_sentinel(records)

def run(state: dict) -> list:
    matches = []
    es_indexed = 0
    for scored in state['scored']:
        if scored['severity'] in ('High','Critical'):
            fv   = scored.get('feature_vector', [])
            fp   = make_fingerprint(fv, scored['escalation_flags'], scored['event_sequence'])
            approval = next((a for a in state.get('approvals',[])
                            if a.get('cluster_id')==scored['cluster_id']), {})
            put_incident({
                'fingerprint_sha256': fp,
                'feature_vector':     fv,
                'escalation_flags':   scored['escalation_flags'],
                'approved_actions':   approval.get('approved_actions', []),
                'outcome':            approval.get('outcome', None),
                'timestamp_utc':      datetime.now(timezone.utc).isoformat(),
                'model_version':      '20260321_mistral',
                'schema_version':     'v1',
                'approval_status':    approval.get('status', 'pending')
            })
            similar = get_similar(fv, top_k=3)
            matches.append({'cluster_id': scored['cluster_id'], 'similar': similar})
            # Index to Elasticsearch (graceful — won't fail if ES is down)
            try:
                from pipeline.es_store import index_incident
                if index_incident(scored):
                    es_indexed += 1
            except Exception:
                pass
    es_msg = f' | ES indexed: {es_indexed}' if es_indexed else ''
    print(f'[PHASE 9] Sentinel updated: {len(matches)} high incidents stored{es_msg}')
    return matches

