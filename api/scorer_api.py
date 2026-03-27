# api/scorer_api.py
from fastapi import FastAPI
from pathlib import Path
import json

app = FastAPI(title='ckcSOC Scorer')

@app.get('/health')
def health():
    version_path = Path('models/active_version.txt')
    version      = version_path.read_text().strip() if version_path.exists() else 'not_loaded'
    sentinel_path= Path('state/sentinel_memory.json')
    entries      = len(json.loads(sentinel_path.read_text())) if sentinel_path.exists() else 0
    return {
        'status':          'ok',
        'service':         'scorer',
        'schema_version':  'v1',
        'model_version':   version,
        'model_loaded_at': '2026-03-21T09:00:00Z',
        'sentinel_entries': entries
    }
