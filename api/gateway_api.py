# api/gateway_api.py
from fastapi import FastAPI, HTTPException, Depends, Header
from pathlib import Path
import json

app = FastAPI(title='ckcSOC Gateway')

# Mount dashboard
from api.dashboard_api import mount_dashboard
mount_dashboard(app)

TOKENS = {'reader-token-xxx': 'reader', 'approver-token-yyy': 'approver',
          'admin-token-zzz': 'admin'}

def auth(authorization: str = Header(...)):
    token = authorization.replace('Bearer ', '')
    if token not in TOKENS:
        raise HTTPException(401, 'Invalid token')
    return TOKENS[token]

@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'gateway'}

@app.post('/ingest')
def ingest(payload: dict, role=Depends(auth)):
    from kafka.producer import publish
    publish(payload['source_system'], payload['data'])
    return {'status': 'queued'}

@app.get('/playbook/{cluster_id}')
def get_playbook(cluster_id: str, role=Depends(auth)):
    path = Path('state/playbooks.json')
    if not path.exists():
        raise HTTPException(404, 'No playbooks')
    books = json.loads(path.read_text())
    book  = next((b for b in books if b['cluster_id']==cluster_id), None)
    if not book:
        raise HTTPException(404, 'Playbook not found')
    return book
