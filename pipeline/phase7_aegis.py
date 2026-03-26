# pipeline/phase7_aegis.py
ASSETS = {
    'payment-svc':  {'criticality':'critical','impact':10,'blast':'HIGH'},
    'auth-svc':     {'criticality':'critical','impact':9, 'blast':'HIGH'},
    'core-banking': {'criticality':'critical','impact':10,'blast':'HIGH'},
    'email-gw':     {'criticality':'medium',  'impact':4, 'blast':'LOW'},
    'monitoring':   {'criticality':'low',     'impact':2, 'blast':'NONE'},
}
DISRUPTIVE = ['block','isolate','shutdown','terminate','disable','revoke']

def evaluate_action(action: str, asset: str = '') -> dict:
    is_disruptive = any(k in action.lower() for k in DISRUPTIVE)
    meta = ASSETS.get(asset, {'criticality':'unknown','impact':5,'blast':'MEDIUM'})
    if meta['criticality'] == 'critical' and is_disruptive:
        return {'decision':'block',    'reason':f'Critical asset {asset} — manual only'}
    if meta['impact'] >= 7 and is_disruptive:
        return {'decision':'escalate', 'reason':f'High impact — manager approval needed'}
    return     {'decision':'allow',    'reason':'Low impact — auto-approved'}

def evaluate_playbook(playbook: dict) -> dict:
    decisions = []
    phases = playbook.get('nist_phases', {})
    all_steps = []
    if isinstance(phases, dict):
        for steps in phases.values():
            if isinstance(steps, list):
                all_steps.extend(steps)
            elif isinstance(steps, str):
                all_steps.append(steps)
    for step in all_steps[:10]:
        result = evaluate_action(str(step))
        decisions.append({'step': step, **result})
    block_count    = sum(1 for d in decisions if d['decision']=='block')
    escalate_count = sum(1 for d in decisions if d['decision']=='escalate')
    overall = 'block' if block_count > 0 else 'escalate' if escalate_count > 0 else 'allow'
    return {'cluster_id': playbook['cluster_id'], 'overall': overall, 'decisions': decisions}

def run(state: dict) -> list:
    results = [evaluate_playbook(p) for p in state['playbooks']]
    blocked = sum(1 for r in results if r['overall']=='block')
    print(f'[PHASE 7] AEGIS: {len(results)} evaluated | {blocked} blocked')
    return results
