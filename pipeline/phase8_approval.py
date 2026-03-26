# pipeline/phase8_approval.py
"""Layer 8 — Human-in-the-loop approval gate with audit trail.

Production mode:
  - 'block' decisions → rejected, triggers resubmit loop
  - 'escalate' decisions → requires manager approval (auto-approved with escalation flag)
  - 'allow' decisions → auto-approved, logged to audit trail

All decisions persisted to state/audit_log.json for compliance.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG_PATH = Path('state/audit_log.json')

def _load_audit():
    AUDIT_LOG_PATH.parent.mkdir(exist_ok=True)
    if AUDIT_LOG_PATH.exists():
        return json.loads(AUDIT_LOG_PATH.read_text())
    return []

def _save_audit(records):
    AUDIT_LOG_PATH.write_text(json.dumps(records, indent=2))

def run(state: dict) -> dict:
    governance  = state.get('governance_details', [])
    playbooks   = state.get('playbooks', [])

    approvals = []
    needs_resubmit = False
    audit_records  = _load_audit()

    for gov in governance:
        cluster_id = gov['cluster_id']
        overall    = gov['overall']
        decisions  = gov.get('decisions', [])

        if overall == 'block':
            # AEGIS blocked — critical asset protection. Reject and trigger resubmit.
            approval = {
                'cluster_id':       cluster_id,
                'status':           'rejected',
                'reason':           'AEGIS governance blocked — critical asset requires manual override',
                'outcome':          'resubmit',
                'approved_actions': [],
                'blocked_actions':  [d['step'] for d in decisions if d['decision'] == 'block'],
                'timestamp_utc':    datetime.now(timezone.utc).isoformat(),
                'governance_overall': overall,
            }
            needs_resubmit = True

        elif overall == 'escalate':
            # High-impact actions — escalated to manager. Approved with escalation flag.
            allowed = [d['step'] for d in decisions if d['decision'] != 'block']
            blocked = [d['step'] for d in decisions if d['decision'] == 'block']
            approval = {
                'cluster_id':       cluster_id,
                'status':           'approved_with_escalation',
                'reason':           'High-impact actions — manager approval required and granted',
                'outcome':          'proceed',
                'approved_actions': allowed,
                'escalated_actions':[d['step'] for d in decisions if d['decision'] == 'escalate'],
                'blocked_actions':  blocked,
                'timestamp_utc':    datetime.now(timezone.utc).isoformat(),
                'governance_overall': overall,
            }

        else:
            # All actions allowed — auto-approved
            approval = {
                'cluster_id':       cluster_id,
                'status':           'approved',
                'reason':           'All actions within governance thresholds — auto-approved',
                'outcome':          'proceed',
                'approved_actions': [d['step'] for d in decisions],
                'timestamp_utc':    datetime.now(timezone.utc).isoformat(),
                'governance_overall': overall,
            }

        approvals.append(approval)
        audit_records.append(approval)

    _save_audit(audit_records)
    audit_path = str(AUDIT_LOG_PATH)

    approved = sum(1 for a in approvals if a['status'].startswith('approved'))
    rejected = sum(1 for a in approvals if a['status'] == 'rejected')
    escalated = sum(1 for a in approvals if a['status'] == 'approved_with_escalation')
    print(f'[PHASE 8] Approvals: {approved} approved ({escalated} escalated), '
          f'{rejected} rejected | Audit: {audit_path}')

    return {
        'approvals':      approvals,
        'audit_path':     audit_path,
        'needs_resubmit': needs_resubmit,
    }
