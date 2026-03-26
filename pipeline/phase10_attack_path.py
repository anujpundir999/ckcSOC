# pipeline/phase10_attack_path.py
MITRE = {
    'failure_then_data_access': {
        'kill_chain':       ['T1078 Valid Accounts','T1083 File Discovery','T1041 Exfiltration'],
        'pivot_targets':    ['DC-01','payment-svc'],
        'high_risk_assets': ['auth-svc','core-banking'],
        'preventive':       ['Enable MFA on all accounts','Monitor DC-01 lateral movement'],
    },
    'email_exfiltration_risk': {
        'kill_chain':       ['T1114 Email Collection','T1048 Exfiltration Alt Protocol'],
        'pivot_targets':    ['email-gateway','external-smtp'],
        'high_risk_assets': ['email-gw'],
        'preventive':       ['Block external email forwarding','DLP on attachments'],
    },
    'credential_then_privilege': {
        'kill_chain':       ['T1078 Valid Accounts','T1068 Exploit for Privilege Escalation','T1003 Credential Dumping'],
        'pivot_targets':    ['DC-01','backup-server'],
        'high_risk_assets': ['auth-svc','core-banking','payment-svc'],
        'preventive':       ['Enforce least privilege','PAM solution for admin accounts'],
    },
    'lateral_movement_suspected': {
        'kill_chain':       ['T1021 Remote Services','T1078 Valid Accounts','T1550 Pass the Hash'],
        'pivot_targets':    ['DC-01','file-server','backup-server'],
        'high_risk_assets': ['DC-01','payment-svc'],
        'preventive':       ['Network segmentation','SMB signing enforcement'],
    },
    'possible_compromise': {
        'kill_chain':       ['T1078 Valid Accounts','T1110 Brute Force'],
        'pivot_targets':    ['DC-01'],
        'high_risk_assets': ['auth-svc'],
        'preventive':       ['Account lockout policy','MFA enforcement'],
    },
}

def map_cluster(cluster):
    tactics, pivots, assets, preventive = [], [], [], []
    for flag in cluster['escalation_flags']:
        m = MITRE.get(flag, {})
        tactics   += m.get('kill_chain', [])
        pivots    += m.get('pivot_targets', [])
        assets    += m.get('high_risk_assets', [])
        preventive+= m.get('preventive', [])
    return {
        'cluster_id':      cluster['cluster_id'],
        'kill_chain':      list(dict.fromkeys(tactics)),
        'pivot_targets':   list(dict.fromkeys(pivots)),
        'high_risk_assets':list(dict.fromkeys(assets)),
        'preventive_recs': list(dict.fromkeys(preventive)),
    }

def run(state: dict) -> list:
    paths = [map_cluster(c) for c in state['clusters']]
    has_tactics = sum(1 for p in paths if p['kill_chain'])
    print(f'[PHASE 10] Attack paths: {len(paths)} | With MITRE tactics: {has_tactics}')
    return paths
