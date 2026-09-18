# pipeline/phase6_playbook.py
"""Layer 6 — LLM-powered playbook generation via Ollama.

Ollama Parameters Used:
  model:        'mistral' (7.2B Q4_K_M) — primary model
  temperature:  0.3 — low creativity, high consistency for SOC playbooks
  num_predict:  800 — max tokens to generate (~600 words)
  top_p:        0.9 — nucleus sampling for balanced diversity
  top_k:        40  — limits token pool for coherent output
  repeat_penalty: 1.1 — discourages repetitive text
  stream:       False — wait for full response (production batch mode)
  timeout:      90s — generous timeout for 7B model on CPU

Falls back to structured NIST 800-61 templates if LLM is unavailable.
"""
import os, json, requests
from datetime import datetime, timezone

# ── Ollama Configuration ──
OLLAMA_URL  = os.environ.get('OLLAMA_URL', 'http://localhost:11434') + '/api/generate'
MODEL       = os.environ.get('OLLAMA_MODEL', 'mistral')
FALLBACK    = 'llama3.2:3b'
TIMEOUT     = 90
MIN_WORDS   = 80
MAX_RETRIES = 2

# ── Secure Channel Config (for distributed LLM on separate machine) ──
# Set OLLAMA_API_KEY to require Bearer token auth on the remote Ollama
OLLAMA_API_KEY   = os.environ.get('OLLAMA_API_KEY', '')       # e.g. 'sk-soc-barclays-xxx'
# Set OLLAMA_VERIFY_SSL=false to use self-signed certs during dev
OLLAMA_VERIFY_SSL = os.environ.get('OLLAMA_VERIFY_SSL', 'true').lower() != 'false'
# Set OLLAMA_CERT=/path/to/client.pem for mutual TLS (mTLS)
OLLAMA_CERT      = os.environ.get('OLLAMA_CERT', '')          # client cert for mTLS

def _build_headers() -> dict:
    """Build request headers — adds Bearer auth if API key is configured."""
    h = {'Content-Type': 'application/json'}
    if OLLAMA_API_KEY:
        h['Authorization'] = f'Bearer {OLLAMA_API_KEY}'
    return h

def _get_cert():
    """Return cert config for requests — supports both mTLS and no-cert modes."""
    if OLLAMA_CERT and os.path.exists(OLLAMA_CERT):
        return OLLAMA_CERT
    return None

# ── Ollama Model Parameters ──
OLLAMA_PARAMS = {
    'temperature':    0.3,
    'num_predict':    800,
    'top_p':          0.9,
    'top_k':          40,
    'repeat_penalty': 1.1,
    'num_ctx':        4096,
    'seed':           42,
}

# ── NIST 800-61 Template Playbooks ──
TEMPLATES = {
    'failure_then_data_access': {
        'immediate':    ['Disable {user} account in Active Directory immediately',
                         'Capture active session tokens before revocation',
                         'Preserve DB query logs from incident window'],
        'containment':  ['Block {user} outbound network access',
                         'Revoke all OAuth tokens for {user}',
                         'Enable enhanced monitoring on peer accounts'],
        'investigation':['Review all DB queries by {user} in past 30 days',
                         'Check email forwarding rules',
                         'Identify all IPs that received exported data'],
        'recovery':     ['Force password reset via MFA channel only',
                         'Re-enable after manager + security sign-off'],
    },
    'credential_then_privilege': {
        'immediate':    ['Lock {user} account across all systems',
                         'Revoke active sessions and VPN access',
                         'Alert SOC commander and CISO'],
        'containment':  ['Isolate affected endpoints',
                         'Block lateral movement paths',
                         'Enable PAM audit on privilege escalation'],
        'investigation':['Dump credential cache from affected hosts',
                         'Review privilege escalation timeline',
                         'Check for golden ticket indicators'],
        'recovery':     ['Full credential rotation for {user}',
                         'Review and harden PAM policies'],
    },
    'lateral_movement_suspected': {
        'immediate':    ['Isolate source and destination hosts',
                         'Capture memory dumps before remediation',
                         'Alert network operations center'],
        'containment':  ['Block SMB/RDP between segments',
                         'Enable enhanced network monitoring',
                         'Disable suspicious service accounts'],
        'investigation':['Map full lateral movement path',
                         'Check for pass-the-hash indicators',
                         'Review all logins from source IP'],
        'recovery':     ['Re-image compromised endpoints',
                         'Enforce network segmentation changes'],
    },
    'email_exfiltration_risk': {
        'immediate':    ['Block external email forwarding for {user}',
                         'Quarantine recent emails with attachments',
                         'Alert DLP team'],
        'containment':  ['Enable attachment scanning',
                         'Block {user} external communication',
                         'Review email rules'],
        'investigation':['Audit all emails sent by {user} in past 7 days',
                         'Check for auto-forwarding rules',
                         'Identify all external recipients'],
        'recovery':     ['Remove unauthorized forwarding rules',
                         'Reset {user} email credentials'],
    },
    'possible_compromise': {
        'immediate':    ['Force {user} password reset immediately',
                         'Revoke all active sessions',
                         'Enable account lockout for 30 minutes'],
        'containment':  ['Monitor {user} activity across all systems',
                         'Block suspicious source IPs at firewall',
                         'Enable geo-based login restrictions'],
        'investigation':['Correlate failed logins with successful auth events',
                         'Check for credential stuffing indicators',
                         'Review MFA enrollment status for {user}'],
        'recovery':     ['Enforce MFA re-enrollment',
                         'Review and strengthen password policy'],
    },
    '_default': {
        'immediate':    ['Alert incident commander and security team',
                         'Begin incident log with timestamps',
                         'Preserve all evidence — do not alter systems'],
        'containment':  ['Isolate affected accounts',
                         'Monitor all related user activity'],
        'investigation':['Collect and preserve relevant logs',
                         'Identify scope and timeline'],
        'recovery':     ['Follow standard account recovery procedure'],
    }
}

def _fill(steps, user):
    return [s.format(user=user) for s in steps]

def _template_playbook(cluster, scored):
    user  = cluster['primary_user']
    flags = cluster['escalation_flags']
    tmpl  = next((TEMPLATES[f] for f in flags if f in TEMPLATES), TEMPLATES['_default'])
    return {k: _fill(v, user) for k, v in tmpl.items()}

def _llm(prompt, model=MODEL, retry=0):
    """Call Ollama API with full production parameters and secure channel support."""
    try:
        r = requests.post(
            OLLAMA_URL,
            json={'model': model, 'prompt': prompt, 'stream': False, 'options': OLLAMA_PARAMS},
            headers=_build_headers(),
            timeout=TIMEOUT,
            verify=OLLAMA_VERIFY_SSL,
            cert=_get_cert() or None,
        )
        r.raise_for_status()
        resp = r.json()
        text = resp.get('response', '').strip()

        eval_count    = resp.get('eval_count', 0)
        eval_duration = resp.get('eval_duration', 0)
        tokens_per_sec = eval_count / (eval_duration / 1e9) if eval_duration else 0

        if text and len(text.split()) >= MIN_WORDS:
            return text, {
                'model': model,
                'tokens_generated': eval_count,
                'tokens_per_sec': round(tokens_per_sec, 1),
                'total_duration_ms': round(resp.get('total_duration', 0) / 1e6, 1),
            }
        elif retry < MAX_RETRIES:
            return _llm(prompt, model, retry + 1)
        return None, None
    except requests.exceptions.ConnectionError:
        print(f'[PHASE 6] Ollama not reachable at {OLLAMA_URL}')
        return None, None
    except requests.exceptions.Timeout:
        if retry < MAX_RETRIES:
            return _llm(prompt, model, retry + 1)
        return None, None
    except Exception as e:
        print(f'[PHASE 6] LLM error: {e}')
        return None, None

def _build_prompt(user, severity, flags, systems, mitre, event_seq):
    """Production SOC playbook prompt — NIST 800-61 compliant."""
    return f"""You are a senior cybersecurity incident response analyst at Barclays Bank.

INCIDENT CONTEXT:
- Affected User: {user}
- Severity: {severity}
- Escalation Flags: {flags}
- Source Systems Involved: {systems}
- MITRE ATT&CK Kill Chain: {mitre}
- Event Sequence: {event_seq}

Generate a comprehensive NIST 800-61 Rev.2 incident response playbook with these exact sections:

## Immediate Actions (first 15 minutes)
List 3-5 specific, actionable steps. Include exact system names and commands where applicable.

## Containment (first 1 hour)
List 3-5 containment measures. Reference specific network segments, services, and access controls.

## Investigation (first 4 hours)
List 4-6 investigation steps. Include specific log sources, queries, and forensic procedures.

## Recovery (within 24 hours)
List 3-4 recovery procedures. Include verification steps and sign-off requirements.

Requirements:
- Be specific to banking/financial services context
- Reference Barclays-specific systems where relevant
- Include regulatory considerations (PCI-DSS, FCA, GDPR)
- Provide exact commands or tool references where possible
- Consider blast radius and business impact"""

def generate_one(cluster, scored, attack_path):
    user   = cluster['primary_user']
    flags  = ', '.join(cluster['escalation_flags']) or 'none'
    systems= ', '.join(cluster['source_systems'])
    mitre  = ' → '.join(attack_path.get('kill_chain', []))
    event_seq = cluster.get('event_sequence_compact', '')

    prompt = _build_prompt(user, scored['severity'], flags, systems, mitre, event_seq)

    text, llm_meta = _llm(prompt)
    if not text:
        # Try fallback model
        text, llm_meta = _llm(prompt, FALLBACK)

    source = 'ollama_llm' if text else 'template_fallback'
    steps  = {'text': text} if text else _template_playbook(cluster, scored)
    revision = scored.get('playbook_revision', 0)

    playbook = {
        'cluster_id':    cluster['cluster_id'],
        'primary_user':  user,
        'severity':      scored['severity'],
        'confidence':    scored['final_score'],
        'source':        source,
        'revision':      revision,
        'nist_phases':   steps,
        'attack_path':   attack_path,
        'generated_at':  datetime.now(timezone.utc).isoformat(),
    }

    if llm_meta:
        playbook['llm_metadata'] = llm_meta

    return playbook

def run(state: dict) -> list:
    scored     = state['scored']
    atk_paths  = state.get('attack_paths', [{}] * len(scored))
    playbooks  = []

    for sc, ap in zip(scored, atk_paths):
        should_generate = sc['severity'] in ('High', 'Critical')
        if not should_generate and sc['severity'] == 'Medium':
            corr = float(sc.get('correlation_score', 0.0))
            seq = float(sc.get('sequence_risk', 0.0))
            ent = float(sc.get('entity_risk', 0.0))
            sev = float(sc.get('explicit_severity', sc.get('explicit_severity_max', 0.0)))
            should_generate = (
                corr >= 0.60
                or (seq >= 0.65 and ent >= 0.45)
                or (sc.get('anomalous_count', 0) >= 2 and corr >= 0.50)
                or sev >= 0.75
            )

        if should_generate:
            pb = generate_one(sc, sc, ap)
            playbooks.append(pb)
            if pb['source'] == 'ollama_llm':
                meta = pb.get('llm_metadata', {})
                print(f'  → {pb["cluster_id"]}: LLM ({meta.get("model","?")})'
                      f' {meta.get("tokens_generated",0)} tokens'
                      f' @ {meta.get("tokens_per_sec",0)} t/s')

    # Save playbooks to state file for API access
    from pathlib import Path
    Path('state').mkdir(exist_ok=True)
    Path('state/playbooks.json').write_text(json.dumps(playbooks, indent=2))

    llm_count = sum(1 for p in playbooks if p['source'] == 'ollama_llm')
    tmpl_count = len(playbooks) - llm_count
    print(f'[PHASE 6] Playbooks: {len(playbooks)} | LLM: {llm_count} | Template: {tmpl_count}')
    return playbooks
