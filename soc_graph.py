# soc_graph.py
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, END
from pipeline import (
    phase1_ingest, phase2_normalize, phase3_correlate,
    phase4_score, phase5_explain, phase6_playbook,
    phase7_aegis, phase8_approval, phase9_sentinel,
    phase10_attack_path, phase11_retrain
)

# ── State — shared across all nodes ──
class SOCState(TypedDict):
    raw_logs:          list
    normalized:        list
    clusters:          list
    scored:            list
    explainability:    list
    attack_paths:      list
    playbooks:         list
    governance_details:list
    approvals:         list
    audit_path:        Optional[str]
    sentinel_matches:  list
    needs_resubmit:    bool
    playbook_revision: int
    runtime_meta:      dict

def _initial_state() -> SOCState:
    return SOCState(raw_logs=[], normalized=[], clusters=[],
                    scored=[], explainability=[], attack_paths=[],
                    playbooks=[], governance_details=[], approvals=[],
                    audit_path=None, sentinel_matches=[], needs_resubmit=False,
                    playbook_revision=0, runtime_meta={})

# ── Nodes ──
def ingest_node(state):
    state['raw_logs'] = phase1_ingest.run(state)
    return state

def normalize_node(state):
    state['normalized'] = phase2_normalize.run(state)
    return state

def correlate_node(state):
    state['clusters'] = phase3_correlate.run(state)
    return state

def score_node(state):
    state['scored'] = phase4_score.run(state)
    return state

def explain_node(state):
    state['explainability'] = phase5_explain.run(state)
    return state

def attack_path_node(state):
    state['attack_paths'] = phase10_attack_path.run(state)
    return state

def playbook_node(state):
    state['playbooks'] = phase6_playbook.run(state)
    state['playbook_revision'] = state.get('playbook_revision', 0) + (
        1 if state.get('needs_resubmit') else 0)
    state['needs_resubmit'] = False
    return state

def aegis_node(state):
    state['governance_details'] = phase7_aegis.run(state)
    return state

def approval_node(state):
    result                   = phase8_approval.run(state)
    state['approvals']       = result['approvals']
    state['audit_path']      = result['audit_path']
    state['needs_resubmit']  = result.get('needs_resubmit', False)
    return state

def sentinel_node(state):
    state['sentinel_matches'] = phase9_sentinel.run(state)
    return state

def feedback_node(state):
    phase11_retrain.run(state)
    return state

# ── Conditional routing ──
def route_after_approval(state):
    if state.get('needs_resubmit', False):
        return 'playbook'   # Rejected — regenerate
    return 'sentinel_update'

# ── Build graph ──
def build_graph():
    g = StateGraph(SOCState)
    g.add_node('ingest',          ingest_node)
    g.add_node('normalize',       normalize_node)
    g.add_node('correlate',       correlate_node)
    g.add_node('score',           score_node)
    g.add_node('explain',         explain_node)
    g.add_node('attack_path',     attack_path_node)
    g.add_node('playbook',        playbook_node)
    g.add_node('aegis',           aegis_node)
    g.add_node('human_gate',      approval_node)
    g.add_node('sentinel_update', sentinel_node)
    g.add_node('feedback',        feedback_node)

    g.set_entry_point('ingest')
    g.add_edge('ingest',          'normalize')
    g.add_edge('normalize',       'correlate')
    g.add_edge('correlate',       'score')
    g.add_edge('score',           'explain')
    g.add_edge('explain',         'attack_path')
    g.add_edge('attack_path',     'playbook')
    g.add_edge('playbook',        'aegis')
    g.add_edge('aegis',           'human_gate')
    g.add_conditional_edges('human_gate', route_after_approval,
                           {'playbook': 'playbook', 'sentinel_update': 'sentinel_update'})
    g.add_edge('sentinel_update', 'feedback')
    g.add_edge('feedback',        END)
    return g.compile()

SOC_APP = build_graph()
