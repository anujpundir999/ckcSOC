# kafka/topics.py — single source of truth for all topic names
SOURCE_TOPICS    = ['auth_events','edr_events','network_events',
                    'db_events','email_events','siem_events']
ALLOWED_SOURCES  = {'auth','edr','network','db','email','siem'}
NORMALIZED_TOPIC = 'normalized_events'
CORRELATED_TOPIC = 'correlated_incidents'
SCORED_TOPIC     = 'scored_incidents'
PLAYBOOK_TOPIC   = 'playbook_recommendations'
GOVERNANCE_TOPIC = 'governance_decisions'
AUDIT_TOPIC      = 'approval_audit'
DLQ_SUFFIX       = '_dlq'
import os
BOOTSTRAP        = os.environ.get('KAFKA_BOOTSTRAP', 'localhost:9092')
