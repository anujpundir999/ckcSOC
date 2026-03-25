# schemas/schema_validation.py
import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).parent / 'v1'

_schemas = {}

def _load_schema(name: str) -> dict:
    if name not in _schemas:
        path = SCHEMA_DIR / f'{name}.json'
        if path.exists():
            _schemas[name] = json.loads(path.read_text())
        else:
            _schemas[name] = None
    return _schemas[name]

def validate_payload(schema_name: str, data: dict) -> tuple:
    """Validate data against a named schema.
    Returns (True, None) on success, (False, error_string) on failure.
    Uses lightweight validation without jsonschema dependency.
    """
    schema = _load_schema(schema_name)
    if schema is None:
        return (True, None)  # No schema = accept all

    required = schema.get('required', [])
    for field in required:
        if field not in data:
            return (False, f'Missing required field: {field}')

    # Type checks for known fields
    props = schema.get('properties', {})
    for field, spec in props.items():
        if field in data:
            expected = spec.get('type')
            if expected == 'string' and not isinstance(data[field], str):
                return (False, f'Field {field} must be string')
            elif expected == 'object' and not isinstance(data[field], dict):
                return (False, f'Field {field} must be object')
            elif expected == 'array' and not isinstance(data[field], list):
                return (False, f'Field {field} must be array')

    # Enum checks
    for field, spec in props.items():
        if field in data and 'enum' in spec:
            if data[field] not in spec['enum']:
                return (False, f'Field {field} value {data[field]} not in {spec["enum"]}')

    return (True, None)
