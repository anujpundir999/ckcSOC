# run_demo.py
"""ckcSOC pipeline entrypoint — production mode.

Usage:
    python run_demo.py                    # Full production run (10k events)
    python run_demo.py --no-plots         # Skip matplotlib heatmaps
    python run_demo.py --verbose          # Show per-event logs at each layer (1k events)
    python run_demo.py --limit 500        # Cap events at 500
    python run_demo.py --dataset <path>   # Custom dataset path
"""
import argparse, json, time
from pathlib import Path
from soc_graph import SOC_APP, _initial_state

def run(no_plots=False, dataset='datasets/all_events.json', verbose=False,
        limit=None, source='file'):
    print('='*60)
    print('ckcSOC — 11-Layer Cyber Incident Response Pipeline')
    print('Team CKC  ·  Hack O Hire 2026  ·  Barclays SOC')
    if verbose:
        cap = limit or 1000
        print(f'[VERBOSE MODE] Showing per-event logs | Event cap: {cap}')
    if source == 'kafka':
        print('[SOURCE] Kafka — events will be drained from real Kafka topics')
    print('='*60)

    # Verify dataset exists
    if not Path(dataset).exists():
        print(f'[ERROR] Dataset not found: {dataset}')
        print('[INFO]  Run: python datasets/synthetic_dataset_builder.py')
        return None

    # In verbose mode, default to 1k events unless user specified a limit
    if verbose and limit is None:
        limit = 1000

    state = _initial_state()
    state['runtime_meta'] = {
        'no_plots':  no_plots,
        'dataset':   dataset,
        'verbose':   verbose,
        'limit':     limit,
        'source':    source,
    }

    start = time.time()
    result = SOC_APP.invoke(state)
    elapsed = time.time() - start

    # Print summary
    print('\n' + '='*60)
    print('PIPELINE RESULTS')
    print('='*60)
    print(f'[RESULT] Events ingested:     {len(result.get("raw_logs", []))}')
    print(f'[RESULT] Events normalized:   {len(result.get("normalized", []))}')
    print(f'[RESULT] Clusters processed:  {len(result.get("clusters", []))}')
    print(f'[RESULT] High severity:       {sum(1 for s in result.get("scored", []) if s.get("severity")=="High")}')
    print(f'[RESULT] Playbooks generated: {len(result.get("playbooks", []))}')

    # Show playbook sources
    playbooks = result.get('playbooks', [])
    llm_count = sum(1 for p in playbooks if p.get('source') == 'ollama_llm')
    tmpl_count = len(playbooks) - llm_count
    print(f'[RESULT]   ├─ LLM (Ollama):   {llm_count}')
    print(f'[RESULT]   └─ Template:        {tmpl_count}')

    print(f'[RESULT] Approvals recorded:  {len(result.get("approvals", []))}')
    print(f'[RESULT] Attack paths mapped: {len(result.get("attack_paths", []))}')
    print(f'[RESULT] Sentinel matches:    {len(result.get("sentinel_matches", []))}')
    print(f'[RESULT] Audit log:           {result.get("audit_path", "N/A")}')
    print(f'[RESULT] Pipeline time:       {elapsed:.2f}s')
    print('='*60)
    print('[OK] Pipeline completed successfully')
    return result

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='ckcSOC — 11-Layer SOC Pipeline')
    ap.add_argument('--no-plots', action='store_true', help='Skip matplotlib visualizations')
    ap.add_argument('--verbose',  action='store_true', help='Print per-event logs at every layer (auto-caps at 1k)')
    ap.add_argument('--limit',    type=int, default=None, help='Cap number of events (e.g. --limit 1000)')
    ap.add_argument('--dataset',  default='datasets/all_events.json', help='Path to events dataset')
    ap.add_argument('--source',   default='file', choices=['file','kafka'],
                    help='Ingestion source: file (default) or kafka')
    args = ap.parse_args()
    run(no_plots=args.no_plots, dataset=args.dataset,
        verbose=args.verbose, limit=args.limit, source=args.source)
