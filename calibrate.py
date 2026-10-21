"""Calibrate a reference profile for one model from a TRUSTED source (never a miner).

Runs the validator's own hard probes directly against an operator-held endpoint and
prints a profile entry for reference_profiles.json. Review it, then commit it together
with a VERSION bump in terza_validator.py.

Usage: calibrate.py --source /private/source.json --model MODEL [--samples 60]
source.json (mode 0600): {"base_url": "https://...", "api_key": "..."}
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import statistics
import time
import urllib.request

from terza_validator import HARD_FAMILIES, HARD_MAX_TOKENS, challenge, grade, private_json, wilson


def run_one(src, model, family):
    prompt, expected = challenge(family)
    body = json.dumps({'model': model, 'messages': [{'role': 'user', 'content': prompt}],
                       'temperature': 0, 'max_tokens': HARD_MAX_TOKENS, 'stream': False}).encode()
    request = urllib.request.Request(src['base_url'].rstrip('/') + '/v1/chat/completions', data=body, headers={
        'Authorization': 'Bearer ' + src['api_key'], 'Content-Type': 'application/json',
        'User-Agent': 'terza-calibrate/1'})
    started = time.monotonic()
    try:
        response = json.loads(urllib.request.build_opener(urllib.request.ProxyHandler({}))
                              .open(request, timeout=180).read())
    except Exception:
        return None
    usage = response.get('usage') or {}
    return {'ok': grade(response, expected, response.get('model')), 'latency': time.monotonic() - started,
            'reasoning': (usage.get('completion_tokens_details') or {}).get('reasoning_tokens', 0)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--model', required=True)
    p.add_argument('--samples', type=int, default=60)
    a = p.parse_args()
    src = private_json(a.source)
    families = [HARD_FAMILIES[i % len(HARD_FAMILIES)] for i in range(a.samples)]
    with cf.ThreadPoolExecutor(4) as pool:
        rows = [r for r in pool.map(lambda f: run_one(src, a.model, f), families) if r]
    k = sum(r['ok'] for r in rows)
    low, high = wilson(k, len(rows))
    print(json.dumps({a.model: {
        'hard_accuracy': round(k / max(len(rows), 1), 3),
        'median_reasoning_tokens': statistics.median(r['reasoning'] for r in rows) if rows else None,
        'median_latency_seconds': round(statistics.median(r['latency'] for r in rows), 2) if rows else None,
        'samples': len(rows),
        'accuracy_95ci': [round(low, 3), round(high, 3)],
        'calibrated_at': dt.date.today().isoformat(),
        'source': 'operator-trusted endpoint (describe here)',
    }}, indent=2))


if __name__ == '__main__':
    main()
