"""Run with python -m lab.reproduce; never contacts external services."""
import argparse
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path
from .detections import detect, read_events

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--with-independent-pcap", action="store_true", help="Also verify PCAP using optional dpkt dependency")
    args = ap.parse_args()
    source = ROOT / 'lab/auth_events.csv'
    events = read_events(source)
    alerts = detect(events)
    expected = json.loads((ROOT / 'lab/expected_alerts.json').read_text())
    observed = [{'rule_id': a['rule_id'], 'event_id': a['event_id']} for a in alerts]
    if observed != expected:
        raise AssertionError(f'Alert mismatch: {observed!r} != {expected!r}')
    output = ROOT / 'evidence'
    output.mkdir(exist_ok=True)
    (output/'alerts.json').write_text(json.dumps(alerts, indent=2)+'\n')
    connection = sqlite3.connect(':memory:')
    connection.execute('CREATE TABLE auth_events (event_id TEXT, timestamp TEXT, username TEXT, src_ip TEXT, action TEXT, geo TEXT)')
    connection.executemany('INSERT INTO auth_events VALUES (:event_id,:timestamp,:username,:src_ip,:action,:geo)', events)
    connection.row_factory = sqlite3.Row
    sql = (ROOT/'lab/correlation.sql').read_text()
    rows = [dict(r) for r in connection.execute(sql)]
    expected_successes = [a['event_id'] for a in alerts if a['rule_id'] == 'AUTH-002']
    if [r['event_id'] for r in rows] != expected_successes:
        raise AssertionError('SQL and Python correlation disagree')
    (output/'sql_correlation.json').write_text(json.dumps(rows, indent=2)+'\n')
    from .extended import run as run_extended
    run_extended()
    independent_status = 'Not requested in this run; see separately hashed verification evidence'
    if args.with_independent_pcap:
        from .verify_pcap import main as verify_pcap
        verify_pcap()
        independent_status = 'Passed: dpkt independently decoded fixture and verified IP/TCP checksums'
    result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                            cwd=ROOT, text=True, capture_output=True)
    (output/'test_results.txt').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(list((ROOT/'lab').glob('*.py')) + list((ROOT/'lab').glob('*.csv'))
                              + list((ROOT/'lab').glob('*.sql')) + [ROOT/'lab/expected_alerts.json'])}
    manifest = {'python': platform.python_version(), 'events': len(events), 'alerts': len(alerts),
                'sql_correlations': len(rows), 'tests_exit_code': result.returncode,
                'data_origin': 'Synthetic, authored fixture; no production telemetry',
                'splunk_execution': 'Not performed', 'independent_pcap_verification': independent_status, 'sha256': hashes}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(f'PASS: {len(events)} synthetic events, {len(alerts)} expected alerts, {len(rows)} SQL correlations; tests passed.')

if __name__ == '__main__':
    main()
