"""Reproduce endpoint/network investigations and labeled rolling-rule evaluation."""
import hashlib
import json
import platform
import time
from pathlib import Path
from .forensics import read_windows,endpoint_alerts,read_pcap,network_findings
from .rolling import detect_rolling
ROOT=Path(__file__).resolve().parents[1]

def write(relative,value):
    p=ROOT/relative;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(value,indent=2)+'\n')

def run():
    expected=json.loads((ROOT/'lab/fixtures/forensics_expected.json').read_text())
    events=read_windows(ROOT/'lab/fixtures/endpoint/windows_events.xml')
    endpoint=endpoint_alerts(events)
    assert len(endpoint)==1 and endpoint[0]['record_id']==expected['endpoint_alert_record']
    assert endpoint[0]['evidence_record_ids']==expected['endpoint_supporting_records']
    packets=read_pcap(ROOT/'lab/fixtures/network/traffic.pcap');network=network_findings(packets)
    assert len(packets)==expected['packets']
    assert [p['dns_query'] for p in packets if p.get('dns_query')]==expected['dns_queries']
    assert len(network)==1 and network[0]['src_ip']==expected['periodic_source']
    assert network[0]['dst_ip']==expected['periodic_destination']
    assert network[0]['syn_attempts']==expected['syn_attempts']
    assert network[0]['median_interval_seconds']==expected['interval_seconds']
    write('evidence/endpoint/normalized_events.json',events)
    write('evidence/endpoint/alerts.json',endpoint)
    write('evidence/network/packets.json',packets)
    write('evidence/network/findings.json',network)
    cases=json.loads((ROOT/'lab/fixtures/benchmark/scenarios.json').read_text())
    result=[];counts={r:{'tp':0,'tn':0,'fp':0,'fn':0} for r in ['ROLL-001','ROLL-002','ROLL-003']}
    for c in cases:
        observed=any(a['rule_id']==c['target_rule'] for a in detect_rolling(c['events']))
        label=('t' if observed==c['expected_positive'] else 'f')+('p' if observed else 'n')
        counts[c['target_rule']][label]+=1
        result.append({'case_id':c['case_id'],'target_rule':c['target_rule'],
                       'expected_positive':c['expected_positive'],'observed_positive':observed,
                       'passed':observed==c['expected_positive'],'rationale':c['rationale']})
    if not all(r['passed'] for r in result):raise AssertionError('labeled scenario mismatch')
    report={'scope':'Deterministic synthetic regression scenarios; not a representative efficacy benchmark',
            'cases':len(cases),'passed':len(result),'counts_by_rule':counts,'results':result}
    write('evidence/benchmark/scenario_results.json',report)
    hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((ROOT/'lab/fixtures').rglob('*')) if p.is_file()}
    write('evidence/forensics_manifest.json',{'origin':'Authored synthetic XML and PCAP; not captured from a host or network',
          'python':platform.python_version(),'windows_events':len(events),'packets':len(packets),
          'endpoint_alerts':len(endpoint),'network_findings':len(network),'labeled_scenarios':len(cases),'sha256':hashes})
    print(f'PASS: {len(events)} Windows events, {len(packets)} packets, {len(cases)} labeled scenarios')

if __name__=='__main__':run()
