#!/usr/bin/env python3
"""CSV adapter for the reference lab. Legacy timestamps without offsets are UTC.

Legacy rows receive row-based IDs; identical records without IDs are retained because
only a source event ID can safely distinguish duplicate ingestion from distinct events.
"""
import argparse
import csv
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lab.detections import detect

def load_events(path):
    events, seen = [], set()
    with Path(path).open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        if not {'timestamp','username','src_ip','action','geo'}.issubset(reader.fieldnames or []):
            raise ValueError('required columns: timestamp, username, src_ip, action, geo')
        for n,row in enumerate(reader,2):
            try:
                if any(not row.get(k) for k in ('timestamp','username','src_ip','action','geo')):
                    raise ValueError('empty required field')
                dt=datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
                if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
                row['timestamp']=dt.astimezone(timezone.utc).isoformat()
                ipaddress.ip_address(row['src_ip'])
                if row['action'] not in ('success','failure'): raise ValueError('invalid action')
                row['event_id']=row.get('event_id') or f'row-{n}'
                if row['event_id'] in seen: raise ValueError('duplicate event_id')
            except ValueError as exc:
                raise ValueError(f'CSV row {n}: {exc}') from exc
            seen.add(row['event_id']); events.append(row)
    return events

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',required=True)
    ap.add_argument('--output',required=True)
    args=ap.parse_args()
    try:
        alerts=detect(load_events(args.input))
        output=Path(args.output)
        if output.resolve()==Path(args.input).resolve(): raise ValueError('output must not overwrite input')
        output.write_text(json.dumps(alerts,indent=2)+'\n')
    except (OSError,ValueError) as exc:
        ap.exit(2,f'error: {exc}\n')
    print(f'Generated {len(alerts)} alerts')

if __name__=='__main__': main()
