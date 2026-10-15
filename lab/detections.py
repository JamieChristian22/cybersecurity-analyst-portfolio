"""Offline reference detections for synthetic authentication events; standard library only."""
from __future__ import annotations
import csv
import hashlib
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = {'event_id', 'timestamp', 'username', 'src_ip', 'action', 'geo'}

def timestamp(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp requires an explicit UTC offset')
    return dt.astimezone(timezone.utc)

def read_events(path):
    with Path(path).open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        if not REQUIRED.issubset(reader.fieldnames or []):
            raise ValueError('missing required CSV columns')
        events, identifiers = [], set()
        for number, row in enumerate(reader, 2):
            try:
                if any(not row.get(k, '').strip() for k in REQUIRED):
                    raise ValueError('empty required field')
                if row['event_id'] in identifiers:
                    raise ValueError('duplicate event_id')
                if row['action'] not in {'failure', 'success'}:
                    raise ValueError('action must be failure or success')
                ipaddress.ip_address(row['src_ip'])
                timestamp(row['timestamp'])
            except (ValueError, AttributeError) as exc:
                raise ValueError(f'CSV row {number}: {exc}') from exc
            identifiers.add(row['event_id'])
            events.append({k: row[k] for k in sorted(REQUIRED)})
    return sorted(events, key=lambda e: (timestamp(e['timestamp']), e['event_id']))

def detect(events):
    """Reference model, intentionally O(n²) for small reviewable fixtures.

    Correlation includes only strictly earlier failures within 300 seconds.
    Repeated-failure alerts occur once per user/IP per fixed UTC five-minute bin.
    Spray alerts occur once per source per fixed UTC ten-minute bin.
    Geography changes are review signals, never proof of impossible travel.
    """
    events = sorted(events, key=lambda e: (timestamp(e['timestamp']), e['event_id']))
    alerts, emitted = [], set()
    def emit(rule, event, supporting, severity):
        identity = f"{rule}:{event['event_id']}"
        alerts.append({'alert_id': hashlib.sha256(identity.encode()).hexdigest()[:16],
                       'rule_id': rule, 'severity': severity,
                       'event_id': event['event_id'], 'timestamp': event['timestamp'],
                       'username': event['username'], 'src_ip': event['src_ip'],
                       'evidence_event_ids': [x['event_id'] for x in supporting]})
    for event in events:
        now = timestamp(event['timestamp'])
        prior = [e for e in events if 0 < (now - timestamp(e['timestamp'])).total_seconds() <= 300
                 and e['username'] == event['username'] and e['src_ip'] == event['src_ip']
                 and e['action'] == 'failure']
        if event['action'] == 'success' and len(prior) >= 3:
            emit('AUTH-002', event, prior + [event], 'high')
        if event['action'] == 'failure':
            bucket = int(now.timestamp()) // 300
            key = ('AUTH-001', event['username'], event['src_ip'], bucket)
            group = [e for e in events if e['action'] == 'failure'
                     and e['username'] == event['username'] and e['src_ip'] == event['src_ip']
                     and int(timestamp(e['timestamp']).timestamp()) // 300 == bucket
                     and (timestamp(e['timestamp']), e['event_id']) <= (now, event['event_id'])]
            if len(group) >= 5 and key not in emitted:
                emit('AUTH-001', event, group, 'medium'); emitted.add(key)
            spray_bucket = int(now.timestamp()) // 600
            key = ('AUTH-003', event['src_ip'], spray_bucket)
            group = [e for e in events if e['action'] == 'failure' and e['src_ip'] == event['src_ip']
                     and int(timestamp(e['timestamp']).timestamp()) // 600 == spray_bucket
                     and (timestamp(e['timestamp']), e['event_id']) <= (now, event['event_id'])]
            if len({e['username'] for e in group}) >= 5 and key not in emitted:
                emit('AUTH-003', event, group, 'medium'); emitted.add(key)
        if event['action'] == 'success':
            previous = [e for e in events if e['action'] == 'success'
                        and e['username'] == event['username'] and timestamp(e['timestamp']) < now]
            if previous:
                old = max(previous, key=lambda e: (timestamp(e['timestamp']), e['event_id']))
                if old['geo'] != event['geo'] and (now-timestamp(old['timestamp'])).total_seconds() <= 3600:
                    emit('AUTH-004', event, [old, event], 'medium')
    return alerts
