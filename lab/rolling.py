"""Rolling authentication detections with bounded history per active key.

Offline replay: sort by UTC timestamp, successes before failures on ties. Stale keys
are periodically evicted. Input normalization/duplicate-ID rejection belongs to read_events.
"""
from collections import Counter, defaultdict, deque
from .detections import timestamp

def detect_rolling(events):
    events=sorted(events,key=lambda e:(timestamp(e['timestamp']),e['action']!='success',e['event_id']))
    user_history=defaultdict(deque)
    source_history=defaultdict(deque)
    source_counts=defaultdict(Counter)
    alerts=[]
    last_sweep=None
    def emit(rule,e,support):
        alerts.append({'rule_id':rule,'event_id':e['event_id'],'timestamp':e['timestamp'],
                       'username':e['username'],'src_ip':e['src_ip'],
                       'evidence_event_ids':[x['event_id'] for x in support]})
    for e in events:
        now=timestamp(e['timestamp']).timestamp()
        if last_sweep is None or now-last_sweep>=600:
            for key in list(user_history):
                if not user_history[key] or now-user_history[key][-1][0]>300:
                    del user_history[key]
            for key in list(source_history):
                if not source_history[key] or now-source_history[key][-1][0]>600:
                    del source_history[key];source_counts.pop(key,None)
            last_sweep=now
        key=(e['username'],e['src_ip']);uq=user_history[key]
        while uq and now-uq[0][0]>300: uq.popleft()
        if e['action']=='success':
            prior=[item for t,item in uq if t<now]
            if len(prior)>=3: emit('ROLL-002',e,prior+[e])
            continue
        if e['action']!='failure': raise ValueError('unknown action')
        before=len(uq);uq.append((now,e))
        if before<5<=len(uq): emit('ROLL-001',e,[x for _,x in uq])
        sq=source_history[e['src_ip']];counts=source_counts[e['src_ip']]
        while sq and now-sq[0][0]>600:
            _,old=sq.popleft();counts[old['username']]-=1
            if not counts[old['username']]: del counts[old['username']]
        previous_users=len(counts)
        sq.append((now,e));counts[e['username']]+=1
        if previous_users<5<=len(counts): emit('ROLL-003',e,[x for _,x in sq])
    return alerts
