#!/usr/bin/env python3
"""Parse synthetic authentication logs and generate simple security alerts."""
from __future__ import annotations
import argparse, csv, json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

def parse_ts(s): return datetime.fromisoformat(s)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args=ap.parse_args()

    events=[]
    with open(args.input, newline="") as f:
        for row in csv.DictReader(f):
            row["timestamp_dt"]=parse_ts(row["timestamp"])
            events.append(row)
    events.sort(key=lambda x:x["timestamp_dt"])

    alerts=[]
    failures=defaultdict(deque)
    for e in events:
        key=(e["username"],e["src_ip"])
        now=e["timestamp_dt"]
        dq=failures[key]
        while dq and now-dq[0] > timedelta(minutes=5):
            dq.popleft()
        if e["action"]=="failure":
            dq.append(now)
            if len(dq)==5:
                alerts.append({
                    "type":"Repeated Authentication Failures",
                    "severity":"medium",
                    "timestamp":e["timestamp"],
                    "username":e["username"],
                    "src_ip":e["src_ip"],
                    "evidence":f"{len(dq)} failures within 5 minutes"
                })
        elif e["action"]=="success" and len(dq)>=3:
            alerts.append({
                "type":"Failures Followed by Success",
                "severity":"high",
                "timestamp":e["timestamp"],
                "username":e["username"],
                "src_ip":e["src_ip"],
                "evidence":f"{len(dq)} recent failures followed by success"
            })

    Path(args.output).write_text(json.dumps(alerts, indent=2)+"\n")
    print(f"Generated {len(alerts)} alerts")

if __name__=="__main__":
    main()
