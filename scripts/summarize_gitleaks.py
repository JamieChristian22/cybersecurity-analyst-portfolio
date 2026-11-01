#!/usr/bin/env python3
"""Print only safe metadata from a local Gitleaks report. Never print secret contents."""
import argparse
import json
from pathlib import Path

def summarize(report: Path):
    if not report.is_file():
        raise FileNotFoundError("Gitleaks report was not written")
    findings=json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(findings,list):
        raise ValueError("Unexpected Gitleaks report schema")
    safe=[]
    for item in findings:
        if not isinstance(item,dict):
            raise ValueError("Unexpected Gitleaks finding")
        safe.append({
            "rule":str(item.get("RuleID","unknown"))[:100],
            "file":str(item.get("File","unknown"))[:350],
            "line":item.get("StartLine"),
            "commit":str(item.get("Commit",""))[:40],
            "fingerprint":str(item.get("Fingerprint",""))[:350],
        })
    return safe

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report",type=Path)
    args=ap.parse_args()
    safe=summarize(args.report)
    print("Gitleaks findings:",len(safe))
    for item in safe:
        print(json.dumps(item,sort_keys=True))
    if safe:
        print("Security review required: do not expose the matched value or bypass the full-history scan.")

if __name__=="__main__":
    main()
