#!/usr/bin/env python3
"""IP allow-list validation and cleanup utility.

Portfolio lab utility:
- validates IPv4 addresses
- removes duplicates
- checks membership in approved CIDR networks
- supports dry-run
- logs invalid and unauthorized entries
- writes an updated allow-list and JSON change summary
"""
from __future__ import annotations
import argparse, ipaddress, json, logging
from pathlib import Path

def load_lines(path: Path):
    return [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

def load_networks(path: Path):
    networks=[]
    for line in load_lines(path):
        networks.append(ipaddress.ip_network(line, strict=False))
    return networks

def evaluate_allowlist(entries, networks):
    seen=set()
    valid=[]
    invalid=[]
    unauthorized=[]
    duplicates=[]
    for entry in entries:
        try:
            ip = ipaddress.ip_address(entry)
            if ip.version != 4:
                invalid.append(entry); continue
        except ValueError:
            invalid.append(entry); continue
        normalized=str(ip)
        if normalized in seen:
            duplicates.append(normalized); continue
        seen.add(normalized)
        if any(ip in net for net in networks):
            valid.append(normalized)
        else:
            unauthorized.append(normalized)
    return {
        "approved": sorted(valid, key=lambda x: tuple(map(int,x.split(".")))),
        "invalid": invalid,
        "unauthorized": unauthorized,
        "duplicates": duplicates,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--allowlist", required=True)
    ap.add_argument("--networks", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args=ap.parse_args()

    logging.basicConfig(filename=args.log, level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")
    allow=Path(args.allowlist); nets=Path(args.networks)
    result=evaluate_allowlist(load_lines(allow), load_networks(nets))
    logging.info("approved=%d invalid=%d unauthorized=%d duplicates=%d",
        len(result["approved"]),len(result["invalid"]),
        len(result["unauthorized"]),len(result["duplicates"]))
    for item in result["invalid"]:
        logging.warning("invalid entry: %s", item)
    for item in result["unauthorized"]:
        logging.warning("unauthorized entry: %s", item)
    for item in result["duplicates"]:
        logging.info("duplicate removed: %s", item)

    summary={
        "input_entries": sum(len(result[k]) for k in ["approved","invalid","unauthorized","duplicates"]),
        "approved_entries": len(result["approved"]),
        "invalid_entries_removed": len(result["invalid"]),
        "unauthorized_entries_removed": len(result["unauthorized"]),
        "duplicates_removed": len(result["duplicates"]),
        "dry_run": args.dry_run
    }
    Path(args.summary).write_text(json.dumps(summary, indent=2)+"\n")
    if not args.dry_run:
        Path(args.output).write_text("\n".join(result["approved"])+"\n")
    print(json.dumps(summary, indent=2))

if __name__=="__main__":
    main()
