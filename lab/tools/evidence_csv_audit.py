"""Offline CSV audit: required fields, duplicate business keys, and SHA-256 evidence."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def audit(path, required=(), unique=()):
    required, unique = tuple(required), tuple(unique)
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames or []
        missing = sorted((set(required) | set(unique)) - set(headers))
        if missing:
            raise ValueError("Missing columns: " + ", ".join(missing))
        seen, duplicates, blanks, count = set(), 0, {k: 0 for k in required}, 0
        for row in reader:
            count += 1
            for key in required:
                if not (row[key] or "").strip():
                    blanks[key] += 1
            if unique:
                key = tuple(row[k] for k in unique)
                if key in seen:
                    duplicates += 1
                seen.add(key)
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return {"rows": count, "duplicate_keys": duplicates,
            "blank_required": blanks, "sha256": digest}


def main():
    p = argparse.ArgumentParser(description="Audit a CSV without modifying it")
    p.add_argument("csv_file", type=Path)
    p.add_argument("--required", nargs="*", default=[])
    p.add_argument("--unique", nargs="*", default=[])
    args = p.parse_args()
    result = audit(args.csv_file, args.required, args.unique)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["duplicate_keys"] or any(result["blank_required"].values()):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
