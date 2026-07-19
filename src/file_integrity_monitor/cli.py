from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .correlator import IOC, correlate


def load_iocs(path: Path) -> list[IOC]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return [
            IOC(type=row["type"], value=row["value"], source=row.get("source", "unknown"))
            for row in csv.DictReader(fh)
        ]


def load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                events.append(json.loads(line))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Correlate security events with IOC feeds")
    parser.add_argument("iocs", type=Path)
    parser.add_argument("events", type=Path)
    parser.add_argument("--output", type=Path, default=Path("findings.json"))
    args = parser.parse_args()

    findings = correlate(load_events(args.events), load_iocs(args.iocs))
    args.output.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2),
        encoding="utf-8",
    )
    print(f"IOC matches: {len(findings)}")


if __name__ == "__main__":
    main()
