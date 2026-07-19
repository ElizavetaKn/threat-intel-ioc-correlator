from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    source: str


@dataclass(frozen=True)
class Finding:
    event_id: str
    ioc_type: str
    ioc_value: str
    ioc_source: str
    field: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def normalize(ioc_type: str, value: str) -> str:
    value = value.strip()
    if ioc_type in {"domain", "sha256"}:
        return value.lower()
    return value


def correlate(events: list[dict], iocs: list[IOC]) -> list[Finding]:
    index: dict[str, dict[str, IOC]] = {}
    for ioc in iocs:
        index.setdefault(ioc.type, {})[normalize(ioc.type, ioc.value)] = ioc

    field_map = {
        "source_ip": "ip",
        "destination_ip": "ip",
        "domain": "domain",
        "sha256": "sha256",
    }

    findings: list[Finding] = []
    for event in events:
        event_id = str(event.get("event_id", "unknown"))
        for field, ioc_type in field_map.items():
            raw = event.get(field)
            if raw is None:
                continue
            matched = index.get(ioc_type, {}).get(normalize(ioc_type, str(raw)))
            if matched:
                findings.append(
                    Finding(
                        event_id=event_id,
                        ioc_type=ioc_type,
                        ioc_value=matched.value,
                        ioc_source=matched.source,
                        field=field,
                    )
                )
    return findings
