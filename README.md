# Threat Intelligence IOC Correlator

A defensive threat-intelligence utility that matches known indicators of compromise (IOCs) against normalized security events.

## What it demonstrates

- Threat intelligence basics
- IOC normalization
- IP, domain and SHA-256 matching
- Event correlation
- Structured alert reporting
- Python testing

## IOC format

```csv
type,value,source
ip,203.0.113.55,training-feed
domain,malicious.example,training-feed
sha256,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,training-feed
```

## Run

```bash
python -m threat_intel_ioc_correlator.cli \
  examples/iocs.csv \
  examples/events.jsonl \
  --output findings.json
```

## Tests

```bash
python -m unittest discover -s tests -v
```

All bundled indicators are synthetic and reserved for documentation/training use.
