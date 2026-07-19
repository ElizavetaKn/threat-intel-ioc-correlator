import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_intel_ioc_correlator.correlator import IOC, correlate


class CorrelatorTests(unittest.TestCase):
    def test_matches_ip_and_domain(self):
        iocs = [
            IOC("ip", "203.0.113.55", "test"),
            IOC("domain", "malicious.example", "test"),
        ]
        events = [
            {"event_id": "1", "source_ip": "203.0.113.55"},
            {"event_id": "2", "domain": "MALICIOUS.EXAMPLE"},
        ]
        findings = correlate(events, iocs)
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
