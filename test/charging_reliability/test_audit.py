"""Deterministic tests for the offline charging-event audit."""
import unittest

from audit import audit


class AuditTests(unittest.TestCase):
    def test_happy_path(self):
        events = [
            {"dialog_id": "call-a", "event": "start", "at": 100, "request_id": "1"},
            {"dialog_id": "call-a", "event": "interim", "at": 110, "request_id": "2",
             "cumulative_used_units": 20},
            {"dialog_id": "call-a", "event": "stop", "at": 120, "request_id": "3",
             "cumulative_used_units": 30},
        ]
        self.assertEqual(audit(events, now=1000, stale_after=10)["anomaly_count"], 0)

    def test_duplicate_and_usage_regression(self):
        events = [
            {"dialog_id": "a", "event": "start", "at": 100, "request_id": "1",
             "cumulative_used_units": 50},
            {"dialog_id": "a", "event": "start", "at": 101, "request_id": "1",
             "cumulative_used_units": 20},
        ]
        kinds = {x["type"] for x in audit(events, 102, 1800)["anomalies"]}
        self.assertEqual(kinds, {"duplicate_request_id", "duplicate_start",
                                 "usage_regression"})

    def test_timeout_does_not_imply_failure(self):
        events = [{"dialog_id": "a", "event": "start", "at": 100, "result": "timeout"}]
        kinds = {x["type"] for x in audit(events, 100, 60)["anomalies"]}
        self.assertEqual(kinds, {"ambiguous_timeout"})

    def test_stale_not_immediate(self):
        events = [{"dialog_id": "a", "event": "start", "at": 100}]
        self.assertEqual(audit(events, 110, 60)["anomaly_count"], 0)
        self.assertEqual(audit(events, 200, 60)["anomalies"][0]["type"],
                         "stale_open_session")

    def test_orphans_and_repeated_stop(self):
        events = [
            {"dialog_id": "b", "event": "interim", "at": 1},
            {"dialog_id": "b", "event": "stop", "at": 2},
            {"dialog_id": "b", "event": "stop", "at": 3},
        ]
        kinds = {a["type"] for a in audit(events, 10, 60)["anomalies"]}
        self.assertEqual(kinds, {"orphan_interim", "orphan_stop", "duplicate_stop"})


if __name__ == "__main__":
    unittest.main()
