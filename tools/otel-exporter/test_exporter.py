#!/usr/bin/env python3
import unittest
from unittest.mock import patch

import exporter


class ExporterTests(unittest.TestCase):
    def test_metric_name_sanitization(self):
        self.assertEqual(exporter.sanitize_metric_name("dialog:active_dialogs"), "opensips_dialog_active_dialogs")
        self.assertEqual(exporter.sanitize_metric_name("tm:2xx_replies"), "opensips_tm_2xx_replies")

    def test_endpoint_suffix(self):
        self.assertEqual(exporter.otlp_endpoint("http://collector:4318"), "http://collector:4318/v1/metrics")
        self.assertEqual(exporter.otlp_endpoint("http://collector:4318/v1/metrics"), "http://collector:4318/v1/metrics")

    def test_payload_keeps_original_stat_as_attribute(self):
        payload = exporter.build_otlp({"media_qoe:degraded_reports": 7.0}, "opensips-test", "deployment.environment=test", timestamp_ns=123)
        metric = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
        self.assertEqual(metric["name"], "opensips_media_qoe_degraded_reports")
        point = metric["gauge"]["dataPoints"][0]
        self.assertEqual(point["timeUnixNano"], "123")
        self.assertEqual(point["attributes"][0]["value"]["stringValue"], "media_qoe:degraded_reports")

    def test_sanitized_metric_name_collisions_get_stable_suffix(self):
        payload = exporter.build_otlp(
            {"custom:a-b": 1.0, "custom:a_b": 2.0},
            "opensips-test", "", timestamp_ns=123,
        )
        metrics = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        names = [m["name"] for m in metrics]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("opensips_custom_a_b", names)
        self.assertTrue(any(name.startswith("opensips_custom_a_b_") for name in names))

    def test_counter_patterns_emit_cumulative_monotonic_sum(self):
        payload = exporter.build_otlp(
            {"core:received_requests": 42.0, "dialog:active_dialogs": 3.0},
            "opensips-test", "", timestamp_ns=123,
            counter_patterns=["core:*_requests"],
        )
        metrics = {
            m["name"]: m
            for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        counter = metrics["opensips_core_received_requests"]
        self.assertNotIn("gauge", counter)
        self.assertTrue(counter["sum"]["isMonotonic"])
        self.assertEqual(counter["sum"]["aggregationTemporality"], 2)
        self.assertIn("gauge", metrics["opensips_dialog_active_dialogs"])

        point = counter["sum"]["dataPoints"][0]
        self.assertEqual(point["startTimeUnixNano"], "123")

    def test_counter_start_time_is_stable_until_reset(self):
        state = {}
        first = exporter.build_otlp(
            {"core:received_requests": 42.0},
            "opensips-test", "", timestamp_ns=100,
            counter_patterns=["core:*_requests"], counter_state=state,
        )
        second = exporter.build_otlp(
            {"core:received_requests": 50.0},
            "opensips-test", "", timestamp_ns=200,
            counter_patterns=["core:*_requests"], counter_state=state,
        )
        reset = exporter.build_otlp(
            {"core:received_requests": 3.0},
            "opensips-test", "", timestamp_ns=300,
            counter_patterns=["core:*_requests"], counter_state=state,
        )

        def point(payload):
            return payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0]

        self.assertEqual(point(first)["startTimeUnixNano"], "100")
        self.assertEqual(point(second)["startTimeUnixNano"], "100")
        self.assertEqual(point(reset)["startTimeUnixNano"], "300")
        self.assertEqual(point(reset)["timeUnixNano"], "300")

    def test_gauge_has_no_counter_start_time(self):
        payload = exporter.build_otlp(
            {"dialog:active_dialogs": 3.0},
            "opensips-test", "", timestamp_ns=123,
        )
        point = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"][0]
        self.assertNotIn("startTimeUnixNano", point)

    def test_incremental_mi_type_is_auto_counter(self):
        payload = exporter.build_otlp(
            {
                "dialog:processed_dialogs": 12.0,
                "dialog:active_dialogs": 3.0,
            },
            "opensips-test", "", timestamp_ns=123,
            stat_types={
                "dialog:processed_dialogs": "incremental",
                "dialog:active_dialogs": "non-incremental",
            },
        )
        metrics = {
            m["name"]: m
            for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        self.assertIn("sum", metrics["opensips_dialog_processed_dialogs"])
        self.assertIn("gauge", metrics["opensips_dialog_active_dialogs"])

    def test_explicit_counter_pattern_can_override_non_incremental_type(self):
        payload = exporter.build_otlp(
            {"custom:never_reset_total": 9.0},
            "opensips-test", "", timestamp_ns=123,
            counter_patterns=["custom:*_total"],
            stat_types={"custom:never_reset_total": "non-incremental"},
        )
        metric = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
        self.assertIn("sum", metric)

    @patch("exporter.json_request")
    def test_fetch_stat_types_uses_named_statistics_array(self, request):
        request.return_value = {
            "jsonrpc": "2.0",
            "result": {
                "dialog:active_dialogs": "non-incremental",
                "dialog:processed_dialogs": "incremental",
                "ignored": 123,
            },
            "id": 2,
        }
        result = exporter.fetch_stat_types(
            "http://127.0.0.1:8888/mi", ["dialog:"]
        )
        self.assertEqual(
            result,
            {
                "dialog:active_dialogs": "non-incremental",
                "dialog:processed_dialogs": "incremental",
            },
        )
        payload = request.call_args.args[1]
        self.assertEqual(payload["method"], "list_statistics")
        self.assertEqual(payload["params"], {"statistics": ["dialog:"]})

    def test_parse_pairs(self):
        self.assertEqual(exporter.parse_pairs("a=1,b=two"), {"a": "1", "b": "two"})
        with self.assertRaises(ValueError):
            exporter.parse_pairs("broken")


if __name__ == "__main__":
    unittest.main()
