#!/usr/bin/env python3
import unittest
from unittest.mock import patch

import server


class ControlPlaneTests(unittest.TestCase):
    def test_read_only_classification(self):
        self.assertTrue(server.is_read_only("get_statistics"))
        self.assertTrue(server.is_read_only("show_rtpengines"))
        self.assertTrue(server.is_read_only("status_report:status"))
        self.assertTrue(server.is_read_only("status"))
        self.assertFalse(server.is_read_only("reload"))
        self.assertFalse(server.is_read_only("teardown"))

    def test_listener_safety(self):
        self.assertTrue(server.is_loopback_listener("127.0.0.1"))
        self.assertTrue(server.is_loopback_listener("::1"))
        self.assertTrue(server.is_loopback_listener("localhost"))
        self.assertFalse(server.is_loopback_listener("0.0.0.0"))
        self.assertFalse(server.is_loopback_listener("10.0.0.10"))

        self.assertTrue(server.is_loopback_listener("127.0.0.2"))
        with patch("server.socket.getaddrinfo") as resolve:
            resolve.return_value = [
                (server.socket.AF_INET, server.socket.SOCK_STREAM, 6, "",
                 ("127.0.0.1", 0))
            ]
            self.assertTrue(server.is_loopback_listener("loopback.internal"))
        with patch("server.socket.getaddrinfo") as resolve:
            resolve.return_value = [
                (server.socket.AF_INET, server.socket.SOCK_STREAM, 6, "",
                 ("10.0.0.10", 0))
            ]
            self.assertFalse(server.is_loopback_listener("not-local.internal"))

    def test_loopback_host_header_blocks_dns_rebinding_names(self):
        self.assertTrue(server.is_safe_local_host_header("localhost:8088"))
        self.assertTrue(server.is_safe_local_host_header("127.0.0.1:8088"))
        self.assertTrue(server.is_safe_local_host_header("[::1]:8088"))
        self.assertFalse(server.is_safe_local_host_header("evil.example:8088"))
        self.assertFalse(server.is_safe_local_host_header("10.0.0.10:8088"))
        self.assertFalse(server.is_safe_local_host_header(None))

    def test_snapshot_methods_are_read_only_only(self):
        server.validate_snapshot_methods(["get_statistics", "status_report:status", "uptime"])
        with self.assertRaises(ValueError):
            server.validate_snapshot_methods(["get_statistics", "reload"])

    def test_mutations_require_token(self):
        old_token = server.CONTROL_TOKEN
        old_remote = server.ALLOW_REMOTE
        try:
            server.CONTROL_TOKEN = "secret"
            server.ALLOW_REMOTE = False
            self.assertTrue(server.authorized(None, "get_statistics"))
            self.assertFalse(server.authorized(None, "reload"))
            self.assertFalse(server.authorized("Bearer wrong", "reload"))
            self.assertTrue(server.authorized("Bearer secret", "reload"))
        finally:
            server.CONTROL_TOKEN = old_token
            server.ALLOW_REMOTE = old_remote

    def test_remote_mode_requires_token_for_reads_too(self):
        old_token = server.CONTROL_TOKEN
        old_remote = server.ALLOW_REMOTE
        try:
            server.CONTROL_TOKEN = "secret"
            server.ALLOW_REMOTE = True
            self.assertFalse(server.authorized(None, "get_statistics"))
            self.assertFalse(server.authorized("Bearer wrong", "get_statistics"))
            self.assertTrue(server.authorized("Bearer secret", "get_statistics"))
        finally:
            server.CONTROL_TOKEN = old_token
            server.ALLOW_REMOTE = old_remote

    def test_read_only_does_not_use_broad_status_prefix(self):
        self.assertFalse(server.is_read_only("status_set"))
        self.assertFalse(server.is_read_only("status_reset_everything"))

    def test_snapshot_statistics_uses_required_array_param(self):
        old = server.MI

        class FakeMI:
            def call(self, method, params=None):
                return {"method": method, "params": params}

        try:
            server.MI = FakeMI()
            result = server.snapshot_call("get_statistics")
            self.assertEqual(result["params"], {"statistics": ["all"]})
            result = server.snapshot_call("status_report:status")
            self.assertIsNone(result["params"])
        finally:
            server.MI = old

    def test_metrics_prometheus_format(self):
        metrics = server.Metrics()
        metrics.inc_http()
        metrics.observe_mi(12.5, False)
        text = metrics.prometheus()
        self.assertIn("opensips_control_http_requests_total 1", text)
        self.assertIn("opensips_control_mi_requests_total 1", text)
        self.assertIn("opensips_control_mi_last_latency_ms 12.500", text)


if __name__ == "__main__":
    unittest.main()
