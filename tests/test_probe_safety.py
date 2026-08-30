"""Regression tests for the ways a scanner can do harm.

These exist because an early version sent an HTTP request to every port it did
not recognise. On a raw print port that request is not parsed, it is printed —
a real printer produced a page of protocol text and then jammed with the job
still open.

    python3 tests/test_probe_safety.py

No network access and no privileges are needed: everything binds to loopback on
unprivileged ports.
"""
from __future__ import annotations

import asyncio
import os
import resource
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscan import discovery, interfaces, report, services  # noqa: E402
from netscan.fingerprint import NEVER_WRITE, fingerprint_port  # noqa: E402
from netscan.portscan import raise_fd_limit, scan_host_ports  # noqa: E402


class RecordingServer:
    """A TCP listener that remembers every byte it is sent."""

    def __init__(self, port: int):
        self.port = port
        self.received = b""
        self._server = None

    async def __aenter__(self):
        async def handle(reader, writer):
            try:
                self.received += await asyncio.wait_for(reader.read(4096), timeout=1.5)
            except asyncio.TimeoutError:
                pass
            writer.close()

        self._server = await asyncio.start_server(handle, "127.0.0.1", self.port)
        return self

    async def __aexit__(self, *exc):
        self._server.close()


def run(coro):
    return asyncio.run(coro)


class TestNeverWriteToDataPorts(unittest.TestCase):
    """Ports where input is consumed as payload must never be written to."""

    # Unprivileged members of NEVER_WRITE, so the tests can bind them.
    SILENT_PORTS = [9100, 9102, 9107, 20000, 44818, 47808]

    def test_raw_print_and_ics_ports_receive_nothing(self):
        async def check(port):
            async with RecordingServer(port) as server:
                await fingerprint_port("127.0.0.1", port, timeout=1.5)
                await asyncio.sleep(0.2)
                return server.received

        for port in self.SILENT_PORTS:
            with self.subTest(port=port):
                received = run(check(port))
                self.assertEqual(
                    received, b"",
                    f"scanner sent {received!r} to port {port}; a printer would "
                    f"print that and the queue can jam behind it")

    def test_ordinary_ports_are_still_probed(self):
        """The safety rule must not silently disable fingerprinting elsewhere."""
        async def check(port):
            async with RecordingServer(port) as server:
                await fingerprint_port("127.0.0.1", port, timeout=1.5)
                await asyncio.sleep(0.2)
                return server.received

        for port in (8080, 9091):
            with self.subTest(port=port):
                self.assertIn(b"GET /", run(check(port)))

    def test_known_data_ports_are_listed(self):
        for port in (515, 9100, 9101, 502, 102, 20000, 44818, 47808):
            self.assertIn(port, NEVER_WRITE)

    def test_discovery_does_not_probe_raw_print_port(self):
        self.assertNotIn(9100, services.DISCOVERY_PORTS)


class TestUntrustedDeviceInput(unittest.TestCase):
    """Values supplied by scanned devices must not be trusted."""

    def test_upnp_location_rejects_non_http_schemes(self):
        handle, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(handle, "w") as fh:
            fh.write("<friendlyName>LEAKED</friendlyName>")
        try:
            # urllib will read a file:// URL happily; a device must not be able
            # to pull a local file into the scan report.
            self.assertEqual(discovery.fetch_upnp_description("file://" + path, 2), {})
        finally:
            os.unlink(path)

    def test_upnp_location_must_match_responding_host(self):
        result = discovery.fetch_upnp_description(
            "http://10.9.9.9:80/desc.xml", 2, expected_host="10.0.0.1")
        self.assertEqual(result, {})

    def test_csv_export_neutralises_formulas(self):
        document = {"hosts": [{
            "ip": "10.0.0.9", "label": "=1+1", "device_type": "@SUM(A1:A9)",
            "vendor": "-2+3", "mac": "", "model": "", "network": "",
            "rtt_ms": "", "tcp_ports": [], "udp_ports": [],
        }]}
        row = report.render_csv(document).splitlines()[1]
        for cell in row.split(","):
            self.assertNotIn(cell[:1], ("=", "+", "-", "@"),
                             f"cell {cell!r} would be evaluated as a formula")

    def test_html_export_escapes_device_names(self):
        document = {"summary": {}, "networks": [], "hosts": [{
            "ip": "10.0.0.9", "label": "<script>alert(1)</script>",
            "device_type": "", "vendor": "", "mac": "", "model": "",
            "network": "", "tcp_ports": [], "udp_ports": [], "findings": [],
        }]}
        html = report.render_html(document)
        self.assertNotIn("<script>alert(1)</script>", html)


class TestScanScale(unittest.TestCase):
    """Guard rails that stop a scan consuming unreasonable resources."""

    def test_port_scan_uses_a_bounded_worker_pool(self):
        """A task per port meant 65,535 tasks and ~100 MB for one host."""
        async def check():
            task = asyncio.create_task(
                scan_host_ports("127.0.0.2", range(1, 65536), timeout=0.2, concurrency=300))
            await asyncio.sleep(1.0)
            live = len(asyncio.all_tasks())
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return live

        raise_fd_limit(8192)
        live = run(check())
        self.assertLess(live, 1000,
                        f"{live} live tasks: the scan is creating a task per port")

    def test_oversized_routes_are_skipped(self):
        """netstat abbreviates, so a VPN route can read as "10" -> 10.0.0.0/8."""
        fake_netstat = (
            "Routing tables\n\n"
            "Internet:\n"
            "Destination        Gateway            Flags               Netif Expire\n"
            "10                 link#20            UCS                 utun4\n"
            "172.16             link#18            UCS                 en1\n"
            "192.168.9          link#16            UCS                 en0\n"
        )
        original = interfaces._run
        interfaces._run = lambda *args, **kwargs: fake_netstat
        try:
            networks = set(interfaces.routed_networks().values())
        finally:
            interfaces._run = original

        self.assertNotIn("10.0.0.0/8", networks,
                         "a /8 route would offer 16 million addresses to scan")
        self.assertIn("192.168.9.0/24", networks, "ordinary routes must survive")
        self.assertIn("172.16.0.0/16", networks, "/16 is the boundary and is allowed")

    def test_malformed_port_spec_gives_a_readable_error(self):
        with self.assertRaises(ValueError) as caught:
            services.parse_port_spec("22,badinput")
        self.assertIn("badinput", str(caught.exception))
        self.assertEqual(services.parse_port_spec("22,8000-8002"), [22, 8000, 8001, 8002])


if __name__ == "__main__":
    unittest.main(verbosity=2)
