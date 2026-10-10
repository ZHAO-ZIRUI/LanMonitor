"""HTTP regressions use loopback sockets and a fake, inactive collector."""

import http.client
import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch

from config import DEFAULT_SETTINGS
from http_api import BoundedHTTPServer, make_handler
from store import Store


class InactiveScanner:
    started_at = 1234.5

    def __init__(self, settings):
        self.settings = settings

    def snapshot(self):
        return {"started_at": self.started_at, "enabled": False, "error": None}


class HTTPRegressionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "http.sqlite3")
        self.scanner = InactiveScanner(self.store.settings)
        self.handler = make_handler(self.store, self.scanner, 0, "127.0.0.1")
        self.server = BoundedHTTPServer(("127.0.0.1", 0), self.handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01))
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.directory.cleanup()

    def request(self, method, path, value=None, headers=None):
        headers = dict(headers or {})
        body = None if value is None else json.dumps(value)
        if method != "GET":
            headers.setdefault("Content-Type", "application/json")
            headers.setdefault("X-LanMonitor", "1")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def raw_request(self, target, headers, body=b"", method="PATCH", shutdown_write=False):
        request = f"{method} {target} HTTP/1.0\r\n".encode()
        request += b"\r\n".join(line.encode() for line in headers) + b"\r\n\r\n" + body
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as client:
            client.sendall(request)
            if shutdown_write:
                client.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(client)
            response.begin()
            return response.status, json.loads(response.read())

    def test_api_responses_identify_server_lifetime(self):
        for method, path, value in [
            ("GET", "/api/state", None), ("GET", "/api/settings", None),
            ("PATCH", "/api/settings", {"scan_enabled": False}),
            ("PATCH", "/api/hosts/20", {"reserved": True}),
            ("DELETE", "/api/hosts/20", None),
            ("PATCH", "/api/devices/00:11:22:33:44:55/note", {"note": "设备"}),
            ("POST", "/api/history/clear", {"scope": "all"}),
        ]:
            with self.subTest(path=path, method=method):
                status, value = self.request(method, path, value)
                self.assertEqual(status, 200)
                self.assertEqual(value["instance"], self.scanner.started_at)
                if "state" in value:
                    self.assertEqual(value["state"]["instance"], self.scanner.started_at)

    def test_settings_schema_excludes_retired_collector_and_rejects_stale_writes(self):
        for path in ("/api/settings", "/api/state"):
            with self.subTest(path=path):
                status, payload = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(set(payload["settings"]), set(DEFAULT_SETTINGS))
                self.assertNotIn("surge_enabled", payload["settings"])
        before = self.scanner.settings.export()
        status, _ = self.request("PATCH", "/api/settings", {"surge_enabled": False, "scan_enabled": False})
        self.assertEqual(status, 400)
        self.assertEqual(self.scanner.settings.export(), before)
        status, payload = self.request("PATCH", "/api/settings", {"scan_enabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(payload["settings"]["scan_enabled"])
        self.assertNotIn("surge_enabled", payload["settings"])

    def test_malformed_authorities_origins_and_duplicate_headers_are_rejected(self):
        for value in ["[", "[::1", "localhost:bad", "localhost:65536", "localhost/path", "user@localhost", "localhost?x", "localhost#x"]:
            with self.subTest(host=value):
                self.assertEqual(self.request("GET", "/api/state", headers={"Host": value})[0], 403)
        for value in ["http://[", "http://127.0.0.1:bad", "https://127.0.0.1", "null", "http://user@127.0.0.1", "http://127.0.0.1/path", "http://127.0.0.1?", "http://127.0.0.1#"]:
            with self.subTest(origin=value):
                status, _ = self.request("PATCH", "/api/hosts/20", {"reserved": True}, {"Origin": value})
                self.assertEqual(status, 403)
        status, _ = self.raw_request("/api/state", ["Host: localhost", "Host: example.com"], method="GET")
        self.assertEqual(status, 403)
        status, _ = self.request("PATCH", "/api/hosts/20", {"reserved": True},
                                 {"Host": f"LOCALHOST:{self.port}", "Origin": f"http://localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_request_framing_json_and_resource_limits(self):
        base = ["Host: localhost", "X-LanMonitor: 1", "Content-Type: application/json"]
        cases = [
            (["Content-Length: -1"], b"{}"),
            (["Content-Length: 4097"], b"{}"),
            (["Content-Length: 2", "Content-Length: 2"], b"{}"),
            (["Transfer-Encoding: chunked", "Content-Length: 2"], b"{}"),
            (["Content-Length: 100"], b"{}"),
        ]
        bodies = [b'\xff', b'{"reserved":NaN}', b'{"reserved":true,"reserved":false}', b'[' * 1000 + b']' * 1000]
        cases += [([f"Content-Length: {len(body)}"], body) for body in bodies]
        for extra, body in cases:
            with self.subTest(headers=extra, size=len(body)):
                status, _ = self.raw_request("/api/settings", base + extra, body, shutdown_write=True)
                self.assertEqual(status, 400)
        self.assertEqual(self.request("GET", "/api/state?" + "&".join("x=1" for _ in range(9)))[0], 400)
        self.assertEqual(self.request("GET", "/api/state?since=" + "1" * 5000)[0], 400)
        self.assertTrue(self.request("GET", "/api/state?since=-1")[1]["full"])

    def test_database_failure_is_json_and_does_not_break_next_request(self):
        with patch.object(self.store, "set_flags", side_effect=sqlite3.OperationalError("private database path")):
            with self.assertLogs(level="ERROR"):
                status, result = self.request("PATCH", "/api/hosts/20", {"reserved": True})
        self.assertEqual(status, 500)
        self.assertNotIn("private", result["error"])
        self.assertEqual(self.request("GET", "/api/state")[0], 200)

    def test_host_and_revision_are_captured_before_competing_scan(self):
        before = self.store.snapshot()["revision"]
        original = self.store.get
        finished = threading.Event()
        workers = []

        def competing_get(octet):
            host = original(octet)
            def update():
                self.store.set_flags(octet, {"reserved": False})
                finished.set()
            worker = threading.Thread(target=update)
            workers.append(worker)
            worker.start()
            finished.wait(0.05)
            return host

        with patch.object(self.store, "get", side_effect=competing_get):
            status, data = self.request("PATCH", "/api/hosts/20", {"reserved": True})
        for worker in workers:
            worker.join(timeout=1)
        self.assertEqual(status, 200)
        self.assertTrue(data["host"]["reserved"])
        self.assertEqual(data["revision"], before + 1)
        self.assertTrue(finished.is_set())
        self.assertFalse(self.store.get(20)["reserved"])

    def test_clear_snapshot_precedes_competing_write(self):
        before = self.store.snapshot()["revision"]
        original = self.store.clear_history
        workers = []
        finished = threading.Event()

        def competing_clear(*args):
            result = original(*args)
            def update():
                self.store.set_flags(20, {"reserved": True})
                finished.set()
            worker = threading.Thread(target=update)
            workers.append(worker)
            worker.start()
            finished.wait(0.05)
            return result

        with patch.object(self.store, "clear_history", side_effect=competing_clear):
            status, data = self.request("POST", "/api/history/clear", {"scope": "all"})
        for worker in workers:
            worker.join(timeout=1)
        self.assertEqual(status, 200)
        self.assertEqual(data["state"]["revision"], before + 1)
        self.assertFalse(next(host for host in data["state"]["hosts"] if host["octet"] == 20)["reserved"])
        self.assertTrue(finished.is_set())


class ConnectionLimitTests(unittest.TestCase):
    def test_slow_drip_is_closed_and_worker_limit_is_reusable(self):
        entered = threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def handle(self):
                entered.set()
                try:
                    super().handle()
                except OSError:
                    pass
            def log_message(self, *_args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = BoundedHTTPServer(("127.0.0.1", 0), Handler, max_workers=1, request_timeout=0.3)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
        thread.start()
        address = server.server_address
        try:
            with socket.create_connection(address, timeout=1) as slow:
                started = time.monotonic()
                slow.sendall(b"G")
                self.assertTrue(entered.wait(1))
                with socket.create_connection(address, timeout=1) as overflow:
                    self.assertIn(b"503", overflow.recv(200))
                while time.monotonic() - started < 0.5:
                    try:
                        slow.sendall(b"E")
                    except OSError:
                        break
                    time.sleep(0.03)
                self.assertLess(time.monotonic() - started, 0.8)
            connection = http.client.HTTPConnection(*address, timeout=1)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally:
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
