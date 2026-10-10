"""Exercise the real entry point with isolated files and collection disabled."""

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import app
from constants import ROOT
from store import Store


class LifecycleTests(unittest.TestCase):
    def test_real_service_persists_flags_and_drains_before_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            settings = Path(directory) / "settings.json"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            env = dict(os.environ)
            env.pop("LANMONITOR_MANAGED", None)
            with subprocess.Popen([sys.executable, str(ROOT / "app.py"), "--no-scan",
                                   "--port", str(port), "--database", str(database),
                                   "--settings", str(settings)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, env=env) as process:
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), "service exited before ready")
                        try:
                            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                            try:
                                conn.request("GET", "/api/state")
                                response = conn.getresponse()
                                state = json.loads(response.read())
                            finally:
                                conn.close()
                            break
                        except OSError:
                            time.sleep(0.025)
                    else:
                        self.fail("service readiness deadline exceeded")
                    self.assertFalse(state["scanner"]["enabled"])
                    self.assertEqual(len(state["hosts"]), 254)
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                    try:
                        conn.request("PATCH", "/api/hosts/200", '{"reserved":true}',
                                     {"Content-Type": "application/json", "X-LanMonitor": "1"})
                        response = conn.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertTrue(json.loads(response.read())["host"]["reserved"])
                    finally:
                        conn.close()
                    process.send_signal(signal.SIGTERM)
                    _, errors = process.communicate(timeout=8)
                    self.assertEqual(process.returncode, 0, errors.decode())
                    self.assertNotIn(b"Traceback", errors)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=3)
            store = Store(database)
            try:
                self.assertTrue(store.get(200)["reserved"])
                self.assertEqual(store.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                store.close()

    def test_managed_logging_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(app, "ROOT", Path(directory)), mock.patch.dict(os.environ, {"LANMONITOR_MANAGED": "1"}):
                with mock.patch.object(app.logging, "basicConfig") as configure:
                    app.configure_logging()
            handler = configure.call_args.kwargs["handlers"][0]
            try:
                self.assertEqual(handler.maxBytes, 5 * 1024 * 1024)
                self.assertEqual(handler.backupCount, 3)
                self.assertEqual(Path(handler.baseFilename), Path(directory) / "data" / "server.log")
            finally:
                handler.close()

    def test_start_failure_closes_store_and_listener(self):
        server = mock.Mock()
        store = mock.Mock()
        scanner = mock.Mock()
        scanner.start.side_effect = RuntimeError("injected startup failure")
        with tempfile.TemporaryDirectory() as directory:
            argv = ["app.py", "--database", str(Path(directory) / "db"), "--settings", str(Path(directory) / "settings")]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(app, "Store", return_value=store), \
                    mock.patch.object(app, "Scanner", return_value=scanner), \
                    mock.patch.object(app, "BoundedHTTPServer", return_value=server), \
                    mock.patch.object(app.signal, "signal"):
                with self.assertRaises(RuntimeError):
                    app.main()
        server.server_close.assert_called_once()
        scanner.stop.assert_called_once()
        store.close.assert_called_once()
