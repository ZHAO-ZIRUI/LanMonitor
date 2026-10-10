"""Service-manager regressions without starting, stopping, or probing a service."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import manage
from config import atomic_write_json


class ManageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data = Path(self.directory.name)
        for name, value in (("DATA", self.data), ("PID_FILE", self.data / "server.pid"),
                            ("CONFIG_FILE", self.data / "server.json")):
            patcher = mock.patch.object(manage, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.config = dict(manage.DEFAULT_CONFIG)
        self.command = "{} -u {} --host 127.0.0.1 --port 25400".format(manage.sys.executable, manage.APP)
        self.identity = {"pid": 4321, "started": "Sat Oct 10 12:00:00 2026", "command": self.command}
        self.process = mock.Mock(pid=4321)
        self.process.poll.return_value = None
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def write_pid(self, value=None):
        atomic_write_json(manage.PID_FILE, self.identity if value is None else value)

    def test_config_validation_and_corruption(self):
        self.assertEqual(manage.load_config(), self.config)
        for value in ([], {"host": "127.0.0.1", "port": True}, {"host": "::1", "port": 1},
                      {"host": "127.0.0.1", "port": 65536}, dict(self.config, other=True)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                manage.validate_config(value)
        manage.CONFIG_FILE.write_text("[]", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            manage.load_config()

    def test_management_lock_prevents_overlapping_commands(self):
        with manage.management_lock():
            with self.assertRaises(RuntimeError):
                with manage.management_lock():
                    self.fail("Concurrent transaction entered")
        with manage.management_lock():
            pass

    def test_pid_command_must_be_the_exact_managed_invocation(self):
        self.write_pid(4321)
        for command in ("/usr/bin/grep " + str(manage.APP), self.command + " --unexpected",
                        self.command.replace("app.py", "app.py.other"), "python -c 'print(" + str(manage.APP) + ")'"):
            identity = dict(self.identity, command=command)
            with self.subTest(command=command), mock.patch.object(manage, "_process_identity", return_value=identity):
                self.assertIsNone(manage.managed_pid())
        with mock.patch.object(manage, "_process_identity", return_value=self.identity):
            self.assertEqual(manage.managed_pid(), 4321)

    def test_macos_framework_interpreter_is_recognized(self):
        framework = Path(manage.sys.executable).resolve().parent.parent / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
        command = "{} -u {} --host 127.0.0.1 --port 25400".format(framework, manage.APP)
        with mock.patch.object(manage.sys, "platform", "darwin"):
            self.assertTrue(manage._is_managed_command(command))

    def test_reused_pid_is_not_managed_even_with_identical_arguments(self):
        self.write_pid()
        replacement = dict(self.identity, started="Sat Oct 10 13:00:00 2026")
        with mock.patch.object(manage, "_process_identity", return_value=replacement):
            self.assertIsNone(manage.managed_pid())

    def test_invalid_pid_files_never_query_or_signal_processes(self):
        for payload in ("-1", "1", "true", "2147483648", '"4321"', "{}", "[1]", "x" * 4097):
            manage.PID_FILE.write_text(payload, encoding="utf-8")
            with self.subTest(payload=payload[:30]), mock.patch.object(manage, "_process_identity") as identity:
                self.assertIsNone(manage.managed_pid())
                identity.assert_not_called()

    def test_ps_lookup_failure_does_not_treat_a_process_as_exited(self):
        self.write_pid()
        with mock.patch.object(manage.subprocess, "run", side_effect=subprocess.TimeoutExpired("ps", 2)):
            with self.assertRaises(RuntimeError):
                manage.managed_pid()
        self.assertTrue(manage.PID_FILE.exists())

    def test_ps_output_extracts_birth_time_and_command(self):
        output = "Sat Oct 10 12:00:00 2026 " + self.command + "\n"
        with mock.patch.object(manage.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=output)):
            self.assertEqual(manage._process_identity(4321), self.identity)

    def health_response(self, payload):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = payload
        opener = mock.Mock()
        opener.open.return_value = response
        return opener, response

    def test_health_response_is_bounded_and_requires_expected_shape(self):
        good = {"subnet": "192.168.100.0/24", "hosts": [{}] * 254}
        for value, expected in ((good, True), ([], False), (None, False),
                                ({"subnet": "192.168.100.0/24", "hosts": "a" * 254}, False)):
            opener, response = self.health_response(json.dumps(value).encode())
            with self.subTest(value=str(value)[:40]), mock.patch.object(manage.urllib.request, "build_opener", return_value=opener):
                self.assertEqual(manage.healthy(self.config), expected)
            response.__enter__.return_value.read.assert_called_once_with(manage.MAX_STATE_BYTES + 1)
        for payload in (b"x" * (manage.MAX_STATE_BYTES + 1), b"[" * 2000 + b"]" * 2000, b"\xff"):
            opener, _ = self.health_response(payload)
            with mock.patch.object(manage.urllib.request, "build_opener", return_value=opener):
                self.assertFalse(manage.healthy(self.config))

    def start_context(self, health):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(manage, "healthy", side_effect=health))
        stack.enter_context(mock.patch.object(manage, "managed_pid", return_value=None))
        stack.enter_context(mock.patch.object(manage, "_process_identity", return_value=self.identity))
        stack.enter_context(mock.patch.object(manage.subprocess, "Popen", return_value=self.process))
        stack.enter_context(mock.patch.object(manage.time, "sleep"))
        return stack

    def test_successful_start_records_identity_and_configuration(self):
        with self.start_context([False, True]):
            manage.start(self.config)
        self.assertEqual(json.loads(manage.PID_FILE.read_text()), self.identity)
        self.assertEqual(json.loads(manage.CONFIG_FILE.read_text()), self.config)
        self.process.terminate.assert_not_called()

    def test_start_timeout_reaps_child_and_removes_pid(self):
        with self.start_context([False] * 41):
            with self.assertRaises(RuntimeError):
                manage.start(self.config)
        self.process.terminate.assert_called_once()
        self.process.wait.assert_called_once_with(timeout=8)
        self.assertFalse(manage.PID_FILE.exists())
        self.assertFalse(manage.CONFIG_FILE.exists())

    def test_pid_write_failure_reaps_child(self):
        with self.start_context([False]), mock.patch.object(manage, "atomic_write_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                manage.start(self.config)
        self.process.terminate.assert_called_once()
        self.assertFalse(manage.PID_FILE.exists())

    def test_config_write_failure_reaps_child_and_preserves_previous_config(self):
        previous = dict(self.config, port=25401)
        atomic_write_json(manage.CONFIG_FILE, previous)

        def write(path, value):
            if path == manage.CONFIG_FILE:
                raise OSError("disk full")
            atomic_write_json(path, value)

        with self.start_context([False, True]), mock.patch.object(manage, "atomic_write_json", side_effect=write):
            with self.assertRaises(OSError):
                manage.start(self.config)
        self.assertEqual(json.loads(manage.CONFIG_FILE.read_text()), previous)
        self.assertFalse(manage.PID_FILE.exists())
        self.process.terminate.assert_called_once()

    def test_start_cleanup_escalates_only_the_child_it_created(self):
        self.process.wait.side_effect = [subprocess.TimeoutExpired("app.py", 8), 0]
        with self.start_context([False] * 41):
            with self.assertRaises(RuntimeError):
                manage.start(self.config)
        self.process.kill.assert_called_once()
        self.assertFalse(manage.PID_FILE.exists())

    def test_failed_child_cleanup_retains_identity_for_later_management(self):
        self.process.wait.side_effect = subprocess.TimeoutExpired("app.py", 8)
        with self.start_context([False] * 41):
            with self.assertRaisesRegex(RuntimeError, "尚未退出"):
                manage.start(self.config)
        self.process.kill.assert_called_once()
        self.assertEqual(json.loads(manage.PID_FILE.read_text()), self.identity)

    def test_stop_rechecks_process_identity_before_signaling(self):
        self.write_pid()
        replacement = dict(self.identity, started="Sat Oct 10 13:00:00 2026")
        with mock.patch.object(manage, "managed_process", return_value=self.identity), \
                mock.patch.object(manage, "_process_identity", return_value=replacement), \
                mock.patch.object(manage.os, "kill") as kill:
            manage.stop(self.config)
        kill.assert_not_called()
        self.assertFalse(manage.PID_FILE.exists())

    def test_stop_signals_verified_pid_and_waits_for_original_process_exit(self):
        self.write_pid()
        with mock.patch.object(manage, "managed_process", return_value=self.identity), \
                mock.patch.object(manage, "_process_identity", side_effect=[self.identity, None]), \
                mock.patch.object(manage.os, "kill") as kill:
            manage.stop(self.config)
        kill.assert_called_once_with(4321, manage.signal.SIGTERM)
        self.assertFalse(manage.PID_FILE.exists())

    def test_restart_holds_one_lock_across_configuration_stop_and_start(self):
        events = []

        @contextlib.contextmanager
        def lock():
            events.append("lock")
            yield
            events.append("unlock")

        with mock.patch.object(manage.sys, "argv", ["manage.py", "restart", "--port", "25401"]), \
                mock.patch.object(manage, "management_lock", lock), \
                mock.patch.object(manage, "load_config", side_effect=lambda: events.append("load") or self.config), \
                mock.patch.object(manage, "stop", side_effect=lambda config: events.append(("stop", config))), \
                mock.patch.object(manage, "start", side_effect=lambda config: events.append(("start", config))):
            self.assertEqual(manage.main(), 0)
        self.assertEqual(events, ["lock", "load", ("stop", self.config), ("start", dict(self.config, port=25401)), "unlock"])


if __name__ == "__main__":
    unittest.main()
