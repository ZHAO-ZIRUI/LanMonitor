"""Persistent-settings regressions; all files stay inside temporary directories."""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from config import DEFAULT_SETTINGS, MAX_CONFIG_BYTES, Settings, atomic_write_json, read_json_file, validate_settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "settings.json"

    def test_partial_saved_settings_receive_defaults_and_updates_survive_restart(self):
        self.path.write_text('{"scan_enabled": false}', encoding="utf-8")
        settings = Settings(self.path)
        self.assertFalse(settings.snapshot()["scan_enabled"])
        self.assertEqual(settings.snapshot()["dhcp_end"], DEFAULT_SETTINGS["dhcp_end"])
        settings.update({"dhcp_start": 20, "dhcp_end": 30})
        self.assertEqual(Settings(self.path).snapshot(), settings.snapshot())

    def test_legacy_collector_setting_is_migrated_atomically_and_only_on_load(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                saved = dict(DEFAULT_SETTINGS, surge_enabled=enabled, probe_rate=2, scan_enabled=False)
                atomic_write_json(self.path, saved)
                settings = Settings(self.path)
                expected = dict(DEFAULT_SETTINGS, probe_rate=2, scan_enabled=False)
                self.assertEqual(settings.snapshot(), expected)
                self.assertEqual(read_json_file(self.path), expected)
                self.assertEqual(Settings(self.path).snapshot(), expected)
                self.assertNotIn("surge_enabled", settings.export()["settings"])
                before = settings.export()
                with self.assertRaises(ValueError):
                    settings.update({"surge_enabled": enabled, "probe_rate": 3})
                self.assertEqual(settings.export(), before)
                self.assertEqual(read_json_file(self.path), expected)

    def test_legacy_migration_rejects_invalid_values_and_other_unknown_fields(self):
        for saved in ({"surge_enabled": 1}, {"surge_enabled": None},
                      {"surge_enabled": True, "unknown": False},
                      {"surge_enabled": True, "probe_rate": 0}):
            with self.subTest(saved=saved):
                atomic_write_json(self.path, saved)
                disk = self.path.read_bytes()
                with self.assertRaises(ValueError):
                    Settings(self.path)
                self.assertEqual(self.path.read_bytes(), disk)

    def test_failed_legacy_migration_preserves_original_file_and_can_retry(self):
        saved = dict(DEFAULT_SETTINGS, surge_enabled=True, probe_rate=2)
        atomic_write_json(self.path, saved)
        disk = self.path.read_bytes()
        with mock.patch("config.os.replace", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                Settings(self.path)
        self.assertEqual(self.path.read_bytes(), disk)
        self.assertEqual(list(self.path.parent.glob(".*.tmp")), [])
        self.assertEqual(Settings(self.path).snapshot(), dict(DEFAULT_SETTINGS, probe_rate=2))

    def test_invalid_settings_never_replace_valid_memory_or_disk(self):
        settings = Settings(self.path)
        before = settings.export()
        disk = self.path.read_bytes()
        for changes in ({}, [], {"unknown": True}, {"probe_rate": True},
                        {"scan_enabled": 1}, {"dhcp_start": 100}, {"refresh_interval": 31}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                settings.update(changes)
            self.assertEqual(settings.export(), before)
            self.assertEqual(self.path.read_bytes(), disk)
        with self.assertRaises(ValueError):
            validate_settings({"scan_enabled": True})

    def test_failed_atomic_replace_preserves_revision_and_original_file(self):
        settings = Settings(self.path)
        before = settings.export()
        disk = self.path.read_bytes()
        with mock.patch("config.os.replace", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                settings.update({"scan_enabled": False})
        self.assertEqual(settings.export(), before)
        self.assertEqual(self.path.read_bytes(), disk)
        self.assertEqual(list(self.path.parent.glob(".*.tmp")), [])

    def test_failed_flush_preserves_original_file_and_removes_temporary_file(self):
        atomic_write_json(self.path, {"original": True})
        disk = self.path.read_bytes()
        with mock.patch("config.os.fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                atomic_write_json(self.path, {"original": False})
        self.assertEqual(self.path.read_bytes(), disk)
        self.assertEqual(list(self.path.parent.glob(".*.tmp")), [])

    def test_rejects_corruption_without_overwriting_it(self):
        for payload in (b"[1]", b'{"scan_enabled": NaN}', b'{"scan_enabled": true, "scan_enabled": false}',
                        b'{"unknown": 1}', b"\xff", b"[" * 2000 + b"]" * 2000,
                        b" " * (MAX_CONFIG_BYTES + 1)):
            with self.subTest(payload=payload[:50]):
                self.path.write_bytes(payload)
                with self.assertRaises(ValueError):
                    Settings(self.path)
                self.assertEqual(self.path.read_bytes(), payload)

    def test_memory_only_updates_do_not_touch_persisted_settings(self):
        settings = Settings(self.path)
        disk = self.path.read_bytes()
        settings.update({"scan_enabled": False}, persist=False)
        self.assertFalse(settings.snapshot()["scan_enabled"])
        self.assertEqual(self.path.read_bytes(), disk)

    def test_snapshots_are_copies_and_revision_survives_clock_regression(self):
        settings = Settings()
        before = settings.export()
        before["settings"]["scan_enabled"] = False
        self.assertTrue(settings.snapshot()["scan_enabled"])
        revision = settings.revision
        with mock.patch("config.time.time", return_value=0):
            settings.update({"scan_enabled": False})
        self.assertGreater(settings.revision, revision)
        same = settings.revision
        settings.update({"scan_enabled": False})
        self.assertEqual(settings.revision, same)

    def test_shared_lock_is_reentrant_and_update_wakes_waiter(self):
        settings = Settings()
        ready = threading.Event()
        finished = threading.Event()
        stop = threading.Event()
        revision = settings.revision

        def waiter():
            with settings.condition:
                ready.set()
                settings.wait(stop, 2, revision)
            finished.set()

        thread = threading.Thread(target=waiter)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.assertTrue(ready.wait(1))
        with settings.lock:
            settings.update({"scan_enabled": False})
            self.assertFalse(settings.snapshot()["scan_enabled"])
        self.assertTrue(finished.wait(1))

    def test_reader_limits_actual_bytes(self):
        self.path.write_text(json.dumps({"text": "测试"}, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(ValueError):
            read_json_file(self.path, limit=12)


if __name__ == "__main__":
    unittest.main()
