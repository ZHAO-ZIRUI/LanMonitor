"""Persistence invariants and fault injection; every database is temporary."""

import json
import math
import random
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from store import Store

MAC = "02:11:22:33:44:55"


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "test.sqlite3"
        self.store = Store(self.database)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(lambda: self.store.close())

    def restart(self):
        self.store.close()
        self.store = Store(self.database)

    def fail_sql(self, table, action):
        self.store.connection.execute(
            "CREATE TEMP TRIGGER injected BEFORE " + action + " ON " + table +
            " BEGIN SELECT RAISE(ABORT, 'injected failure'); END")

    def test_delete_failure_rolls_back_database_memory_and_revision(self):
        self.store.observe(50, "ARP", mac=MAC, now=100)
        before = self.store.snapshot()
        self.fail_sql("tombstones", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.delete(50)
        self.assertFalse(self.store.connection.in_transaction)
        self.assertEqual(self.store.snapshot(), before)
        self.store.set_flags(51, {"reserved": True})
        self.restart()
        self.assertEqual(self.store.get(50)["mac"], MAC)
        self.assertNotIn(50, self.store.deleted)

    def test_failed_rediscovery_keeps_tombstone_and_revision(self):
        self.store.delete(50)
        before = self.store.snapshot()
        self.fail_sql("hosts", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.observe(50, "mDNS", live=True, mac=MAC, now=100)
        self.assertEqual(self.store.snapshot(), before)
        self.assertFalse(self.store.connection.in_transaction)
        self.assertIn(50, self.store.deleted)
        self.restart()
        self.store.observe(50, "ARP", mac=MAC)
        self.assertIsNone(self.store.get(50)["mac"])

    def test_ping_failure_keeps_tombstone_until_success_commits(self):
        self.store.delete(50)
        self.fail_sql("hosts", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.record_ping(50, True, now=100)
        self.assertIn(50, self.store.deleted)
        self.restart()
        self.assertIn(50, self.store.deleted)

    def test_bulk_clear_is_atomic_including_notes(self):
        self.store.observe(50, "ARP", mac=MAC, now=100)
        self.store.set_device_note(MAC, "打印机")
        before = self.store.snapshot()
        self.fail_sql("tombstones", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.clear_history("all")
        self.assertEqual(self.store.snapshot(), before)
        self.restart()
        self.assertEqual(self.store.get(50)["note"], "打印机")

    def test_note_failure_does_not_publish_delta(self):
        self.store.observe(50, "ARP", mac=MAC, now=100)
        before = self.store.snapshot()
        self.fail_sql("device_notes", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.set_device_note(MAC, "打印机")
        self.assertEqual(self.store.snapshot(), before)
        self.assertFalse(self.store.connection.in_transaction)

    def test_note_tracks_mac_and_survives_address_deletion(self):
        self.store.observe(50, "ARP", mac=MAC, now=100)
        self.store.set_device_note("02-11-22-33-44-55", "  打印机  ")
        self.store.delete(50)
        self.store.observe(51, "ARP", mac=MAC, now=200)
        self.assertEqual(self.store.get(51)["note"], "打印机")
        self.restart()
        self.assertEqual(self.store.get(51)["note"], "打印机")
        self.store.clear_history("dhcp", (5, 99))
        self.store.observe(51, "ICMP", live=True, mac=MAC)
        self.assertEqual(self.store.get(51)["note"], "打印机")
        self.store.clear_history("all")
        self.store.observe(51, "ICMP", live=True, mac=MAC)
        self.assertEqual(self.store.get(51)["note"], "")

    def test_note_updates_every_matching_address_in_delta(self):
        for octet in (50, 51):
            self.store.observe(octet, "ARP", mac=MAC, now=100)
        before = self.store.snapshot()["revision"]
        self.store.set_device_note(MAC, "设备")
        self.assertEqual([host["octet"] for host in self.store.snapshot(before)["hosts"]], [50, 51])
        self.store.observe(50, "ARP", mac="02:11:22:33:44:66", now=200)
        self.assertEqual(self.store.get(50)["note"], "")

    def test_live_evidence_only_cleans_offline_old_addresses(self):
        self.store.observe(50, "ICMP", live=True, mac=MAC, now=100)
        self.store.set_flags(50, {"reserved": True})
        self.store.observe(51, "ARP", mac=MAC, now=200)
        self.assertTrue(self.store.get(50)["reserved"])
        self.store.observe(51, "ICMP", live=True, mac=MAC, now=200)
        self.assertIsNone(self.store.get(50)["first_recorded"])
        self.store.observe(52, "ICMP", live=True, mac=MAC, now=201)
        self.assertEqual(self.store.get(51)["last_seen"], 200)

    def test_cleanup_setting_and_stale_confirmation(self):
        self.store.settings.update({"auto_cleanup_old_addresses": False})
        self.store.observe(50, "ARP", mac=MAC, now=100)
        self.store.observe(51, "ICMP", live=True, mac=MAC, now=200)
        self.assertEqual(self.store.get(50)["first_recorded"], 100)
        self.store.settings.update({"dhcp_start": 10})
        with self.assertRaises(ValueError):
            self.store.clear_history("dhcp", (5, 99))
        self.assertEqual(self.store.get(50)["first_recorded"], 100)
        self.assertIs(self.store.lock, self.store.settings.lock)

    def test_nonfinite_huge_and_boolean_numbers_never_reach_json(self):
        for value in (math.nan, math.inf, -math.inf, -1, 10 ** 1000, True):
            with self.subTest(value=repr(value)[:30]):
                with self.assertRaises(ValueError):
                    self.store.record_ping(50, True, rtt=value)
                with self.assertRaises(ValueError):
                    self.store.observe(50, "ARP", now=value)
        for octet in (0, 255, True, 1.0, "1"):
            with self.assertRaises(ValueError):
                self.store.record_ping(octet, True)
        with self.assertRaises(ValueError):
            self.store.set_device_note(MAC, "\ud800")
        with self.assertRaises(ValueError):
            self.store.observe(50, "ARP", hostname="x" * 254)
        json.dumps(self.store.snapshot(), allow_nan=False)

    def test_epoch_zero_remains_first_observation(self):
        self.store.record_ping(50, True, now=0)
        self.store.record_ping(50, True, now=1)
        self.assertEqual(self.store.get(50)["first_seen"], 0)
        self.assertEqual(self.store.get(50)["first_recorded"], 0)

    def test_corrupt_records_cannot_replace_identity_or_poison_api(self):
        self.store.close()
        with closing(sqlite3.connect(self.database)) as db, db:
            payload = {"octet": 99, "ip": "wrong", "special": "bad", "first_recorded": 100,
                       "last_seen": float("inf"), "last_ping_ms": "bad", "hostname": {},
                       "infrastructure": "yes", "mac": [1], "last_checked": 10 ** 1000}
            for octet, raw in ((50, json.dumps(payload)), (51, "[]"), (52, "[" * 2000),
                               (53, "x" * 20000)):
                db.execute("INSERT INTO hosts VALUES (?, ?)", (octet, raw))
        self.store = Store(self.database)
        host = self.store.get(50)
        self.assertEqual(host["ip"], "192.168.100.50")
        self.assertEqual(host["octet"], 50)
        self.assertIsNone(host["special"])
        self.assertIsNone(host["last_seen"])
        self.assertIsNone(host["last_ping_ms"])
        self.assertIsNone(host["hostname"])
        self.assertIsNone(host["last_checked"])
        self.assertFalse(host["infrastructure"])
        self.assertEqual(host["first_recorded"], 100)
        json.dumps(self.store.snapshot(), allow_nan=False)

    def test_single_owner_prevents_independent_cache_overwrites(self):
        with self.assertRaises(BlockingIOError):
            Store(self.database)
        self.restart()
        self.store.record_ping(1, True)

    def test_initialization_failure_releases_database_ownership(self):
        self.store.close()
        with mock.patch.object(Store, "_initialize", side_effect=sqlite3.OperationalError("injected")):
            with self.assertRaises(sqlite3.OperationalError):
                Store(self.database)
        self.store = Store(self.database)
        self.store.record_ping(1, True)

    def test_historical_notes_are_loaded_on_demand_with_bounded_cache(self):
        for index in range(600):
            mac = "02:11:22:33:{:02x}:{:02x}".format(index // 256, index % 256)
            self.store.set_device_note(mac, "设备 {}".format(index))
        self.assertLessEqual(len(self.store._note_cache), 254)
        self.restart()
        self.assertEqual(len(self.store._note_cache), 0)
        self.store.observe(50, "ARP", mac="02:11:22:33:00:00")
        self.assertEqual(self.store.get(50)["note"], "设备 0")
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM device_notes").fetchone()[0], 600)

    def test_oversized_or_malformed_saved_notes_are_not_returned(self):
        self.store.observe(50, "ARP", mac=MAC)
        with self.store.connection:
            self.store.connection.execute("INSERT INTO device_notes VALUES (?, ?, ?)", (MAC, "x" * 100000, 100))
        self.restart()
        self.assertEqual(self.store.get(50)["note"], "")

    def test_repeated_mutations_remain_bounded_and_persist(self):
        randomizer = random.Random(17)
        for tick in range(1500):
            octet = randomizer.randrange(1, 255)
            if tick % 11 == 0:
                self.store.delete(octet)
            else:
                self.store.record_ping(octet, bool(tick % 3), now=tick)
        before = self.store.snapshot()["hosts"]
        self.assertEqual(len(self.store.hosts), 254)
        self.assertEqual(len(self.store.changed), 254)
        self.assertLessEqual(len(self.store.deleted), 254)
        self.assertEqual(self.store.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.restart()
        self.assertEqual(self.store.snapshot()["hosts"], before)

    def test_concurrent_writes_and_snapshots_complete_without_deadlocks(self):
        failures = []
        def writer(octet):
            try:
                for tick in range(60):
                    with self.store.lock:
                        self.store.set_flags(octet, {"reserved": bool(tick % 2)})
                        self.store.settings.update({"show_hostnames": bool(tick % 2)})
                        self.store.snapshot()
            except Exception as exc:
                failures.append(exc)
        threads = [threading.Thread(target=writer, args=(n,), daemon=True) for n in range(1, 5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
