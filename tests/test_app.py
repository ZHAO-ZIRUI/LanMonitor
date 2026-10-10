import http.client
import json
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer

from app import Store, Scanner, make_handler, encode_dns_name, parse_ptr_packet, decode_dns_name


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "test.sqlite3"
        self.store = Store(self.database)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_all_usable_addresses_and_exact_dhcp_bounds(self):
        hosts = self.store.snapshot()["hosts"]
        self.assertEqual([host["octet"] for host in hosts], list(range(1, 255)))
        self.assertEqual(sum(host["dhcp"] for host in hosts), 95)
        self.assertFalse(self.store.get(4)["dhcp"])
        self.assertTrue(self.store.get(5)["dhcp"])
        self.assertTrue(self.store.get(99)["dhcp"])
        self.assertFalse(self.store.get(100)["dhcp"])

    def test_cache_is_history_not_live_evidence(self):
        self.store.observe(50, "ARP 缓存", mac="00:11:22:33:44:55", now=100)
        self.store.observe(50, "ARP 缓存", now=200)
        host = self.store.get(50)
        self.assertEqual(host["first_recorded"], 100)
        self.assertIsNone(host["last_seen"])
        self.assertIsNone(host["first_seen"])

    def test_ping_failure_preserves_last_success(self):
        self.store.record_ping(50, True, rtt=0.7, now=100)
        self.store.record_ping(50, False, now=200)
        host = self.store.get(50)
        self.assertEqual(host["last_seen"], 100)
        self.assertEqual(host["last_ping_success"], 100)
        self.assertEqual(host["last_checked"], 200)
        self.assertFalse(host["last_ping_ok"])

    def test_marking_an_address_does_not_make_it_seen(self):
        self.store.set_flags(180, {"infrastructure": True, "reserved": True})
        host = self.store.get(180)
        self.assertTrue(host["infrastructure"])
        self.assertTrue(host["reserved"])
        self.assertIsNone(host["first_recorded"])
        self.assertIsNone(host["last_seen"])
        self.store.set_flags(180, {"infrastructure": False})
        self.assertFalse(self.store.get(180)["infrastructure"])
        self.assertTrue(self.store.get(180)["reserved"])

    def test_restart_preserves_flags_and_actual_timestamps(self):
        self.store.observe(172, "mDNS", live=True, hostname="workstation.local", now=100)
        self.store.set_flags(172, {"infrastructure": True, "reserved": True})
        self.store.close()
        self.store = Store(self.database)
        host = self.store.get(172)
        self.assertEqual(host["last_seen"], 100)
        self.assertEqual(host["hostname"], "workstation.local")
        self.assertTrue(host["infrastructure"])
        self.assertTrue(host["reserved"])

    def test_mac_reassignment_clears_stale_name(self):
        self.store.observe(50, "mDNS", live=True, mac="00:11:22:33:44:55", hostname="old-phone.local", now=100)
        self.store.observe(50, "ARP 缓存", mac="00:11:22:33:44:66", now=200)
        self.assertIsNone(self.store.get(50)["hostname"])
        self.assertEqual(self.store.get(50)["last_seen"], 100)

    def test_delete_returns_blank_address_and_can_be_rediscovered(self):
        self.store.record_ping(172, True, now=100)
        self.store.set_flags(172, {"infrastructure": True, "reserved": True})
        before = self.store.snapshot()["revision"]
        self.store.delete(172)
        delta = self.store.snapshot(before)
        self.assertEqual(len(delta["hosts"]), 1)
        host = delta["hosts"][0]
        self.assertEqual(host["ip"], "192.168.100.172")
        self.assertIsNone(host["first_recorded"])
        self.assertFalse(host["infrastructure"])
        self.assertFalse(host["reserved"])
        self.store.record_ping(172, True, now=300)
        self.assertEqual(self.store.get(172)["first_recorded"], 300)

    def test_delta_and_restart_cursor_recovery(self):
        self.store.set_flags(1, {"reserved": True})
        revision = self.store.snapshot()["revision"]
        self.store.record_ping(2, True, now=100)
        delta = self.store.snapshot(revision)
        self.assertFalse(delta["full"])
        self.assertEqual([host["octet"] for host in delta["hosts"]], [2])
        self.assertTrue(self.store.snapshot(999)["full"])

    def test_deleted_cache_stays_deleted_across_restart_until_fresh_evidence(self):
        self.store.observe(50, "ARP 缓存", now=100)
        self.store.delete(50)
        self.store.close()
        self.store = Store(self.database)
        self.store.observe(50, "ARP 缓存", now=200)
        self.store.record_ping(50, False, now=200)
        self.assertIsNone(self.store.get(50)["first_recorded"])
        self.store.observe(50, "mDNS", live=True, hostname="phone.local", now=300)
        self.assertEqual(self.store.get(50)["first_recorded"], 300)
        self.assertEqual(self.store.get(50)["last_seen"], 300)
        self.assertNotIn(50, self.store.deleted)

    def test_rejects_invalid_flags_and_special_addresses(self):
        for values in [{"reserved": "yes"}, {"unsupported": True}, {}]:
            with self.assertRaises(ValueError):
                self.store.set_flags(1, values)
        for octet in [0, 255]:
            with self.assertRaises(ValueError):
                self.store.delete(octet)


class DNSTests(unittest.TestCase):
    def response(self, ttl):
        name = "50.100.168.192.in-addr.arpa"
        question = encode_dns_name(name) + struct.pack("!HH", 12, 1)
        target = encode_dns_name("phone.local")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, ttl, len(target)) + target
        return struct.pack("!HHHHHH", 0x4C4D, 0x8400, 1, 1, 0, 0) + question + answer

    def test_compressed_ptr(self):
        self.assertEqual(parse_ptr_packet(self.response(10)), [("50.100.168.192.in-addr.arpa", "phone.local")])

    def test_mdns_goodbye_is_not_live_but_zero_ttl_unicast_is_valid(self):
        self.assertEqual(parse_ptr_packet(self.response(0)), [])
        self.assertEqual(len(parse_ptr_packet(self.response(0), allow_zero_ttl=True)), 1)

    def test_malformed_pointer_is_bounded(self):
        with self.assertRaises(ValueError):
            decode_dns_name(b"\xc0\x00", 0)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "test.sqlite3")
        scanner = Scanner(self.store, enabled=False)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, scanner, 0, "127.0.0.1"))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()
        self.directory.cleanup()

    def request(self, method, target, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        return status, json.loads(payload)

    def test_state_and_mutations(self):
        status, state = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(len(state["hosts"]), 254)
        headers = {"Content-Type": "application/json", "X-LanMonitor": "1"}
        status, payload = self.request("PATCH", "/api/hosts/200", json.dumps({"reserved": True, "infrastructure": True}), headers)
        self.assertEqual(status, 200)
        self.assertTrue(payload["host"]["reserved"])
        status, payload = self.request("DELETE", "/api/hosts/200", headers=headers)
        self.assertEqual(status, 200)
        self.assertFalse(payload["host"]["reserved"])

    def test_cross_origin_and_invalid_requests_are_rejected(self):
        status, _ = self.request("PATCH", "/api/hosts/200", '{"reserved":true}', {"Content-Type": "application/json"})
        self.assertEqual(status, 403)

        status, _ = self.request("PATCH", "/api/hosts/200", '{"reserved":true}', {"Content-Type": "application/json", "X-LanMonitor": "1", "Origin": "http://example.com"})
        self.assertEqual(status, 403)
        status, _ = self.request("DELETE", "/api/hosts/255", headers={"X-LanMonitor": "1"})
        self.assertEqual(status, 400)
        status, _ = self.request("GET", "/api/state", headers={"Host": "example.com"})
        self.assertEqual(status, 403)

    def test_server_restart_forces_full_state_even_if_revision_is_equal(self):
        status, payload = self.request("GET", "/api/state?since=1&instance=old-server")
        self.assertEqual(status, 200)
        self.assertTrue(payload["full"])
        self.assertEqual(len(payload["hosts"]), 254)


if __name__ == "__main__":
    unittest.main()
