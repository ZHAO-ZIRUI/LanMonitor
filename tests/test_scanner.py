"""Collectors use mocked network/CLI data; command tests only launch local Python."""

import concurrent.futures
import json
import socket
import struct
import subprocess
import sys
import threading
import unittest
from unittest import mock

from config import Settings
from scanner import Scanner, encode_dns_name, run_command


def command_result(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class CommandTests(unittest.TestCase):
    def test_captures_both_streams_and_exit_status(self):
        result = run_command([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "out\n", "err\n"))

    def test_timeout_reaps_process(self):
        original = subprocess.Popen
        processes = []

        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch("scanner.subprocess.Popen", side_effect=launch):
            with self.assertRaises(subprocess.TimeoutExpired):
                run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
        self.assertIsNotNone(processes[0].poll())

    def test_output_limit_applies_to_combined_streams(self):
        with mock.patch("scanner.MAX_COMMAND_OUTPUT", 1024):
            with self.assertRaisesRegex(ValueError, "output limit"):
                run_command([sys.executable, "-c", "import sys; sys.stdout.write('x' * 600); sys.stderr.write('x' * 600)"])

    def test_invalid_output_encoding_is_safe(self):
        result = run_command([sys.executable, "-c", "import os; os.write(1, b'\\xff')"])
        self.assertEqual(result.stdout, "\ufffd")

    def test_commands_use_stable_locale_for_parsing(self):
        with mock.patch.dict("os.environ", {"LC_ALL": "zh_CN.UTF-8"}):
            result = run_command([sys.executable, "-c", "import os; print(os.environ['LC_ALL'])"])
        self.assertEqual(result.stdout, "C\n")


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings()
        self.store = mock.Mock()
        self.store.settings = self.settings
        self.store.known_hosts.return_value = []
        self.store.get.return_value = {"first_recorded": 100, "mac": None}
        self.scanner = Scanner(self.store)
        self.scanner.local_ip = "192.168.100.254"
        self.scanner.interface = "en0"

    def tearDown(self):
        self.scanner.stop()

    def test_arp_mac_churn_is_bounded_by_addresses(self):
        lines = ["? (192.168.100.50) at 02:00:00:00:{:02x}:{:02x} on en0".format(index // 256, index % 256)
                 for index in range(1000)]
        with mock.patch("scanner.platform.system", return_value="Darwin"), mock.patch("scanner.run_command", return_value=command_result("\n".join(lines))):
            self.scanner.read_arp()
        self.assertEqual(len(self.scanner.arp_cache_seen), 1)
        self.assertEqual(self.scanner.arp_cache_seen[50], "02:00:00:00:03:e7")
        self.store.observe.assert_called_once_with(50, "ARP 缓存", mac="02:00:00:00:03:e7")
        self.assertTrue(all("live" not in call.kwargs for call in self.store.observe.call_args_list))

    def test_arp_rejects_invalid_mac_and_other_interfaces(self):
        text = "\n".join(("? (192.168.100.50) at ff:ff:ff:ff:ff:ff on en0",
                          "? (192.168.100.51) at 00:00:00:00:00:00 on en0",
                          "? (192.168.100.52) at 00:11:22:33:44:55 on en1",
                          "? (192.168.100.255) at 00:11:22:33:44:55 on en0"))
        with mock.patch("scanner.platform.system", return_value="Darwin"), mock.patch("scanner.run_command", return_value=command_result(text)):
            self.scanner.read_arp()
        self.store.observe.assert_not_called()

    def test_deleted_arp_cache_is_not_reimported_without_fresh_evidence(self):
        self.scanner.arp_cache_seen[50] = "00:11:22:33:44:55"
        self.store.get.return_value = {"first_recorded": None, "mac": None}
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result("192.168.100.50 dev en0 lladdr 00:11:22:33:44:55 STALE")):
            self.scanner.read_arp()
        self.store.observe.assert_not_called()

    def test_linux_neighbors_only_import_valid_ipv4_on_selected_interface(self):
        self.scanner.interface = "eth0"
        lines = [
            "192.168.100.50 dev eth0 lladdr 00:11:22:33:44:55 STALE",
            "192.168.100.51 dev eth0 lladdr 00:11:22:33:44:66 REACHABLE",
            "192.168.100.52 dev docker0 lladdr 00:11:22:33:44:77 REACHABLE",
            "192.168.100.53 dev eth0 FAILED",
            "192.168.100.54 dev eth0 lladdr ff:ff:ff:ff:ff:ff PERMANENT",
            "192.168.100.55 dev eth0 lladdr 00:00:00:00:00:00 STALE",
            "192.168.100.256 dev eth0 lladdr 00:11:22:33:44:88 REACHABLE",
            "fe80::192.168.100.56 dev eth0 lladdr 00:11:22:33:44:99 STALE",
            "192.168.101.57 dev eth0 lladdr 00:11:22:33:44:aa STALE",
        ]
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result("\n".join(lines))) as command:
            self.scanner.read_arp()
        command.assert_called_once_with(["ip", "-4", "neigh", "show"], 3)
        self.assertEqual(self.store.observe.call_args_list, [
            mock.call(50, "ARP 缓存", mac="00:11:22:33:44:55"),
            mock.call(51, "ARP 缓存", mac="00:11:22:33:44:66"),
        ])
        self.assertIsNotNone(self.scanner.snapshot()["last_arp_read"])

    def test_failed_neighbor_command_does_not_import_partial_output(self):
        text = "192.168.100.50 dev en0 lladdr 00:11:22:33:44:55 STALE"
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result(text, returncode=1)):
            with self.assertRaises(OSError):
                self.scanner.read_arp()
        self.store.observe.assert_not_called()
        self.assertIsNone(self.scanner.snapshot()["last_arp_read"])

    def test_interface_error_clears_status_and_invalid_shapes_are_ignored(self):
        self.scanner.update_status(local_ip=self.scanner.local_ip, interface="en0")
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result("{}")):
            self.scanner.inspect_interface()
        self.assertIsNone(self.scanner.local_ip)
        self.assertIsNone(self.scanner.snapshot()["local_ip"])
        interfaces = [None, {"addr_info": [None, {"local": "192.168.100.999"}, {"family": "inet", "local": "192.168.100.2"}], "ifname": "eth0", "address": "02:00:00:00:00:01"}]
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result(json.dumps(interfaces))):
            self.scanner.inspect_interface()
        self.assertEqual(self.scanner.local_ip, "192.168.100.2")

    def test_linux_interface_selection_uses_first_matching_ipv4(self):
        interfaces = [
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
            {"ifname": "docker0", "addr_info": [{"family": "inet", "local": "172.17.0.1"}]},
            {"ifname": "invalid", "addr_info": [{"family": "inet6", "local": "192.168.100.3"}]},
            {"ifname": "eth0", "address": "02:11:22:33:44:55", "addr_info": [
                {"family": "inet6", "local": "fe80::1"},
                {"family": "inet", "local": "192.168.100.2", "prefixlen": 24},
                {"family": "inet", "local": "192.168.100.4", "prefixlen": 24},
            ]},
            {"ifname": "eth1", "addr_info": [{"family": "inet", "local": "192.168.100.5"}]},
        ]
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result(json.dumps(interfaces))) as command:
            self.scanner.inspect_interface()
        command.assert_called_once_with(["ip", "-j", "-4", "address", "show", "up"], 3)
        self.assertEqual((self.scanner.interface, self.scanner.local_ip, self.scanner.local_mac),
                         ("eth0", "192.168.100.2", "02:11:22:33:44:55"))

    def test_failed_interface_command_clears_old_address(self):
        text = json.dumps([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.100.2"}]}])
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result(text, returncode=1)):
            self.scanner.inspect_interface()
        self.assertIsNone(self.scanner.local_ip)
        self.assertIsNone(self.scanner.interface)
        self.assertIn("暂停", self.scanner.snapshot()["error"])

    def test_ping_bad_rtt_cannot_poison_storage(self):
        for value in ("1..2", "9" * 400, "nan", "inf"):
            with self.subTest(value=value), mock.patch("scanner.run_command", return_value=command_result("time=" + value + " ms")):
                self.scanner.ping(50)
                self.store.record_ping.assert_called_with(50, True, None)

    def test_permission_failure_is_not_a_failed_host_probe(self):
        with mock.patch("scanner.run_command", return_value=command_result(stderr="Operation not permitted", returncode=2)):
            self.scanner.ping(50)
        self.store.record_ping.assert_not_called()
        self.assertIn("权限", self.scanner.snapshot()["error"])

    def test_platform_ping_exit_codes_preserve_local_error_state(self):
        for system, no_reply, local_error in (("Linux", 1, 2), ("Darwin", 2, 64)):
            with self.subTest(system=system), mock.patch("scanner.platform.system", return_value=system), mock.patch("scanner.run_command") as command:
                command.return_value = command_result(returncode=no_reply)
                self.scanner.ping(50)
                self.store.record_ping.assert_called_once_with(50, False, None)
                self.store.record_ping.reset_mock()
                command.return_value = command_result(stderr="socket unavailable", returncode=local_error)
                self.scanner.ping(50)
                self.store.record_ping.assert_not_called()
                self.assertIn("ICMP", self.scanner.snapshot()["error"])

    def test_linux_ping_binds_selected_local_ip_and_parses_rtt(self):
        text = "64 bytes from 192.168.100.50: icmp_seq=1 ttl=64 time=0.321 ms"
        with mock.patch("scanner.platform.system", return_value="Linux"), mock.patch("scanner.run_command", return_value=command_result(text)) as command:
            self.scanner.ping(50)
        command.assert_called_once_with(["ping", "-n", "-c", "1", "-W", "1", "-I", "192.168.100.254", "192.168.100.50"], 2.5)
        self.store.record_ping.assert_called_once_with(50, True, 0.321)

    def test_timeout_is_recorded_as_a_failed_probe(self):
        with mock.patch("scanner.run_command", side_effect=subprocess.TimeoutExpired("ping", 2.5)):
            self.scanner.ping(50)
        self.store.record_ping.assert_called_once_with(50, False)

    def test_invalid_probe_addresses_never_run_a_command(self):
        with mock.patch("scanner.run_command") as command:
            for octet in (0, 255, True, "50"):
                with self.assertRaises(ValueError):
                    self.scanner.ping(octet)
            command.assert_not_called()

    def test_probe_queue_never_exceeds_four_and_worker_exceptions_are_reported(self):
        executor = mock.Mock()
        futures = []

        def submit(*args):
            future = concurrent.futures.Future()
            if not futures:
                future.set_exception(RuntimeError("temporary database failure"))
            futures.append(future)
            return future

        executor.submit.side_effect = submit
        ticks = 0

        def wait(_timeout):
            nonlocal ticks
            ticks += 1
            if ticks == 20:
                self.scanner.stop_event.set()

        with mock.patch("scanner.concurrent.futures.ThreadPoolExecutor") as pool, mock.patch.object(self.scanner.stop_event, "wait", side_effect=wait), self.assertLogs("lanmonitor", level="ERROR"):
            pool.return_value.__enter__.return_value = executor
            self.scanner.ping_loop()
        self.assertEqual(len(futures), 5)
        self.assertEqual(sum(not future.done() for future in futures), 4)

    def test_name_retry_intervals_use_monotonic_time(self):
        host = {"ip": "192.168.100.50", "octet": 50}
        self.store.known_hosts.return_value = [host]
        cycles = 0

        def wait(*_args):
            nonlocal cycles
            cycles += 1
            if cycles == 4:
                self.scanner.stop_event.set()

        with mock.patch.object(self.settings, "wait", side_effect=wait), mock.patch("scanner.time.monotonic", side_effect=[1, 2, 46, 301]), mock.patch("scanner.time.time", side_effect=AssertionError("wall clock used for interval")), mock.patch.object(self.scanner, "query_mdns") as mdns, mock.patch.object(self.scanner, "query_router_name") as router:
            self.scanner.name_loop()
        self.assertEqual(mdns.call_count, 3)
        self.assertEqual(router.call_count, 2)

    def test_worker_recovers_from_transient_exception(self):
        calls = 0

        def collector():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("temporary failure")
            self.scanner.stop_event.set()

        with mock.patch.object(self.scanner.stop_event, "wait", return_value=False), self.assertLogs("lanmonitor", level="ERROR"):
            self.scanner._run_loop(collector)
        self.assertEqual(calls, 2)

    def test_disabled_start_is_idempotent_and_stop_joins_workers(self):
        self.settings.update({"scan_enabled": False})
        with mock.patch.object(self.scanner, "inspect_interface") as inspect:
            self.scanner.start()
            self.scanner.start()
            self.scanner.stop()
            inspect.assert_not_called()
        self.assertEqual(len(self.scanner.threads), 3)
        self.assertTrue(all(not thread.is_alive() for thread in self.scanner.threads))

    def test_stop_waits_for_worker_completion_before_returning(self):
        release, finished = threading.Event(), threading.Event()
        worker = threading.Thread(target=release.wait)
        worker.start()
        self.scanner.threads = [worker]
        stopper = threading.Thread(target=lambda: (self.scanner.stop(), finished.set()))
        stopper.start()
        try:
            self.assertFalse(finished.wait(0.05))
        finally:
            release.set()
            stopper.join(1)
        self.assertTrue(finished.is_set())

    def test_router_query_binds_local_interface_and_rejects_wrong_source_port(self):
        owner = encode_dns_name("1.100.168.192.in-addr.arpa")
        target = encode_dns_name("router.local")
        response = struct.pack("!HHHHHH", 123, 0x8000, 0, 1, 0, 0) + owner + struct.pack("!HHIH", 12, 1, 0, len(target)) + target
        udp = mock.MagicMock()
        udp.recvfrom.return_value = (response, ("192.168.100.1", 9999))
        with mock.patch("scanner.socket.socket") as factory, mock.patch("scanner.secrets.randbits", return_value=123):
            factory.return_value.__enter__.return_value = udp
            self.scanner.query_router_name()
            self.store.observe.assert_not_called()
            udp.recvfrom.return_value = (response, ("192.168.100.1", 53))
            self.scanner.query_router_name()
        udp.bind.assert_called_with(("192.168.100.254", 0))
        udp.settimeout.assert_called_with(1)
        self.store.observe.assert_called_once_with(1, "主路由 DNS", live=True, hostname="router.local")

    def test_mdns_timeout_and_malformed_packets_obey_deadline(self):
        udp = mock.MagicMock()
        udp.recvfrom.side_effect = [socket.timeout(), (b"\0" * 12, ("192.168.100.50", 5353))]
        with mock.patch("scanner.socket.socket") as factory, mock.patch("scanner.time.monotonic", side_effect=[0, 0, 0, 1, 1, 4]):
            factory.return_value.__enter__.return_value = udp
            self.scanner.query_mdns([{"octet": 50, "ip": "192.168.100.50"}])
        self.assertEqual(udp.recvfrom.call_count, 2)
        self.store.observe.assert_not_called()
        self.assertTrue(all(0 < call.args[0] <= 0.3 for call in udp.settimeout.call_args_list))

    def test_mdns_legacy_query_uses_selected_interface_and_ephemeral_port(self):
        udp = mock.MagicMock()
        with mock.patch("scanner.socket.socket") as factory, mock.patch("scanner.secrets.randbits", return_value=123), mock.patch("scanner.time.monotonic", side_effect=[0, 4]):
            factory.return_value.__enter__.return_value = udp
            self.scanner.query_mdns([{"octet": 50, "ip": "192.168.100.50"}])
        udp.bind.assert_called_once_with(("192.168.100.254", 0))
        udp.setsockopt.assert_has_calls([
            mock.call(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("192.168.100.254")),
            mock.call(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255),
        ])
        request, destination = udp.sendto.call_args.args
        self.assertEqual(destination, ("224.0.0.251", 5353))
        self.assertEqual(struct.unpack_from("!HHHHHH", request), (123, 0, 1, 0, 0, 0))
        self.assertEqual(request[12:], encode_dns_name("50.100.168.192.in-addr.arpa") + struct.pack("!HH", 12, 1))

    def test_mdns_duplicate_answers_bound_writes_and_prefer_direct_reply(self):
        owner = encode_dns_name("50.100.168.192.in-addr.arpa")

        def response(hostname):
            target = encode_dns_name(hostname)
            answer = owner + struct.pack("!HHIH", 12, 1, 30, len(target)) + target
            return struct.pack("!HHHHHH", 123, 0x8000, 0, 2, 0, 0) + answer * 2

        replies = iter(((response("proxy.local"), ("192.168.100.1", 5353)),
                        (response("phone.local"), ("192.168.100.50", 5353)),
                        (response("proxy.local"), ("192.168.100.1", 5353))))

        def receive(_size):
            try:
                return next(replies)
            except StopIteration:
                self.scanner.stop_event.set()
                return b"", ("192.168.100.1", 5353)

        udp = mock.MagicMock()
        udp.recvfrom.side_effect = receive
        with mock.patch("scanner.socket.socket") as factory, mock.patch("scanner.secrets.randbits", return_value=123), mock.patch("scanner.time.monotonic", return_value=0):
            factory.return_value.__enter__.return_value = udp
            self.scanner.query_mdns([{"octet": 50, "ip": "192.168.100.50"}])
        self.assertEqual(self.store.observe.call_args_list,
                         [mock.call(50, "mDNS 代理", live=False, hostname="proxy.local"),
                          mock.call(50, "mDNS", live=True, hostname="phone.local")])


if __name__ == "__main__":
    unittest.main()
