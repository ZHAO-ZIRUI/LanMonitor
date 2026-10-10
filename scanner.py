"""Bounded network collectors and DNS parsing, independent of HTTP."""

import concurrent.futures
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import selectors
import socket
import struct
# required for bounded, local system probes.
import subprocess  # nosec B404
import threading
import time

from constants import LOG, ONLINE_WINDOW, PREFIX
from store import normalize_mac


MAX_COMMAND_OUTPUT = 1024 * 1024


def run_command(argv, timeout=4):
    """Bound both command duration and captured output, including failed commands."""
    deadline = time.monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    size = 0
    # Keep numeric output and command errors stable across host/container locales.
    command_env = dict(os.environ, LC_ALL="C")
    # Callers construct fixed executable/argument lists; no shell command is accepted.
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=command_env) as process:  # nosec B603
        try:
            with selectors.DefaultSelector() as selector:
                for label in output:
                    stream = getattr(process, label)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > MAX_COMMAND_OUTPUT:
                            raise ValueError("Command output limit exceeded")
                        output[key.data].extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                process.wait(timeout=remaining)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    return subprocess.CompletedProcess(argv, process.returncode,
                                       output["stdout"].decode("utf-8", errors="replace"),
                                       output["stderr"].decode("utf-8", errors="replace"))


def encode_dns_name(name):
    if not isinstance(name, str):
        raise ValueError("DNS name must be text")
    if name in ("", "."):
        return b"\0"
    labels = [part.encode("ascii") for part in name.removesuffix(".").split(".")]
    if any(not 1 <= len(part) <= 63 for part in labels) or sum(len(part) + 1 for part in labels) + 1 > 255:
        raise ValueError("DNS name length")
    return b"".join(bytes([len(part)]) + part for part in labels) + b"\0"


def decode_dns_name(packet, offset, depth=0):
    labels, visited = [], set()
    end, expanded_size = None, 1
    while True:
        if not 0 <= offset < len(packet):
            raise ValueError("DNS bounds")
        if offset in visited or depth > 20:
            raise ValueError("DNS pointer recursion")
        visited.add(offset)
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        if length & 0xC0 == 0xC0:
            if offset >= len(packet):
                raise ValueError("DNS pointer bounds")
            if end is None:
                end = offset + 1
            offset = ((length & 0x3F) << 8) | packet[offset]
            depth += 1
            continue
        if length > 63 or offset + length > len(packet):
            raise ValueError("DNS label bounds")
        expanded_size += length + 1
        if expanded_size > 255:
            raise ValueError("DNS name length")
        labels.append(packet[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length


def parse_ptr_packet(packet, allow_zero_ttl=False):
    if len(packet) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet)
    if len(packet) > 65535:
        raise ValueError("DNS packet length")
    if not flags & 0x8000 or flags & 0x7A0F:
        return []
    offset, records = 12, []
    for _ in range(qd):
        _, offset = decode_dns_name(packet, offset)
        if offset + 4 > len(packet):
            raise ValueError("DNS question bounds")
        offset += 4
    for _ in range(an + ns + ar):
        owner, offset = decode_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("DNS record header bounds")
        rrtype, rrclass, ttl, size = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + size > len(packet):
            raise ValueError("DNS record bounds")
        if rrtype == 12 and rrclass & 0x7FFF == 1 and (ttl > 0 or allow_zero_ttl):
            target, end = decode_dns_name(packet, offset)
            if end != offset + size:
                raise ValueError("DNS PTR data bounds")
            if target and len(target) <= 253:
                records.append((owner.lower(), target))
        offset += size
    return records


class Scanner:
    def __init__(self, store, enabled=True, settings=None):
        self.store = store
        self.settings = settings or store.settings
        if not enabled:
            self.settings.update({"scan_enabled": False}, persist=False)
        self.stop_event = threading.Event()
        self.threads = []
        self.lifecycle_lock = threading.Lock()
        self.started_at = time.time()
        self.status_lock = threading.Lock()
        self.status = {"enabled": enabled, "interface": None, "local_ip": None,
                       "last_arp_read": None,
                       "last_scan_completed": None, "checks": 0, "error": None,
                       "probe_rate": 4, "online_window": ONLINE_WINDOW}
        self.local_ip = None
        self.local_mac = None
        self.interface = None
        # One entry per usable address; MAC churn must not retain an unbounded history.
        self.arp_cache_seen = {}
        self.name_attempts = {}
        self.probe_attempts = {}

    def update_status(self, **values):
        with self.status_lock:
            self.status.update(values)

    @property
    def enabled(self):
        return self.settings.snapshot()["scan_enabled"]

    def snapshot(self):
        settings = self.settings.snapshot()
        with self.status_lock:
            return dict(self.status, started_at=self.started_at, enabled=settings["scan_enabled"],
                        probe_rate=settings["probe_rate"], online_window=settings["online_window"])

    def start(self):
        with self.lifecycle_lock:
            if self.threads or self.stop_event.is_set():
                return
            if self.enabled:
                self.inspect_interface()
            for target in (self.passive_loop, self.ping_loop, self.name_loop):
                thread = threading.Thread(target=self._run_loop, args=(target,), daemon=True, name=target.__name__)
                self.threads.append(thread)
                thread.start()

    def _run_loop(self, target):
        """A transient collector/storage error must not permanently end a worker."""
        while not self.stop_event.is_set():
            try:
                target()
            except Exception:
                LOG.exception("Collector %s failed; retrying", target.__name__)
                self.update_status(error="采集暂时失败，正在重试")
            if self.stop_event.wait(1):
                return

    @staticmethod
    def _local_octet(address):
        if not isinstance(address, str):
            return None
        match = re.fullmatch(re.escape(PREFIX) + r"(\d{1,3})", address)
        if match and 1 <= int(match.group(1)) <= 254:
            return int(match.group(1))
        return None

    def inspect_interface(self):
        local_ip, local_mac, interface = None, None, None
        try:
            if platform.system() == "Darwin":
                result = run_command(["/sbin/ifconfig"], 3)
                if result.returncode:
                    raise OSError("Unable to read network interfaces")
                blocks = re.split(r"\n(?=\S)", result.stdout)
                for block in blocks:
                    match = re.search(r"\binet (192\.168\.100\.\d+)\b", block)
                    if match and self._local_octet(match.group(1)) is not None:
                        local_ip = match.group(1)
                        interface = block.split(":", 1)[0]
                        mac = re.search(r"ether ([0-9a-f:]{17})", block, re.I)
                        local_mac = normalize_mac(mac.group(1)) if mac else None
                        break
            else:
                result = run_command(["ip", "-j", "-4", "address", "show", "up"], 3)
                if result.returncode:
                    raise OSError("Unable to read network interfaces")
                interfaces = json.loads(result.stdout)
                if not isinstance(interfaces, list):
                    raise ValueError("Invalid interface list")
                for item in interfaces:
                    if not isinstance(item, dict) or not isinstance(item.get("addr_info", []), list):
                        continue
                    for address in item.get("addr_info", []):
                        if (isinstance(address, dict) and address.get("family") == "inet"
                                and self._local_octet(address.get("local")) is not None
                                and isinstance(item.get("ifname"), str) and item["ifname"]):
                            local_ip, interface = address["local"], item["ifname"]
                            local_mac = normalize_mac(item.get("address"))
                            break
                    if local_ip:
                        break
            self.local_ip, self.local_mac, self.interface = local_ip, local_mac, interface
            self.update_status(local_ip=self.local_ip, interface=self.interface,
                               error=None if self.local_ip else "本机未连接 192.168.100.0/24，探测已暂停")
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.local_ip, self.local_mac, self.interface = None, None, None
            self.update_status(local_ip=None, interface=None, error="无法读取本机网络接口，探测已暂停")

    def read_arp(self):
        if platform.system() == "Darwin":
            result = run_command(["/usr/sbin/arp", "-an"], 3)
            entries = re.findall(r"\(192\.168\.100\.(\d{1,3})\) at ([0-9a-f:]+) on (\S+)", result.stdout, re.I)
        else:
            result = run_command(["ip", "-4", "neigh", "show"], 3)
            entries = re.findall(r"^192\.168\.100\.(\d{1,3}) dev (\S+) lladdr ([0-9a-f:]+)(?=\s|$)", result.stdout, re.I | re.M)
            entries = [(octet, mac, interface) for octet, interface, mac in entries]
        if result.returncode:
            raise OSError("Unable to read ARP cache")
        current_entries = {}
        for octet, mac, interface in entries:
            octet = int(octet)
            mac = normalize_mac(mac)
            if not 1 <= octet <= 254 or interface != self.interface or not mac:
                continue
            current_entries[octet] = mac
        for octet, mac in current_entries.items():
            if self.stop_event.is_set():
                break
            if self.arp_cache_seen.get(octet) != mac:
                # Import an old cache entry once, without inventing a last-seen time.
                self.store.observe(octet, "ARP 缓存", mac=mac)
                self.arp_cache_seen[octet] = mac
            else:
                host = self.store.get(octet)
                if host["first_recorded"] is not None and host["mac"] != mac:
                    self.store.observe(octet, "ARP 缓存", mac=mac)
        self.update_status(last_arp_read=time.time())

    def passive_loop(self):
        while not self.stop_event.is_set():
            state = self.settings.export()
            settings = state["settings"]
            if settings["scan_enabled"]:
                self.inspect_interface()
            if settings["scan_enabled"] and self.local_ip:
                octet = int(self.local_ip.rsplit(".", 1)[1])
                self.store.observe(octet, "本机接口", live=True, mac=self.local_mac, hostname=socket.gethostname())
                if not self.stop_event.is_set() and self.enabled and settings["arp_enabled"]:
                    try:
                        self.read_arp()
                    except (OSError, ValueError, subprocess.TimeoutExpired):
                        LOG.debug("ARP cache unavailable", exc_info=True)
            self.settings.wait(self.stop_event, settings["passive_interval"], state["settings_revision"])

    def ping(self, octet):
        settings = self.settings.snapshot()
        local_ip = self.local_ip
        if self.stop_event.is_set() or not local_ip or not settings["scan_enabled"] or not settings["ping_enabled"]:
            return
        if type(octet) is not int or not 1 <= octet <= 254:
            raise ValueError("Invalid probe address")
        ip = PREFIX + str(octet)
        darwin = platform.system() == "Darwin"
        if darwin:
            argv = ["/sbin/ping", "-n", "-c", "1", "-t", "1", "-W", "1000", "-S", local_ip, ip]
        else:
            argv = ["ping", "-n", "-c", "1", "-W", "1", "-I", local_ip, ip]
        try:
            result = run_command(argv, 2.5)
            # iputils: 1 means no reply, 2 means a local error; macOS uses 2 for no reply.
            # Local command failures must not overwrite a device's last probe result.
            no_reply = 2 if darwin else 1
            if result.returncode not in (0, no_reply) or "Permission denied" in result.stderr or "Operation not permitted" in result.stderr:
                self.update_status(error="ICMP 探测不可用，请检查 ping 命令、权限及接口")
                return
            success = result.returncode == 0
            match = re.search(r"time[=<]([0-9]{1,20}(?:\.[0-9]{1,20})?)\s*ms", result.stdout)
            rtt = float(match.group(1)) if match else None
            self.store.record_ping(octet, success, rtt if rtt is not None and math.isfinite(rtt) else None)
            with self.status_lock:
                self.status["checks"] += 1
        except subprocess.TimeoutExpired:
            self.store.record_ping(octet, False)
        except OSError:
            self.update_status(error="系统 ping 命令不可用")
        except ValueError:
            self.update_status(error="系统 ping 输出无效")

    def ping_loop(self):
        cursor, tick = 1, 0
        pending = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="probe") as executor:
            while not self.stop_event.is_set():
                settings = self.settings.snapshot()
                for octet, future in list(pending.items()):
                    if future.done():
                        del pending[octet]
                        try:
                            future.result()
                        except Exception:
                            LOG.exception("Probe failed for %s%s", PREFIX, octet)
                            self.update_status(error="采集暂时失败，正在重试")
                if settings["scan_enabled"] and settings["ping_enabled"] and self.local_ip and len(pending) < 4:
                    target = None
                    # One slot in four prioritizes known devices. The other slots always advance the full sweep.
                    if tick % 4 == 3:
                        candidates = sorted(self.store.known_hosts(), key=lambda host: self.probe_attempts.get(host["octet"], -math.inf))
                        for host in candidates:
                            if host["octet"] not in pending and host["ip"] != self.local_ip and time.monotonic() - self.probe_attempts.get(host["octet"], -math.inf) >= 20:
                                target = host["octet"]
                                break
                    if target is None:
                        target = cursor
                        cursor = cursor % 254 + 1
                        if cursor == 1:
                            self.update_status(last_scan_completed=time.time())
                    if target not in pending and PREFIX + str(target) != self.local_ip:
                        self.probe_attempts[target] = time.monotonic()
                        pending[target] = executor.submit(self.ping, target)
                    tick = (tick + 1) % 4
                # At most four new probes per second, with no unbounded task queue.
                self.stop_event.wait(1 / settings["probe_rate"])

    def query_mdns(self, hosts):
        settings = self.settings.snapshot()
        local_ip = self.local_ip
        if self.stop_event.is_set() or not local_ip or not settings["scan_enabled"] or not settings["name_lookup"]:
            return
        names = {}
        for index, host in enumerate(hosts):
            if index >= 254 or self._local_octet(host["ip"]) != host["octet"]:
                raise ValueError("Invalid name lookup batch")
            names[ipaddress.ip_address(host["ip"]).reverse_pointer] = host["octet"]
        if not names:
            return
        transaction = secrets.randbits(16)
        request = struct.pack("!HHHHHH", transaction, 0, len(names), 0, 0, 0)
        request += b"".join(encode_dns_name(name) + struct.pack("!HH", 12, 1) for name in names)
        observed = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            # RFC 6762 legacy queries use an ephemeral source port and receive
            # unicast replies, so a host's existing mDNS service can retain 5353.
            udp.bind((local_ip, 0))
            udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            udp.settimeout(0.3)
            udp.sendto(request, ("224.0.0.251", 5353))
            deadline = time.monotonic() + 3
            while not self.stop_event.is_set() and self.enabled and time.monotonic() < deadline:
                udp.settimeout(min(0.3, max(0.01, deadline - time.monotonic())))
                try:
                    packet, peer = udp.recvfrom(9000)
                    if peer[1] != 5353 or self._local_octet(peer[0]) is None or len(packet) < 12 or struct.unpack_from("!H", packet)[0] != transaction:
                        continue
                    for owner, hostname in parse_ptr_packet(packet):
                        if self.stop_event.is_set() or time.monotonic() >= deadline:
                            break
                        if owner in names:
                            octet = names[owner]
                            direct = peer[0] == PREFIX + str(octet)
                            # Repeated multicast replies must not amplify database writes.
                            # A direct reply can still replace an earlier proxy answer.
                            if octet in observed and (observed[octet] or not direct):
                                continue
                            self.store.observe(octet, "mDNS" if direct else "mDNS 代理", live=direct, hostname=hostname)
                            observed[octet] = direct
                except socket.timeout:
                    continue
                except (ValueError, struct.error, IndexError):
                    continue

    def query_router_name(self):
        settings = self.settings.snapshot()
        local_ip = self.local_ip
        if self.stop_event.is_set() or not local_ip or not settings["scan_enabled"] or not settings["name_lookup"]:
            return
        # Ask only the local router about itself. Never send private PTR lookups to a public DNS service.
        name = ipaddress.ip_address(PREFIX + "1").reverse_pointer
        transaction = secrets.randbits(16)
        packet = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + encode_dns_name(name) + struct.pack("!HH", 12, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind((local_ip, 0))
            udp.settimeout(1)
            udp.sendto(packet, (PREFIX + "1", 53))
            response, peer = udp.recvfrom(4096)
            if peer == (PREFIX + "1", 53) and len(response) >= 12 and struct.unpack_from("!H", response)[0] == transaction:
                for owner, hostname in parse_ptr_packet(response, allow_zero_ttl=True):
                    if owner == name:
                        self.store.observe(1, "主路由 DNS", live=True, hostname=hostname)
                        break

    def name_loop(self):
        last_router_query = None
        while not self.stop_event.is_set():
            state = self.settings.export()
            settings = state["settings"]
            if settings["scan_enabled"] and settings["name_lookup"] and self.local_ip:
                now = time.monotonic()
                candidates = [host for host in self.store.known_hosts()
                              if host["ip"] != self.local_ip and now - self.name_attempts.get(host["octet"], -math.inf) >= 45]
                candidates.sort(key=lambda host: self.name_attempts.get(host["octet"], -math.inf))
                batch = candidates[:32]
                for host in batch:
                    self.name_attempts[host["octet"]] = now
                if batch:
                    try:
                        self.query_mdns(batch)
                    except (OSError, ValueError):
                        LOG.debug("mDNS unavailable", exc_info=True)
                if last_router_query is None or now - last_router_query >= 300:
                    last_router_query = now
                    try:
                        self.query_router_name()
                    except (OSError, ValueError, struct.error, IndexError):
                        LOG.debug("Router PTR unavailable", exc_info=True)
            self.settings.wait(self.stop_event, settings["name_interval"], state["settings_revision"])

    def stop(self):
        with self.lifecycle_lock:
            self.stop_event.set()
            self.settings.wake()
            threads = list(self.threads)
        # All command/socket operations are bounded. Wait for actual completion so
        # callers can safely close the database immediately after stop() returns.
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join()
