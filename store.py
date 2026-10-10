"""SQLite persistence and synchronized in-memory host state."""

import fcntl
import json
import math
import re
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path

from config import Settings
from constants import DHCP_START, DHCP_END, LOG, PREFIX

# Timestamps must also be representable by the browser's date formatter.
MAX_TIMESTAMP = 253402300799
MAX_RECORD_BYTES = 16384


def valid_number(value, maximum=MAX_TIMESTAMP):
    return type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value)


def checked_time(value):
    value = time.time() if value is None else value
    if not valid_number(value):
        raise ValueError("时间戳无效")
    return value


def valid_text(value, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def check_octet(octet):
    if type(octet) is not int or not 1 <= octet <= 254:
        raise ValueError("需要有效的可用 IPv4 地址")


def normalize_mac(value):
    if not isinstance(value, str) or len(value) > 32:
        return None
    parts = value.strip().lower().replace("-", ":").split(":")
    if len(parts) != 6 or any(not re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts):
        return None
    octets = [int(part, 16) for part in parts]
    if not any(octets) or octets[0] & 1:
        return None
    return ":".join("{:02x}".format(octet) for octet in octets)


def blank_host(octet):
    return {
        "octet": octet, "ip": PREFIX + str(octet),
        "dhcp": DHCP_START <= octet <= DHCP_END,
        "special": "网络地址" if octet == 0 else "广播地址" if octet == 255 else None,
        "first_recorded": None, "first_seen": None, "last_seen": None,
        "last_seen_source": None, "last_ping_success": None, "last_ping_ms": None,
        "last_checked": None, "last_ping_ok": None, "cache_source": None,
        "mac": None, "hostname": None, "hostname_source": None,
        "hostname_updated_at": None, "infrastructure": False, "reserved": False,
    }


class Store:
    def __init__(self, database, settings=None):
        self.settings = settings or Settings()
        # One reentrant lock covers settings and data: a confirmed DHCP range,
        # its deletion, and the response revision describe the same state.
        self.lock = self.settings.lock
        self._database_lock = None
        try:
            if str(database) != ":memory:":
                lock_path = Path(str(Path(database).resolve()) + ".lock")
                self._database_lock = lock_path.open("a+b")
                # SQLite serializes SQL writes, but two independent host caches
                # would still overwrite one another. Hold ownership for life.
                fcntl.flock(self._database_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.connection = sqlite3.connect(str(database), check_same_thread=False)
            self._initialize()
        except BaseException:
            try:
                if hasattr(self, "connection"):
                    self.connection.close()
            finally:
                if self._database_lock:
                    self._database_lock.close()
            raise

    def _initialize(self):
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("CREATE TABLE IF NOT EXISTS hosts (octet INTEGER PRIMARY KEY, data TEXT NOT NULL)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS tombstones (octet INTEGER PRIMARY KEY, deleted_at REAL NOT NULL)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS device_notes (mac TEXT PRIMARY KEY, note TEXT NOT NULL, updated_at REAL NOT NULL)")
        # Notes intentionally outlive addresses. Keep that history on disk and
        # cache only one subnet's worth, rather than loading every past device.
        self._note_cache = OrderedDict()
        self.deleted = {row[0] for row in self.connection.execute("SELECT octet FROM tombstones WHERE octet BETWEEN 1 AND 254")}
        self.hosts = {n: blank_host(n) for n in range(1, 255)}
        for octet, raw in self.connection.execute(
                "SELECT octet, substr(data, 1, ?) FROM hosts WHERE octet BETWEEN 1 AND 254", (MAX_RECORD_BYTES + 1,)):
            try:
                if not isinstance(raw, str) or len(raw) > MAX_RECORD_BYTES:
                    raise ValueError("record too large")
                saved = json.loads(raw)
                if not isinstance(saved, dict):
                    raise ValueError("record is not an object")
                host = self.hosts[octet]
                # Only restore known fields of the expected type. Identity is
                # derived from the primary key, never from JSON on disk.
                for key in ("first_recorded", "first_seen", "last_seen", "last_ping_success", "last_checked", "hostname_updated_at"):
                    if valid_number(saved.get(key)):
                        host[key] = saved[key]
                if valid_number(saved.get("last_ping_ms"), 9007199254740991):
                    host["last_ping_ms"] = saved["last_ping_ms"]
                for key in ("infrastructure", "reserved", "last_ping_ok"):
                    if type(saved.get(key)) is bool:
                        host[key] = saved[key]
                for key in ("hostname", "hostname_source", "last_seen_source", "cache_source"):
                    if valid_text(saved.get(key), 253):
                        host[key] = saved[key]
                host["mac"] = normalize_mac(saved.get("mac"))
            except (ValueError, TypeError, RecursionError):
                LOG.warning("Ignoring malformed record for %s", octet)
        # Old timestamps survive a restart; a restart does not make a host online.
        self.revision = 1
        self.changed = {n: 1 for n in range(1, 255)}

    def _save(self, octet, host, live=False):
        restore = live and octet in self.deleted
        if host == self.hosts[octet] and not restore:
            return
        # Roll back every failed write; publish memory and revision only once
        # SQLite commits both the record and any tombstone removal.
        with self.connection:
            if restore:
                self.connection.execute("DELETE FROM tombstones WHERE octet=?", (octet,))
            self.connection.execute(
                "INSERT INTO hosts (octet, data) VALUES (?, ?) "
                "ON CONFLICT(octet) DO UPDATE SET data=excluded.data",
                (octet, json.dumps(host, ensure_ascii=False, allow_nan=False)),
            )
        if restore:
            self.deleted.discard(octet)
        self.hosts[octet] = host
        self.revision += 1
        self.changed[octet] = self.revision

    def observe(self, octet, source, live=False, mac=None, hostname=None, now=None):
        if type(octet) is not int or not 1 <= octet <= 254:
            return
        now = checked_time(now)
        if not valid_text(source, 253) or type(live) is not bool:
            raise ValueError("观测来源无效")
        if hostname is not None and not valid_text(hostname, 253):
            raise ValueError("主机名称无效")
        with self.lock:
            settings = self.settings.snapshot()
            if octet in self.deleted and not live:
                return
            host = dict(self.hosts[octet])
            if host["first_recorded"] is None:
                host["first_recorded"] = now
            mac = normalize_mac(mac)
            if mac:
                if host["mac"] and host["mac"] != mac:
                    host.update(hostname=None, hostname_source=None, hostname_updated_at=None)
                host["mac"] = mac
            if live:
                if host["first_seen"] is None:
                    host["first_seen"] = now
                host["last_seen"] = now
                host["last_seen_source"] = source
            else:
                host["cache_source"] = source
            if hostname:
                host.update(hostname=hostname, hostname_source=source, hostname_updated_at=now)
            self._save(octet, host, live=live)
            if live:
                self._cleanup_old_addresses(now, settings, octet)

    def record_ping(self, octet, success, rtt=None, now=None):
        check_octet(octet)
        now = checked_time(now)
        if type(success) is not bool or (rtt is not None and not valid_number(rtt, 9007199254740991)):
            raise ValueError("探测结果无效")
        with self.lock:
            settings = self.settings.snapshot()
            host = dict(self.hosts[octet])
            host.update(last_checked=now, last_ping_ok=success)
            if success:
                if host["first_recorded"] is None:
                    host["first_recorded"] = now
                if host["first_seen"] is None:
                    host["first_seen"] = now
                host.update(last_seen=now, last_seen_source="ICMP", last_ping_success=now, last_ping_ms=rtt)
            self._save(octet, host, live=success)
            if success:
                self._cleanup_old_addresses(now, settings, octet)

    def _cleanup_old_addresses(self, now, settings, current_octet=None):
        if not settings["auto_cleanup_old_addresses"]:
            return 0
        def online(host):
            return host["last_seen"] is not None and 0 <= now - host["last_seen"] <= settings["online_window"]
        active_hosts = self.hosts.values() if current_octet is None else [self.hosts[current_octet]]
        active_macs = {host["mac"] for host in active_hosts if host["mac"] and online(host)}
        stale = [n for n, host in self.hosts.items()
                 if host["mac"] in active_macs and host["first_recorded"] is not None and not online(host)]
        for octet in stale:
            self.delete(octet)
        return len(stale)

    def cleanup_old_addresses(self):
        with self.lock:
            return self._cleanup_old_addresses(time.time(), self.settings.snapshot())

    def set_flags(self, octet, values):
        check_octet(octet)
        if not isinstance(values, dict) or not values or set(values) - {"infrastructure", "reserved"}:
            raise ValueError("不支持的字段")
        if any(type(value) is not bool for value in values.values()):
            raise ValueError("标记必须为布尔值")
        with self.lock:
            host = dict(self.hosts[octet])
            host.update(values)
            self._save(octet, host)

    def _view(self, octet, settings):
        host = self.hosts[octet]
        note = self._device_note(host["mac"])
        return dict(host, **note, dhcp=settings["dhcp_start"] <= octet <= settings["dhcp_end"])

    def _cache_note(self, mac, value):
        self._note_cache[mac] = value
        self._note_cache.move_to_end(mac)
        if len(self._note_cache) > 254:
            self._note_cache.popitem(last=False)

    def _device_note(self, mac):
        if mac in self._note_cache:
            self._note_cache.move_to_end(mac)
            return self._note_cache[mac]
        value = {"note": "", "note_updated_at": None}
        if mac:
            row = self.connection.execute(
                "SELECT substr(note, 1, 201), CASE WHEN typeof(updated_at) IN ('real', 'integer') "
                "THEN updated_at ELSE NULL END FROM device_notes WHERE mac=?", (mac,)).fetchone()
            if row and valid_text(row[0], 200) and valid_number(row[1]):
                value = {"note": row[0], "note_updated_at": row[1]}
            self._cache_note(mac, value)
        return value

    def set_device_note(self, mac, note):
        mac = normalize_mac(mac)
        if not mac:
            raise ValueError("需要有效的设备 MAC 地址")
        if not valid_text(note, 200):
            raise ValueError("备注必须是最多 200 字的文本")
        note = note.strip()
        with self.lock:
            settings = self.settings.snapshot()
            previous = self._device_note(mac)
            if previous["note"] != note:
                updated_at = time.time()
                with self.connection:
                    if note:
                        self.connection.execute(
                            "INSERT INTO device_notes (mac, note, updated_at) VALUES (?, ?, ?) "
                            "ON CONFLICT(mac) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at",
                            (mac, note, updated_at),
                        )
                    else:
                        self.connection.execute("DELETE FROM device_notes WHERE mac=?", (mac,))
                self._cache_note(mac, {"note": note, "note_updated_at": updated_at if note else None})
                self.revision += 1
                for n, host in self.hosts.items():
                    if host["mac"] == mac:
                        self.changed[n] = self.revision
            return dict(mac=mac, revision=self.revision,
                        hosts=[self._view(n, settings) for n, host in self.hosts.items() if host["mac"] == mac],
                        **self._device_note(mac))

    def delete(self, octet):
        check_octet(octet)
        with self.lock:
            with self.connection:
                self.connection.execute("DELETE FROM hosts WHERE octet=?", (octet,))
                self.connection.execute("INSERT INTO tombstones (octet, deleted_at) VALUES (?, ?) "
                                        "ON CONFLICT(octet) DO UPDATE SET deleted_at=excluded.deleted_at", (octet, time.time()))
            self.deleted.add(octet)
            self.hosts[octet] = blank_host(octet)
            self.revision += 1
            self.changed[octet] = self.revision

    def clear_history(self, scope, expected_range=None):
        with self.lock:
            settings = self.settings.snapshot()
            if scope == "all":
                lower, upper = 1, 254
            elif scope == "dhcp":
                lower, upper = settings["dhcp_start"], settings["dhcp_end"]
                if expected_range is not None and expected_range != (lower, upper):
                    raise ValueError("DHCP 范围已更新，请重新确认清空范围")
            else:
                raise ValueError("清空范围无效")
            octets = list(range(lower, upper + 1))
            with self.connection:
                self.connection.execute("DELETE FROM hosts WHERE octet BETWEEN ? AND ?", (lower, upper))
                if scope == "all":
                    self.connection.execute("DELETE FROM device_notes")
                self.connection.executemany(
                    "INSERT INTO tombstones (octet, deleted_at) VALUES (?, ?) "
                    "ON CONFLICT(octet) DO UPDATE SET deleted_at=excluded.deleted_at",
                    [(octet, time.time()) for octet in octets],
                )
            self.deleted.update(octets)
            if scope == "all":
                self._note_cache.clear()
            self.revision += 1
            for octet in octets:
                self.hosts[octet] = blank_host(octet)
                self.changed[octet] = self.revision
        return {"scope": scope, "cleared": len(octets), "range": [lower, upper]}

    def snapshot(self, since=None, settings=None):
        with self.lock:
            settings = settings or self.settings.snapshot()
            full = since is None or since < 1 or since > self.revision
            hosts = [self._view(n, settings) for n in self.hosts if full or self.changed[n] > since]
            return {"revision": self.revision, "full": full, "hosts": hosts}

    def known_hosts(self):
        with self.lock:
            return [dict(host) for host in self.hosts.values() if host["first_recorded"] is not None]

    def get(self, octet):
        check_octet(octet)
        with self.lock:
            return self._view(octet, self.settings.snapshot())

    def close(self):
        with self.lock:
            try:
                self.connection.close()
            finally:
                if self._database_lock:
                    self._database_lock.close()
