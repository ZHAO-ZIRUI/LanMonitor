"""Validated, persistent settings shared by the collector and web interface."""

import json
import os
import tempfile
import threading
import time
from pathlib import Path

DEFAULT_SETTINGS = {
    "scan_enabled": True,
    "ping_enabled": True,
    "probe_rate": 4,
    "passive_interval": 12,
    "name_lookup": True,
    "name_interval": 12,
    "arp_enabled": True,
    "online_window": 90,
    "dhcp_start": 5,
    "dhcp_end": 99,
    "refresh_interval": 2,
    "show_hostnames": True,
    "auto_cleanup_old_addresses": True,
}

LIMITS = {
    "probe_rate": (1, 4, "每秒探测次数"),
    "passive_interval": (10, 120, "记录读取间隔"),
    "name_interval": (12, 120, "名称查询间隔"),
    "online_window": (30, 600, "在线判定时间"),
    "dhcp_start": (1, 254, "DHCP 起始地址"),
    "dhcp_end": (1, 254, "DHCP 结束地址"),
    "refresh_interval": (1, 30, "页面刷新间隔"),
}

MAX_CONFIG_BYTES = 64 * 1024


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("配置字段重复：" + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("配置数值无效：" + value)


def read_json_file(path, limit=MAX_CONFIG_BYTES):
    """Read small control files with bounded memory and strict JSON semantics."""
    with Path(path).open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("配置文件过大")
    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except RecursionError as exc:
        raise ValueError("配置嵌套过深") from exc


def atomic_write_json(path, values):
    """Replace a file only after its complete UTF-8 payload has reached disk.

    Each writer owns its temporary file; a failed write leaves the previous
    file and in-memory settings untouched. Callers provide their own locking.
    """
    path = Path(path)
    payload = json.dumps(values, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="." + path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_settings(values):
    if not isinstance(values, dict) or set(values) != set(DEFAULT_SETTINGS):
        raise ValueError("配置字段无效")
    for key, value in values.items():
        if key in LIMITS:
            lower, upper, label = LIMITS[key]
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("{}必须在 {}–{} 之间".format(label, lower, upper))
        elif type(value) is not bool:
            raise ValueError("开关必须为布尔值")
    if values["dhcp_start"] > values["dhcp_end"]:
        raise ValueError("DHCP 起始地址不能大于结束地址")
    return dict(values)


class Settings:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        # The store shares this lock so settings and dependent mutations have
        # a single lock order and return consistent snapshots.
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        values = dict(DEFAULT_SETTINGS)
        missing = False
        migrated = False
        if self.path:
            try:
                saved = read_json_file(self.path)
                if not isinstance(saved, dict):
                    raise ValueError("配置格式无效")
                # This one-time disk migration keeps the current update schema
                # strict, including requests from pages opened before upgrading.
                if "surge_enabled" in saved:
                    if type(saved["surge_enabled"]) is not bool:
                        raise ValueError("开关必须为布尔值")
                    del saved["surge_enabled"]
                    migrated = True
                values.update(saved)
                validate_settings(values)
            except FileNotFoundError:
                missing = True
            except (OSError, ValueError) as exc:
                raise ValueError("设置文件无效：" + str(exc)) from exc
        self.values = values
        self.revision = int(time.time() * 1000)
        if self.path and (missing or migrated):
            self._write(values)

    def _write(self, values):
        atomic_write_json(self.path, values)

    def snapshot(self):
        with self.condition:
            return dict(self.values)

    def export(self):
        with self.condition:
            return {"settings": dict(self.values), "settings_revision": self.revision}

    def update(self, changes, persist=True):
        if not isinstance(changes, dict) or not changes or set(changes) - set(DEFAULT_SETTINGS):
            raise ValueError("配置字段无效")
        with self.condition:
            values = validate_settings(dict(self.values, **changes))
            if persist and self.path:
                self._write(values)
            if values != self.values:
                self.values = values
                self.revision = max(self.revision + 1, int(time.time() * 1000))
                self.condition.notify_all()
            return self.export()

    def wait(self, stop_event, timeout, revision):
        with self.condition:
            self.condition.wait_for(lambda: stop_event.is_set() or self.revision != revision, timeout)

    def wake(self):
        with self.condition:
            self.condition.notify_all()
