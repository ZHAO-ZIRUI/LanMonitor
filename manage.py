#!/usr/bin/env python3
"""Start/stop the local server in the background without changing login items."""

import argparse
from contextlib import contextmanager
import fcntl
import http.client
import ipaddress
import json
import os
import signal
# fixed internal argv only; no shell execution.
import subprocess  # nosec B404
import sys
import time
import urllib.request
from pathlib import Path

from config import atomic_write_json, read_json_file

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app.py"
DATA = ROOT / "data"
PID_FILE = DATA / "server.pid"
CONFIG_FILE = DATA / "server.json"
DEFAULT_CONFIG = {"host": "127.0.0.1", "port": 25400}
MAX_STATE_BYTES = 2 * 1024 * 1024
# Wildcard input maps to a loopback URL for local health checks.
WILDCARD_HOST = "0.0.0.0"  # nosec B104


def validate_config(config):
    if not isinstance(config, dict) or set(config) != {"host", "port"}:
        raise ValueError("配置字段无效")
    host, port = config["host"], config["port"]
    if not isinstance(host, str):
        raise ValueError("监听地址无效")
    if host != "localhost":
        ipaddress.IPv4Address(host)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("端口必须在 1–65535 之间")
    return {"host": host, "port": port}


def load_config():
    try:
        return validate_config(read_json_file(CONFIG_FILE))
    except FileNotFoundError:
        return dict(DEFAULT_CONFIG)
    except (OSError, ValueError) as exc:
        raise RuntimeError("data/server.json 配置无效：" + str(exc)) from exc


@contextmanager
def management_lock():
    """Serialize the complete read/stop/start/save transaction across CLI runs.

    Keep the lock inode on disk: deleting it would let a concurrent command
    obtain a different lock while the first command still owns the old one.
    """
    DATA.mkdir(parents=True, exist_ok=True)
    with (DATA / "server.lock").open("a") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("另一个服务管理命令正在执行，请稍后重试") from exc
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def service_url(config):
    host = "127.0.0.1" if config["host"] == WILDCARD_HOST else config["host"]
    return "http://{}:{}".format(host, config["port"])


def _read_pid_record():
    try:
        record = read_json_file(PID_FILE, limit=4096)
    except FileNotFoundError:
        return None
    except ValueError:
        return None
    # Numeric PID files from earlier versions remain readable. New files also
    # record process birth time, so a reused PID does not become our process.
    if type(record) is int:
        record = {"pid": record}
    if not isinstance(record, dict) or type(record.get("pid")) is not int:
        return None
    if not 1 < record["pid"] <= 2 ** 31 - 1:
        return None
    if "started" in record and not isinstance(record["started"], str):
        return None
    if "command" in record and not isinstance(record["command"], str):
        return None
    return record


def _process_identity(pid):
    argv = ["/bin/ps", "-ww", "-p", str(pid), "-o", "lstart=", "-o", "command="]
    try:
        # fixed system utility and validated PID; shell is disabled.
        result = subprocess.run(argv, capture_output=True, text=True, timeout=2, shell=False)  # nosec B603
    except (OSError, subprocess.TimeoutExpired) as exc:
        # A lookup failure is not evidence that a recorded process has exited.
        raise RuntimeError("无法检查后台进程，请稍后重试") from exc
    if result.returncode != 0 or not result.stdout.strip():
        return None
    fields = result.stdout.strip().split(maxsplit=5)
    if len(fields) != 6:
        raise RuntimeError("无法识别后台进程状态")
    return {"pid": pid, "started": " ".join(fields[:5]), "command": fields[5]}


def _is_managed_command(command):
    # ps does not quote argv, so match the known executable and full script path
    # before parsing the only allowed remaining arguments. A substring match
    # could mistake an editor, grep, or another script for the managed server.
    resolved = Path(sys.executable).resolve()
    executables = {sys.executable, str(resolved)}
    # macOS framework launchers exec the bundled Python.app binary, so ps can
    # show a different path from sys.executable even for our own child.
    if sys.platform == "darwin":
        executables.add(str(resolved.parent.parent / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"))
    for executable in executables:
        prefix = executable + " -u " + str(APP) + " --host "
        if command.startswith(prefix):
            tail = command[len(prefix):].split()
            if len(tail) != 3 or tail[1] != "--port":
                return False
            try:
                validate_config({"host": tail[0], "port": int(tail[2])})
                return True
            except ValueError:
                return False
    return False


def managed_process():
    record = _read_pid_record()
    if record is None:
        return None
    identity = _process_identity(record["pid"])
    if identity is None or not _is_managed_command(identity["command"]):
        return None
    if any(record[key] != identity[key] for key in ("started", "command") if key in record):
        return None
    return identity


def managed_pid():
    identity = managed_process()
    return identity["pid"] if identity else None


def healthy(config):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(service_url(config) + "/api/state", timeout=0.5) as response:
            body = response.read(MAX_STATE_BYTES + 1)
        if len(body) > MAX_STATE_BYTES:
            return False
        payload = json.loads(body)
        return (isinstance(payload, dict) and payload.get("subnet") == "192.168.100.0/24"
                and isinstance(payload.get("hosts"), list) and len(payload["hosts"]) == 254)
    except (OSError, ValueError, RecursionError, http.client.HTTPException):
        return False


def _discard_pid(pid):
    record = _read_pid_record()
    if record is not None and record["pid"] == pid:
        PID_FILE.unlink(missing_ok=True)


def _abort_start(process):
    """Reap only the child created by this invocation, including on Ctrl-C."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as exc:
                # Retain the identity record if the OS has not reaped the child
                # yet (for example, a process stuck in uninterruptible I/O).
                raise RuntimeError("启动失败，后台进程尚未退出，请稍后检查状态") from exc
    _discard_pid(process.pid)


def start(config):
    config = validate_config(config)
    url = service_url(config)
    if healthy(config):
        print("服务已运行：" + url)
        return
    if managed_pid():
        raise RuntimeError("后台进程仍在运行；更换监听地址请使用 restart --host")
    DATA.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, LANMONITOR_MANAGED="1")
    argv = [sys.executable, "-u", str(APP), "--host", config["host"], "--port", str(config["port"])]
    # fixed interpreter/script and validated host/port; no shell.
    process = subprocess.Popen(argv, cwd=ROOT, shell=False,  # nosec B603
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True, env=environment)
    try:
        identity = _process_identity(process.pid)
        if identity is None or not _is_managed_command(identity["command"]):
            raise RuntimeError("启动失败，请查看 data/server.log（端口可能已被占用）")
        atomic_write_json(PID_FILE, identity)
        for _ in range(40):
            if process.poll() is not None:
                raise RuntimeError("启动失败，请查看 data/server.log（端口可能已被占用）")
            if healthy(config) and process.poll() is None:
                current = _process_identity(process.pid)
                if current is None or current["started"] != identity["started"] or not _is_managed_command(current["command"]):
                    raise RuntimeError("启动进程状态发生变化，请查看 data/server.log")
                # Refresh the command after interpreter launchers have exec'd.
                if current != identity:
                    atomic_write_json(PID_FILE, current)
                atomic_write_json(CONFIG_FILE, config)
                print("已启动：{}（PID {}）".format(url, process.pid))
                return
            time.sleep(0.1)
        raise RuntimeError("启动后未能响应，已停止后台进程，请查看 data/server.log")
    except BaseException:
        _abort_start(process)
        raise


def stop(config):
    identity = managed_process()
    if identity is None:
        if healthy(config):
            raise RuntimeError("服务由其他方式启动，请在其终端中停止")
        PID_FILE.unlink(missing_ok=True)
        print("服务未运行")
        return
    # Check the birth time again immediately before signaling; never signal a
    # newly observed replacement process just because its numeric PID matches.
    if _process_identity(identity["pid"]) == identity:
        try:
            os.kill(identity["pid"], signal.SIGTERM)
        except ProcessLookupError:
            pass
    for _ in range(80):
        if _process_identity(identity["pid"]) != identity:
            _discard_pid(identity["pid"])
            print("服务已停止，历史和标记已保留")
            return
        time.sleep(0.1)
    raise RuntimeError("服务正在关闭，请稍后检查状态")


def main():
    parser = argparse.ArgumentParser(description="Manage the local LAN Monitor at port 25400")
    parser.add_argument("command", choices=["start", "stop", "restart", "status"])
    parser.add_argument("--host", help="监听的 IPv4 地址；启动成功后保存，重启沿用")
    parser.add_argument("--port", type=int, help="监听端口；默认 25400")
    args = parser.parse_args()
    if args.command in ("stop", "status") and (args.host is not None or args.port is not None):
        parser.error("--host 和 --port 仅用于 start / restart")
    try:
        with management_lock():
            current = load_config()
            requested = validate_config({"host": args.host if args.host is not None else current["host"],
                                         "port": args.port if args.port is not None else current["port"]})
            if args.command == "restart":
                stop(current)
                start(requested)
            elif args.command == "start":
                start(requested)
            elif args.command == "stop":
                stop(current)
            else:
                print("运行中：" + service_url(current) if healthy(current) else "服务未响应")
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
