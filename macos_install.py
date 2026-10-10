#!/usr/bin/env python3
"""Transactional macOS installer; macos_install.zsh is the public entry point.

Only launchd owns the installed process. Releases are immutable, while every
release resolves data/ to the same directory (including SQLite's lock inode).
Keep OS operations behind Launchd so regression tests never touch real jobs.
"""

import argparse
from contextlib import contextmanager, closing
import fcntl
import grp
import http.client
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import socket
import sqlite3
import stat
# Fixed system utilities and explicit argv; never execute a shell.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
import uuid

LABEL = "io.github.zhao-zirui.lanmonitor"
INSTALL_ROOT = Path("/Library/Application Support/LanMonitor")
PLIST_PATH = Path("/Library/LaunchDaemons") / (LABEL + ".plist")
FILES = ("app.py", "config.py", "constants.py", "store.py", "scanner.py", "http_api.py",
         "README.md", "static/app.js", "static/index.html", "static/style.css", "static/favicon.svg")
MAX_FILE_BYTES = 2 * 1024 * 1024
# Only compared with input to choose a loopback health URL; not a default bind.
WILDCARD_HOST = "0.0.0.0"  # nosec B104


def read_regular(path, limit=MAX_FILE_BYTES):
    """Reject links/devices and cap reads, including user-owned migration files."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("需要普通文件：" + str(path))
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("文件过大：" + str(path))
    return payload


def atomic_write(path, payload, mode=0o644):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".install-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def file_lock(path):
    # Never remove this file: the inode is the cross-process exclusion boundary.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "a+b") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("锁文件无效：" + str(path))
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("文件正在使用，请先停止服务或等待另一次安装：" + str(path)) from exc
        yield stream


def validate_address(host, port):
    if not isinstance(host, str):
        raise ValueError("监听地址必须是 IPv4 字符串或 localhost")
    if host != "localhost":
        ipaddress.IPv4Address(host)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("端口必须在 1–65535 之间")
    return host, port


def port_available(host, port):
    # A pre-existing source checkout must not be mistaken for the new daemon.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as exc:
            raise RuntimeError("监听地址不可用或端口已占用；请先停止旧服务并确认本机地址") from exc


def make_plist(root, python, user, host, port):
    return {
        "Label": LABEL,
        "ProgramArguments": [str(python), "-I", "-B", str(root / "current" / "launch.py"),
                             str(root / "current" / "app.py"),
                             "--host", host, "--port", str(port)],
        "WorkingDirectory": str(root / "current"),
        "UserName": user.pw_name,
        "GroupName": grp.getgrgid(user.pw_gid).gr_name,
        "EnvironmentVariables": {"LANMONITOR_MANAGED": "1", "PYTHONUNBUFFERED": "1",
                                 "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ExitTimeOut": 30,
        "Umask": 0o077,
        # Runtime logging uses app.py's bounded rotating handler. launchd's
        # append-only stdout/stderr files would otherwise grow without limit.
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }


class Launchd:
    def run(self, arguments, check=True):
        # launchctl has bounded system-generated output for this one job.
        result = subprocess.run(["/bin/launchctl", *arguments], capture_output=True,  # nosec B603
                                text=True, timeout=40, check=False)
        if check and result.returncode:
            raise RuntimeError("launchctl 操作失败：" + result.stderr[:2000].strip())
        return result

    def state(self):
        result = self.run(["print", "system/" + LABEL], check=False)
        if result.returncode:
            if "Could not find service" in result.stderr:
                return None
            raise RuntimeError("无法确定 launchd 状态：" + result.stderr[:2000].strip())
        match = re.search(r"^\s*pid = (\d+)\s*$", result.stdout, re.MULTILINE)
        return int(match.group(1)) if match else 0

    def stop(self):
        if self.state() is not None:
            self.run(["bootout", "system/" + LABEL])

    def start(self, plist):
        self.run(["enable", "system/" + LABEL])
        self.run(["bootstrap", "system", str(plist)])

    def owns_listener(self, pid, port):
        # Do not accept a healthy source-checkout process that raced our bind
        # preflight. lsof is scoped to the exact launchd PID and listening port.
        argv = ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP:" + str(port), "-sTCP:LISTEN", "-Fn"]
        result = subprocess.run(argv, capture_output=True, timeout=2, check=False)  # nosec B603
        return result.returncode == 0 and b"\nn" in result.stdout

    def ready(self, host, port):
        # A wildcard listener is reachable through loopback for this local check.
        target = "127.0.0.1" if host == WILDCARD_HOST else host
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            pid = self.state()
            if pid and self.owns_listener(pid, port):
                connection = http.client.HTTPConnection(target, port, timeout=0.5)
                timer = None
                try:
                    connection.connect()
                    sock = connection.sock

                    def expire(sock=sock):
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

                    # Bound the entire headers+body exchange, including a peer
                    # sending bytes frequently enough to evade socket timeouts.
                    timer = threading.Timer(1, expire)
                    timer.daemon = True
                    timer.start()
                    connection.request("GET", "/api/state")
                    response = connection.getresponse()
                    body = response.read(MAX_FILE_BYTES + 1)
                    if response.status == 200 and len(body) <= MAX_FILE_BYTES:
                        state = json.loads(body)
                        if (isinstance(state, dict) and state.get("subnet") == "192.168.100.0/24"
                                and isinstance(state.get("hosts"), list) and len(state["hosts"]) == 254
                                and self.state() == pid):
                            return
                except (OSError, ValueError, RecursionError, http.client.HTTPException):
                    pass
                finally:
                    if timer is not None:
                        timer.cancel()
                        timer.join()
                    connection.close()
            time.sleep(0.2)
        raise RuntimeError("新服务未就绪，请查看安装目录 data/server.log")


class Installer:
    def __init__(self, source, root, plist, python, user, launchd=None):
        self.source, self.root, self.plist = source, root, plist
        self.python, self.user = python, user
        self.launchd = launchd if launchd is not None else Launchd()
        self.data = root / "data"
        self.releases = root / "releases"
        self.current = root / "current"

    def existing(self):
        if not self.plist.exists():
            if self.current.exists() or self.current.is_symlink():
                raise RuntimeError("安装状态不完整：current 存在但 plist 缺失")
            return None
        value = plistlib.loads(read_regular(self.plist, 65536))
        if (not isinstance(value, dict) or value.get("Label") != LABEL
                or value.get("UserName") != self.user.pw_name
                or value.get("WorkingDirectory") != str(self.current)):
            raise RuntimeError("已有服务配置不匹配；升级时必须沿用原服务用户与安装目录")
        args = value.get("ProgramArguments", [])
        if (not isinstance(args, list) or len(args) != 9 or not all(isinstance(arg, str) for arg in args)
                or args[1:4] != ["-I", "-B", str(self.current / "launch.py")]
                or args[4:6] != [str(self.current / "app.py"), "--host"] or args[7] != "--port"):
            raise RuntimeError("已有启动参数无效")
        validate_address(args[6], int(args[8]))
        self.current_release()
        return value

    def current_release(self):
        if not self.current.is_symlink():
            raise RuntimeError("current 必须是安装器创建的版本链接")
        target = os.readlink(self.current)
        if not re.fullmatch(r"releases/release-[a-f0-9]{32}", target):
            raise RuntimeError("版本链接无效")
        release = self.root / target
        if release.is_symlink() or not release.is_dir():
            raise RuntimeError("当前程序版本不存在或不安全")
        return release

    def prepare(self):
        release = self.releases / ("release-" + uuid.uuid4().hex)
        release.mkdir(mode=0o755)
        try:
            for name in FILES:
                src = self.source / name
                # Resolve only the known source root, never links within it.
                if src.parent != self.source and src.parent.is_symlink():
                    raise ValueError("源目录不能是符号链接：" + str(src.parent))
                payload = read_regular(src)
                destination = release / name
                destination.parent.mkdir(mode=0o755, exist_ok=True)
                atomic_write(destination, payload)
            (release / "data").symlink_to(self.data, target_is_directory=True)
            # -I omits the script directory. Use an isolated stdlib bootstrap
            # to insert only this immutable release before executing app.py.
            bootstrap = ("import runpy,sys; from pathlib import Path; "
                         "p=Path(sys.argv[1]).resolve(); sys.path.insert(0,str(p.parent)); "
                         "sys.argv=sys.argv[1:]; runpy.run_path(str(p),run_name='__main__')")
            atomic_write(release / "launch.py", bootstrap.encode("utf-8"))
            argv = ["/usr/bin/sudo", "-n", "-u", self.user.pw_name, "--", str(self.python),
                    "-I", "-B", str(release / "launch.py"), str(release / "app.py"), "--help"]
            # Run import/CLI checks as the service user, never run the daemon here.
            result = subprocess.run(argv, capture_output=True, timeout=15, check=False)  # nosec B603
            if result.returncode:
                raise RuntimeError("Python 或程序预检失败：" + result.stderr[:2000].decode("utf-8", "replace"))
            return release
        except BaseException:
            shutil.rmtree(release)
            raise

    def switch(self, release):
        temporary = self.root / (".current-" + uuid.uuid4().hex)
        try:
            temporary.symlink_to(release.relative_to(self.root), target_is_directory=True)
            os.replace(temporary, self.current)
        finally:
            temporary.unlink(missing_ok=True)

    def wait_stopped(self):
        # bootout can return before the old process has fully drained. Wait for
        # the real SQLite ownership lock; its path/inode survives every release.
        deadline = time.monotonic() + 35
        while True:
            try:
                with file_lock(self.data / "lanmonitor.sqlite3.lock") as stream:
                    os.fchown(stream.fileno(), self.user.pw_uid, self.user.pw_gid)
                    return
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("旧服务仍在关闭，安装中止；未切换程序") from None
                time.sleep(0.1)

    def import_data(self, source):
        if any(self.data.iterdir()):
            raise RuntimeError("导入要求目标 data 为空，已有数据不会被覆盖")
        database = source / "lanmonitor.sqlite3"
        if not database.is_file() or database.is_symlink():
            raise ValueError("导入目录缺少普通 SQLite 数据库")
        lock = source / "lanmonitor.sqlite3.lock"
        if not lock.is_file() or lock.is_symlink():
            raise ValueError("导入目录缺少数据库锁文件，请先正常运行并停止旧服务")
        # Copy a stopped database together with any remaining WAL into private
        # staging, then use SQLite backup. No SQLite access to source files: this
        # avoids creating root-owned SHM files in the user's original directory.
        with file_lock(lock), tempfile.TemporaryDirectory(dir=self.root, prefix=".migration-") as directory:
            stage = Path(directory)
            staged_data = stage / "data"
            staged_data.mkdir(mode=0o700)
            for suffix in ("", "-wal"):
                path = Path(str(database) + suffix)
                if path.exists():
                    # Historical notes can grow; bound migration to 256 MiB/file.
                    payload = read_regular(path, 256 * 1024 * 1024)
                    (stage / ("source.sqlite3" + suffix)).write_bytes(payload)
            with closing(sqlite3.connect(str(stage / "source.sqlite3"))) as source_db:
                with closing(sqlite3.connect(str(staged_data / "lanmonitor.sqlite3"))) as target_db:
                    deadline = time.monotonic() + 30

                    def progress(_status, _remaining, _total):
                        if time.monotonic() > deadline:
                            raise RuntimeError("数据库导入超时")
                    source_db.backup(target_db, pages=256, progress=progress)
                    target_db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                    if target_db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise ValueError("导入数据库损坏")
            for name in ("settings.json", "server.json"):
                path = source / name
                if path.exists():
                    payload = read_regular(path, 65536)
                    json.loads(payload)
                    (staged_data / name).write_bytes(payload)
            for name in ("lanmonitor.sqlite3", "settings.json", "server.json"):
                path = staged_data / name
                if path.exists():
                    os.chown(path, self.user.pw_uid, self.user.pw_gid)
                    path.chmod(0o600)
            os.chown(staged_data, self.user.pw_uid, self.user.pw_gid)
            # data is still empty and no daemon/DB lock has been created here.
            # A single rename publishes all imported files or leaves it empty.
            os.replace(staged_data, self.data)

    def install(self, host=None, port=None, import_source=None):
        with file_lock(self.root / ".install.lock"):
            old = self.existing()
            self.releases.mkdir(mode=0o755, exist_ok=True)
            self.data.mkdir(mode=0o700, exist_ok=True)
            if self.data.is_symlink() or self.releases.is_symlink():
                raise ValueError("安装子目录不能是符号链接")
            os.chown(self.data, self.user.pw_uid, self.user.pw_gid)
            if import_source is not None:
                if old:
                    raise RuntimeError("--import-data 仅用于首次安装")
                self.import_data(import_source)
            defaults = {"host": "127.0.0.1", "port": 25400}
            if old:
                defaults = {"host": old["ProgramArguments"][6], "port": int(old["ProgramArguments"][8])}
            elif (self.data / "server.json").exists():
                defaults = json.loads(read_regular(self.data / "server.json", 65536))
                if not isinstance(defaults, dict) or set(defaults) != {"host", "port"}:
                    raise ValueError("server.json 字段无效")
            host, port = validate_address(host if host is not None else defaults["host"],
                                          port if port is not None else defaults["port"])
            release = self.prepare()
            try:
                old_release = self.current_release() if old else None
                was_loaded = self.launchd.state() is not None
                if was_loaded and old is None:
                    raise RuntimeError("同名 launchd 服务已存在，无法确认归属")
                plist = make_plist(self.root, self.python, self.user, host, port)
            except BaseException:
                shutil.rmtree(release)
                raise
            changed = False
            new_attempted = False
            try:
                self.launchd.stop()
                self.wait_stopped()
                port_available(host, port)
                changed = True
                self.switch(release)
                atomic_write(self.plist, plistlib.dumps(plist))
                new_attempted = True
                self.launchd.start(self.plist)
                self.launchd.ready(host, port)
            except BaseException as original:
                try:
                    if new_attempted:
                        self.launchd.stop()
                        self.wait_stopped()
                    if changed:
                        if old_release:
                            self.switch(old_release)
                        else:
                            self.current.unlink(missing_ok=True)
                        if old:
                            atomic_write(self.plist, plistlib.dumps(old))
                        else:
                            self.plist.unlink(missing_ok=True)
                    if was_loaded and self.launchd.state() is None:
                        self.launchd.start(self.plist)
                except Exception as rollback:
                    # Do not delete potentially running code when shutdown or
                    # restoration failed. Preserve evidence and report both errors.
                    raise RuntimeError(f"安装失败：{original}；自动恢复失败：{rollback}") from original
                shutil.rmtree(release)
                raise
            # Retain at most the current and preceding versions. Never touch data.
            for path in self.releases.iterdir():
                if (path not in (release, old_release) and path.is_dir() and not path.is_symlink()
                        and re.fullmatch(r"release-[a-f0-9]{32}", path.name)):
                    shutil.rmtree(path)
            return host, port


def trusted_directory(path):
    """Validate the privileged destination chain before creating any files."""
    for parent in (*reversed(path.parents), path):
        if parent.is_symlink():
            raise ValueError("安装路径不能经过符号链接：" + str(parent))
        if parent.exists():
            info = parent.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("安装目录必须归 root 所有且不可由其他用户写入：" + str(parent))


def main(argv=None):
    parser = argparse.ArgumentParser(description="安装或升级 macOS LAN Monitor 系统服务")
    parser.add_argument("--python", help="稳定的 Python 3.9+ 绝对路径，由 zsh 入口选择")
    parser.add_argument("--user", default=os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name)
    parser.add_argument("--host", help="监听 IPv4 地址；首次默认 127.0.0.1，升级沿用")
    parser.add_argument("--port", type=int, help="监听端口；首次默认 25400，升级沿用")
    parser.add_argument("--import-data", type=Path, help="首次安装时导入已停止服务的数据目录")
    parser.add_argument("--dry-run", action="store_true", help="只检查并显示安装计划，不修改系统")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "darwin" or sys.version_info < (3, 9):
            raise RuntimeError("需要 macOS 和 Python 3.9+")
        user = pwd.getpwnam(args.user)
        if user.pw_uid == 0:
            raise ValueError("服务必须使用普通用户；请用 --user 指定")
        if args.host is not None or args.port is not None:
            validate_address(args.host if args.host is not None else "127.0.0.1",
                             args.port if args.port is not None else 25400)
        python = Path(sys.executable).absolute()
        source = Path(__file__).resolve().parent
        for name in FILES:
            read_regular(source / name)
        trusted_directory(INSTALL_ROOT)
        trusted_directory(INSTALL_ROOT / "releases")
        trusted_directory(PLIST_PATH.parent)
        installer = Installer(source, INSTALL_ROOT, PLIST_PATH, python, user)
        existing = installer.existing()
        if existing:
            trusted_directory(installer.current_release())
            info = PLIST_PATH.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("已有 plist 必须归 root 所有且不可由其他用户写入")
        if args.dry_run:
            print(f"程序：{INSTALL_ROOT}/current\n数据与轮转日志：{INSTALL_ROOT}/data\n"
                  f"系统服务：{PLIST_PATH}\n运行用户：{user.pw_name}\nPython：{python}\n"
                  "安装时会验证启动状态；升级失败自动恢复旧程序，数据保留。")
            return 0
        if os.geteuid() != 0:
            raise PermissionError("安装系统服务需要 sudo；可先使用 --dry-run 查看计划")
        os.umask(0o022)
        INSTALL_ROOT.mkdir(parents=True, mode=0o755, exist_ok=True)
        host, port = installer.install(args.host, args.port,
                                       args.import_data.resolve() if args.import_data else None)
        print(f"已安装并启动：http://{host}:{port}\n数据与轮转日志：{installer.data}")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error,
            subprocess.SubprocessError, RecursionError) as exc:
        print("安装失败：" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
