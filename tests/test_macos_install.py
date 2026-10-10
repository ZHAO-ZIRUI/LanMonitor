"""macOS installation transactions, using only private files and fake services."""

from contextlib import closing
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import macos_install as install


class FakeLaunchd:
    """Record service transitions without launching or querying any process."""

    def __init__(self):
        self.loaded = False
        self.events = []
        self.started = []
        self.ready_error = None

    def state(self):
        self.events.append("state")
        return 12345 if self.loaded else None

    def stop(self):
        self.events.append("stop")
        self.loaded = False

    def start(self, path):
        self.events.append("start")
        self.started.append(plistlib.loads(path.read_bytes()))
        self.loaded = True

    def ready(self, host, port):
        self.events.append(("ready", host, port))
        if self.ready_error is not None:
            raise self.ready_error


class InstallerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lanmonitor-install-tests-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.source = self.directory / "源码 带空格"
        self.source.mkdir()
        for name in install.FILES:
            path = self.source / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b"# source fixture\n")
        self.root = self.directory / "Application Support" / "测试 LanMonitor"
        self.root.mkdir(parents=True)
        self.plist = self.directory / "Launch Daemons" / "lanmonitor.plist"
        self.plist.parent.mkdir()
        self.user = SimpleNamespace(pw_name="fixture-user", pw_uid=os.getuid() or 501, pw_gid=os.getgid())
        self.python = self.directory / "Python 安装" / "bin" / "python3"
        self.launchd = FakeLaunchd()
        self.installer = install.Installer(self.source, self.root, self.plist, self.python,
                                           self.user, self.launchd)
        for name in ("chown", "fchown"):
            patcher = mock.patch.object(install.os, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        self.run_process = install.subprocess.run
        patcher = mock.patch.object(install.subprocess, "run",
                                    return_value=SimpleNamespace(returncode=0, stderr=b""))
        self.preflight = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(install, "port_available")
        self.port_available = patcher.start()
        self.addCleanup(patcher.stop)

    def install_initial(self):
        self.assertEqual(self.installer.install(), ("127.0.0.1", 25400))
        return self.installer.current_release()

    def test_first_install_has_unprivileged_isolated_argv_and_private_data(self):
        release = self.install_initial()
        plist = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(plist["ProgramArguments"], [str(self.python), "-I", "-B",
                         str(self.root / "current" / "launch.py"),
                         str(self.root / "current" / "app.py"), "--host", "127.0.0.1", "--port", "25400"])
        self.assertEqual(plist["UserName"], self.user.pw_name)
        self.assertNotEqual(plist["UserName"], "root")
        self.assertEqual(plist["WorkingDirectory"], str(self.root / "current"))
        self.assertEqual(plist["Umask"], 0o077)
        self.assertTrue(plist["RunAtLoad"])
        self.assertTrue(plist["KeepAlive"])
        self.assertGreaterEqual(plist["ThrottleInterval"], 10)
        self.assertEqual(plist["StandardOutPath"], "/dev/null")
        self.assertEqual(plist["StandardErrorPath"], "/dev/null")
        self.assertEqual(plist["EnvironmentVariables"]["LANMONITOR_MANAGED"], "1")
        self.assertEqual(stat.S_IMODE(self.plist.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.installer.data.stat().st_mode), 0o700)
        self.assertEqual((release / "data").resolve(), self.installer.data.resolve())
        self.assertEqual(stat.S_IMODE((release / "app.py").stat().st_mode), 0o644)
        self.chown.assert_any_call(self.installer.data, self.user.pw_uid, self.user.pw_gid)
        self.fchown.assert_called()
        self.assertEqual(self.fchown.call_args.args[1:], (self.user.pw_uid, self.user.pw_gid))
        argv = self.preflight.call_args.args[0]
        self.assertEqual(argv[:6], ["/usr/bin/sudo", "-n", "-u", self.user.pw_name, "--", str(self.python)])
        self.assertEqual(argv[-1], "--help")
        self.assertEqual(self.preflight.call_args.kwargs["timeout"], 15)
        self.assertTrue(self.launchd.loaded)

    def test_three_installs_keep_data_lock_inode_and_only_two_releases(self):
        first = self.install_initial()
        data = self.installer.data
        marker = data / "settings.json"
        marker.write_bytes(b'{"fixture": "unchanged"}')
        lock = data / "lanmonitor.sqlite3.lock"
        inode = lock.stat().st_ino
        (self.source / "app.py").write_bytes(b"# second revision\n")
        self.installer.install(host="192.168.100.25", port=25401)
        second = self.installer.current_release()
        (self.source / "app.py").write_bytes(b"# third revision\n")
        self.assertEqual(self.installer.install(), ("192.168.100.25", 25401))
        third = self.installer.current_release()
        self.assertEqual(set(self.installer.releases.iterdir()), {second, third})
        self.assertFalse(first.exists())
        self.assertNotEqual(second, third)
        self.assertEqual(marker.read_bytes(), b'{"fixture": "unchanged"}')
        self.assertEqual(lock.stat().st_ino, inode)
        self.assertEqual((third / "data").resolve(), data.resolve())
        self.assertEqual(self.launchd.started[-1]["ProgramArguments"][-4:],
                         ["--host", "192.168.100.25", "--port", "25401"])

    def test_failed_upgrade_restores_previous_release_plist_and_loaded_service(self):
        old_release = self.install_initial()
        old_plist = self.plist.read_bytes()
        self.launchd.events.clear()
        self.launchd.ready_error = RuntimeError("fixture startup failure")
        with self.assertRaisesRegex(RuntimeError, "fixture startup failure"):
            self.installer.install(host="127.0.0.1", port=25402)
        self.assertEqual(self.installer.current_release(), old_release)
        self.assertEqual(self.plist.read_bytes(), old_plist)
        self.assertEqual(set(self.installer.releases.iterdir()), {old_release})
        self.assertTrue(self.launchd.loaded)
        self.assertEqual(self.launchd.events.count("stop"), 2)
        self.assertEqual(self.launchd.events.count("start"), 2)
        self.assertEqual(self.launchd.started[-1], plistlib.loads(old_plist))

    def test_first_start_failure_removes_job_and_current_but_preserves_data(self):
        self.installer.data.mkdir()
        marker = self.installer.data / "notes-fixture"
        marker.write_bytes(b"preserve on failed first start")
        self.launchd.ready_error = RuntimeError("fixture first start failure")
        with self.assertRaisesRegex(RuntimeError, "fixture first start failure"):
            self.installer.install()
        self.assertFalse(self.launchd.loaded)
        self.assertFalse(self.installer.current.is_symlink())
        self.assertFalse(self.plist.exists())
        self.assertEqual(list(self.installer.releases.iterdir()), [])
        self.assertEqual(marker.read_bytes(), b"preserve on failed first start")
        self.assertTrue((self.installer.data / "lanmonitor.sqlite3.lock").is_file())

    def test_occupied_port_never_reports_new_service_ready_and_restores_old_service(self):
        old_release = self.install_initial()
        old_plist = self.plist.read_bytes()
        self.launchd.events.clear()
        self.port_available.side_effect = RuntimeError("fixture port occupied")
        with self.assertRaisesRegex(RuntimeError, "fixture port occupied"):
            self.installer.install()
        self.assertEqual(self.installer.current_release(), old_release)
        self.assertEqual(self.plist.read_bytes(), old_plist)
        self.assertEqual(set(self.installer.releases.iterdir()), {old_release})
        self.assertTrue(self.launchd.loaded)
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "ready"
                             for event in self.launchd.events))

    def test_upgrade_with_different_user_cannot_change_data_ownership(self):
        old_release = self.install_initial()
        self.launchd.events.clear()
        self.chown.reset_mock()
        self.fchown.reset_mock()
        self.installer.user = SimpleNamespace(pw_name="another-fixture-user", pw_uid=self.user.pw_uid + 1,
                                             pw_gid=os.getgid())
        with self.assertRaisesRegex(RuntimeError, "原服务用户"):
            self.installer.install()
        self.chown.assert_not_called()
        self.fchown.assert_not_called()
        self.assertEqual(self.launchd.events, [])
        self.assertTrue(self.launchd.loaded)
        self.assertEqual(self.installer.current_release(), old_release)

    def test_real_source_preflight_imports_in_isolated_python_without_starting_service(self):
        real_source = Path(install.__file__).resolve().parent
        for name in install.FILES:
            (self.source / name).write_bytes(install.read_regular(real_source / name))
        self.installer.python = Path(install.sys.executable)

        def preflight(argv, **kwargs):
            self.assertEqual(argv[:5], ["/usr/bin/sudo", "-n", "-u", self.user.pw_name, "--"])
            self.assertEqual(argv[-1], "--help")
            # Only this test-owned child runs: argparse exits before constructing
            # a scanner, HTTP listener or database. Every path is inside the fixture.
            result = self.run_process(argv[5:], env=dict(os.environ, LANMONITOR_MANAGED="1"), **kwargs)
            self.assertIn(b"--no-scan", result.stdout)
            return result

        self.preflight.side_effect = preflight
        self.install_initial()
        self.assertFalse((self.installer.data / "lanmonitor.sqlite3").exists())
        self.assertTrue((self.installer.data / "server.log").is_file())

    def test_missing_source_does_not_stop_existing_service(self):
        old_release = self.install_initial()
        self.launchd.events.clear()
        (self.source / "scanner.py").unlink()
        with self.assertRaises(FileNotFoundError):
            self.installer.install()
        self.assertEqual(self.launchd.events, [])
        self.assertTrue(self.launchd.loaded)
        self.assertEqual(self.installer.current_release(), old_release)
        self.assertEqual(set(self.installer.releases.iterdir()), {old_release})

    def test_preflight_import_failure_does_not_stop_existing_service(self):
        old_release = self.install_initial()
        self.launchd.events.clear()
        self.preflight.return_value = SimpleNamespace(returncode=1, stderr=b"fixture import failed")
        with self.assertRaisesRegex(RuntimeError, "fixture import failed"):
            self.installer.install()
        self.assertEqual(self.launchd.events, [])
        self.assertTrue(self.launchd.loaded)
        self.assertEqual(set(self.installer.releases.iterdir()), {old_release})

    def test_installer_lock_prevents_concurrent_transaction(self):
        with install.file_lock(self.root / ".install.lock"):
            with self.assertRaisesRegex(RuntimeError, "文件正在使用"):
                self.installer.install()
        self.assertEqual(self.launchd.events, [])
        self.preflight.assert_not_called()
        self.assertFalse(self.plist.exists())

    def test_existing_foreign_launchd_job_is_never_stopped(self):
        self.launchd.loaded = True
        with self.assertRaisesRegex(RuntimeError, "同名 launchd 服务已存在"):
            self.installer.install()
        self.assertEqual(self.launchd.events, ["state"])
        self.assertTrue(self.launchd.loaded)
        self.assertFalse(self.installer.current.is_symlink())
        self.assertFalse(self.plist.exists())
        self.assertEqual(list(self.installer.releases.iterdir()), [])

    def test_rollback_shutdown_failure_keeps_potentially_running_release(self):
        old_release = self.install_initial()
        self.launchd.ready_error = RuntimeError("fixture startup failure")
        with mock.patch.object(self.launchd, "stop", side_effect=[None, RuntimeError("fixture stop failed")]):
            with self.assertRaisesRegex(RuntimeError, "自动恢复失败.*fixture stop failed"):
                self.installer.install()
        new_release = self.installer.current_release()
        self.assertNotEqual(new_release, old_release)
        self.assertEqual(set(self.installer.releases.iterdir()), {old_release, new_release})
        self.assertTrue((new_release / "app.py").is_file())

    def test_wait_stopped_times_out_while_database_lock_is_owned(self):
        self.installer.data.mkdir()
        lock = self.installer.data / "lanmonitor.sqlite3.lock"
        with install.file_lock(lock), mock.patch.object(install.time, "monotonic", side_effect=[0, 36]):
            with self.assertRaisesRegex(RuntimeError, "旧服务仍在关闭"):
                self.installer.wait_stopped()
        self.assertTrue(lock.exists())
        self.fchown.assert_not_called()

    def test_wait_stopped_repairs_root_owned_sqlite_files_under_database_lock(self):
        self.installer.data.mkdir()
        lock = self.installer.data / "lanmonitor.sqlite3.lock"
        lock.touch()
        lock_inode = lock.stat().st_ino
        files = {}
        for suffix in ("", "-wal", "-shm"):
            path = self.installer.data / ("lanmonitor.sqlite3" + suffix)
            path.write_bytes(b"preserved database bytes")
            path.chmod(0o644)
            files[path.stat().st_ino] = path
        original_fstat = install.os.fstat
        owners = {}
        modes = {}

        def root_owned_stat(fd):
            result = original_fstat(fd)
            if result.st_ino in files:
                fields = list(result)
                fields[4] = 0  # Simulate root ownership without changing real owners.
                return os.stat_result(fields)
            return result

        def change_owner(fd, uid, gid):
            path = files.get(original_fstat(fd).st_ino)
            if path is not None:
                with self.assertRaisesRegex(RuntimeError, "文件正在使用"):
                    with install.file_lock(lock):
                        self.fail("SQLite ownership changed without the database lock")
                owners[path.name] = (uid, gid)

        def change_mode(fd, mode):
            path = files.get(original_fstat(fd).st_ino)
            if path is not None:
                modes[path.name] = mode

        self.fchown.side_effect = change_owner
        with mock.patch.object(install.os, "fstat", side_effect=root_owned_stat), \
                mock.patch.object(install.os, "fchmod", side_effect=change_mode):
            self.installer.wait_stopped()
        self.assertEqual(owners, {path.name: (self.user.pw_uid, self.user.pw_gid)
                                  for path in files.values()})
        self.assertEqual(modes, {path.name: 0o600 for path in files.values()})
        self.assertEqual(lock.stat().st_ino, lock_inode)
        for inode, path in files.items():
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(path.read_bytes(), b"preserved database bytes")

    def test_wait_stopped_refuses_sqlite_files_owned_by_another_user(self):
        self.installer.data.mkdir()
        database = self.installer.data / "lanmonitor.sqlite3"
        database.write_bytes(b"another user's database")
        inode = database.stat().st_ino
        original_fstat = install.os.fstat
        changed_inodes = []

        def foreign_owned_stat(fd):
            result = original_fstat(fd)
            if result.st_ino == inode:
                fields = list(result)
                fields[4] = self.user.pw_uid + 1000
                return os.stat_result(fields)
            return result

        self.fchown.side_effect = lambda fd, _uid, _gid: changed_inodes.append(original_fstat(fd).st_ino)
        with mock.patch.object(install.os, "fstat", side_effect=foreign_owned_stat):
            with self.assertRaises(PermissionError):
                self.installer.wait_stopped()
        self.assertNotIn(inode, changed_inodes)
        self.assertEqual(database.read_bytes(), b"another user's database")

    def migration_source(self):
        source = self.directory / "旧 data 空格"
        source.mkdir()
        (source / "lanmonitor.sqlite3.lock").touch()
        with closing(sqlite3.connect(str(source / "lanmonitor.sqlite3"))) as connection:
            connection.execute("CREATE TABLE fixture_notes (note TEXT NOT NULL)")
            connection.commit()
        return source

    def test_import_refuses_active_source_lock_before_reading_database(self):
        source = self.migration_source()
        with install.file_lock(source / "lanmonitor.sqlite3.lock"):
            with self.assertRaisesRegex(RuntimeError, "文件正在使用"):
                self.installer.install(import_source=source)
        self.assertEqual(list(self.installer.data.iterdir()), [])
        self.assertEqual(self.launchd.events, [])
        self.preflight.assert_not_called()

    def test_import_reads_wal_preserves_settings_and_never_modifies_source(self):
        source = self.migration_source()
        database = source / "lanmonitor.sqlite3"
        settings = '{"arp_enabled": true, "custom_note": "测试备注"}'.encode("utf-8")
        server = b'{"host": "127.0.0.1", "port": 25403}'
        (source / "settings.json").write_bytes(settings)
        (source / "server.json").write_bytes(server)
        with closing(sqlite3.connect(str(database))) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("INSERT INTO fixture_notes VALUES (?)", ("WAL 中的备注",))
            connection.commit()
            wal = Path(str(database) + "-wal")
            self.assertGreater(wal.stat().st_size, 0)
            before = {path.name: path.read_bytes() for path in source.iterdir()}
            self.assertEqual(self.installer.install(import_source=source), ("127.0.0.1", 25403))
            self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, before)
        copied = self.installer.data / "lanmonitor.sqlite3"
        with closing(sqlite3.connect(str(copied))) as copied_db:
            self.assertEqual(copied_db.execute("SELECT note FROM fixture_notes").fetchall(),
                             [("WAL 中的备注",)])
        self.assertEqual((self.installer.data / "settings.json").read_bytes(), settings)
        self.assertEqual((self.installer.data / "server.json").read_bytes(), server)
        for name in ("lanmonitor.sqlite3", "settings.json", "server.json"):
            self.assertEqual(stat.S_IMODE((self.installer.data / name).stat().st_mode), 0o600)
        self.assertFalse(any(path.name.startswith(".migration-") for path in self.root.iterdir()))

    def test_import_never_overwrites_existing_destination_data(self):
        source = self.migration_source()
        self.installer.data.mkdir()
        marker = self.installer.data / "settings.json"
        marker.write_bytes(b"existing settings")
        with self.assertRaisesRegex(RuntimeError, "已有数据不会被覆盖"):
            self.installer.install(import_source=source)
        self.assertEqual(marker.read_bytes(), b"existing settings")
        self.assertEqual(self.launchd.events, [])
        self.preflight.assert_not_called()

    def test_wal_import_publishes_only_service_owned_files_before_first_open(self):
        source = self.migration_source()
        (source / "settings.json").write_bytes(b'{"arp_enabled": true}')
        (source / "server.json").write_bytes(b'{"host": "127.0.0.1", "port": 25400}')
        self.installer.data.mkdir()
        original_replace = install.os.replace
        publications = []

        def inspect_publish(staged, destination):
            if Path(destination) == self.installer.data:
                # Opening the destination first may let SQLite clean up WAL/SHM
                # and hide root-owned sidecars left by a privileged installer.
                files = list(Path(staged).iterdir())
                self.assertEqual({path.name for path in files},
                                 {"lanmonitor.sqlite3", "settings.json", "server.json"})
                for path in files:
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    self.chown.assert_any_call(path, self.user.pw_uid, self.user.pw_gid)
                publications.append(Path(destination))
            return original_replace(staged, destination)

        database = source / "lanmonitor.sqlite3"
        with closing(sqlite3.connect(str(database))) as source_db:
            source_db.execute("PRAGMA journal_mode=WAL")
            source_db.execute("PRAGMA wal_autocheckpoint=0")
            source_db.execute("INSERT INTO fixture_notes VALUES (?)", ("pending WAL note",))
            source_db.commit()
            self.assertGreater(Path(str(database) + "-wal").stat().st_size, 0)
            with mock.patch.object(install.os, "replace", side_effect=inspect_publish):
                self.installer.import_data(source)
        self.assertEqual(publications, [self.installer.data])
        with closing(sqlite3.connect(str(self.installer.data / "lanmonitor.sqlite3"))) as target_db:
            self.assertEqual(target_db.execute("PRAGMA journal_mode").fetchone(), ("delete",))
            self.assertEqual(target_db.execute("SELECT note FROM fixture_notes").fetchall(),
                             [("pending WAL note",)])
            self.assertEqual(target_db.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            target_db.execute("INSERT INTO fixture_notes VALUES (?)", ("service write",))
            target_db.commit()
            self.assertEqual(target_db.execute("SELECT count(*) FROM fixture_notes").fetchone(), (2,))

    def test_import_publish_failure_leaves_empty_destination_and_can_retry(self):
        source = self.migration_source()
        (source / "settings.json").write_bytes(b'{"arp_enabled": true}')
        original_replace = install.os.replace

        def fail_data_publish(source_path, destination):
            if Path(destination) == self.installer.data:
                raise OSError("fixture publish failure")
            return original_replace(source_path, destination)

        with mock.patch.object(install.os, "replace", side_effect=fail_data_publish):
            with self.assertRaisesRegex(OSError, "fixture publish failure"):
                self.installer.install(import_source=source)
        self.assertEqual(list(self.installer.data.iterdir()), [])
        self.assertEqual(self.launchd.events, [])
        self.assertFalse(any(path.name.startswith(".migration-") for path in self.root.iterdir()))
        self.assertEqual(self.installer.install(import_source=source), ("127.0.0.1", 25400))
        self.assertEqual((self.installer.data / "settings.json").read_bytes(), b'{"arp_enabled": true}')
        self.assertTrue((self.installer.data / "lanmonitor.sqlite3").is_file())

    def test_invalid_import_settings_leave_destination_empty(self):
        source = self.migration_source()
        (source / "settings.json").write_bytes(b"{broken")
        with self.assertRaises(ValueError):
            self.installer.install(import_source=source)
        self.assertEqual(list(self.installer.data.iterdir()), [])
        self.assertFalse(any(path.name.startswith(".migration-") for path in self.root.iterdir()))
        self.assertEqual(self.launchd.events, [])


class InstallerSafetyTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(install.subprocess, "run",
                                    side_effect=AssertionError("Unexpected real system command in an isolated test"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_persisted_listener_configuration_rejects_non_string_hosts_and_invalid_ports(self):
        for host, port in ((123, 25400), (None, 25400), (True, 25400),
                           ("127.0.0.1", True), ("127.0.0.1", 0), ("127.0.0.1", 65536)):
            with self.subTest(host=host, port=port), self.assertRaises(ValueError):
                install.validate_address(host, port)

    def test_file_lock_keeps_inode_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with install.file_lock(path):
                inode = path.stat().st_ino
                with self.assertRaises(RuntimeError):
                    with install.file_lock(path):
                        self.fail("A second owner acquired the same lock")
            with install.file_lock(path):
                self.assertEqual(path.stat().st_ino, inode)
            linked = Path(directory) / "linked"
            linked.symlink_to(path)
            with self.assertRaises(OSError):
                with install.file_lock(linked):
                    self.fail("A symlink lock must not be accepted")

    def test_bounded_regular_reads_reject_links_and_oversize_files(self):
        with tempfile.TemporaryDirectory() as directory:
            regular = Path(directory) / "fixture"
            regular.write_bytes(b"12345")
            self.assertEqual(install.read_regular(regular, 5), b"12345")
            with self.assertRaisesRegex(ValueError, "文件过大"):
                install.read_regular(regular, 4)
            linked = Path(directory) / "linked"
            linked.symlink_to(regular)
            with self.assertRaises(OSError):
                install.read_regular(linked)

    def test_port_probe_reports_occupied_address_without_network_traffic(self):
        with mock.patch.object(install.socket, "socket") as socket_factory:
            probe = socket_factory.return_value.__enter__.return_value
            probe.bind.side_effect = OSError("fixture occupied")
            with self.assertRaisesRegex(RuntimeError, "端口已占用"):
                install.port_available("127.0.0.1", 25400)
            probe.bind.assert_called_once_with(("127.0.0.1", 25400))
            probe.connect.assert_not_called()

    def test_ready_rejects_service_restart_during_http_response(self):
        daemon = install.Launchd()
        response = mock.Mock(status=200)
        response.read.return_value = json.dumps({"subnet": "192.168.100.0/24", "hosts": [{}] * 254}).encode()
        with mock.patch.object(daemon, "state", side_effect=[123, 456]), \
                mock.patch.object(daemon, "owns_listener", return_value=True), \
                mock.patch.object(install.threading, "Timer"), \
                mock.patch.object(install.http.client, "HTTPConnection") as http, \
                mock.patch.object(install.time, "monotonic", side_effect=[0, 0, 16]), \
                mock.patch.object(install.time, "sleep"):
            http.return_value.getresponse.return_value = response
            with self.assertRaisesRegex(RuntimeError, "新服务未就绪"):
                daemon.ready("127.0.0.1", 25400)
            http.return_value.close.assert_called_once()
            response.read.assert_called_once_with(install.MAX_FILE_BYTES + 1)

    def test_ready_does_not_accept_http_from_another_process(self):
        daemon = install.Launchd()
        with mock.patch.object(daemon, "state", return_value=123), \
                mock.patch.object(daemon, "owns_listener", return_value=False), \
                mock.patch.object(install.http.client, "HTTPConnection") as http, \
                mock.patch.object(install.time, "monotonic", side_effect=[0, 0, 16]), \
                mock.patch.object(install.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "新服务未就绪"):
                daemon.ready("127.0.0.1", 25400)
            http.assert_not_called()

    def test_launchctl_failure_does_not_guess_that_job_is_absent(self):
        daemon = install.Launchd()
        with mock.patch.object(daemon, "run", return_value=SimpleNamespace(returncode=1,
                               stderr="fixture permission denied", stdout="")):
            with self.assertRaisesRegex(RuntimeError, "无法确定 launchd 状态"):
                daemon.state()
        with mock.patch.object(daemon, "run", return_value=SimpleNamespace(returncode=113,
                               stderr="Could not find service", stdout="")):
            self.assertIsNone(daemon.state())


if __name__ == "__main__":
    unittest.main()
