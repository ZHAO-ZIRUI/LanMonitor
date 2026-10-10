"""HTTP transport with bounded connections and atomic mutation responses."""

import json
import re
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from constants import LOG, ROOT, SUBNET


class BoundedHTTPServer(ThreadingHTTPServer):
    """Bound worker count and connection lifetime, including slow header/body reads."""

    daemon_threads = False
    block_on_close = True

    def __init__(self, server_address, handler, max_workers=32, request_timeout=5.0):
        if type(max_workers) is not int or not 1 <= max_workers <= 256:
            raise ValueError("max_workers must be between 1 and 256")
        if not isinstance(request_timeout, (int, float)) or not 0 < request_timeout <= 60:
            raise ValueError("request_timeout must be between 0 and 60 seconds")
        self.request_timeout = request_timeout
        self._slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(0.1)
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        # A socket timeout alone permits a client to keep a worker forever by
        # sending one byte at a time. This deadline bounds the whole connection.
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline = threading.Timer(self.request_timeout, expire)
        deadline.daemon = True
        try:
            deadline.start()
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._slots.release()


def _authority(value):
    """Parse an HTTP authority without accepting userinfo, paths or ambiguity."""
    if not isinstance(value, str) or not re.fullmatch(r"(?:\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+)(?::[0-9]{1,5})?", value):
        raise ValueError("请求主机无效")
    parsed = urlsplit("http://" + value)
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("请求端口无效")
    return parsed.hostname, port or 80


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON 字段重复")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("JSON 数值无效")


def make_handler(store, scanner, port, bind_host):
    allowed_hosts = {"localhost", "127.0.0.1", "::1", "192.168.100.254", bind_host.lower()}

    class Handler(BaseHTTPRequestHandler):
        server_version = "LanMonitor/1.0"

        def log_message(self, fmt, *args):
            LOG.debug("%s " + fmt, self.address_string(), *args)

        def handle(self):
            try:
                super().handle()
            except (OSError, TimeoutError):
                # Disconnected and expired clients are normal transport events.
                pass

        def send_body(self, status, body, content_type="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def json_response(self, status, data):
            self.send_body(status, json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8"))

        def check_host(self):
            try:
                headers = self.headers.get_all("Host", [])
                if len(headers) != 1 or _authority(headers[0])[0] not in allowed_hosts:
                    raise ValueError("不允许的主机名")
            except ValueError:
                self.json_response(403, {"error": "不允许的主机名"})
                return False
            return True

        def check_mutation(self):
            try:
                origins = self.headers.get_all("Origin", [])
                if self.headers.get_all("X-LanMonitor", []) != ["1"] or len(origins) > 1:
                    raise ValueError("请求来源无效")
                if origins:
                    origin = urlsplit(origins[0])
                    if (origins[0] != "http://" + origin.netloc or origin.scheme != "http"
                            or origin.path or origin.query or origin.fragment
                            or _authority(origin.netloc) != _authority(self.headers["Host"])):
                        raise ValueError("请求来源无效")
            except ValueError:
                self.json_response(403, {"error": "请求来源无效"})
                return False
            if self.headers.get_all("Transfer-Encoding", []):
                self.json_response(400, {"error": "不支持的请求编码"})
                return False
            return True

        def read_json(self, maximum=4096):
            if self.headers.get_all("Content-Type", []) and len(self.headers.get_all("Content-Type")) != 1:
                raise ValueError("需要 JSON 请求")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("需要 JSON 请求")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                raise ValueError("请求大小无效")
            length = int(lengths[0])
            if not 0 < length <= maximum:
                raise ValueError("请求大小无效")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("请求内容不完整")
            try:
                values = json.loads(body, object_pairs_hook=_json_object, parse_constant=_invalid_constant)
            except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
                raise ValueError("JSON 请求格式无效") from exc
            if not isinstance(values, dict):
                raise ValueError("请求格式无效")
            return values

        def settings_payload(self):
            with store.lock:
                return dict(scanner.settings.export(), instance=scanner.started_at,
                            service={"host": bind_host, "port": self.server.server_address[1], "subnet": SUBNET},
                            scanner=scanner.snapshot())

        def dispatch(self, method):
            if not self.check_host():
                return
            try:
                self.target = urlsplit(self.path)
                if not self.path.startswith("/") or self.target.scheme or self.target.netloc or self.target.fragment:
                    raise ValueError("请求路径无效")
                method()
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                self.json_response(400, {"error": str(exc) or "请求格式无效"})
            except sqlite3.Error:
                LOG.exception("Database operation failed")
                self.json_response(500, {"error": "数据保存失败，请稍后重试"})
            except OSError as exc:
                if isinstance(exc, (ConnectionError, TimeoutError)):
                    raise
                LOG.exception("Unable to read or save application files")
                self.json_response(500, {"error": "文件读写失败，请检查文件权限"})
            except Exception:
                LOG.exception("Unable to handle API request")
                self.json_response(500, {"error": "服务暂时不可用，请稍后重试"})

        def get(self):
            if self.target.path == "/api/settings":
                self.json_response(200, self.settings_payload())
                return
            if self.target.path == "/api/state":
                try:
                    query = parse_qs(self.target.query, max_num_fields=8)
                    value = query.get("since", [None])[0]
                    if value is not None and not re.fullmatch(r"-?[0-9]{1,16}", value):
                        raise ValueError("版本号无效")
                    since = int(value) if value is not None else None
                    if query.get("instance", [str(scanner.started_at)])[0] != str(scanner.started_at):
                        since = None
                except ValueError as exc:
                    raise ValueError("版本号无效") from exc
                with store.lock:
                    configuration = scanner.settings.export()
                    settings = configuration["settings"]
                    payload = store.snapshot(since, settings)
                    payload.update(configuration)
                    payload.update(now=time.time(), instance=scanner.started_at, subnet=SUBNET,
                                   dhcp_start=settings["dhcp_start"], dhcp_end=settings["dhcp_end"],
                                   online_window=settings["online_window"], scanner=scanner.snapshot())
                self.json_response(200, payload)
                return
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8"),
                      "/favicon.svg": ("favicon.svg", "image/svg+xml")}
            if self.target.path not in assets:
                self.json_response(404, {"error": "页面不存在"})
                return
            filename, content_type = assets[self.target.path]
            self.send_body(200, (ROOT / "static" / filename).read_bytes(), content_type)

        def mutate(self, delete=False):
            if not self.check_mutation():
                return
            match = re.fullmatch(r"/api/hosts/(\d{1,3})", self.target.path)
            if not match or not 1 <= int(match.group(1)) <= 254:
                raise ValueError("IP 地址无效")
            octet = int(match.group(1))
            values = None if delete else self.read_json(1024)
            # Keep host and revision from the same commit. A scan between the
            # two reads would otherwise make the browser suppress newer data.
            with store.lock:
                if delete:
                    store.delete(octet)
                else:
                    store.set_flags(octet, values)
                payload = {"host": store.get(octet), "revision": store.snapshot()["revision"],
                           "instance": scanner.started_at}
            self.json_response(200, payload)

        def patch(self):
            device_note = re.fullmatch(r"/api/devices/([^/]+)/note", self.target.path)
            if device_note:
                if not self.check_mutation():
                    return
                values = self.read_json()
                if set(values) != {"note"}:
                    raise ValueError("请求格式无效")
                payload = store.set_device_note(device_note.group(1), values["note"])
                payload["instance"] = scanner.started_at
                self.json_response(200, payload)
                return
            if self.target.path == "/api/settings":
                if not self.check_mutation():
                    return
                changes = self.read_json()
                cleanup_failed = False
                with store.lock:
                    scanner.settings.update(changes)
                    try:
                        if changes.get("auto_cleanup_old_addresses") is True:
                            store.cleanup_old_addresses()
                    except sqlite3.Error:
                        LOG.exception("Unable to clean up old addresses")
                        cleanup_failed = True
                    payload = self.settings_payload()
                if cleanup_failed:
                    self.json_response(500, {"error": "设置已保存，旧地址清理失败"})
                else:
                    self.json_response(200, payload)
                return
            self.mutate()

        def post(self):
            if not self.check_mutation():
                return
            if self.target.path != "/api/history/clear":
                self.json_response(404, {"error": "页面不存在"})
                return
            values = self.read_json(1024)
            if set(values) - {"scope", "dhcp_start", "dhcp_end"} or "scope" not in values:
                raise ValueError("请求格式无效")
            expected = None
            if values["scope"] == "dhcp":
                if any(type(values.get(key)) is not int for key in ("dhcp_start", "dhcp_end")):
                    raise ValueError("需要确认 DHCP 起止地址")
                expected = values["dhcp_start"], values["dhcp_end"]
            with store.lock:
                result = store.clear_history(values["scope"], expected)
                result["state"] = dict(store.snapshot(), instance=scanner.started_at)
                result["instance"] = scanner.started_at
            self.json_response(200, result)

        def do_GET(self):
            self.dispatch(self.get)

        def do_PATCH(self):
            self.dispatch(self.patch)

        def do_POST(self):
            self.dispatch(self.post)

        def do_DELETE(self):
            self.dispatch(lambda: self.mutate(delete=True))

    return Handler
