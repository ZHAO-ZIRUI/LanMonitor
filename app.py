#!/usr/bin/env python3
"""LAN Monitor entry point; collectors, persistence and HTTP live in separate modules."""

import argparse
import ipaddress
import logging
import os
import signal
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import Settings
from constants import LOG, ROOT, SUBNET
from store import Store, blank_host as blank_host, normalize_mac as normalize_mac
from scanner import (Scanner, encode_dns_name as encode_dns_name,
                     parse_ptr_packet as parse_ptr_packet, decode_dns_name as decode_dns_name)
from http_api import BoundedHTTPServer, make_handler


def configure_logging():
    handlers = None
    if os.environ.get("LANMONITOR_MANAGED") == "1":
        log_path = ROOT / "data" / "server.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers = [RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024,
                                        backupCount=3, encoding="utf-8")]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


def main():
    parser = argparse.ArgumentParser(description="192.168.100.0/24 LAN monitor")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=25400)
    parser.add_argument("--database", type=Path, default=ROOT / "data" / "lanmonitor.sqlite3")
    parser.add_argument("--settings", type=Path, default=ROOT / "data" / "settings.json")
    parser.add_argument("--no-scan", action="store_true", help="serve stored data without sending probes")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("端口必须在 1–65535 之间")
    try:
        if args.host != "localhost":
            ipaddress.IPv4Address(args.host)
    except ValueError:
        parser.error("监听地址必须是 IPv4 地址或 localhost")
    args.database.parent.mkdir(parents=True, exist_ok=True)
    settings = Settings(args.settings)
    store = Store(args.database, settings=settings)
    scanner = None
    server = None
    try:
        scanner = Scanner(store, enabled=not args.no_scan, settings=settings)
        server = BoundedHTTPServer((args.host, args.port), make_handler(store, scanner, args.port, args.host))
        stopping = False

        def request_shutdown(*_args):
            nonlocal stopping
            if not stopping:
                stopping = True
                threading.Thread(target=server.shutdown, daemon=True, name="http-shutdown").start()

        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, request_shutdown)
        scanner.start()
        LOG.info("LanMonitor listening at http://%s:%s · %s", args.host, args.port, SUBNET)
        server.serve_forever(poll_interval=0.25)
    finally:
        # Drain HTTP writers and collectors before closing their connection.
        try:
            if server is not None:
                server.server_close()
        finally:
            try:
                if scanner is not None:
                    scanner.stop()
            finally:
                store.close()


if __name__ == "__main__":
    configure_logging()
    try:
        main()
    except Exception:
        LOG.exception("LanMonitor startup or service failure")
        raise SystemExit(1) from None
