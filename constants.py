"""Shared network identity and paths; keep collection scoped to this subnet."""

import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PREFIX = "192.168.100."
SUBNET = "192.168.100.0/24"
DHCP_START, DHCP_END = 5, 99
ONLINE_WINDOW = 90
LOG = logging.getLogger("lanmonitor")
