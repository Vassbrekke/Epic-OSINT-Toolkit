"""Shared network helpers — SSRF-safe URL checks and HTTP defaults."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse

UA = (
    "Mozilla/5.0 (compatible; EpicOSINT/2.0; +https://github.com/Vassbrekke/Epic-OSINT-Toolkit)"
)
DEFAULT_HEADERS = {"User-Agent": UA, "Accept": "text/html,application/json,*/*"}

_PRIVATE = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def is_safe_host(host: str) -> bool:
    """Reject empty, localhost names, and private/link-local IPs."""
    if not host or len(host) > 253:
        return False
    h = host.strip("[]").lower()
    if h in ("localhost", "metadata.google.internal") or h.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(h)
        return not any(ip in net for net in _PRIVATE)
    except ValueError:
        # hostname — resolve and reject if any private A/AAAA
        try:
            infos = socket.getaddrinfo(h, None)
        except socket.gaierror:
            # Unresolved: allow FQDN-shaped hosts (request will fail later);
            # still block localhost-style names above.
            return "." in h and not h.endswith((".local", ".internal", ".lan"))
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
                if any(ip in net for net in _PRIVATE):
                    return False
            except ValueError:
                continue
        return True


def is_safe_url(url: str, allow_onion: bool = False) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = p.hostname or ""
    if allow_onion and host.endswith(".onion"):
        return bool(re.match(r"^[a-z2-7]{16,56}\.onion$", host))
    return is_safe_host(host)


def normalize_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None
