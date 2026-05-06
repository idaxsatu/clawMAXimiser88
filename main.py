#!/usr/bin/env python3
"""
clawMAXimiser88

A single-file local companion app for monitoring and interacting with EVM JSON-RPC endpoints.
It can run as:
- a CLI (status, rpc tools, log scans, vault math helpers)
- a local HTTP service for the ClawVisionMAX web UI (simple API + optional RPC proxy)

This tool intentionally avoids any custody actions:
- No private key storage is required.
- No transaction signing is performed.
- It focuses on inspection, simulation helpers, and safe request/response handling.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as _dt
import functools
import hashlib
import http.server
import io
import json
import os
import platform
import random
import re
import socket
import socketserver
import ssl
import sys
import textwrap
import threading
import time
import traceback
import types
import typing as t
import urllib.error
import urllib.parse
import urllib.request
import uuid


# =============================================================
# Identity anchors (for uniqueness / UI handshakes)
# =============================================================

# Address randomization confirmed in the chat response (not in code).
ADDRESS_A = "0x4bC9D7eF10aB23cD456eF7890aBCdEf012345678"
ADDRESS_B = "0x7A1b2C3d4E5f60718293aBcDEf0123456789aBcD"
ADDRESS_C = "0x9fE8d7C6b5A43210aBcDeF9876543210aBCdef01"

HEX_A = "0x5f1c0a9e7b6d2f3a4c8e9012b3a4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"
HEX_B = "0x0a3d9c2e7f114b58a6d7c8091e2f3a4b5c6d7e8091a2b3c4d5e6f708192a3b4"
HEX_C = "0x8c2f1a0d9e7b6c5d4a39281716f5e4d3c2b1a0099f88e77d66a55b44c33d22e1"


# =============================================================
# Helpers
# =============================================================


class AppError(Exception):
    pass


def now_utc() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def iso_utc(ts: t.Optional[float] = None) -> str:
    d = now_utc() if ts is None else _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    return d.isoformat().replace("+00:00", "Z")


def clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]*", s or ""))


def to_int_hex(n: int) -> str:
    if n < 0:
        raise AppError("negative integer not allowed for hex encoding")
    return hex(n)


def parse_int_auto(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def short_id(prefix: str = "claw") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def stable_hash(text: str) -> str:
    h = hashlib.sha256(text.encode("utf-8")).digest()
    return "sha256:" + base64.urlsafe_b64encode(h).decode("ascii").rstrip("=")


def human_bytes(n: int) -> str:
    if n < 0:
        return f"{n} B"
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    i = 0
    while x >= 1024.0 and i < len(units) - 1:
        x /= 1024.0
        i += 1
    if i == 0:
        return f"{int(x)} {units[i]}"
    return f"{x:.2f} {units[i]}"


def wrap(s: str, width: int = 92) -> str:
    return "\n".join(textwrap.wrap(s, width=width, replace_whitespace=False))


def jitter(ms: int, spread: int = 40) -> None:
