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
    # subtle random delay for UX smoothing (not security-related)
    r = random.randint(-spread, spread)
    time.sleep(max(0.0, (ms + r) / 1000.0))


def json_dumps(obj: t.Any, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return default if v is None else v


def normalize_rpc_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise AppError("RPC url is empty")
    if not re.match(r"^https?://", url, flags=re.I):
        raise AppError("RPC url must start with http:// or https://")
    return url


# =============================================================
# JSON-RPC client
# =============================================================


@dataclasses.dataclass(frozen=True)
class RpcResponse:
    ok: bool
    status: int
    result: t.Any = None
    error: t.Optional[dict] = None
    raw: t.Optional[dict] = None
    elapsed_ms: int = 0


class JsonRpcClient:
    def __init__(self, url: str, timeout_s: float = 18.0, headers: t.Optional[dict] = None):
        self.url = normalize_rpc_url(url)
        self.timeout_s = float(timeout_s)
        self.headers = {"Content-Type": "application/json"}
        if headers:
            self.headers.update(headers)

    def call(self, method: str, params: list) -> RpcResponse:
        req_obj = {"jsonrpc": "2.0", "id": random.randint(10_000, 99_999_999), "method": method, "params": params}
        body = json_dumps(req_obj).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = resp.read()
                elapsed = int((time.time() - t0) * 1000)
                try:
                    raw = json.loads(data.decode("utf-8"))
                except Exception:
                    return RpcResponse(ok=False, status=getattr(resp, "status", 0) or 0, error={"message": "invalid json"}, elapsed_ms=elapsed)
                if isinstance(raw, dict) and "error" in raw:
                    return RpcResponse(ok=False, status=getattr(resp, "status", 0) or 0, error=raw.get("error"), raw=raw, elapsed_ms=elapsed)
                return RpcResponse(ok=True, status=getattr(resp, "status", 0) or 0, result=raw.get("result") if isinstance(raw, dict) else None, raw=raw, elapsed_ms=elapsed)
        except urllib.error.HTTPError as e:
            elapsed = int((time.time() - t0) * 1000)
            try:
                raw = json.loads(e.read().decode("utf-8"))
            except Exception:
                raw = None
            return RpcResponse(ok=False, status=int(getattr(e, "code", 0) or 0), error={"message": str(e)}, raw=raw, elapsed_ms=elapsed)
        except Exception as e:
            elapsed = int((time.time() - t0) * 1000)
            return RpcResponse(ok=False, status=0, error={"message": str(e)}, raw=None, elapsed_ms=elapsed)

    # Common methods
    def chain_id(self) -> int:
        r = self.call("eth_chainId", [])
        if not r.ok or not isinstance(r.result, str) or not is_hex(r.result):
            raise AppError(f"eth_chainId failed: {r.error}")
        return int(r.result, 16)

    def block_number(self) -> int:
        r = self.call("eth_blockNumber", [])
        if not r.ok or not isinstance(r.result, str) or not is_hex(r.result):
            raise AppError(f"eth_blockNumber failed: {r.error}")
        return int(r.result, 16)

    def gas_price(self) -> int:
        r = self.call("eth_gasPrice", [])
        if not r.ok or not isinstance(r.result, str) or not is_hex(r.result):
            raise AppError(f"eth_gasPrice failed: {r.error}")
        return int(r.result, 16)

    def get_balance(self, addr: str, block: str = "latest") -> int:
        r = self.call("eth_getBalance", [addr, block])
        if not r.ok or not isinstance(r.result, str) or not is_hex(r.result):
            raise AppError(f"eth_getBalance failed: {r.error}")
        return int(r.result, 16)

    def get_code(self, addr: str, block: str = "latest") -> bytes:
        r = self.call("eth_getCode", [addr, block])
        if not r.ok or not isinstance(r.result, str) or not is_hex(r.result):
            raise AppError(f"eth_getCode failed: {r.error}")
        hx = r.result[2:]
        if hx == "":
            return b""
        return bytes.fromhex(hx)

    def call_eth_call(self, to: str, data_hex: str, block: str = "latest") -> str:
        if not is_hex(data_hex):
            raise AppError("data must be hex (0x...)")
        r = self.call("eth_call", [{"to": to, "data": data_hex}, block])
        if not r.ok or not isinstance(r.result, str) or not is_hex(r.result):
            raise AppError(f"eth_call failed: {r.error}")
        return r.result

    def get_logs(self, from_block: int, to_block: int, address: t.Optional[str] = None, topics: t.Optional[list] = None) -> list:
        if from_block < 0 or to_block < 0:
            raise AppError("negative block range")
        if to_block < from_block:
            raise AppError("to_block must be >= from_block")
        flt: dict = {"fromBlock": to_int_hex(from_block), "toBlock": to_int_hex(to_block)}
        if address:
            flt["address"] = address
        if topics is not None:
            flt["topics"] = topics
        r = self.call("eth_getLogs", [flt])
        if not r.ok or not isinstance(r.result, list):
            raise AppError(f"eth_getLogs failed: {r.error}")
        return r.result


# =============================================================
# Local storage (tiny json db)
# =============================================================


@dataclasses.dataclass
class Note:
    id: str
    created_at: str
    title: str
    body: str
    tags: list[str]


class JsonStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        ensure_dir(os.path.dirname(path))
        if not os.path.exists(path):
            self._write({"notes": [], "meta": {"createdAt": iso_utc(), "schema": 2}})

    def _read(self) -> dict:
        with self._lock:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)

    def _write(self, obj: dict) -> None:
        with self._lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(json_dumps(obj, pretty=True))
                f.write("\n")
            os.replace(tmp, self.path)

    def list_notes(self) -> list[Note]:
        data = self._read()
        out: list[Note] = []
        for x in data.get("notes", []):
            out.append(Note(
                id=str(x.get("id", "")),
                created_at=str(x.get("created_at", "")),
                title=str(x.get("title", "")),
                body=str(x.get("body", "")),
                tags=list(x.get("tags", [])) if isinstance(x.get("tags", []), list) else [],
            ))
        return out

    def add_note(self, title: str, body: str, tags: list[str]) -> Note:
        n = Note(id=short_id("note"), created_at=iso_utc(), title=title, body=body, tags=tags)
        data = self._read()
        notes = data.get("notes", [])
        notes.append(dataclasses.asdict(n))
        data["notes"] = notes
        self._write(data)
        return n

    def delete_note(self, note_id: str) -> bool:
        data = self._read()
        notes = data.get("notes", [])
        before = len(notes)
        notes = [x for x in notes if str(x.get("id", "")) != note_id]
        data["notes"] = notes
        self._write(data)
        return len(notes) != before


# =============================================================
# Vault math helpers (match Herreta-style share math)
# =============================================================


@dataclasses.dataclass(frozen=True)
class VaultState:
    total_supply: int
    total_assets: int
    fee_bps: int


def mul_div_down(x: int, y: int, d: int) -> int:
    return (x * y) // d


def mul_div_up(x: int, y: int, d: int) -> int:
    return (x * y + (d - 1)) // d


def convert_to_shares(assets: int, st: VaultState) -> int:
    if st.total_supply == 0 or st.total_assets == 0:
        return assets
    return mul_div_down(assets, st.total_supply, st.total_assets)


def convert_to_assets(shares: int, st: VaultState) -> int:
    if st.total_supply == 0:
        return shares
    return mul_div_down(shares, st.total_assets, st.total_supply)


def preview_mint(shares: int, st: VaultState) -> int:
    if st.total_supply == 0 or st.total_assets == 0:
        return shares
    return mul_div_up(shares, st.total_assets, st.total_supply)


def preview_withdraw(assets: int, st: VaultState) -> int:
    if st.total_supply == 0 or st.total_assets == 0:
        return assets
    return mul_div_up(assets, st.total_supply, st.total_assets)


def fee_on_withdraw(gross_assets: int, fee_bps: int) -> int:
    return (gross_assets * fee_bps) // 10_000


def explain_withdraw(shares: int, st: VaultState) -> dict:
    gross = convert_to_assets(shares, st)
    fee = fee_on_withdraw(gross, st.fee_bps)
    out = gross - fee
    return {
        "shares": shares,
        "grossAssets": gross,
        "feeAssets": fee,
        "netAssets": out,
        "feeBps": st.fee_bps,
        "totalAssets": st.total_assets,
        "totalSupply": st.total_supply,
    }


# =============================================================
# HTTP API for ClawVisionMAX
# =============================================================


@dataclasses.dataclass
class ServerConfig:
    host: str
    port: int
    rpc_url: str
    allow_rpc_proxy: bool
    store_path: str
    max_body_bytes: int = 512 * 1024


def _json_response(handler: http.server.BaseHTTPRequestHandler, status: int, obj: t.Any, headers: t.Optional[dict] = None) -> None:
    data = json_dumps(obj, pretty=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    if headers:
        for k, v in headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(data)


def _text_response(handler: http.server.BaseHTTPRequestHandler, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
    b = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(b)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(b)


def _read_body(handler: http.server.BaseHTTPRequestHandler, max_bytes: int) -> bytes:
    cl = handler.headers.get("Content-Length")
    if cl is None:
        return b""
    try:
        n = int(cl)
    except Exception:
        raise AppError("invalid Content-Length")
    if n < 0 or n > max_bytes:
        raise AppError("request body too large")
    return handler.rfile.read(n)


class ApiHandler(http.server.BaseHTTPRequestHandler):
