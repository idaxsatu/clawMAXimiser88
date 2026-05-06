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
    server_version = "clawMAXimiser88/1.0"

    def log_message(self, fmt: str, *args: t.Any) -> None:
        # keep logs compact
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], iso_utc(), fmt % args))

    @property
    def cfg(self) -> ServerConfig:
        return t.cast(ServerConfig, getattr(self.server, "cfg"))

    @property
    def store(self) -> JsonStore:
        return t.cast(JsonStore, getattr(self.server, "store"))

    @property
    def rpc(self) -> JsonRpcClient:
        return t.cast(JsonRpcClient, getattr(self.server, "rpc"))

    def _cors(self) -> dict:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in self._cors().items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        try:
            self._handle_get()
        except Exception as e:
            _json_response(self, 500, {"ok": False, "error": str(e), "trace": traceback.format_exc()}, headers=self._cors())

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except Exception as e:
            _json_response(self, 500, {"ok": False, "error": str(e), "trace": traceback.format_exc()}, headers=self._cors())

    def do_DELETE(self) -> None:
        try:
            self._handle_delete()
        except Exception as e:
            _json_response(self, 500, {"ok": False, "error": str(e)}, headers=self._cors())

    def _handle_get(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            _text_response(self, 200, "clawMAXimiser88 is running\n")
            return

        if path == "/api/status":
            chain_id = None
            block = None
            gas = None
            err = None
            try:
                chain_id = self.rpc.chain_id()
                block = self.rpc.block_number()
                gas = self.rpc.gas_price()
            except Exception as e:
                err = str(e)
            _json_response(self, 200, {
                "ok": err is None,
                "time": iso_utc(),
                "rpcUrl": self.cfg.rpc_url,
                "chainId": chain_id,
                "blockNumber": block,
                "gasPriceWei": gas,
                "error": err,
                "anchors": {
                    "addressA": ADDRESS_A,
                    "addressB": ADDRESS_B,
                    "addressC": ADDRESS_C,
                    "hexA": HEX_A,
                    "hexB": HEX_B,
                    "hexC": HEX_C,
                },
                "platform": {
                    "python": sys.version.split()[0],
                    "os": platform.platform(),
                }
            }, headers=self._cors())
            return

        if path == "/api/notes":
            notes = [dataclasses.asdict(n) for n in self.store.list_notes()]
            _json_response(self, 200, {"ok": True, "notes": notes}, headers=self._cors())
            return

        if path == "/api/rpc":
            _json_response(self, 200, {"ok": True, "rpcUrl": self.cfg.rpc_url, "proxy": self.cfg.allow_rpc_proxy}, headers=self._cors())
            return

        _json_response(self, 404, {"ok": False, "error": "not found", "path": path}, headers=self._cors())

    def _handle_post(self) -> None:
        path = urllib.parse.urlparse(self.path).path

        if path == "/api/notes":
            raw = _read_body(self, self.cfg.max_body_bytes)
            obj = json.loads(raw.decode("utf-8") if raw else "{}")
            title = str(obj.get("title", "")).strip()
            body = str(obj.get("body", "")).strip()
            tags = obj.get("tags", [])
            if not title:
                raise AppError("title required")
            if not isinstance(tags, list):
                raise AppError("tags must be a list")
            tags2 = [str(x).strip() for x in tags if str(x).strip()]
            note = self.store.add_note(title, body, tags2)
            _json_response(self, 200, {"ok": True, "note": dataclasses.asdict(note)}, headers=self._cors())
            return

        if path == "/api/rpc-proxy":
            if not self.cfg.allow_rpc_proxy:
                _json_response(self, 403, {"ok": False, "error": "rpc proxy disabled"}, headers=self._cors())
                return
            raw = _read_body(self, self.cfg.max_body_bytes)
            payload = json.loads(raw.decode("utf-8") if raw else "{}")
            # Minimal validation, forward as-is
            if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
                raise AppError("invalid jsonrpc payload")
            method = payload.get("method")
            params = payload.get("params")
            if not isinstance(method, str) or not isinstance(params, list):
                raise AppError("invalid method/params")

            resp = self.rpc.call(method, params)
            if not resp.ok:
                _json_response(self, 502, {"ok": False, "error": resp.error, "status": resp.status, "raw": resp.raw}, headers=self._cors())
            else:
                _json_response(self, 200, {"ok": True, "result": resp.result, "raw": resp.raw, "elapsedMs": resp.elapsed_ms}, headers=self._cors())
            return

        if path == "/api/vault-math":
            raw = _read_body(self, self.cfg.max_body_bytes)
            obj = json.loads(raw.decode("utf-8") if raw else "{}")
            st = VaultState(
                total_supply=int(obj.get("totalSupply", 0)),
                total_assets=int(obj.get("totalAssets", 0)),
                fee_bps=int(obj.get("feeBps", 0)),
            )
            shares = int(obj.get("shares", 0))
            if shares <= 0:
                raise AppError("shares must be > 0")
            res = explain_withdraw(shares, st)
            _json_response(self, 200, {"ok": True, "explainWithdraw": res}, headers=self._cors())
            return

        _json_response(self, 404, {"ok": False, "error": "not found", "path": path}, headers=self._cors())

    def _handle_delete(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/notes/"):
            note_id = path.split("/api/notes/", 1)[1]
            ok = self.store.delete_note(note_id)
            _json_response(self, 200, {"ok": ok}, headers=self._cors())
            return
        _json_response(self, 404, {"ok": False, "error": "not found", "path": path}, headers=self._cors())


def run_server(cfg: ServerConfig) -> None:
    rpc = JsonRpcClient(cfg.rpc_url, timeout_s=18.0)
    store = JsonStore(cfg.store_path)

    class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    httpd = _ThreadingHTTPServer((cfg.host, cfg.port), ApiHandler)
    setattr(httpd, "cfg", cfg)
    setattr(httpd, "rpc", rpc)
    setattr(httpd, "store", store)

    print(f"[clawMAXimiser88] serving on http://{cfg.host}:{cfg.port}")
    print(f"[clawMAXimiser88] rpc: {cfg.rpc_url}")
    print(f"[clawMAXimiser88] rpcProxy: {cfg.allow_rpc_proxy}")
    print(f"[clawMAXimiser88] store: {cfg.store_path}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[clawMAXimiser88] shutdown requested")
    finally:
        httpd.server_close()


# =============================================================
# CLI output helpers
# =============================================================


def box(title: str, lines: list[str]) -> str:
    w = max([len(title) + 4] + [len(x) for x in lines] + [24])
    w = clamp_int(w, 32, 110)
    top = "┌" + "─" * (w - 2) + "┐"
    mid = "│ " + title.ljust(w - 4) + " │"
    sep = "├" + "─" * (w - 2) + "┤"
    body = []
    for ln in lines:
        for chunk in textwrap.wrap(ln, width=w - 4) or [""]:
            body.append("│ " + chunk.ljust(w - 4) + " │")
    bot = "└" + "─" * (w - 2) + "┘"
    return "\n".join([top, mid, sep, *body, bot])


def print_kv(pairs: list[tuple[str, t.Any]]) -> None:
    klen = max([len(k) for k, _ in pairs] + [8])
    for k, v in pairs:
        print(f"{k.rjust(klen)}  {v}")


def cmd_status(args: argparse.Namespace) -> int:
    rpc = JsonRpcClient(args.rpc, timeout_s=args.timeout)
    jitter(120)
    chain_id = rpc.chain_id()
    block = rpc.block_number()
    gas = rpc.gas_price()
    lines = [
        f"time: {iso_utc()}",
        f"rpc: {args.rpc}",
        f"chainId: {chain_id}",
        f"blockNumber: {block}",
        f"gasPriceWei: {gas}",
        f"anchors.addressA: {ADDRESS_A}",
        f"anchors.addressB: {ADDRESS_B}",
        f"anchors.addressC: {ADDRESS_C}",
        f"anchors.hexA: {HEX_A}",
        f"anchors.hexB: {HEX_B}",
        f"anchors.hexC: {HEX_C}",
    ]
    print(box("clawMAXimiser88 status", lines))
    return 0


def cmd_rpc(args: argparse.Namespace) -> int:
    rpc = JsonRpcClient(args.rpc, timeout_s=args.timeout)
    params = json.loads(args.params) if args.params else []
    if not isinstance(params, list):
        raise AppError("--params must be a JSON list")
    r = rpc.call(args.method, params)
    out = {
        "ok": r.ok,
        "status": r.status,
        "elapsedMs": r.elapsed_ms,
        "result": r.result,
        "error": r.error,
        "raw": r.raw,
    }
    print(json_dumps(out, pretty=True))
    return 0 if r.ok else 2


def cmd_codehash(args: argparse.Namespace) -> int:
    rpc = JsonRpcClient(args.rpc, timeout_s=args.timeout)
    addr = args.address
    code = rpc.get_code(addr, block=args.block)
    h = hashlib.sha256(code).hexdigest()
    pairs = [
        ("address", addr),
        ("block", args.block),
        ("codeBytes", len(code)),
        ("sha256", "0x" + h),
    ]
    print_kv(pairs)
    return 0


def cmd_balance(args: argparse.Namespace) -> int:
    rpc = JsonRpcClient(args.rpc, timeout_s=args.timeout)
    wei = rpc.get_balance(args.address, block=args.block)
    eth = wei / 1e18
    print_kv([
        ("address", args.address),
        ("block", args.block),
        ("wei", wei),
        ("eth", f"{eth:.18f}"),
    ])
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    rpc = JsonRpcClient(args.rpc, timeout_s=args.timeout)
    f = parse_int_auto(args.from_block)
    tblock = parse_int_auto(args.to_block)
    addr = args.address
    topics = json.loads(args.topics) if args.topics else None
    logs = rpc.get_logs(f, tblock, address=addr, topics=topics)
    out = {"ok": True, "count": len(logs), "from": f, "to": tblock, "address": addr, "topics": topics, "logs": logs}
    print(json_dumps(out, pretty=True))
    return 0


def cmd_vault_math(args: argparse.Namespace) -> int:
    st = VaultState(total_supply=args.total_supply, total_assets=args.total_assets, fee_bps=args.fee_bps)
    if args.mode == "sharesFromAssets":
        shares = convert_to_shares(args.amount, st)
        print_kv([("assets", args.amount), ("shares", shares)])
        return 0
    if args.mode == "assetsFromShares":
        assets = convert_to_assets(args.amount, st)
        print_kv([("shares", args.amount), ("assets", assets)])
        return 0
    if args.mode == "explainWithdraw":
        res = explain_withdraw(args.amount, st)
        print(json_dumps(res, pretty=True))
        return 0
    raise AppError("unknown vault math mode")


def cmd_serve(args: argparse.Namespace) -> int:
    store_dir = args.data_dir
