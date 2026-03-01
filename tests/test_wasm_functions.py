#!/usr/bin/env python3
"""
Enclave OS — WASM Integration Test Suite
=========================================

Exercises all 6 exported functions of the wasm-example app over an RA-TLS
connection to the SGX enclave.  Outputs a clean report with pass/fail per test.

Usage:
    python tests/test_wasm_functions.py [CWASM_PATH]

The script connects to 127.0.0.1:8443 by default (edit HOST/PORT below).
Requires only Python 3.6+ stdlib.
"""

import json
import socket
import ssl
import struct
import sys
import time

# ── Configuration ──────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 8443
APP_NAME = "test-app"

# ── Wire protocol helpers ─────────────────────────────────────────────────


def encode_frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def decode_frame(data: bytes):
    if len(data) < 4:
        return None, data
    length = struct.unpack(">I", data[:4])[0]
    if len(data) < 4 + length:
        return None, data
    return data[4 : 4 + length], data[4 + length :]


def make_request(variant: str, value=None) -> bytes:
    return json.dumps(variant if value is None else {variant: value}).encode()


def connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=60)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def send_recv(tls, payload: bytes) -> bytes:
    tls.sendall(encode_frame(payload))
    buf = b""
    while True:
        chunk = tls.recv(16384)
        if not chunk:
            raise ConnectionError("Connection closed by server")
        buf += chunk
        result, _ = decode_frame(buf)
        if result is not None:
            return result


def wasm_load(tls, name: str, path: str):
    with open(path, "rb") as f:
        wasm_bytes = list(f.read())
    inner = json.dumps({"wasm_load": {"name": name, "bytes": wasm_bytes}}).encode()
    resp = json.loads(send_recv(tls, make_request("Data", list(inner))))
    if "Data" in resp:
        return json.loads(bytes(resp["Data"]))
    if "Error" in resp:
        return {"error": bytes(resp["Error"]).decode(errors="replace")}
    return resp


def wasm_call(tls, app: str, function: str, params=None):
    inner = json.dumps(
        {"wasm_call": {"app": app, "function": function, "params": params or []}}
    ).encode()
    resp = json.loads(send_recv(tls, make_request("Data", list(inner))))
    if "Data" in resp:
        raw = bytes(resp["Data"])
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw.decode(errors="replace")}
    if "Error" in resp:
        return {"error": bytes(resp["Error"]).decode(errors="replace")}
    return resp


# ── Test definitions ──────────────────────────────────────────────────────


def extract_return_value(result):
    """Extract the value from a wasm_call result.

    Expected shape: {"status": "ok", "returns": [{"type": "...", "value": ...}]}
    """
    if isinstance(result, dict) and result.get("status") == "ok":
        returns = result.get("returns", [])
        if returns and isinstance(returns, list):
            return returns[0].get("value")
    return None


def test_hello(tls):
    r = wasm_call(tls, APP_NAME, "hello")
    val = extract_return_value(r)
    ok = val == "Hello, World!"
    return ok, val if ok else json.dumps(r)


def test_get_random(tls):
    r = wasm_call(tls, APP_NAME, "get-random")
    val = extract_return_value(r)
    ok = isinstance(val, int) and 1 <= val <= 100
    return ok, str(val) if ok else json.dumps(r)


def test_get_time(tls):
    r = wasm_call(tls, APP_NAME, "get-time")
    val = extract_return_value(r)
    if val and isinstance(val, str) and "." in val:
        try:
            ts = float(val.split(".")[0])
            ok = 1_704_067_200 < ts < 1_893_456_000
            return ok, val if ok else f"timestamp out of range: {val}"
        except ValueError:
            pass
    return False, json.dumps(r)


def test_kv_store(tls):
    r = wasm_call(
        tls, APP_NAME, "kv-store",
        [
            {"type": "string", "value": "greeting"},
            {"type": "string", "value": "Hello from WASM in SGX!"},
        ],
    )
    val = extract_return_value(r)
    ok = val == "stored: greeting"
    return ok, "greeting = 'Hello from WASM in SGX!'" if ok else json.dumps(r)


def test_kv_read(tls):
    r = wasm_call(
        tls, APP_NAME, "kv-read",
        [{"type": "string", "value": "greeting"}],
    )
    val = extract_return_value(r)
    ok = val == "Hello from WASM in SGX!"
    return ok, val if ok else json.dumps(r)


def test_fetch_headlines(tls):
    r = wasm_call(tls, APP_NAME, "fetch-headlines")
    val = extract_return_value(r)
    if val and isinstance(val, str):
        lines = [l for l in val.strip().split("\n") if l.strip()]
        ok = len(lines) >= 2 and lines[0].startswith("1.")
        preview = lines[0][:72] if lines else ""
        return ok, f"{len(lines)} headlines — {preview}" if ok else val
    return False, json.dumps(r)


# ── Runner ────────────────────────────────────────────────────────────────

TESTS = [
    ("hello",           "Hello World",       "Smoke test (no imports)",            test_hello),
    ("get-random",      "Random Number",     "wasi:random -> RDRAND",              test_get_random),
    ("get-time",        "Wall Clock",        "wasi:clocks -> OCALL",               test_get_time),
    ("kv-store",        "KV Store (write)",  "wasi:filesystem -> sealed KV",       test_kv_store),
    ("kv-read",         "KV Store (read)",   "wasi:filesystem -> sealed KV",       test_kv_read),
    ("fetch-headlines", "HTTPS Egress",      "privasys:enclave-os/https -> TLS",   test_fetch_headlines),
]


def main():
    wasm_path = sys.argv[1] if len(sys.argv) > 1 else "wasm_example.cwasm"

    print()
    print("=" * 64)
    print("  Enclave OS (Mini) - WASM Integration Test Suite")
    print("=" * 64)
    print()

    # Connect
    print(f"  Connecting to {HOST}:{PORT} ...")
    try:
        tls = connect()
    except Exception as e:
        print(f"  [FAIL] Connection failed: {e}")
        sys.exit(1)
    print(f"  Connected: {tls.version()}, {tls.cipher()[0]}")
    print()

    # Load WASM app
    print(f"  Loading {wasm_path} ...")
    t0 = time.time()
    load_result = wasm_load(tls, APP_NAME, wasm_path)
    load_time = time.time() - t0
    if "error" in (load_result if isinstance(load_result, dict) else {}):
        print(f"  [FAIL] Load failed: {load_result}")
        sys.exit(1)
    print(f"  Loaded in {load_time:.2f}s")
    print()

    # Run tests
    SEP = "  " + "-" * 60
    print(SEP)
    print(f"  {'#':>3}  {'Test':<20} {'Result':<8}{'Details'}")
    print(SEP)

    passed = 0
    failed = 0
    results = []

    for i, (func_name, label, desc, test_fn) in enumerate(TESTS, 1):
        t0 = time.time()
        try:
            ok, detail = test_fn(tls)
        except Exception as e:
            ok, detail = False, f"Exception: {e}"
        elapsed = time.time() - t0

        icon = "\u2714" if ok else "\u274c"
        if ok:
            passed += 1
        else:
            failed += 1

        detail_str = str(detail)[:40]
        print(f"  {i:>3}  {label:<20} {icon}  {detail_str}")
        results.append((i, func_name, label, desc, ok, detail, elapsed))

    print(SEP)
    print()

    # Summary
    total = passed + failed
    if failed == 0:
        print(f"  \u2714 Result: ALL {total} TESTS PASSED")
    else:
        print(f"  \u274c Result: {failed}/{total} TESTS FAILED")
    print()

    # Detailed results
    print("  Detailed Results")
    print("  " + "-" * 40)
    for i, func_name, label, desc, ok, detail, elapsed in results:
        icon = "\u2714" if ok else "\u274c"
        print(f"  {icon} {i}. {label} ({func_name}) - {elapsed:.2f}s")
        print(f"       WASI: {desc}")
        print(f"       Output: {detail}")
        print()

    tls.close()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
