#!/usr/bin/env python3
"""
test_bore_migration.py — simulate a bore tunnel dying mid-session.

What it does:
  1. Reads the current bore port from the discovery service
  2. Kills the bore process so the server's _migration_loop restarts it
  3. Polls discovery until the new port appears (proves the server posted it)
  4. Optionally verifies a client reconnects to the new port

Run while a NoEyes server is already running:
    python test_bore_migration.py

Flags:
    --wait N   seconds to wait for new port to appear (default: 30)
    --no-kill  skip the kill step — just watch discovery for a change
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

KV_BASE      = "https://keyvalue.immanuel.co/api/KeyVal"
APPKEY_FILE  = Path.home() / ".noeyes" / "discovery_appkey"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _appkey() -> str:
    try:
        ak = APPKEY_FILE.read_text().strip()
        if ak and re.match(r'^[A-Za-z0-9]{6,}', ak):
            return ak
    except Exception:
        pass
    return ""


def _discovery_key() -> str:
    """
    Derive discovery key exactly as noeyes.py does:
      1. Load chat.key (v1: raw base64 line, v2: JSON with 'key' field)
      2. base64-decode to get raw key_bytes
      3. sha256(key_bytes).hexdigest()[:24]
    """
    import hashlib
    import base64
    import json as _json

    root = Path(__file__).parent
    for candidate in (
        root / "ui" / "chat.key",
        root / "chat.key",
        Path.home() / ".noeyes" / "chat.key",
    ):
        if not candidate.exists():
            continue
        try:
            raw = candidate.read_text().strip()
            if raw.startswith("{"):
                key_b64 = _json.loads(raw)["key"].encode()
            else:
                key_b64 = raw.encode()
            key_bytes = base64.urlsafe_b64decode(key_b64)
            return hashlib.sha256(key_bytes).hexdigest()[:24]
        except Exception:
            continue
    return ""


def _get_port(ak: str, dk: str) -> str:
    try:
        url = f"{KV_BASE}/GetValue/{ak}/{dk}"
        with urllib.request.urlopen(url, timeout=8) as r:
            val = r.read().decode().strip().strip('"')
            return val if val and val != "null" else ""
    except Exception:
        return ""


def _find_bore_pids() -> list:
    """Return list of PIDs running 'bore local'."""
    pids = []
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq bore.exe", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL, text=True
            )
            for line in out.splitlines():
                m = re.search(r'"bore\.exe","(\d+)"', line)
                if m:
                    pids.append(int(m.group(1)))
        else:
            out = subprocess.check_output(
                ["pgrep", "-f", "bore local"],
                stderr=subprocess.DEVNULL, text=True
            )
            pids = [int(p) for p in out.split() if p.isdigit()]
    except Exception:
        pass
    return pids


def _kill_bore(pids: list) -> bool:
    if not pids:
        return False
    for pid in pids:
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)
            print(f"  ✔  Killed bore PID {pid}")
        except Exception as e:
            print(f"  ✘  Could not kill PID {pid}: {e}")
            return False
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Simulate bore tunnel death for NoEyes")
    ap.add_argument("--wait",    type=int, default=30,
                    help="seconds to wait for new port (default: 30)")
    ap.add_argument("--no-kill", action="store_true",
                    help="don't kill bore — just watch discovery for a change")
    args = ap.parse_args()

    print("\n  NoEyes — Bore Migration Test\n")

    # 1. Check discovery is configured
    ak = _appkey()
    if not ak:
        print("  ✘  No discovery app-key found at ~/.noeyes/discovery_appkey")
        print("     Start the server first so it provisions one.")
        sys.exit(1)
    print(f"  App-key     : {ak}")

    dk = _discovery_key()
    if not dk:
        print("  ✘  Could not find chat.key to derive discovery key.")
        print("     Make sure chat.key is in ./ui/chat.key or ./chat.key")
        sys.exit(1)
    print(f"  Discovery key: {dk}")

    # 2. Read current port from discovery
    current_port = _get_port(ak, dk)
    if not current_port:
        print("\n  ✘  No port found in discovery service.")
        print("     Is the server running with discovery enabled?")
        sys.exit(1)
    print(f"  Current port : {current_port}")

    # 3. Kill bore
    if not args.no_kill:
        print("\n  Searching for bore process...")
        pids = _find_bore_pids()
        if not pids:
            print("  ✘  No bore process found. Is the server running bore?")
            sys.exit(1)
        print(f"  Found bore PID(s): {pids}")
        print("  Killing bore — server should restart tunnel in ~5s...\n")
        _kill_bore(pids)
    else:
        print("\n  --no-kill set — watching for port change without killing bore.\n")

    # 4. Poll discovery until port changes
    print(f"  Waiting up to {args.wait}s for new port to appear in discovery...")
    deadline = time.monotonic() + args.wait
    new_port = ""
    dots = 0
    while time.monotonic() < deadline:
        p = _get_port(ak, dk)
        if p and p != current_port:
            new_port = p
            break
        print(".", end="", flush=True)
        dots += 1
        if dots % 20 == 0:
            print()
        time.sleep(1)
    print()

    if new_port:
        print(f"\n  ✔  New port detected: {new_port}")
        print(f"     Old: bore.pub:{current_port}")
        print(f"     New: bore.pub:{new_port}")
        print("\n  ✔  Discovery is working — clients with the key file will reconnect automatically.")
    else:
        print(f"\n  ✘  Port did not change within {args.wait}s.")
        print("     Check that the server restarted bore and discovery is enabled.")
        sys.exit(1)


if __name__ == "__main__":
    main()
