# FILE: noeyes.py
"""
noeyes.py — NoEyes entry point.

Usage:
    python noeyes.py --server [--port PORT] [--no-bore] [--key PASS | --key-file PATH]
    python noeyes.py --connect HOST [--port PORT] [--key PASS | --key-file PATH]
    python noeyes.py --gen-key --key-file PATH
"""

import logging
import os
import sys
from getpass import getpass

from core import config as cfg_mod
from core import encryption as enc
from core import utils
from core import firewall as fw

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
# Keep the noeyes.server logger at INFO for join/leave/listen events,
# but make sure raw IP addresses never appear at INFO level — see server.py.
logging.getLogger("noeyes.server").setLevel(logging.INFO)


def _resolve_fernet(cfg: dict):
    """
    Derive or load a group Fernet key.

    Priority: --key-file > --key > interactive passphrase prompt.
    """
    from cryptography.fernet import Fernet

    if cfg.get("key_file"):
        return enc.load_key_file(cfg["key_file"])  # returns (Fernet, key_bytes)

    passphrase = cfg.get("key")
    if not passphrase:
        if sys.stdin.isatty():
            passphrase = getpass("Shared passphrase: ")
            confirm    = getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print(utils.cerr("[error] Passphrases do not match."))
                sys.exit(1)
        else:
            print(utils.cerr("[error] No key or key-file provided."))
            sys.exit(1)
    else:
        # Security warning: the passphrase is visible in `ps aux` and in
        # shell history to any local user who can read /proc/<pid>/cmdline.
        # --key-file is always safer — the passphrase never touches argv.
        print(utils.cwarn(
            "[security] WARNING: passphrase passed via --key is visible in\n"
            "           `ps aux` and shell history. Use --key-file instead:\n"
            "             python noeyes.py --gen-key --key-file ./chat.key\n"
            "             python noeyes.py --connect HOST --key-file ./chat.key"
        ))

    # ── Secure key derivation ──────────────────────────────────────────────────
    # Instead of re-deriving from the passphrase on every run (which would
    # reuse the same static salt each time), we derive ONCE with a fresh random
    # salt, save the result to a key file, and use the key file from then on.
    #
    # This means:
    #   - Each deployment gets a unique random salt → rainbow tables are useless.
    #   - After the first run the passphrase is no longer needed.
    #   - Other users should receive the generated key FILE, not the passphrase.
    #
    # Key file is saved to --key-file path if provided, otherwise to the
    # default location ~/.noeyes/derived.key.
    import os as _os
    from pathlib import Path as _Path

    save_path = cfg.get("key_file") or "~/.noeyes/derived.key"
    save_p    = _Path(save_path).expanduser()

    if save_p.exists():
        # Key file already exists from a previous run — load it directly.
        # No PBKDF2 re-derivation, no static salt.
        return enc.load_key_file(save_path)  # returns (Fernet, key_bytes)

    # First run with this passphrase: derive key with fresh random salt and save.
    fernet, key_bytes = enc.derive_and_save_key_file(save_path, passphrase)
    print(utils.cok(
        f"[keygen] Passphrase derived and saved to {save_p}\n"
        f"         Share this file (not the passphrase) with other users:\n"
        f"           python noeyes.py --connect HOST --key-file {save_p}"
    ))
    return fernet, key_bytes


def _get_username(cfg: dict) -> str:
    uname = cfg.get("username")
    if uname:
        return uname.strip()[:32]
    if sys.stdin.isatty():
        uname = input("Username: ").strip()[:32]
    if not uname:
        import random, string
        uname = "user_" + "".join(random.choices(string.ascii_lowercase, k=5))
    return uname


# ── Bore port discovery ───────────────────────────────────────────────────────
# When bore.pub kills a tunnel and the server restarts with a new port,
# clients need to find the new port without being told manually.
# We use keyvalue.immanuel.co — a free, fully anonymous key-value REST API.
# An app-key is auto-provisioned on first use with a single GET request
# (no email, no account, no auth) and cached in ~/.noeyes/discovery_appkey.
# The lookup key is derived from the shared group key so only people with
# the key file know which URL to check.

_KV_BASE       = "https://keyvalue.immanuel.co/api/KeyVal"
_KV_APPKEY_CACHE = "~/.noeyes/discovery_appkey"


def _get_or_create_appkey() -> str:
    """
    Return the cached app-key, creating one if needed.
    App-key is an 8-char alphanumeric string returned by a single GET.
    Cached at ~/.noeyes/discovery_appkey.
    """
    import urllib.request as _ur
    from pathlib import Path as _P
    import re as _re

    cache = _P(_KV_APPKEY_CACHE).expanduser()
    try:
        ak = cache.read_text().strip()
        if ak and _re.match(r'^[A-Za-z0-9]{6,}', ak):
            return ak
    except Exception:
        pass

    try:
        with _ur.urlopen(f"{_KV_BASE}/GetAppKey", timeout=10) as r:
            ak = r.read().decode().strip().strip('"')
        if not ak:
            raise ValueError("empty response")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(ak)
        # CVE-NE-011 FIX: restrict permissions so other local users cannot read
        # the app-key and overwrite the discovery record.
        import sys as _sys2
        if _sys2.platform != "win32":
            try:
                cache.chmod(0o600)
            except OSError:
                pass
        return ak
    except Exception as e:
        print(utils.cgrey(f"[discovery] could not provision app-key: {e}"), flush=True)
        return ""


def _discovery_post(key: str, port: str) -> None:
    """Post the current bore port to the discovery service."""
    import urllib.request as _ur
    try:
        ak = _get_or_create_appkey()
        if not ak:
            return
        url = f"{_KV_BASE}/UpdateValue/{ak}/{key}/{port}"
        req = _ur.Request(url, data=b"", method="POST")
        with _ur.urlopen(req, timeout=8):
            pass
        print(utils.cinfo(f"[discovery] port {port} posted — clients will find new address automatically."), flush=True)
    except Exception as e:
        print(utils.cgrey(f"[discovery] post failed: {e}"), flush=True)


def _discovery_get(key: str) -> str:
    """Fetch the current bore port from the discovery service. Returns port string or ''."""
    import urllib.request as _ur
    try:
        ak = _get_or_create_appkey()
        if not ak:
            return ""
        with _ur.urlopen(f"{_KV_BASE}/GetValue/{ak}/{key}", timeout=8) as r:
            val = r.read().decode().strip().strip('"')
            return val if val and val != "null" else ""
    except Exception:
        return ""


def _start_bore(port: int, discovery_key: str = "", no_discovery: bool = False) -> None:
    """
    Launch bore in background and keep it alive.

    Watches for unexpected death and restarts immediately.
    When a new port is assigned, posts it to the discovery service so
    clients can find it automatically on reconnect.
    Silently skips if bore is not installed.
    """
    import subprocess, threading, shutil, re
    _this_file = __file__  # capture before entering threads where __file__ is unavailable

    import sys as _sys, os as _os
    from pathlib import Path as _Path
    cargo_bin  = str(_Path.home() / ".cargo" / "bin")
    bore_exe   = _Path.home() / ".cargo" / "bin" / ("bore.exe" if _sys.platform == "win32" else "bore")
    bore_cmd   = shutil.which("bore")

    # On Windows the PATH may not be refreshed yet — fall back to direct path
    if not bore_cmd and bore_exe.exists():
        bore_cmd = str(bore_exe)
        # Also add to session PATH so child process inherits it
        if cargo_bin not in _os.environ.get("PATH", ""):
            _os.environ["PATH"] = cargo_bin + _os.pathsep + _os.environ.get("PATH", "")

    if not bore_cmd:
        print(utils.cgrey(
            "[bore] not installed — run without tunnel.\n"
            "       Install: https://github.com/ekzhang/bore (see README)"
        ))
        return

    import time as _time

    def _make_kwargs():
        """Return platform-specific Popen kwargs (hides console on Windows)."""
        kw = {}
        if _sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            kw["startupinfo"] = si
        return kw

    def _launch_tunnel():
        """
        Start one bore process.
        Returns (proc, assigned_port_str) once bore.pub has assigned a port,
        or (proc, None) if we couldn't read a port within 15 s (bore failed).
        Stdout/stderr draining threads are started automatically.
        """
        proc = subprocess.Popen(
            [bore_cmd, "local", str(port), "--to", "bore.pub"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_make_kwargs(),
        )

        # Drain stderr in a background thread so the pipe never fills.
        def _drain_stderr():
            for err_line in proc.stderr:
                err_line = err_line.strip()
                if err_line:
                    print(utils.cgrey(f"[bore] {err_line}"), flush=True)
        threading.Thread(target=_drain_stderr, daemon=True).start()

        # Read stdout lines until we see the assigned port or the process dies.
        # We must drain stdout in a thread too (so the pipe never blocks), but
        # we also need the first port line — use a queue to hand it back.
        import queue as _queue
        port_q: "_queue.Queue[str | None]" = _queue.Queue()
        announced_port: list = [None]   # shared with drain thread

        def _drain_stdout():
            for line in proc.stdout:
                m = re.search(r"bore\.pub:(\d+)", line)
                if m and announced_port[0] is None:
                    announced_port[0] = m.group(1)
                    port_q.put(announced_port[0])
                # Keep draining forever so the pipe never fills.
            port_q.put(None)   # process stdout closed

        threading.Thread(target=_drain_stdout, daemon=True).start()

        try:
            assigned = port_q.get(timeout=15)   # wait up to 15 s for bore.pub
        except _queue.Empty:
            assigned = None

        return proc, assigned

    def _print_banner(p: str) -> None:
        _root = str(_Path(_this_file).parent)
        _key  = "./chat.key"
        if (_Path(_this_file).parent / "ui" / "chat.key").exists() and \
                not (_Path(_this_file).parent / "chat.key").exists():
            _key = "./ui/chat.key"
        disc_line = (
            f"  │  discovery : disabled (--no-discovery)\n"
            if no_discovery else
            f"  │  discovery : enabled — clients find new port automatically\n"
        )
        print(utils.cinfo(
            f"\n  ┌─ bore tunnel active ─────────────────────────────────────────\n"
            f"  │  address  : bore.pub:{p}\n"
            f"{disc_line}"
            f"  │\n"
            f"  │  Share this with anyone who wants to connect:\n"
            f"  │\n"
            f"  │    1. cd {_root}\n"
            f"  │    2. python noeyes.py --connect bore.pub --port {p} --key-file {_key}\n"
            f"  │\n"
            f"  │  They also need a copy of the key file ({_key})\n"
            f"  └──────────────────────────────────────────────────────────────\n"
        ), flush=True)

    def _migration_loop():
        """
        Bore lifecycle loop — start tunnel, watch for unexpected death, restart.
        Posts the current port to the discovery service on each (re)start
        so clients can find the new port automatically.
        """
        current_proc = None

        while True:
            # ── Launch / restart tunnel ───────────────────────────────────
            if current_proc is None or current_proc.poll() is not None:
                if current_proc is not None:
                    code = current_proc.poll()
                    print(utils.cwarn(
                        f"[bore] tunnel died (exit {code}) — restarting…"
                    ), flush=True)
                try:
                    proc, assigned = _launch_tunnel()
                except Exception as e:
                    print(utils.cgrey(f"[bore] failed to start: {e}"), flush=True)
                    _time.sleep(5)
                    continue

                if assigned is None:
                    print(utils.cwarn("[bore] timed out waiting for port — retrying in 5s…"), flush=True)
                    try: proc.kill()
                    except Exception: pass
                    _time.sleep(5)
                    continue

                current_proc = proc
                _print_banner(assigned)
                if not no_discovery and discovery_key:
                    _discovery_post(discovery_key, assigned)
                else:
                    print(utils.cgrey(
                        f"[bore] new port: {assigned} — discovery disabled, share address manually."
                    ), flush=True)

            # ── Poll for unexpected death every 100 ms ────────────────────
            _time.sleep(0.1)

    threading.Thread(target=_migration_loop, daemon=True).start()


def _check_port_available(port: int) -> "int | bool":
    """
    Check if *port* is free to bind.
    If already in use, shows who owns it and asks:
      k  — kill that process and keep the port
      p  — pick a different port
      q  — quit
    Returns True (port free), int (new port chosen), or False (quit).
    Cross-platform: Windows, Linux, macOS.
    """
    import socket as _sock
    import subprocess as _sp
    import re as _re
    import sys as _sys
    import time as _t

    def _is_free(p: int) -> bool:
        with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
            s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", p))
                return True
            except OSError:
                return False

    def _who_owns(p: int) -> "tuple[str, str]":
        """Return (display_str, pid_str) for the process bound to *p*, or ('','')."""
        pid = ""
        cmd = ""
        try:
            if _sys.platform == "win32":
                # netstat on Windows: "  TCP  0.0.0.0:5000  ...  LISTENING  1234"
                out = _sp.check_output(
                    ["netstat", "-ano", "-p", "TCP"],
                    stderr=_sp.DEVNULL, text=True
                )
                for line in out.splitlines():
                    if f":{p} " in line and "LISTEN" in line:
                        parts = line.split()
                        pid = parts[-1] if parts[-1].isdigit() else ""
                        break
                if pid:
                    out2 = _sp.check_output(
                        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                        stderr=_sp.DEVNULL, text=True
                    ).strip()
                    if out2:
                        cmd = out2.split(",")[0].strip('"')
            else:
                # Try ss first (Linux), fall back to netstat (macOS/older Linux/BSD)
                for argv in (
                    ["ss", "-tlnp", f"sport = :{p}"],
                    ["netstat", "-tlnp"],
                    ["netstat", "-anp", "tcp"],   # macOS
                ):
                    try:
                        out = _sp.check_output(argv, stderr=_sp.DEVNULL, text=True)
                    except FileNotFoundError:
                        continue
                    for line in out.splitlines():
                        if str(p) not in line:
                            continue
                        # ss style: pid=1234
                        m = _re.search(r'pid=(\d+)', line)
                        if m:
                            pid = m.group(1)
                            break
                        # netstat style: last column is PID/cmd
                        m2 = _re.search(r' (\d+)/(\S+)\s*$', line)
                        if m2:
                            pid, cmd = m2.group(1), m2.group(2)
                            break
                    if pid:
                        break
                if pid and not cmd:
                    try:
                        cmd = _sp.check_output(
                            ["ps", "-p", pid, "-o", "comm="],
                            stderr=_sp.DEVNULL, text=True
                        ).strip()
                    except Exception:
                        cmd = "?"
        except Exception:
            pass
        if pid:
            label = f"PID {pid}" + (f" ({cmd})" if cmd else "")
            return label, pid
        return "", ""

    def _kill_pid(pid: str) -> bool:
        """Terminate a process by PID. Cross-platform."""
        try:
            if _sys.platform == "win32":
                _sp.run(["taskkill", "/F", "/PID", pid],
                        capture_output=True)
                _t.sleep(0.4)
            else:
                import os as _os, signal as _sig
                ipid = int(pid)
                _os.kill(ipid, _sig.SIGTERM)
                _t.sleep(0.8)
                try:
                    _os.kill(ipid, 0)   # still alive?
                    _os.kill(ipid, _sig.SIGKILL)
                    _t.sleep(0.3)
                except ProcessLookupError:
                    pass
        except Exception:
            pass
        return True   # best-effort; caller checks _is_free()

    if _is_free(port):
        return True

    owner_str, pid = _who_owns(port)
    print(utils.cwarn(
        f"\n[!] Port {port} is already in use"
        + (f" — {owner_str}" if owner_str else "") + ".\n"
        f"    What would you like to do?\n"
        f"      k  — kill the process holding the port\n"
        f"      p  — choose a different port\n"
        f"      q  — quit\n"
    ))

    while True:
        try:
            choice = input("  Your choice [k/p/q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "q"

        if choice == "q":
            print(utils.cwarn("[!] Aborted."))
            return False

        elif choice == "k":
            if not pid:
                _, pid = _who_owns(port)
            if pid:
                _kill_pid(pid)
                if _is_free(port):
                    print(utils.cinfo(f"[+] Process {pid} terminated — port {port} is now free."))
                    return True
                print(utils.cwarn(f"[!] Port {port} still occupied after kill attempt."))
            else:
                print(utils.cwarn("[!] Could not determine PID — kill manually or choose 'p'."))

        elif choice == "p":
            while True:
                try:
                    raw = input("  New port number: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print(utils.cwarn("[!] Aborted."))
                    return False
                if raw.isdigit() and 1 <= int(raw) <= 65535:
                    np = int(raw)
                    if _is_free(np):
                        return np
                    who2, _ = _who_owns(np)
                    print(utils.cwarn(
                        f"[!] Port {np} is also in use"
                        + (f" ({who2})" if who2 else "") + " — try another."
                    ))
                else:
                    print(utils.cwarn("[!] Enter a number between 1 and 65535."))
        else:
            print("  Please enter k, p, or q.")


def run_server(cfg: dict) -> None:
    import atexit, signal as _signal, hashlib as _hl
    from network.server import NoEyesServer

    # ── Port availability check ───────────────────────────────────────────────
    _avail = _check_port_available(cfg["port"])
    if _avail is False:
        sys.exit(0)
    if isinstance(_avail, int) and not isinstance(_avail, bool):
        cfg["port"] = _avail

    _port       = cfg["port"]
    _no_fw      = cfg.get("no_firewall", False)

    # Derive discovery key from the shared group key so server and clients
    # independently compute the same lookup key without any coordination.
    # Only attempt this if a key file or key was actually provided —
    # the server is a blind forwarder and does not require the key to run.
    _disc_key = ""
    if not cfg.get("no_discovery") and (cfg.get("key_file") or cfg.get("key")):
        try:
            _fernet, _key_bytes = _resolve_fernet(cfg)
            _disc_key = _hl.sha256(_key_bytes).hexdigest()[:24]
        except SystemExit:
            raise
        except Exception:
            _disc_key = ""
    elif not cfg.get("no_discovery") and not (cfg.get("key_file") or cfg.get("key")):
        print(utils.cgrey(
            "[discovery] no key file provided — port discovery disabled.\n"
            "            Pass --key-file to enable automatic port discovery."
        ))

    # Open firewall rule for the server port (skip if --no-firewall)
    if not _no_fw:
        fw.open_port(_port)
        atexit.register(fw.close_port, _port)

    # Also close on SIGINT / SIGTERM so Ctrl-C and kill both clean up
    def _sig_handler(signum, frame):
        if not _no_fw:
            fw.close_port(_port)
        # Stop the asyncio event loop cleanly — sys.exit() inside a signal
        # handler races with asyncio's internal exception handling and can
        # get swallowed, leaving the server running.  Stopping the loop
        # makes serve_forever() return, which unwinds _main() and lets
        # asyncio.run() exit normally.
        loop = getattr(server, "_loop", None)
        if loop and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        else:
            sys.exit(0)
    try:
        _signal.signal(_signal.SIGINT,  _sig_handler)
        _signal.signal(_signal.SIGTERM, _sig_handler)
    except (OSError, ValueError):
        pass  # signal setup can fail inside threads; atexit still covers it

    server = NoEyesServer(
        host="0.0.0.0",
        port=cfg["port"],
        history_size=cfg["history_size"],
        rate_limit_per_minute=cfg["rate_limit_per_minute"],
        ssl_cert=cfg.get("cert") or "",
        ssl_key=cfg.get("tls_key") or "",
        no_tls=cfg.get("no_tls", False),
    )

    if cfg.get("daemon"):
        _daemonize()

    if cfg.get("no_bore"):
        # --no-bore was passed: skip the tunnel entirely and explain why that
        # can be the right choice (LAN server, static IP, custom tunnel, etc.).
        print(utils.cgrey(
            "[bore] tunnel disabled via --no-bore.\n"
            "       Clients on the same network can connect directly:\n"
            f"       python noeyes.py --connect <YOUR-IP> --port {cfg['port']} --key-file ./chat.key"
        ))
    else:
        _start_bore(cfg["port"], discovery_key=_disc_key, no_discovery=cfg.get("no_discovery", False))

    server.run()


TLS_TOFU_PATH = "~/.noeyes/tls_fingerprints.json"


def _resolve_tls_for_client(host: str, port: int, no_tls: bool) -> tuple:
    """
    Resolve TLS settings for a client connection.

    Returns (tls: bool, tls_cert: str) where tls_cert is a path to the
    server's cert if we have it cached, or empty string to use TOFU mode.

    How it works:
      1. Client connects with TLS but without certificate verification
         (check_hostname=False, verify_mode=CERT_NONE).
      2. After the handshake, it reads the server's cert fingerprint.
      3. On first connection: stores the fingerprint and trusts it.
      4. On subsequent connections: verifies the fingerprint matches.
      5. If fingerprint changed: warns the user (possible MITM).

    This mirrors SSH host-key verification — transport is always encrypted,
    and the server's identity is pinned after first contact.
    """
    if no_tls:
        return False, ""
    return True, ""   # tls=True, cert="" → client uses TOFU mode


def run_client(cfg: dict) -> None:
    import hashlib as _hl
    from network.client import NoEyesClient

    group_fernet, group_key_bytes = _resolve_fernet(cfg)
    username     = _get_username(cfg)

    no_tls = cfg.get("no_tls", False)
    tls, tls_cert = _resolve_tls_for_client(cfg["connect"], cfg["port"], no_tls)

    disc_key = _hl.sha256(group_key_bytes).hexdigest()[:24] if group_key_bytes else ""

    client = NoEyesClient(
        host=cfg["connect"],
        port=cfg["port"],
        username=username,
        group_fernet=group_fernet,
        group_key_bytes=group_key_bytes,
        room=cfg["room"],
        identity_path=cfg["identity_path"],
        tofu_path=cfg["tofu_path"],
        tls=tls,
        tls_cert=tls_cert,
        tls_tofu_path=TLS_TOFU_PATH,
        discovery_key=disc_key,
        no_discovery=cfg.get("no_discovery", False),
    )
    client.run()


def run_gen_key(cfg: dict) -> None:
    path = cfg.get("key_file")
    if not path:
        print(utils.cerr("[error] --gen-key requires --key-file PATH"))
        sys.exit(1)
    enc.generate_key_file(path)


def _daemonize() -> None:
    """Double-fork to create a background daemon (Unix only)."""
    if os.name != "posix":
        print(utils.cwarn("[warn] --daemon is not supported on Windows; ignoring."))
        return
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    sys.stdin  = open(os.devnull)
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")


def main(argv=None) -> None:
    cfg = cfg_mod.load_config(argv)

    if cfg["gen_key"]:
        run_gen_key(cfg)
        return

    if cfg["server"]:
        fw.check_stale()
        run_server(cfg)
        return

    if cfg["connect"]:
        run_client(cfg)
        return

    # No mode selected
    cfg_mod.build_arg_parser().print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
