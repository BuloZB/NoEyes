#!/usr/bin/env python
"""
launch.py — NoEyes interactive launcher.

Guides beginners through server setup and client connection with a
pretty terminal UI. Arrow keys to navigate, Enter to select.

Usage:
    python launch.py
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path

# Make sure the project root (parent of ui/) is on the path so core.firewall works
_PROJECT_ROOT = str(Path(__file__).parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from core import firewall as fw

# Compatibility: termios / tty only exist on Unix.
# On Windows we fall back to msvcrt for raw keypress reading.
try:
    import termios
    import tty
    _UNIX = True
except ImportError:
    import msvcrt
    _UNIX = False

# ── ANSI colours ─────────────────────────────────────────────────────────────

def _tty(): return os.isatty(sys.stdout.fileno())

R  = "\033[0m"          # reset
B  = "\033[1m"          # bold
DIM= "\033[2m"          # dim
CY = "\033[96m"         # cyan
GR = "\033[92m"         # green
YL = "\033[93m"         # yellow
RD = "\033[91m"         # red
BL = "\033[94m"         # blue
MG = "\033[95m"         # magenta
GY = "\033[90m"         # grey

def cy(s):  return f"{CY}{s}{R}" if _tty() else s
def gr(s):  return f"{GR}{s}{R}" if _tty() else s
def yl(s):  return f"{YL}{s}{R}" if _tty() else s
def rd(s):  return f"{RD}{s}{R}" if _tty() else s
def bl(s):  return f"{BL}{s}{R}" if _tty() else s
def mg(s):  return f"{MG}{s}{R}" if _tty() else s
def gy(s):  return f"{GY}{s}{R}" if _tty() else s
def bo(s):  return f"{B}{s}{R}"  if _tty() else s
def dim(s): return f"{DIM}{s}{R}" if _tty() else s

# ── Terminal helpers ──────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def hide_cursor():
    if _tty(): sys.stdout.write("\033[?25l"); sys.stdout.flush()

def show_cursor():
    if _tty(): sys.stdout.write("\033[?25h"); sys.stdout.flush()

def getch() -> str:
    """
    Read a single keypress from the raw file descriptor.

    On Unix: uses os.read(fd, 1) via termios/tty so Python's internal stdio
    buffer stays empty and select() remains accurate.
    On Windows: uses msvcrt.getwch() with special-key handling.

    Handles both escape sequence formats terminals send for arrows/scroll:
      CSI  ESC [ A/B/C/D        — standard xterm / most terminals
      SS3  ESC O A/B/C/D        — Konsole application-cursor / scroll wheel
    Extended CSI sequences (shifted arrows, F-keys, mouse) are consumed
    silently so nothing leaks into the menu as printable characters.
    """
    if not _UNIX:
        # Windows path — msvcrt.getwch() returns a single character.
        # Arrow / special keys send two calls: first '\x00' or '\xe0', then the key code.
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            code = msvcrt.getwch()
            return {"H": "UP", "P": "DOWN", "M": "RIGHT", "K": "LEFT"}.get(code, "ESC")
        if ch == "\r":
            return "\n"
        return ch

    import select as _sel
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        ch = os.read(fd, 1).decode("utf-8", errors="replace")
        if ch != "\x1b":
            return ch

        # ESC received — peek for more bytes
        r, _, _ = _sel.select([fd], [], [], 0.05)
        if not r:
            return "ESC"   # lone ESC

        nxt = os.read(fd, 1).decode("utf-8", errors="replace")

        if nxt == "[":
            # CSI sequence — read until alphabetic terminator or ~
            param = ""
            while True:
                r2, _, _ = _sel.select([fd], [], [], 0.05)
                if not r2:
                    break
                b = os.read(fd, 1).decode("utf-8", errors="replace")
                if b.isalpha() or b == "~":
                    param += b
                    break
                param += b
            final = param[-1] if param else ""
            if final == "A": return "UP"
            if final == "B": return "DOWN"
            if final == "C": return "RIGHT"
            if final == "D": return "LEFT"
            return "ESC"

        elif nxt == "O":
            # SS3 sequence — exactly one more byte
            r2, _, _ = _sel.select([fd], [], [], 0.05)
            if r2:
                fin = os.read(fd, 1).decode("utf-8", errors="replace")
                if fin == "A": return "UP"
                if fin == "B": return "DOWN"
                if fin == "C": return "RIGHT"
                if fin == "D": return "LEFT"
            return "ESC"

        return "ESC"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def input_line(prompt: str, default: str = "") -> str:
    """
    Prompt for a line of text with full arrow key support.

    On Unix: uses os.read(fd,1) so escape sequences are consumed silently.
    On Windows: uses msvcrt.getwch() for raw character reading.
    Left/right arrows move the cursor. Up arrow fills the default.
    """
    hint = f" {gy(f'[{default}]')}" if default else " "
    sys.stdout.write(f"\n{prompt}{hint}")
    sys.stdout.flush()

    buf = []   # list of chars
    cur = 0    # cursor position

    def _redraw():
        line = "".join(buf)
        sys.stdout.write("\r" + prompt + hint + line + "\033[K")
        offset = len(hint) + len(prompt) + cur - len(buf)
        if offset < 0:
            sys.stdout.write(f"\033[{-offset}D")
        sys.stdout.flush()

    show_cursor()

    if not _UNIX:
        # Windows path using msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n"); sys.stdout.flush(); break
            elif ch == "\x03":
                sys.stdout.write("\n"); sys.stdout.flush()
                raise KeyboardInterrupt
            elif ch == "\x04":
                sys.stdout.write("\n"); sys.stdout.flush()
                raise EOFError
            elif ch in ("\x7f", "\x08"):
                if cur > 0:
                    buf.pop(cur - 1); cur -= 1; _redraw()
            elif ch in ("\x00", "\xe0"):
                code = msvcrt.getwch()
                if code == "K" and cur > 0:       # left
                    cur -= 1; _redraw()
                elif code == "M" and cur < len(buf):  # right
                    cur += 1; _redraw()
                elif code == "H" and not buf and default:  # up → default
                    buf[:] = list(default); cur = len(buf); _redraw()
            elif ch >= " ":
                buf.insert(cur, ch); cur += 1; _redraw()
        hide_cursor()
        result = "".join(buf).strip()
        return result if result else default

    import select as _sel
    fd  = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    def _rb() -> str:
        return os.read(fd, 1).decode("utf-8", errors="replace")

    try:
        tty.setcbreak(fd)
        while True:
            ch = _rb()

            if ch in ("\n", "\r"):
                sys.stdout.write("\n"); sys.stdout.flush(); break

            elif ch == "\x03":
                sys.stdout.write("\n"); sys.stdout.flush()
                raise KeyboardInterrupt

            elif ch == "\x04":
                sys.stdout.write("\n"); sys.stdout.flush()
                raise EOFError

            elif ch in ("\x7f", "\x08"):   # backspace
                if cur > 0:
                    buf.pop(cur - 1); cur -= 1; _redraw()

            elif ch == "\x1b":             # escape sequence
                r, _, _ = _sel.select([fd], [], [], 0.05)
                if not r: continue
                nxt = _rb()
                if nxt in ("[", "O"):      # CSI or SS3
                    r2, _, _ = _sel.select([fd], [], [], 0.05)
                    if not r2: continue
                    fin = _rb()
                    if fin == "D" and cur > 0:              # left
                        cur -= 1; _redraw()
                    elif fin == "C" and cur < len(buf):     # right
                        cur += 1; _redraw()
                    elif fin == "A" and not buf and default: # up → default
                        buf[:] = list(default); cur = len(buf); _redraw()
                    elif not (fin.isalpha() or fin == "~"):
                        while True:
                            r3, _, _ = _sel.select([fd], [], [], 0.05)
                            if not r3: break
                            b = _rb()
                            if b.isalpha() or b == "~": break

            elif ch >= " ":                # printable
                buf.insert(cur, ch); cur += 1; _redraw()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    hide_cursor()
    result = "".join(buf).strip()
    return result if result else default

def confirm(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    sys.stdout.write(f"{prompt} {gy(f'[{hint}]')}: ")
    sys.stdout.flush()
    show_cursor()
    try:
        val = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        val = ""
    hide_cursor()
    if val == "": return default
    return val in ("y", "yes")

# ── UI components ─────────────────────────────────────────────────────────────

LOGO = f"""{cy(B)}
  ███╗   ██╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
  ████╗  ██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ██╔██╗ ██║██║   ██║█████╗   ╚████╔╝ █████╗  ███████╗
  ██║╚██╗██║██║   ██║██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║ ╚████║╚██████╔╝███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝{R}
{gy("  Secure Terminal Chat  │  End-to-End Encrypted  │  Blind-Forwarder Server")}
"""

def _strip_ansi(s: str) -> str:
    """Return visible length of a string (strips ANSI escape codes)."""
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

def box(title: str, lines: list, width: int = 0, colour=cy) -> str:
    """Render a labelled box. Width auto-sizes from content if width=0."""
    # Calculate minimum width needed to fit title and all lines
    min_w = max(
        len(_strip_ansi(title)) + 4,
        *[len(_strip_ansi(l)) + 4 for l in lines] if lines else [0],
        40  # minimum box width
    )
    if width == 0 or width < min_w:
        width = min_w

    # Pad each line to visible width (accounting for ANSI codes)
    def pad_line(l):
        visible = len(_strip_ansi(l))
        padding = width - 4 - visible
        return l + (" " * max(0, padding))

    top   = f"  {colour('╭')}{'─' * (width-2)}{colour('╮')}"
    label = f"  {colour('│')} {bo(title)}{' ' * (width - 4 - len(_strip_ansi(title)))} {colour('│')}"
    sep   = f"  {colour('├')}{'─' * (width-2)}{colour('┤')}"
    body  = "\n".join(f"  {colour('│')} {pad_line(l)} {colour('│')}" for l in lines)
    bot   = f"  {colour('╰')}{'─' * (width-2)}{colour('╯')}"
    return "\n".join([top, label, sep, body, bot])

def status_box(checks: list) -> str:
    """Render a status checklist. checks = [(label, ok, detail), ...]"""
    lines = []
    for label, ok, detail in checks:
        icon  = gr("✔") if ok else rd("✘")
        det   = gy(f"  {detail}") if detail else ""
        lines.append(f"{icon}  {label}{det}")
    return box("System Status", lines, width=62)

def menu(title: str, options: list, selected: int = 0) -> int:
    """
    Interactive arrow-key menu. Returns index of chosen option.
    options = [(label, description), ...]
    """
    hide_cursor()
    while True:
        clear()
        print(LOGO)
        print(f"  {bo(title)}\n")
        for i, (label, desc) in enumerate(options):
            if i == selected:
                prefix = f"  {cy('❯')} {cy(bo(label))}"
                suffix = f"  {cy(desc)}" if desc else ""
            else:
                prefix = f"    {gy(label)}"
                suffix = f"  {gy(desc)}" if desc else ""
            print(f"{prefix}{suffix}")
        print(f"\n  {gy('↑ ↓  navigate    Enter  select    Ctrl+C  quit')}")

        key = getch()
        if key in ("UP",   "k"): selected = (selected - 1) % len(options)
        elif key in ("DOWN","j"): selected = (selected + 1) % len(options)
        elif key in ("\r", "\n", "\x0a"): return selected
        elif key == "\x03": raise KeyboardInterrupt

# ── Dependency check ──────────────────────────────────────────────────────────

def check_deps() -> dict:
    checks = {}

    # cryptography
    try:
        import cryptography  # noqa: F401
        checks["cryptography"] = True
    except ImportError:
        checks["cryptography"] = False

    # bore (optional)
    checks["bore"] = bool(shutil.which("bore"))

    # noeyes files
    root = Path(__file__).parent.parent
    checks["noeyes"] = all(
        (root / f).exists()
        for f in ("noeyes.py", "network/server.py", "network/client.py", "core/encryption.py")
    )

    return checks

def install_cryptography():
    print(f"\n  {yl('Installing cryptography...')}\n")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", "cryptography",
         "--break-system-packages"],
        capture_output=False)
    return r.returncode == 0

# ── Key management ────────────────────────────────────────────────────────────

DEFAULT_KEY = "./chat.key"

def find_key_files() -> list:
    """Return .key files in the current directory and home."""
    found = []
    for p in Path(".").glob("*.key"):
        found.append(str(p))
    home_key = Path("~/.noeyes/chat.key").expanduser()
    if home_key.exists() and str(home_key) not in found:
        found.append(str(home_key))
    return found

def generate_key_flow() -> str:
    """Guide user through generating a new key file. Returns path."""
    clear()
    print(LOGO)
    print(box("Generate Shared Key", [
        "All participants need the same key file to communicate.",
        "Generate it once, then share it with everyone via:",
        "",
        gy("  • USB drive"),
        gy("  • Signal / WhatsApp"),
        gy("  • Encrypted email"),
        "",
        rd("  Never share it over NoEyes itself or in plaintext."),
    ], colour=gr))
    print()
    path = input_line(f"  {bo('Save key to')}", DEFAULT_KEY)
    if not path.endswith(".key"):
        path += ".key"

    root = Path(__file__).parent.parent
    noeyes = root / "noeyes.py"
    r = subprocess.run(
        [sys.executable, str(noeyes), "--gen-key", "--key-file", path],
        capture_output=True, text=True)

    if r.returncode == 0:
        print(f"\n  {gr('✔')} Key saved to {bo(path)}")
        size = Path(path).stat().st_size
        print(f"  {gy(f'  {size} bytes — copy this file to all participants')}")
    else:
        print(f"\n  {rd('✘')} Failed: {r.stderr.strip()}")
    return path

# ── Server setup flow ─────────────────────────────────────────────────────────

def server_flow(deps: dict):
    clear()
    print(LOGO)

    # Key file
    keys = find_key_files()
    if keys:
        key_path = keys[0]
        print(box("Start Server", [
            gr(f"✔  Key found: {key_path}"),
            "",
            "The server does NOT need the key — it never decrypts anything.",
            "The key is only needed by connecting clients.",
        ], colour=cy))
    else:
        print(box("Start Server", [
            rd("✘  No key file found."),
            "",
            "Generate one first, then share it with your participants.",
        ], colour=rd))
        print()
        if confirm(f"  {bo('Generate a key now?')}"):
            key_path = generate_key_flow()
        else:
            return

    print()
    env_port = os.environ.get("NOEYES_PORT", "")
    port = input_line(f"  {bo('Port')}", env_port or "5000")
    try:
        port = int(port)
    except ValueError:
        port = 5000

    history_raw = input_line(f"  {bo('Message history size')} {gy('(lines replayed to new clients)')}", "50")
    try:
        history_size = max(0, int(history_raw))
    except ValueError:
        history_size = 50

    rate_raw = input_line(f"  {bo('Rate limit')} {gy('(messages per client per minute)')}", "30")
    try:
        rate_limit = max(1, int(rate_raw))
    except ValueError:
        rate_limit = 30

    if os.environ.get("NOEYES_NO_BORE"):
        use_bore = False
    elif deps["bore"]:
        print(f"\n  {gy('bore is installed — the server can be reached from anywhere.')}")
        use_bore = confirm(f"  {bo('Enable bore tunnel?')} (allows internet access)", True)
    else:
        print(f"\n  {gy('bore not installed — LAN/local connections only.')}")
        print(f"  {gy('Install bore for internet access: https://github.com/ekzhang/bore')}")
        use_bore = False

    use_discovery = True
    if use_bore:
        clear()
        print(LOGO)
        disc_explain = [
            "When bore.pub kills the tunnel and the server restarts with a",
            "new port, clients cannot reconnect without the new address.",
            "",
            f"  {gr('With discovery enabled')} NoEyes automatically posts the current",
            "  bore port to a free anonymous key-value store so clients",
            "  reconnect without any manual action.",
            "",
            "  An app-key is provisioned automatically on first run —",
            "  no email, no account, no setup needed.",
            "",
            "  Disable only if you want no external HTTP calls.",
        ]
        print(box("Bore Port Discovery (recommended)", disc_explain, colour=cy))
        print()
        use_discovery = confirm(f"  {bo('Enable automatic port discovery?')}", True)


    # Firewall rule — optional, with explanation
    clear()
    print(LOGO)
    fw_explain = [
        f"NoEyes can add a firewall rule to open port {bo(str(port))} on this machine.",
        "",
        f"  {gr('You need this if')} clients connect to your IP directly",
        f"  (LAN connections, static IP, or manual port forwarding).",
        "",
        f"  {yl('You do NOT need this if')} you are using bore tunnel —",
        "  clients connect via bore.pub and never touch your firewall.",
        "",
        "  You can also skip this and manage your firewall yourself.",
    ]
    print(box("Firewall Rule", fw_explain, colour=cy))
    print()
    if use_bore:
        print(f"  {gy('Bore tunnel is enabled — firewall rule is not required.')}")
        print()
    open_firewall = confirm(f"  {bo('Add firewall rule for port')} {bo(str(port))}{'?' if not use_bore else ' (optional since bore is on)?'}", default=not use_bore)

    # Summary box
    clear()
    print(LOGO)
    bore_line = gr("✔  bore tunnel enabled (internet accessible)") if use_bore else gy("—  LAN / local only (--no-bore)")
    if use_bore and use_discovery:
        bore_line += gr("  · auto-discovery on")
    elif use_bore:
        bore_line += yl("  · auto-discovery off (--no-discovery)")
    fw_line   = gr(f"✔  rule will be added for port {port}") if open_firewall else gy(f"—  skipped (--no-firewall)")
    print(box("Server Ready to Start", [
        f"Port       :  {bo(str(port))}",
        f"Tunnel     :  {bore_line}",
        f"Firewall   :  {fw_line}",
        "",
        "The server is a blind forwarder — it cannot read any messages.",
        "Clients connect with their key file and can start chatting.",
    ], colour=gr))
    print()

    if not confirm(f"  {bo('Start server now?')}"):
        return

    root = Path(__file__).parent.parent
    noeyes = root / "noeyes.py"

    # Write server-tuning values to a temp config file (no CLI flags exist for them)
    import tempfile, json as _json
    _cfg_data = {"history_size": history_size, "rate_limit_per_minute": rate_limit}
    _tmp_cfg  = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="noeyes_launch_", delete=False
    )
    _json.dump(_cfg_data, _tmp_cfg)
    _tmp_cfg.close()

    cmd = [sys.executable, str(noeyes), "--server", "--port", str(port),
           "--config", _tmp_cfg.name]
    if key_path:
        cmd.extend(["--key-file", str(key_path)])
    if not use_bore:
        cmd.append("--no-bore")
    if use_bore and not use_discovery:
        cmd.append("--no-discovery")
    if not open_firewall:
        cmd.append("--no-firewall")
    if os.environ.get("NOEYES_NO_TLS"):
        cmd.append("--no-tls")

    print(f"\n  {cy('Starting server...')}\n")
    show_cursor()
    try:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"\n  {rd('Server exited with error code')} {result.returncode}")
            input("\n  Press Enter to return to menu...")
    except KeyboardInterrupt:
        pass
    finally:
        # Clean up the temp config file
        try:
            import os as _os
            _os.unlink(_tmp_cfg.name)
        except Exception:
            pass
        # Surface stale port cleanup after server exits
        fw.check_stale()

# ── Client connection flow ────────────────────────────────────────────────────

def client_flow():
    """
    Interactive connect flow.

    Environment variable shortcuts (used by demo scripts and power users
    running multiple clients on the same machine — beginners never see them):

      NOEYES_HOST          pre-fill server address    (skips host prompt)
      NOEYES_PORT          pre-fill port              (skips port prompt)
      NOEYES_USERNAME      pre-fill username          (skips username prompt)
      NOEYES_KEY_FILE      path to key file           (skips key detection)
      NOEYES_IDENTITY_PATH identity keypair path
      NOEYES_TOFU_PATH     TOFU store path
      NOEYES_NO_TLS        disable TLS

    If ALL required vars (HOST, PORT, USERNAME, KEY_FILE) are set, the flow
    skips all prompts and connects immediately.
    """
    # Read env var overrides
    env_host     = os.environ.get("NOEYES_HOST", "")
    env_port     = os.environ.get("NOEYES_PORT", "")
    env_username = os.environ.get("NOEYES_USERNAME", "")
    env_keyfile  = os.environ.get("NOEYES_KEY_FILE", "")

    autoconnect = all([env_host, env_port, env_username, env_keyfile])

    if not autoconnect:
        clear()
        print(LOGO)
        print(box("Connect to Server", [
            "You need:",
            "",
            gy("  1. The server's IP address or hostname"),
            gy("  2. The port number"),
            gy("  3. The shared key file (.key)"),
            "",
            "Ask the server host to share these with you.",
        ], colour=bl))
        print()

    host_raw = env_host or input_line(f"  {bo('Server address')}", "")
    if not host_raw:
        print(f"\n  {rd(chr(0x2718))} No address entered. Cancelled.")
        input(f"\n  {gy('Press Enter to go back...')}")
        return

    # Allow host:port shorthand (e.g. bore.pub:48255)
    _port_from_host = None
    if ":" in host_raw and not host_raw.startswith("["):
        _parts = host_raw.rsplit(":", 1)
        if _parts[1].isdigit():
            host = _parts[0]
            _port_from_host = int(_parts[1])
        else:
            host = host_raw
    else:
        host = host_raw

    try:
        _port_input = env_port or (_port_from_host is not None and str(_port_from_host)) or input_line(f"  {bo('Port')}", "5000")
        port = int(_port_input)
        if not (0 < port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        print(f"\n  {yl('Invalid port — defaulting to 5000.')}")
        port = 5000

    username = env_username or input_line(f"  {bo('Your username')}", "")

    # Key file
    if env_keyfile:
        key_path = env_keyfile
    else:
        keys = find_key_files()
        if keys:
            print(f"\n  {gy('Key files found:')}")
            for i, k in enumerate(keys):
                print(f"    {cy(str(i+1))}  {k}")
            choice = input_line(f"  {bo('Choose key file (number or path)')}", "1")
            try:
                idx = int(choice) - 1
                key_path = keys[idx] if 0 <= idx < len(keys) else choice
            except ValueError:
                key_path = choice
        else:
            print(f"\n  {yl('No key file found in current directory.')}")
            key_path = input_line(f"  {bo('Path to key file')}", "./chat.key")

    if not Path(key_path).exists():
        print(f"\n  {rd('✘')} Key file not found: {key_path}")
        print(f"  {gy('Get the .key file from your server host and try again.')}")
        input(f"\n  {gy('Press Enter to go back...')}")
        return

    # Summary
    clear()
    print(LOGO)
    print(box("Connecting", [
        f"Server     :  {bo(host)}:{bo(str(port))}",
        f"Username   :  {bo(username) if username else gy('(will prompt)')}",
        f"Key file   :  {bo(key_path)}",
        "",
        gr("Messages are end-to-end encrypted."),
        gr("The server cannot read any of your messages."),
    ], colour=bl))
    print()

    root = Path(__file__).parent.parent
    noeyes = root / "noeyes.py"
    cmd = [sys.executable, str(noeyes), "--connect", host,
           "--port", str(port), "--key-file", key_path]
    if username:
        cmd += ["--username", username]
    if os.environ.get("NOEYES_IDENTITY_PATH"):
        cmd += ["--identity-path", os.environ["NOEYES_IDENTITY_PATH"]]
    if os.environ.get("NOEYES_TOFU_PATH"):
        cmd += ["--tofu-path", os.environ["NOEYES_TOFU_PATH"]]
    if os.environ.get("NOEYES_NO_TLS"):
        cmd += ["--no-tls"]

    print(f"  {cy('Connecting...')}\n")
    show_cursor()
    try:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"\n  {rd('Connection exited with error code')} {result.returncode}")
            input("\n  Press Enter to return to menu...")
    except KeyboardInterrupt:
        pass

# ── About screen ──────────────────────────────────────────────────────────────

def about_screen():
    clear()
    print(LOGO)
    print(box("How NoEyes Works", [
        bo("Blind-Forwarder Server"),
        "  The server only sees who sent what to which room.",
        "  It forwards encrypted bytes it cannot decrypt.",
        "",
        bo("Group Chat"),
        "  Each room has its own key derived via HKDF.",
        "  Rooms are cryptographically isolated.",
        "",
        bo("Private Messages  (/msg user text)"),
        "  X25519 DH handshake on first contact.",
        "  Pairwise key only the two of you hold.",
        "",
        bo("File Transfer  (/send user file)"),
        "  AES-256-GCM streaming, any file size.",
        "  Ed25519 signed — tamper-proof.",
        "",
        bo("Identity"),
        "  Auto-generated Ed25519 keypair in ~/.noeyes/",
        "  TOFU: first-seen keys trusted, mismatches warned.",
    ], width=62, colour=mg))
    print(f"\n  {gy('Press any key to go back...')}")
    hide_cursor()
    getch()

# ── Status screen ─────────────────────────────────────────────────────────────

def status_screen(deps: dict):
    clear()
    print(LOGO)
    checks = [
        ("cryptography installed",  deps["cryptography"],
         "" if deps["cryptography"] else "run: pip install cryptography"),
        ("bore installed (optional)", deps["bore"],
         "" if deps["bore"] else "get it at github.com/ekzhang/bore"),
        ("NoEyes files present",    deps["noeyes"],
         "" if deps["noeyes"] else "missing core files — re-clone the repo"),
    ]

    # Key files
    keys = find_key_files()
    checks.append((
        f"Key file found ({keys[0] if keys else 'none'})",
        bool(keys),
        "" if keys else "use 'Generate Key' from the main menu",
    ))

    # Identity
    id_path = Path("~/.noeyes/identity.key").expanduser()
    checks.append((
        "Identity key (~/.noeyes/identity.key)",
        id_path.exists(),
        "" if id_path.exists() else "auto-created on first connect",
    ))

    print(status_box(checks))
    print(f"\n  {gy('Press any key to go back...')}")
    hide_cursor()
    getch()

# ── Commands reference ────────────────────────────────────────────────────────

def commands_screen():
    clear()
    print(LOGO)
    cmds = [
        ("/help",              "Show all commands"),
        ("/quit",              "Disconnect and exit"),
        ("/clear",             "Clear screen"),
        ("/users",             "List users in current room"),
        ("/nick <name>",       "Change your display name"),
        ("/join <room>",       "Switch to a room"),
        ("/leave",             "Return to general room"),
        ("/msg <user> <text>", "Send encrypted private message"),
        ("/send <user> <file>","Send encrypted file"),
        ("/whoami",            "Show your key fingerprint"),
        ("/trust <user>",      "Trust a user's new key after reinstall"),
        ("/anim on|off",       "Toggle decrypt animation"),
    ]
    lines = []
    for cmd, desc in cmds:
        lines.append(f"{cy(f'{cmd:<24}')}{gy(desc)}")
    print(box("In-Chat Commands", lines, width=62, colour=cy))
    print(f"\n  {gy('Press any key to go back...')}")
    hide_cursor()
    getch()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not sys.stdin.isatty():
        print("NoEyes Launcher requires an interactive terminal.")
        sys.exit(1)

    deps = check_deps()

    # Surface stale NoEyes ports from any previous crashed session
    fw.check_stale()

    # If cryptography is missing, offer to install it before showing menu
    if not deps["cryptography"]:
        clear()
        print(LOGO)
        print(box("Missing Dependency", [
            rd("✘  The 'cryptography' package is not installed."),
            "",
            "NoEyes needs it for all encryption operations.",
            "It can be installed automatically right now.",
        ], colour=rd))
        print()
        if confirm(f"  {bo('Install cryptography now?')}"):
            if install_cryptography():
                print(f"\n  {gr('✔')} Installed successfully!")
                deps["cryptography"] = True
            else:
                print(f"\n  {rd('✘')} Installation failed.")
                print(f"  Try manually:  {cy('pip install cryptography')}")
        input(f"\n  {gy('Press Enter to continue...')}")

    OPTIONS = [
        ("🖥   Start Server",      "host a chat server others can join"),
        ("🔗  Connect to Server",  "join an existing server"),
        ("🔑  Generate Key",       "create a new shared key file"),
        ("📋  Commands",           "in-chat command reference"),
        ("ℹ   How It Works",      "security and architecture overview"),
        ("⚙   System Status",     "check dependencies and config"),
        ("✖   Quit",               ""),
    ]

    selected = 0
    while True:
        try:
            selected = menu("What do you want to do?", OPTIONS, selected)
        except KeyboardInterrupt:
            break

        try:
            if selected == 0:
                server_flow(deps)
            elif selected == 1:
                client_flow()
            elif selected == 2:
                generate_key_flow()
                input(f"\n  {gy('Press Enter to go back...')}")
            elif selected == 3:
                commands_screen()
            elif selected == 4:
                about_screen()
            elif selected == 5:
                deps = check_deps()   # refresh
                status_screen(deps)
            elif selected == 6:
                break
        except KeyboardInterrupt:
            pass   # Ctrl+C from any sub-screen returns to menu

    clear()
    show_cursor()
    fw.check_stale()
    print(f"\n  {gy('Goodbye.')}\n")


if __name__ == "__main__":
    main()
