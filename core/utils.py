# FILE: utils.py
"""
utils.py — Terminal utilities, ANSI colors, and the NoEyes TUI.

Visual design adapted from waha-tui (MIT licence, muhammedaksam/waha-tui):
  dark color palette, two-panel layout, bubble-style messages, sender colors,
  keyboard-hint footer.  All NoEyes-specific logic (tags, E2E, rooms, PMs,
  notifications) is preserved.
"""

import sys
import os
import time
import re
import random
import threading
import signal
from collections import defaultdict, Counter

# ---------------------------------------------------------------------------
# ANSI base helpers
# ---------------------------------------------------------------------------

RESET        = "\033[0m"
BOLD         = "\033[1m"
DIM          = "\033[2m"
RED          = "\033[31m"
GREEN        = "\033[32m"
YELLOW       = "\033[33m"
CYAN         = "\033[36m"
WHITE        = "\033[37m"
GREY         = "\033[90m"
PURPLE       = "\033[35m"
BRIGHT_WHITE = "\033[1;37m"

# ---------------------------------------------------------------------------
# waha-tui inspired 24-bit color palette
# ---------------------------------------------------------------------------

NE_DEEP_DARK  = "\033[48;2;11;20;26m"
NE_PANEL_DARK = "\033[48;2;17;27;33m"
NE_PANEL_LT   = "\033[48;2;32;44;51m"
NE_RECV_BG    = "\033[48;2;32;44;51m"
NE_SENT_BG    = "\033[48;2;0;88;110m"
NE_GREEN      = "\033[38;2;0;200;220m"   # cyan accent
NE_TEXT_PRI   = "\033[38;2;233;237;239m"
NE_TEXT_SEC   = "\033[38;2;134;150;160m"
NE_TEXT_TER   = "\033[38;2;102;119;129m"
NE_BORDER     = "\033[38;2;59;74;84m"

# Sender colors (waha-tui WDS 300-level palette, hash-selected per username)
_SENDER_COLORS = [
    "\033[38;2;122;227;195m",  # emerald-300
    "\033[38;2;83;189;235m",   # skyBlue-300
    "\033[38;2;255;114;161m",  # pink-300
    "\033[38;2;167;145;255m",  # purple-300
    "\033[38;2;255;210;121m",  # yellow-300
    "\033[38;2;252;151;117m",  # orange-300
    "\033[38;2;83;166;253m",   # cobalt-300
    "\033[38;2;66;199;184m",   # teal-300
    "\033[38;2;113;235;133m",  # green-300
    "\033[38;2;251;80;97m",    # red-300
    "\033[38;2;2;131;119m",    # teal-500
    "\033[38;2;94;71;222m",    # purple-500
    "\033[38;2;196;83;45m",    # orange-500
]

def _sender_color(username: str) -> str:
    return _SENDER_COLORS[hash(username) % len(_SENDER_COLORS)]

# Two-panel layout constants
_LEFT_W   = 18   # side panel width (rooms top half + users bottom half)
_DIV_W    = 1    # vertical divider
_MIN_COLS = 44   # minimum cols for two-panel mode

# Detect platform once at import time
_IS_WINDOWS = sys.platform == "win32"
_IS_TERMUX  = "com.termux" in os.environ.get("PREFIX", "") or \
              "termux"     in os.environ.get("HOME",   "").lower()

# Enable ANSI escape codes on Windows (Virtual Terminal Processing).
# This is a no-op on Windows Terminal (already enabled) but fixes plain
# cmd.exe and older PowerShell hosts.  Safe to call at import time.
if _IS_WINDOWS:
    try:
        import ctypes as _ctypes
        _kernel32 = _ctypes.windll.kernel32
        # Get current stdout console mode and OR in ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
        _handle = _kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        _mode   = _ctypes.c_ulong(0)
        if _kernel32.GetConsoleMode(_handle, _ctypes.byref(_mode)):
            _kernel32.SetConsoleMode(_handle, _mode.value | 0x0004)
        # Also set console output to UTF-8 so Unicode chars render correctly
        _kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass  # non-console environment (redirected output etc.) — ignore

# Input prompt
_PROMPT     = "\033[96m" + "▶ " + "\033[0m"
_PROMPT_VIS = 2

# ---------------------------------------------------------------------------
# Message tag system
# ---------------------------------------------------------------------------

TAGS = {
    "ok":     {"label": "✔ OK",     "color": "\033[92m",  "bold": True,  "sound": "ok"},
    "warn":   {"label": "⚡ WARN",  "color": "\033[93m",  "bold": True,  "sound": "warn"},
    "danger": {"label": "☠ DANGER", "color": "\033[91m",  "bold": True,  "sound": "danger"},
    "info":   {"label": "ℹ INFO",   "color": "\033[94m",  "bold": False, "sound": "info"},
    "req":    {"label": "↗ REQ",    "color": "\033[95m",  "bold": False, "sound": "req"},
    "?":      {"label": "? ASK",    "color": "\033[96m",  "bold": False, "sound": "ask"},
}
TAG_NAMES  = set(TAGS.keys())
TAG_PREFIX = "!"

def parse_tag(text: str) -> tuple:
    if not text.startswith(TAG_PREFIX):
        return None, text
    space = text.find(" ", 1)
    if space == -1:
        word, rest = text[1:], ""
    else:
        word, rest = text[1:space], text[space + 1:]
    if word.lower() in TAG_NAMES:
        return word.lower(), rest.strip()
    return None, text

def format_tag_badge(tag: str) -> str:
    if not tag or tag not in TAGS:
        return ""
    t     = TAGS[tag]
    color = t["color"]
    bold  = BOLD if t["bold"] else ""
    return f"[{bold}{color}{t['label']}{RESET}] "

# ---------------------------------------------------------------------------
# Notification sounds  (fully preserved)
# ---------------------------------------------------------------------------

_SOUNDS_ENABLED = True

def set_sounds_enabled(val: bool) -> None:
    global _SOUNDS_ENABLED
    _SOUNDS_ENABLED = val

def sounds_enabled() -> bool:
    return _SOUNDS_ENABLED

_SOUNDS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sfx")
_SOUND_EXTS = (".wav", ".mp3", ".ogg", ".aiff", ".flac", ".m4a")

def _find_custom_sound(sound_type: str):
    if not os.path.isdir(_SOUNDS_DIR):
        return None
    for ext in _SOUND_EXTS:
        p = os.path.join(_SOUNDS_DIR, sound_type + ext)
        if os.path.isfile(p):
            return p
    return None

def play_notification(sound_type: str) -> None:
    if not _SOUNDS_ENABLED or not _is_tty():
        return

    def _play():
        import subprocess, sys as _sys
        plat = _sys.platform
        custom = _find_custom_sound(sound_type)
        if custom:
            try:
                if plat == "darwin":
                    subprocess.run(["afplay", custom], capture_output=True, timeout=10); return
                elif plat == "win32":
                    import winsound as _ws
                    if custom.lower().endswith(".wav"):
                        _ws.PlaySound(custom, _ws.SND_FILENAME)
                    else:
                        subprocess.run(["wmplayer", "/play", "/close", custom],
                                       capture_output=True, timeout=10)
                    return
                else:
                    for player in ("paplay", "aplay", "mpg123", "ffplay", "afplay"):
                        if subprocess.run(["which", player], capture_output=True).returncode == 0:
                            subprocess.run([player, custom], capture_output=True, timeout=10)
                            return
            except Exception:
                pass
        try:
            if plat == "darwin":
                _mac = {
                    "ok":     "/System/Library/Sounds/Ping.aiff",
                    "warn":   "/System/Library/Sounds/Tink.aiff",
                    "danger": "/System/Library/Sounds/Basso.aiff",
                    "info":   "/System/Library/Sounds/Pop.aiff",
                    "req":    "/System/Library/Sounds/Hero.aiff",
                    "ask":    "/System/Library/Sounds/Bottle.aiff",
                    "normal": "/System/Library/Sounds/Funk.aiff",
                }
                snd = _mac.get(sound_type, _mac["normal"])
                if os.path.exists(snd):
                    subprocess.run(["afplay", snd], capture_output=True, timeout=3); return
            elif plat == "win32":
                import winsound as _ws
                _win = {
                    "ok": (880, 120), "warn": (440, 280), "danger": (220, 500),
                    "info": (660, 100), "req": (550, 180), "ask": (770, 130), "normal": (440, 80),
                }
                freq, dur = _win.get(sound_type, (440, 80))
                _ws.Beep(freq, dur); return
            else:
                import wave, struct, tempfile, math
                _linux = {
                    "ok": (880, 0.15), "warn": (440, 0.28), "danger": (220, 0.45),
                    "info": (660, 0.10), "req": (550, 0.18), "ask": (770, 0.13), "normal": (440, 0.08),
                }
                freq, dur = _linux.get(sound_type, (440, 0.08))
                rate = 22050; n = int(rate * dur)
                data = b"".join(
                    struct.pack("<h", int(32767 * math.sin(
                        2 * math.pi * freq * i / rate
                    ) * max(0, 1 - i / n)))
                    for i in range(n)
                )
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                    fname = f.name
                    with wave.open(f, "w") as wf:
                        wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(rate)
                        wf.writeframes(data)
                for player in ("paplay", "aplay", "afplay"):
                    if subprocess.run(["which", player], capture_output=True).returncode == 0:
                        subprocess.run([player, fname], capture_output=True, timeout=3)
                        break
                os.unlink(fname); return
        except Exception:
            pass
        _bells = {
            "ok": "\007", "warn": "\007\007", "danger": "\007\007\007",
            "info": "\007", "req": "\007\007", "ask": "\007", "normal": "",
        }
        for b in _bells.get(sound_type, ""):
            _sys.stdout.write(b); _sys.stdout.flush(); time.sleep(0.12)

    threading.Thread(target=_play, daemon=True).start()

# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------

def _is_tty() -> bool:
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False

def _set_title(text: str) -> None:
    if not _is_tty():
        return
    sys.stdout.write(f"\033]0;{text}\007")
    sys.stdout.flush()

def colorize(text: str, color: str, bold: bool = False) -> str:
    if not _is_tty():
        return text
    prefix = BOLD if bold else ""
    return f"{prefix}{color}{text}{RESET}"

def cinfo(msg: str)  -> str: return colorize(msg, CYAN)
def cwarn(msg: str)  -> str: return colorize(msg, YELLOW, bold=True)
def cerr(msg: str)   -> str: return colorize(msg, RED,    bold=True)
def cok(msg: str)    -> str: return colorize(msg, GREEN)
def cgrey(msg: str)  -> str: return colorize(msg, GREY)

def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")

# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

BANNER = (
    "\n"
    "  \u2588\u2588\u2588\u2557   \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\n"
    "  \u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\n"
    "  \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557   \u255a\u2588\u2588\u2588\u2588\u2554\u255d \u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\n"
    "  \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d    \u255a\u2588\u2588\u2554\u255d  \u2588\u2588\u2554\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\n"
    "  \u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\n"
    "  \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d   \u255a\u2550\u255d   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
    "  Secure Terminal Chat  \u2502  E2E Encrypted\n"
)

def print_banner() -> None:
    print(colorize(BANNER, CYAN, bold=True))

def _play_sfx_file(filename: str) -> None:
    """Play one of the sfx/ files (logo.mp3, crt.mp3) in background."""
    sfx_path = os.path.join(_SOUNDS_DIR, filename)
    if not os.path.isfile(sfx_path):
        return
    def _play():
        try:
            import sys as _sys
            plat = _sys.platform
            if plat == "darwin":
                import subprocess as _sp
                _sp.run(["afplay", sfx_path], capture_output=True, timeout=10)
            elif plat == "win32":
                # Use winmm MCI entirely in-process — no subprocess, no window,
                # no focus stealing. Works for both .wav and .mp3.
                import ctypes
                mci = ctypes.windll.winmm.mciSendStringW
                alias = "noeyesfx"
                sfx_escaped = sfx_path.replace("\\", "\\\\")
                mci(f'open "{sfx_escaped}" type mpegvideo alias {alias}', None, 0, 0)
                mci(f'play {alias} wait', None, 0, 0)
                mci(f'close {alias}', None, 0, 0)
            else:
                import subprocess as _sp
                for player in ("mpg123", "ffplay", "paplay", "aplay", "afplay"):
                    if _sp.run(["which", player], capture_output=True).returncode == 0:
                        _sp.run([player, sfx_path], capture_output=True, timeout=10)
                        return
        except Exception:
            pass
    threading.Thread(target=_play, daemon=True).start()

def play_startup_animation() -> None:
    """CRT boot animation — full-window cold-start. Skipped if not a TTY."""
    if not _is_tty():
        return

    import shutil as _shutil

    tw = _shutil.get_terminal_size((80, 24)).columns
    th = _shutil.get_terminal_size((80, 24)).lines

    ESC     = "\033"
    RST     = ESC + "[0m"
    BRT_WHT = ESC + "[1;37m"
    BRT_CYN = ESC + "[1;96m"
    CYN     = ESC + "[36m"
    DIM_CYN = ESC + "[2;36m"
    GRN     = ESC + "[32m"
    BRT_GRN = ESC + "[1;32m"
    DIM_GRN = ESC + "[2;32m"
    GREY    = ESC + "[90m"
    DIM_E   = ESC + "[2m"
    BOLD_E  = ESC + "[1m"
    CYANS   = [CYN, BRT_CYN, ESC + "[96m", ESC + "[1;36m"]
    FRINGE  = [ESC + "[31m", ESC + "[32m", ESC + "[34m", ESC + "[96m", ESC + "[37m"]
    GLITCH  = list("\u2588\u2593\u2592\u2591\u2584\u2580\u25a0\u25a1\u256c\u2560\u2563\u2550\u2551\xb7:!@#$%^&*")
    NOISECH = list("\u2591\u2592\u2593\u2502\u2500\u253c\u256c\xb7:;!?$#@%")

    def _goto(r, c=1):
        sys.stdout.write(f"\033[{r};{c}H")

    def _clr():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    def _fill(color, char):
        line = color + (char * tw) + RST
        buf  = "".join(f"\033[{r};1H" + line for r in range(1, th + 1))
        sys.stdout.write(buf)
        sys.stdout.flush()

    def _noise_frame():
        buf = ""
        for r in range(1, th + 1):
            buf += f"\033[{r};1H" + "".join(
                random.choice(CYANS) + random.choice(NOISECH) + RST
                for _ in range(tw)
            )
        sys.stdout.write(buf)
        sys.stdout.flush()

    # 1. Flash
    _play_sfx_file("crt.mp3")
    _clr()
    _fill(BRT_WHT, "\u2588")
    time.sleep(0.04)
    _clr()
    time.sleep(0.02)

    # 2. Glitch burst
    for _ in range(6):
        row = random.randint(1, max(1, th - 1))
        col = random.randint(1, max(1, tw - 25))
        lng = random.randint(12, min(45, tw - col + 1))
        _goto(row, col)
        sys.stdout.write("".join(
            random.choice(FRINGE) + random.choice(GLITCH) + RST
            for _ in range(lng)
        ))
        sys.stdout.flush()
        time.sleep(0.012)
    _clr()

    # 3. Phosphor ramp: black → green → cyan
    for col, char, delay in [
        (DIM_GRN, "\u2593", 0.030),
        (GRN,     "\u2593", 0.025),
        (BRT_GRN, "\u2592", 0.025),
        (CYN,     "\u2592", 0.025),
        (BRT_CYN, "\u2591", 0.020),
        (ESC + "[96m", "\u2591", 0.018),
    ]:
        _fill(col, char)
        time.sleep(delay)
    _clr()

    # 4. Static burst
    for _ in range(3):
        _noise_frame()
        time.sleep(0.035)
    _clr()

    # 5. Beam sweep
    beam  = BRT_CYN + ("\u2501" * tw) + RST
    trail = DIM_CYN + ("\u2500" * tw) + RST
    for r in range(1, th + 1):
        out = ""
        if r > 1:
            out += f"\033[{r-1};1H" + trail
        out += f"\033[{r};1H" + beam
        sys.stdout.write(out)
        sys.stdout.flush()
        time.sleep(0.007)
    time.sleep(0.04)
    _clr()

    # 6. Logo burn-in
    _play_sfx_file("logo.mp3")
    logo_lines = BANNER.split("\n")
    logo_h     = len(logo_lines)
    logo_w     = 56
    h_pad      = max(0, (tw - logo_w) // 2)
    v_start    = max(1, (th - logo_h) // 2 - 2)
    indent     = " " * h_pad

    _clr()
    cur_row = v_start
    for line in logo_lines:
        _goto(cur_row)
        cur_row += 1
        if not line.strip():
            continue
        vis = len(line)
        sys.stdout.write(indent + "".join(
            random.choice(CYANS) + random.choice(GLITCH) + RST
            for _ in range(min(vis, tw - h_pad))
        ) + "\r")
        sys.stdout.flush()
        time.sleep(0.018)
        step = max(1, vis // 6)
        for s in range(0, vis, step):
            e = min(s + step, vis)
            sys.stdout.write(
                indent +
                BRT_CYN + line[:e] + RST +
                "".join(
                    random.choice(CYANS) + random.choice(GLITCH) + RST
                    for _ in range(max(0, vis - e))
                ) + "\r"
            )
            sys.stdout.flush()
            time.sleep(0.008)
        sys.stdout.write(BRT_CYN + indent + line + RST)
        sys.stdout.flush()
        time.sleep(0.028)

    # 7. Bloom pulse
    for delay in [0.05, 0.04]:
        time.sleep(delay)
        sys.stdout.write(DIM_E);  sys.stdout.flush(); time.sleep(0.03)
        sys.stdout.write(RST);    sys.stdout.flush()

    # 8. Tagline
    tagline = "E2E Encrypted  \xb7  Blind-Forwarder Server  \xb7  Zero Trust"
    tag_col = max(1, (tw - len(tagline)) // 2)
    _goto(cur_row + 1, tag_col)
    for ch in tagline:
        sys.stdout.write(CYN + ch + RST)
        sys.stdout.flush()
        time.sleep(0.012)

    # 9. Boot status
    status = [
        ("SYS", "Ed25519 / X25519 / AES-256-GCM / Fernet"),
        ("SYS", "Blind-forwarder protocol active         "),
        ("OK ", "Identity loaded \u2014 transport armed         "),
    ]
    stat_col = max(1, (tw - 52) // 2)
    stat_row = cur_row + 3
    for tag, msg in status:
        _goto(stat_row, stat_col)
        stat_row += 1
        col = GRN if tag == "OK " else GREY
        sys.stdout.write(
            GREY + "[" + RST + col + tag + RST + GREY + "] " + RST +
            CYN + msg + RST
        )
        sys.stdout.flush()
        time.sleep(0.075)

    # 10. Scanline flickers then clear
    time.sleep(0.15)
    for _ in range(2):
        sys.stdout.write(DIM_E);         sys.stdout.flush(); time.sleep(0.04)
        sys.stdout.write(RST + BOLD_E);  sys.stdout.flush(); time.sleep(0.04)
    sys.stdout.write(RST); sys.stdout.flush()
    time.sleep(0.55)
    _clr()

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_OUTPUT_LOCK    = threading.Lock()
_g_buf          : list = []
_g_cur          : int  = 0
_g_input_active : bool = False
_g_header       : str  = ""
_room_logs      : dict = defaultdict(list)
_room_seen      : dict = defaultdict(set)
# Lines printed during a migration window that should be removed from the log
# once the tunnel is restored.  Stored as room → Counter(line_text → count)
# so identical buffered-notice strings (one per queued message) are all removed.
_ephemeral_lines: dict = defaultdict(Counter)
_current_room   : list = ["general"]
_known_rooms    : list = []   # ordered list of rooms joined this session
_room_users     : dict = defaultdict(list)  # room -> [username, ...]
_tab_switch_cb         = None  # set by client.py to handle room switch
_panel_action_cb       = None  # called with ("join", room) or ("msg", user)

# ---------------------------------------------------------------------------
# Panel state — collapsible, split ROOMS (top) + USERS (bottom), each scrollable
# ---------------------------------------------------------------------------
_panel_visible      : list = [True]   # [0] = is panel open
_panel_rooms_scroll : list = [0]      # [0] = rooms list scroll offset
_panel_status       : list = [""]     # [0] = tiny status line at bottom of panel

_tunnel_down        : list = [False]  # [0] = True while bore tunnel is down / reconnecting
_panel_users_scroll : list = [0]      # [0] = users list scroll offset

# ---------------------------------------------------------------------------
# TUI state
# ---------------------------------------------------------------------------

_tui_active        : bool = False
_tui_rows          : list = [24]
_tui_cols          : list = [80]
_scroll_offset     : dict = defaultdict(int)
_unread_while_away : dict = defaultdict(int)
_resize_pending    : list = [False]

# Kept for API compatibility
_SKIP_ANIM : threading.Event = threading.Event()

def trigger_skip_animation() -> None:
    """No-op — animations removed. Kept so callers don't break."""
    _SKIP_ANIM.set()
    def _auto_clear():
        time.sleep(2.0)
        _SKIP_ANIM.clear()
    threading.Thread(target=_auto_clear, daemon=True).start()

def set_room_users(room: str, users: list) -> None:
    """Update the user list for a room and redraw the sidebar."""
    _room_users[room] = list(users)
    if _tui_active:
        with _OUTPUT_LOCK:
            if _panel_visible[0] and _two_panel():
                _tui_draw_rooms_unsafe()
            sys.stdout.flush()

def _panel_prefill(text: str) -> None:
    """Inject text into the live input buffer (e.g. '/msg user ' after a panel click)."""
    global _g_buf, _g_cur
    with _OUTPUT_LOCK:
        _g_buf = list(text)
        _g_cur = len(_g_buf)
        if _tui_active:
            _redraw_input_unsafe()


def set_panel_action_cb(cb) -> None:
    """Register callback invoked on panel click/select: cb(action, name)
    action is 'join' (room selected) or 'msg' (user selected)."""
    global _panel_action_cb
    _panel_action_cb = cb

def set_panel_status(text: str) -> None:
    """Set a tiny one-line status at the bottom of the panel (replaces itself).
    Pass empty string to clear. Never touches the message log."""
    _panel_status[0] = text[:_LEFT_W].strip()
    if _tui_active:
        with _OUTPUT_LOCK:
            _tui_draw_rooms_unsafe()
            sys.stdout.flush()

def print_ephemeral(text: str) -> None:
    """Print text to the current room's message log AND mark it as ephemeral.
    Ephemeral lines are removed from the log (and the TUI redrawn) the next
    time clear_ephemeral_lines() is called — i.e. when the tunnel reconnects.
    Use for all migration/buffering notices that should vanish on restore."""
    room = _current_room[0]
    print_msg(text)
    # Track by exact rendered string so clear_ephemeral_lines can find and
    # remove every occurrence even if the same text appears multiple times.
    _ephemeral_lines[room][text] += 1

def clear_ephemeral_lines() -> None:
    """Remove every ephemeral line from all room logs and redraw the TUI.
    Call once when the tunnel is fully restored so migration noise disappears
    without any flash — the user just sees their clean chat history."""
    with _OUTPUT_LOCK:
        changed = False
        for room, counter in list(_ephemeral_lines.items()):
            if room not in _room_logs:
                continue
            remaining = Counter(counter)
            new_log = []
            for line in _room_logs[room]:
                if remaining.get(line, 0) > 0:
                    remaining[line] -= 1
                    changed = True
                else:
                    new_log.append(line)
            _room_logs[room] = new_log
        _ephemeral_lines.clear()
        if changed and _tui_active:
            _tui_soft_redraw_unsafe()
            sys.stdout.flush()

# ---------------------------------------------------------------------------
# Tunnel-down notification
# ---------------------------------------------------------------------------

_PROMPT_NORMAL  = "\033[96m" + "▶ " + "\033[0m"
_PROMPT_DOWN    = "\033[91m\033[1m" + "⚠ " + "\033[0m"

def is_tunnel_down() -> bool:
    """Return True while bore tunnel is down and reconnecting."""
    return _tunnel_down[0]

def set_tunnel_down(down: bool) -> None:
    """
    Call with down=True when bore dies unexpectedly — shows a red ⚠ prompt
    and prints a system notice so the user knows sends are blocked.
    Call with down=False when the connection is restored — restores the normal
    prompt and prints a 'reconnected' notice.
    Both notifications disappear cleanly without disrupting the TUI.
    """
    global _PROMPT, _PROMPT_VIS
    _tunnel_down[0] = down
    if down:
        _PROMPT     = _PROMPT_DOWN
        _PROMPT_VIS = 2
        print_ephemeral(cwarn("⚠  Tunnel down — messages are buffered and will send on reconnect."))
    else:
        _PROMPT     = _PROMPT_NORMAL
        _PROMPT_VIS = 2
        # "Tunnel restored" is ephemeral too — clear_ephemeral_lines() called
        # right after will remove it along with all other migration notices.
        print_ephemeral(cok("✔  Tunnel restored — sending buffered messages."))
    if _tui_active:
        with _OUTPUT_LOCK:
            _redraw_input_unsafe()

def _fire_panel_action(action: str, name: str) -> None:
    """Fire panel action in a background thread so it doesn't block input."""
    if _panel_action_cb:
        threading.Thread(target=_panel_action_cb, args=(action, name), daemon=True).start()

def toggle_panel_visible() -> None:
    """Toggle left panel open/closed."""
    _panel_visible[0]      = not _panel_visible[0]
    _panel_rooms_scroll[0] = 0
    _panel_users_scroll[0] = 0
    if _tui_active:
        with _OUTPUT_LOCK:
            _tui_full_redraw_unsafe()

# ---------------------------------------------------------------------------
# ANSI utilities
# ---------------------------------------------------------------------------

def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*[mJKHABCDfnrstul@`]", "", s)

def _get_tw() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80

def _ansi_split(s: str, width: int) -> list:
    """
    Split ANSI-colored string into lines of at most `width` visible chars.
    Each line ends with RESET so colors don't bleed across lines.
    """
    if width <= 0:
        return [s]
    lines = []
    cur   = []
    vis   = 0
    i     = 0
    while i < len(s):
        if s[i] == "\033" and i + 1 < len(s) and s[i + 1] == "[":
            j = i + 2
            while j < len(s) and not (0x40 <= ord(s[j]) <= 0x7e):
                j += 1
            if j < len(s):
                j += 1
            cur.append(s[i:j])
            i = j
        else:
            if vis >= width:
                lines.append("".join(cur) + RESET)
                cur = []
                vis = 0
            cur.append(s[i])
            vis += 1
            i += 1
    if cur:
        lines.append("".join(cur) + RESET)
    return lines if lines else [""]

# ---------------------------------------------------------------------------
# TUI input drawing
# ---------------------------------------------------------------------------

def _erase_input_unsafe() -> None:
    """Erase input row. Caller must hold _OUTPUT_LOCK."""
    if not _g_input_active:
        return
    if _tui_active:
        inp_row = _tui_rows[0]
        sys.stdout.write(f"\033[{inp_row};1H\033[2K{_PROMPT}")
        sys.stdout.flush()
        return
    if not _g_buf:
        return
    tw      = _get_tw()
    rows_up = _g_cur // tw
    if rows_up:
        sys.stdout.write("\033[" + str(rows_up) + "A")
    sys.stdout.write("\r\033[J")
    sys.stdout.flush()

def _redraw_input_unsafe() -> None:
    """Redraw input with cursor. Caller must hold _OUTPUT_LOCK."""
    if not _g_input_active:
        return
    if _tui_active:
        inp_row = _tui_rows[0]
        cols    = max(10, _tui_cols[0])
        win     = cols - _PROMPT_VIS - 1
        sys.stdout.write(f"\033[{inp_row};1H\033[2K{_PROMPT}")
        if _g_buf:
            win_start = max(0, _g_cur - win + 1)
            win_start = min(win_start, max(0, len(_g_buf) - win))
            win_end   = min(len(_g_buf), win_start + win)
            sys.stdout.write("".join(_g_buf[win_start:win_end]))
            chars_after = (win_end - win_start) - (_g_cur - win_start)
            if chars_after > 0:
                sys.stdout.write(f"\033[{chars_after}D")
        sys.stdout.flush()
        return
    if not _g_buf:
        return
    sys.stdout.write("".join(_g_buf))
    trail = len(_g_buf) - _g_cur
    if trail > 0:
        sys.stdout.write(f"\033[{trail}D")
    sys.stdout.flush()

# ---------------------------------------------------------------------------
# TUI layout
# ---------------------------------------------------------------------------

def _tui_size() -> tuple:
    try:
        sz = os.get_terminal_size()
        rows, cols = sz.lines, sz.columns
    except OSError:
        rows, cols = 24, 80
    _tui_rows[0], _tui_cols[0] = rows, cols
    return rows, cols

def _tui_layout() -> tuple:
    """Return (rows, cols, vp_start, vp_end, sep_row, inp_row)."""
    rows, cols = _tui_rows[0], _tui_cols[0]
    return rows, cols, 2, rows - 2, rows - 1, rows

def _two_panel() -> bool:
    return _panel_visible[0] and _tui_cols[0] >= _MIN_COLS

def _msg_col() -> int:
    return (_LEFT_W + _DIV_W + 1) if _two_panel() else 1

def _msg_w() -> int:
    cols = _tui_cols[0]
    return max(20, (cols - _LEFT_W - _DIV_W) if _two_panel() else cols)

# ---------------------------------------------------------------------------
# TUI panel drawing
# ---------------------------------------------------------------------------

def _tui_draw_header_unsafe() -> None:
    """Header bar at row 1. Caller holds _OUTPUT_LOCK."""
    cols  = _tui_cols[0]
    room  = _current_room[0]
    ts    = time.strftime("%H:%M")
    left  = f" \u25c8 NoEyes  \u2502  #{room}"
    right = f"\U0001f512 E2E  {ts} "
    # account for emoji being 2 cells wide
    right_vis = len(right) + 1
    mid_w     = max(0, cols - len(left) - right_vis)
    bar = (
        NE_PANEL_DARK + NE_GREEN + BOLD + left  + RESET +
        NE_PANEL_DARK + NE_BORDER       + "\u2500" * mid_w + RESET +
        NE_PANEL_DARK + NE_TEXT_TER     + right + RESET
    )
    sys.stdout.write(f"\033[1;1H\033[2K{bar}")

def _tui_draw_footer_unsafe() -> None:
    """Keyboard-hint footer on the separator row. Caller holds _OUTPUT_LOCK."""
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout()
    panel_hint = "hide" if _panel_visible[0] else "show"
    hints_raw = [
        (NE_GREEN,        "\u2191\u2193"),    (NE_TEXT_SEC, " scroll"),
        (NE_BORDER,       "  \u2502  "),
        (NE_GREEN,        "PgUp/Dn"),         (NE_TEXT_SEC, " page"),
        (NE_BORDER,       "  \u2502  "),
        (NE_GREEN,        "^P"),              (NE_TEXT_SEC, f" {panel_hint} panel"),
        (NE_BORDER,       "  \u2502  "),
        (NE_GREEN,        "Esc"),             (NE_TEXT_SEC, " skip"),
        (NE_BORDER,       "  \u2502  "),
        (NE_GREEN + BOLD, "^C"),              (NE_TEXT_SEC, " quit"),
    ]
    hint_vis = sum(len(t) for _, t in hints_raw)
    hint_str = "".join(c + t + RESET for c, t in hints_raw)
    pad_l    = max(0, (cols - hint_vis) // 2)
    pad_r    = max(0, cols - pad_l - hint_vis)
    line     = (NE_BORDER + "\u2500" * pad_l + RESET
                + hint_str
                + NE_BORDER + "\u2500" * pad_r + RESET)
    sys.stdout.write(f"\033[{sep_row};1H\033[2K{line}")

def _tui_draw_rooms_unsafe() -> None:
    """Left panel: ROOMS in top half, USERS in bottom half, each independently
    scrollable. Display-only (no clicks). Caller holds _OUTPUT_LOCK."""
    if not _two_panel():
        return
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout()
    cur_room    = _current_room[0]
    all_rooms   = list(_known_rooms)
    all_users   = list(_room_users.get(cur_room, []))
    panel_h     = vp_end - vp_start + 1          # total panel rows

    # Split panel in half; rooms get top, users get bottom.
    # Each half = floor(panel_h/2). If odd, rooms get the extra row.
    half        = panel_h // 2
    rooms_start = vp_start
    rooms_end   = vp_start + half - 1
    users_start = rooms_end + 1
    users_end   = vp_end

    W = _LEFT_W  # shorthand

    def _draw_section(title: str, items: list, scroll_ref: list,
                      sec_start: int, sec_end: int, active_item: str = "") -> None:
        """Draw one section (rooms or users) within [sec_start..sec_end]."""
        # ── Section header ────────────────────────────────────────────────────
        pad  = max(0, W - len(title))
        hdr  = (NE_PANEL_DARK + NE_GREEN + BOLD
                + title + " " * pad + RESET)
        sys.stdout.write(f"\033[{sec_start};1H{hdr}")

        sec_h     = sec_end - sec_start       # rows available for items (below header)
        if sec_h <= 0:
            return

        scroll    = scroll_ref[0]
        max_sc    = max(0, len(items) - sec_h)
        scroll    = max(0, min(scroll, max_sc))
        scroll_ref[0] = scroll
        visible   = items[scroll : scroll + sec_h]

        row = sec_start + 1
        for item in visible:
            if row > sec_end:
                break
            if active_item and item == active_item:
                # Highlight active room
                label = f" \u25b6{item}"[:W]
                pad2  = max(0, W - len(label))
                sys.stdout.write(f"\033[{row};1H"
                    + NE_PANEL_LT + NE_TEXT_PRI + BOLD
                    + label + " " * pad2 + RESET)
            else:
                unread = _unread_while_away.get(item, 0) if not active_item else 0
                dot    = "\u25cf " if active_item else f"{'#' if not active_item else ''}"
                # rooms get # prefix, users get dot
                if active_item == "":
                    # users section
                    label = f" \u25cf {item}"[:W]
                else:
                    # rooms section
                    label = f" #{item}"[:W]
                    if unread:
                        label = f" #{item}"
                pad2  = max(0, W - len(label))
                badge = f"+{unread}" if unread else ""
                badge_w = len(badge)
                pad2  = max(0, W - len(label) - badge_w)
                bg    = NE_PANEL_DARK
                fg    = NE_TEXT_SEC
                sys.stdout.write(f"\033[{row};1H"
                    + bg + fg + label + " " * pad2
                    + ((NE_GREEN + BOLD + badge) if badge else "")
                    + RESET)
            row += 1

        # ── Overflow indicator ────────────────────────────────────────────────
        remaining = len(items) - (scroll + sec_h)
        if remaining > 0 and row <= sec_end:
            more = f" +{remaining} more"[:W]
            pad3 = max(0, W - len(more))
            sys.stdout.write(f"\033[{row};1H"
                + NE_PANEL_DARK + NE_TEXT_TER + more + " " * pad3 + RESET)
            row += 1

        # ── Fill empty rows ───────────────────────────────────────────────────
        while row <= sec_end:
            sys.stdout.write(f"\033[{row};1H" + NE_PANEL_DARK + " " * W + RESET)
            row += 1

    # ── Draw separator between halves ────────────────────────────────────────
    mid_sep = rooms_end + 1  # = users_start
    # We draw rooms up to rooms_end, then users from users_start.
    # The dividing row IS users_start header — no extra sep row needed.

    _draw_section(" ROOMS", all_rooms, _panel_rooms_scroll,
                  rooms_start, rooms_end, cur_room)
    _draw_section(" USERS", all_users, _panel_users_scroll,
                  users_start, users_end, "")

    # ── Status line — bottom row of panel, replaces itself ────────────────────
    status = _panel_status[0]
    if status and _two_panel():
        label = status[:_LEFT_W]
        pad   = max(0, _LEFT_W - len(label))
        sys.stdout.write(
            f"\033[{vp_end};1H"
            + NE_PANEL_DARK + NE_TEXT_TER + label + " " * pad + RESET
        )

def _tui_draw_divider_unsafe() -> None:
    """Vertical divider between panels. Caller holds _OUTPUT_LOCK."""
    if not _two_panel():
        return
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout()
    dc = _LEFT_W + 1
    for r in range(vp_start, vp_end + 1):
        sys.stdout.write(f"\033[{r};{dc}H{NE_BORDER}\u2502{RESET}")

def _tui_draw_viewport_unsafe() -> None:
    """
    Redraw message viewport respecting scroll offset.
    Lines are hard-truncated to the right-panel width so they can never
    bleed into the left panel or cause terminal wrap corruption.
    Caller holds _OUTPUT_LOCK.
    """
    room = _current_room[0]
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout()
    mc   = _msg_col()
    mw   = _msg_w()
    vh   = max(1, vp_end - vp_start + 1)

    log    = list(_room_logs[room])
    max_off = max(0, len(log) - vh)   # can't scroll more than log - viewport height
    offset  = max(0, min(_scroll_offset.get(room, 0), max_off))
    _scroll_offset[room] = offset
    end_idx = max(0, len(log) - offset)

    # Build display lines walking backwards from end_idx until viewport is full
    display_groups: list = []
    used_rows = 0

    for i in range(end_idx - 1, -1, -1):
        wrapped = _ansi_split(log[i], mw)
        n = len(wrapped)
        if used_rows + n > vh:
            take = vh - used_rows
            # Guard: if take==0, wrapped[-0:] == wrapped[0:] (full slice in Python)
            # which would overflow vp_end onto the footer/input rows.
            if take > 0:
                display_groups.insert(0, wrapped[-take:])
                used_rows += take
            break
        display_groups.insert(0, wrapped)
        used_rows += n

    # Erase ONLY the message area of each viewport row — not the panel!
    # \033[2K would erase the entire line including the left panel content.
    mc_col = _msg_col()
    for r in range(vp_start, vp_end + 1):
        sys.stdout.write(f"\033[{r};{mc_col}H\033[K")
    # Write messages bottom-aligned; hard-clip at right edge (no autowrap)
    cur_row = vp_start + (vh - used_rows)
    for group in display_groups:
        for line in group:
            # Hard-truncate: re-split to mw in case line was pre-wrapped wider
            truncated = _ansi_split(line, mw)[0] if line else ""
            sys.stdout.write(f"\033[{cur_row};{mc}H{truncated}")
            cur_row += 1

    # Scroll-back indicator at vp_end
    if offset > 0:
        unread = _unread_while_away.get(room, 0)
        if unread:
            ind = colorize(f"  \u2193 {unread} new \u2014 PgDn to resume  ", CYAN, bold=True)
        else:
            ind = colorize(f"  \u2191 scrolled back {offset}  \u2014  PgDn / \u2193 to resume  ", GREY)
        sys.stdout.write(f"\033[{vp_end};{mc}H\033[K{ind}")

    sys.stdout.flush()

def _tui_full_redraw_unsafe() -> None:
    """Full TUI screen redraw. Caller holds _OUTPUT_LOCK."""
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout()

    if rows < 4 or cols < 10:
        sys.stdout.write("\033[2J\033[H")
        if _g_header:
            sys.stdout.write(_g_header + "\n")
        sys.stdout.flush()
        return

    # Full clear — no scroll region (DECSTBM causes corruption on resize)
    sys.stdout.write("\033[r\033[2J")

    _tui_draw_header_unsafe()

    if _two_panel():
        _tui_draw_rooms_unsafe()
        _tui_draw_divider_unsafe()

    _tui_draw_viewport_unsafe()
    _tui_draw_footer_unsafe()

    sys.stdout.write(f"\033[{inp_row};1H\033[2K{_PROMPT}")
    if _g_buf:
        sys.stdout.write("".join(_g_buf))
        trail = len(_g_buf) - _g_cur
        if trail > 0:
            sys.stdout.write(f"\033[{trail}D")

def _tui_soft_redraw_unsafe() -> None:
    """Repaint the TUI in-place WITHOUT clearing the screen first.
    Used during bore migration so there is zero black flash — each cell is
    overwritten directly.  Caller holds _OUTPUT_LOCK."""
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout()
    if rows < 4 or cols < 10:
        return
    # Reset scroll margins without clearing, then repaint each region.
    sys.stdout.write("\033[r")
    _tui_draw_header_unsafe()
    if _two_panel():
        _tui_draw_rooms_unsafe()
        _tui_draw_divider_unsafe()
    _tui_draw_viewport_unsafe()
    _tui_draw_footer_unsafe()
    sys.stdout.write(f"\033[{inp_row};1H\033[2K{_PROMPT}")
    if _g_buf:
        sys.stdout.write("".join(_g_buf))
        trail = len(_g_buf) - _g_cur
        if trail > 0:
            sys.stdout.write(f"\033[{trail}D")
    sys.stdout.flush()

    sys.stdout.write("\033[?25h")
    sys.stdout.flush()

# ---------------------------------------------------------------------------
# TUI scroll
# ---------------------------------------------------------------------------

def _tui_scroll(delta: int) -> None:
    with _OUTPUT_LOCK:
        room = _current_room[0]
        log  = _room_logs[room]
        vh   = max(1, _tui_rows[0] - 3)
        max_off = max(0, len(log) - vh)
        old_off = _scroll_offset.get(room, 0)
        new_off = max(0, min(max_off, old_off + delta))
        if new_off == old_off:
            return
        _scroll_offset[room] = new_off
        if new_off == 0:
            _unread_while_away[room] = 0
        _erase_input_unsafe()
        _tui_draw_viewport_unsafe()
        _redraw_input_unsafe()

# ---------------------------------------------------------------------------
# enter / exit TUI  (cross-platform)
# ---------------------------------------------------------------------------

def reset_for_reconnect(is_migration: bool = False) -> None:
    """Clear room state so history replay starts fresh.
    During a migration (is_migration=True) we keep _room_logs and _room_seen
    intact — the already_seen dedup will silently skip replayed messages so
    the screen never flashes or clears."""
    with _OUTPUT_LOCK:
        if not is_migration:
            _room_logs.clear()
            _room_seen.clear()
            _scroll_offset.clear()
            _unread_while_away.clear()
            _ephemeral_lines.clear()
        # During migration: keep everything — already_seen handles dedup


def enter_tui() -> None:
    """Enter TUI mode — alternate screen + wheel scroll. No mouse capture,
    so text selection always works freely on all platforms."""
    global _tui_active
    if not _is_tty() or _tui_active:
        return
    _tui_active = True
    _tui_size()
    sys.stdout.write(
        "\033[?1049h"   # alternate screen
        "\033[?1007h"   # wheel → arrow keys (no click capture)
    )
    sys.stdout.flush()
    try:
        signal.signal(signal.SIGWINCH, _handle_resize)
    except (AttributeError, OSError):
        pass
    with _OUTPUT_LOCK:
        _tui_full_redraw_unsafe()

def exit_tui() -> None:
    """Exit TUI mode and restore the terminal."""
    global _tui_active
    if not _tui_active:
        return
    _tui_active = False
    sys.stdout.write("\033[?1007l\033[r\033[?25h\033[?1049l")
    sys.stdout.flush()

def _handle_resize(signum, frame) -> None:
    """SIGWINCH handler — debounce, then full redraw in background thread."""
    try:
        sz = os.get_terminal_size()
        _tui_rows[0], _tui_cols[0] = sz.lines, sz.columns
    except OSError:
        pass
    _resize_pending[0] = True

    def _do_resize():
        time.sleep(0.05)
        if not _tui_active:
            return
        _resize_pending[0] = False
        with _OUTPUT_LOCK:
            _tui_size()
            _tui_full_redraw_unsafe()

    threading.Thread(target=_do_resize, daemon=True).start()

# ---------------------------------------------------------------------------
# Output primitives
# ---------------------------------------------------------------------------

def print_msg(text: str, _skip_log: bool = False) -> None:
    """Print a line (or multi-line block), cleanly interleaving with in-progress input."""
    if not _is_tty():
        print(text)
        return
    try:
        acquired = False
        while not acquired:
            acquired = _OUTPUT_LOCK.acquire(timeout=0.05)
        try:
            if _tui_active:
                _erase_input_unsafe()
                room   = _current_room[0]
                offset = _scroll_offset.get(room, 0)
                # Split on newlines so multiline text (e.g. /help) renders correctly
                lines = text.split("\n") if "\n" in text else [text]
                if not _skip_log:
                    for ln in lines:
                        _room_logs[room].append(ln)
                    if offset > 0:
                        _unread_while_away[room] = (
                            _unread_while_away.get(room, 0) + len(lines)
                        )
                _tui_draw_viewport_unsafe()
                _tui_draw_footer_unsafe()
                _redraw_input_unsafe()
            else:
                _erase_input_unsafe()
                print(text)
                _redraw_input_unsafe()
        finally:
            _OUTPUT_LOCK.release()
    except KeyboardInterrupt:
        pass

def log_and_print(room: str, text: str) -> None:
    if not _tui_active:
        _room_logs[room].append(text)
    print_msg(text)

def _msg_key(from_user: str, ts: str, text: str) -> str:
    return f"{ts}|{from_user}|{text[:40]}"

def already_seen(room: str, from_user: str, ts: str, text: str) -> bool:
    return _msg_key(from_user, ts, text) in _room_seen[room]

def mark_seen(room: str, from_user: str, ts: str, text: str) -> None:
    _room_seen[room].add(_msg_key(from_user, ts, text))

# ---------------------------------------------------------------------------
# Room management
# ---------------------------------------------------------------------------

def switch_room_display(room_name: str, show_banner: bool = False,
                        is_migration: bool = False) -> None:
    """Switch active room, reset scroll, trigger full TUI redraw.

    Pass is_migration=True during a bore tunnel migration so the scroll
    position and unread count are preserved — the user stays exactly where
    they were before the tunnel rolled over.
    """
    global _g_header
    _current_room[0] = room_name
    if room_name not in _known_rooms:
        _known_rooms.append(room_name)
    if not is_migration:
        # Only reset scroll / unread when actually switching rooms, not when
        # redrawing after a bore tunnel migration in the same room.
        _scroll_offset[room_name]     = 0
        _unread_while_away[room_name] = 0
    # NOTE: do NOT clear _room_logs here — we want history preserved per room
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _g_header = colorize(f"  \u2550\u2550  {room_name}  \u2550\u2550", CYAN, bold=True)
        _set_title(f"NoEyes \u2502 #{room_name}")
        if _tui_active:
            _tui_size()
            if not is_migration:
                # Full clear only when actually switching rooms — during a
                # bore migration we repaint in-place so there is zero flash.
                sys.stdout.write("\033[2J")
                sys.stdout.flush()
            _tui_full_redraw_unsafe()
        elif _is_tty():
            sys.stdout.write("\033[3J\033[2J\033[H\033[r")
            sys.stdout.write(_g_header + "\n\n")
            sys.stdout.flush()
        else:
            _g_header = ""
            print(colorize(f"  \u2550\u2550  {room_name}  \u2550\u2550", CYAN, bold=True))
            print()
        _redraw_input_unsafe()

def clear_for_room(room_name: str, show_banner: bool = False) -> None:
    switch_room_display(room_name, show_banner=show_banner)

# ---------------------------------------------------------------------------
# Message display — instant, no animation
# ---------------------------------------------------------------------------

def _animate_msg(prefix: str, plaintext: str, room: str,
                 from_user: str = "", ts: str = "",
                 tag: str = "") -> None:
    """Display a message. prefix already contains [ts] username: """
    if from_user and ts:
        mark_seen(room, from_user, ts, plaintext)

    badge   = format_tag_badge(tag) if tag else ""
    full_msg = prefix + badge + NE_TEXT_PRI + plaintext + RESET

    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _room_logs[room].append(full_msg)
        offset = _scroll_offset.get(room, 0)
        if offset > 0:
            _unread_while_away[room] = _unread_while_away.get(room, 0) + 1
        if _tui_active:
            _tui_draw_viewport_unsafe()
            _tui_draw_footer_unsafe()
        else:
            sys.stdout.write(full_msg + "\n")
            sys.stdout.flush()
        _redraw_input_unsafe()

# ---------------------------------------------------------------------------
# Message formatting — waha-tui visual style
#
#   Received  ◥ [sender_color bold]username[reset]  text  [dim]HH:MM[reset]
#   Sent            [sent_bg]  text  [dim]HH:MM[reset][/bg] ◤
#   System    ─ [dim]text  HH:MM[reset]
#   PM        ◈ [cyan bold]PM: from[reset][sig]  text  [dim]HH:MM[reset]
# ---------------------------------------------------------------------------

def _msg_prefix(from_user: str, timestamp: str, tag: str = "", is_own: bool = False) -> str:
    """[ts] username:  prefix — consistent for own and others."""
    sc  = YELLOW if is_own else _sender_color(from_user)
    ts  = NE_TEXT_TER + f"[{timestamp}]" + RESET
    usr = BOLD + sc + from_user + RESET
    return f"{ts} {usr}: "

def _pm_prefix(from_user: str, timestamp: str, verified: bool, tag: str = "") -> str:
    """[ts] [PM: user]✓  prefix."""
    ts  = NE_TEXT_TER + f"[{timestamp}]" + RESET
    src = BOLD + CYAN + f"[PM: {from_user}]" + RESET
    sig = cok("\u2713") if verified else cwarn("?")
    return f"{ts} {src}{sig} "

def format_message(username: str, text: str, timestamp: str,
                   tag: str = "", is_own: bool = False) -> str:
    """Format a chat message: [ts] username: badge text"""
    badge = format_tag_badge(tag) if tag else ""
    sc    = YELLOW if is_own else _sender_color(username)
    ts    = NE_TEXT_TER + f"[{timestamp}]" + RESET
    usr   = BOLD + sc + username + RESET
    return f"{ts} {usr}: {badge}{NE_TEXT_PRI}{text}{RESET}"

def format_system(text: str, timestamp: str) -> str:
    ts = NE_TEXT_TER + f"[{timestamp}]" + RESET
    return f"{ts} {NE_BORDER}\u2500{RESET} {NE_TEXT_SEC}{text}{RESET}"

def format_privmsg(from_user: str, text: str, timestamp: str,
                   verified: bool, tag: str = "") -> str:
    badge = format_tag_badge(tag) if tag else ""
    ts    = NE_TEXT_TER + f"[{timestamp}]" + RESET
    sig   = cok("\u2713") if verified else cwarn("?")
    src   = BOLD + CYAN + f"[PM: {from_user}]" + RESET
    return f"{ts} {src}{sig} {badge}{NE_TEXT_PRI}{text}{RESET}"

# ---------------------------------------------------------------------------
# Public message entry points (called by client.py)
# ---------------------------------------------------------------------------

def chat_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    anim_enabled: bool = True,
    room: str = "general",
    own_username: str = "",
    tag: str = "",
) -> None:
    """Receive and display an incoming chat message."""
    is_own   = (from_user == own_username)
    rendered = format_message(from_user, plaintext, msg_ts, tag=tag, is_own=is_own)

    if already_seen(room, from_user, msg_ts, plaintext):
        # Already displayed — silently skip during history replay.
        # Do NOT re-append to _room_logs (it's already there).
        return

    if not is_own:
        if tag and tag in TAGS:
            play_notification(TAGS[tag]["sound"])
        else:
            play_notification("normal")

    _animate_msg(
        prefix    = _msg_prefix(from_user, msg_ts, tag=tag, is_own=is_own),
        plaintext = plaintext,
        room      = room,
        from_user = from_user,
        ts        = msg_ts,
        tag       = tag,
    )


def privmsg_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    verified: bool = False,
    anim_enabled: bool = True,
    room: str = "general",
    tag: str = "",
) -> None:
    """Receive and display an incoming private message."""
    rendered = format_privmsg(from_user, plaintext, msg_ts, verified, tag=tag)

    if already_seen(room, from_user, msg_ts, plaintext):
        # Already displayed — silently skip during history replay.
        return

    if tag and tag in TAGS:
        play_notification(TAGS[tag]["sound"])
    else:
        play_notification("info")

    _animate_msg(
        prefix    = _pm_prefix(from_user, msg_ts, verified, tag=tag),
        plaintext = plaintext,
        room      = room,
        from_user = from_user,
        ts        = msg_ts,
        tag       = tag,
    )

# ---------------------------------------------------------------------------
# No-echo input  (cross-platform, fully preserved from session 3)
# ---------------------------------------------------------------------------

def read_line_noecho() -> str:
    """
    Read a line with manual echo and cursor movement.

    Characters go into _g_buf so print_msg() can erase/redraw them
    cleanly around incoming messages.

    Keys:
      Printable       insert at cursor
      Backspace/Del   delete left
      Left/Right      move cursor
      Home/End        jump to start/end (also Ctrl+A / Ctrl+E)
      Ctrl+U          clear line
      Up/Down         consumed silently
      PageUp/Dn       scroll viewport (TUI mode)
      Mouse wheel     scroll viewport (TUI mode)
      Tab             cycle rooms (TUI mode)
      Escape          no-op (animations removed)
      Ctrl+C/D        raise KeyboardInterrupt / EOFError
    """
    global _g_input_active, _g_buf, _g_cur

    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\n")

    try:
        import termios, tty
        _unix = True
    except ImportError:
        import msvcrt as _msvcrt
        _unix = False

    if not _unix:
        # ── Windows msvcrt path ───────────────────────────────────────────────
        with _OUTPUT_LOCK:
            _g_buf          = []
            _g_cur          = 0
            _g_input_active = True
            if _tui_active:
                inp_row = _tui_rows[0]
                sys.stdout.write(f"\033[{inp_row};1H\033[2K{_PROMPT}")
                sys.stdout.flush()

        _win_resize_stop = threading.Event()
        def _win_resize_poll():
            last = (_tui_rows[0], _tui_cols[0])
            while not _win_resize_stop.is_set():
                try:
                    sz  = os.get_terminal_size()
                    cur = (sz.lines, sz.columns)
                except OSError:
                    cur = last
                if cur != last:
                    last = cur
                    _tui_rows[0], _tui_cols[0] = cur
                    if _tui_active:
                        with _OUTPUT_LOCK:
                            _tui_full_redraw_unsafe()
                _win_resize_stop.wait(0.25)
        threading.Thread(target=_win_resize_poll, daemon=True).start()

        try:
            while True:
                ch = _msvcrt.getwch()

                if ch in ("\r", "\n"):
                    with _OUTPUT_LOCK:
                        result          = "".join(_g_buf)
                        _g_input_active = False
                        _g_buf          = []
                        _g_cur          = 0
                        if _tui_active:
                            _erase_input_unsafe()
                    return result

                elif ch == "\x03":
                    with _OUTPUT_LOCK:
                        _g_input_active = False; _g_buf = []; _g_cur = 0
                    raise KeyboardInterrupt

                elif ch == "\x04":
                    with _OUTPUT_LOCK:
                        _g_input_active = False; _g_buf = []; _g_cur = 0
                    raise EOFError

                elif ch == "\x10":   # Ctrl+P — toggle panel
                    if _tui_active:
                        toggle_panel_visible()

                elif ch == "\x1b":
                    # Collect VT sequence bytes
                    import time as _wt
                    _wt.sleep(0.05)
                    seqbuf = ""
                    while _msvcrt.kbhit():
                        seqbuf += _msvcrt.getwch()
                    if seqbuf in ("[5~", "[5"):                   # PageUp
                        if _tui_active: _tui_scroll(10)
                    elif seqbuf in ("[6~", "[6"):                 # PageDown
                        if _tui_active: _tui_scroll(-10)
                    elif seqbuf in ("[A", "OA"):                  # Up arrow
                        if _tui_active: _tui_scroll(3)
                    elif seqbuf in ("[B", "OB"):                  # Down arrow
                        if _tui_active: _tui_scroll(-3)
                    elif seqbuf in ("[C", "OC"):                  # Right arrow
                        with _OUTPUT_LOCK:
                            if _g_cur < len(_g_buf):
                                _g_cur += 1
                                if _tui_active: _redraw_input_unsafe()
                    elif seqbuf in ("[D", "OD"):                  # Left arrow
                        with _OUTPUT_LOCK:
                            if _g_cur > 0:
                                _g_cur -= 1
                                if _tui_active: _redraw_input_unsafe()
                    else:
                        trigger_skip_animation()

                elif ch in ("\x7f", "\x08"):
                    with _OUTPUT_LOCK:
                        if _g_cur > 0:
                            _g_buf.pop(_g_cur - 1)
                            _g_cur -= 1
                            if _tui_active:
                                _redraw_input_unsafe()
                            else:
                                sys.stdout.write("\b \b"); sys.stdout.flush()

                elif ch in ("\x00", "\xe0"):
                    code = _msvcrt.getwch()
                    _scroll_delta = 0
                    with _OUTPUT_LOCK:
                        if   code == "K" and _g_cur > 0:           _g_cur -= 1
                        elif code == "M" and _g_cur < len(_g_buf): _g_cur += 1
                        elif code == "G":                           _g_cur = 0
                        elif code == "O":                           _g_cur = len(_g_buf)
                        elif code == "I":                           _scroll_delta = 10
                        elif code == "Q":                           _scroll_delta = -10
                        if _tui_active and not _scroll_delta:
                            _redraw_input_unsafe()
                        elif not _tui_active:
                            sys.stdout.flush()
                    if _scroll_delta and _tui_active:
                        _tui_scroll(_scroll_delta)

                elif ch >= " ":
                    with _OUTPUT_LOCK:
                        _g_buf.insert(_g_cur, ch)
                        _g_cur += 1
                        if _tui_active:
                            _redraw_input_unsafe()
                        else:
                            sys.stdout.write(ch); sys.stdout.flush()
        finally:
            _win_resize_stop.set()
            with _OUTPUT_LOCK:
                _g_input_active = False; _g_buf = []; _g_cur = 0

    # ── Unix termios path ─────────────────────────────────────────────────────
    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    result       = ""

    with _OUTPUT_LOCK:
        _g_buf          = []
        _g_cur          = 0
        _g_input_active = True
        if _tui_active:
            inp_row = _tui_rows[0]
            sys.stdout.write(f"\033[{inp_row};1H\033[2K{_PROMPT}")
            sys.stdout.flush()

    import os as _os, select as _sel

    def _readbyte():
        return _os.read(fd, 1).decode("utf-8", errors="replace")

    def _inline_redraw():
        """Redraw tail after cursor (plain mode). Caller holds lock."""
        tail = "".join(_g_buf[_g_cur:])
        sys.stdout.write(tail + " ")
        sys.stdout.write(f"\033[{len(tail)+1}D")
        sys.stdout.flush()

    try:
        tty.setcbreak(fd)
        while True:
            ch = _readbyte()

            if ch in ("\n", "\r"):
                with _OUTPUT_LOCK:
                    result          = "".join(_g_buf)
                    _erase_input_unsafe()
                    _g_input_active = False
                    _g_buf = []; _g_cur = 0
                if not _tui_active:
                    sys.stdout.write("\n"); sys.stdout.flush()
                return result

            elif ch == "\x03":
                with _OUTPUT_LOCK:
                    _g_input_active = False; _g_buf = []; _g_cur = 0
                raise KeyboardInterrupt

            elif ch == "\x04":
                with _OUTPUT_LOCK:
                    _g_input_active = False; _g_buf = []; _g_cur = 0
                raise EOFError

            elif ch == "\x15":   # Ctrl+U — clear line
                with _OUTPUT_LOCK:
                    _g_buf = []; _g_cur = 0
                    if _tui_active:
                        _redraw_input_unsafe()
                    else:
                        sys.stdout.write("\r\033[K"); sys.stdout.flush()

            elif ch == "\x01":   # Ctrl+A — Home
                with _OUTPUT_LOCK:
                    _g_cur = 0
                    if _tui_active:
                        _redraw_input_unsafe()

            elif ch == "\x05":   # Ctrl+E — End
                with _OUTPUT_LOCK:
                    _g_cur = len(_g_buf)
                    if _tui_active:
                        _redraw_input_unsafe()

            elif ch == "\x10":   # Ctrl+P — toggle panel
                if _tui_active:
                    toggle_panel_visible()

            elif ch == "\x1b":
                # Escape sequence or bare Escape key
                rlist, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                if not rlist:
                    trigger_skip_animation()
                    continue
                seq = _readbyte()

                # ── SS3: ESC O x  (Home=H End=F, F1-F4 ignored) ─────────────
                if seq == "O":
                    rlist2, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                    if not rlist2:
                        continue
                    c3 = _readbyte()
                    if c3 == "H":
                        with _OUTPUT_LOCK:
                            _g_cur = 0
                            if _tui_active: _redraw_input_unsafe()
                    elif c3 == "F":
                        with _OUTPUT_LOCK:
                            _g_cur = len(_g_buf)
                            if _tui_active: _redraw_input_unsafe()
                    continue

                if seq != "[":
                    continue
                seq2 = _readbyte()

                if seq2 == "A":    # Up arrow → scroll back (older)
                    if _tui_active:
                        _tui_scroll(3)
                elif seq2 == "B":  # Down arrow → scroll forward (newer)
                    if _tui_active:
                        _tui_scroll(-3)
                elif seq2 == "C":  # Right
                    with _OUTPUT_LOCK:
                        if _g_cur < len(_g_buf):
                            _g_cur += 1
                            if _tui_active:
                                _redraw_input_unsafe()
                            else:
                                sys.stdout.write("\033[C"); sys.stdout.flush()
                elif seq2 == "D":  # Left
                    with _OUTPUT_LOCK:
                        if _g_cur > 0:
                            _g_cur -= 1
                            if _tui_active:
                                _redraw_input_unsafe()
                            else:
                                sys.stdout.write("\033[D"); sys.stdout.flush()
                elif seq2 == "H":  # Home
                    with _OUTPUT_LOCK:
                        _g_cur = 0
                        if _tui_active:
                            _redraw_input_unsafe()
                elif seq2 == "F":  # End
                    with _OUTPUT_LOCK:
                        _g_cur = len(_g_buf)
                        if _tui_active:
                            _redraw_input_unsafe()
                elif seq2 in ("5", "6"):
                    # PageUp (5~) / PageDown (6~) — consume trailing '~'
                    rlist, _, _ = _sel.select([sys.stdin], [], [], 0.1)
                    if rlist:
                        _readbyte()  # consume '~'
                    if _tui_active:
                        _tui_scroll(10 if seq2 == "5" else -10)
                elif seq2 in ("1", "2", "3", "4"):
                    # Multi-char CSI: consume the rest (don't insert garbage)
                    rlist, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                    if rlist:
                        _readbyte()  # consume digit
                        rlist2, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                        if rlist2:
                            _readbyte()  # consume ~ or extra char
            elif ch in ("\x7f", "\x08"):
                with _OUTPUT_LOCK:
                    if _g_cur > 0:
                        _g_buf.pop(_g_cur - 1)
                        _g_cur -= 1
                        if _tui_active:
                            _redraw_input_unsafe()
                        else:
                            _inline_redraw()

            elif ch >= " ":
                with _OUTPUT_LOCK:
                    _g_buf.insert(_g_cur, ch)
                    _g_cur += 1
                    if _tui_active:
                        _redraw_input_unsafe()
                    else:
                        sys.stdout.write(ch)
                        if _g_cur < len(_g_buf):
                            _inline_redraw()
                        else:
                            sys.stdout.flush()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        with _OUTPUT_LOCK:
            _g_input_active = False; _g_buf = []; _g_cur = 0

    return result
