# FILE: utils.py
"""
utils.py — Terminal utilities, ANSI colors, and the NoEyes ASCII banner.
"""

import sys
import os
import time
import random
import re
import threading
from collections import defaultdict

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

RESET        = "\033[0m"
BOLD         = "\033[1m"
RED          = "\033[31m"
GREEN        = "\033[32m"
YELLOW       = "\033[33m"
CYAN         = "\033[36m"
WHITE        = "\033[37m"
GREY         = "\033[90m"
PURPLE       = "\033[35m"
BRIGHT_WHITE = "\033[1;37m"


# ---------------------------------------------------------------------------
# Message tag system
# ---------------------------------------------------------------------------
# Senders prefix their message with !tagname to signal tone.
# The tag travels inside the encrypted payload — the server never sees it.
# Receivers use the tag to color the message and play a notification sound.
# Everything is opt-in and silent for normal untagged messages.

TAGS = {
    "ok":     {"label": "✔ OK",     "color": "[92m",  "bold": True,  "sound": "ok"},
    "warn":   {"label": "⚡ WARN",  "color": "[93m",  "bold": True,  "sound": "warn"},
    "danger": {"label": "☠ DANGER","color": "[91m",  "bold": True,  "sound": "danger"},
    "info":   {"label": "ℹ INFO",   "color": "[94m",  "bold": False, "sound": "info"},
    "req":    {"label": "↗ REQ",    "color": "[95m",  "bold": False, "sound": "req"},
    "?":      {"label": "? ASK",    "color": "[96m",  "bold": False, "sound": "ask"},
}
TAG_NAMES = set(TAGS.keys())

# Prefix a user types to tag a message, e.g.  !danger server is down
TAG_PREFIX = "!"

def parse_tag(text: str) -> tuple:
    """
    Parse optional !tag prefix from a message.
    Returns (tag_or_None, message_text).
    Normal messages with no tag return (None, original_text).
    """
    if not text.startswith(TAG_PREFIX):
        return None, text
    # Find end of tag word
    space = text.find(" ", 1)
    if space == -1:
        word = text[1:]
        rest = ""
    else:
        word = text[1:space]
        rest = text[space + 1:]
    if word.lower() in TAG_NAMES:
        return word.lower(), rest.strip()
    # Not a known tag — treat whole thing as normal message
    return None, text


def format_tag_badge(tag: str) -> str:
    """Render a colored badge for a tag, e.g.  [[92m✔ OK[0m]"""
    if not tag or tag not in TAGS:
        return ""
    t = TAGS[tag]
    color = t["color"]
    bold  = "[1m" if t["bold"] else ""
    return f"[{bold}{color}{t['label']}[0m] "


# ---------------------------------------------------------------------------
# Notification sounds
# ---------------------------------------------------------------------------
# Sounds play in a background thread so they never block the UI.
# Uses platform-native audio where available, falls back to terminal bell.

_SOUNDS_ENABLED = True  # toggled by /notify on|off

def set_sounds_enabled(val: bool) -> None:
    global _SOUNDS_ENABLED
    _SOUNDS_ENABLED = val

def sounds_enabled() -> bool:
    return _SOUNDS_ENABLED

# Custom sounds folder — place files here to override built-in sounds.
# Naming: <tag>.<ext>  e.g.  sounds/danger.mp3  sounds/ok.wav  sounds/warn.ogg
# Any format your OS player supports works.  Falls back to built-in tones.
_SOUNDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sounds")
_SOUND_EXTS  = (".wav", ".mp3", ".ogg", ".aiff", ".flac", ".m4a")

def _find_custom_sound(sound_type: str):
    """Return path to a custom sound file for *sound_type*, or None."""
    if not os.path.isdir(_SOUNDS_DIR):
        return None
    for ext in _SOUND_EXTS:
        p = os.path.join(_SOUNDS_DIR, sound_type + ext)
        if os.path.isfile(p):
            return p
    return None


def play_notification(sound_type: str) -> None:
    """Play a non-blocking notification sound for the given tag type.

    Custom sounds: drop files into a  sounds/  folder next to noeyes.py.
    Name them after the tag: ok.wav, danger.mp3, warn.ogg, info.wav,
    req.wav, ask.wav, normal.wav.  Any format your OS player supports works.
    Built-in tones are used as fallback when no custom file is found.
    """
    if not _SOUNDS_ENABLED:
        return
    if not _is_tty():
        return

    def _play():
        import subprocess, sys as _sys
        plat = _sys.platform

        # ── 1. Custom sound file (highest priority) ───────────────────────────
        custom = _find_custom_sound(sound_type)
        if custom:
            try:
                if plat == "darwin":
                    subprocess.run(["afplay", custom], capture_output=True, timeout=10)
                    return
                elif plat == "win32":
                    import winsound as _ws
                    if custom.lower().endswith(".wav"):
                        _ws.PlaySound(custom, _ws.SND_FILENAME)
                    else:
                        subprocess.run(
                            ["wmplayer", "/play", "/close", custom],
                            capture_output=True, timeout=10,
                        )
                    return
                else:
                    for player in ("paplay", "aplay", "mpg123", "ffplay", "afplay"):
                        if subprocess.run(
                            ["which", player], capture_output=True
                        ).returncode == 0:
                            subprocess.run(
                                [player, custom], capture_output=True, timeout=10
                            )
                            return
            except Exception:
                pass   # custom sound failed — fall through to built-in

        # ── 2. Built-in system sounds ─────────────────────────────────────────
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
                    subprocess.run(["afplay", snd], capture_output=True, timeout=3)
                    return
            elif plat == "win32":
                import winsound as _ws
                _win = {
                    "ok":     (880, 120), "warn":   (440, 280),
                    "danger": (220, 500), "info":   (660, 100),
                    "req":    (550, 180), "ask":    (770, 130),
                    "normal": (440,  80),
                }
                freq, dur = _win.get(sound_type, (440, 80))
                _ws.Beep(freq, dur)
                return
            else:
                import wave, struct, tempfile, math
                _linux = {
                    "ok":     (880, 0.15), "warn":   (440, 0.28),
                    "danger": (220, 0.45), "info":   (660, 0.10),
                    "req":    (550, 0.18), "ask":    (770, 0.13),
                    "normal": (440, 0.08),
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
                os.unlink(fname)
                return
        except Exception:
            pass

        # ── 3. Terminal bell fallback ─────────────────────────────────────────
        _bells = {
            "ok": "", "warn": "", "danger": "",
            "info": "", "req": "", "ask": "", "normal": "",
        }
        for b in _bells.get(sound_type, ""):
            _sys.stdout.write(b); _sys.stdout.flush(); time.sleep(0.12)

    threading.Thread(target=_play, daemon=True).start()


def _is_tty() -> bool:
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False


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


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------

def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

BANNER = (
    "\n"
    "  ███╗   ██╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗\n"
    "  ████╗  ██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝\n"
    "  ██╔██╗ ██║██║   ██║█████╗   ╚████╔╝ █████╗  ███████╗\n"
    "  ██║╚██╗██║██║   ██║██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║\n"
    "  ██║ ╚████║╚██████╔╝███████╗   ██║   ███████╗███████║\n"
    "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝\n"
    "  Secure Terminal Chat  │  E2E Encrypted\n"
)


def print_banner() -> None:
    print(colorize(BANNER, CYAN, bold=True))


# ---------------------------------------------------------------------------
# CRT startup animation  (shown once on connect, never inside the chat)
# ---------------------------------------------------------------------------

def play_startup_animation() -> None:
    """
    CRT boot animation — slick full-window cold-start.
    Skipped when stdout is not a TTY.
    """
    if not _is_tty():
        return

    import shutil

    tw = shutil.get_terminal_size((80, 24)).columns
    th = shutil.get_terminal_size((80, 24)).lines

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
    DIM     = ESC + "[2m"
    BOLD    = ESC + "[1m"
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

    # ── 1. Flash ──────────────────────────────────────────────────────────────
    _clr()
    _fill(BRT_WHT, "\u2588")
    time.sleep(0.04)
    _clr()
    time.sleep(0.02)

    # ── 2. Glitch burst — scattered RGB tears ─────────────────────────────────
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

    # ── 3. Phosphor ramp: black → green → cyan ────────────────────────────────
    for col, char, delay in [
        (DIM_GRN,          "\u2593", 0.030),
        (GRN,              "\u2593", 0.025),
        (BRT_GRN,          "\u2592", 0.025),
        (CYN,              "\u2592", 0.025),
        (BRT_CYN,          "\u2591", 0.020),
        (ESC + "[96m",     "\u2591", 0.018),
    ]:
        _fill(col, char)
        time.sleep(delay)
    _clr()

    # ── 4. Static burst — 3 quick noise frames ────────────────────────────────
    for _ in range(3):
        _noise_frame()
        time.sleep(0.035)
    _clr()

    # ── 5. Beam sweep — full height, crisp and fast ───────────────────────────
    beam  = BRT_CYN + ("\u2501" * tw) + RST
    trail = DIM_CYN + ("\u2500" * tw) + RST
    buf   = ""
    for r in range(1, th + 1):
        if r > 1:
            buf += f"\033[{r-1};1H" + trail
        buf += f"\033[{r};1H" + beam
    sys.stdout.write(buf)
    sys.stdout.flush()
    # now animate it row by row at speed
    _clr()
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

    # ── 6. Logo burn-in — vertically & horizontally centred ───────────────────
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

        # cipher flash
        sys.stdout.write(indent + "".join(
            random.choice(CYANS) + random.choice(GLITCH) + RST
            for _ in range(min(vis, tw - h_pad))
        ) + "\r")
        sys.stdout.flush()
        time.sleep(0.018)

        # left-to-right wipe
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

        # lock in
        sys.stdout.write(BRT_CYN + indent + line + RST)
        sys.stdout.flush()
        time.sleep(0.028)

    # ── 7. Bloom pulse — two quick dim/bright flickers ────────────────────────
    for delay in [0.05, 0.04]:
        time.sleep(delay)
        sys.stdout.write(DIM);  sys.stdout.flush(); time.sleep(0.03)
        sys.stdout.write(RST);  sys.stdout.flush()

    # ── 8. Tagline — centred, typed fast ─────────────────────────────────────
    tagline = "E2E Encrypted  \xb7  Blind-Forwarder Server  \xb7  Zero Trust"
    tag_col = max(1, (tw - len(tagline)) // 2)
    _goto(cur_row + 1, tag_col)
    for ch in tagline:
        sys.stdout.write(CYN + ch + RST)
        sys.stdout.flush()
        time.sleep(0.012)

    # ── 9. Boot status — fast scroll ─────────────────────────────────────────
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

    # ── 10. Two scanline flickers then hold ───────────────────────────────────
    time.sleep(0.15)
    for _ in range(2):
        sys.stdout.write(DIM);        sys.stdout.flush(); time.sleep(0.04)
        sys.stdout.write(RST + BOLD); sys.stdout.flush(); time.sleep(0.04)
    sys.stdout.write(RST);  sys.stdout.flush()

    time.sleep(0.55)
    _clr()


# ---------------------------------------------------------------------------
# Global state — output lock + per-room message log + input buffer
#
# ALL terminal output goes through print_msg() which holds _OUTPUT_LOCK.
# read_line_noecho() shares _g_buf with print_msg() so incoming messages
# can erase the partial input, print, then redraw it seamlessly.
#
# Per-room log: every displayed message is stored in _room_logs[room].
# switch_room_display() clears the screen and reprints that room's log —
# no server history replay needed for room switches.
# ---------------------------------------------------------------------------

_OUTPUT_LOCK    = threading.Lock()
_g_buf          : list = []
_g_cur          : int  = 0    # cursor position within _g_buf (0 = start)
_g_input_active : bool = False
_g_header       : str  = ""   # sticky header shown at top of screen
_room_logs      : dict = defaultdict(list)   # room -> [rendered_string, ...]
_room_seen      : dict = defaultdict(set)    # room -> set of "ts|user|text" keys already animated
_current_room   : list = ["general"]         # mutable single-element so closures can mutate it

# Animation skip — set by Escape hotkey; auto-clears after 2 s so future messages still animate.
_SKIP_ANIM : threading.Event = threading.Event()

def trigger_skip_animation() -> None:
    """
    Called when user presses Escape.
    Skips all ongoing/queued animations instantly.
    Auto-resets after 2 s so future incoming messages still animate.
    """
    _SKIP_ANIM.set()
    def _auto_clear():
        time.sleep(2.0)
        _SKIP_ANIM.clear()
    threading.Thread(target=_auto_clear, daemon=True).start()



def _get_tw() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _erase_input_unsafe() -> None:
    """
    Erase partial input from screen. Caller must hold _OUTPUT_LOCK.

    Cursor may be anywhere within _g_buf (left/right arrows move it).
    We need to move UP to the start row of the input, then clear down.
    The cursor is at column (_g_cur % tw) on row (_g_cur // tw) of the
    input area, so we go up that many rows to reach the input start row.
    """
    if not _g_input_active or not _g_buf:
        return
    tw      = _get_tw()
    rows_up = _g_cur // tw      # rows above cursor to reach start of input
    if rows_up:
        sys.stdout.write("\033[" + str(rows_up) + "A")
    sys.stdout.write("\r\033[J")
    sys.stdout.flush()


def _redraw_input_unsafe() -> None:
    """
    Redraw partial input with cursor at _g_cur. Caller must hold _OUTPUT_LOCK.

    Prints the entire buffer then moves the cursor left by however many
    characters trail after the cursor position.
    """
    if not _g_input_active:
        return
    if not _g_buf:
        return
    sys.stdout.write("".join(_g_buf))
    trail = len(_g_buf) - _g_cur
    if trail > 0:
        sys.stdout.write(f"\033[{trail}D")
    sys.stdout.flush()


def _redraw_header_unsafe() -> None:
    """Re-stamp the sticky header at row 1. Caller holds _OUTPUT_LOCK."""
    if not _g_header or not _is_tty():
        return
    try:
        rows = os.get_terminal_size().lines
    except OSError:
        rows = 24
    sys.stdout.write(f"[s[1;1H[2K{_g_header}[2;{rows}r[u")
    sys.stdout.flush()


def print_msg(text: str) -> None:
    """Print a line of output, cleanly interleaving with in-progress input."""
    if not _is_tty():
        print(text)
        return
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        print(text)
        _redraw_input_unsafe()


def log_and_print(room: str, text: str) -> None:
    """Store message in room log and print it (no animation)."""
    _room_logs[room].append(text)
    print_msg(text)


def _msg_key(from_user: str, ts: str, text: str) -> str:
    return f"{ts}|{from_user}|{text[:40]}"


def already_seen(room: str, from_user: str, ts: str, text: str) -> bool:
    """Return True if this message has already been animated for this room."""
    return _msg_key(from_user, ts, text) in _room_seen[room]


def mark_seen(room: str, from_user: str, ts: str, text: str) -> None:
    """Mark a message as having been animated."""
    _room_seen[room].add(_msg_key(from_user, ts, text))


def switch_room_display(room_name: str, show_banner: bool = False) -> None:
    """
    Clear the terminal, pin a sticky header at row 1 showing the room name,
    and set the scroll region to rows 2..N so messages scroll under it.

    show_banner is kept for backward-compat but ignored — use
    play_startup_animation() to show the logo before entering chat.
    """
    global _g_header
    _current_room[0] = room_name
    _room_logs[room_name].clear()   # server replay will refill it
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        if _is_tty():
            try:
                rows = os.get_terminal_size().lines
            except OSError:
                rows = 24
            # Build sticky header
            _g_header = colorize(f"  ══  {room_name}  ══", CYAN, bold=True)
            # Clear screen, pin header at row 1, set scroll region rows 2..N
            sys.stdout.write("[2J[H")
            sys.stdout.write(f"[1;1H[2K{_g_header}")
            sys.stdout.write(f"[2;{rows}r")   # scroll region = row 2..rows
            sys.stdout.write("[2;1H")          # cursor into scroll region
            sys.stdout.flush()
        else:
            _g_header = ""
            print(colorize(f"  ══  {room_name}  ══", CYAN, bold=True))
            print()
        _redraw_input_unsafe()


# Alias used in older call sites
def clear_for_room(room_name: str, show_banner: bool = False) -> None:
    switch_room_display(room_name, show_banner=show_banner)


# ---------------------------------------------------------------------------
# Decrypt animation
# ---------------------------------------------------------------------------

_CIPHER_POOL = list(
    "─│┌┐└┘├┤┬┴┼╔╗╚╝╠╣╦╩╬═║╒╓╕╖╘╙╛╜╞╟╡╢╤╥╧╨╪╫"
    "░▒▓█▀▄▌▐▖▗▘▙▚▛▜▝▞▟"
    "⠿⠾⠽⠻⠷⠯⠟⡿⢿"
    "!#$%&*+/<=>?@^~|*+-=<>{}[]"
    "·×÷±∑∏∂∇∞∴≈≠≡≤≥"
)

_CIPHER_COLORS = [
    "\033[36m",
    "\033[1;36m",
    "\033[96m",
    "\033[1;96m",
]

_CIPHER_CHAR_DELAY = 0.022
_REVEAL_PAUSE      = 0.38
_PLAIN_CHAR_MAX    = 0.060
_PLAIN_TOTAL_CAP   = 2.0


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _run_animation(prefix: str, plaintext: str) -> None:
    """
    Wave animation using DECSC/DECRC (\0337/\0338) save-restore cursor.

    At every step we restore to the saved position and rewrite the full
    current wave state — no cursor arithmetic, no line-wrap maths, works
    at any terminal width.

    Wave state at step i:
      plaintext[0 .. i-WAVE]     already revealed (plaintext chars)
      cipher x WAVE              the moving cipher window
    End-of-wave drain reveals the last WAVE chars one by one.
    """
    WAVE = 6
    n    = len(plaintext)
    if n == 0:
        sys.stdout.write(prefix + "\n")
        sys.stdout.flush()
        return

    # ── fast path ─────────────────────────────────────────────────────────────
    if _SKIP_ANIM.is_set():
        sys.stdout.write(prefix + plaintext + RESET + "\n")
        sys.stdout.flush()
        return

    # Save cursor position — we restore here at every frame
    sys.stdout.write("\0337")
    sys.stdout.flush()

    def _write_state(revealed: int, wave_end: int) -> None:
        """Restore to saved pos, write prefix + plaintext[:revealed] + cipher window."""
        sys.stdout.write("\0338" + RESET + prefix)
        if revealed > 0:
            sys.stdout.write(plaintext[:revealed])
        for _ in range(wave_end - revealed):
            sys.stdout.write(
                random.choice(_CIPHER_COLORS) + random.choice(_CIPHER_POOL) + RESET
            )
        sys.stdout.flush()

    # ── main wave ─────────────────────────────────────────────────────────────
    for i in range(n):
        if _SKIP_ANIM.is_set():
            break
        # revealed = chars before the WAVE window
        revealed = max(0, i + 1 - WAVE)
        _write_state(revealed, i + 1)
        time.sleep(_CIPHER_CHAR_DELAY)

    # ── end-of-wave drain: reveal last WAVE chars one by one ─────────────────
    end_delay = min(_PLAIN_CHAR_MAX, _REVEAL_PAUSE / max(WAVE, 1))
    for k in range(max(0, n - WAVE), n):
        if _SKIP_ANIM.is_set():
            break
        _write_state(k + 1, n)
        time.sleep(end_delay)

    # ── final clean overwrite ─────────────────────────────────────────────────
    sys.stdout.write("\0338" + RESET + prefix + plaintext + RESET + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Katana Zero word animation engine — fully automatic, no user markup needed
# ---------------------------------------------------------------------------
# Tag sets the animation rhythm (speed per word).
# Each word is independently classified by the engine and gets its own color.
# Both layers apply simultaneously: tag = speed, word detection = color.
#
# Word classifications (auto-detected, no syntax needed from user):
#   ALL CAPS          → shout    — instant red pop
#   word...           → trailing — dim grey, slow fade-in
#   @mention          → mention  — bright cyan highlight
#   number/digit      → number   — slightly emphasized white
#   intensifier       → intense  — bold bright white
#   happy/positive    → happy    — bright green
#   angry/urgent      → angry    — bright red/orange
#   sad/low-energy    → sad      — dim blue
#   surprised/shocked → shocked  — bright yellow flash
#   question word     → question — cyan
#   normal            → normal   — default terminal color
# ---------------------------------------------------------------------------

# ── Word emotion dictionaries ─────────────────────────────────────────────────

_HAPPY_WORDS = {
    # joy / excitement
    "great","love","perfect","nice","good","awesome","excellent","amazing",
    "wonderful","fantastic","happy","joy","best","beautiful","brilliant",
    "superb","outstanding","incredible","magnificent","glorious","splendid",
    "delightful","marvelous","exceptional","extraordinary","terrific",
    # social / gratitude
    "congrats","congratulations","thanks","thank","appreciate","proud",
    "grateful","thankful","blessed","honored","respect","welcome","cheers",
    "bravo","kudos","legend","goat","elite","fire","lit","based",
    # success / achievement
    "win","won","success","victory","achieved","done","completed","finished",
    "solved","fixed","working","shipped","deployed","released","launched",
    "passed","approved","accepted","confirmed","verified","valid","clean",
    # positive vibes
    "yes","yay","cool","sweet","glad","pleased","excited","enjoy","fun",
    "laugh","smile","cheerful","positive","hope","hype","hyped","lets","letsgo",
    "nice","dope","sick","goated","smooth","solid","crisp","clean","fresh",
    "perfect","flawless","easy","ez","gg","poggers","pog","lol","haha",
    "hahaha","lmao","lmfao","rofl","xd",
}

_ANGRY_WORDS = {
    # frustration / failure
    "hate","wrong","broken","stop","bad","terrible","awful","horrendous",
    "atrocious","dreadful","pathetic","garbage","trash","rubbish","junk",
    "useless","worthless","pointless","stupid","dumb","idiotic","braindead",
    "fail","failed","failure","failing","crash","crashed","crashing","bug",
    "bugs","buggy","error","errors","glitch","glitches","corrupt","corrupted",
    "problem","problems","issue","issues","disaster","catastrophe","mess",
    # urgency
    "urgent","asap","immediately","critical","emergency","priority","now",
    "broken","offline","down","dead","stuck","blocked","denied","rejected",
    "banned","suspended","terminated","deleted","lost","missing","gone",
    # anger words
    "unacceptable","ridiculous","absurd","outrageous","disgusting","pathetic",
    "infuriating","maddening","enraging","infuriated","furious","rage","angry",
    "mad","livid","outraged","annoyed","irritated","frustrated","pissed",
    "annoying","irritating","frustrating","impossible","unbearable","intolerable",
    "horrible","worst","terrible","awful","disgusting","revolting","appalling",
    # curse words
    "fuck","fucked","fucking","fucker","fucks","motherfucker","mf",
    "shit","shitty","bullshit","bs","horseshit","shitstorm",
    "damn","dammit","damned","goddamn","goddammit",
    "ass","asshole","asshat","jackass","smartass","dumbass","dipshit",
    "bitch","bitching","bitchy","son","bastard",
    "crap","crapload","crappy",
    "hell","wtf","stfu","gtfo","kys","ffs","smh",
    "idiot","moron","imbecile","buffoon","clown","loser","creep",
    "screw","screwed","piss","pissy","hate","detests",
}

_SAD_WORDS = {
    # core sadness
    "sorry","sad","hurt","miss","lost","gone","alone","lonely","isolated",
    "abandoned","rejected","unloved","unwanted","invisible","forgotten",
    "tired","exhausted","drained","burnt","burnout","depleted","empty",
    "numb","hollow","broken","shattered","crushed","devastated","destroyed",
    # emotional distress
    "disappointed","heartbroken","grief","grieving","mourning","depressed",
    "depression","anxious","anxiety","hopeless","helpless","worthless",
    "useless","failure","loser","pathetic","weak","fragile","vulnerable",
    # regret / apology
    "unfortunately","regret","regrets","regretful","wish","wished","mistake",
    "mistakes","oops","apologize","apologies","apology","pardon","forgive",
    "forgiveness","blame","fault","guilty","shame","ashamed","embarrassed",
    # difficulty
    "afraid","scared","terrified","frightened","worried","worrying","concern",
    "concerned","nervous","stressed","stress","struggling","struggle","suffer",
    "suffering","pain","painful","agony","miserable","misery","cry","crying",
    "tears","weeping","aching","difficult","hard","tough","rough","dark",
}

_SHOCKED_WORDS = {
    # disbelief
    "wait","what","wow","omg","wtf","wth","omfg","seriously","really",
    "actually","literally","honest","honestly","genuinely","truly","really",
    "impossible","unbelievable","unreal","unthinkable","inconceivable",
    "incredible","shocking","shocking","stunned","speechless","mindblown",
    "unexpected","sudden","suddenly","overnight","instantly","immediately",
    # reactions
    "whoa","woah","damn","holy","insane","crazy","wild","nuts","bonkers",
    "absurd","surreal","bizarre","weird","strange","odd","peculiar",
    "no","nope","nah","no way","never","wut","huh","eh","uh","um","hmm",
    "bruh","bro","dude","man","yo","ayo","oi","oof","yikes","sheesh",
    "dayum","dayumn","geez","gosh","dang","shoot","snap","crikey",
}

# Only true interrogative words — not auxiliary verbs
_QUESTION_WORDS = {
    "who","what","why","when","how","where","which","whose","whom",
    "whatever","whoever","whenever","wherever","however","whichever",
}

_INTENSIFIERS = {
    # degree
    "very","extremely","absolutely","completely","totally","utterly","fully",
    "entirely","wholly","perfectly","purely","quite","rather","fairly",
    "terribly","awfully","dreadfully","frightfully","incredibly","remarkably",
    "especially","particularly","specifically","notably","significantly",
    "highly","deeply","strongly","heavily","seriously","severely","badly",
    # certainty
    "definitely","certainly","surely","undoubtedly","unquestionably","clearly",
    "obviously","evidently","apparently","plainly","simply","just","literally",
    "basically","essentially","fundamentally","really","truly","genuinely",
    "honestly","frankly","absolutely","positively","categorically",
    # frequency / scope
    "always","never","forever","constantly","continuously","perpetually",
    "everywhere","anywhere","nowhere","everything","anything","nothing",
    "everyone","anyone","nobody","somebody","all","none","every","each",
}

_EXCITED_WORDS = {
    "hype","hyped","fire","lit","banger","letsgo","lets","go","poggers","pog",
    "insane","crazy","wild","nuts","epic","legendary","goated","peak","based",
    "bussin","slaps","bop","heat","flames","absolute","unit","beast","god",
    "cracked","nasty","filthy","dirty","clean","crispy","crisp","smooth",
    "unstoppable","unreal","unmatched","untouchable","dominant","obliterated",
    "destroyed","clapped","rekt","bodied","demolished","annihilated","carried",
    "popping","popped","banging","slapping","hitting","going","going","off",
    "vibrating","vibing","vibes","energy","surge","rush","boost","turbo",
    "max","maxed","full","send","sending","sent","launched","blasted","rocket",
    "zooming","zoomed","flying","soaring","rising","climbing","skyrocket",
    "let","go","goo","gooo","lesgo","letsgooo","sheesh","sheeeesh","yoooo",
}

_UNCERTAIN_WORDS = {
    "maybe","idk","dunno","probably","guess","perhaps","kinda","sorta","ish",
    "possibly","potentially","presumably","apparently","seemingly","supposedly",
    "roughly","approximately","around","about","almost","nearly","somewhat",
    "kind","sort","type","like","fairly","pretty","quite","rather","relatively",
    "might","could","would","should","may","unsure","uncertain","unclear",
    "confused","confusing","complicated","complex","ambiguous","vague","fuzzy",
    "not sure","not certain","not clear","not sure","hard to say","depends",
    "wondering","wonder","curious","not sure","thinking","thought","feel",
    "suppose","suspect","reckon","imagine","assume","believe","think",
}

_THREAT_WORDS = {
    "careful","watch","beware","risk","danger","caution","avoid","warning",
    "alert","alarm","hazard","threat","menace","peril","jeopardy","crisis",
    "critical","severe","extreme","high","elevated","imminent","incoming",
    "suspicious","suspect","shady","sketchy","fishy","off","wrong","bad",
    "malicious","malware","virus","hack","hacked","breach","compromised",
    "leaked","exposed","vulnerable","attack","attacked","attacking","exploit",
    "phishing","scam","fraud","fake","spoofed","hijacked","targeted","pwned",
    "stay","heads","up","watch","out","look","out","be","careful","dont",
    "never","trust","verify","check","double","check","confirm","validate",
}

_TIMEPRESSURE_WORDS = {
    "deadline","late","overdue","today","tonight","tomorrow","asap","now",
    "urgent","immediately","soon","quickly","fast","hurry","rush","sprint",
    "yesterday","due","past","due","missed","delayed","behind","schedule",
    "running","out","time","clock","ticking","countdown","expire","expiring",
    "expired","timeout","timeouts","cutoff","last","chance","final","closing",
    "end","ends","ending","closing","close","almost","nearly","minutes","hours",
    "seconds","deadline","crunch","pressure","pending","waiting","overdue",
    "morning","afternoon","evening","midnight","noon","eod","eow","eom",
}

_SOCIAL_WORDS = {
    "bro","bruh","yo","dude","man","guys","everyone","team","hey","ayo",
    "fam","homie","homies","crew","squad","gang","people","folks","peeps",
    "friend","friends","buddy","mate","pal","partner","colleague","boss",
    "sir","ma","madam","chief","captain","boss","king","queen","legend",
    "brother","sister","sibling","cousin","neighbor","stranger","person",
    "yall","ya'll","u","ur","you","your","yours","yourself","yourselves",
    "them","they","those","these","we","us","our","ours","ourselves","i",
}

_AGREEMENT_WORDS = {
    "yes","yep","yup","yeah","yah","ya","sure","ok","okay","k","kk","ight",
    "alright","right","correct","exactly","precisely","absolutely","definitely",
    "roger","copy","affirmative","confirmed","understood","noted","received",
    "gotcha","got","agreed","agree","concur","seconded","approved","accepted",
    "valid","true","fact","facts","accurate","spot","on","nail","nailed",
    "true","real","legit","based","solid","good","great","perfect","nice",
    "makes","sense","fair","enough","works","fine","cool","sounds","good",
}

_DISAGREEMENT_WORDS = {
    "no","nope","nah","negative","nay","disagree","wrong","incorrect","false",
    "reject","denied","denied","refused","declined","rejected","vetoed",
    "absolutely not","no way","not a chance","never","not happening","nope",
    "invalid","inaccurate","mistaken","error","bug","issue","problem","flaw",
    "but","however","although","though","yet","still","nevertheless","despite",
    "except","unless","until","without","against","oppose","opposed","counter",
    "contradict","refute","dispute","challenge","question","doubt","skeptical",
}

_GREETING_WORDS = {
    "hi","hello","hey","howdy","hiya","sup","wassup","whatsup","what's up",
    "greetings","salutations","good morning","good afternoon","good evening",
    "morning","afternoon","evening","night","gm","gn","goodnight","goodmorning",
    "bye","goodbye","cya","later","laters","ttyl","ttys","peace","out","deuces",
    "take care","stay safe","see you","see ya","catch you","later","peaceout",
    "farewell","adieu","adios","ciao","sayonara","toodles","cheers","seeya",
    "wb","welcome back","welcome","back","nice to see","glad you're here",
}

# ── ANSI styles per word class ────────────────────────────────────────────────

_KZ_STYLES = {
    # original categories
    "shout":       "[1;91m",     # bold bright red          — loud impact
    "trailing":    "[2;90m",     # dim dark grey            — fading out
    "mention":     "[1;95m",     # bold bright magenta      — @user highlight
    "number":      "[38;5;214m", # amber orange             — data/value
    "intense":     "[1;97m",     # bold bright white        — emphasis
    "happy":       "[1;92m",     # bold bright green        — positive
    "angry":       "[38;5;202m", # deep orange-red          — anger
    "sad":         "[38;5;69m",  # steel blue               — melancholy
    "shocked":     "[1;93m",     # bold bright yellow       — surprise
    "question":    "[38;5;51m",  # bright aqua              — inquiry
    # new categories
    "excited":     "[38;5;213m", # hot pink/fuchsia         — hype energy
    "uncertain":   "[38;5;245m", # medium grey              — ambiguity
    "threat":      "[38;5;196m", # pure red (brighter)      — danger/warning
    "timepressure":"[38;5;220m", # gold yellow              — urgency/time
    "social":      "[38;5;159m", # light sky blue           — address/people
    "agreement":   "[38;5;120m", # light green              — yes/confirm
    "disagreement":"[38;5;210m", # soft red/salmon          — no/reject
    "greeting":    "[38;5;227m", # pale yellow              — hello/bye
    "normal":      "",               # default terminal color
}

# ── Base delay between words per tag ─────────────────────────────────────────

_KZ_WORD_DELAY = {
    "danger": 0.022,
    "warn":   0.034,
    "ok":     0.046,
    "req":    0.052,
    "ask":    0.058,
    "info":   0.064,
    "normal": 0.040,
}

_KZ_PUNCT_PAUSE = {".": 3.5, "!": 2.0, "?": 2.8, ",": 1.6, ";": 1.8, ":": 1.5}


def _kz_classify(word: str) -> str:
    """
    Classify a single word into a KZ style category.
    Order matters — more specific checks first.
    """
    import re
    bare = word.rstrip(".,!?;:").lower()
    raw  = word.rstrip(".,!?;:")

    # Structural detections first
    if raw == raw.upper() and len(raw) >= 2 and raw.isalpha():
        return "shout"
    if word.endswith("...") or word.endswith("…"):
        return "trailing"
    if bare.startswith("@") and len(bare) > 1:
        return "mention"
    if re.match(r"^-?\d[\d,.%$€£]*$", bare):
        return "number"

    # Semantic detections — order matters, more specific wins
    if bare in _INTENSIFIERS:
        return "intense"
    if bare in _THREAT_WORDS:
        return "threat"
    if bare in _TIMEPRESSURE_WORDS:
        return "timepressure"
    if bare in _GREETING_WORDS:
        return "greeting"
    if bare in _SOCIAL_WORDS:
        return "social"
    if bare in _AGREEMENT_WORDS:
        return "agreement"
    if bare in _DISAGREEMENT_WORDS:
        return "disagreement"
    if bare in _EXCITED_WORDS:
        return "excited"
    if bare in _HAPPY_WORDS:
        return "happy"
    if bare in _ANGRY_WORDS:
        return "angry"
    if bare in _SAD_WORDS:
        return "sad"
    if bare in _UNCERTAIN_WORDS:
        return "uncertain"
    if bare in _SHOCKED_WORDS:
        return "shocked"
    if bare in _QUESTION_WORDS:
        return "question"

    return "normal"


def _kz_render(word: str, style: str) -> str:
    """Apply ANSI color for a word's style."""
    color = _KZ_STYLES.get(style, "")
    if not color:
        return word
    if style == "shout":
        return f"{color}{word.upper()}[0m"
    return f"{color}{word}[0m"


def _kz_tokenize(text: str) -> list:
    """Split text into (word, style) pairs, preserving punctuation on words.

    Also strips any leftover markup syntax characters (*,_,~) that might
    appear literally in the message so they never show on screen.
    """
    import re
    # Strip any residual markup markers — *word*, _word_, ~word~, **word**
    # These are no longer valid syntax but could appear in old messages or
    # if someone types them literally.
    clean = re.sub(r'\*{1,2}([^*]+)\*{1,2}', r'', text)
    clean = re.sub(r'~([^~]+)~', r'', clean)
    clean = re.sub(r'(?<!\w)_([^_]+)_(?!\w)', r'', clean)
    tokens = []
    for word in re.split(r'(\s+)', clean):
        if not word or word.isspace():
            continue
        tokens.append((word, _kz_classify(word)))
    return tokens


def _has_kz_content(text: str) -> bool:
    """Return True if any word in text would get a non-normal KZ style."""
    return any(style != "normal" for _, style in _kz_tokenize(text))


def _run_kz_animation(prefix: str, plaintext: str, tag: str = "") -> None:
    """
    Word-by-word cipher wave animation.

    Each word runs through the same cipher wave as the full-sentence animation
    (random chars scrolling → plaintext reveal) but word by word.
    Emotion color is applied when the word finally reveals.
    Tag sets the wave speed per word.
    Shout words skip the wave and pop in instantly.
    Trailing words use a slower wave.
    Escape skips to full reveal immediately.
    """
    tokens = _kz_tokenize(plaintext)
    if not tokens:
        sys.stdout.write(prefix + "\n")
        sys.stdout.flush()
        return

    if _SKIP_ANIM.is_set():
        sys.stdout.write(prefix)
        for i, (w, sty) in enumerate(tokens):
            sys.stdout.write(_kz_render(w, sty))
            if i < len(tokens) - 1:
                sys.stdout.write(" ")
        sys.stdout.write(RESET + "\n")
        sys.stdout.flush()
        return

    WAVE = 4   # cipher window width per word (shorter than full-sentence wave)
    base_char_delay = _KZ_WORD_DELAY.get(tag, _KZ_WORD_DELAY["normal"]) * 0.35

    # Save cursor once — we restore to here to redraw the whole line each frame
    sys.stdout.write("\0337" + prefix)
    sys.stdout.flush()

    revealed: list = []   # list of (word, style) already shown

    def _redraw_line(word_placeholder: str = "") -> None:
        """Restore saved cursor, rewrite prefix + revealed words + placeholder."""
        sys.stdout.write("\0338" + RESET + prefix)
        for i, (w, sty) in enumerate(revealed):
            sys.stdout.write(_kz_render(w, sty))
            sys.stdout.write(" ")
        if word_placeholder:
            sys.stdout.write(word_placeholder)
        sys.stdout.flush()

    def _wave_reveal_word(word: str, style: str) -> None:
        """Run the cipher wave over a single word then snap to its colored form."""
        n = len(word)
        color = _KZ_STYLES.get(style, "")

        # Speed modifiers per style
        if style == "trailing":
            delay = base_char_delay * 1.7
        elif style in ("shout", "shocked"):
            delay = base_char_delay * 0.3
        elif style in ("intense", "mention"):
            delay = base_char_delay * 0.7
        else:
            delay = base_char_delay

        # Wave: cipher chars scroll across the word length
        for i in range(n):
            if _SKIP_ANIM.is_set():
                break
            revealed_chars = max(0, i + 1 - WAVE)
            # already-revealed part of this word in its final color
            prefix_part = (color + word[:revealed_chars] + RESET) if revealed_chars else ""
            # cipher window
            cipher_part  = "".join(
                random.choice(_CIPHER_COLORS) + random.choice(_CIPHER_POOL) + RESET
                for _ in range(min(WAVE, i + 1))
            )
            _redraw_line(prefix_part + cipher_part)
            time.sleep(delay)

        # Drain: reveal last WAVE chars
        drain_delay = delay * 0.6
        for k in range(max(0, n - WAVE), n):
            if _SKIP_ANIM.is_set():
                break
            prefix_part = color + word[:k + 1] + RESET
            _redraw_line(prefix_part)
            time.sleep(drain_delay)

        # Word fully revealed — add to revealed list
        revealed.append((word, style))
        _redraw_line()

    for word, style in tokens:
        if _SKIP_ANIM.is_set():
            revealed.append((word, style))
            continue

        if style == "shout":
            # Block flash then instant snap — no wave, just impact
            _redraw_line(
                "[1;91m" + "█" * len(word) + RESET
            )
            time.sleep(0.022)
            revealed.append((word, style))
            _redraw_line()
            time.sleep(base_char_delay * 0.9)
        else:
            _wave_reveal_word(word, style)

        # Natural pause on sentence-ending punctuation
        last_char = word[-1] if word else ""
        if last_char in _KZ_PUNCT_PAUSE and not _SKIP_ANIM.is_set():
            pause = base_char_delay * _KZ_PUNCT_PAUSE[last_char] * 1.2
            elapsed = 0.0
            while elapsed < pause and not _SKIP_ANIM.is_set():
                time.sleep(0.02)
                elapsed += 0.02

    # Final clean write — full line with all emotion colors
    sys.stdout.write("\0338" + RESET + prefix)
    for i, (word, style) in enumerate(_kz_tokenize(plaintext)):
        sys.stdout.write(_kz_render(word, style))
        if i < len(tokens) - 1:
            sys.stdout.write(" ")
    sys.stdout.write(RESET + "\n")
    sys.stdout.flush()



def _animate_msg(prefix: str, plaintext: str, room: str,
                  from_user: str = "", ts: str = "",
                  tag: str = "") -> None:
    """Run animation inside the output lock, log the final text, mark seen."""
    _room_logs[room].append(prefix + plaintext)
    if from_user and ts:
        mark_seen(room, from_user, ts, plaintext)
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        # Use KZ word animation when message has a tag or any word
        # the engine would style (ALL CAPS, emotion words, @mentions etc).
        # Fall back to cipher wave for plain untagged messages with no
        # interesting words — keeps the original feel for simple chatter.
        if tag or _has_kz_content(plaintext):
            _run_kz_animation(prefix, plaintext, tag=tag)
        else:
            _run_animation(prefix, plaintext)
        _redraw_input_unsafe()


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
    ts_part   = cgrey(f"[{msg_ts}]")
    # Own messages use YELLOW (matching what was displayed at send time).
    # Other users use GREEN.  Tagged messages use the tag's color instead.
    if tag and tag in TAGS:
        color = TAGS[tag]["color"]
        bold  = TAGS[tag]["bold"]
    else:
        color = YELLOW if (own_username and from_user == own_username) else GREEN
        bold  = True
    user_part  = colorize(from_user, color, bold=bold)
    badge_part = format_tag_badge(tag)
    prefix     = f"{ts_part} {user_part}: {badge_part}"
    rendered   = prefix + plaintext

    # Already seen — reprint plain (no animation) so it shows in the room
    # after a screen clear / room switch.
    if already_seen(room, from_user, msg_ts, plaintext):
        _room_logs[room].append(rendered)
        print_msg(rendered)
        return

    if not anim_enabled or not _is_tty():
        log_and_print(room, rendered)
        mark_seen(room, from_user, msg_ts, plaintext)
    else:
        _animate_msg(prefix, plaintext, room, from_user=from_user, ts=msg_ts, tag=tag)

    # Play notification sound after printing (daemon thread — non-blocking)
    if tag and tag in TAGS and from_user != own_username:
        play_notification(TAGS[tag]["sound"])
    elif not tag and from_user != own_username:
        play_notification("normal")


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
    ts_part   = cgrey(f"[{msg_ts}]")
    src_part  = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig_part  = cok("✓") if verified else cwarn("?")
    badge_part = format_tag_badge(tag)
    prefix    = f"{ts_part} {src_part}{sig_part} {badge_part}"
    rendered  = prefix + plaintext

    if already_seen(room, from_user, msg_ts, plaintext):
        print_msg(rendered)   # replay — don't re-log, already in _room_logs
        return

    if not anim_enabled or not _is_tty():
        log_and_print(room, rendered)
        mark_seen(room, from_user, msg_ts, plaintext)
    else:
        _animate_msg(prefix, plaintext, room, from_user=from_user, ts=msg_ts, tag=tag)

    # Play notification sound (always for PMs — they deserve attention)
    if tag and tag in TAGS:
        play_notification(TAGS[tag]["sound"])
    else:
        play_notification("info")   # PMs always ping


# ---------------------------------------------------------------------------
# No-echo input
# ---------------------------------------------------------------------------

def read_line_noecho() -> str:
    """
    Read a line with manual echo and left/right cursor movement.

    Characters go into _g_buf (cursor tracked by _g_cur) so print_msg()
    can erase/redraw them cleanly around incoming messages.

    Keys:
      Printable       inserted at cursor position
      Backspace/Del   delete char left of cursor
      Left/Right      move cursor (CSI ESC[D/C or SS3 ESC OD/OC)
      Home/End        jump to start/end
      Up/Down/scroll  consumed silently
      Escape          trigger animation skip
      Ctrl+C/D        raise KeyboardInterrupt/EOFError
    """
    global _g_input_active, _g_buf, _g_cur

    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\n")

    import termios, tty

    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    result       = ""

    with _OUTPUT_LOCK:
        _g_buf          = []
        _g_cur          = 0
        _g_input_active = True

    import os as _os, select as _sel

    def _readbyte():
        return _os.read(fd, 1).decode("utf-8", errors="replace")

    def _inline_redraw():
        """Redraw tail from cursor to end, then reposition. Caller holds lock."""
        tail = "".join(_g_buf[_g_cur:])
        sys.stdout.write(tail + " ")          # trailing space erases leftover on delete
        sys.stdout.write(f"\033[{len(tail)+1}D")  # move cursor back
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
                    _g_buf          = []
                    _g_cur          = 0
                break

            elif ch == "\x03":
                with _OUTPUT_LOCK:
                    _g_input_active = False
                    _g_buf = []; _g_cur = 0
                raise KeyboardInterrupt

            elif ch == "\x04":
                with _OUTPUT_LOCK:
                    _g_input_active = False
                    _g_buf = []; _g_cur = 0
                raise EOFError

            elif ch in ("\x7f", "\x08"):
                with _OUTPUT_LOCK:
                    if _g_cur > 0:
                        _g_buf.pop(_g_cur - 1)
                        _g_cur -= 1
                        sys.stdout.write("\033[D")   # move cursor left
                        _inline_redraw()

            elif ch == "\x1b":
                r, _, _ = _sel.select([fd], [], [], 0.05)
                if not r:
                    trigger_skip_animation()
                    continue
                nxt = _readbyte()
                if nxt in ("[", "O"):
                    r2, _, _ = _sel.select([fd], [], [], 0.05)
                    if not r2:
                        continue
                    fin = _readbyte()
                    with _OUTPUT_LOCK:
                        if fin == "D":                # Left
                            if _g_cur > 0:
                                _g_cur -= 1
                                sys.stdout.write("\033[D")
                                sys.stdout.flush()
                        elif fin == "C":              # Right
                            if _g_cur < len(_g_buf):
                                _g_cur += 1
                                sys.stdout.write("\033[C")
                                sys.stdout.flush()
                        elif fin == "H":              # Home
                            if _g_cur > 0:
                                sys.stdout.write(f"\033[{_g_cur}D")
                                _g_cur = 0
                                sys.stdout.flush()
                        elif fin == "F":              # End
                            trail = len(_g_buf) - _g_cur
                            if trail > 0:
                                sys.stdout.write(f"\033[{trail}C")
                                _g_cur = len(_g_buf)
                                sys.stdout.flush()
                        elif fin == "5":        # PageUp = ESC[5~
                            r3,_,_ = _sel.select([fd],[],[],0.05)
                            if r3: _readbyte()  # consume trailing ~
                            _erase_input_unsafe()
                            room = _current_room[0]
                            log  = _room_logs.get(room, [])
                            if log:
                                lines = log[-30:]
                                sys.stdout.write(colorize(f"\n  \u2500\u2500 last {len(lines)} of {len(log)} messages \u2500\u2500\n","\033[90m"))
                                for ln in lines: print(ln)
                                sys.stdout.write("\n")
                                sys.stdout.flush()
                            _redraw_input_unsafe()
                        elif not (fin.isalpha() or fin == "~"):
                            # Extended sequence — drain until terminator
                            while True:
                                r3, _, _ = _sel.select([fd], [], [], 0.05)
                                if not r3: break
                                b = _readbyte()
                                if b.isalpha() or b == "~": break
                        # Up/Down/F-keys — fin consumed, ignore

            elif ch >= " ":
                with _OUTPUT_LOCK:
                    _g_buf.insert(_g_cur, ch)
                    _g_cur += 1
                    if _g_cur == len(_g_buf):
                        sys.stdout.write(ch)
                        sys.stdout.flush()
                    else:
                        sys.stdout.write(ch)
                        _inline_redraw()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        with _OUTPUT_LOCK:
            _g_input_active = False
            _g_buf = []; _g_cur = 0

    return result

def format_message(username: str, text: str, timestamp: str) -> str:
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, GREEN, bold=True)
    return f"{ts} {usr}: {text}"


def format_own_message(username: str, text: str, timestamp: str) -> str:
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, YELLOW, bold=True)
    return f"{ts} {usr}: {text}"


def format_system(text: str, timestamp: str) -> str:
    ts  = cgrey(f"[{timestamp}]")
    tag = colorize("[SYSTEM]", YELLOW, bold=True)
    return f"{ts} {tag} {text}"


def format_privmsg(from_user: str, text: str, timestamp: str, verified: bool) -> str:
    ts  = cgrey(f"[{timestamp}]")
    src = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig = cok("✓") if verified else cwarn("?")
    return f"{ts} {src}{sig} {text}"
