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

BANNER = r"""
 _   _       _____
| \ | | ___ | ____|_   _  ___  ___
|  \| |/ _ \|  _| | | | |/ _ \/ __|
| |\  | (_) | |___| |_| |  __/\__ \
|_| \_|\___/|_____|\__, |\___||___/
                   |___/
  Secure Terminal Chat  |  E2E Encrypted
"""


def print_banner() -> None:
    print(colorize(BANNER, CYAN, bold=True))


# ---------------------------------------------------------------------------
# Global input state
#
# read_line_noecho() writes every typed char into _g_buf and sets
# _g_input_active = True.  Any thread that wants to print something calls
# print_msg() which:
#   1. acquires _OUTPUT_LOCK
#   2. erases the current partial input (if any) from the screen
#   3. prints the message
#   4. redraws the partial input so the user can keep typing
#   5. releases _OUTPUT_LOCK
#
# This means incoming messages, animations, status lines — everything —
# always land cleanly above the input line regardless of race conditions.
# ---------------------------------------------------------------------------

_OUTPUT_LOCK    = threading.Lock()   # serialises ALL terminal writes
_g_buf          : list  = []         # chars typed so far (shared with input thread)
_g_input_active : bool  = False      # True while noecho loop is running


def _get_tw() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _erase_input_unsafe() -> None:
    """Erase the current partial input from the screen (no lock — caller holds it)."""
    if not _g_input_active or not _g_buf:
        return
    tw = _get_tw()
    n  = len(_g_buf)
    lines_up = (n - 1) // tw   # number of extra rows above the last row
    if lines_up:
        sys.stdout.write("\033[" + str(lines_up) + "A")
    sys.stdout.write("\r\033[J")
    sys.stdout.flush()


def _redraw_input_unsafe() -> None:
    """Redraw the partial input after a message was printed (no lock — caller holds it)."""
    if not _g_input_active or not _g_buf:
        return
    sys.stdout.write("".join(_g_buf))
    sys.stdout.flush()


def print_msg(text: str) -> None:
    """
    Print a line of output, cleanly interleaving with any in-progress input.
    ALL output in the client must go through this function (or print_msg_raw).
    """
    if not _is_tty():
        print(text)
        return
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        print(text)
        _redraw_input_unsafe()


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
    "\033[36m",    # cyan
    "\033[1;36m",  # bright cyan
    "\033[96m",    # light cyan
    "\033[1;96m",  # bold light cyan
]

_CIPHER_CHAR_DELAY = 0.022
_REVEAL_PAUSE      = 0.38
_PLAIN_CHAR_MAX    = 0.060
_PLAIN_TOTAL_CAP   = 2.0


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _run_animation(prefix: str, plaintext: str) -> None:
    """
    Wave-decrypt animation. Called while _OUTPUT_LOCK is held.
    Input line is already erased; we redraw it at the end.
    """
    WAVE = 6
    n    = len(plaintext)
    if n == 0:
        sys.stdout.write(prefix + "\n")
        sys.stdout.flush()
        return

    tw         = _get_tw()
    prefix_vis = len(_strip_ansi(prefix))

    # ── Phase 1: wave stream ──────────────────────────────────────────────
    sys.stdout.write(prefix)
    sys.stdout.flush()

    for i in range(n):
        sys.stdout.write(random.choice(_CIPHER_COLORS) + random.choice(_CIPHER_POOL) + RESET)
        sys.stdout.flush()

        reveal_i = i - WAVE
        if reveal_i >= 0:
            cursor_col = (prefix_vis + i + 1) % tw
            if cursor_col >= WAVE + 1:
                sys.stdout.write(
                    "\033[" + str(WAVE + 1) + "D"
                    + plaintext[reveal_i]
                    + "\033[" + str(WAVE) + "C"
                )
                sys.stdout.flush()

        time.sleep(_CIPHER_CHAR_DELAY)

    time.sleep(_REVEAL_PAUSE * 0.4)

    # ── Phase 2: cleanup ──────────────────────────────────────────────────
    lines_up = (prefix_vis + n) // tw
    if lines_up:
        sys.stdout.write("\033[" + str(lines_up) + "A")
    sys.stdout.write("\r" + prefix + plaintext + "\n")
    sys.stdout.flush()


def chat_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    anim_enabled: bool = True,
) -> None:
    ts_part   = cgrey(f"[{msg_ts}]")
    user_part = colorize(from_user, GREEN, bold=True)
    prefix    = f"{ts_part} {user_part}: "

    if not anim_enabled or not _is_tty():
        print_msg(prefix + plaintext)
        return

    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _run_animation(prefix, plaintext)
        _redraw_input_unsafe()


def privmsg_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    verified: bool = False,
    anim_enabled: bool = True,
) -> None:
    ts_part  = cgrey(f"[{msg_ts}]")
    src_part = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig_part = cok("✓") if verified else cwarn("?")
    prefix   = f"{ts_part} {src_part}{sig_part} "

    if not anim_enabled or not _is_tty():
        print_msg(prefix + plaintext)
        return

    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _run_animation(prefix, plaintext)
        _redraw_input_unsafe()


# ---------------------------------------------------------------------------
# No-echo input
# ---------------------------------------------------------------------------

def read_line_noecho() -> str:
    """
    Read a line from stdin with manual echo.  Characters are written into
    _g_buf so that any concurrent print_msg() call can erase/redraw them.
    On Enter: erase the input line(s) cleanly, return the string.
    Falls back to plain input() when stdin is not a TTY.
    """
    global _g_input_active, _g_buf

    if not sys.stdin.isatty():
        return input()

    import termios, tty

    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    result       = ""

    with _OUTPUT_LOCK:
        _g_buf          = []
        _g_input_active = True

    try:
        tty.setcbreak(fd)
        while True:
            ch = sys.stdin.read(1)

            if ch in ("\n", "\r"):
                with _OUTPUT_LOCK:
                    result          = "".join(_g_buf)
                    _erase_input_unsafe()
                    _g_input_active = False
                    _g_buf          = []
                break

            elif ch == "\x03":
                with _OUTPUT_LOCK:
                    _g_input_active = False
                    _g_buf          = []
                raise KeyboardInterrupt

            elif ch == "\x04":
                with _OUTPUT_LOCK:
                    _g_input_active = False
                    _g_buf          = []
                raise EOFError

            elif ch in ("\x7f", "\x08"):  # Backspace
                with _OUTPUT_LOCK:
                    if _g_buf:
                        _g_buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()

            elif ch == "\x1b":             # Escape / arrow keys — swallow
                nxt = sys.stdin.read(1)
                if nxt == "[":
                    sys.stdin.read(1)

            elif ch >= " ":                 # Printable char
                with _OUTPUT_LOCK:
                    _g_buf.append(ch)
                    sys.stdout.write(ch)
                    sys.stdout.flush()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        with _OUTPUT_LOCK:
            _g_input_active = False
            _g_buf          = []

    return result



# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

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
