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
    """True if we are attached to a real terminal (robust check)."""
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False


def colorize(text: str, color: str, bold: bool = False) -> str:
    """Wrap *text* with ANSI escape codes if stdout is a TTY."""
    if not _is_tty():
        return text
    prefix = BOLD if bold else ""
    return f"{prefix}{color}{text}{RESET}"


def cinfo(msg: str) -> str:
    return colorize(msg, CYAN)


def cwarn(msg: str) -> str:
    return colorize(msg, YELLOW, bold=True)


def cerr(msg: str) -> str:
    return colorize(msg, RED, bold=True)


def cok(msg: str) -> str:
    return colorize(msg, GREEN)


def cgrey(msg: str) -> str:
    return colorize(msg, GREY)


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------


def clear_screen() -> None:
    """Clear the terminal screen (cross-platform)."""
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
    """Print the ASCII banner with colour if the terminal supports it."""
    print(colorize(BANNER, CYAN, bold=True))


# ---------------------------------------------------------------------------
# Decrypt animation
#
# Two-phase cinematic effect on every incoming message:
#
#   Phase 1 — CIPHER: exactly len(plaintext) random characters from a
#              cinematic noise pool stream out in shifting purple/magenta.
#              Each char picks a different shade — not a flat block of colour.
#
#   Phase 2 — REVEAL: cursor rewinds (save/restore — works after line-wrap)
#              and the real plaintext types over the cipher position-by-
#              position.  Each character flashes bright-white for one tick
#              then settles to normal: the "lock-in" feel.
#
# A threading.Lock() serialises concurrent messages so two animations never
# interleave.  chat and privmsg share a single _run_animation() core.
#
# Toggle: /anim on|off  (stored in NoEyesClient._anim_enabled)
# Non-TTY: animation skipped entirely — plain print, no side effects.
# ---------------------------------------------------------------------------

# Character pool — box-drawing, block-elements, braille dots, symbol noise.
# No letters/digits: looks like encrypted noise, not garbled plaintext.
_CIPHER_POOL = list(
    "─│┌┐└┘├┤┬┴┼╔╗╚╝╠╣╦╩╬═║╒╓╕╖╘╙╛╜╞╟╡╢╤╥╧╨╪╫"
    "░▒▓█▀▄▌▐▖▗▘▙▚▛▜▝▞▟"
    "⠿⠾⠽⠻⠷⠯⠟⡿⢿"
    "!#$%&*+/<=>?@^~|*+-=<>{}[]"
    "·×÷±∑∏∂∇∞∴≈≠≡≤≥"
)

# Cyan shades — matches the NoEyes logo colour
_CIPHER_COLORS = [
    "\033[36m",    # cyan
    "\033[1;36m",  # bright cyan
    "\033[96m",    # light cyan
    "\033[1;96m",  # bold light cyan
]

# ── Timing ──────────────────────────────────────────────────────────────────
_CIPHER_CHAR_DELAY = 0.022   # s per cipher char
_REVEAL_PAUSE      = 0.38    # s pause between phases (the "moment of decryption")
_PLAIN_CHAR_MAX    = 0.060   # s per plaintext char (cap for short messages)
_PLAIN_TOTAL_CAP   = 2.0     # s max total for the whole plaintext phase

# VT100 cursor save/restore — supported by every modern terminal

# Serialise all animation writes so concurrent arrivals never interleave
_ANIM_LOCK = threading.Lock()


def _strip_ansi(s: str) -> str:
    """Strip ANSI escape codes to get the printable-only string."""
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _run_animation(prefix: str, plaintext: str) -> None:
    """
    Wave-decrypt animation.

    Phase 1 — wave: cipher chars stream forward while reveal chases 6 behind.
               At each step i: write cipher char at position i, then jump back
               WAVE+1 cols to overwrite position i-WAVE with the real char,
               then jump forward WAVE cols back to the end.
               Safe only when the back-jump doesn't cross a line boundary
               (cursor_col >= WAVE+1). Any position that can't be wave-revealed
               is handled by the cleanup pass.

    Phase 2 — cleanup: move cursor back to start, overwrite everything with
               full plaintext instantly. Snaps any leftover cipher chars clean.

    If n < WAVE: skip the wave, fall through to plain full-cipher then cleanup.
    """
    WAVE = 6
    n = len(plaintext)
    if n == 0:
        sys.stdout.write(prefix + "\n")
        sys.stdout.flush()
        return

    try:
        term_width = os.get_terminal_size().columns
    except OSError:
        term_width = 80

    prefix_vis = len(_strip_ansi(prefix))

    # ── Phase 1: wave stream ──────────────────────────────────────────────────
    sys.stdout.write(prefix)
    sys.stdout.flush()

    for i in range(n):
        # Write cipher char at current position (cursor advances by 1)
        sys.stdout.write(random.choice(_CIPHER_COLORS) + random.choice(_CIPHER_POOL) + RESET)
        sys.stdout.flush()

        reveal_i = i - WAVE
        if reveal_i >= 0:
            # cursor_col: column the cursor is at after writing cipher char i
            cursor_col = (prefix_vis + i + 1) % term_width
            if cursor_col >= WAVE + 1:
                # Safe: jump back WAVE+1, write plaintext char, jump forward WAVE
                sys.stdout.write(
                    f"\033[{WAVE + 1}D"
                    + plaintext[reveal_i]
                    + f"\033[{WAVE}C"
                )
                sys.stdout.flush()
            # else: crosses a line boundary — cleanup pass handles it

        time.sleep(_CIPHER_CHAR_DELAY)

    # Brief pause — shorter than normal since decryption already started
    time.sleep(_REVEAL_PAUSE * 0.4)

    # ── Phase 2: instant cleanup — snap all remaining cipher to plaintext ─────
    lines_up = (prefix_vis + n) // term_width
    if lines_up:
        sys.stdout.write(f"\033[{lines_up}A")
    sys.stdout.write("\r" + prefix + plaintext + "\n")
    sys.stdout.flush()


def chat_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    anim_enabled: bool = True,
) -> None:
    """Display an incoming group-chat message with the decrypt animation."""
    ts_part   = cgrey(f"[{msg_ts}]")
    user_part = colorize(from_user, GREEN, bold=True)
    prefix    = f"{ts_part} {user_part}: "

    if not anim_enabled or not _is_tty():
        print(prefix + plaintext)
        return

    with _ANIM_LOCK:
        _run_animation(prefix, plaintext)


def privmsg_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    verified: bool = False,
    anim_enabled: bool = True,
) -> None:
    """Display an incoming private message with the decrypt animation."""
    ts_part  = cgrey(f"[{msg_ts}]")
    src_part = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig_part = cok("✓") if verified else cwarn("?")
    prefix   = f"{ts_part} {src_part}{sig_part} "

    if not anim_enabled or not _is_tty():
        print(prefix + plaintext)
        return

    with _ANIM_LOCK:
        _run_animation(prefix, plaintext)


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def format_message(username: str, text: str, timestamp: str) -> str:
    """Format a chat line for display (incoming — other users)."""
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, GREEN, bold=True)
    return f"{ts} {usr}: {text}"


def format_own_message(username: str, text: str, timestamp: str) -> str:
    """Format a sent message — own name in bold yellow to stand out from others."""
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, YELLOW, bold=True)
    return f"{ts} {usr}: {text}"


def format_system(text: str, timestamp: str) -> str:
    """Format a system/event line for display."""
    ts = cgrey(f"[{timestamp}]")
    tag = colorize("[SYSTEM]", YELLOW, bold=True)
    return f"{ts} {tag} {text}"


def format_privmsg(from_user: str, text: str, timestamp: str, verified: bool) -> str:
    """Format a private message line, noting signature status."""
    ts  = cgrey(f"[{timestamp}]")
    src = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig = cok("✓") if verified else cwarn("?")
    return f"{ts} {src}{sig} {text}"
