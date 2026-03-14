# FILE: client.py
"""
client.py — NoEyes chat client.

Features:
  - Group chat: payload encrypted with shared Fernet (passphrase or key file).
  - Private /msg: automatic X25519 DH handshake on first contact, then
    pairwise Fernet encryption + Ed25519 signing.
  - TOFU pubkey tracking: ~/.noeyes/tofu_pubkeys.json
  - Identity: Ed25519 keypair at ~/.noeyes/identity.key (auto-generated on
    first run).
  - Commands: /help /quit /clear /users /nick /join /msg /send

Wire protocol:
    [4 bytes header_len BE][4 bytes payload_len BE][header JSON][encrypted payload]
"""

import base64
import json
import os
import queue
import readline  # enables arrow keys, history, line editing in input()
import socket
import struct
import sys
import threading
import time
from getpass import getpass
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from core import encryption as enc
from core import identity as id_mod
from core import utils
from core.utils import enter_tui, exit_tui

# ---------------------------------------------------------------------------
# File receive directory and type classification
# ---------------------------------------------------------------------------

# Place received files at the project root, not inside the network/ package
RECEIVE_BASE = Path(__file__).parent.parent / "received_files"

_TYPE_MAP = {
    "images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
               ".ico", ".tiff", ".tif", ".heic", ".heif"},
    "videos": {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
               ".m4v", ".mpg", ".mpeg"},
    "audio":  {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma",
               ".opus", ".aiff"},
    "docs":   {".pdf", ".doc", ".docx", ".txt", ".md", ".xlsx", ".xls",
               ".pptx", ".ppt", ".csv", ".odt", ".rtf", ".pages"},
}

FILE_CHUNK_SIZE = 512 * 1024  # 512 KB per wire frame.
# WHY 64 KB (not the old 4 MB):
#   1. SENDER side: _send_lo holds _sock_lock for one sendall() call. At 1 MB/s
#      bore bandwidth a 4 MB sendall blocks for ~4 seconds — during that window
#      the input thread cannot acquire the lock, so pressing Enter appears to do
#      nothing.  64 KB → ≤ 64 ms at 1 MB/s, imperceptible to the user.
#   2. RECEIVER side: recv_frame() reads the full payload before dispatching.
#      With 4 MB payloads, all incoming frames (chat, system, DH…) are blocked
#      for the duration of reading a single chunk.  64 KB means the recv loop
#      can process other frame types between every chunk.
#   3. Priority interleaving: hi-priority chat/control frames queued while a
#      chunk is in-flight get the socket between consecutive 64 KB chunks.
# Throughput impact: negligible — AES-256-GCM processes 64 KB in ~0.08 ms
# (800 MB/s hardware path) and TCP coalesces small writes in the kernel buffer.
# Binary frame: [4B index BE][4B tid_len BE][tid bytes][nonce(12)+ct+tag(16)]


def _file_type_folder(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    for folder, exts in _TYPE_MAP.items():
        if ext in exts:
            return folder
    return "other"


def _unique_dest(filename: str) -> Path:
    """Return a unique Path in the right files/<type> sub-folder."""
    folder = RECEIVE_BASE / _file_type_folder(filename)
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / filename
    counter = 1
    while dest.exists():
        stem, suffix = Path(filename).stem, Path(filename).suffix
        dest = folder / f"{stem}_{counter}{suffix}"
        counter += 1
    return dest


def _human_size(n: int) -> str:
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


# ---------------------------------------------------------------------------
# Framing (mirrors server.py — must stay in sync)
# ---------------------------------------------------------------------------


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> Optional[tuple[dict, bytes]]:
    """Read one frame.  Returns (header_dict, raw_payload_bytes) or None."""
    size_buf = _recv_exact(sock, 8)
    if size_buf is None:
        return None
    header_len  = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]

    # Sanity check — a zero or huge header means garbage data on the socket
    if header_len == 0 or header_len > 65536:
        return None

    # Guard against oversized payloads.
    # A compromised or malicious server could send payload_len = 4 GB to OOM
    # the client.  Cap matches the server-side MAX_PAYLOAD constant.
    _MAX_PAYLOAD = 16 * 1024 * 1024  # 16 MB — same as server.MAX_PAYLOAD
    if payload_len > _MAX_PAYLOAD:
        return None

    header_bytes  = _recv_exact(sock, header_len)
    if header_bytes is None:
        return None
    payload_bytes = _recv_exact(sock, payload_len) if payload_len else b""
    if payload_bytes is None:
        return None

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    return header, payload_bytes


def send_frame(sock: socket.socket, header: dict, payload: bytes = b"") -> bool:
    try:
        hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
        sock.sendall(struct.pack(">I", len(hb)) + struct.pack(">I", len(payload)) + hb + payload)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# NoEyesClient
# ---------------------------------------------------------------------------


class NoEyesClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        group_fernet: Fernet,
        group_key_bytes: bytes,
        room: str = "general",
        identity_path: str = "~/.noeyes/identity.key",
        tofu_path: str     = "~/.noeyes/tofu_pubkeys.json",
        reconnect: bool    = True,
        tls: bool          = False,
        tls_cert: str      = "",        # path to CA cert (manual override)
        tls_tofu_path: str = "~/.noeyes/tls_fingerprints.json",
        discovery_key: str = "",        # derived from group key — used to find new bore port
        no_discovery: bool = False,     # skip external discovery HTTP calls
    ):
        self.host          = host
        self.port          = port
        # Normalise to lowercase — must match server-side normalisation so that
        # TOFU lookups and pairwise-key dictionaries use the same keys everywhere.
        self.username      = username.strip().lower()[:32]
        self.group_fernet  = group_fernet
        # Raw master key bytes for HKDF room-key derivation.
        # Passed in directly so we never touch private Fernet attributes
        # (_signing_key, _encryption_key) that are not part of the public API.
        self._master_key_bytes: bytes = group_key_bytes
        self.room          = room.strip().lower()[:64]
        self._room_fernet: Fernet = enc.derive_room_fernet(self._master_key_bytes, self.room)
        self.identity_path = identity_path
        self.tofu_path     = tofu_path
        self.reconnect     = reconnect
        self._tls          = tls
        self._tls_cert     = tls_cert       # CA cert path, empty = TOFU mode
        self._tls_tofu_path = tls_tofu_path
        # Guard: only print the TLS fingerprint line once per session,
        # not on every bore-tunnel reconnect / migration.
        self._tls_announced: bool = False

        # Port discovery — used when bore.pub kills the tunnel and the server
        # restarts with a new port.  Clients poll the discovery service to find
        # the new port automatically without user intervention.
        self._discovery_key  = discovery_key
        self._no_discovery   = no_discovery

        # Load / generate Ed25519 identity
        self.sk_bytes, self.vk_bytes = enc.load_identity(identity_path)
        self.vk_hex = self.vk_bytes.hex()

        # Inbox token — opaque routing address derived from our vk.
        # blake2s(vk_bytes, digest_size=16) — same formula the server uses.
        # Peers derive our token locally from the TOFU store so no exchange needed.
        import hashlib as _hl
        self.inbox_token: str = _hl.blake2s(self.vk_bytes, digest_size=16).hexdigest()

        # TOFU store
        self.tofu_store = id_mod.load_tofu(tofu_path)

        # Animation flag — toggled by /anim on|off
        self._anim_enabled: bool = True

        # DH state: username → {"priv": bytes, "pub": bytes}  (pending handshakes)
        self._dh_pending: dict[str, dict] = {}
        # Pairwise Fernet: username → Fernet  (established sessions)
        self._pairwise: dict[str, Fernet] = {}
        # Raw pairwise key bytes: username → bytes
        # Kept separately so derive_file_cipher_key never needs private Fernet attrs.
        self._pairwise_raw: dict[str, bytes] = {}
        # Queue of outgoing /msg text waiting for DH to complete (sender side)
        self._msg_queue: dict[str, list] = {}
        # Queued outgoing file sends waiting for DH to complete
        self._file_queue: dict[str, list] = {}  # peer -> [(filepath, ...),]
        # In-progress incoming file transfers: tid -> metadata dict
        self._incoming_files: dict = {}

        # Resume handshake state for outgoing file sends (sender side).
        # When a bore migration interrupts a transfer, the sender retransmits
        # file_start with the same tid.  The receiver replies with file_resume_ack
        # telling us exactly how many chunks it already wrote (next_index).
        # _file_resume_events: tid → threading.Event  (set when ack arrives)
        # _file_resume_index:  tid → int              (ack's next_index value)
        self._file_resume_events: dict[str, threading.Event] = {}
        self._file_resume_index:  dict[str, int] = {}

        # Users whose pubkey didn't match our TOFU store (possible key regen or attack)
        # Messages from these users are shown with a ⚠ marker, not silently dropped.
        self._tofu_mismatched: set = set()
        # Users we have already shown the SECURITY WARNING for this session.
        # The server sends pubkey_announce twice per join (send_known_pubkeys +
        # the client's own _announce_pubkey) so without this guard the warning
        # fires twice for the same event.
        self._tofu_warned: set = set()
        # When a TOFU mismatch fires we cache the peer's new (unverified) key here.
        # /trust <peer> then promotes it into tofu_store immediately.
        # Without this, /trust only deletes the old key; the new key is never stored
        # and every future PM from that peer shows ? forever.
        self._tofu_pending: dict[str, str] = {}

        # Buffer of incoming privmsg frames that arrived before pairwise key was ready
        self._privmsg_buffer: dict[str, list] = {}

        # Messages typed during a migration window or tunnel-down period —
        # held here and flushed immediately after the new socket is ready.
        # Each entry is (text, tag, ts) as passed to _send_chat.
        self._pending_outbox: list = []

        # Privmsgs queued while the tunnel is down, keyed by peer username.
        # Each value is a list of (text, tag, ts).
        self._pending_privmsg: dict[str, list] = {}

        self.sock: Optional[socket.socket] = None
        # Priority send queues — replace the old _sock_lock / _hi_waiting approach.
        #
        # WHY (bugs fixed):
        #   _hi_waiting += 1 is a non-atomic read-modify-write; the GIL can
        #   switch between the LOAD_ATTR and STORE_ATTR bytecodes, so two threads
        #   racing on it produce wrong counts — the priority mechanism silently
        #   fails and chat frames can be starved or the counter drifts negative,
        #   causing _send_lo to spin forever.  Additionally, _send_lo held
        #   _sock_lock for the entire duration of sendall(4 MB), blocking the
        #   input thread at the lock and making Enter appear unresponsive.
        #
        # NEW design:
        #   _send_hi_q  — high-priority: chat, control, heartbeat, DH, pubkey.
        #                 Put items via _send(); returned immediately (non-blocking).
        #   _send_lo_q  — low-priority: file chunks.
        #                 Put items via _send_lo(); caller blocks on an Event until
        #                 the sender thread processes the frame and sets the result.
        #   _sender_loop() drains _send_hi_q completely before touching _send_lo_q,
        #   guaranteeing chat always beats file chunks for socket access.
        import queue as _q
        self._send_hi_q: _q.Queue = _q.Queue()
        self._send_lo_q: _q.Queue = _q.Queue()
        self._running = False
        self._quit    = False               # set True on intentional /quit or Ctrl+C
        self._migrating = False             # set True on a clean bore tunnel migration
        # Pre-set True if connecting via bore.pub so discovery works even before
        # the first successful handshake (e.g. on initial connect or after bore dies).
        self._using_bore = (self.host.lower() == "bore.pub")
        # Timestamp until which join/leave chat messages are suppressed.
        # Set for 15s when a migrate event arrives so users don't see the churn
        # of everyone disconnecting and reconnecting during the tunnel switch.
        self._migration_quiet_until: float = 0.0
        # Set when a new connection is fully ready (auth_ok + pubkey announced).
        # Cleared when a migration starts. Send threads that hit a dead socket
        # during migration wait on this instead of failing immediately.
        self._reconnect_event = threading.Event()
        self._reconnect_event.set()         # starts set — no migration in progress
        self._input_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread]  = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Open TCP socket to the server, with automatic TLS + TOFU fingerprint
        verification.

        TLS mode (default):
          1. Connect with TLS but no CA verification (self-signed cert is fine).
          2. Extract the server's cert fingerprint from the live TLS session.
          3. Look up the fingerprint in the TOFU store (~/.noeyes/tls_fingerprints.json).
             - First connection to this host:port → trust and store the fingerprint.
             - Known host, matching fingerprint → connect silently.
             - Known host, DIFFERENT fingerprint → warn user (possible MITM).
          4. The connection is always TLS-encrypted regardless of TOFU outcome.
             The warning means the server's certificate changed unexpectedly.

        No-TLS mode (--no-tls):
          Plain TCP. Messages are still E2E encrypted but metadata (usernames,
          room names, timestamps) is visible to anyone watching the wire.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((self.host, self.port))
            if self._tls:
                import ssl as _ssl
                import binascii

                # Connect with TLS but skip CA verification — we do our own
                # TOFU verification on the raw fingerprint instead.
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE

                if self._tls_cert:
                    # Manual CA cert override — use proper verification
                    ctx.verify_mode = _ssl.CERT_REQUIRED
                    ctx.load_verify_locations(self._tls_cert)
                    ctx.check_hostname = True

                s = ctx.wrap_socket(s, server_hostname=self.host)

                # Extract fingerprint from the live TLS session
                der  = s.getpeercert(binary_form=True)
                if der:
                    import hashlib
                    fp = hashlib.sha256(der).hexdigest()
                    # Key on host only (not host:port) so the stored fingerprint
                    # survives bore tunnel migrations that change the port.
                    key = self.host

                    # Load TOFU store and verify / register the fingerprint
                    store = enc.load_tls_tofu(self._tls_tofu_path)
                    if key not in store:
                        # First contact — trust and store
                        store[key] = fp
                        enc.save_tls_tofu(store, self._tls_tofu_path)
                        if not self._tls_announced:
                            utils.print_msg(utils.cok(
                                f"[tls] New server fingerprint trusted (first contact):\n"
                                f"      {fp[:16]}...{fp[-16:]}"
                            ))
                        self._tls_announced = True
                    elif store[key] != fp:
                        # Fingerprint changed — abort immediately.
                        # Continuing with a mismatched cert would let a MITM attacker
                        # see all transport metadata (usernames, room names, timing).
                        # The user must manually remove the stored fingerprint and
                        # reconnect — this is the same model as SSH StrictHostKeyChecking.
                        utils.print_msg(utils.cerr(
                            f"[TLS WARNING] Server certificate changed for {key}!\n"
                            f"  Stored : {store[key][:16]}...{store[key][-16:]}\n"
                            f"  New    : {fp[:16]}...{fp[-16:]}\n"
                            f"  Connection REFUSED — possible man-in-the-middle attack.\n"
                            f"  If the server was legitimately reinstalled, remove the\n"
                            f"  stored fingerprint and reconnect:\n"
                            f"    Delete '{key}' from {self._tls_tofu_path}\n"
                            f"  Then run NoEyes again."
                        ))
                        s.close()
                        return False
                    else:
                        # Known fingerprint — silently good (print once per session only)
                        if not self._tls_announced:
                            utils.print_msg(utils.cok(
                                f"[tls] Encrypted  ·  {fp[:8]}...{fp[-8:]}"
                            ))
                        self._tls_announced = True

            self.sock = s
            return True
        except OSError:
            if self._migrating or self._using_bore:
                # Swallow — panel spinner already shows reconnect state
                pass
            else:
                utils.print_msg(utils.cerr(f"[error] Cannot connect to {self.host}:{self.port}"))
            return False

    # ------------------------------------------------------------------
    # Send primitives
    # ------------------------------------------------------------------

    def _send_direct(self, header: dict, payload: bytes = b"") -> bool:
        """Synchronous send used ONLY during the join handshake (before the
        sender thread starts).  All post-handshake code must use _send()."""
        if self.sock is None:
            return False
        return send_frame(self.sock, header, payload)

    def _send(self, header: dict, payload: bytes = b"", priority: int = 0) -> bool:
        """Non-blocking high-priority send: enqueue to _send_hi_q and return
        immediately.  The sender thread drains this queue before touching any
        file chunk.  Returns False only when _quit is already set."""
        if self._quit:
            return False
        try:
            self._send_hi_q.put_nowait((header, payload))
            return True
        except Exception:
            return False

    def _send_lo(self, header: dict, payload: bytes = b"") -> bool:
        """Blocking low-priority send for file chunks.  Enqueues to _send_lo_q
        and waits until the sender thread processes the frame and reports the
        result.  Returns False on socket failure or quit."""
        if self._quit:
            return False
        import queue as _q
        ev  = threading.Event()
        res = [False]
        self._send_lo_q.put((header, payload, ev, res))
        ev.wait()   # sender thread always sets the event; no infinite hang
        return res[0]

    def _flush_send_lo_queue(self) -> None:
        """Signal every pending lo-priority waiter with failure so file-send
        threads detect the dead socket and enter the migration pause."""
        import queue as _q
        while True:
            try:
                _, _, ev, res = self._send_lo_q.get_nowait()
                res[0] = False
                ev.set()
            except _q.Empty:
                break

    def _sender_loop(self) -> None:
        """Persistent sender thread.  Runs for the full client lifetime across
        all bore tunnel migrations.

        Invariant: every item put into _send_lo_q has its Event set before
        this method returns, so _send_lo() never blocks forever.

        Priority rule: _send_hi_q is drained completely before any single
        lo-priority frame is sent, and again between each pair of lo-priority
        frames.  This guarantees chat/control frames are never behind a file
        chunk from the user's perspective, even on a slow bore tunnel.
        """
        import queue as _q

        def _drain_hi() -> bool:
            """Drain all hi-prio items. Returns False if socket fails."""
            while True:
                try:
                    hdr, pay = self._send_hi_q.get_nowait()
                except _q.Empty:
                    return True
                if self._quit:
                    return False
                sock = self.sock
                if sock is None:
                    # Migration in progress — silently drop disposable frames
                    # (heartbeats, users_req…).  Chat messages were already
                    # short-circuited into _pending_outbox by _send_chat().
                    continue
                try:
                    if not send_frame(sock, hdr, pay):
                        return False
                except OSError:
                    return False
            # unreachable

        try:
            while not self._quit:
                # ── Phase 1: flush all hi-priority ────────────────────────
                if not _drain_hi():
                    # Socket died while sending a hi-prio frame.
                    # Flush lo-queue waiters so file threads detect migration.
                    self._flush_send_lo_queue()
                    # Don't exit — wait for the new socket after migration.
                    # The outer loop will retry once self.sock is set again.
                    time.sleep(0.05)
                    continue

                # ── Phase 2: one lo-priority frame ────────────────────────
                try:
                    hdr, pay, ev, res = self._send_lo_q.get(timeout=0.005)
                except _q.Empty:
                    continue

                if self._quit:
                    res[0] = False
                    ev.set()
                    break

                # Final hi-prio drain before committing to the chunk so a
                # chat message typed mid-transfer still beats this chunk.
                if not _drain_hi():
                    res[0] = False
                    ev.set()
                    self._flush_send_lo_queue()
                    time.sleep(0.05)
                    continue

                sock = self.sock
                if sock is None:
                    res[0] = False
                    ev.set()
                    continue

                try:
                    ok = send_frame(sock, hdr, pay)
                except OSError:
                    ok = False

                res[0] = ok
                ev.set()

                if not ok:
                    # Socket died mid-chunk — flush remaining lo waiters.
                    self._flush_send_lo_queue()
                    time.sleep(0.05)   # brief pause before retrying hi-drain
        finally:
            # Guarantee: no _send_lo() call ever hangs after we exit.
            self._flush_send_lo_queue()

    def run(self) -> None:
        """Main entry point: connect, join, and start I/O threads."""
        # Pre-create all receive folders so they exist on every platform
        # (including Android/Termux) before any transfer happens.
        for subfolder in ("images", "videos", "audio", "docs", "other"):
            (RECEIVE_BASE / subfolder).mkdir(parents=True, exist_ok=True)

        # Clean up any .part files left over from a previous session that
        # was interrupted before transfers completed.
        for part_file in RECEIVE_BASE.rglob("*.part"):
            try:
                part_file.unlink()
            except Exception:
                pass

        backoff = 1
        session_start = 0.0

        # CRT animation runs once before we open any connection.
        # This means zero server traffic can arrive mid-animation.
        utils.play_startup_animation()

        while True:
            # Always clear logs before history replay on real disconnects.
            # During migration, keep logs and seen-set intact — already_seen
            # dedup silently skips replayed messages so screen never flashes.
            utils.reset_for_reconnect(is_migration=self._migrating)

            if not self.connect():
                if not self.reconnect or self._quit:
                    if not self._migrating:
                        return
                if self._migrating:
                    # Tunnel not yet ready — update panel spinner, no log spam.
                    utils.set_panel_status(f"↻ :{self.port} retrying…")
                else:
                    utils.print_msg(utils.cwarn(f"[reconnect] Retrying in {backoff}s…"))
                # Discovery: check if the server's bore port has changed.
                if (self._using_bore and not self._no_discovery
                        and self._discovery_key):
                    _new_port = self._discovery_lookup()
                    if _new_port and _new_port != self.port:
                        self.port = _new_port
                        utils.set_panel_status(f"↻ :{_new_port}")
                # During migration hammer the reconnect — no exponential backoff.
                # For non-migration drops keep the backoff to avoid tight loops.
                if self._migrating:
                    time.sleep(0.15)
                else:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                continue

            session_start = time.monotonic()
            # Don't reset backoff here — only reset it after a successful join.
            # If we reset on every TCP connect, nick_error retries always
            # sleep 1s regardless of how many times we've retried.

            # Send join event — include our Ed25519 verify key so the server
            # can issue a challenge if our username is still registered (e.g.
            # an in-progress bore tunnel migration where the old session hasn't
            # timed out yet).  Without vk_hex the server falls through to the
            # "username taken" branch → nick_error → 3-second wait per retry.
            join_header = {
                "type":         "system",
                "event":        "join",
                "username":     self.username,
                "room":         self._room_token(),
                "vk_hex":       self.vk_hex,
                "inbox_token":  self.inbox_token,
            }
            if not self._send_direct(join_header):
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue

            # ----------------------------------------------------------------
            # Join handshake — read the server's response synchronously before
            # the recv_thread starts.  The server always sends exactly one of:
            #   auth_ok       — join accepted, history replay follows
            #   auth_challenge — server wants proof of identity key ownership
            #   nick_error    — join rejected (name taken / auth failed)
            # ----------------------------------------------------------------
            self.sock.settimeout(10.0)
            try:
                _hs_result = recv_frame(self.sock)
            except OSError:
                _hs_result = None
            finally:
                self.sock.settimeout(None)

            if _hs_result is None:
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue

            _hs_hdr, _ = _hs_result
            _hs_event  = _hs_hdr.get("event", "")

            if _hs_event == "auth_challenge":
                # Server wants us to prove we own the private key for our
                # claimed vk_hex.  Sign the nonce and send the response.
                _nonce = str(_hs_hdr.get("nonce", ""))
                _sig   = enc.sign_message(self.sk_bytes, _nonce.encode()).hex()
                if not self._send_direct({
                    "type":  "system",
                    "event": "auth_response",
                    "sig":   _sig,
                }):
                    if not self.reconnect or self._quit:
                        return
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                    continue
                # Read the server's final verdict after verifying our signature
                self.sock.settimeout(10.0)
                try:
                    _hs_result = recv_frame(self.sock)
                except OSError:
                    _hs_result = None
                finally:
                    self.sock.settimeout(None)
                if _hs_result is None:
                    if not self.reconnect or self._quit:
                        return
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                    continue
                _hs_hdr, _ = _hs_result
                _hs_event   = _hs_hdr.get("event", "")

            if _hs_event in ("nick_error", "auth_failed"):
                # During migration the server may still hold the old session
                # for a few seconds after bore kills the tunnel.  Suppress the
                # error print and wait quietly — it will clear on its own.
                if self._migrating:
                    time.sleep(3)
                else:
                    utils.print_msg(utils.cerr(
                        f"[error] {_hs_hdr.get('message', 'Connection rejected by server.')}"
                    ))
                    if not self.reconnect or self._quit:
                        return
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                continue

            if _hs_event != "auth_ok":
                utils.print_msg(utils.cerr(
                    "[error] Unexpected server response during join handshake — reconnecting."
                ))
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue
            # auth_ok received — handshake complete, history replay follows
            backoff = 1  # reset only here, after a confirmed successful join

            # If the server included its current bore port in auth_ok (crash
            # recovery path: migrate broadcast reached nobody because all clients
            # were already dropped when bore.pub killed the tunnel), update
            # self.port now so the NEXT reconnect cycle uses the correct port.
            # Only act if the port actually changed — avoids a no-op migrate loop.
            _auth_bore_port = _hs_hdr.get("bore_port")
            if _auth_bore_port and int(_auth_bore_port) != self.port:
                utils.print_ephemeral(utils.cgrey(
                    f"[migrate] bore port updated → {_auth_bore_port}"
                ))
                self.port = int(_auth_bore_port)
            if _auth_bore_port:
                self._using_bore = True

            # Migration complete — clear the flag before history replay so
            # the next unplanned disconnect gets a fresh reset as normal.
            was_migrating  = self._migrating
            self._migrating = False

            # Clear tunnel-down state regardless of whether this was a clean
            # migration or an unexpected drop — we are back online either way.
            if self._using_bore and utils.is_tunnel_down():
                utils.set_tunnel_down(False)
                utils.clear_ephemeral_lines()

            # Announce our Ed25519 pubkey
            self._announce_pubkey()

            if was_migrating:
                # Screen is already showing the right room — don't re-enter
                # or re-clear it.  Just clear the spinner and ephemeral notices
                # in a single redraw so the user never sees a flash or blank.
                utils.set_panel_status("")
                utils.clear_ephemeral_lines()
            else:
                utils.switch_room_display(self.room)
                enter_tui()

            # Signal file-send threads and unblock send path.
            self._reconnect_event.set()

            # Flush any messages typed during the tunnel-down / migration window.
            if self._pending_outbox:
                pending = self._pending_outbox[:]
                self._pending_outbox.clear()
                for _item in pending:
                    if len(_item) == 3:
                        _text, _tag, _ts = _item
                    else:
                        _text, _tag = _item
                        _ts = ""
                    self._send_chat(_text, tag=_tag, _ts=_ts)

            # Flush buffered privmsgs per peer.
            if self._pending_privmsg:
                pending_pm = self._pending_privmsg.copy()
                self._pending_privmsg.clear()
                for _peer, _msgs in pending_pm.items():
                    for _text, _tag, _ts in _msgs:
                        self._send_privmsg_encrypted(_peer, _text, _tag)

            # Register Tab key room-switch callback so utils.py can notify the server
            import core.encryption as _enc_mod
            def _tab_cb(room: str) -> None:
                self._room_fernet = _enc_mod.derive_room_fernet(self._master_key_bytes, room)
                self.room = room
                self._send({"type": "command", "event": "join_room", "room": self._room_token()})
                self._announce_pubkey()
            utils._tab_switch_cb = _tab_cb

            # Register panel click callback
            def _panel_cb(action: str, name: str) -> None:
                if action == "join":
                    self._process_input(f"/join {action}")
                elif action == "msg":
                    utils._panel_prefill(f"/msg {name} ")
            utils.set_panel_action_cb(_panel_cb)

            # Fetch initial user list so the sidebar is populated on connect
            self._send({"type": "command", "event": "users_req", "room": self.room})

            try:
                self._running = True

                # Start the dedicated sender thread.  It runs for the entire
                # client lifetime (across bore migrations) so we only create it
                # once — check is_alive() to avoid spawning a second thread on
                # reconnect while the old one is still winding down.
                if not hasattr(self, "_sender_thread") or \
                        not self._sender_thread.is_alive():
                    self._sender_thread = threading.Thread(
                        target=self._sender_loop, daemon=True, name="noeyes-sender"
                    )
                    self._sender_thread.start()

                self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
                self._recv_thread.start()

                if self._input_thread is None or not self._input_thread.is_alive():
                    self._input_thread = threading.Thread(target=self._input_loop, daemon=True)
                    self._input_thread.start()

                try:
                    self._recv_thread.join()
                except KeyboardInterrupt:
                    self._quit = True
                    self._running = False

                self._running = False

                if self._quit:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self._reconnect_event.set()  # unblock any waiting file threads
                    utils.print_msg(utils.cinfo("\n[bye] Disconnected."))
                    return

                # If the session lasted less than 5 seconds it was a bad connection,
                # not a normal drop — apply backoff so we don't spin tight on localhost.
                session_duration = time.monotonic() - session_start
                if session_duration < 5.0 and not self._migrating:
                    backoff = min(backoff * 2, 10)

                if not self._migrating:
                    if self._using_bore:
                        self._migrating = True
                        self._migration_quiet_until = time.monotonic() + 30
                        self._reconnect_event.clear()
                        utils.print_ephemeral(utils.cgrey("↻  Reconnecting…"))
                        # Update prompt colour without printing the tunnel-down message
                        utils._tunnel_down[0] = True
                        utils._PROMPT     = utils._PROMPT_DOWN
                        utils._PROMPT_VIS = 2
                        if utils._tui_active:
                            with utils._OUTPUT_LOCK:
                                utils._redraw_input_unsafe()
                    else:
                        utils.print_msg(utils.cwarn(
                            f"[reconnect] Connection lost. Reconnecting in {backoff}s…"
                        ))
                try:
                    self.sock.close()
                except OSError:
                    pass
                if not self._migrating:
                    time.sleep(backoff)
            finally:
                # Only exit TUI on a real quit or unrecoverable disconnect —
                # never during a migration/bore reconnect so the screen stays alive.
                if self._quit or not self._migrating:
                    exit_tui()

    # ------------------------------------------------------------------
    # Announce / pubkey
    # ------------------------------------------------------------------

    def _discovery_lookup(self) -> int:
        """
        Poll the discovery service for the current bore port.
        Uses keyvalue.immanuel.co — reads the app-key cached at
        ~/.noeyes/discovery_appkey.  Returns the port as int, or 0 on failure.
        """
        import urllib.request as _ur
        from pathlib import Path as _P
        import re as _re
        try:
            appkey_file = _P.home() / ".noeyes" / "discovery_appkey"
            if not appkey_file.exists():
                return 0
            ak = appkey_file.read_text().strip()
            if not ak or not _re.match(r'^[A-Za-z0-9]{6,}', ak):
                return 0
            url = f"https://keyvalue.immanuel.co/api/KeyVal/GetValue/{ak}/{self._discovery_key}"
            with _ur.urlopen(url, timeout=8) as r:
                val = r.read().decode().strip().strip('"')
                return int(val) if val and val.isdigit() else 0
        except Exception:
            return 0

    def _room_token(self) -> str:
        """
        Compute the opaque room routing token.
        blake2s((room_name + group_key_hex).encode(), digest_size=16)
        Server never sees the human-readable room name — only this token.
        Stable per (room, group_key) pair so all clients independently arrive
        at the same token without coordination.
        """
        import hashlib as _hl
        raw = (self.room + self._master_key_bytes.hex()).encode()
        return _hl.blake2s(raw, digest_size=16).hexdigest()

    def _announce_pubkey(self) -> None:
        """Tell room peers our Ed25519 verify key and inbox_token."""
        header = {
            "type":        "pubkey_announce",
            "username":    self.username,
            "vk_hex":      self.vk_hex,
            "inbox_token": self.inbox_token,   # so peers can compute our token locally
            "room":        self._room_token(),
        }
        self._send(header)

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    def _recv_loop(self) -> None:
        while self._running:
            result = recv_frame(self.sock)
            if result is None:
                break
            header, payload = result
            try:
                self._handle_frame(header, payload)
            except Exception as exc:
                utils.print_msg(utils.cerr(f"[error] Frame handling error: {exc}"))

    def _handle_frame(self, header: dict, payload: bytes) -> None:
        msg_type = header.get("type", "")
        ts = header.get("ts", time.strftime("%H:%M:%S"))

        if msg_type == "heartbeat":
            self._send({"type": "heartbeat"})
            return

        # Bore tunnel migration — server is rolling over to a new port.
        # Update self.port and close the socket; the existing reconnect loop
        # picks it up immediately with the new port. No other logic needed.
        if msg_type == "system" and header.get("event") == "migrate":
            new_port = header.get("port")
            if new_port:
                # CVE-NE-006 FIX: if the server included a signature over
                # f"{port}:{ts}", verify it against the pinned server vk before
                # acting on the migrate event.  A missing sig is allowed when TLS
                # is active (TLS already prevents injection); in --no-tls mode a
                # missing sig is warned but accepted for backward-compat.
                _migrate_sig = header.get("migrate_sig", "")
                _server_vk   = getattr(self, "_server_vk_hex", "")
                if _migrate_sig and _server_vk:
                    _migrate_msg = f"{new_port}:{header.get('ts', '')}".encode()
                    try:
                        _sig_ok = enc.verify_signature(
                            bytes.fromhex(_server_vk),
                            _migrate_msg,
                            bytes.fromhex(_migrate_sig),
                        )
                    except Exception:
                        _sig_ok = False
                    if not _sig_ok:
                        utils.print_msg(utils.cerr(
                            "[security] migrate event has INVALID signature — ignoring. "
                            "Possible evil-twin redirection attempt."
                        ))
                        return
                elif not self._tls and not _migrate_sig:
                    utils.print_msg(utils.cwarn(
                        "[security] migrate event has no signature (--no-tls mode). "
                        "Accepting, but upgrade to TLS for full protection."
                    ))
                self.port = int(new_port)
                self._migrating = True
                self._migration_quiet_until = time.monotonic() + 15
                self._reconnect_event.clear()
                utils.print_ephemeral(utils.cgrey("↻  Reconnecting…"))
                utils.set_panel_status(f"↻ :{new_port}")
                self._running = False
                try:
                    self.sock.close()
                except OSError:
                    pass
            return

        # Fast path: binary file chunk (no JSON parsing of payload)
        if msg_type == "privmsg" and header.get("subtype") == "file_chunk_bin":
            self._handle_file_chunk_binary(header, payload)
            return

        if msg_type == "pubkey_announce":
            self._handle_pubkey_announce(header)
            return

        if msg_type == "dh_init":
            self._handle_dh_init(header, payload)
            return

        if msg_type == "dh_resp":
            self._handle_dh_resp(header, payload)
            return

        if msg_type == "privmsg":
            self._handle_privmsg(header, payload, ts)
            return

        if msg_type == "chat":
            self._handle_chat(header, payload, ts)
            return

        if msg_type == "system":
            self._handle_system(header, ts)
            return

        if msg_type == "command":
            self._handle_command(header, ts)
            return

    # ------------------------------------------------------------------
    # Pubkey / TOFU
    # ------------------------------------------------------------------

    def _handle_pubkey_announce(self, header: dict) -> None:
        uname  = header.get("username", "").lower()
        vk_hex = header.get("vk_hex", "")
        if not uname or not vk_hex or uname == self.username:
            return

        trusted, is_new = id_mod.trust_or_verify(
            self.tofu_store, uname, vk_hex, self.tofu_path
        )
        if is_new:
            utils.print_msg(utils.cok(f"[tofu] Trusted new key for {uname} (first contact)."))
        elif not trusted:
            # Cache new key so /trust can promote it into tofu_store immediately.
            self._tofu_pending[uname] = vk_hex
            self._tofu_mismatched.add(uname)
            if uname not in self._tofu_warned:
                self._tofu_warned.add(uname)
                utils.print_msg(utils.cerr(
                    f"[SECURITY WARNING] Key mismatch for {uname}!\n"
                    f"  Stored key : {self.tofu_store.get(uname, '(none)')[:24]}...\n"
                    f"  New key    : {vk_hex[:24]}...\n"
                    "  Their identity may have changed (e.g. they reinstalled NoEyes),\n"
                    "  or this could be an impersonation attempt.\n"
                    "  Messages from this user will be shown with a ⚠ marker.\n"
                    f"  If you trust them, type:  /trust {uname}"
                ))

        # Refresh sidebar now that we can resolve this token to a username
        self._send({"type": "command", "event": "users_req", "room": self.room})

    # ------------------------------------------------------------------
    # DH handshake
    # ------------------------------------------------------------------

    _DH_TIMEOUT = 30.0   # seconds before a stale pending handshake is retried

    def _peer_inbox_token(self, peer_username: str) -> str:
        """
        Derive the inbox routing token for *peer_username* from their TOFU vk.
        Returns empty string if peer vk is unknown (server will silently drop).
        Formula: blake2s(vk_bytes, digest_size=16).hexdigest() — same as server.
        """
        import hashlib as _hl
        peer_vk = self.tofu_store.get(peer_username, "")
        if not peer_vk:
            return ""
        try:
            return _hl.blake2s(bytes.fromhex(peer_vk), digest_size=16).hexdigest()
        except Exception:
            return ""

    def _token_to_username(self, token: str) -> str:
        """
        Reverse-lookup: find the username whose TOFU vk maps to *token*.
        Scans tofu_store first (trusted keys), then _tofu_pending (mismatched
        keys) so users with key mismatches still show their name, not a hex stub.
        Returns empty string if not found (unknown peer, TOFU not yet set).
        """
        import hashlib as _hl
        for uname, vk_hex in self.tofu_store.items():
            try:
                t = _hl.blake2s(bytes.fromhex(vk_hex), digest_size=16).hexdigest()
                if t == token:
                    return uname
            except Exception:
                continue
        # Also check pending/mismatched keys — identity changed but name is known.
        for uname, vk_hex in self._tofu_pending.items():
            try:
                t = _hl.blake2s(bytes.fromhex(vk_hex), digest_size=16).hexdigest()
                if t == token:
                    return uname
            except Exception:
                continue
        return ""
    def _ensure_dh(self, peer: str, then_send: Optional[tuple] = None) -> None:
        """
        Ensure a pairwise Fernet with *peer* is established.

        If not yet established, initiates a dh_init handshake and optionally
        queues *then_send* = (text,) to be sent once the handshake completes.
        """
        if peer in self._pairwise:
            if then_send:
                text_q, tag_q = then_send[0], then_send[1] if len(then_send) > 1 else ""
                self._send_privmsg_encrypted(peer, text_q, tag=tag_q)
            return

        if then_send:
            self._msg_queue.setdefault(peer, []).append(
                (then_send[0], then_send[1] if len(then_send) > 1 else "")
            )

        if peer in self._dh_pending:
            # Bug fix: if the pending handshake is stale (dh_resp never arrived,
            # e.g. peer was briefly offline or resp was lost), clear and re-initiate
            # rather than blocking forever with no feedback.
            age = time.monotonic() - self._dh_pending[peer]["ts"]
            if age < self._DH_TIMEOUT:
                return  # genuinely in flight, keep waiting
            utils.print_msg(utils.cwarn(f"[dh] Key exchange with {peer} timed out — retrying…"))
            del self._dh_pending[peer]

        priv_bytes, pub_bytes = enc.dh_generate_keypair()
        self._dh_pending[peer] = {
            "priv": priv_bytes,
            "pub":  pub_bytes,
            "ts":   time.monotonic(),   # used to detect stale handshakes
        }

        # CVE-NE-001 FIX: sign the DH public key with our Ed25519 signing key
        # before encrypting.  Without this, any group member who has chat.key
        # can silently MITM the handshake by swapping in their own DH pubkey.
        dh_pub_bytes = pub_bytes  # raw 32-byte X25519 public key
        dh_sig = enc.sign_message(self.sk_bytes, dh_pub_bytes).hex()

        # Encrypt the DH public key with the group key so the server cannot read it.
        inner = json.dumps({"dh_pub": pub_bytes.hex(), "sig": dh_sig}).encode()
        encrypted_payload = self.group_fernet.encrypt(inner)

        # Zero-metadata routing: address by opaque inbox token, not username.
        # Include our own token so the recipient can route the dh_resp back.
        peer_token = self._peer_inbox_token(peer)
        header = {
            "type":       "dh_init",
            "to":         peer_token,
            "from_token": self.inbox_token,   # recipient needs this to send dh_resp
            "from":       self.username,       # still needed so recipient knows who initiated
        }
        self._send(header, encrypted_payload)
        utils.print_msg(utils.cgrey(f"[dh] Initiating key exchange with {peer}…"))

    def _handle_dh_init(self, header: dict, payload: bytes) -> None:
        """Respond to a dh_init from *from_user* with our DH public key."""
        # `from` is stripped by the server (zero-metadata routing).
        # Resolve the sender via from_token → TOFU reverse lookup.
        from_user = header.get("from", "").lower()
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if not from_user or from_user == self.username:
            return

        # Decrypt the payload with group key to extract initiator's DH pubkey
        try:
            inner_bytes = self.group_fernet.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            utils.print_msg(utils.cwarn(f"[dh] Could not decrypt dh_init from {from_user}"))
            return

        # CVE-NE-001 FIX: verify the Ed25519 signature over the DH pubkey.
        # Reject the handshake if the signature is missing or invalid so a
        # group-member MITM cannot silently swap in their own DH pubkey.
        sig_hex = inner.get("sig", "")
        peer_vk_hex = self.tofu_store.get(from_user, "")
        if not sig_hex or not peer_vk_hex:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_init from {from_user}: "
                f"{'no signature' if not sig_hex else 'unknown identity key — run /users first'}."
            ))
            return
        try:
            sig_valid = enc.verify_signature(
                bytes.fromhex(peer_vk_hex),
                bytes.fromhex(inner["dh_pub"]),
                bytes.fromhex(sig_hex),
            )
        except Exception:
            sig_valid = False
        if not sig_valid:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_init from {from_user}: invalid Ed25519 signature — possible MITM."
            ))
            return

        # Bug fix: simultaneous DH initiation tiebreaker.
        # If both users type /msg at the same time, both send dh_init. Without a
        # tiebreaker, both also respond with dh_resp, producing two different derived
        # keys — so messages silently fail to decrypt on one side.
        #
        # Resolution: the user whose name is lexicographically SMALLER is always the
        # "true initiator". When the larger-named user receives a dh_init while they
        # have their own pending, they discard their pending and respond instead.
        # When the smaller-named user receives a dh_init mid-handshake, they ignore it
        # and wait for the dh_resp to their own init.
        if from_user in self._dh_pending:
            if self.username < from_user:
                # We are the true initiator — ignore their dh_init, wait for dh_resp.
                return
            else:
                # They are the true initiator — discard our pending and respond.
                del self._dh_pending[from_user]

        # Generate our own DH keypair for this session
        priv_bytes, pub_bytes = enc.dh_generate_keypair()

        # Derive pairwise Fernet immediately and store raw bytes alongside it
        pairwise, p_raw = enc.dh_derive_shared_fernet(priv_bytes, peer_dh_pub)
        self._pairwise[from_user]     = pairwise
        self._pairwise_raw[from_user] = p_raw
        utils.print_msg(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        # Send dh_resp
        # CVE-NE-001 FIX: sign our DH pubkey so the initiator can verify it.
        resp_sig = enc.sign_message(self.sk_bytes, pub_bytes).hex()
        resp_inner = json.dumps({"dh_pub": pub_bytes.hex(), "sig": resp_sig}).encode()
        resp_payload = self.group_fernet.encrypt(resp_inner)

        header_resp = {
            "type":       "dh_resp",
            "to":         header.get("from_token", self._peer_inbox_token(from_user)),
            "from_token": self.inbox_token,
            "from":       self.username,   # recipient needs to know who responded
        }
        self._send(header_resp, resp_payload)

        # Flush any outgoing messages queued while waiting for this handshake.
        # This matters when the tiebreaker makes us the responder mid-flight:
        # we queued our own /msg in _msg_queue but _handle_dh_resp never fires for us.
        for text, tag in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text, tag=tag)

        # Flush queued file sends — run each in its own thread so large transfers
        # never block the recv loop that called this handler.
        for filepath in self._file_queue.pop(from_user, []):
            threading.Thread(target=self._send_file, args=(from_user, filepath), daemon=True).start()

        # Replay any incoming privmsgs that arrived before the key was ready
        self._flush_privmsg_buffer(from_user)

    def _handle_dh_resp(self, header: dict, payload: bytes) -> None:
        """Complete the DH exchange after receiving a dh_resp."""
        from_user = header.get("from", "").lower()
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if from_user not in self._dh_pending:
            return

        try:
            inner_bytes = self.group_fernet.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            utils.print_msg(utils.cwarn(f"[dh] Could not decrypt dh_resp from {from_user}"))
            return

        # CVE-NE-001 FIX: verify Ed25519 signature over the responder's DH pubkey.
        resp_sig_hex  = inner.get("sig", "")
        resp_vk_hex   = self.tofu_store.get(from_user, "")
        if not resp_sig_hex or not resp_vk_hex:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_resp from {from_user}: "
                f"{'no signature' if not resp_sig_hex else 'unknown identity key'}."
            ))
            self._dh_pending.pop(from_user, None)
            return
        try:
            resp_sig_valid = enc.verify_signature(
                bytes.fromhex(resp_vk_hex),
                bytes.fromhex(inner["dh_pub"]),
                bytes.fromhex(resp_sig_hex),
            )
        except Exception:
            resp_sig_valid = False
        if not resp_sig_valid:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_resp from {from_user}: invalid Ed25519 signature — possible MITM."
            ))
            self._dh_pending.pop(from_user, None)
            return

        priv_bytes = self._dh_pending.pop(from_user)["priv"]
        pairwise, p_raw = enc.dh_derive_shared_fernet(priv_bytes, peer_dh_pub)
        self._pairwise[from_user]     = pairwise
        self._pairwise_raw[from_user] = p_raw
        utils.print_msg(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        # Flush any queued outgoing messages
        for text, tag in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text, tag=tag)

        # Flush queued file sends — run each in its own thread so large transfers
        # never block the recv loop that called this handler.
        for filepath in self._file_queue.pop(from_user, []):
            threading.Thread(target=self._send_file, args=(from_user, filepath), daemon=True).start()

        # Replay any incoming privmsgs that arrived before the key was ready
        self._flush_privmsg_buffer(from_user)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    def _send_chat(self, text: str, tag: str = "", _ts: str = "") -> None:
        """Encrypt and broadcast a group chat message."""
        # Reuse a preserved timestamp (from pending_outbox flush) or capture now.
        ts  = _ts or time.strftime("%H:%M:%S")
        sig = enc.sign_message(self.sk_bytes, text.encode("utf-8")).hex()
        body_dict: dict = {
            "text":     text,
            "username": self.username,
            "ts":       ts,
            "sig":      sig,   # Ed25519 over plaintext — proves sender holds their identity key
        }
        if tag:
            body_dict["tag"] = tag
        body = json.dumps(body_dict).encode()
        payload = self._room_fernet.encrypt(body)
        header = {
            "type": "chat",
            "room": self.room,
            "from": self.username,
            # Replay-protection ID: 16 random bytes as hex (128-bit collision space).
            # Server rejects any frame whose mid it has already seen for this room.
            "mid":  os.urandom(16).hex(),
        }
        # If tunnel is down or migration in progress — buffer the message.
        # Show it locally immediately so the user knows it was captured,
        # and show a one-line "buffered" notice that disappears on reconnect.
        if (self._using_bore and utils.is_tunnel_down()) or not self._reconnect_event.is_set():
            self._pending_outbox.append((text, tag, ts))
            if not utils.already_seen(self.room, self.username, ts, text):
                utils.log_and_print(self.room, utils.format_message(self.username, text, ts, is_own=True))
                utils.mark_seen(self.room, self.username, ts, text)

            return
        self._send(header, payload)
        # Guard against double-display on flush path (message was already logged
        # when it was queued during the migration window above).
        if not utils.already_seen(self.room, self.username, ts, text):
            utils.log_and_print(self.room, utils.format_message(self.username, text, ts, is_own=True))
            utils.mark_seen(self.room, self.username, ts, text)

    def _send_privmsg_encrypted(self, peer: str, text: str, tag: str = "") -> bool:
        """Send a /msg to *peer* using the established pairwise Fernet.
        Returns True if the frame was handed to the socket, False on failure."""
        if self._using_bore and utils.is_tunnel_down():
            ts = time.strftime("%H:%M:%S")
            self._pending_privmsg.setdefault(peer, []).append((text, tag, ts))
            utils.log_and_print(self.room, utils.format_privmsg(f"you → {peer}", text, ts, verified=True))

            return False
        pairwise = self._pairwise.get(peer)
        if pairwise is None:
            utils.print_msg(utils.cwarn(f"[msg] No pairwise key for {peer} — queuing after DH."))
            self._ensure_dh(peer, then_send=(text, tag))
            return False

        ts  = time.strftime("%H:%M:%S")
        sig = enc.sign_message(self.sk_bytes,
                               text.encode("utf-8")).hex()
        body_dict: dict = {
            "text":     text,
            "username": self.username,
            "ts":       ts,
            "sig":      sig,
        }
        if tag:
            body_dict["tag"] = tag
        body = json.dumps(body_dict).encode()
        payload = pairwise.encrypt(body)

        header = {
            "type":       "privmsg",
            "to":         self._peer_inbox_token(peer),  # opaque token, not username
            "from_token": self.inbox_token,               # so recipient can reply
            # Replay-protection ID — same mechanism as group chat.
            "mid":        os.urandom(16).hex(),
        }
        # Note: `from` is intentionally omitted from the header.
        # The recipient authenticates sender identity from the encrypted payload
        # (username + Ed25519 sig inside pairwise Fernet), not from the plaintext header.
        ok = self._send(header, payload)
        # Only log to chat for real text messages, not internal file-transfer
        # control frames (file_start / file_end) whose text is a raw JSON blob.
        # BUG-001 FIX: file_resume_ack was added by the bore resume patch but
        # was not added here, causing raw JSON ack blobs to appear in the chat window.
        if ok and tag not in ("file_start", "file_end", "file_resume_ack"):
            utils.log_and_print(self.room, utils.format_privmsg(f"you → {peer}", text, ts, verified=True))
        return ok

    def _handle_chat(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and display a group chat message."""
        try:
            body = json.loads(self._room_fernet.decrypt(payload))
            text   = body.get("text", "")
            msg_ts = body.get("ts", ts)
            # Sender identity lives inside the encrypted payload (sealed sender).
            # The server strips `from` from the header — read from body instead.
            from_user = body.get("username", header.get("from", "?")).lower()
        except (InvalidToken, json.JSONDecodeError):
            utils.print_msg(utils.cwarn("[warn] Could not decrypt group message. Wrong key?"))
            return

        # Verify Ed25519 signature if we have a trusted key for this sender.
        # This prevents anyone who obtained the group key from impersonating
        # other users in group chat — the same protection privmsg already had.
        sig_hex  = body.get("sig", "")
        vk_hex   = self.tofu_store.get(from_user)
        verified = False
        if vk_hex and sig_hex:
            try:
                verified = enc.verify_signature(
                    bytes.fromhex(vk_hex),
                    text.encode("utf-8"),
                    bytes.fromhex(sig_hex),
                )
            except ValueError:
                pass
        if not verified and vk_hex and sig_hex:
            # Show the warning once per user per session — same guard as the
            # SECURITY WARNING already uses (_tofu_warned).  This way you see
            # it exactly once whether they send 1 or 100 messages before /trust.
            _sig_warn_key = f"sig_warn_{from_user}"
            if _sig_warn_key not in self._tofu_warned:
                self._tofu_warned.add(_sig_warn_key)
                utils.print_msg(utils.cwarn(
                    f"[SECURITY] Signature FAILED for group message from {from_user} — displaying anyway."
                ))

        tag = body.get("tag", "")
        utils.chat_decrypt_animation(
            payload, text, from_user, msg_ts,
            anim_enabled=self._anim_enabled,
            room=self.room,
            own_username=self.username,
            tag=tag,
        )

    def _flush_privmsg_buffer(self, from_user: str) -> None:
        """Replay any buffered incoming privmsgs from *from_user* now that the key is ready."""
        for h, p, ts in self._privmsg_buffer.pop(from_user, []):
            self._handle_privmsg(h, p, ts)

    def _handle_privmsg(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and dispatch a private message frame."""
        from_user = header.get("from", "").lower()
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if not from_user:
            from_user = "?"

        pairwise = self._pairwise.get(from_user)
        if pairwise is None:
            buf = self._privmsg_buffer.setdefault(from_user, [])
            # Simple 25-message cap — the server already enforces 25/15min per pair
            # so legitimate traffic never hits this.  This is a last-resort safety net
            # in case someone runs a modified server.
            if len(buf) < 25:
                buf.append((header, payload, ts))
            return

        try:
            body = json.loads(pairwise.decrypt(payload))
        except (InvalidToken, json.JSONDecodeError):
            utils.print_msg(utils.cwarn(f"[msg] Could not decrypt message from {from_user}."))
            return

        # subtype may be in the header (future) or inside the encrypted body as "tag"
        # We check body first so file transfers never leak type to the server.
        subtype = header.get("subtype") or body.get("tag", "text")

        if subtype in ("file_start", "file_chunk", "file_end", "file_resume_ack"):
            # Sender wraps metadata as json.dumps(meta_dict) in body["text"].
            # Unwrap it so handlers can access fields directly.
            inner = body.get("text", "")
            if isinstance(inner, str) and inner.startswith("{"):
                try:
                    file_body = json.loads(inner)
                except json.JSONDecodeError:
                    file_body = body
            else:
                file_body = body

            if subtype == "file_start":
                self._handle_file_start(from_user, file_body)
            elif subtype == "file_chunk":
                self._handle_file_chunk(from_user, file_body)
            elif subtype == "file_end":
                self._handle_file_end(from_user, file_body, ts)
            elif subtype == "file_resume_ack":
                self._handle_file_resume_ack(from_user, file_body)
        else:
            # Plain text message
            text    = body.get("text", "")
            msg_ts  = body.get("ts", ts)
            sig_hex = body.get("sig", "")

            vk_hex   = self.tofu_store.get(from_user)
            verified = False
            if vk_hex and sig_hex:
                try:
                    vk_bytes  = bytes.fromhex(vk_hex)
                    sig_bytes = bytes.fromhex(sig_hex)
                    verified  = enc.verify_signature(vk_bytes, text.encode("utf-8"), sig_bytes)
                except ValueError:
                    pass

            if not verified and vk_hex:
                utils.print_msg(utils.cwarn(
                    f"[SECURITY] Signature FAILED for message from {from_user} — displaying anyway."
                ))

            if from_user in self._tofu_mismatched:
                utils.print_msg(utils.cwarn(
                    f"⚠ Message from {from_user} — key mismatch (run /trust {from_user} if you trust them)."
                ))

            # Animate text privmsgs: show encrypted payload → reveal plaintext
            tag = body.get("tag", "")
            utils.privmsg_decrypt_animation(
                payload, text, from_user, msg_ts,
                verified=verified,
                anim_enabled=self._anim_enabled,
                room=self.room,
                tag=tag,
            )

    # ------------------------------------------------------------------
    # File transfer — receive side
    # ------------------------------------------------------------------

    def _handle_file_start(self, from_user: str, body: dict) -> None:
        tid      = body.get("transfer_id", "")
        # Strip all directory components — prevents path traversal attacks
        # where a malicious sender sets filename="../../../home/user/.bashrc"
        filename = Path(body.get("filename", "unknown")).name or "unknown"
        # Cap total_chunks — an uncapped value lets a malicious sender set
        # total_chunks=9999999 so the transfer never completes, leaking the
        # temp file handle and _incoming_files entry forever.
        # 100_000 chunks × 4 MB = ~400 GB effective max — no practical limit
        # while still blocking the DoS attack.  Security is unaffected: each
        # chunk is independently AES-256-GCM authenticated regardless of count.
        _MAX_CHUNKS = 100_000
        total    = min(int(body.get("total_chunks", 1)), _MAX_CHUNKS)
        size     = body.get("total_size", 0)

        # ── Idempotency guard / Resume ────────────────────────────────────────
        # The sender retransmits file_start with the same tid after a bore
        # migration.  Reply with a resume ack so the sender can skip ahead to
        # our current next_index instead of restarting from chunk 0.
        if tid in self._incoming_files:
            meta = self._incoming_files[tid]
            ack_body = {
                "transfer_id": tid,
                "next_index":  meta["next_index"],
            }
            self._send_privmsg_encrypted(
                from_user, json.dumps(ack_body), tag="file_resume_ack"
            )
            return

        # ── Orphan cleanup ────────────────────────────────────────────────────
        # If this sender already has an in-progress transfer with a different tid,
        # it was interrupted mid-migration and restarted from scratch with a new
        # tid.  Close and delete the stale temp file immediately so .part files
        # don't accumulate on disk.
        stale = [t for t, m in self._incoming_files.items()
                 if m.get("from") == from_user and t != tid]
        for stale_tid in stale:
            meta = self._incoming_files.pop(stale_tid)
            try:
                meta["tmp_file"].close()
            except Exception:
                pass
            try:
                os.unlink(meta["tmp_path"])
            except Exception:
                pass
            utils.print_msg(utils.cgrey(
                f"[recv] Cleaned up interrupted transfer from {from_user}."
            ))

        # Open a temp file on disk — chunks written directly, no RAM buffer
        import tempfile as _tf
        folder = RECEIVE_BASE / _file_type_folder(filename)
        folder.mkdir(parents=True, exist_ok=True)
        tmp = _tf.NamedTemporaryFile(delete=False, dir=folder, suffix=".part")

        self._incoming_files[tid] = {
            "filename":     filename,
            "total_chunks": total,
            "total_size":   size,
            "from":         from_user,
            "received":     0,
            "tmp_path":     tmp.name,
            "tmp_file":     tmp,
            "hasher":       __import__("hashlib").sha256(),
            "next_index":   0,
            "pending":      {},   # out-of-order chunks held briefly
        }
        utils.print_msg(utils.cinfo(
            f"[recv] Incoming '{filename}' from {from_user} "
            f"({_human_size(size)}, {total} chunk(s))…"
        ))

    def _handle_file_chunk_binary(self, header: dict, payload: bytes) -> None:
        """
        Fast path: binary file chunk with AES-256-GCM encryption.
        Payload: [4B index BE][4B tid_len BE][tid bytes][nonce(12)+gcm_ct+tag(16)]
        """
        if len(payload) < 8:
            return
        index   = struct.unpack(">I", payload[:4])[0]
        tid_len = struct.unpack(">I", payload[4:8])[0]
        if len(payload) < 8 + tid_len:
            return
        tid      = payload[8:8 + tid_len].decode("utf-8", errors="replace")
        gcm_blob = payload[8 + tid_len:]

        if tid not in self._incoming_files:
            return
        meta      = self._incoming_files[tid]
        from_user = header.get("from", "")
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if not from_user:
            from_user = meta.get("from", "?")

        # Resolve the GCM decryption key for this transfer.
        # Priority:
        #   1. Already cached in meta["gcm_key"] — use it directly.
        #      This is the normal post-migration path: the pairwise Fernet entry
        #      may have been cleaned up by a leave event that fired after the
        #      15-second quiet window expired, but the derived GCM key is still
        #      safely stored in the transfer metadata.
        #   2. Not yet cached — derive it from the live pairwise raw bytes.
        #      Requires pairwise to be present (first chunk of a new transfer).
        gcm_key = meta.get("gcm_key")
        if gcm_key is None:
            raw = self._pairwise_raw.get(from_user)
            if raw is None:
                utils.print_msg(utils.cwarn(
                    f"[recv] No pairwise key for {from_user} yet — dropping chunk {index}"
                ))
                return
            gcm_key = enc.derive_file_cipher_key(raw, tid)
            meta["gcm_key"] = gcm_key

        try:
            raw = enc.gcm_decrypt(gcm_key, gcm_blob)
        except Exception:
            utils.print_msg(utils.cwarn(f"[recv] GCM auth failed on chunk {index} from {from_user}"))
            return

        # Drop chunks with index beyond total — prevents unbounded pending dict growth
        if index >= meta["total_chunks"]:
            return

        # Sender restart detection: if we receive chunk 0 but we've already
        # written chunks, the sender restarted from the beginning (TCP buffer
        # loss after migration).  Truncate and reset so we accept the fresh stream.
        if index == 0 and meta["next_index"] > 0:
            meta["tmp_file"].seek(0)
            meta["tmp_file"].truncate(0)
            meta["hasher"]     = __import__("hashlib").sha256()
            meta["received"]   = 0
            meta["next_index"] = 0
            meta["pending"]    = {}
            meta.pop("_last_pct", None)
            old_prog = meta.pop("_prog_line", None)
            if old_prog:
                with utils._OUTPUT_LOCK:
                    room = utils._current_room[0]
                    try: utils._room_logs[room].remove(old_prog)
                    except ValueError: pass

        # Drop chunks already written
        if index < meta["next_index"]:
            return
        meta["pending"][index] = raw
        while meta["next_index"] in meta["pending"]:
            c = meta["pending"].pop(meta["next_index"])
            meta["tmp_file"].write(c)
            meta["hasher"].update(c)
            meta["received"]   += 1
            meta["next_index"] += 1
        if meta["total_chunks"] > 1:
            pct = int(meta["received"] / meta["total_chunks"] * 100)
            last = meta.get("_last_pct", -1)
            if pct != last:
                meta["_last_pct"] = pct
                old_line = meta.get("_prog_line")
                new_line = utils.cgrey(f"[recv] {meta['filename']} {pct}%")
                meta["_prog_line"] = new_line
                with utils._OUTPUT_LOCK:
                    room = utils._current_room[0]
                    # Remove old progress line from log, add new one.
                    # NOT stored in _ephemeral_lines — file progress must
                    # survive clear_ephemeral_lines() during migration.
                    if old_line and old_line in utils._room_logs[room]:
                        utils._room_logs[room].remove(old_line)
                    utils._room_logs[room].append(new_line)
                utils.print_msg(new_line, _skip_log=True)

    def _handle_file_chunk(self, from_user: str, body: dict) -> None:
        # Legacy JSON/base64 path (kept for compatibility)
        tid   = body.get("transfer_id", "")
        index = body.get("index", 0)
        data  = base64.b64decode(body.get("data_b64", ""))
        if tid not in self._incoming_files:
            return
        meta = self._incoming_files[tid]
        # Drop out-of-range chunks — same guard as the binary path
        if index >= meta["total_chunks"]:
            return
        meta["pending"][index] = data
        while meta["next_index"] in meta["pending"]:
            chunk = meta["pending"].pop(meta["next_index"])
            meta["tmp_file"].write(chunk)
            meta["hasher"].update(chunk)
            meta["received"]   += 1
            meta["next_index"] += 1
        if meta["total_chunks"] > 4:
            pct = int(meta["received"] / meta["total_chunks"] * 100)
            print(utils.cgrey(f"[recv] {pct}%…"), end="\r", flush=True)

    def _handle_file_end(self, from_user: str, body: dict, ts: str) -> None:
        tid     = body.get("transfer_id", "")
        sig_hex = body.get("sig_hex", "")
        if tid not in self._incoming_files:
            utils.print_msg(utils.cwarn(f"[recv] Got file_end for unknown transfer {tid}"))
            return

        meta = self._incoming_files.pop(tid)
        meta["tmp_file"].flush()
        meta["tmp_file"].close()

        # Remove the progress line from the log before printing the result
        prog_line = meta.get("_prog_line")
        if prog_line:
            with utils._OUTPUT_LOCK:
                room = utils._current_room[0]
                try:
                    utils._room_logs[room].remove(prog_line)
                except ValueError:
                    pass

        if meta["received"] != meta["total_chunks"]:
            utils.print_msg(utils.cwarn(
                f"[recv] '{meta['filename']}' incomplete "
                f"({meta['received']}/{meta['total_chunks']} chunks) — discarded."
            ))
            import os as _os; _os.unlink(meta["tmp_path"])
            return

        file_hash = meta["hasher"].digest()   # SHA-256, never loads full file

        # Verify Ed25519 sig over the hash
        vk_hex   = self.tofu_store.get(from_user)
        verified = False
        if vk_hex and sig_hex:
            try:
                verified = enc.verify_signature(
                    bytes.fromhex(vk_hex), file_hash, bytes.fromhex(sig_hex)
                )
            except ValueError:
                pass

        if not verified and vk_hex:
            utils.print_msg(utils.cwarn(
                f"[SECURITY] File signature FAILED from {from_user} — saving anyway."
            ))

        # Move temp file to final named destination
        dest = _unique_dest(meta["filename"])
        import shutil as _sh
        _sh.move(meta["tmp_path"], dest)
        utils.print_msg(utils.cok(
            f"[recv] ✓ '{meta['filename']}' from {from_user} saved to {dest} "
            f"({_human_size(meta['total_size'])})"
            f"{' ✓ verified' if verified else ''}"
        ))

    def _handle_file_resume_ack(self, from_user: str, body: dict) -> None:
        """
        Receiver tells us how many chunks it already has for a transfer we're
        resuming.  Store next_index and wake the waiting _send_file thread.
        """
        tid        = body.get("transfer_id", "")
        next_index = int(body.get("next_index", 0))
        self._file_resume_index[tid] = next_index
        ev = self._file_resume_events.get(tid)
        if ev:
            ev.set()

    def _handle_system(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        _in_quiet = time.monotonic() < self._migration_quiet_until
        if event == "join":
            token = header.get("inbox_token", "")
            uname = self._token_to_username(token) or header.get("username", token[:8] or "?")
            if not _in_quiet:
                utils.log_and_print(self.room, utils.format_system(f"{uname} has joined the chat.", ts))
            # Re-announce our pubkey so the newcomer can resolve our token → username
            self._announce_pubkey()
            self._send({"type": "command", "event": "users_req", "room": self.room})
        elif event == "leave":
            token  = header.get("inbox_token", "")
            uname  = self._token_to_username(token) or header.get("username", token[:8] or "?")
            reason = header.get("reason", "disconnect")
            if not _in_quiet:
                if reason == "room_change":
                    utils.log_and_print(self.room, utils.format_system(f"{uname} switched rooms.", ts))
                else:
                    utils.log_and_print(self.room, utils.format_system(f"{uname} has left the chat.", ts))
            if not _in_quiet:
                self._pairwise.pop(uname, None)
                self._pairwise_raw.pop(uname, None)
                self._dh_pending.pop(uname, None)
                self._file_queue.pop(uname, None)
                self._msg_queue.pop(uname, None)
            self._send({"type": "command", "event": "users_req", "room": self.room})
        elif event == "nick":
            old = header.get("old_nick", "?").lower()
            new = header.get("new_nick", "?").lower()
            utils.log_and_print(self.room, utils.format_system(f"{old} is now known as {new}.", ts))
            # Move ALL pairwise state to new nick — including in-flight handshakes.
            # Without migrating _dh_pending, a dh_resp from the renamed user
            # arrives with the new name but is silently dropped (not found in pending).
            if old in self._pairwise:
                self._pairwise[new] = self._pairwise.pop(old)
            if old in self._pairwise_raw:
                self._pairwise_raw[new] = self._pairwise_raw.pop(old)
            if old in self._dh_pending:
                self._dh_pending[new] = self._dh_pending.pop(old)
            if old in self._msg_queue:
                self._msg_queue[new] = self._msg_queue.pop(old)
            if old in self._file_queue:
                self._file_queue[new] = self._file_queue.pop(old)
            # Also migrate mismatched-user tracking
            if old in self._tofu_mismatched:
                self._tofu_mismatched.discard(old)
                self._tofu_mismatched.add(new)
        elif event == "rate_limit":
            utils.print_msg(utils.cwarn("[warn] You are sending messages too fast."))
        elif event == "nick_error":
            utils.print_msg(utils.cwarn(f"[nick] {header.get('message', 'Nick change failed.')}"))

    def _handle_command(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        if event == "users_resp":
            # Use self.room (plain name) not header["room"] (which is a token).
            room = self.room
            tokens = header.get("tokens", header.get("users", []))
            seen = set()
            users = []
            for tok in tokens:
                if tok == self.inbox_token:
                    name = self.username
                else:
                    name = self._token_to_username(tok)
                    # _token_to_username may match own key if stored in TOFU —
                    # skip to avoid listing self twice.
                    if name == self.username:
                        continue
                    if not name:
                        name = tok[:8]
                if name not in seen:
                    seen.add(name)
                    users.append(name)
            utils.set_room_users(room, users)

    # ------------------------------------------------------------------
    # Input loop
    # ------------------------------------------------------------------

    def _input_loop(self) -> None:
        try:
            while self._running or self._migrating:
                try:
                    line = utils.read_line_noecho()
                except EOFError:
                    break
                if not line:
                    continue
                self._process_input(line.strip())
        except KeyboardInterrupt:
            self._quit = True
        finally:
            self._running = False
            try:
                self.sock.close()
            except OSError:
                pass

    def _process_input(self, line: str) -> None:
        if not line.startswith("/"):
            # Parse optional !tag prefix — e.g. "!danger server is down"
            tag, text = utils.parse_tag(line)
            self._send_chat(text, tag=tag)
            return

        parts = line.split(None, 2)
        cmd   = parts[0].lower()

        if cmd == "/quit":
            self._send({"type": "system", "event": "leave",
                        "username": self.username, "room": self.room})
            self._quit    = True
            self._running = False
            try:
                self.sock.close()
            except OSError:
                pass
            return

        if cmd == "/help":
            self._print_help()
            return

        if cmd == "/clear":
            utils.switch_room_display(self.room)
            return

        if cmd == "/users":
            self._send( {"type": "command", "event": "users_req",
                                   "room": self.room})
            return

        if cmd == "/nick" and len(parts) >= 2:
            new_nick = parts[1].strip().lower()[:32]
            if not new_nick:
                return
            self._send({"type": "command", "event": "nick", "nick": new_nick})
            self.username = new_nick
            return

        if cmd == "/join" and len(parts) >= 2:
            new_room = parts[1]
            self._room_fernet = enc.derive_room_fernet(self._master_key_bytes, new_room)
            self.room = new_room
            # Clear pairwise state — peers wiped their side on our leave event,
            # so our keys are stale. DH will re-establish on next /msg.
            self._pairwise.clear()
            self._pairwise_raw.clear()
            self._dh_pending.clear()
            utils.switch_room_display(new_room)
            self._send({"type": "command", "event": "join_room", "room": self._room_token()})
            # Re-announce pubkey so room members can resolve our token → username
            self._announce_pubkey()
            # Request fresh user list for the new room
            self._send({"type": "command", "event": "users_req", "room": new_room})
            return

        if cmd == "/anim" and len(parts) >= 2:
            if parts[1].lower() in ("on", "1", "yes"):
                self._anim_enabled = True
                utils.print_msg(utils.cok("[anim] Decrypt animation ON."))
            elif parts[1].lower() in ("off", "0", "no"):
                self._anim_enabled = False
                utils.print_msg(utils.cinfo("[anim] Decrypt animation OFF."))
            else:
                state = "ON" if self._anim_enabled else "OFF"
                utils.print_msg(utils.cinfo(f"[anim] Currently {state}. Use /anim on or /anim off."))
            return

        if cmd == "/notify" and len(parts) >= 2:
            if parts[1].lower() in ("on", "1", "yes"):
                utils.set_sounds_enabled(True)
                utils.print_msg(utils.cok("[notify] Notification sounds ON."))
            elif parts[1].lower() in ("off", "0", "no"):
                utils.set_sounds_enabled(False)
                utils.print_msg(utils.cinfo("[notify] Notification sounds OFF."))
            else:
                state = "ON" if utils.sounds_enabled() else "OFF"
                utils.print_msg(utils.cinfo(f"[notify] Currently {state}. Use /notify on or /notify off."))
            return

        if cmd == "/leave":
            if self.room == "general":
                utils.print_msg(utils.cinfo("[leave] You are already in 'general'."))
            else:
                self._room_fernet = enc.derive_room_fernet(self._master_key_bytes, "general")
                self.room = "general"
                self._pairwise.clear()
                self._pairwise_raw.clear()
                self._dh_pending.clear()
                utils.switch_room_display("general")
                self._send({"type": "command", "event": "join_room", "room": self._room_token()})
                self._announce_pubkey()
            return

        if cmd == "/msg" and len(parts) >= 3:
            peer = parts[1].lower()
            raw  = parts[2]
            if peer == self.username:
                utils.print_msg(utils.cwarn("[msg] Cannot send a private message to yourself."))
                return
            tag, text = utils.parse_tag(raw)
            if peer in self._pairwise:
                self._send_privmsg_encrypted(peer, text, tag=tag)
            else:
                self._ensure_dh(peer, then_send=(text, tag))
            return

        if cmd == "/send":
            if len(parts) < 3:
                utils.print_msg(utils.cwarn("[send] Usage: /send <user> <filepath>"))
            else:
                peer     = parts[1].lower()
                filepath = parts[2]
                # Run in background thread — never blocks the input loop
                threading.Thread(
                    target=self._send_file, args=(peer, filepath), daemon=True
                ).start()
            return

        if cmd == "/whoami":
            # Show own username and key fingerprint for out-of-band verification
            fingerprint = self.vk_bytes.hex()[:16] + "..."
            utils.print_msg(utils.cinfo(
                f"[whoami] You are '{self.username}'\n"
                f"  Key fingerprint: {fingerprint}"
            ))
            return

        if cmd == "/trust" and len(parts) >= 2:
            target = parts[1].lower()
            if target in self._tofu_pending:
                # Promote the pending key (from the mismatch warning) to trusted store
                new_vk = self._tofu_pending.pop(target)
                self.tofu_store[target] = new_vk
                id_mod.save_tofu(self.tofu_store, self.tofu_path)
                self._tofu_mismatched.discard(target)
                utils.print_msg(utils.cok(f"[trust] Trusted new key for {target}."))
                # Replay buffered messages that arrived during the mismatch
                self._flush_privmsg_buffer(target)
            elif target in self.tofu_store:
                utils.print_msg(utils.cinfo(f"[trust] {target} is already trusted."))
            else:
                utils.print_msg(utils.cwarn(f"[trust] No pending key for {target}."))
            return

        utils.print_msg(utils.cwarn(f"[error] Unknown command: {cmd}"))

    def _send_file(self, peer: str, filepath: str) -> None:
        """Initiate a file transfer to *peer*, pausing and resuming across bore
        tunnel outages so every chunk is delivered exactly once."""
        if peer == self.username:
            utils.print_msg(utils.cwarn("[send] Cannot send files to yourself."))
            return

        path = Path(filepath).expanduser()
        if not path.exists() or not path.is_file():
            utils.print_msg(utils.cerr(f"[send] File not found: {filepath}"))
            return

        size = path.stat().st_size
        _MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024
        if size > _MAX_FILE_SIZE:
            utils.print_msg(utils.cerr(f"[send] File too large: {_human_size(size)} (max 100 GB)"))
            return

        filename = path.name
        if peer not in self._pairwise:
            utils.print_msg(utils.cgrey(f"[send] Queuing file '{filename}' for {peer} (waiting for DH)..."))
            self._file_queue.setdefault(peer, []).append(filepath)
            self._ensure_dh(peer)
            return

        total_chunks = (size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE
        tid          = os.urandom(8).hex()

        utils.print_msg(utils.cinfo(
            f"[send] Sending '{filename}' ({_human_size(size)}, {total_chunks} chunk(s)) to {peer}…"
        ))

        # ── Migration helpers ──────────────────────────────────────────────
        # How long to wait for a reconnect before giving up entirely.
        _MIGRATE_WAIT  = 90   # seconds — bore restarts can take 30-60s
        # Grace window after a send failure in which we decide if it was a
        # real network error or a bore migration.  We check BOTH the
        # _reconnect_event (cleared when migration starts) AND self._migrating
        # (set slightly before _reconnect_event is cleared) so we never mistake
        # a slow migration detection for a real failure.
        _MIGRATE_GRACE = 5.0  # seconds

        def _pause_for_migration(label: str) -> bool:
            """
            Called after any send failure.
            Waits up to _MIGRATE_GRACE seconds for evidence that a bore
            migration is in progress (_reconnect_event cleared OR _migrating
            set).  Returns True if we should retry, False to abort.
            """
            if self._quit:
                return False

            deadline = time.monotonic() + _MIGRATE_GRACE
            while time.monotonic() < deadline:
                # Either signal is enough to confirm a migration is underway.
                if not self._reconnect_event.is_set() or self._migrating:
                    break
                time.sleep(0.05)

            if self._quit:
                return False

            if self._reconnect_event.is_set() and not self._migrating:
                # Grace period elapsed without any migration signal — real failure.
                utils.print_msg(utils.cerr(
                    f"[send] '{filename}' failed on {label} — connection lost."
                ))
                return False

            # Migration confirmed — wait for full reconnect
            reconnected = self._reconnect_event.wait(timeout=_MIGRATE_WAIT)
            if not reconnected or self._quit:
                utils.print_msg(utils.cerr(
                    f"[send] '{filename}' aborted — reconnect timed out."
                ))
                return False
            return True

        # ── Transfer state ────────────────────────────────────────────────────
        start_body = {
            "filename":     filename,
            "total_size":   size,
            "total_chunks": total_chunks,
            "transfer_id":  tid,
        }
        gcm_key   = enc.derive_file_cipher_key(self._pairwise_raw[peer], tid)
        tid_bytes = tid.encode("utf-8")
        import hashlib as _hl

        send_prog: dict = {}   # tracks the single in-place progress line
        first_attempt = True   # longer ack wait on retries

        # ── Outer migration loop ──────────────────────────────────────────────
        # Each iteration handles one attempt (initial or post-migration resume).
        # On the first pass we start from chunk 0.  On subsequent passes we ask
        # the receiver how many chunks it already has via a file_resume_ack so
        # we can skip ahead rather than restart from 0.
        while True:
            # ── Resume handshake ──────────────────────────────────────────────
            # Register event BEFORE sending file_start so the ack can't arrive
            # and be dropped between the send and the wait.
            resume_from = 0
            resume_ev   = threading.Event()
            self._file_resume_events[tid] = resume_ev
            self._file_resume_index.pop(tid, None)

            # (Re-)send file_start.  Receiver replies with file_resume_ack if it
            # already has partial data for this tid, or stays silent if it has
            # nothing (first send, or receiver was restarted).
            while True:
                if self._send_privmsg_encrypted(peer, json.dumps(start_body), tag="file_start"):
                    break
                if not _pause_for_migration("file_start"):
                    self._file_resume_events.pop(tid, None)
                    return

            # Short timeout on first attempt (receiver has nothing yet, no ack
            # expected).  Longer on retries (receiver should respond quickly).
            ack_timeout = 2.0 if first_attempt else 8.0
            first_attempt = False
            resume_ev.wait(timeout=ack_timeout)
            self._file_resume_events.pop(tid, None)

            ack_idx = self._file_resume_index.pop(tid, None)
            if ack_idx is not None and 0 < ack_idx <= total_chunks:
                resume_from = ack_idx

            # ── Log resume ────────────────────────────────────────────────────
            if resume_from > 0:
                utils.print_msg(utils.cgrey(
                    f"[send] Resuming '{filename}' from chunk "
                    f"{resume_from}/{total_chunks}…"
                ))

            # ── Build SHA-256 state up to resume_from ─────────────────────────
            # The integrity signature at file_end covers the WHOLE file.  We
            # fast-forward by hashing the chunks the receiver already wrote so
            # our running digest stays in sync with the receiver's hasher.
            sha256 = _hl.sha256()
            if resume_from > 0:
                try:
                    with open(path, "rb") as _f:
                        for _i in range(resume_from):
                            _chunk = _f.read(FILE_CHUNK_SIZE)
                            if not _chunk:
                                resume_from = _i
                                break
                            sha256.update(_chunk)
                except OSError as e:
                    utils.print_msg(utils.cerr(f"[send] Error reading file for resume: {e}"))
                    return

            # ── Clear stale progress line ──────────────────────────────────────
            if send_prog.get("line"):
                old = send_prog["line"]
                with utils._OUTPUT_LOCK:
                    room = utils._current_room[0]
                    try: utils._room_logs[room].remove(old)
                    except ValueError: pass
                    utils._ephemeral_lines[room].pop(old, None)
            send_prog.clear()

            # ── Send chunks from resume_from onward ───────────────────────────
            migration_happened = False

            if resume_from < total_chunks:
                try:
                    with open(path, "rb") as f:
                        f.seek(resume_from * FILE_CHUNK_SIZE)
                        for idx in range(resume_from, total_chunks):
                            if self._quit:
                                return

                            chunk = f.read(FILE_CHUNK_SIZE)
                            if not chunk:
                                break

                            sha256.update(chunk)
                            gcm_blob = enc.gcm_encrypt(gcm_key, chunk)
                            frame_payload = (
                                struct.pack(">I", idx) +
                                struct.pack(">I", len(tid_bytes)) +
                                tid_bytes +
                                gcm_blob
                            )
                            peer_token = self._peer_inbox_token(peer)
                            chunk_header = {
                                "type":    "privmsg",
                                "to":      peer_token,
                                "from_token": self.inbox_token,
                                "subtype": "file_chunk_bin",
                                "mid":     os.urandom(16).hex(),
                            }

                            sent = False
                            while not sent:
                                if self._send_lo(chunk_header, frame_payload):
                                    sent = True
                                else:
                                    if not _pause_for_migration(
                                            f"chunk {idx + 1}/{total_chunks}"):
                                        return
                                    migration_happened = True
                                    break

                            if migration_happened:
                                break

                            if total_chunks > 1:
                                pct = int((idx + 1) / total_chunks * 100)
                                last_pct = send_prog.get("last_pct", -1)
                                if pct != last_pct:
                                    send_prog["last_pct"] = pct
                                    new_line = utils.cgrey(f"[send] {filename} {pct}%")
                                    old_line = send_prog.get("line")
                                    send_prog["line"] = new_line
                                    with utils._OUTPUT_LOCK:
                                        room = utils._current_room[0]
                                        if old_line and old_line in utils._room_logs[room]:
                                            utils._room_logs[room].remove(old_line)
                                        utils._room_logs[room].append(new_line)
                                        utils._ephemeral_lines[room][new_line] += 1
                                        if old_line:
                                            utils._ephemeral_lines[room].pop(old_line, None)
                                    utils.print_msg(new_line, _skip_log=True)

                except OSError as e:
                    utils.print_msg(utils.cerr(f"[send] Error reading file: {e}"))
                    return

            if migration_happened:
                # Loop again: will send file_start, get ack, skip ahead.
                continue

            # ── file_end ──────────────────────────────────────────────────────
            sig_hex  = enc.sign_message(self.sk_bytes, sha256.digest()).hex()
            end_body = {"transfer_id": tid, "sig_hex": sig_hex}
            end_ok   = True
            while True:
                if self._send_privmsg_encrypted(peer, json.dumps(end_body), tag="file_end"):
                    break
                if not _pause_for_migration("file_end"):
                    return
                # Migration at file_end — receiver should have all chunks.
                # Resume handshake will confirm next_index == total_chunks
                # so the next iteration skips straight back here.
                end_ok = False
                migration_happened = True
                break

            if migration_happened:
                continue

            break  # ── Transfer complete ─────────────────────────────────────

        utils.print_msg(utils.cok(f"[send] ✓ '{filename}' sent to {peer}."))
        # Remove progress line from log now that we're done
        prog_line = send_prog.get("line")
        if prog_line:
            with utils._OUTPUT_LOCK:
                room = utils._current_room[0]
                try: utils._room_logs[room].remove(prog_line)
                except ValueError: pass
                utils._ephemeral_lines[room].pop(prog_line, None)

    def _print_help(self) -> None:
        entries = [
            ("", "[commands]",       ""),
            ("/help",                "Show this message",                 ""),
            ("/quit",                "Disconnect and exit",               ""),
            ("/clear",               "Clear screen",                      ""),
            ("/users",               "List online users in room",         ""),
            ("/nick <n>",            "Change display name",               ""),
            ("/join <room>",         "Switch room",                       ""),
            ("/leave",               "Return to general",                 ""),
            ("/msg <user> <text>",   "E2E private message",               ""),
            ("/send <user> <path>",  "Send encrypted file",               ""),
            ("/trust <user>",        "Trust key after TOFU mismatch",     ""),
            ("/notify on|off",       "Toggle notification sounds",        ""),
            ("/whoami",              "Show identity fingerprint",         ""),
            ("", "[message tags]",   ""),
            ("!ok <msg>",            "Green — success",                   ""),
            ("!warn <msg>",          "Yellow — warning",                  ""),
            ("!danger <msg>",        "Red — critical",                    ""),
            ("!info <msg>",          "Blue — info",                       ""),
            ("!req <msg>",           "Purple — request",                  ""),
            ("!? <msg>",             "Cyan — question",                   ""),
        ]
        for cmd, desc, _ in entries:
            if not cmd:
                utils.print_msg(utils.cinfo(desc))
            else:
                utils.print_msg(utils.cgrey(f"  {cmd:<22}{desc}"))
