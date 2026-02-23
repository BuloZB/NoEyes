# FILE: server.py
"""
server.py — NoEyes chat server (asyncio rewrite).

The server is a BLIND FORWARDER.  It reads only the plaintext header JSON
(routing metadata) and forwards the encrypted payload bytes verbatim.
It has no keys, calls no decryption function, and cannot read any message.

Why asyncio instead of threads:
  - One OS thread handles all clients via an event loop.
  - When a client is idle the coroutine is suspended with zero CPU cost.
  - No GIL thrashing between idle threads → CPU drops to true idle → no heat.
  - Memory per client: ~50 KB instead of ~8 MB (no per-client thread stack).

Wire protocol (identical to v1 — clients unchanged):
    [4 bytes: header_len BE uint32]
    [4 bytes: payload_len BE uint32]
    [header_len bytes: UTF-8 JSON — plaintext routing metadata]
    [payload_len bytes: opaque encrypted bytes — never touched]

Header fields the server inspects:
    type       "chat"|"system"|"privmsg"|"dh_init"|"dh_resp"
               |"pubkey_announce"|"command"|"heartbeat"
    room       room name for broadcast routing
    to         target username for point-to-point delivery
    from       sender username
    event      "join"|"leave"|"nick"|"users_req"|"join_room"
    username   used by join/nick events
    nick       new nickname (nick event)
    vk_hex     Ed25519 verify key hex (pubkey_announce only)

SECURITY INVARIANTS (unchanged from threaded version):
  - Zero calls to Fernet / .decrypt() / any private-key primitive.
  - pubkey store holds ONLY verify-key hex strings, never signing keys.
  - Server never derives DH keys; dh_init/dh_resp forwarded opaque.
"""

import asyncio
import json
import logging
import struct
import time
from collections import defaultdict, deque
from typing import Optional

logger = logging.getLogger("noeyes.server")

# ---------------------------------------------------------------------------
# Async framing helpers
# ---------------------------------------------------------------------------


async def _read_exact(reader: asyncio.StreamReader, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes; return None on EOF/error."""
    try:
        data = await reader.readexactly(n)
        return data
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        return None


async def recv_frame(
    reader: asyncio.StreamReader,
) -> Optional[tuple[dict, bytes]]:
    """
    Read one frame from *reader*.
    Returns (header_dict, raw_payload_bytes) or None on disconnect.
    Payload bytes are NEVER decrypted — returned raw.
    """
    size_buf = await _read_exact(reader, 8)
    if size_buf is None:
        return None

    header_len  = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]

    # Guard against malformed/oversized headers
    if header_len > 65536:
        logger.warning("Oversized header (%d bytes) — dropping connection", header_len)
        return None

    header_bytes = await _read_exact(reader, header_len)
    if header_bytes is None:
        return None

    payload_bytes = b""
    if payload_len:
        payload_bytes = await _read_exact(reader, payload_len)
        if payload_bytes is None:
            return None

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Malformed header — dropping frame")
        return None

    return header, payload_bytes


async def send_frame(
    writer: asyncio.StreamWriter,
    header: dict,
    payload: bytes = b"",
) -> bool:
    """
    Write one frame to *writer*.
    Returns False if the connection is already closing.
    """
    if writer.is_closing():
        return False
    try:
        hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
        frame = (
            struct.pack(">I", len(hb)) +
            struct.pack(">I", len(payload)) +
            hb +
            payload
        )
        writer.write(frame)
        await writer.drain()
        return True
    except (OSError, ConnectionResetError, BrokenPipeError):
        return False


# ---------------------------------------------------------------------------
# Client state
# ---------------------------------------------------------------------------


class ClientConn:
    """State for one connected client — no thread, no lock needed."""

    def __init__(
        self,
        writer:   asyncio.StreamWriter,
        addr:     tuple,
    ):
        self.writer   = writer
        self.addr     = addr
        self.username: str   = ""
        self.room:     str   = "general"
        self.vk_hex:   str   = ""
        self.alive:    bool  = True
        # Rate limiting: timestamps of recent messages
        self._msg_times: deque = deque()

    async def send(self, header: dict, payload: bytes = b"") -> bool:
        """Send a frame to this client. Returns False on error."""
        ok = await send_frame(self.writer, header, payload)
        if not ok:
            self.alive = False
        return ok

    def check_rate_limit(self, limit_per_minute: int) -> bool:
        now = time.monotonic()
        while self._msg_times and (now - self._msg_times[0]) > 60:
            self._msg_times.popleft()
        if len(self._msg_times) >= limit_per_minute:
            return False
        self._msg_times.append(now)
        return True


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class NoEyesServer:
    """
    Async TCP chat server — rooms, rate limiting, heartbeat, history.

    BLIND FORWARDER: payload bytes forwarded verbatim, never decrypted.
    Single-threaded asyncio — zero CPU when idle, low heat, low battery.
    """

    def __init__(
        self,
        host:                 str = "0.0.0.0",
        port:                 int = 5000,
        history_size:         int = 50,
        rate_limit_per_minute: int = 30,
        heartbeat_interval:   int = 20,
    ):
        self.host               = host
        self.port               = port
        self.history_size       = history_size
        self.rate_limit         = rate_limit_per_minute
        self.heartbeat_interval = heartbeat_interval

        # username → ClientConn
        self._clients: dict[str, ClientConn] = {}
        # room → deque[(header, payload)]
        self._history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=history_size)
        )
        # username → vk_hex (Ed25519 verify key, plaintext header value)
        self._pubkeys: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the event loop. Blocks until Ctrl+C."""
        try:
            asyncio.run(self._main())
        except KeyboardInterrupt:
            print("\n[server] Shutting down.")

    async def _main(self) -> None:
        server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True,
        )
        async with server:
            addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
            print(f"[server] Listening on {addrs}")
            logger.info("NoEyes server listening on %s", addrs)
            # Start heartbeat as a background task
            asyncio.create_task(self._heartbeat_loop())
            await server.serve_forever()

    # ------------------------------------------------------------------
    # Per-client coroutine  (replaces the per-client thread)
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername")
        conn = ClientConn(writer, addr)
        logger.debug("New connection from %s", addr)

        try:
            # First frame must be a join event
            result = await recv_frame(reader)
            if result is None:
                return
            header, payload = result

            if header.get("type") != "system" or header.get("event") != "join":
                logger.warning("First frame was not join from %s", addr)
                return

            username = str(header.get("username", "")).strip()[:32]
            room     = str(header.get("room", "general")).strip()[:64]
            vk_hex   = str(header.get("vk_hex", "")).strip()

            if not username:
                return

            # Reject duplicate username
            if username in self._clients:
                await send_frame(writer, {
                    "type":    "system",
                    "event":   "nick_error",
                    "message": f"Username '{username}' is already taken.",
                    "ts":      _now_ts(),
                })
                return

            conn.username = username
            conn.room     = room
            conn.vk_hex   = vk_hex
            self._clients[username] = conn

            if vk_hex:
                self._pubkeys[username] = vk_hex

            # Replay history to the new joiner
            history_snapshot = list(self._history[room])
            for h, p in history_snapshot:
                await conn.send(h, p)

            # Broadcast join event to room
            join_header = {
                "type":     "system",
                "event":    "join",
                "username": username,
                "room":     room,
                "ts":       _now_ts(),
            }
            await self._broadcast_room(room, join_header, b"", exclude=username)

            # Send known pubkeys of room members to new joiner
            await self._send_known_pubkeys(conn, room)

            logger.info("%s joined room '%s'", username, room)

            # Main receive loop — suspends cheaply between frames
            while conn.alive:
                result = await recv_frame(reader)
                if result is None:
                    break
                h, p = result
                await self._dispatch(conn, h, p)

        except Exception as exc:
            logger.exception("Unhandled error for %s: %s", addr, exc)
        finally:
            await self._disconnect(conn)
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Frame dispatcher
    # ------------------------------------------------------------------

    async def _dispatch(
        self,
        conn:    ClientConn,
        header:  dict,
        payload: bytes,
    ) -> None:
        msg_type = header.get("type", "")

        # Rate limiting — skip for heartbeats (they're dropped anyway)
        if msg_type != "heartbeat":
            if not conn.check_rate_limit(self.rate_limit):
                await conn.send({
                    "type":  "system",
                    "event": "rate_limit",
                    "ts":    _now_ts(),
                })
                return

        # Heartbeat from client — it's an ACK, just drop it silently.
        # Do NOT echo back or we create an infinite ping-pong loop.
        if msg_type == "heartbeat":
            return

        # Pubkey announcement — store and rebroadcast to room
        if msg_type == "pubkey_announce":
            vk_hex = str(header.get("vk_hex", "")).strip()
            if vk_hex:
                self._pubkeys[conn.username] = vk_hex
                conn.vk_hex = vk_hex
                announce = {
                    "type":     "pubkey_announce",
                    "username": conn.username,
                    "vk_hex":   vk_hex,
                    "room":     conn.room,
                    "ts":       _now_ts(),
                }
                await self._broadcast_room(
                    conn.room, announce, b"", exclude=conn.username, record=False
                )
            return

        # DH handshake — route point-to-point, payload forwarded blind
        if msg_type in ("dh_init", "dh_resp"):
            to_user       = header.get("to", "")
            header["from"] = conn.username
            header["ts"]   = _now_ts()
            await self._send_to_user(to_user, header, payload)
            return

        # Commands
        if msg_type == "command":
            event = header.get("event", "")
            if event == "users_req":
                await self._handle_users_req(conn)
            elif event == "nick":
                await self._handle_nick(conn, header)
            elif event == "join_room":
                await self._handle_join_room(conn, header)
            return

        # Chat (broadcast) and privmsg (point-to-point) — payload never decrypted
        if msg_type in ("chat", "privmsg"):
            header["from"] = conn.username
            header["ts"]   = _now_ts()
            if msg_type == "privmsg":
                to_user = header.get("to", "")
                await self._send_to_user(to_user, header, payload)
            else:
                room = header.get("room", conn.room)
                if room != conn.room:
                    room = conn.room   # cannot broadcast to other rooms
                await self._broadcast_room(room, header, payload, record=True)
            return

        # Client-initiated leave
        if msg_type == "system" and header.get("event") == "leave":
            conn.alive = False
            return

        logger.debug("Unknown frame type '%s' from %s", msg_type, conn.username)

    # ------------------------------------------------------------------
    # Routing helpers — NO decryption, payload forwarded opaque
    # ------------------------------------------------------------------

    async def _broadcast_room(
        self,
        room:    str,
        header:  dict,
        payload: bytes,
        *,
        exclude: Optional[str] = None,
        record:  bool = False,
    ) -> None:
        """Send a frame to every client in *room*, optionally skipping one."""
        targets = [
            c for u, c in self._clients.items()
            if c.room == room and u != exclude
        ]
        if record:
            self._history[room].append((header, payload))
        for client in targets:
            await client.send(header, payload)

    async def _send_to_user(
        self,
        username: str,
        header:   dict,
        payload:  bytes,
    ) -> bool:
        """Send a frame to a single user. Returns False if not found."""
        conn = self._clients.get(username)
        if conn is None:
            return False
        return await conn.send(header, payload)

    async def _send_known_pubkeys(
        self,
        new_conn: ClientConn,
        room:     str,
    ) -> None:
        """Send all known room-member pubkeys to a newly joined client."""
        for uname, c in self._clients.items():
            if c.room == room and c.vk_hex and uname != new_conn.username:
                await new_conn.send({
                    "type":     "pubkey_announce",
                    "username": uname,
                    "vk_hex":   c.vk_hex,
                    "room":     room,
                    "ts":       _now_ts(),
                }, b"")

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    async def _handle_users_req(self, conn: ClientConn) -> None:
        users = [u for u, c in self._clients.items() if c.room == conn.room]
        await conn.send({
            "type":  "command",
            "event": "users_resp",
            "users": users,
            "room":  conn.room,
            "ts":    _now_ts(),
        })

    async def _handle_nick(self, conn: ClientConn, header: dict) -> None:
        new_nick = str(header.get("nick", "")).strip()[:32]
        if not new_nick:
            return
        old_nick = conn.username

        if new_nick in self._clients:
            await conn.send({
                "type":    "system",
                "event":   "nick_error",
                "message": f"Username '{new_nick}' is already taken.",
                "ts":      _now_ts(),
            })
            return

        del self._clients[old_nick]
        conn.username = new_nick
        self._clients[new_nick] = conn
        if old_nick in self._pubkeys:
            self._pubkeys[new_nick] = self._pubkeys.pop(old_nick)

        # Broadcast nick change to ALL rooms, not just the current one.
        # If we only broadcast to conn.room, clients in other rooms keep sending
        # /msg to the old name, which the server can no longer route — silent drop.
        nick_event = {
            "type":     "system",
            "event":    "nick",
            "old_nick": old_nick,
            "new_nick": new_nick,
            "room":     conn.room,
            "ts":       _now_ts(),
        }
        seen = set()
        for uname, c in list(self._clients.items()):
            if c.room not in seen and uname != new_nick:
                seen.add(c.room)
        for room in seen:
            await self._broadcast_room(room, nick_event, b"", exclude=new_nick)

    async def _handle_join_room(self, conn: ClientConn, header: dict) -> None:
        new_room = str(header.get("room", "general")).strip()[:64]
        old_room = conn.room

        # Notify old room — reason:"room_change" so clients keep pairwise keys
        await self._broadcast_room(old_room, {
            "type":     "system",
            "event":    "leave",
            "username": conn.username,
            "room":     old_room,
            "reason":   "room_change",
            "ts":       _now_ts(),
        }, b"", exclude=conn.username)

        conn.room = new_room

        # Notify new room
        await self._broadcast_room(new_room, {
            "type":     "system",
            "event":    "join",
            "username": conn.username,
            "room":     new_room,
            "ts":       _now_ts(),
        }, b"", exclude=conn.username)

        # Replay history to the joining client
        for h, p in list(self._history[new_room]):
            await conn.send(h, p)

    # ------------------------------------------------------------------
    # Disconnect / cleanup
    # ------------------------------------------------------------------

    async def _disconnect(self, conn: ClientConn) -> None:
        if not conn.username:
            return
        self._clients.pop(conn.username, None)
        conn.alive = False
        logger.info("%s disconnected", conn.username)

        # Notify room of real disconnect (no "reason" field → client clears pairwise)
        await self._broadcast_room(conn.room, {
            "type":     "system",
            "event":    "leave",
            "username": conn.username,
            "room":     conn.room,
            "ts":       _now_ts(),
        }, b"", exclude=conn.username)

    # ------------------------------------------------------------------
    # Heartbeat — asyncio.sleep is true idle, zero CPU
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            dead = []
            for username, conn in list(self._clients.items()):
                ok = await conn.send({"type": "heartbeat", "ts": _now_ts()})
                if not ok:
                    dead.append(conn)
            for conn in dead:
                await self._disconnect(conn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_ts() -> str:
    return time.strftime("%H:%M:%S")
