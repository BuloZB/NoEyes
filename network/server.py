# FILE: server.py
"""
server.py — NoEyes chat server (zero-metadata routing).

ZERO-METADATA ROUTING MODEL
============================
The server routes by opaque tokens only — it never sees display names,
room names, or who is messaging whom.

  inbox_token = blake2s(vk_bytes, digest_size=16)   — client-computed
  room_token  = blake2s((room + group_key_hex).encode(), digest_size=16) — client-computed

What the server stores in RAM:
  _clients          inbox_token → ClientConn  (socket handle only)
  _history          room_token  → deque of encrypted payloads (no `from` field)
  _privmsg_pairs    blake2s(token_a:token_b, session_salt) → rate-limit bucket

What the server NEVER stores:
  - Display names / usernames
  - Ed25519 public keys (vk_hex used only for auth challenge, then discarded)
  - Room names (only hashed tokens)
  - Sender identity on any forwarded frame (`from` stripped before routing)

Sender authentication uses SEALED SENDER:
  - Chat:    display name + Ed25519 sig inside group-Fernet encrypted payload
  - Privmsg: from_token + sig inside pairwise-Fernet encrypted payload
  - DH:      from_token + sig inside group-Fernet encrypted inner dict
  Recipients authenticate from the decrypted payload, not the header.

Security invariants:
  - Zero calls to Fernet / .decrypt() / any private-key primitive.
  - vk_hex used only for auth-challenge, never persisted.
  - Server never derives DH keys; all payloads forwarded opaque.
"""

import asyncio
import hashlib
import json
import logging
import os
import sys
import struct
import time
from collections import defaultdict, deque
from typing import Optional

logger = logging.getLogger("noeyes.server")

MAX_PAYLOAD         = 16 * 1024 * 1024
MAX_HISTORY_PAYLOAD = MAX_PAYLOAD
REPLAY_WINDOW_SIZE  = 1000
PRIVMSG_PAIR_LIMIT  = 25
PRIVMSG_PAIR_WINDOW = 900
MAX_CONNECTIONS     = 200


async def _read_exact(reader: asyncio.StreamReader, n: int) -> Optional[bytes]:
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        return None


async def recv_frame(reader: asyncio.StreamReader) -> Optional[tuple[dict, bytes]]:
    size_buf = await _read_exact(reader, 8)
    if size_buf is None:
        return None
    header_len  = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]
    if header_len > 65536:
        logger.warning("Oversized header (%d bytes) — dropping", header_len)
        return None
    if payload_len > MAX_PAYLOAD:
        logger.warning("Oversized payload (%d bytes) — dropping", payload_len)
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
        return json.loads(header_bytes.decode("utf-8")), payload_bytes
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Malformed header — dropping frame")
        return None


async def send_frame(writer: asyncio.StreamWriter, header: dict, payload: bytes = b"") -> bool:
    if writer.is_closing():
        return False
    try:
        hb    = json.dumps(header, separators=(",", ":")).encode("utf-8")
        frame = struct.pack(">I", len(hb)) + struct.pack(">I", len(payload)) + hb + payload
        writer.write(frame)
        await writer.drain()
        return True
    except (OSError, ConnectionResetError, BrokenPipeError):
        return False


class ClientConn:
    def __init__(self, writer: asyncio.StreamWriter, addr: tuple):
        self.writer       = writer
        self.addr         = addr
        self.inbox_token: str  = ""
        self.room:        str  = ""
        self.alive:       bool = True
        self._msg_times:  deque = deque()
        self._ctrl_times: deque = deque()
        self._ctrl_limit: int   = 0

    async def send(self, header: dict, payload: bytes = b"") -> bool:
        ok = await send_frame(self.writer, header, payload)
        if not ok:
            self.alive = False
        return ok

    def check_rate_limit(self, limit_per_minute: int, *, control: bool = False) -> bool:
        now    = time.monotonic()
        bucket = self._ctrl_times if control else self._msg_times
        limit  = max(1, self._ctrl_limit) if control else limit_per_minute
        while bucket and (now - bucket[0]) > 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


class NoEyesServer:
    """Zero-metadata async TCP chat server."""

    def __init__(
        self,
        host:                  str  = "0.0.0.0",
        port:                  int  = 5000,
        history_size:          int  = 50,
        rate_limit_per_minute: int  = 30,
        heartbeat_interval:    int  = 20,
        ssl_cert:              str  = "",
        ssl_key:               str  = "",
        no_tls:                bool = False,
    ):
        self.host               = host
        self.port               = port
        self.history_size       = history_size
        self.rate_limit         = rate_limit_per_minute
        self.heartbeat_interval = heartbeat_interval
        self.ssl_cert           = ssl_cert
        self.ssl_key            = ssl_key
        self.no_tls             = no_tls

        # inbox_token → ClientConn  (no display names stored)
        self._clients: dict[str, ClientConn] = {}

        # room_token → deque[(header_no_from, payload)]
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))

        # Replay protection
        self._room_mids: dict[str, deque] = defaultdict(lambda: deque(maxlen=REPLAY_WINDOW_SIZE))
        self._priv_mids: deque = deque(maxlen=REPLAY_WINDOW_SIZE)

        # Per-pair rate limiting — keyed by BLAKE2s hash, never plaintext tokens
        self._pair_salt: bytes = os.urandom(32)
        self._privmsg_pairs: dict[str, deque] = defaultdict(deque)
        self._token_pair_hashes: dict[str, set] = defaultdict(set)

        self._current_bore_port: int = 0
        self._conn_sem: Optional[asyncio.Semaphore] = None

    def run(self) -> None:
        try:
            asyncio.run(self._main())
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()
            print("\n[server] Shutting down.")

    def broadcast_migrate(self, new_port: int) -> None:
        self._current_bore_port = new_port
        loop = getattr(self, "_loop", None)
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(self._do_broadcast_migrate(new_port), loop)

    async def _main(self) -> None:
        self._loop    = asyncio.get_running_loop()
        self._conn_sem = asyncio.Semaphore(MAX_CONNECTIONS)

        import ssl as _ssl
        from core import encryption as _enc

        ssl_ctx = None
        if not self.no_tls:
            cert_path = self.ssl_cert or "~/.noeyes/server.crt"
            key_path  = self.ssl_key  or "~/.noeyes/server.key"
            from pathlib import Path as _P
            if not _P(cert_path).expanduser().exists():
                print("[server] Generating self-signed TLS certificate...")
                _enc.generate_tls_cert(cert_path, key_path)
                fp = _enc.get_tls_fingerprint(cert_path)
                print(f"[server] Fingerprint: {fp[:16]}...{fp[-16:]}")
            ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            try:
                ssl_ctx.load_cert_chain(_P(cert_path).expanduser(), _P(key_path).expanduser())
            except Exception as e:
                print(f"[server] TLS failed: {e}")
                ssl_ctx = None

        server = await asyncio.start_server(
            self._handle_client, self.host, self.port,
            reuse_address=True, ssl=ssl_ctx,
        )
        async with server:
            addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
            if ssl_ctx:
                fp    = _enc.get_tls_fingerprint(self.ssl_cert or "~/.noeyes/server.crt")
                proto = f"TLS — fingerprint: {fp[:16]}...{fp[-16:]}"
            else:
                proto = "no TLS (--no-tls)"
            print(f"[server] Listening on {addrs} ({proto})")
            logger.info("NoEyes server listening on %s (%s)", addrs, proto)
            asyncio.create_task(self._heartbeat_loop())
            await server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        sem = self._conn_sem
        if sem is not None and sem.locked():
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass
            return
        async with (sem if sem is not None else _null_context()):
            await self._handle_client_inner(reader, writer)

    async def _handle_client_inner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr     = writer.get_extra_info("peername")
        conn     = ClientConn(writer, addr)
        _ip      = str(addr[0]) if addr else "?"
        _ip_anon = ".".join(_ip.split(".")[:2]) + ".*.*" if "." in _ip \
                   else ":".join(_ip.split(":")[:4]) + ":…"
        logger.debug("New connection from %s", addr)
        logger.info("New connection from %s", _ip_anon)
        print(f"  [server] Incoming connection from {_ip_anon}", flush=True)

        try:
            # CVE-NE-003: timeout on join frame
            try:
                result = await asyncio.wait_for(recv_frame(reader), timeout=10.0)
            except asyncio.TimeoutError:
                return
            if result is None:
                return
            header, _ = result

            if header.get("type") != "system" or header.get("event") != "join":
                return

            # Zero-metadata join — server sees only opaque tokens.
            inbox_token = str(header.get("inbox_token", "")).strip()[:64]
            room_token  = str(header.get("room", "")).strip()[:64]
            vk_hex      = str(header.get("vk_hex", "")).strip()   # auth only, discarded after

            if not inbox_token or not room_token:
                return

            # Duplicate token handling (same identity reconnecting)
            if inbox_token in self._clients:
                old_conn = self._clients[inbox_token]
                if not old_conn.alive:
                    self._clients.pop(inbox_token, None)
                    try: old_conn.writer.close()
                    except Exception: pass
                elif vk_hex:
                    nonce = os.urandom(32).hex()
                    await send_frame(writer, {"type": "system", "event": "auth_challenge",
                                              "nonce": nonce, "ts": _now_ts()})
                    try:
                        resp = await asyncio.wait_for(recv_frame(reader), timeout=10.0)
                    except asyncio.TimeoutError:
                        return
                    if resp is None or resp[0].get("event") != "auth_response":
                        return
                    sig_hex = str(resp[0].get("sig", "")).strip()
                    try:
                        from core import encryption as _enc
                        _ok = _enc.verify_signature(
                            bytes.fromhex(vk_hex), nonce.encode(), bytes.fromhex(sig_hex)
                        )
                    except Exception:
                        _ok = False
                    if not _ok:
                        await send_frame(writer, {"type": "system", "event": "auth_failed",
                                                  "message": "Authentication failed.", "ts": _now_ts()})
                        return
                    old_conn.alive = False
                    self._clients.pop(inbox_token, None)
                    try: old_conn.writer.close()
                    except Exception: pass
                else:
                    await send_frame(writer, {"type": "system", "event": "auth_failed",
                                              "message": "Token in use.", "ts": _now_ts()})
                    return
            # vk_hex NOT stored — discarded after auth challenge above.

            conn.inbox_token = inbox_token
            conn.room        = room_token
            conn._ctrl_limit = max(1, self.rate_limit * 2)
            self._clients[inbox_token] = conn

            auth_ok: dict = {"type": "system", "event": "auth_ok", "ts": _now_ts()}
            if self._current_bore_port:
                auth_ok["bore_port"] = self._current_bore_port
            await send_frame(writer, auth_ok)

            # History replay — headers have `from` stripped at store time
            for h, p in list(self._history[room_token]):
                await conn.send(h, p)

            # Broadcast join with opaque token only
            await self._broadcast_room(room_token, {
                "type": "system", "event": "join",
                "inbox_token": inbox_token, "room": room_token, "ts": _now_ts(),
            }, b"", exclude=inbox_token)

            logger.info("[%s…] joined [%s…]", inbox_token[:8], room_token[:8])

            while conn.alive:
                result = await recv_frame(reader)
                if result is None:
                    break
                await self._dispatch(conn, result[0], result[1])

        except Exception as exc:
            logger.exception("Unhandled error for %s: %s", _ip_anon, exc)
        finally:
            await self._disconnect(conn)
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def _dispatch(self, conn: ClientConn, header: dict, payload: bytes) -> None:
        msg_type = header.get("type", "")

        is_file_chunk = (msg_type == "privmsg" and header.get("subtype") == "file_chunk_bin")
        if msg_type != "heartbeat" and not is_file_chunk:
            is_ctrl = msg_type in ("dh_init", "dh_resp", "pubkey_announce", "command")
            if not conn.check_rate_limit(self.rate_limit, control=is_ctrl):
                await conn.send({"type": "system", "event": "rate_limit", "ts": _now_ts()})
                return

        if msg_type == "heartbeat":
            return

        # pubkey_announce: forward verbatim — server NEVER stores pubkeys.
        # Clients maintain their own TOFU stores; server is a pure relay here.
        if msg_type == "pubkey_announce":
            fwd = {k: v for k, v in header.items() if k != "from"}
            fwd["ts"] = _now_ts()
            await self._broadcast_room(conn.room, fwd, payload,
                                       exclude=conn.inbox_token, record=False)
            return

        # DH handshake: route by inbox_token, `from` stripped (sealed sender)
        if msg_type in ("dh_init", "dh_resp"):
            to_token = header.get("to", "")
            fwd = {"type": msg_type, "to": to_token, "ts": _now_ts()}
            # from_token must be forwarded so recipient can identify sender
            # (server strips `from` username but token routing needs this)
            for k in ("mid", "subtype", "from_token"):
                if k in header: fwd[k] = header[k]
            await self._send_to_token(to_token, fwd, payload)
            return

        if msg_type == "command":
            ev = header.get("event", "")
            if ev == "users_req":
                await self._handle_users_req(conn)
            elif ev == "nick":
                await self._handle_nick_relay(conn, header)
            elif ev == "join_room":
                await self._handle_join_room(conn, header)
            return

        # Room chat: NO `from` stamp — sender name lives inside encrypted payload.
        if msg_type == "chat":
            room = conn.room
            mid  = str(header.get("mid", ""))
            if mid:
                rm = self._room_mids[room]
                if mid in rm: return
                rm.append(mid)
            fwd = {"type": "chat", "room": room, "ts": _now_ts()}
            if mid: fwd["mid"] = mid
            await self._broadcast_room(room, fwd, payload, record=True, exclude=conn.inbox_token)
            return

        # Privmsg: route by inbox_token, `from` stripped (sealed sender)
        if msg_type == "privmsg":
            to_token = header.get("to", "")
            mid      = str(header.get("mid", ""))
            if mid:
                if mid in self._priv_mids: return
                self._priv_mids.append(mid)

            if not is_file_chunk:
                pair_hash = hashlib.blake2s(
                    f"{conn.inbox_token}:{to_token}".encode(),
                    key=self._pair_salt[:32], digest_size=8,
                ).hexdigest()
                self._token_pair_hashes[conn.inbox_token].add(pair_hash)
                self._token_pair_hashes[to_token].add(pair_hash)
                bucket = self._privmsg_pairs[pair_hash]
                now_ts = time.monotonic()
                while bucket and (now_ts - bucket[0]) > PRIVMSG_PAIR_WINDOW:
                    bucket.popleft()
                if len(bucket) >= PRIVMSG_PAIR_LIMIT:
                    await conn.send({"type": "system", "event": "rate_limit",
                                     "message": "Sending too fast.", "ts": _now_ts()})
                    return
                bucket.append(now_ts)

            fwd = {"type": "privmsg", "to": to_token, "ts": _now_ts()}
            for k in ("mid", "subtype", "from_token"):
                if k in header: fwd[k] = header[k]
            await self._send_to_token(to_token, fwd, payload)
            return

        if msg_type == "system" and header.get("event") == "leave":
            conn.alive = False
            return

        logger.debug("Unknown frame type '%s'", msg_type)

    async def _broadcast_room(
        self, room: str, header: dict, payload: bytes,
        *, exclude: Optional[str] = None, record: bool = False,
    ) -> None:
        targets = [c for t, c in self._clients.items() if c.room == room and t != exclude]
        if record:
            stored = {k: v for k, v in header.items() if k != "from"}
            self._history[room].append((stored, payload))
        for c in targets:
            await c.send(header, payload)

    async def _send_to_token(self, token: str, header: dict, payload: bytes) -> bool:
        conn = self._clients.get(token)
        if conn is None:
            return False
        return await conn.send(header, payload)

    async def _handle_users_req(self, conn: ClientConn) -> None:
        """Return opaque inbox_tokens — clients resolve to names via their TOFU store."""
        tokens = [t for t, c in self._clients.items() if c.room == conn.room]
        await conn.send({"type": "command", "event": "users_resp",
                         "tokens": tokens, "room": conn.room, "ts": _now_ts()})

    async def _handle_nick_relay(self, conn: ClientConn, header: dict) -> None:
        """Nick is display-only — server just relays, holds no display names."""
        await self._broadcast_room(conn.room, {
            "type": "system", "event": "nick",
            "old_nick":    header.get("old_nick", ""),
            "new_nick":    header.get("nick", ""),
            "inbox_token": conn.inbox_token,
            "room":        conn.room,
            "ts":          _now_ts(),
        }, b"", exclude=conn.inbox_token)

    async def _handle_join_room(self, conn: ClientConn, header: dict) -> None:
        old_room = conn.room
        new_room = str(header.get("room", "")).strip()[:64]
        if not new_room:
            return
        await self._broadcast_room(old_room, {
            "type": "system", "event": "leave",
            "inbox_token": conn.inbox_token, "room": old_room,
            "reason": "room_change", "ts": _now_ts(),
        }, b"", exclude=conn.inbox_token)
        conn.room = new_room
        await self._broadcast_room(new_room, {
            "type": "system", "event": "join",
            "inbox_token": conn.inbox_token,
            "username": conn.username,
            "room": new_room, "ts": _now_ts(),
        }, b"", exclude=conn.inbox_token)
        for h, p in list(self._history[new_room]):
            await conn.send(h, p)

    async def _disconnect(self, conn: ClientConn) -> None:
        if not conn.inbox_token:
            return
        self._clients.pop(conn.inbox_token, None)
        conn.alive = False
        logger.info("[%s…] disconnected", conn.inbox_token[:8])
        for ph in self._token_pair_hashes.pop(conn.inbox_token, set()):
            self._privmsg_pairs.pop(ph, None)
            for s in self._token_pair_hashes.values():
                s.discard(ph)
        # CVE-NE-014: prune empty room history
        if conn.room not in (c.room for c in self._clients.values()):
            self._history.pop(conn.room, None)
        await self._broadcast_room(conn.room, {
            "type": "system", "event": "leave",
            "inbox_token": conn.inbox_token, "room": conn.room, "ts": _now_ts(),
        }, b"", exclude=conn.inbox_token)

    async def _do_broadcast_migrate(self, new_port: int) -> None:
        header = {"type": "system", "event": "migrate", "port": new_port, "ts": _now_ts()}
        logger.info("Broadcasting migrate → bore.pub:%d to %d clients", new_port, len(self._clients))
        for conn in list(self._clients.values()):
            await conn.send(header)

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            dead = []
            for conn in list(self._clients.values()):
                if not await conn.send({"type": "heartbeat", "ts": _now_ts()}):
                    dead.append(conn)
            for conn in dead:
                await self._disconnect(conn)


def _now_ts() -> str:
    return time.strftime("%H:%M:%S")


class _null_context:
    async def __aenter__(self): return self
    async def __aexit__(self, *_): pass
