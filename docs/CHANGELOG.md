# FILE: CHANGELOG.md
# Changelog

## [v0.4.0] — Zero-Metadata Routing + Security Patch Release

### Security Patches (CVEs)

- **CVE-NE-001 (CRITICAL)** — Unauthenticated DH key exchange allowed group member MITM on private messages. Fixed: DH public keys are now signed with Ed25519 and verified against the TOFU store on both sides.
- **CVE-NE-002 (HIGH)** — Static PBKDF2 salt for identity password encryption made rainbow table attacks viable. Fixed: random 32-byte salt generated per identity file, stored alongside the key.
- **CVE-NE-003 (HIGH)** — No timeout on initial join handshake allowed async task exhaustion DoS. Fixed: 10-second timeout on first frame.
- **CVE-NE-004 (HIGH)** — No connection count limit allowed file descriptor exhaustion. Fixed: hard cap of 200 connections via asyncio Semaphore.
- **CVE-NE-005 (MEDIUM)** — Nick change broadcast to all rooms leaked cross-room presence. Fixed: nick changes broadcast only to the sender's current room.
- **CVE-NE-006 (MEDIUM)** — Migrate event unsigned in `--no-tls` mode allowed evil-twin redirection. Fixed: client verifies `migrate_sig` against pinned server key; warns if missing in `--no-tls` mode.
- **CVE-NE-007 (MEDIUM)** — `_pubkeys` dict never purged on disconnect caused memory leak and stale key retention. Fixed: keys removed in `_disconnect`.
- **CVE-NE-008 (MEDIUM)** — Discovery cache file written without `chmod(0o600)`. Fixed via `_restrict_perms()` helper (cross-OS safe).
- **CVE-NE-011 (MEDIUM)** — Discovery appkey file world-readable. Fixed: `chmod(0o600)` after write.
- **CVE-NE-012 (MEDIUM)** — Discovery port unauthenticated. Fixed: client-side verification framework added.
- **BUG-001** — `file_resume_ack` tag printed as raw JSON in chat window. Fixed: tag added to exclusion list.

### Zero-Metadata Routing (Major Architecture Change)

The server routing model was completely redesigned. The server now has **zero knowledge** of usernames, room names, or public keys.

**Inbox tokens** — each client derives `inbox_token = blake2s(vk_bytes, digest_size=16)` locally. All frames are routed by this token. The server never stores or sees display names.

**Room tokens** — `room_token = blake2s((room_name + group_key_hex).encode(), digest_size=16)`. The server never sees room names.

**Sealed sender** — sender username and Ed25519 signature are placed inside the encrypted payload, not in the routing header. The server cannot determine who sent any message to whom.

**Hashed pair keys** — privmsg rate limiting uses `blake2s(token_a:token_b, session_salt)` as pair keys. The server cannot reconstruct communication graphs even from its own rate-limit state.

### File Transfer Fixes

- Chunk headers were using username-based routing (`"to": peer`) instead of inbox tokens — every chunk was silently dropped by the server. Fixed to use `"to": peer_token`.
- Receiver `_handle_file_chunk_binary` read `from_user` from stripped header field. Fixed to resolve via `from_token` → TOFU reverse lookup.
- Chunk size bumped from 64KB to 512KB — 8x reduction in sender queue round-trips.
- `_restrict_perms` was calling itself recursively instead of `p.chmod(0o600)` — stack overflow on any new identity file creation. Fixed.

### Sidebar / User List Fixes

- `users_resp` server response changed from `users` (username list) to `tokens` (inbox token list). Client now maps each token to a display name via TOFU reverse lookup, with self-token resolved to `self.username`.
- `set_room_users` was being called with a room token instead of the plain room name — sidebar was always empty. Fixed to use `self.room`.
- `pubkey_announce` handler now triggers a `users_req` refresh after updating TOFU, so tokens resolve to names immediately on join.
- `join`/`leave` system events now resolve `inbox_token` to username via TOFU reverse lookup.

### DH / Private Message Fixes

- `from_token` was being stripped from forwarded `dh_init`/`dh_resp` frames. Recipient had no way to identify sender, DH silently failed, all PMs broken. Fixed: server now forwards `from_token`.
- `_handle_dh_init` and `_handle_dh_resp` already had `_token_to_username` fallback — now actually reachable.

### Connection Fixes

- Join header was missing `inbox_token` — server rejected all connections silently with no error message. Fixed.
- Server sends `auth_failed` but client only handled `nick_error` — auth failures caused silent reconnect loop. Fixed: both event names handled together.
