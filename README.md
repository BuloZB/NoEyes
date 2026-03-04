# NoEyes — Secure Terminal Chat

> End-to-end encrypted group chat, private messages, and file transfer — right in your terminal.  
> The server is a **blind forwarder**: it cannot read a single byte of your messages, even if fully compromised.

[![asciicast](https://asciinema.org/a/Rj1YaEgQjEkeEgPG.svg)](https://asciinema.org/a/Rj1YaEgQjEkeEgPG)

---

**Install demo 1 — `sh install.sh`** (no Python required):

[![asciicast](https://asciinema.org/a/WFlG0y6hcn2X4rB6.svg)](https://asciinema.org/a/WFlG0y6hcn2X4rB6)

---

**Install demo 2 — `python setup.py`** (guided wizard):

[![asciicast](https://asciinema.org/a/33CtfifXVdPOsiVA.svg)](https://asciinema.org/a/33CtfifXVdPOsiVA)

---

## Features

| Feature | Details |
|---|---|
| **Blind-forwarder server** | Zero decryption — server sees only routing metadata |
| **Group chat** | Per-room Fernet keys via HKDF — rooms are cryptographically isolated |
| **Private messages** | X25519 DH handshake — pairwise key only the two parties hold |
| **File transfer** | AES-256-GCM streaming — any size, low RAM |
| **Ed25519 identity** | Auto-generated signing key — all private messages and files are signed |
| **TOFU** | First-seen keys trusted; mismatches trigger a visible security warning |
| **Guided launcher** | Arrow-key menu UI — no command-line experience needed |
| **Auto-installer** | Detects your platform, installs what's missing, asks before changing anything |
| **Self-updater** | `python update.py` pulls the latest version from GitHub |

---

## Installation

### 🐧 Linux / macOS

**No Python?** Run the bootstrap script — it installs Python automatically, then hands off to the setup wizard:
```bash
sh install.sh
```

**Already have Python?** Skip straight to the wizard:
```bash
python setup.py
```

---

### 🪟 Windows

**No Python?**

- PowerShell: `.\\install.ps1`
- Command Prompt: `install.bat`

Either script installs Python if missing, then runs the setup wizard automatically.

**Already have Python?**
```powershell
python setup.py
```

---

### 🤖 Android (Termux)

Install **Termux** from [F-Droid](https://f-droid.org/packages/com.termux/) or the Play Store, then open it and run:

```bash
pkg update && pkg install python git -y
git clone https://github.com/Ymsniper/NoEyes
cd NoEyes
python setup.py
```

---

### 🍎 iOS (iSH)

Install **iSH** from the App Store, then run:
```bash
sh install.sh
```

---

### 🐳 Docker

```bash
docker-compose up
```

Or manually:
```bash
docker build -t noeyes .
docker run -p 5000:5000 noeyes --server --port 5000
```

---

## Running NoEyes

After setup, the easiest way is the guided launcher:
```bash
python launch.py
```

Use the arrow keys to choose **Start server** or **Connect to server** — no commands to memorize.

---

### Manual usage

```bash
# Start a server
python noeyes.py --server --port 5000

# Connect as a client
python noeyes.py --connect SERVER_IP --port 5000

# Using a key file (recommended — share the file out-of-band, never over NoEyes)
python noeyes.py --gen-key --key-file ./chat.key
python noeyes.py --server --port 5000
python noeyes.py --connect SERVER_IP --port 5000 --username alice --key-file ./chat.key
```

---

## In-Chat Commands

| Command | Description |
|---|---|
| `/help` | Show all commands |
| `/quit` | Disconnect and exit |
| `/clear` | Clear the screen |
| `/users` | List users in the current room |
| `/nick <n>` | Change your display name |
| `/join <room>` | Switch rooms (created automatically) |
| `/leave` | Return to the general room |
| `/msg <user> <text>` | Send an E2E-encrypted private message |
| `/send <user> <file>` | Send an encrypted file |
| `/whoami` | Show your identity fingerprint |
| `/trust <user>` | Trust a user's new key after they reinstall |
| `/anim on\|off` | Toggle the decrypt animation |

---

## Connecting Over the Internet (bore tunnel)

NoEyes automatically tries to start a **bore** tunnel when you launch a server. This gives you a public address instantly — no port forwarding or router config needed.

```
bore.pub:12345   ← share this address with your friends
```

Friends connect with:
```bash
python noeyes.py --connect bore.pub --port 12345 --key-file ./chat.key
```

Everything remains end-to-end encrypted — bore only forwards raw bytes.

To disable bore:
```bash
python noeyes.py --server --port 5000 --no-bore
```

> For a permanent server (team use, 24/7 uptime), a cheap VPS like Hetzner (€4/mo) or DigitalOcean ($4/mo) is the better choice. Use `--no-bore` on a VPS since it already has a public IP.

---

## Security Summary

| Layer | Mechanism |
|---|---|
| Group chat | Fernet (AES-128-CBC + HMAC-SHA256), per-room key via HKDF |
| Private messages | Fernet with X25519 pairwise key, Ed25519 signed, TOFU verified |
| File transfer | AES-256-GCM, per-transfer key, Ed25519 signed |
| Identity | Ed25519 keypair auto-generated at `~/.noeyes/identity.key` |
| Key derivation | PBKDF2-HMAC-SHA256 + random salt — unique per deployment |
| Server | Blind forwarder — zero decryption, never holds any keys |
| Transport | TLS on by default with TOFU cert pinning |
| Replay protection | Per-room message ID deque — replayed frames silently dropped |

---

## Project Structure

```
NoEyes/
├── noeyes.py        Entry point and CLI argument parser
├── server.py        Async blind-forwarder server (zero decryption)
├── client.py        Terminal chat client (E2E, DH, TOFU, file transfer)
├── encryption.py    All crypto: Fernet, HKDF, X25519, Ed25519, AES-256-GCM
├── identity.py      Ed25519 keypair generation and TOFU pubkey store
├── utils.py         Terminal output, ANSI colours, decrypt animation
├── config.py        Configuration loading and CLI parsing
│
├── launch.py        ★ Guided launcher — arrow-key menu UI
├── setup.py         ★ Dependency wizard — auto-installs everything
├── update.py        Self-updater — pulls latest from GitHub
│
├── install.sh       Bootstrap for Linux / macOS / Termux / iSH
├── install.ps1      Bootstrap for Windows PowerShell
├── install.bat      Bootstrap for Windows CMD
│
├── selftest.py      Automated test suite (29 tests)
├── requirements.txt pip dependencies (just: cryptography)
└── README.md
```

---

## Keeping NoEyes Up to Date

```bash
python update.py           # update to latest version
python update.py --check   # just check — don't change anything
```
