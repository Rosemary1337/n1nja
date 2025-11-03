

# n1nja — CTF & Cybersecurity Helper Bot 🤖

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

**n1nja** is a Discord bot to help with *Capture The Flag (CTF)*, *bug bounty*, and *cybersecurity challenges*.  
This bot has many built-in features for decoding, hashing, stego, and even AI integration.

---

## ✨ Features

- **Encoding / Decoding**
  - Base64, Hex, Base32, ROT13, Atbash
  - XOR brute force (single-byte)
  - Caesar & Vigenère cipher
  - Recursive auto-decode (base64 → hex → base32 → base58)

- **Hash Tools**
  - `!hashid` → identify hash via [hashes.com](https://hashes.com) + local fallback `hashid`
  - `!fileinfo` → file info + MD5/SHA1/SHA256 hash

- **Steganography**
  - Extract EXIF metadata
  - LSB extractor
  - Strings & hexdump

- **Utility**
  - `!strings` → extract strings from file
  - `!hexdump` → display hex/ascii data
  - `!jwt` → decode JWT header & payload
  - `!url` → encode/decode URL
  - `!history` → command history per user

- **AI (optional)**
  - `!ask` → use OpenAI GPT (requires `OPENAI_API_KEY`)

- **Web server (Flask)**
  - Endpoint `/`, `/status`, `/messages` for healthcheck & external integration

---

## 📦 Installation

### 1. Clone repo
```bash
git clone https://github.com/Rosemary1337/n1nja.git
cd n1nja
````

### 2. Create virtualenv & install dependencies

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### 3. Configure environment

Create `.env` file:

```env
DISCORD_TOKEN=your_discord_bot_token_here
BOT_NAME=n1nja
OWNER_ID=1234567890123456
OPENAI_API_KEY=your_openai_api_key_here
PASTE_PROVIDER=spaste
PASTE_EXPIRY=1d
DB_FILE=/tmp/n1nja.db
```

### 4. Run

```bash
python main.py
```

---

## 🔑 Command List

Type `!ctfhelp` in Discord to see all commands.

Example:

```text
!decode base64 SGVsbG8=
!hashid e10adc3949ba59abbe56e057f20f883e
!decode crack e10adc3949ba59abbe56e057f20f883e
!xorbrute 7b2020207d
!stego (upload image then run)
```

---

## 🛠️ Requirements

See [requirements.txt](requirements.txt)

* Python **3.11+**
* Discord bot token
* (optional) OpenAI API key for `!ask`

---

## 🐳 Docker (optional)

Build & run with Docker:

```bash
docker build -t n1nja .
docker run -d --env-file .env n1nja
```

---

## ⚠️ Notes

* Use only for **legal CTF / education** ⚡
* AI (`!ask`) requires `OPENAI_API_KEY`

---

## 📜 License

MIT © 2025 [Rosemary1337](https://github.com/Rosemary1337)

---
