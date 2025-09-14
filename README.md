# n1nja — CTF & Cybersecurity Helper Bot 🤖

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

**n1nja** adalah bot Discord untuk membantu *Capture The Flag (CTF)*, *bug bounty*, dan *cybersecurity challenge*.  
Bot ini memiliki banyak fitur bawaan untuk decoding, hashing, stego, dan bahkan integrasi AI.

---

## ✨ Fitur

- **Encoding / Decoding**
  - Base64, Hex, Base32, ROT13, Atbash
  - XOR brute force (single-byte)
  - Caesar & Vigenère cipher
  - Auto-decode rekursif (base64 → hex → base32 → base58)

- **Hash Tools**
  - `!hashid` → identifikasi hash via [hashes.com](https://hashes.com) + fallback lokal `hashid`
  - `!fileinfo` → info file + hash MD5/SHA1/SHA256

- **Steganografi**
  - Ekstrak EXIF metadata
  - LSB extractor
  - Strings & hexdump

- **Utility**
  - `!strings` → ekstrak string dari file
  - `!hexdump` → tampilkan data hex/ascii
  - `!jwt` → decode JWT header & payload
  - `!url` → encode/decode URL
  - `!history` → riwayat command per user

- **AI (opsional)**
  - `!ask` → gunakan OpenAI GPT (butuh `OPENAI_API_KEY`)

- **Web server (Flask)**
  - Endpoint `/`, `/status`, `/messages` untuk healthcheck & integrasi eksternal

---

## 📦 Instalasi

### 1. Clone repo
```bash
git clone https://github.com/Rosemary1337/n1nja.git
cd n1nja
````

### 2. Buat virtualenv & install dependencies

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### 3. Konfigurasi environment

Buat file `.env`:

```env
DISCORD_TOKEN=your_discord_bot_token_here
BOT_NAME=n1nja
OWNER_ID=1234567890123456
OPENAI_API_KEY=your_openai_api_key_here
PASTE_PROVIDER=spaste
PASTE_EXPIRY=1d
DB_FILE=/tmp/n1nja.db
```

### 4. Jalankan

```bash
python main.py
```

---

## 🔑 Command List

Ketik `!ctfhelp` di Discord untuk melihat semua command.

Contoh:

```text
!decode base64 SGVsbG8=
!hashid e10adc3949ba59abbe56e057f20f883e
!decode crack e10adc3949ba59abbe56e057f20f883e
!xorbrute 7b2020207d
!stego (upload image lalu jalankan)
```

---

## 🛠️ Requirements

Lihat [requirements.txt](requirements.txt)

* Python **3.11+**
* Discord bot token
* (opsional) OpenAI API key untuk `!ask`

---

## 🐳 Docker (opsional)

Build & run dengan Docker:

```bash
docker build -t n1nja .
docker run -d --env-file .env n1nja
```

---

## ⚠️ Catatan

* Gunakan hanya untuk **legal CTF / edukasi** ⚡
* AI (`!ask`) butuh `OPENAI_API_KEY`

---

## 📜 Lisensi

MIT © 2025 [Rosemary1337](https://github.com/Rosemary1337)

---


