# n1nja.py
# Ultimate Swiss-Army-Knife CTF helper (Bahasa Indonesia)
# - Integrasi spaste.us untuk paste otomatis
# - Banyak fitur: decode/encode, crypto, stego, fileinfo, hashid (dCode), AI, history, paste
# - Gunakan .env untuk DISCORD_TOKEN, OPENAI_API_KEY, USE_DCODE, OWNER_ID, PORT

import os
import re
import io
import time
import json
import base64
import binascii
import hashlib
import codecs
import sqlite3
import asyncio
import aiohttp
import threading
from typing import Optional, List, Tuple

from dotenv import load_dotenv
from flask import Flask
from PIL import Image, ExifTags

import discord
from discord.ext import commands
import sqlite3

# Cek environment variable
DB_FILE = os.getenv('DB_FILE', 'n1nja.db')

# Jika path memiliki subfolder, buat foldernya agar ada
db_dir = os.path.dirname(DB_FILE)
if db_dir:
    try:
        os.makedirs(db_dir, exist_ok=True)
    except Exception as e:
        print("Gagal membuat folder untuk DB:", e)

try:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
except sqlite3.OperationalError as e:
    print("SQLite error:", str(e))
    # coba fallback ke temp
    DB_FILE = '/tmp/n1nja.db'
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    
# ---------------- Load config ----------------
load_dotenv()
BOT_NAME = 'n1nja'
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
OPENAI_KEY = os.getenv('OPENAI_API_KEY', '')
USE_DCODE = os.getenv('USE_DCODE', 'true').lower() == 'true'
PASTE_PROVIDER = os.getenv('PASTE_PROVIDER', 'spaste')  # 'spaste' default
PASTE_EXPIRY = os.getenv('PASTE_EXPIRY', '1d')  # spaste expiry string
OWNER_ID = int(os.getenv('OWNER_ID', '0') or 0)
PORT = int(os.getenv('PORT', '8080') or 8080)

# ---------------- Bot setup ----------------
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# ---------------- Database (history + kv) ----------------
DB_FILE = os.path.join(os.getcwd(), 'n1nja.db')
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
conn.execute('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT, user_id TEXT, command TEXT, input TEXT, output TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.execute('CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)')
conn.commit()

# ---------------- Constants & regex ----------------
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=\n\r]+$')
BASE32_RE = re.compile(r'^[A-Z2-7=\n\r]+$', re.IGNORECASE)

B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}

HASH_GUESSES = {
    32: ['MD5', 'NTLM', 'LM'],
    40: ['SHA-1', 'RIPEMD-160'],
    56: ['SHA-224'],
    64: ['SHA-256', 'SHA3-256'],
    96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'SHA3-512']
}

COMMON_WORDS = [b'the', b'flag', b'ctf', b'and', b'http', b'admin']
FLAG_PATTERNS = [r'CTF\{[^}]{3,}\}', r'flag\{[^}]{3,}\}', r'[A-Za-z0-9_{}-]{8,}']

# in-memory cache for providers (dCode etc)
_provider_cache = {}

# ---------------- Utilities ----------------
def save_history(guild_id, user_id, command, inp, out):
    try:
        conn.execute('INSERT INTO history(guild_id,user_id,command,input,output) VALUES(?,?,?,?,?)', (str(guild_id), str(user_id), command, inp[:4000], out[:4000]))
        conn.commit()
    except Exception:
        pass

async def paste_text_spaste(text: str, expiry: str = '1d') -> Optional[str]:
    """
    Upload ke spaste.us API.
    Request:
      POST https://spaste.us/api/v1/paste
      JSON: { "content": "...", "syntax": "text", "expiry":"1d" }
    Response:
      { "status":"success", "paste_url": "https://spaste.us/p/abcd" }
    """
    url = 'https://spaste.us/api/v1/paste'
    payload = {
        'content': text,
        'syntax': 'text',
        'expiry': expiry
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=20) as resp:
                if resp.status != 200:
                    return None
                j = await resp.json()
                if isinstance(j, dict) and j.get('status') == 'success' and j.get('paste_url'):
                    return j.get('paste_url')
                # fallback: if paste_url directly
                if isinstance(j, dict) and j.get('paste_url'):
                    return j.get('paste_url')
    except Exception:
        return None
    return None

async def paste_text(text: str) -> Optional[str]:
    """
    Wrapper paste_text: saat ini mendukung spaste.us.
    Mudah diubah untuk provider lain dengan mengganti fungsi di sini.
    """
    # hanya spaste untuk sekarang
    return await paste_text_spaste(text, expiry=PASTE_EXPIRY)

async def safe_send(channel, text: str):
    """
    Kirim ke Discord: jika teks panjang, upload ke paste provider lalu kirim link.
    """
    if text is None:
        return
    max_len = 1900
    try:
        if len(text) <= max_len:
            await channel.send('```' + text + '```')
            return
        url = await paste_text(text)
        if url:
            await channel.send('📄 Output terlalu panjang, disimpan di: ' + url)
            return
        # fallback: kirim potongan
        for i in range(0, len(text), max_len):
            await channel.send('```' + text[i:i+max_len] + '```')
    except Exception:
        # final fallback: kirim simple error
        try:
            await channel.send('⚠️ Gagal mengirim output. Cek bot logs.')
        except Exception:
            pass

def find_flags(text: str) -> List[str]:
    found = []
    for p in FLAG_PATTERNS:
        for m in re.findall(p, text, flags=re.IGNORECASE):
            if m not in found:
                found.append(m)
    return found

# ---------------- Binary helpers ----------------
def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    res = []
    current = bytearray()
    for b in data:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                res.append(current.decode('utf-8', errors='ignore'))
            current = bytearray()
    if len(current) >= min_len:
        res.append(current.decode('utf-8', errors='ignore'))
    return res

def hexdump(data: bytes, length=16) -> str:
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = ' '.join(['%02x' % b for b in chunk])
        ascii_bytes = ''.join([chr(b) if 32 <= b < 127 else '.' for b in chunk])
        lines.append('%08x  %s  %s' % (i, hex_bytes.ljust(length*3), ascii_bytes))
    return '\n'.join(lines[:400])

# ---------------- Encoding/decoding ----------------
def is_hex(s: str) -> bool:
    s2 = s.strip().replace(' ', '')
    return bool(HEX_RE.match(s2)) and len(s2) % 2 == 0

def is_base64(s: str) -> bool:
    s2 = s.strip()
    if len(s2) % 4 != 0:
        return False
    return bool(BASE64_RE.match(s2))

def try_base64(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        try:
            return base64.b64decode(s + '==')
        except Exception:
            return None

def try_hex(s: str) -> Optional[bytes]:
    try:
        s2 = re.sub(r'[^0-9a-fA-F]', '', s)
        return bytes.fromhex(s2)
    except Exception:
        return None

def try_base32(s: str) -> Optional[bytes]:
    try:
        return base64.b32decode(s)
    except Exception:
        return None

def b58_decode(s: str) -> bytes:
    num = 0
    for ch in s:
        if ch not in B58_MAP:
            raise ValueError('Invalid base58 char')
        num = num * 58 + B58_MAP[ch]
    full = num.to_bytes((num.bit_length() + 7) // 8, 'big') or b'\x00'
    n_pad = len(s) - len(s.lstrip('1'))
    return b'\x00' * n_pad + full

# ---------------- Crypto helpers ----------------
def score_plaintext(b: bytes) -> int:
    s = 0
    low = b.lower()
    for w in COMMON_WORDS:
        if w.lower() in low:
            s += 10
    printable = sum(1 for c in b if 32 <= c < 127)
    s += int((printable / max(1, len(b))) * 20)
    return s

def single_xor_bruteforce(data: bytes, top=6):
    res = []
    for k in range(256):
        out = bytes([c ^ k for c in data])
        sc = score_plaintext(out)
        res.append((sc, k, out))
    res.sort(reverse=True, key=lambda x: x[0])
    return res[:top]

def caesar_shift(text: str, shift: int) -> str:
    out = ''
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out += chr((ord(ch) - base + shift) % 26 + base)
        else:
            out += ch
    return out

def atbash(text: str) -> str:
    out = ''
    for ch in text:
        if ch.isupper():
            out += chr(90 - (ord(ch) - 65))
        elif ch.islower():
            out += chr(122 - (ord(ch) - 97))
        else:
            out += ch
    return out

def vigenere(text: str, key: str, decrypt=False) -> str:
    out = ''
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            kch = key[ki % len(key)]
            shift = ord(kch.upper()) - ord('A')
            if decrypt:
                shift = -shift
            out += chr((ord(ch) - base + shift) % 26 + base)
            ki += 1
        else:
            out += ch
    return out

# ---------------- LSB stego ----------------
def lsb_extract(img: Image.Image, bits=1, max_bytes=8192) -> bytes:
    img = img.convert('RGB')
    pixels = list(img.getdata())
    bits_stream = []
    for px in pixels:
        for c in px:
            bits_stream.append(c & ((1 << bits) - 1))
    bits_flat = []
    for val in bits_stream:
        for b in range(bits - 1, -1, -1):
            bits_flat.append((val >> b) & 1)
    out = bytearray()
    for i in range(0, min(len(bits_flat), max_bytes * 8), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits_flat[i + j]
        out.append(byte)
    return bytes(out).rstrip(b'\x00')

# ---------------- Auto recursive decode ----------------
def auto_decode_recursive(data: bytes, max_depth=3) -> List[Tuple[str, bytes]]:
    results = []
    seen = set()
    def rec(d: bytes, depth: int, label: str):
        if depth > max_depth:
            return
        key = (label, d)
        if key in seen:
            return
        seen.add(key)
        results.append((label, d))
        # base64
        try:
            b64 = base64.b64decode(d, validate=True)
            rec(b64, depth + 1, label + '->base64')
        except Exception:
            pass
        # hex
        try:
            hx = binascii.unhexlify(d)
            rec(hx, depth + 1, label + '->hex')
        except Exception:
            pass
        # base32
        try:
            b32 = base64.b32decode(d)
            rec(b32, depth + 1, label + '->base32')
        except Exception:
            pass
        # base58
        try:
            s = d.decode(errors='ignore')
            b58 = b58_decode(s)
            rec(b58, depth + 1, label + '->base58')
        except Exception:
            pass
    rec(data, 0, 'raw')
    return results

# ---------------- dCode lookup (optional) ----------------
async def lookup_hash_dcode(hashtext: str, use_cache=True, cache_ttl=3600) -> Optional[str]:
    if not USE_DCODE:
        return None
    if use_cache and hashtext in _provider_cache:
        ts, val = _provider_cache[hashtext]
        if time.time() - ts < cache_ttl:
            return val
    url = 'https://www.dcode.fr/api/'
    data = {'tool': 'hash-identifier', 'hash': hashtext}
    headers = {
        'User-Agent': 'Mozilla/5.0 n1nja-bot',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': 'https://www.dcode.fr/hash-identifier',
        'Origin': 'https://www.dcode.fr'
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, headers=headers, timeout=15) as resp:
                if resp.status != 200:
                    return None
                j = await resp.json()
                results = j.get('results') if isinstance(j, dict) else None
                if results and isinstance(results, list) and len(results) > 0:
                    lines = ['Hasil dCode (kemungkinan algoritma):']
                    for i, r in enumerate(results[:12]):
                        lines.append('%d. %s' % (i+1, r))
                    out = '\n'.join(lines)
                    _provider_cache[hashtext] = (time.time(), out)
                    return out
    except Exception:
        return None
    return None

# ---------------- Commands (Bahasa Indonesia) ----------------
@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Game(name=BOT_NAME + ' — CTF helper'))
    print(BOT_NAME + ' siap, logged in as ' + str(bot.user))

@bot.command(name='ctfhelp')
async def cmd_ctfhelp(ctx):
    help_text = (
        BOT_NAME + ' — Perintah utama (Bahasa Indonesia)\n'
        + '!solve <teks> — auto-decode rekursif (base64/hex/base32/base58) + deteksi flag\n'
        + '!decode <type> <teks> — contoh: !decode base64 SGVsbG8=\n'
        + '!encode <type> <teks> — base64/hex/url\n'
        + '!hashid <hash> — tebak hash & (opsional) lookup dCode\n'
        + '!xorbrute <data> — brute single-byte XOR\n'
        + '!caesar <shift> <teks> — Caesar cipher\n'
        + '!vigenere enc|dec <key> <teks>\n'
        + '!atbash <teks>\n'
        + '!rot13 <teks>\n'
        + '!strings — extract printable strings dari file terlampir\n'
        + '!stego — upload file lalu jalankan (EXIF, LSB, strings, hexdump)\n'
        + '!fileinfo — informasi file (hash, ukuran)\n'
        + '!hexdump <hex|base64> — tampilkan hexdump\n'
        + '!jwt <token> — decode JWT header/payload\n'
        + '!url <decode|encode> <url>\n'
        + '!ask <pertanyaan> — tanya AI (OPENAI_API_KEY dibutuhkan)\n'
        + '!prompt-set <text> — owner-only: set system prompt untuk AI\n'
        + '!history [limit] — lihat riwayat perintah mu\n'
    )
    await safe_send(ctx.channel, help_text)

@bot.command(name='decode')
async def cmd_decode(ctx, dtype: str, *, teks: str):
    d = dtype.lower()
    out = ''
    if d == 'base64':
        b = try_base64(teks)
        if b:
            try:
                out = b.decode('utf-8', errors='ignore')
            except Exception:
                out = b.hex()
        else:
            out = 'Gagal decode base64.'
    elif d == 'hex':
        b = try_hex(teks)
        if b:
            try:
                out = b.decode('utf-8', errors='ignore')
            except Exception:
                out = b.hex()
        else:
            out = 'Gagal decode hex.'
    elif d == 'base32':
        b = try_base32(teks)
        if b:
            try:
                out = b.decode('utf-8', errors='ignore')
            except Exception:
                out = b.hex()
        else:
            out = 'Gagal decode base32.'
    elif d == 'rot13':
        out = codecs.decode(teks, 'rot_13')
    elif d == 'atbash':
        out = atbash(teks)
    else:
        out = 'Tipe decode tidak dikenal.'
    save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'decode ' + d, teks, out[:4000])
    await safe_send(ctx.channel, out)

@bot.command(name='encode')
async def cmd_encode(ctx, dtype: str, *, teks: str):
    d = dtype.lower()
    out = ''
    if d == 'base64':
        out = base64.b64encode(teks.encode()).decode()
    elif d == 'hex':
        out = teks.encode().hex()
    elif d == 'url':
        from urllib.parse import quote
        out = quote(teks)
    else:
        out = 'Tipe encode tidak dikenal.'
    save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'encode ' + d, teks, out)
    await safe_send(ctx.channel, out)

@bot.command(name='hashid')
async def cmd_hashid(ctx, *, hashtext: str):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', hashtext)
    guesses = HASH_GUESSES.get(len(cleaned), [])
    lines = []
    if guesses:
        lines.append('Tebakan lokal: ' + ', '.join(guesses))
    else:
        lines.append('Tebakan lokal: tidak diketahui (berdasarkan panjang)')
    external = await lookup_hash_dcode(hashtext)
    if external:
        lines.append(external)
    else:
        lines.append('Lookup dCode gagal atau tidak aktif.')
    out = '\n'.join(lines)
    save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'hashid', hashtext, out)
    await safe_send(ctx.channel, out)

@bot.command(name='solve')
async def cmd_solve(ctx, *, teks: str):
    try:
        b = teks.encode()
        decs = auto_decode_recursive(b, max_depth=3)
        lines = []
        for label, data in decs:
            try:
                preview = data.decode('utf-8', errors='ignore')
            except Exception:
                preview = data.hex()
            flags = find_flags(preview)
            lines.append('[' + label + ']\n' + preview[:800])
            if flags:
                lines.append('  >> flag terdeteksi: ' + ', '.join(flags))
        out = '\n\n'.join(lines[:30])
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'solve', teks, out[:4000])
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('Error saat solve: ' + str(e))

@bot.command(name='xorbrute')
async def cmd_xorbrute(ctx, *, data: str):
    try:
        parsed = None
        if is_hex(data):
            parsed = try_hex(data)
        else:
            parsed = try_base64(data) or data.encode()
        res = single_xor_bruteforce(parsed, top=12)
        lines = []
        for sc, k, outb in res:
            try:
                pr = outb.decode('utf-8', errors='ignore')
            except Exception:
                pr = outb.hex()
            lines.append('k=0x%02x score=%d\n%s' % (k, sc, pr[:800]))
        outt = '\n\n'.join(lines)
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'xorbrute', data, outt[:4000])
        await safe_send(ctx.channel, outt)
    except Exception as e:
        await ctx.send('XOR error: ' + str(e))

@bot.command(name='caesar')
async def cmd_caesar(ctx, shift: int, *, teks: str):
    try:
        out = caesar_shift(teks, shift)
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'caesar', str(shift) + '|' + teks, out)
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('Caesar error: ' + str(e))

@bot.command(name='vigenere')
async def cmd_vigenere(ctx, mode: str, key: str, *, teks: str):
    try:
        if mode.lower() in ('enc', 'encrypt'):
            out = vigenere(teks, key, decrypt=False)
        else:
            out = vigenere(teks, key, decrypt=True)
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'vigenere', mode + '|' + key + '|' + teks, out[:4000])
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('Vigenere error: ' + str(e))

@bot.command(name='atbash')
async def cmd_atbash(ctx, *, teks: str):
    try:
        out = atbash(teks)
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'atbash', teks, out)
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('Atbash error: ' + str(e))

@bot.command(name='rot13')
async def cmd_rot13(ctx, *, teks: str):
    try:
        out = codecs.decode(teks, 'rot_13')
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'rot13', teks, out)
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('ROT13 error: ' + str(e))

@bot.command(name='strings')
async def cmd_strings(ctx):
    if not ctx.message.attachments:
        await ctx.send('Lampirkan file untuk diekstrak string-nya.')
        return
    attachment = ctx.message.attachments[0]
    data = await attachment.read()
    hasil = extract_strings(data)
    if not hasil:
        await ctx.send('Tidak ada string terbaca.')
        return
    teks = '\n'.join(hasil[:200])
    save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'strings', attachment.filename if hasattr(attachment, 'filename') else 'attachment', teks[:4000])
    await safe_send(ctx.channel, teks)

@bot.command(name='stego')
async def cmd_stego(ctx):
    try:
        target = None
        async for m in ctx.channel.history(limit=40):
            if m.author == ctx.author and m.attachments:
                target = m
                break
        if not target:
            await ctx.send('Unggah file lalu jalankan !stego di channel yang sama.')
            return
        att = target.attachments[0]
        bio = io.BytesIO()
        await att.save(bio)
        data = bio.getvalue()
        reply = []
        try:
            img = Image.open(io.BytesIO(data))
            exif = img._getexif()
            if exif:
                reply.append('EXIF terdeteksi:')
                for k, v in exif.items():
                    name = ExifTags.TAGS.get(k, k)
                    reply.append('%s: %s' % (str(name), str(v)[:200]))
            else:
                reply.append('Tidak ada EXIF.')
            lsb = lsb_extract(img, bits=1, max_bytes=8192)
            strings = extract_strings(lsb, min_len=4)
            if strings:
                reply.append('\nLSB-extracted (beberapa):')
                reply.extend(strings[:40])
            else:
                reply.append('\nTidak ada LSB output jelas.')
        except Exception:
            strings = extract_strings(data, min_len=4)
            if strings:
                reply.append('Strings (beberapa):')
                reply.extend(strings[:200])
            else:
                reply.append('Tidak ada printable strings.')
        reply.append('\nHexdump (dipotong):')
        reply.append(hexdump(data, length=16))
        out = '\n'.join(reply)
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'stego', att.filename if hasattr(att, 'filename') else 'attachment', out[:4000])
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('Stego error: ' + str(e))

@bot.command(name='fileinfo')
async def cmd_fileinfo(ctx):
    if not ctx.message.attachments:
        await ctx.send('Lampirkan file.')
        return
    f = ctx.message.attachments[0]
    data = await f.read()
    out_lines = []
    out_lines.append('Nama: ' + (f.filename if hasattr(f, 'filename') else 'attachment'))
    out_lines.append('Ukuran: %d bytes' % len(data))
    out_lines.append('MD5: ' + hashlib.md5(data).hexdigest())
    out_lines.append('SHA1: ' + hashlib.sha1(data).hexdigest())
    out_lines.append('SHA256: ' + hashlib.sha256(data).hexdigest())
    save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'fileinfo', f.filename if hasattr(f, 'filename') else 'attachment', '\n'.join(out_lines)[:4000])
    await safe_send(ctx.channel, '\n'.join(out_lines))

@bot.command(name='hexdump')
async def cmd_hexdump(ctx, *, teks: str):
    try:
        data = try_hex(teks) or try_base64(teks) or teks.encode()
        out = hexdump(data, length=16)
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'hexdump', teks, out)
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('Hexdump error: ' + str(e))

@bot.command(name='jwt')
async def cmd_jwt(ctx, *, token: str):
    try:
        parts = token.split('.')
        if len(parts) < 2:
            await ctx.send('Token JWT tidak valid.')
            return
        header = parts[0]
        payload = parts[1]
        try:
            hd = base64.urlsafe_b64decode(header + '===').decode(errors='ignore')
        except Exception:
            hd = '[gagal decode header]'
        try:
            pl = base64.urlsafe_b64decode(payload + '===').decode(errors='ignore')
        except Exception:
            pl = '[gagal decode payload]'
        out = 'Header:\n' + hd + '\n\nPayload:\n' + pl
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'jwt', token, out[:4000])
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('JWT error: ' + str(e))

@bot.command(name='url')
async def cmd_url(ctx, mode: str, *, teks: str):
    try:
        if mode.lower() == 'decode':
            from urllib.parse import unquote
            out = unquote(teks)
        elif mode.lower() == 'encode':
            from urllib.parse import quote
            out = quote(teks)
        else:
            out = 'Mode url tidak dikenal.'
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'url ' + mode, teks, out)
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('URL error: ' + str(e))

@bot.command(name='history')
async def cmd_history(ctx, limit: int = 10):
    try:
        cur = conn.execute('SELECT command,input,output,ts FROM history WHERE guild_id=? AND user_id=? ORDER BY id DESC LIMIT ?', (str(ctx.guild.id if ctx.guild else 'dm'), str(ctx.author.id), limit))
        rows = cur.fetchall()
        if not rows:
            await ctx.send('Tidak ada history.')
            return
        out_lines = []
        for r in rows:
            out_lines.append('[' + str(r[3]) + '] ' + str(r[0]) + ': ' + str(r[1])[:200])
        await safe_send(ctx.channel, '\n'.join(out_lines))
    except Exception as e:
        await ctx.send('History error: ' + str(e))

# AI (OpenAI) — optional
@bot.command(name='ask')
async def cmd_ask(ctx, *, prompt: str):
    if not OPENAI_KEY:
        await ctx.send('OPENAI_API_KEY tidak dikonfigurasi.')
        return
    try:
        import openai
        openai.api_key = OPENAI_KEY
    except Exception:
        await ctx.send('OpenAI SDK tidak terpasang. Tambahkan openai di requirements.txt')
        return
    try:
        await ctx.trigger_typing()
        cur = conn.execute('SELECT v FROM kv WHERE k=?', ('n1nja_system_prompt',))
        row = cur.fetchone()
        if row:
            sp = row[0]
        else:
            sp = 'Anda adalah n1nja, asisten CTF ringkas dan aman. Beri petunjuk decoding/analisis, bukan instruksi berbahaya.'
        resp = await asyncio.to_thread(openai.ChatCompletion.create, model='gpt-4o-mini', messages=[{'role':'system','content':sp}, {'role':'user','content':prompt}], max_tokens=800, temperature=0.25)
        out = resp.choices[0].message.content
        save_history(ctx.guild.id if ctx.guild else 'dm', ctx.author.id, 'ask', prompt, out[:4000])
        await safe_send(ctx.channel, out)
    except Exception as e:
        await ctx.send('AI Error: ' + str(e))

@bot.command(name='prompt-set')
async def cmd_prompt_set(ctx, *, prompt: str):
    if OWNER_ID != 0 and ctx.author.id != OWNER_ID:
        await ctx.send('Hanya owner yang dapat mengubah prompt.')
        return
    conn.execute('INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)', ('n1nja_system_prompt', prompt))
    conn.commit()
    await ctx.send('System prompt diperbarui.')

# ---------------- Keep-alive (Flask) ----------------
app = Flask('')
@app.route('/')
def home():
    return BOT_NAME + ' aktif'

def run_web():
    app.run(host='0.0.0.0', port=PORT)

def start_webthread():
    t = threading.Thread(target=run_web)
    t.daemon = True
    t.start()

# ---------------- Run ----------------
if __name__ == '__main__':
    if not DISCORD_TOKEN:
        print('DISCORD_TOKEN tidak ditemukan. Set di .env / Replit Secrets.')
        raise SystemExit(1)
    start_webthread()
    bot.run(DISCORD_TOKEN)
