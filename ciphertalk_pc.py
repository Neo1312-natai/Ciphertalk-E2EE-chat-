"""
CipherTalk PC — Aplikacja desktopowa E2EE (Windows / Linux / macOS)
====================================================================

System: lista kontaktów (zamiast pokoi). Każda rozmowa 1:1 = osobny
deterministyczny "pokój" wyprowadzony z shared-secret kontaktu.

GUI w stylu Cyberpunk 2077 — w 100% kompatybilne z ciphertalk_ios.py.

KRYPTOGRAFIA:
    AES-256-GCM (treść)
    HKDF-SHA256 (wyprowadzanie klucza i room_id z shared-secret)
    PBKDF2-HMAC-SHA256 600k iter (lokalny wallet kontaktów)
    Ed25519 sygnatury (autentykacja per-sesja) + TOFU

INTEROPERACYJNOŚĆ:
    iOS ↔ PC  ✓     iOS ↔ iOS  ✓     PC ↔ PC  ✓

INSTALACJA:
    pip install websockets cryptography pillow

URUCHOMIENIE:
    python ciphertalk_pc.py
"""

import os
import sys
import ssl
import json
import time
import base64
import asyncio
import threading
import mimetypes
import secrets
import queue
from io import BytesIO
from pathlib import Path

import tkinter as tk
from tkinter import scrolledtext, filedialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature, InvalidTag

import websockets
from websockets.exceptions import (
    ConnectionClosed, ConnectionClosedError, ConnectionClosedOK,
)


# =============================================================================
# KONFIGURACJA
# =============================================================================
SERVER_URL = os.environ.get(
    "CIPHERTALK_SERVER",
    "wss://ciphertalk-sygnalizacja.onrender.com",
)


def _default_data_dir() -> Path:
    candidates = [
        Path.home() / "ciphertalk_data",
        Path.cwd() / "ciphertalk_data",
    ]
    for c in candidates:
        try:
            c.mkdir(exist_ok=True, parents=True)
            return c
        except (OSError, PermissionError):
            continue
    return Path.cwd()


DATA_DIR      = _default_data_dir()
CONTACTS_FILE = DATA_DIR / "contacts.dat"
RECEIVED_DIR  = DATA_DIR / "received"
try:
    RECEIVED_DIR.mkdir(exist_ok=True, parents=True)
except (OSError, PermissionError):
    RECEIVED_DIR = DATA_DIR

# --- KRYPTOGRAFIA: stałe IDENTYCZNE z iOS (interop) ----------------------
PBKDF2_ITERATIONS  = 600_000
SHARED_KEY_SALT    = b"CipherTalk-v3-Contact-Salt"
ROOM_ID_SALT       = b"CipherTalk-v3-RoomID-Salt"
LOCAL_WALLET_SALT  = b"CipherTalk-v3-Wallet-Salt"

AES_KEY_BYTES      = 32
GCM_NONCE_BYTES    = 12

MAX_TEXT_BYTES     = 64 * 1024
MAX_NICK_LEN       = 32

MAX_FILE_RAW_BYTES = 1 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf"}
BLOCKED_EXTENSIONS = {".mp3", ".mp4"}
IMAGE_EXTENSIONS   = {".png", ".jpg", ".jpeg"}

RECONNECT_MIN  = 2
RECONNECT_MAX  = 30
PING_INTERVAL  = 20
PING_TIMEOUT   = 20

MAX_PENDING_PER_PEER = 8
MAX_PENDING_PEERS    = 32
MAX_SIGNALING_SIZE   = 12 * 1024 * 1024

INVITE_PREFIX        = "CT1"
INVITE_SECRET_BYTES  = 32


# =============================================================================
# PALETA CYBERPUNK 2077
# =============================================================================
CYBER = {
    "bg_dark":        "#0d0d12",
    "bg_mid":         "#14141f",
    "bg_light":       "#1a1a2e",
    "bg_hover":       "#22223a",
    "bg_active":      "#2a2a45",
    "border":         "#2c2c48",
    "border_accent":  "#3d3d66",
    "text_primary":   "#d4d4e8",
    "text_secondary": "#8888aa",
    "text_dim":       "#555577",
    "accent_cyan":    "#00d4ff",
    "accent_yellow":  "#fcee0a",
    "accent_magenta": "#ff2a6d",
    "accent_green":   "#05d9a6",
    "me_color":       "#00d4ff",
    "peer_color":     "#05d9a6",
    "system_color":   "#555577",
    "btn_bg":         "#1e1e35",
    "btn_hover":      "#2a2a4a",
    "btn_accent_bg":  "#00264d",
    "btn_accent_fg":  "#00d4ff",
    "scrollbar_bg":   "#1a1a2e",
    "scrollbar_fg":   "#2c2c48",
    "highlight_line": "#1e1e38",
    "fingerprint_bg": "#12121e",
    "file_tag":       "#fcee0a",
    "online":         "#05d9a6",
    "offline":        "#555577",
}


# =============================================================================
# KRYPTOGRAFIA — wspólna z wersja iOS
# =============================================================================
def derive_key_from_secret(shared_secret: bytes) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_BYTES,
              salt=SHARED_KEY_SALT, info=b"ciphertalk-room-key")
    return hk.derive(shared_secret)


def derive_room_id(shared_secret: bytes) -> str:
    hk = HKDF(algorithm=hashes.SHA256(), length=24,
              salt=ROOM_ID_SALT, info=b"ciphertalk-room-id")
    raw = hk.derive(shared_secret)
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def derive_local_wallet_key(master_password: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=AES_KEY_BYTES,
                     salt=LOCAL_WALLET_SALT, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[str, str]:
    aes = AESGCM(key)
    nonce = os.urandom(GCM_NONCE_BYTES)
    ct = aes.encrypt(nonce, plaintext, aad or None)
    return (base64.b64encode(nonce).decode("ascii"),
            base64.b64encode(ct).decode("ascii"))


def decrypt(key: bytes, nonce_b64: str, ct_b64: str, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return aes.decrypt(nonce, ct, aad or None)


def gen_identity() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return priv, pub_bytes


def sign_payload(priv: Ed25519PrivateKey, nonce_b64: str, ct_b64: str) -> str:
    msg = nonce_b64.encode("ascii") + b"|" + ct_b64.encode("ascii")
    return base64.b64encode(priv.sign(msg)).decode("ascii")


def verify_payload(pub_bytes: bytes, nonce_b64: str, ct_b64: str, sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        msg = nonce_b64.encode("ascii") + b"|" + ct_b64.encode("ascii")
        pub.verify(base64.b64decode(sig_b64), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def fingerprint_pub(pub_bytes: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(pub_bytes)
    digest = h.finalize()
    hex_s = digest.hex()[:16].upper()
    return "-".join(hex_s[i:i+4] for i in range(0, 16, 4))


# =============================================================================
# INVITE CODE
# =============================================================================
def make_invite_code(shared_secret: bytes, my_nick: str) -> str:
    if len(shared_secret) != INVITE_SECRET_BYTES:
        raise ValueError("zła długość secretu")
    secret_b32 = base64.b32encode(shared_secret).decode("ascii").rstrip("=")
    nick_b32 = base64.b32encode(my_nick.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{INVITE_PREFIX}-{secret_b32}-{nick_b32}"


def parse_invite_code(code: str) -> tuple[bytes, str]:
    code = code.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    parts = code.split("-")
    if len(parts) != 3 or parts[0] != INVITE_PREFIX:
        raise ValueError(f"Niepoprawny format kodu (oczekiwano {INVITE_PREFIX}-XXX-YYY).")

    def _decode_b32(s: str) -> bytes:
        s = s.upper()
        pad = (-len(s)) % 8
        return base64.b32decode(s + "=" * pad)

    try:
        secret = _decode_b32(parts[1])
        nick_bytes = _decode_b32(parts[2])
    except Exception as e:
        raise ValueError(f"Kod uszkodzony: {e}")
    if len(secret) != INVITE_SECRET_BYTES:
        raise ValueError("Zła długość secretu w kodzie.")
    try:
        nick = nick_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Nick w kodzie nie jest poprawnym UTF-8.")
    if not nick or len(nick) > MAX_NICK_LEN:
        raise ValueError(f"Nick z kodu pusty lub za długi (max {MAX_NICK_LEN}).")
    if any(ord(c) < 32 or ord(c) == 127 for c in nick):
        raise ValueError("Nick z kodu zawiera znaki kontrolne.")
    return secret, nick


# =============================================================================
# WALLET — lokalna książka kontaktów
# =============================================================================
class ContactBook:
    def __init__(self, master_password: str):
        self._wallet_key = derive_local_wallet_key(master_password)
        self.my_nick: str = ""
        self.contacts: dict = {}
        self._loaded = False
        self.my_priv_key_b64: str = ""  # === MODYFIKACJA: pole na trwały klucz ===

    def load_or_create(self) -> bool:
        if not CONTACTS_FILE.exists():
            return False
        try:
            blob = CONTACTS_FILE.read_bytes()
        except OSError as e:
            raise RuntimeError(f"Nie można otworzyć książki kontaktów: {e}")
        try:
            nonce = blob[:GCM_NONCE_BYTES]
            ct = blob[GCM_NONCE_BYTES:]
            aes = AESGCM(self._wallet_key)
            plaintext = aes.decrypt(nonce, ct, b"ciphertalk-wallet-v1")
            data = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, ValueError, json.JSONDecodeError):
            raise RuntimeError("Złe hasło master albo plik kontaktów uszkodzony.")
        if not isinstance(data, dict):
            raise RuntimeError("Plik kontaktów ma zły format.")
        self.my_nick = str(data.get("my_nick", ""))[:MAX_NICK_LEN]

        # === MODYFIKACJA: Wczytanie lub wygenerowanie trwałego klucza przy pierwszym uruchomieniu ===
        self.my_priv_key_b64 = data.get("my_priv_key_b64", "")
        if not self.my_priv_key_b64:
            
            priv, _ = gen_identity()
            self.my_priv_key_b64 = base64.b64encode(
                priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            ).decode("ascii")
        # =========================================================================================

        raw_contacts = data.get("contacts", {})
        if isinstance(raw_contacts, dict):
            for nick, info in raw_contacts.items():
                if not isinstance(nick, str) or not isinstance(info, dict):
                    continue
                if "secret_b64" not in info:
                    continue
                self.contacts[nick[:MAX_NICK_LEN]] = {
                    "secret_b64": str(info["secret_b64"]),
                    "added_ts": int(info.get("added_ts", 0)),
                    "note": str(info.get("note", ""))[:200],
                }
        self._loaded = True
        return True

    def save(self):
        # === MODYFIKACJA: Upewniamy się, że klucz prywatny istnieje przed zapisem ===
        if not getattr(self, "my_priv_key_b64", ""):
            priv, _ = gen_identity()
            self.my_priv_key_b64 = base64.b64encode(
                priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            ).decode("ascii")

        data = {
            "version": 1,
            "my_nick": self.my_nick,
            "my_priv_key_b64": self.my_priv_key_b64,  # <-- Szyfrujemy i zapisujemy klucz
            "contacts": self.contacts
        }
        # ============================================================================
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        aes = AESGCM(self._wallet_key)
        nonce = os.urandom(GCM_NONCE_BYTES)
        ct = aes.encrypt(nonce, plaintext, b"ciphertalk-wallet-v1")
        tmp = CONTACTS_FILE.with_suffix(".tmp")
        try:
            tmp.write_bytes(nonce + ct)
            os.replace(tmp, CONTACTS_FILE)
        except OSError:
            CONTACTS_FILE.write_bytes(nonce + ct)
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass

    def add_contact(self, nick: str, secret: bytes, note: str = "") -> bool:
        if not nick or len(nick) > MAX_NICK_LEN:
            raise ValueError(f"Nick musi mieć 1-{MAX_NICK_LEN} znaków.")
        if any(ord(c) < 32 or ord(c) == 127 for c in nick):
            raise ValueError("Nick zawiera znaki kontrolne.")
        if nick == self.my_nick:
            raise ValueError("Nie możesz dodać siebie jako kontakt.")
        if nick in self.contacts:
            raise ValueError(f"Kontakt '{nick}' już istnieje.")
        if len(secret) != INVITE_SECRET_BYTES:
            raise ValueError("Zła długość shared-secret.")
        self.contacts[nick] = {
            "secret_b64": base64.b64encode(secret).decode("ascii"),
            "added_ts": int(time.time()),
            "note": note[:200],
        }
        self.save()
        return True

    def remove_contact(self, nick: str) -> bool:
        if nick in self.contacts:
            del self.contacts[nick]
            self.save()
            return True
        return False

    def get_secret(self, nick: str) -> bytes | None:
        info = self.contacts.get(nick)
        if not info:
            return None
        try:
            return base64.b64decode(info["secret_b64"])
        except Exception:
            return None

    def list_contacts(self) -> list[str]:
        return sorted(self.contacts.keys())

    # === MODYFIKACJA: Nowa metoda rekonstruująca klucz ze struktury danych ===
    def get_my_identity(self) -> tuple[Ed25519PrivateKey, bytes]:
        raw_priv = base64.b64decode(self.my_priv_key_b64)
        priv = Ed25519PrivateKey.from_private_bytes(raw_priv)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv, pub_bytes
    # =========================================================================


# =============================================================================
# OBSŁUGA PLIKÓW DO WYSYLANIA
# =============================================================================
def prepare_file_for_send(path: Path) -> tuple[dict | None, str]:
    if not path.is_file():
        return None, f"Plik nie istnieje: {path}"
    ext = path.suffix.lower()
    if ext in BLOCKED_EXTENSIONS:
        return None, f"Format {ext} jest zablokowany."
    if ext not in ALLOWED_EXTENSIONS:
        return None, f"Dozwolone: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
    try:
        raw = path.read_bytes()
    except OSError as e:
        return None, f"Nie można odczytać pliku: {e}"
    if len(raw) == 0:
        return None, "Plik jest pusty."
    info = ""
    original_size = len(raw)
    if original_size > MAX_FILE_RAW_BYTES:
        if ext in IMAGE_EXTENSIONS:
            compressed = compress_image(raw, ext)
            if compressed is None:
                return None, "Kompresja obrazu nie powiodła się (brak Pillow?)."
            info = f"Skompresowano {original_size//1024} KB → {len(compressed)//1024} KB"
            raw = compressed
            if len(raw) > MAX_FILE_RAW_BYTES:
                return None, "Plik > 1 MB nawet po kompresji."
        else:
            return None, f"PDF > 1 MB ({original_size//1024} KB)."
    return {
        "filename": path.name,
        "size":     len(raw),
        "mime":     mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        "data_b64": base64.b64encode(raw).decode("ascii"),
        "_info":    info,
    }, ""


def compress_image(raw: bytes, ext: str) -> bytes | None:
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        im = Image.open(BytesIO(raw))
        im.thumbnail((1600, 1600))
        out = BytesIO()
        if ext in (".jpg", ".jpeg"):
            im.convert("RGB").save(out, format="JPEG", quality=80, optimize=True)
        else:
            im.save(out, format="PNG", optimize=True)
        return out.getvalue()
    except Exception:
        return None


def save_received_file(filename: str, data: bytes) -> Path:
    safe = "".join(c for c in filename if c.isalnum() or c in "._- ").strip()
    if safe in ("", ".", ".."):
        safe = f"file_{int(time.time())}"
    if len(safe) > 200:
        stem, dot, ext = safe.rpartition(".")
        if dot and len(ext) <= 10:
            safe = stem[:200 - len(ext) - 1] + "." + ext
        else:
            safe = safe[:200]
    out = RECEIVED_DIR / safe
    i = 1
    while out.exists():
        out = RECEIVED_DIR / f"{out.stem}_{i}{out.suffix}"
        i += 1
        if i > 9999:
            out = RECEIVED_DIR / f"file_{int(time.time())}{out.suffix}"
            break
    out.write_bytes(data)
    return out


def human_size(n: int) -> str:
    if n < 1024:        return f"{n} B"
    if n < 1024 * 1024: return f"{n/1024:.1f} KB"
    return f"{n/(1024*1024):.1f} MB"


# =============================================================================
# THEMED DIALOGS — wspólny motyw Cyberpunk
# =============================================================================
class ThemedMessageDialog:
    _ICONS = {
        "info":     ("◈", "accent_cyan"),
        "warning":  ("⚠", "accent_yellow"),
        "error":    ("✕", "accent_magenta"),
        "question": ("?", "accent_cyan"),
        "success":  ("✓", "accent_green"),
    }

    def __init__(self, parent, title, message, kind="info"):
        self.result = False
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.configure(bg=CYBER["bg_dark"])
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        icon_char, color_key = self._ICONS.get(kind, self._ICONS["info"])
        icon_color = CYBER[color_key]

        lines = message.count("\n") + 1
        msg_len = max((len(line) for line in message.split("\n")), default=20)
        w = min(max(400, msg_len * 8 + 80), 640)
        h = min(160 + lines * 20, 500)

        try:
            x = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
            self.dialog.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            self.dialog.geometry(f"{w}x{h}")

        tk.Frame(self.dialog, height=2, bg=icon_color).pack(fill=tk.X)
        content = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(16, 8))

        tk.Label(content, text=icon_char, font=("Consolas", 28, "bold"),
                 bg=CYBER["bg_dark"], fg=icon_color).pack(side=tk.LEFT, padx=(0, 16))
        tk.Label(content, text=message, font=("Consolas", 10),
                 bg=CYBER["bg_dark"], fg=CYBER["text_primary"],
                 wraplength=w - 100, justify="left", anchor="nw"
                 ).pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        btn_frame.pack(pady=(4, 14))

        if kind == "question":
            tk.Button(btn_frame, text="▸ TAK", width=12,
                      font=("Consolas", 10, "bold"),
                      bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
                      activebackground=CYBER["bg_active"],
                      activeforeground=CYBER["accent_cyan"],
                      relief=tk.FLAT, bd=0, cursor="hand2",
                      command=self._on_yes).pack(side=tk.LEFT, padx=6, ipady=3)
            tk.Button(btn_frame, text="✕ NIE", width=12,
                      font=("Consolas", 10),
                      bg=CYBER["btn_bg"], fg=CYBER["accent_magenta"],
                      activebackground=CYBER["btn_hover"],
                      activeforeground=CYBER["accent_magenta"],
                      relief=tk.FLAT, bd=0, cursor="hand2",
                      command=self._on_no).pack(side=tk.LEFT, padx=6, ipady=3)
        else:
            tk.Button(btn_frame, text="▸ OK", width=14,
                      font=("Consolas", 10, "bold"),
                      bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
                      activebackground=CYBER["bg_active"],
                      activeforeground=CYBER["accent_cyan"],
                      relief=tk.FLAT, bd=0, cursor="hand2",
                      command=self._on_ok).pack(padx=6, ipady=3)

        self.dialog.bind("<Return>",
                         lambda e: self._on_yes() if kind == "question" else self._on_ok())
        self.dialog.bind("<Escape>",
                         lambda e: self._on_no() if kind == "question" else self._on_ok())
        self.dialog.protocol("WM_DELETE_WINDOW",
                             self._on_no if kind == "question" else self._on_ok)
        self.dialog.focus_set()
        parent.wait_window(self.dialog)

    def _on_ok(self):  self.result = True;  self.dialog.destroy()
    def _on_yes(self): self.result = True;  self.dialog.destroy()
    def _on_no(self):  self.result = False; self.dialog.destroy()

    @staticmethod
    def info(parent, title, message):     return ThemedMessageDialog(parent, title, message, "info").result
    @staticmethod
    def warning(parent, title, message):  return ThemedMessageDialog(parent, title, message, "warning").result
    @staticmethod
    def error(parent, title, message):    return ThemedMessageDialog(parent, title, message, "error").result
    @staticmethod
    def askyesno(parent, title, message): return ThemedMessageDialog(parent, title, message, "question").result
    @staticmethod
    def success(parent, title, message):  return ThemedMessageDialog(parent, title, message, "success").result


# =============================================================================
# DIALOG LOGOWANIA / TWORZENIA KONTA
# =============================================================================
class LoginDialog:
    """Logowanie do walletu lub tworzenie nowego konta."""

    def __init__(self, parent, is_new_account: bool):
        self.result = None  # tuple (master_password, my_nick) lub None
        self.is_new_account = is_new_account
        self.dialog = tk.Toplevel(parent) if parent else tk.Tk()
        title = "CipherTalk — Tworzenie konta" if is_new_account else "CipherTalk — Logowanie"
        self.dialog.title(title)
        self.dialog.configure(bg=CYBER["bg_dark"])
        self.dialog.resizable(False, False)

        w, h = (520, 460) if is_new_account else (480, 320)
        sw = self.dialog.winfo_screenwidth()
        sh = self.dialog.winfo_screenheight()
        x, y = (sw - w) // 2, (sh - h) // 2
        self.dialog.geometry(f"{w}x{h}+{x}+{y}")

        if parent:
            self.dialog.transient(parent)
            self.dialog.grab_set()

        tk.Frame(self.dialog, height=3, bg=CYBER["accent_magenta"]).pack(fill=tk.X)

        banner = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        banner.pack(pady=(16, 4))
        tk.Label(banner, text="◈ C I P H E R T A L K ◈",
                 font=("Consolas", 16, "bold"),
                 bg=CYBER["bg_dark"], fg=CYBER["accent_magenta"]).pack()
        subtitle = "Tworzenie nowego konta" if is_new_account else "Zaloguj się do swoich kontaktów"
        tk.Label(banner, text=subtitle, font=("Consolas", 9),
                 bg=CYBER["bg_dark"], fg=CYBER["text_secondary"]).pack(pady=(2, 0))

        tk.Frame(self.dialog, height=1, bg=CYBER["border"]).pack(fill=tk.X, pady=(12, 8))

        if is_new_account:
            info = tk.Label(self.dialog,
                text="Hasło master chroni lokalną książkę kontaktów.\n"
                     "Nie da się go odzyskać — zapamiętaj je dobrze.",
                font=("Consolas", 9), justify="center",
                bg=CYBER["bg_dark"], fg=CYBER["text_secondary"])
            info.pack(pady=(0, 8), padx=20)

        form = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        form.pack(padx=24, pady=4, fill=tk.X)

        def _row(label_text, show=None):
            tk.Label(form, text=label_text, font=("Consolas", 10),
                     bg=CYBER["bg_dark"], fg=CYBER["text_primary"],
                     anchor="w").pack(fill=tk.X, pady=(8, 2))
            kwargs = dict(font=("Consolas", 11),
                          bg=CYBER["bg_light"], fg=CYBER["text_primary"],
                          insertbackground=CYBER["accent_cyan"],
                          highlightbackground=CYBER["border"],
                          highlightcolor=CYBER["accent_cyan"],
                          highlightthickness=1, bd=0, relief=tk.FLAT)
            if show:
                kwargs["show"] = show
            ent = tk.Entry(form, **kwargs)
            ent.pack(fill=tk.X, ipady=5)
            return ent

        if is_new_account:
            self.entry_nick  = _row("◈ Twój nick (widoczny w czacie):")
            self.entry_pwd1  = _row("◈ Nowe hasło master (min. 8 znaków):", show="●")
            self.entry_pwd2  = _row("◈ Powtórz hasło:", show="●")
            self.entry_nick.focus_set()
        else:
            self.entry_pwd1  = _row("◈ Hasło master:", show="●")
            self.entry_nick  = None
            self.entry_pwd2  = None
            self.entry_pwd1.focus_set()

        tk.Label(self.dialog, text=f"Plik kontaktów: {CONTACTS_FILE}",
                 font=("Consolas", 8),
                 bg=CYBER["bg_dark"], fg=CYBER["text_dim"],
                 anchor="w", wraplength=w - 40).pack(pady=(12, 0), padx=24, fill=tk.X)

        btn_frame = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        btn_frame.pack(pady=14)
        action_text = "▸ UTWÓRZ" if is_new_account else "▸ ZALOGUJ"
        tk.Button(btn_frame, text=action_text, width=14,
                  font=("Consolas", 11, "bold"),
                  bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
                  activebackground=CYBER["bg_active"],
                  activeforeground=CYBER["accent_cyan"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=self._on_ok).pack(side=tk.LEFT, padx=6, ipady=4)
        tk.Button(btn_frame, text="✕ ZAMKNIJ", width=14,
                  font=("Consolas", 10),
                  bg=CYBER["btn_bg"], fg=CYBER["accent_magenta"],
                  activebackground=CYBER["btn_hover"],
                  activeforeground=CYBER["accent_magenta"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=self._on_cancel).pack(side=tk.LEFT, padx=6, ipady=4)

        for w_ in (self.entry_nick, self.entry_pwd1, self.entry_pwd2):
            if w_ is not None:
                w_.bind("<Return>", lambda e: self._on_ok())
        self.dialog.bind("<Escape>", lambda e: self._on_cancel())
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _on_ok(self):
        if self.is_new_account:
            nick = self.entry_nick.get().strip()
            pwd1 = self.entry_pwd1.get()
            pwd2 = self.entry_pwd2.get()
            if not nick:
                ThemedMessageDialog.warning(self.dialog, "Brak nicka", "Nick jest wymagany.")
                return
            if len(nick) > MAX_NICK_LEN:
                ThemedMessageDialog.warning(self.dialog, "Błąd",
                    f"Nick za długi (max {MAX_NICK_LEN}).")
                return
            if any(ord(c) < 32 or ord(c) == 127 for c in nick):
                ThemedMessageDialog.warning(self.dialog, "Błąd",
                    "Nick zawiera znaki kontrolne.")
                return
            if len(pwd1) < 8:
                ThemedMessageDialog.warning(self.dialog, "Słabe hasło",
                    "Hasło musi mieć co najmniej 8 znaków.")
                return
            if pwd1 != pwd2:
                ThemedMessageDialog.warning(self.dialog, "Hasła różne",
                    "Wpisane hasła nie pasują do siebie.")
                return
            self.result = (pwd1, nick)
        else:
            pwd = self.entry_pwd1.get()
            if not pwd:
                ThemedMessageDialog.warning(self.dialog, "Brak hasła", "Hasło wymagane.")
                return
            self.result = (pwd, None)
        self.dialog.destroy()

    def _on_cancel(self):
        self.result = None
        self.dialog.destroy()


# =============================================================================
# DIALOG: WYŚWIETLENIE WYGENEROWANEGO KODU ZAPROSZENIA
# =============================================================================
class InviteCodeDialog:
    def __init__(self, parent, contact_nick: str, code: str):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Kod zaproszenia")
        self.dialog.configure(bg=CYBER["bg_dark"])
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        w, h = 640, 380
        try:
            x = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
            self.dialog.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            self.dialog.geometry(f"{w}x{h}")

        tk.Frame(self.dialog, height=2, bg=CYBER["accent_yellow"]).pack(fill=tk.X)

        tk.Label(self.dialog, text=f"✓ Dodano kontakt: {contact_nick}",
                 font=("Consolas", 12, "bold"),
                 bg=CYBER["bg_dark"], fg=CYBER["accent_green"]).pack(pady=(14, 4))
        tk.Label(self.dialog, text="Wyślij ten kod znajomemu (SMS, messenger, email).\n"
                                    "Kanał powinien być zaufany — kto ma kod, ten może czytać waszą rozmowę.",
                 font=("Consolas", 9), justify="center",
                 bg=CYBER["bg_dark"], fg=CYBER["text_secondary"]).pack(pady=(0, 10), padx=20)

        text_frame = tk.Frame(self.dialog, bg=CYBER["fingerprint_bg"],
            highlightbackground=CYBER["accent_yellow"], highlightthickness=1)
        text_frame.pack(fill=tk.X, padx=20, pady=4)
        text_widget = tk.Text(text_frame, height=4, font=("Consolas", 11),
            bg=CYBER["fingerprint_bg"], fg=CYBER["accent_cyan"],
            wrap=tk.CHAR, bd=0, relief=tk.FLAT,
            selectbackground=CYBER["bg_active"],
            selectforeground=CYBER["accent_yellow"],
            insertbackground=CYBER["accent_cyan"])
        text_widget.pack(fill=tk.X, padx=8, pady=8)
        text_widget.insert("1.0", code)
        self.code = code

        btn_frame = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        btn_frame.pack(pady=14)
        tk.Button(btn_frame, text="⌘ KOPIUJ KOD", width=18,
                  font=("Consolas", 10, "bold"),
                  bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
                  activebackground=CYBER["bg_active"],
                  activeforeground=CYBER["accent_cyan"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=self._copy).pack(side=tk.LEFT, padx=6, ipady=4)
        tk.Button(btn_frame, text="▸ ZAMKNIJ", width=14,
                  font=("Consolas", 10),
                  bg=CYBER["btn_bg"], fg=CYBER["text_primary"],
                  activebackground=CYBER["btn_hover"],
                  activeforeground=CYBER["accent_magenta"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=self.dialog.destroy).pack(side=tk.LEFT, padx=6, ipady=4)

        self.status_label = tk.Label(self.dialog, text="",
            font=("Consolas", 9),
            bg=CYBER["bg_dark"], fg=CYBER["accent_green"])
        self.status_label.pack(pady=(0, 6))

        self.dialog.bind("<Escape>", lambda e: self.dialog.destroy())
        parent.wait_window(self.dialog)

    def _copy(self):
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(self.code)
        self.status_label.config(text="✓ Skopiowano do schowka")
        self.dialog.after(2500,
            lambda: self.status_label.config(text="") if self.status_label.winfo_exists() else None)


# =============================================================================
# DIALOG: WKLEJANIE KODU ZAPROSZENIA
# =============================================================================
class PasteInviteDialog:
    def __init__(self, parent):
        self.result = None  # tuple (code_text, suggested_nick)
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Wklej kod zaproszenia")
        self.dialog.configure(bg=CYBER["bg_dark"])
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        w, h = 600, 380
        try:
            x = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
            self.dialog.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            self.dialog.geometry(f"{w}x{h}")

        tk.Frame(self.dialog, height=2, bg=CYBER["accent_cyan"]).pack(fill=tk.X)

        tk.Label(self.dialog, text="◈ Wklej kod zaproszenia (CT1-XXX-YYY)",
                 font=("Consolas", 11, "bold"),
                 bg=CYBER["bg_dark"], fg=CYBER["accent_cyan"]).pack(pady=(14, 8))

        text_frame = tk.Frame(self.dialog, bg=CYBER["bg_light"],
            highlightbackground=CYBER["border"], highlightthickness=1)
        text_frame.pack(fill=tk.X, padx=20, pady=4)
        self.text_widget = tk.Text(text_frame, height=5, font=("Consolas", 10),
            bg=CYBER["bg_light"], fg=CYBER["text_primary"],
            wrap=tk.CHAR, bd=0, relief=tk.FLAT,
            insertbackground=CYBER["accent_cyan"],
            selectbackground=CYBER["bg_active"],
            selectforeground=CYBER["accent_cyan"])
        self.text_widget.pack(fill=tk.X, padx=8, pady=8)
        self.text_widget.focus_set()

        tk.Label(self.dialog, text="◈ Pseudonim kontaktu (opcjonalne, puste = z kodu):",
                 font=("Consolas", 10),
                 bg=CYBER["bg_dark"], fg=CYBER["text_primary"],
                 anchor="w").pack(pady=(12, 2), padx=20, fill=tk.X)
        self.entry_nick = tk.Entry(self.dialog, font=("Consolas", 11),
            bg=CYBER["bg_light"], fg=CYBER["text_primary"],
            insertbackground=CYBER["accent_cyan"],
            highlightbackground=CYBER["border"],
            highlightcolor=CYBER["accent_cyan"],
            highlightthickness=1, bd=0, relief=tk.FLAT)
        self.entry_nick.pack(fill=tk.X, padx=20, ipady=5)

        btn_frame = tk.Frame(self.dialog, bg=CYBER["bg_dark"])
        btn_frame.pack(pady=14)
        tk.Button(btn_frame, text="▸ DODAJ KONTAKT", width=18,
                  font=("Consolas", 10, "bold"),
                  bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
                  activebackground=CYBER["bg_active"],
                  activeforeground=CYBER["accent_cyan"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=self._on_ok).pack(side=tk.LEFT, padx=6, ipady=4)
        tk.Button(btn_frame, text="✕ ANULUJ", width=14,
                  font=("Consolas", 10),
                  bg=CYBER["btn_bg"], fg=CYBER["accent_magenta"],
                  activebackground=CYBER["btn_hover"],
                  activeforeground=CYBER["accent_magenta"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=self._on_cancel).pack(side=tk.LEFT, padx=6, ipady=4)

        self.dialog.bind("<Escape>", lambda e: self._on_cancel())
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)
        parent.wait_window(self.dialog)

    def _on_ok(self):
        code = self.text_widget.get("1.0", tk.END).strip()
        nick = self.entry_nick.get().strip()
        if not code:
            ThemedMessageDialog.warning(self.dialog, "Brak kodu", "Wklej kod zaproszenia.")
            return
        self.result = (code, nick)
        self.dialog.destroy()

    def _on_cancel(self):
        self.result = None
        self.dialog.destroy()


# =============================================================================
# KLIENT SIECIOWY (asyncio + websockets) — w osobnym wątku na czat
# =============================================================================
class ChatClient:
    EV_STATUS    = "status"
    EV_SYSTEM    = "system"
    EV_TEXT      = "text"
    EV_FILE      = "file"
    EV_FP_SELF   = "fp_self"
    EV_FP_PEER   = "fp_peer"
    EV_PEER_ON   = "peer_online"
    EV_PEER_OFF  = "peer_offline"
    EV_ERROR     = "error"

    def __init__(self, my_nick: str, contact_nick: str, shared_secret: bytes,
                 ev_queue: queue.Queue):
        self.my_nick      = my_nick
        self.contact_nick = contact_nick
        self.room_id      = derive_room_id(shared_secret)
        self.key          = derive_key_from_secret(shared_secret)
        self.ws           = None
        self.peers        = []
        self.running      = True
        self.ev_queue     = ev_queue
        self.priv_key, self.pub_bytes = gen_identity()
        self.known_keys: dict[str, bytes] = {self.my_nick: self.pub_bytes}
        self.pending_msgs: dict[str, list] = {}
        self.send_queue: asyncio.Queue | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._thread_main,
                                        name=f"CT-Net-{self.contact_nick}",
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._loop and not self._loop.is_closed():
            try:
                self._loop.call_soon_threadsafe(asyncio.create_task,
                                                self._shutdown_async())
            except Exception:
                pass

    async def _shutdown_async(self):
        try:
            await self._send_raw({
                "action":  "leave",
                "room_id": self.room_id,
                "sender":  self.my_nick,
            })
        except Exception:
            pass
        if self.send_queue:
            await self.send_queue.put(None)
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass

    def submit_text(self, text: str) -> bool:
        text_bytes = text.encode("utf-8")
        if len(text_bytes) > MAX_TEXT_BYTES:
            self._emit(self.EV_ERROR,
                       f"Wiadomość za długa ({len(text_bytes)} B, limit {MAX_TEXT_BYTES} B).")
            return False
        if self._loop is None or self.send_queue is None:
            self._emit(self.EV_ERROR, "Brak połączenia.")
            return False
        self._loop.call_soon_threadsafe(self._enqueue_text, text_bytes)
        return True

    def submit_file(self, prepared: dict) -> bool:
        if self._loop is None or self.send_queue is None:
            self._emit(self.EV_ERROR, "Brak połączenia.")
            return False
        self._loop.call_soon_threadsafe(self._enqueue_file, prepared)
        return True

    def _enqueue_text(self, text_bytes: bytes):
        try:
            payload = self._build_signed_payload("text", text_bytes)
            self.send_queue.put_nowait({
                "action":  "message",
                "room_id": self.room_id,
                "sender":  self.my_nick,
                "payload": payload,
            })
        except Exception as e:
            self._emit(self.EV_ERROR, f"Błąd wysyłania: {e}")

    def _enqueue_file(self, prepared: dict):
        try:
            raw = base64.b64decode(prepared["data_b64"])
            payload = self._build_signed_payload("file", raw, extra_meta={
                "filename": prepared["filename"],
                "mime":     prepared["mime"],
                "size":     prepared["size"],
            })
            self.send_queue.put_nowait({
                "action":  "message",
                "room_id": self.room_id,
                "sender":  self.my_nick,
                "payload": payload,
            })
        except Exception as e:
            self._emit(self.EV_ERROR, f"Błąd wysyłania pliku: {e}")

    def _thread_main(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self.send_queue = asyncio.Queue()
        try:
            self._loop.run_until_complete(self._run())
        except Exception as e:
            self._emit(self.EV_ERROR, f"Wątek sieciowy: {e}")
        finally:
            try:
                pending = asyncio.all_tasks(self._loop)
                for t in pending:
                    t.cancel()
                if pending:
                    self._loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            self._loop.close()

    async def _run(self):
        backoff = RECONNECT_MIN
        while self.running:
            try:
                self._emit(self.EV_STATUS, "⚡ Łączenie z relay...", CYBER["accent_yellow"])
                self._emit(self.EV_SYSTEM, "⚡ Łączenie z serwerem...")
                async with websockets.connect(
                    SERVER_URL,
                    max_size=MAX_SIGNALING_SIZE,
                    ping_interval=PING_INTERVAL,
                    ping_timeout=PING_TIMEOUT,
                ) as ws:
                    self.ws = ws
                    backoff = RECONNECT_MIN
                    self._emit(self.EV_STATUS, "◈ Relay: połączony", CYBER["accent_green"])
                    self._emit(self.EV_SYSTEM, "◈ Połączono z relay.")
                    await self._send_raw({
                        "action":  "join",
                        "room_id": self.room_id,
                        "sender":  self.my_nick,
                    })
                    recv_task = asyncio.create_task(self._recv_loop())
                    send_task = asyncio.create_task(self._send_loop())
                    done, pending = await asyncio.wait(
                        {recv_task, send_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in pending:
                        t.cancel()
            except (ConnectionClosed, ConnectionClosedError, ConnectionClosedOK,
                    OSError, ssl.SSLError, asyncio.TimeoutError) as e:
                if not self.running:
                    break
                self._emit(self.EV_STATUS, "✕ Relay: rozłączony", CYBER["accent_magenta"])
                self._emit(self.EV_SYSTEM,
                           f"⚠ Połączenie zerwane ({type(e).__name__}). Ponawiam za {backoff}s...")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX)
            except Exception as e:
                if not self.running:
                    break
                self._emit(self.EV_STATUS, "✕ Błąd relay", CYBER["accent_magenta"])
                self._emit(self.EV_SYSTEM,
                           f"⚠ Nieoczekiwany błąd: {e}. Ponawiam za {backoff}s...")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX)
            finally:
                self.ws = None

        self._emit(self.EV_SYSTEM, "Sesja zakończona.")

    async def _recv_loop(self):
        async for raw in self.ws:
            if isinstance(raw, (str, bytes)) and len(raw) > MAX_SIGNALING_SIZE:
                continue
            try:
                msg = json.loads(raw)
                if not isinstance(msg, dict):
                    continue
            except (json.JSONDecodeError, ValueError):
                continue
            await self._handle_server_msg(msg)

    async def _handle_server_msg(self, msg: dict):
        action = msg.get("action")
        if action == "joined":
            peers = msg.get("peers", [])
            if isinstance(peers, list):
                self.peers = [p for p in peers
                              if isinstance(p, str) and len(p) <= MAX_NICK_LEN]
            sender = str(msg.get("sender", ""))[:MAX_NICK_LEN]
            if msg.get("self"):
                self._emit(self.EV_FP_SELF, fingerprint_pub(self.pub_bytes))
                others = [p for p in self.peers if p != self.my_nick]
                if others:
                    self._emit(self.EV_PEER_ON, others[0])
                    self._emit(self.EV_SYSTEM, f"◈ {others[0]} jest online.")
                else:
                    self._emit(self.EV_PEER_OFF, "")
                    self._emit(self.EV_SYSTEM,
                               f"⏳ Czekam aż {self.contact_nick} się połączy...")
                self._queue_announce()
            else:
                if sender != self.my_nick:
                    self._emit(self.EV_PEER_ON, sender)
                    self._emit(self.EV_SYSTEM, f"⚡ {sender} pojawił się online.")
                    self._queue_announce()

        elif action == "left":
            peers = msg.get("peers", [])
            if isinstance(peers, list):
                self.peers = [p for p in peers
                              if isinstance(p, str) and len(p) <= MAX_NICK_LEN]
            sender = str(msg.get("sender", ""))[:MAX_NICK_LEN]
            if sender != self.my_nick:
                self._emit(self.EV_PEER_OFF, sender)
                self._emit(self.EV_SYSTEM, f"⚡ {sender} wyszedł offline.")

        elif action == "message":
            await self._handle_encrypted(msg)

        elif action == "error":
            reason = str(msg.get("reason", "Nieznany błąd."))[:500]
            self._emit(self.EV_ERROR, f"Serwer: {reason}")

    async def _handle_encrypted(self, msg: dict):
        sender_raw = msg.get("sender", "?")
        sender = str(sender_raw)[:MAX_NICK_LEN] if sender_raw else "?"
        if sender == self.my_nick:
            return
        payload = msg.get("payload") or {}
        if not isinstance(payload, dict):
            self._emit(self.EV_ERROR, f"Odrzucona paczka od {sender} (zły payload).")
            return
        nonce_b64 = payload.get("nonce")
        ct_b64    = payload.get("ciphertext")
        sig_b64   = payload.get("sig")
        sender_pub_hex = payload.get("sender_pub")

        if not (isinstance(nonce_b64, str) and isinstance(ct_b64, str)
                and isinstance(sig_b64, str) and isinstance(sender_pub_hex, str)):
            self._emit(self.EV_ERROR, f"Odrzucona paczka od {sender} (brak sygnatury/pubkey).")
            return
        try:
            claimed_pub = bytes.fromhex(sender_pub_hex)
            if len(claimed_pub) != 32:
                raise ValueError
        except ValueError:
            self._emit(self.EV_ERROR, f"Odrzucona paczka od {sender} (zepsuty pubkey).")
            return
        if not verify_payload(claimed_pub, nonce_b64, ct_b64, sig_b64):
            self._emit(self.EV_ERROR, f"Odrzucona paczka od {sender} (zła sygnatura).")
            return
        try:
            plaintext = decrypt(self.key, nonce_b64, ct_b64,
                                aad=self._aad_for(sender, claimed_pub))
        except Exception:
            self._emit(self.EV_ERROR, f"Odrzucona paczka od {sender} (zły klucz / AAD).")
            return

        kind = payload.get("type", "text")
        if kind == "announce":
            try:
                claimed_nick, pub_hex = plaintext.decode("utf-8").split("|", 1)
            except Exception:
                self._emit(self.EV_ERROR, f"Zły format announce od {sender}.")
                return
            if claimed_nick != sender or pub_hex != sender_pub_hex:
                self._emit(self.EV_ERROR, f"Niespójny announce od {sender}.")
                return
            existing = self.known_keys.get(sender)
            if existing is None:
                self.known_keys[sender] = claimed_pub
                fp = fingerprint_pub(claimed_pub)
                self._emit(self.EV_SYSTEM, f"🔒 Tożsamość {sender}: {fp}")
                self._emit(self.EV_FP_PEER, sender, fp)
                await self._flush_pending(sender)
            elif existing != claimed_pub:
                self._emit(self.EV_ERROR,
                           f"⚠ {sender} ogłasza NOWY klucz "
                           f"({fingerprint_pub(claimed_pub)}) — "
                           f"poprzedni {fingerprint_pub(existing)}. "
                           f"Możliwy MITM. ODRZUCAM.")
                self.pending_msgs.pop(sender, None)
            return

        known = self.known_keys.get(sender)
        if known is None:
            buf = self.pending_msgs.setdefault(sender, [])
            if len(self.pending_msgs) > MAX_PENDING_PEERS:
                oldest = next(iter(self.pending_msgs))
                if oldest != sender:
                    self.pending_msgs.pop(oldest, None)
            if len(buf) < MAX_PENDING_PER_PEER:
                buf.append((kind, plaintext, payload))
            else:
                buf.pop(0)
                buf.append((kind, plaintext, payload))
            return
        if known != claimed_pub:
            self._emit(self.EV_ERROR, f"⚠ {sender} używa innego klucza. Odrzucam.")
            return
        self._deliver(sender, kind, plaintext, payload)

    async def _flush_pending(self, sender: str):
        buf = self.pending_msgs.pop(sender, None)
        if not buf:
            return
        known = self.known_keys.get(sender)
        if known is None:
            return
        for kind, plaintext, payload in buf:
            pub_hex = payload.get("sender_pub", "")
            try:
                payload_pub = bytes.fromhex(pub_hex)
            except ValueError:
                continue
            if payload_pub != known:
                continue
            self._deliver(sender, kind, plaintext, payload)

    def _deliver(self, sender: str, kind: str,
                 plaintext: bytes, payload: dict):
        if kind == "text":
            if len(plaintext) > MAX_TEXT_BYTES:
                self._emit(self.EV_ERROR, f"Odrzucono zbyt długą wiadomość od {sender}.")
                return
            text = plaintext.decode("utf-8", errors="replace")
            self._emit(self.EV_TEXT, sender, text)
        elif kind == "file":
            meta = payload.get("meta") or {}
            if not isinstance(meta, dict):
                self._emit(self.EV_ERROR, f"Plik od {sender}: zły meta.")
                return
            filename = str(meta.get("filename", "file.bin"))[:300]
            try:
                out = save_received_file(filename, plaintext)
                self._emit(self.EV_FILE, sender, out.name, len(plaintext), str(out))
            except OSError as e:
                self._emit(self.EV_ERROR, f"Nie udało się zapisać pliku od {sender}: {e}")
        else:
            self._emit(self.EV_ERROR, f"Nieznany typ payload: {kind}")

    async def _send_loop(self):
        while True:
            item = await self.send_queue.get()
            if item is None:
                return
            try:
                await self._send_raw(item)
            except (ConnectionClosed, OSError):
                await self.send_queue.put(item)
                raise

    async def _send_raw(self, obj: dict):
        if self.ws is None:
            raise ConnectionClosed(None, None)
        await self.ws.send(json.dumps(obj, ensure_ascii=False))

    def _aad_for(self, sender: str, pub_bytes: bytes) -> bytes:
        return (self.room_id + "|" + sender + "|" + pub_bytes.hex()).encode("utf-8")

    def _build_signed_payload(self, type_: str, plaintext: bytes,
                              extra_meta: dict | None = None) -> dict:
        aad = self._aad_for(self.my_nick, self.pub_bytes)
        nonce_b64, ct_b64 = encrypt(self.key, plaintext, aad=aad)
        sig = sign_payload(self.priv_key, nonce_b64, ct_b64)
        p = {
            "type":       type_,
            "nonce":      nonce_b64,
            "ciphertext": ct_b64,
            "sig":        sig,
            "sender_pub": self.pub_bytes.hex(),
        }
        if extra_meta:
            p["meta"] = extra_meta
        return p

    def _queue_announce(self):
        plaintext = f"{self.my_nick}|{self.pub_bytes.hex()}".encode("utf-8")
        payload = self._build_signed_payload("announce", plaintext)
        self.send_queue.put_nowait({
            "action":  "message",
            "room_id": self.room_id,
            "sender":  self.my_nick,
            "payload": payload,
        })

    def _emit(self, *args):
        try:
            self.ev_queue.put_nowait(args)
        except queue.Full:
            pass


# =============================================================================
# OKNO CZATU 1:1 z kontaktem (Toplevel — można otworzyć kilka równolegle)
# =============================================================================
class ChatWindow:
    def __init__(self, parent_root: tk.Tk, my_nick: str,
                 contact_nick: str, shared_secret: bytes,
                 on_close_callback=None):
        self.parent_root  = parent_root
        self.my_nick      = my_nick
        self.contact_nick = contact_nick
        self.on_close_callback = on_close_callback

        self.win = tk.Toplevel(parent_root)
        self.win.title(f"CipherTalk · {contact_nick}")
        self.win.minsize(640, 480)
        self.win.geometry("820x580")
        self.win.configure(bg=CYBER["bg_dark"])

        self.is_fullscreen = False
        self.peer_fingerprint: str | None = None
        self.peer_online = False

        self.ev_queue: queue.Queue = queue.Queue(maxsize=4096)
        self._build_ui()

        # Klient sieciowy
        self.client = ChatClient(my_nick, contact_nick, shared_secret, self.ev_queue)
        self.client.start()

        self.win.after(50, self._pump_events)
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        FONT_MAIN  = ("Consolas", 10)
        FONT_BOLD  = ("Consolas", 10, "bold")
        FONT_SMALL = ("Consolas", 9)
        FONT_TITLE = ("Consolas", 11, "bold")

        # Pasek górny
        top_bar = tk.Frame(self.win, pady=6, padx=10, bg=CYBER["bg_mid"],
                           highlightbackground=CYBER["border"], highlightthickness=1)
        top_bar.pack(fill=tk.X)

        tk.Label(top_bar, text="KONTAKT:", font=FONT_SMALL,
                 bg=CYBER["bg_mid"], fg=CYBER["text_secondary"]).pack(side=tk.LEFT)
        tk.Label(top_bar, text=self.contact_nick, font=FONT_BOLD,
                 bg=CYBER["bg_mid"], fg=CYBER["accent_magenta"]
                 ).pack(side=tk.LEFT, padx=(4, 12))

        self.online_indicator = tk.Label(top_bar, text="● offline",
            font=FONT_SMALL, bg=CYBER["bg_mid"], fg=CYBER["offline"])
        self.online_indicator.pack(side=tk.LEFT, padx=(0, 12))

        tk.Label(top_bar, text="JA:", font=FONT_SMALL,
                 bg=CYBER["bg_mid"], fg=CYBER["text_secondary"]).pack(side=tk.LEFT)
        tk.Label(top_bar, text=self.my_nick, font=FONT_BOLD,
                 bg=CYBER["bg_mid"], fg=CYBER["accent_cyan"]).pack(side=tk.LEFT, padx=4)

        self.fullscreen_btn = tk.Button(top_bar, text="⛶ FULLSCREEN", font=FONT_SMALL,
            bg=CYBER["btn_bg"], fg=CYBER["accent_yellow"],
            activebackground=CYBER["btn_hover"],
            activeforeground=CYBER["accent_yellow"],
            relief=tk.FLAT, bd=0, cursor="hand2",
            command=self._toggle_fullscreen)
        self.fullscreen_btn.pack(side=tk.LEFT, padx=8)

        self.status_label = tk.Label(top_bar, text="⏳ Inicjalizacja...",
            font=FONT_SMALL, fg=CYBER["text_dim"], bg=CYBER["bg_mid"])
        self.status_label.pack(side=tk.RIGHT)

        tk.Frame(self.win, height=1, bg=CYBER["border_accent"]).pack(fill=tk.X)

        # Fingerprint bar
        self.fingerprint_frame = tk.Frame(self.win, bg=CYBER["fingerprint_bg"],
            highlightbackground=CYBER["accent_yellow"], highlightthickness=1)
        self.fingerprint_label = tk.Label(self.fingerprint_frame,
            text="🔒 Inicjalizacja kluczy...",
            font=("Consolas", 8), fg=CYBER["accent_yellow"],
            bg=CYBER["fingerprint_bg"], anchor="w")
        self.fingerprint_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=3)
        tk.Button(self.fingerprint_frame, text="⌘", font=("Consolas", 9, "bold"),
            bg=CYBER["fingerprint_bg"], fg=CYBER["accent_yellow"],
            activebackground=CYBER["btn_hover"], relief=tk.FLAT, bd=0,
            cursor="hand2", command=self._show_fingerprints
            ).pack(side=tk.RIGHT, padx=4)
        self.fingerprint_frame.pack(fill=tk.X, pady=(0, 2))

        # Czat
        chat_frame = tk.Frame(self.win, bg=CYBER["bg_dark"])
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.chat_box = scrolledtext.ScrolledText(chat_frame, state="disabled",
            bg=CYBER["bg_light"], fg=CYBER["text_primary"], font=FONT_MAIN,
            wrap=tk.WORD, insertbackground=CYBER["accent_cyan"],
            highlightbackground=CYBER["border"], highlightthickness=1,
            bd=0, relief=tk.FLAT, selectbackground=CYBER["bg_active"],
            selectforeground=CYBER["accent_cyan"])
        self.chat_box.pack(fill=tk.BOTH, expand=True)
        try:
            self.chat_box.vbar.config(bg=CYBER["scrollbar_bg"],
                troughcolor=CYBER["bg_dark"],
                activebackground=CYBER["scrollbar_fg"],
                highlightbackground=CYBER["border"])
        except Exception:
            pass

        self.chat_box.tag_config("me",     foreground=CYBER["me_color"])
        self.chat_box.tag_config("peer",   foreground=CYBER["peer_color"])
        self.chat_box.tag_config("system", foreground=CYBER["system_color"],
                                 font=("Consolas", 9, "italic"))
        self.chat_box.tag_config("highlight", background=CYBER["highlight_line"])
        self.chat_box.tag_config("file", foreground=CYBER["file_tag"],
                                 font=("Consolas", 10, "bold"))
        self.chat_box.tag_config("error", foreground=CYBER["accent_magenta"],
                                 font=("Consolas", 9, "italic"))

        # Menu kontekstowe
        self.context_menu = tk.Menu(self.win, tearoff=0,
            bg=CYBER["bg_mid"], fg=CYBER["text_primary"],
            activebackground=CYBER["bg_active"],
            activeforeground=CYBER["accent_cyan"],
            font=("Consolas", 9), bd=1, relief=tk.FLAT)
        self.context_menu.add_command(label="⌘ Kopiuj wiadomość",
                                      command=self._copy_selected_message)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="✕ Anuluj")
        self.chat_box.bind("<Button-3>", self._on_chat_right_click)
        self.selected_line = None

        # Pasek wpisywania
        msg_bar = tk.Frame(chat_frame, bg=CYBER["bg_dark"])
        msg_bar.pack(fill=tk.X, pady=(4, 0))

        self.msg_entry = tk.Entry(msg_bar, font=FONT_MAIN,
            bg=CYBER["bg_light"], fg=CYBER["text_primary"],
            insertbackground=CYBER["accent_cyan"],
            highlightbackground=CYBER["border"],
            highlightthickness=1, bd=0, relief=tk.FLAT)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                            padx=(0, 4), ipady=4)
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        self.file_btn = tk.Button(msg_bar, text="📎",
            command=self._pick_and_send_file,
            font=("Consolas", 12),
            bg=CYBER["btn_bg"], fg=CYBER["accent_yellow"],
            activebackground=CYBER["btn_hover"],
            activeforeground=CYBER["accent_yellow"],
            relief=tk.FLAT, bd=0, cursor="hand2", padx=4)
        self.file_btn.pack(side=tk.RIGHT, ipady=0, padx=(0, 4))

        self.send_btn = tk.Button(msg_bar, text="WYŚLIJ ▸ E2EE",
            command=self._send_message,
            font=FONT_BOLD,
            bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
            activebackground=CYBER["bg_active"],
            activeforeground=CYBER["accent_cyan"],
            relief=tk.FLAT, bd=0, cursor="hand2", padx=10)
        self.send_btn.pack(side=tk.RIGHT, ipady=2)

        # Skróty
        self.win.bind("<F11>", lambda e: self._toggle_fullscreen())
        self.win.bind("<Escape>", lambda e: self._exit_fullscreen())

        self.log_system(f"◈ Czat z {self.contact_nick} (E2EE: AES-256-GCM)")
        self.msg_entry.focus_set()

    # ---- pomoc do wyświetlania wiadomości --------------------------------
    def _write_line(self, text: str, tag: str = "peer"):
        self.chat_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_box.insert(tk.END, f"[{ts}] ", "system")
        self.chat_box.insert(tk.END, text + "\n", tag)
        self.chat_box.config(state="disabled")
        self.chat_box.yview(tk.END)

    def log_chat_me(self, text: str):
        self._write_line(f"Ty: {text}", "me")

    def log_chat_peer(self, sender: str, text: str):
        self._write_line(f"{sender}: {text}", "peer")

    def log_system(self, text: str):
        self.chat_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_box.insert(tk.END, f"[{ts}] [{text}]\n", "system")
        self.chat_box.config(state="disabled")
        self.chat_box.yview(tk.END)

    def log_file(self, text: str):
        self.chat_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_box.insert(tk.END, f"[{ts}] ", "system")
        self.chat_box.insert(tk.END, f"📎 {text}\n", "file")
        self.chat_box.config(state="disabled")
        self.chat_box.yview(tk.END)

    def log_error(self, text: str):
        self.chat_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_box.insert(tk.END, f"[{ts}] [⚠ {text}]\n", "error")
        self.chat_box.config(state="disabled")
        self.chat_box.yview(tk.END)

    # ---- akcje ----------------------------------------------------------
    def _on_chat_right_click(self, event):
        index = self.chat_box.index(f"@{event.x},{event.y}")
        line_num = int(index.split(".")[0])
        line_start, line_end = f"{line_num}.0", f"{line_num}.end"
        line_text = self.chat_box.get(line_start, line_end).strip()
        if not line_text:
            return
        self.chat_box.tag_remove("highlight", "1.0", tk.END)
        self.chat_box.tag_add("highlight", line_start, line_end)
        self.selected_line = line_num
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _copy_selected_message(self):
        if self.selected_line is None:
            return
        line_text = self.chat_box.get(f"{self.selected_line}.0",
                                      f"{self.selected_line}.end").strip()
        if line_text:
            self.win.clipboard_clear()
            self.win.clipboard_append(line_text)
            self.log_system("⌘ Skopiowano do schowka.")

    def _set_status(self, text: str, color: str | None = None):
        self.status_label.config(text=text, fg=color or CYBER["text_dim"])

    def _toggle_fullscreen(self):
        self.is_fullscreen = not self.is_fullscreen
        try:
            self.win.attributes("-fullscreen", self.is_fullscreen)
        except tk.TclError:
            pass
        self.fullscreen_btn.config(
            text="⛶ OKNO" if self.is_fullscreen else "⛶ FULLSCREEN")

    def _exit_fullscreen(self):
        if self.is_fullscreen:
            self._toggle_fullscreen()

    def _send_message(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        if self.client.submit_text(text):
            self.log_chat_me(text)
            self.msg_entry.delete(0, tk.END)

    def _pick_and_send_file(self):
        path = filedialog.askopenfilename(
            title="Wybierz plik (E2EE)",
            parent=self.win,
            filetypes=[
                ("Obrazy / PDF", "*.png *.jpg *.jpeg *.pdf"),
                ("PNG", "*.png"),
                ("JPEG", "*.jpg *.jpeg"),
                ("PDF", "*.pdf"),
            ],
        )
        if not path:
            return
        prepared, err = prepare_file_for_send(Path(path).expanduser())
        if not prepared:
            ThemedMessageDialog.warning(self.win, "Plik odrzucony", err)
            return
        if prepared.get("_info"):
            self.log_system(prepared["_info"])
        if self.client.submit_file(prepared):
            self.log_file(f"Ty → wysyłasz: {prepared['filename']} "
                          f"({human_size(prepared['size'])})")

    def _show_fingerprints(self):
        self_fp = self.fingerprint_label.cget("text").replace("🔒 KOD: ", "").strip() or "(brak)"
        peer_fp = self.peer_fingerprint or "(kontakt jeszcze offline)"
        msg = (f"◈ Ty ({self.my_nick}):\n   {self_fp}\n\n"
               f"◈ {self.contact_nick}:\n   {peer_fp}\n\n"
               f"Porównaj z kontaktem out-of-band\n"
               f"(spotkanie / telefon) — to potwierdza brak MITM.")
        ThemedMessageDialog.info(self.win, "🔒 Fingerprinty", msg)

    # ---- pump eventów z wątku sieciowego --------------------------------
    def _pump_events(self):
        try:
            while True:
                ev = self.ev_queue.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        try:
            self.win.after(50, self._pump_events)
        except tk.TclError:
            pass

    def _handle_event(self, ev: tuple):
        if not ev:
            return
        kind = ev[0]
        try:
            if kind == ChatClient.EV_STATUS:
                _, text, color = ev
                self._set_status(text, color)
            elif kind == ChatClient.EV_SYSTEM:
                _, text = ev
                self.log_system(text)
            elif kind == ChatClient.EV_TEXT:
                _, sender, text = ev
                self.log_chat_peer(sender, text)
            elif kind == ChatClient.EV_FILE:
                _, sender, name, size, path = ev
                self.log_file(f"Odebrano od {sender}: {name} "
                              f"({human_size(size)}) → {path}")
            elif kind == ChatClient.EV_FP_SELF:
                _, fp = ev
                self.fingerprint_label.config(text=f"🔒 KOD: {fp}")
            elif kind == ChatClient.EV_FP_PEER:
                _, nick, fp = ev
                self.peer_fingerprint = fp
            elif kind == ChatClient.EV_PEER_ON:
                _, nick = ev
                self.peer_online = True
                self.online_indicator.config(text="● online",
                                             fg=CYBER["online"])
            elif kind == ChatClient.EV_PEER_OFF:
                _, nick = ev
                self.peer_online = False
                self.online_indicator.config(text="● offline",
                                             fg=CYBER["offline"])
            elif kind == ChatClient.EV_ERROR:
                _, text = ev
                self.log_error(text)
        except Exception as e:
            try:
                self.log_error(f"GUI handler: {e}")
            except Exception:
                pass

    def _on_close(self):
        try:
            self.client.stop()
        except Exception:
            pass
        try:
            self.win.destroy()
        except Exception:
            pass
        if self.on_close_callback:
            try:
                self.on_close_callback(self.contact_nick)
            except Exception:
                pass


# =============================================================================
# OKNO GŁÓWNE — (root window)
# =============================================================================
class MainWindow:
    def __init__(self, root: tk.Tk, book: ContactBook):
        self.root = root
        self.book = book
        self.open_chats: dict[str, ChatWindow] = {}  # nick -> ChatWindow

        self.root.title(f"CipherTalk · {book.my_nick}")
        self.root.minsize(540, 480)
        self.root.geometry("640x560")
        self.root.configure(bg=CYBER["bg_dark"])

        self._build_ui()
        self._refresh_contacts()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        FONT_MAIN  = ("Consolas", 10)
        FONT_BOLD  = ("Consolas", 10, "bold")
        FONT_SMALL = ("Consolas", 9)
        FONT_TITLE = ("Consolas", 12, "bold")

        # Pasek górny
        top_bar = tk.Frame(self.root, pady=8, padx=12, bg=CYBER["bg_mid"],
                           highlightbackground=CYBER["border"], highlightthickness=1)
        top_bar.pack(fill=tk.X)

        tk.Label(top_bar, text="◈ C I P H E R T A L K",
                 font=("Consolas", 13, "bold"),
                 bg=CYBER["bg_mid"], fg=CYBER["accent_magenta"]
                 ).pack(side=tk.LEFT)
        tk.Label(top_bar, text="·", font=("Consolas", 13),
                 bg=CYBER["bg_mid"], fg=CYBER["text_dim"]
                 ).pack(side=tk.LEFT, padx=8)
        tk.Label(top_bar, text=self.book.my_nick, font=FONT_BOLD,
                 bg=CYBER["bg_mid"], fg=CYBER["accent_cyan"]
                 ).pack(side=tk.LEFT)

        tk.Label(top_bar,
                 text=f"Serwer: {SERVER_URL.replace('wss://', '').replace('ws://', '')}",
                 font=("Consolas", 8),
                 bg=CYBER["bg_mid"], fg=CYBER["text_dim"]
                 ).pack(side=tk.RIGHT)

        tk.Frame(self.root, height=1, bg=CYBER["border_accent"]).pack(fill=tk.X)

        # Główna zawartość
        main = tk.Frame(self.root, bg=CYBER["bg_dark"])
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tytuł sekcji
        tk.Label(main, text="◈ TWOJE KONTAKTY",
                 font=FONT_TITLE,
                 bg=CYBER["bg_dark"], fg=CYBER["accent_cyan"],
                 anchor="w").pack(fill=tk.X, pady=(0, 6))

        # Lista kontaktów
        list_frame = tk.Frame(main, bg=CYBER["bg_light"],
            highlightbackground=CYBER["border"], highlightthickness=1)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.contacts_listbox = tk.Listbox(list_frame,
            bg=CYBER["bg_light"], fg=CYBER["text_primary"],
            selectbackground=CYBER["bg_active"],
            selectforeground=CYBER["accent_cyan"],
            activestyle="none", font=("Consolas", 11),
            exportselection=False, bd=0, relief=tk.FLAT,
            highlightthickness=0)
        self.contacts_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                                   padx=2, pady=2)
        self.contacts_listbox.bind("<Double-Button-1>", self._on_contact_double_click)
        self.contacts_listbox.bind("<Return>", self._on_contact_double_click)

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL,
            command=self.contacts_listbox.yview,
            bg=CYBER["scrollbar_bg"],
            troughcolor=CYBER["bg_dark"],
            activebackground=CYBER["scrollbar_fg"],
            highlightbackground=CYBER["border"], bd=0)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.contacts_listbox.config(yscrollcommand=scrollbar.set)

        # Podpowiedz (hint)
        self.hint_label = tk.Label(main, text="",
            font=("Consolas", 9, "italic"),
            bg=CYBER["bg_dark"], fg=CYBER["text_dim"],
            anchor="w")
        self.hint_label.pack(fill=tk.X, pady=(4, 0))

        # Przyciski akcji
        actions = tk.Frame(main, bg=CYBER["bg_dark"])
        actions.pack(fill=tk.X, pady=(8, 0))

        tk.Button(actions, text="▸ OTWÓRZ CZAT",
            command=self._open_chat_selected,
            font=FONT_BOLD,
            bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
            activebackground=CYBER["bg_active"],
            activeforeground=CYBER["accent_cyan"],
            relief=tk.FLAT, bd=0, cursor="hand2", padx=10
            ).pack(side=tk.LEFT, ipady=4)

        tk.Frame(actions, width=8, bg=CYBER["bg_dark"]).pack(side=tk.LEFT)

        tk.Button(actions, text="+ NOWY KONTAKT",
            command=self._action_add_invite,
            font=FONT_MAIN,
            bg=CYBER["btn_bg"], fg=CYBER["accent_green"],
            activebackground=CYBER["btn_hover"],
            activeforeground=CYBER["accent_green"],
            relief=tk.FLAT, bd=0, cursor="hand2", padx=10
            ).pack(side=tk.LEFT, ipady=4)

        tk.Button(actions, text="⌘ WKLEJ KOD",
            command=self._action_paste_invite,
            font=FONT_MAIN,
            bg=CYBER["btn_bg"], fg=CYBER["accent_yellow"],
            activebackground=CYBER["btn_hover"],
            activeforeground=CYBER["accent_yellow"],
            relief=tk.FLAT, bd=0, cursor="hand2", padx=10
            ).pack(side=tk.LEFT, padx=(8, 0), ipady=4)

        tk.Button(actions, text="✕ USUŃ",
            command=self._action_remove,
            font=FONT_MAIN,
            bg=CYBER["btn_bg"], fg=CYBER["accent_magenta"],
            activebackground=CYBER["btn_hover"],
            activeforeground=CYBER["accent_magenta"],
            relief=tk.FLAT, bd=0, cursor="hand2", padx=10
            ).pack(side=tk.RIGHT, ipady=4)

        # Stopka
        tk.Frame(self.root, height=1, bg=CYBER["border"]).pack(fill=tk.X)
        footer = tk.Frame(self.root, bg=CYBER["bg_mid"], pady=4)
        footer.pack(fill=tk.X)
        tk.Label(footer, text=f"Dane: {DATA_DIR}",
                 font=("Consolas", 8),
                 bg=CYBER["bg_mid"], fg=CYBER["text_dim"]
                 ).pack(side=tk.LEFT, padx=10)

    def _refresh_contacts(self):
        self.contacts_listbox.delete(0, tk.END)
        contacts = self.book.list_contacts()
        if not contacts:
            self.hint_label.config(
                text="(brak kontaktów — kliknij '+ NOWY KONTAKT' lub '⌘ WKLEJ KOD')")
        else:
            self.hint_label.config(
                text=f"Dwuklik kontaktu → otwiera czat 1:1 (E2EE)")
        for nick in contacts:
            chat_open = nick in self.open_chats
            prefix = "▸ " if chat_open else "  "
            self.contacts_listbox.insert(tk.END, f"{prefix}{nick}")

    def _on_contact_double_click(self, event=None):
        self._open_chat_selected()

    def _open_chat_selected(self):
        sel = self.contacts_listbox.curselection()
        if not sel:
            ThemedMessageDialog.info(self.root, "Wybierz kontakt",
                "Kliknij na kontakt, a potem na 'OTWÓRZ CZAT'.")
            return
        contacts = self.book.list_contacts()
        idx = sel[0]
        if idx >= len(contacts):
            return
        nick = contacts[idx]

        # Jeśli okno czatu już otwarte — przeniesienie na wierzch
        if nick in self.open_chats:
            existing = self.open_chats[nick]
            try:
                existing.win.deiconify()
                existing.win.lift()
                existing.win.focus_force()
                return
            except tk.TclError:
                # Okno zostało zniszczone — usuń wpis
                del self.open_chats[nick]

        secret = self.book.get_secret(nick)
        if secret is None:
            ThemedMessageDialog.error(self.root, "Błąd",
                f"Brak shared-secret dla '{nick}'.")
            return

        chat = ChatWindow(self.root, self.book.my_nick, nick, secret,
                          on_close_callback=self._on_chat_closed)
        self.open_chats[nick] = chat
        self._refresh_contacts()

    def _on_chat_closed(self, contact_nick: str):
        if contact_nick in self.open_chats:
            del self.open_chats[contact_nick]
        try:
            self._refresh_contacts()
        except tk.TclError:
            pass

    def _action_add_invite(self):
        nick = self._ask_string("Nowy kontakt",
            "Pseudonim kontaktu (jak go zapiszesz u siebie):")
        if not nick:
            return
        nick = nick.strip()
        try:
            if not nick:
                raise ValueError("Pseudonim wymagany.")
            if len(nick) > MAX_NICK_LEN:
                raise ValueError(f"Pseudonim za długi (max {MAX_NICK_LEN}).")
            if any(ord(c) < 32 or ord(c) == 127 for c in nick):
                raise ValueError("Pseudonim zawiera znaki kontrolne.")
            if nick == self.book.my_nick:
                raise ValueError("To Twój własny nick.")
            if nick in self.book.contacts:
                raise ValueError(f"Kontakt '{nick}' już istnieje.")
        except ValueError as e:
            ThemedMessageDialog.warning(self.root, "Błąd", str(e))
            return

        secret = secrets.token_bytes(INVITE_SECRET_BYTES)
        try:
            self.book.add_contact(nick, secret)
        except (ValueError, OSError) as e:
            ThemedMessageDialog.error(self.root, "Błąd", str(e))
            return

        code = make_invite_code(secret, self.book.my_nick)
        InviteCodeDialog(self.root, nick, code)
        self._refresh_contacts()

    def _action_paste_invite(self):
        dlg = PasteInviteDialog(self.root)
        if not dlg.result:
            return
        code, suggested_nick = dlg.result
        try:
            secret, sender_nick = parse_invite_code(code)
        except ValueError as e:
            ThemedMessageDialog.error(self.root, "Zły kod", str(e))
            return

        nick = suggested_nick.strip() if suggested_nick else sender_nick
        # Konflikty
        if nick == self.book.my_nick or nick in self.book.contacts:
            base_nick = nick
            i = 2
            while nick in self.book.contacts or nick == self.book.my_nick:
                nick = f"{base_nick}_{i}"
                i += 1
                if i > 999:
                    nick = f"{base_nick}_{int(time.time())}"
                    break

        try:
            self.book.add_contact(nick, secret, note=f"From {sender_nick}")
        except (ValueError, OSError) as e:
            ThemedMessageDialog.error(self.root, "Błąd", str(e))
            return

        ThemedMessageDialog.success(self.root, "Dodano kontakt",
            f"✓ Dodano kontakt '{nick}'.\n\nMożesz teraz otworzyć czat dwuklikiem.")
        self._refresh_contacts()

    def _action_remove(self):
        sel = self.contacts_listbox.curselection()
        if not sel:
            ThemedMessageDialog.info(self.root, "Wybierz kontakt",
                "Kliknij na kontakt, a potem na 'USUŃ'.")
            return
        contacts = self.book.list_contacts()
        idx = sel[0]
        if idx >= len(contacts):
            return
        nick = contacts[idx]

        if nick in self.open_chats:
            ThemedMessageDialog.warning(self.root, "Czat otwarty",
                f"Najpierw zamknij okno czatu z '{nick}'.")
            return

        if not ThemedMessageDialog.askyesno(self.root, "Usunąć kontakt?",
            f"Czy na pewno usunąć '{nick}'?\n\n"
            f"Po usunięciu nie będziesz w stanie odczytać starych\n"
            f"wiadomości z tym kontaktem ani się z nim połączyć\n"
            f"bez nowego kodu zaproszenia."):
            return

        self.book.remove_contact(nick)
        self._refresh_contacts()
        ThemedMessageDialog.success(self.root, "Usunięto",
            f"Kontakt '{nick}' został usunięty.")

    def _ask_string(self, title: str, prompt: str) -> str | None:
        """Mały themed input dialog (ad-hoc)."""
        result_holder = {"value": None}
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=CYBER["bg_dark"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        w, h = 460, 180
        try:
            x = self.root.winfo_rootx() + (self.root.winfo_width()  - w) // 2
            y = self.root.winfo_rooty() + (self.root.winfo_height() - h) // 2
            dialog.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            dialog.geometry(f"{w}x{h}")

        tk.Frame(dialog, height=2, bg=CYBER["accent_cyan"]).pack(fill=tk.X)
        tk.Label(dialog, text=f"◈ {prompt}", font=("Consolas", 10),
                 bg=CYBER["bg_dark"], fg=CYBER["text_primary"],
                 wraplength=w - 40, justify="left", anchor="w"
                 ).pack(pady=(16, 8), padx=20, fill=tk.X)
        entry = tk.Entry(dialog, font=("Consolas", 11),
            bg=CYBER["bg_light"], fg=CYBER["text_primary"],
            insertbackground=CYBER["accent_cyan"],
            highlightbackground=CYBER["border"],
            highlightcolor=CYBER["accent_cyan"],
            highlightthickness=1, bd=0, relief=tk.FLAT)
        entry.pack(padx=20, pady=4, ipady=6, fill=tk.X)
        entry.focus_set()

        def on_ok():
            result_holder["value"] = entry.get()
            dialog.destroy()

        def on_cancel():
            result_holder["value"] = None
            dialog.destroy()

        btn_frame = tk.Frame(dialog, bg=CYBER["bg_dark"])
        btn_frame.pack(pady=14)
        tk.Button(btn_frame, text="▸ OK", width=12,
                  font=("Consolas", 10, "bold"),
                  bg=CYBER["btn_accent_bg"], fg=CYBER["btn_accent_fg"],
                  activebackground=CYBER["bg_active"],
                  activeforeground=CYBER["accent_cyan"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=on_ok).pack(side=tk.LEFT, padx=6, ipady=3)
        tk.Button(btn_frame, text="✕ Anuluj", width=12, font=("Consolas", 10),
                  bg=CYBER["btn_bg"], fg=CYBER["text_primary"],
                  activebackground=CYBER["btn_hover"],
                  activeforeground=CYBER["accent_magenta"],
                  relief=tk.FLAT, bd=0, cursor="hand2",
                  command=on_cancel).pack(side=tk.LEFT, padx=6, ipady=3)

        entry.bind("<Return>", lambda e: on_ok())
        entry.bind("<Escape>", lambda e: on_cancel())
        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        self.root.wait_window(dialog)
        return result_holder["value"]

    def _on_close(self):
        # Zamknij wszystkie otwarte czaty
        for nick, chat in list(self.open_chats.items()):
            try:
                chat._on_close()
            except Exception:
                pass
        try:
            self.root.destroy()
        except Exception:
            pass


# =============================================================================
# MAIN
# =============================================================================

def main():
    if os.name == "nt":
        os.system("")  # ANSI on Windows

    root = tk.Tk()

    # --- FIX DLA LINUX / WAYLAND / WM ---
    # Jeśli okno "root" jest ukryte, całkowicie blokuj wywołanie transient().
    # Dzięki temu system nie ukryje automatycznie okna logowania, co chroni
    # uzytkownika przed utknięciem w nieskończonej pętli wait_window().
    oryginalne_transient = tk.Toplevel.transient

    def naprawione_transient(self, master=None):
        if master and str(master.state()) == 'withdrawn':
            return  # Zablokuj przypięcie, niech okno logowania wyrysuje się jako niezależne
        oryginalne_transient(self, master)

    tk.Toplevel.transient = naprawione_transient
    # ------------------------------------------------

    root.withdraw()  #Ukrycie okna glownego

    def start_app():
        is_new = not CONTACTS_FILE.exists()
        book = None

        if is_new:
            dlg = LoginDialog(root, is_new_account=True)
            root.wait_window(dlg.dialog)
            if dlg.result is None:
                root.destroy()
                return
            pwd, nick = dlg.result
            book = ContactBook(pwd)
            book.my_nick = nick
            try:
                book.save()
            except OSError as e:
                ThemedMessageDialog.error(root, "Błąd zapisu", f"Nie udało się utworzyć pliku kontaktów:\n{e}")
                root.destroy()
                return
        else:
            for attempt in range(3):
                dlg = LoginDialog(root, is_new_account=False)
                root.wait_window(dlg.dialog)
                if dlg.result is None:
                    root.destroy()
                    return
                pwd, _ = dlg.result
                book_try = ContactBook(pwd)
                try:
                    book_try.load_or_create()
                    book = book_try
                    break
                except RuntimeError as e:
                    remaining = 2 - attempt
                    if remaining > 0:
                        ThemedMessageDialog.warning(root, "Błąd logowania", f"{e}\n\nPozostało prób: {remaining}")
                    else:
                        ThemedMessageDialog.error(root, "Brak dostępu", f"{e}\n\nZbyt wiele błędnych prób. Wyjście.")
                        root.destroy()
                        return

            if book is None:
                root.destroy()
                return

        # Gdy logowanie przejdzie pomyślnie, buduje interfejs aplikacji
        app = MainWindow(root, book)

        # Odkrywamy okno, od teraz łatka na transient() znów będzie pozwalać
        # na normalne "przypinanie" wszystkich kolejnych dialogów!
        root.deiconify()
        root.app_ref = app

    # Włączamy start_app po zbudowaniu pętli Wayland/X11
    root.after(50, start_app)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if hasattr(root, 'app_ref'):
                root.app_ref._on_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()