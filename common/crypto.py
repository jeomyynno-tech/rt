"""
Криптографические утилиты.

Хэширование паролей: bcrypt (cost=12) — защищает от rainbow table
и brute-force атак. SHA-256 без соли больше не используется.

Обратная совместимость: если хэш начинается с '$2b$' — это bcrypt,
иначе считается устаревшим SHA-256 и принимается один раз при миграции.
"""

import os
import subprocess
from pathlib import Path

try:
    import bcrypt as _bcrypt
    _HAVE_BCRYPT = True
except ImportError:
    import hashlib as _hashlib
    _HAVE_BCRYPT = False
    print("[crypto] WARNING: bcrypt не установлен, используется SHA-256 (небезопасно). "
          "Установите: pip install bcrypt")

CERTS_DIR = Path(__file__).parent.parent / "certs"


def hash_password(password: str) -> str:
    """
    Создать хэш пароля для хранения.
    Bcrypt автоматически добавляет соль и работает медленно намеренно.
    """
    if _HAVE_BCRYPT:
        return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt(rounds=12)).decode()
    # Fallback: SHA-256 (устаревший)
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(password: str, hashed: str) -> bool:
    """
    Проверить пароль против хэша.
    Поддерживает как bcrypt ($2b$...), так и старый SHA-256.
    """
    if _HAVE_BCRYPT and hashed.startswith("$2b$"):
        try:
            return _bcrypt.checkpw(password.encode("utf-8"), hashed.encode())
        except Exception:
            return False
    # Fallback: SHA-256
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest() == hashed


def get_or_create_secret_key() -> bytes:
    """
    Возвращает постоянный секретный ключ Flask-сессий.
    При первом запуске генерирует случайные 32 байта и сохраняет в certs/.session_key.
    Без этого при каждом перезапуске сервера все сессии сбрасываются.
    """
    CERTS_DIR.mkdir(exist_ok=True)
    key_file = CERTS_DIR / ".session_key"
    if key_file.exists():
        return key_file.read_bytes()
    key = os.urandom(32)
    key_file.write_bytes(key)
    # Права доступа: только владелец может читать
    try:
        key_file.chmod(0o600)
    except Exception:
        pass
    print(f"[crypto] Создан ключ сессий: {key_file}")
    return key


def generate_self_signed_cert(force: bool = False) -> tuple:
    CERTS_DIR.mkdir(exist_ok=True)
    cert_path = str(CERTS_DIR / "server.crt")
    key_path  = str(CERTS_DIR / "server.key")
    if not force and os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "365", "-nodes",
        "-subj", "/CN=RemoteTool/O=Dev/C=RU"
    ], check=True, capture_output=True)
    print(f"[crypto] Сертификат создан: {cert_path}")
    return cert_path, key_path
