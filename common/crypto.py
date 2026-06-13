"""
Криптографические утилиты.

Хэширование паролей: bcrypt (cost=12) — защищает от rainbow table
и brute-force атак. SHA-256 без соли больше не используется.

Обратная совместимость: если хэш начинается с '$2b$' — это bcrypt,
иначе считается устаревшим SHA-256 и принимается один раз при миграции.
"""

import os
import threading
import time
from collections import defaultdict
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

    Приоритет источников:
      1. SECRET_KEY из окружения (продакшен, в т.ч. Render — переживает деплой).
      2. certs/.session_key — локальный файл.
      3. Генерация новых случайных 32 байт (если файл недоступен — только в RAM).

    На эфемерных FS (Render free tier) файл /certs/.session_key исчезает
    при каждом деплое и инвалидирует сессии — поэтому переменная окружения
    SECRET_KEY ОБЯЗАТЕЛЬНА в продакшене.
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        # Поддерживаем hex и сырые байты
        try:
            return bytes.fromhex(env_key) if all(c in "0123456789abcdefABCDEF" for c in env_key) else env_key.encode()
        except Exception:
            return env_key.encode()

    try:
        CERTS_DIR.mkdir(exist_ok=True)
    except Exception:
        # FS только-для-чтения — генерируем эфемерный ключ
        return os.urandom(32)

    key_file = CERTS_DIR / ".session_key"
    if key_file.exists():
        return key_file.read_bytes()
    key = os.urandom(32)
    try:
        key_file.write_bytes(key)
        try:
            key_file.chmod(0o600)
        except Exception:
            pass
        print(f"[crypto] Создан ключ сессий: {key_file}")
    except Exception:
        # Не удалось записать — используем in-memory
        print("[crypto] WARNING: не удалось сохранить .session_key — ключ только в памяти")
    return key


def generate_self_signed_cert(force: bool = False) -> tuple:
    """
    Создаёт самоподписанный сертификат через python-библиотеку `cryptography`,
    не зависит от внешнего openssl-бинарника (его может не быть в Docker).
    """
    CERTS_DIR.mkdir(exist_ok=True)
    cert_path = str(CERTS_DIR / "server.crt")
    key_path  = str(CERTS_DIR / "server.key")
    if not force and os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
    except ImportError:
        raise RuntimeError(
            "Для генерации сертификата нужен пакет cryptography. "
            "Установите: pip install cryptography"
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "RemoteTool"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

    print(f"[crypto] Сертификат создан: {cert_path}")
    return cert_path, key_path


# ── Rate limiter (используется TCP-сервером агента для защиты от брутфорса) ── #
class RateLimiter:
    """
    Скользящее окно: не более max_attempts попыток за window_sec секунд на ключ (IP).
    Применяется как к Flask-логину, так и к TCP-аутентификации агента.
    """
    def __init__(self, max_attempts: int = 5, window_sec: int = 300):
        self.max_attempts = max_attempts
        self.window_sec   = window_sec
        self._attempts: dict = defaultdict(list)
        self._lock = threading.Lock()

    def is_blocked(self, key: str):
        with self._lock:
            now = time.time()
            self._attempts[key] = [t for t in self._attempts[key] if now - t < self.window_sec]
            if len(self._attempts[key]) >= self.max_attempts:
                oldest = self._attempts[key][0]
                return True, int(self.window_sec - (now - oldest)) + 1
            return False, 0

    def record_failure(self, key: str):
        with self._lock:
            self._attempts[key].append(time.time())

    def clear(self, key: str):
        with self._lock:
            self._attempts.pop(key, None)
