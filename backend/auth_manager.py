"""
SystemAuditor Enterprise — Moduł Uwierzytelniania, Sesji JWT oraz MFA (TOTP RFC 6238)
=====================================================================================
Realizuje:
1. Bezpieczne haszowanie haseł algorytmem PBKDF2-HMAC-SHA256 (600 000 iteracji wg OWASP)
   z indywidualną solą kryptograficzną (128-bit) oraz porównaniem stałoczasowym.
2. Natywną implementację algorytmu TOTP (RFC 6238 / HOTP RFC 4226) kompatybilną
   z Google Authenticator, Microsoft Authenticator oraz Authy (sekret Base32, 6 cyfr, okno 30s).
3. Podpisywanie i weryfikację tokenów sesyjnych JWT (HS256) oraz obsługę dwuetapowego
   logowania (Etap 1: Hasło -> Pre-Auth MFA Challenge Token -> Etap 2: Kod 6-cyfrowy TOTP).
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from typing import Any, Dict, Optional, Tuple


JWT_SECRET = os.environ.get("AUDITOR_JWT_SECRET", "enterprise-jwt-signing-secret-key-2026-zt")
PBKDF2_ITERATIONS = 600_000


class PasswordHasher:
    """Haszowanie haseł zgodne z rekomendacjami OWASP (PBKDF2-HMAC-SHA256)."""

    @staticmethod
    def hash_password(password: str, salt_hex: Optional[str] = None) -> str:
        salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        try:
            algo, iter_str, salt_hex, hash_hex = stored_hash.split("$")
            if algo != "pbkdf2_sha256":
                return False
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iter_str),
            )
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False


class TOTPManager:
    """
    Natywna implementacja Time-Based One-Time Password (RFC 6238).
    Kompatybilna z aplikacjami mobilnymi Google/Microsoft Authenticator.
    """

    @staticmethod
    def generate_base32_secret(length_bytes: int = 20) -> str:
        raw = secrets.token_bytes(length_bytes)
        return base64.b32encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _hotp(secret_base32: str, counter: int, digits: int = 6) -> str:
        # Dopełnienie paddingu Base32 wielokrotnością 8 znaków
        clean = secret_base32.strip().replace(" ", "").upper()
        pad_len = (8 - (len(clean) % 8)) % 8
        key = base64.b32decode(clean + ("=" * pad_len), casefold=True)

        counter_bytes = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0F
        code_int = struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code_int % (10**digits)).zfill(digits)

    @classmethod
    def get_current_totp(cls, secret_base32: str, interval: int = 30) -> Tuple[str, int]:
        """Zwraca (aktualny_kod_6_cyfr, pozostale_sekundy_waznosci)."""
        now = int(time.time())
        counter = now // interval
        remaining = interval - (now % interval)
        return cls._hotp(secret_base32, counter), remaining

    @classmethod
    def verify_totp(cls, secret_base32: str, code: str, window: int = 1, interval: int = 30) -> bool:
        """
        Weryfikuje 6-cyfrowy kod TOTP z uwzględnieniem okna dryftu zegara (±1 interwał = ±30s).
        """
        clean_code = (code or "").strip().replace(" ", "")
        if not clean_code.isdigit() or len(clean_code) != 6:
            return False

        current_counter = int(time.time()) // interval
        for offset in range(-window, window + 1):
            expected = cls._hotp(secret_base32, current_counter + offset)
            if hmac.compare_digest(expected, clean_code):
                return True
        return False

    @staticmethod
    def build_provisioning_uri(username: str, secret_base32: str, issuer: str = "SystemAuditor") -> str:
        return f"otpauth://totp/{issuer}:{username}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


class JWTManager:
    """Obsługa tokenów JWT (JSON Web Token - HS256) bez zewnętrznych zależności."""

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _b64url_decode(data_str: str) -> bytes:
        pad = "=" * ((4 - (len(data_str) % 4)) % 4)
        return base64.urlsafe_b64decode(data_str + pad)

    @classmethod
    def create_token(cls, payload: Dict[str, Any], ttl_seconds: int = 28800) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        body = {
            **payload,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        segments = [
            cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            cls._b64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8")),
        ]
        signing_input = ".".join(segments).encode("ascii")
        sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        segments.append(cls._b64url_encode(sig))
        return ".".join(segments)

    @classmethod
    def verify_token(cls, token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
            actual_sig = cls._b64url_decode(parts[2])
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None
            payload = json.loads(cls._b64url_decode(parts[1]).decode("utf-8"))
            if int(time.time()) > int(payload.get("exp", 0)):
                return None
            return payload
        except Exception:
            return None
