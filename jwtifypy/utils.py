
import contextlib
from typing import Optional


try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    _cryptography_available = False
else:
    _cryptography_available = True


def derive_public_key_from_private(private_key_pem: str) -> Optional[str]:
    """
    Извлекает публичный ключ из приватного PEM ключа (RSA/EC).
    Возвращает публичный ключ в PEM формате (str).
    """
    if not _cryptography_available:
        return None
    with contextlib.suppress(Exception):
        private_key_obj = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        public_key_obj = private_key_obj.public_key()
        public_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem.decode()
    return None


class _MissingType:
    __slots__ = ()

    def __bool__(self):
        return False

    def __repr__(self):
        return "<MISSING>"

    def __str__(self):
        return "MISSING"


MISSING = _MissingType()
