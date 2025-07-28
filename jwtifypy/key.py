from typing import Optional

from jwtifypy.utils import derive_public_key_from_private


class JWTKey:
    def __init__(self, algorithm: str,
                 secret: Optional[str] = None,
                 private_key: Optional[str] = None,
                 public_key: Optional[str] = None):
        """
        Автоопределение типа ключа:
        - Если передан только secret (строка), считаем symmetric
        - Если передан private_key или public_key (PEM), считаем asymmetric
        """
        self.algorithm = algorithm

        if secret is not None:
            self.key_type = "symmetric"
            self.secret = secret
            self.private_key = None
            self.public_key = None
        elif private_key is not None or public_key is not None:
            self.key_type = "asymmetric"
            self.secret = None
            self.private_key = private_key
            if public_key is None:
                self.public_key = derive_public_key_from_private(private_key)
            else:
                self.public_key = public_key
        else:
            raise ValueError("No key provided")

    def get_private_key(self) -> str:
        """
        Возвращает приватный ключ для подписи
        Для симметричных ключей — возвращает секрет
        Для асимметричных — приватный ключ (или None)
        """
        if self.key_type == "symmetric":
            return self.secret
        else:
            if self.private_key is None:
                raise ValueError("Private key is not set for asymmetric key")
            return self.private_key

    def get_public_key(self) -> str:
        """
        Возвращает публичный ключ для проверки подписи
        Для симметричных ключей — возвращает секрет (тот же)
        Для асимметричных — публичный ключ (или None)
        """
        if self.key_type == "symmetric":
            return self.secret
        else:
            if self.public_key is None:
                raise ValueError("Public key is not set for asymmetric key")
            return self.public_key
