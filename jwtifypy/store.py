from typing import Union, Optional, Dict
from jwtifypy.key import JWTKey


class JWTStore:
    _keys: Optional[Dict[str, JWTKey]] = None
    _leeway: Optional[Union[float, int]] = None
    _options: Optional[dict] = None

    @classmethod
    def init(
        cls,
        keys: dict,
        options: Optional[dict],
        leeway: Optional[Union[float, int]]
    ):
        """
        Инициализация хранилища JWT-ключей и параметров декодирования.

        Аргументы:
        - keys (dict[str, JWTKey]): Словарь ключей, где ключ — это имя, а значение — экземпляр JWTKey.
        - options (dict, optional): Дополнительные параметры декодирования JWT (например, валидация `aud`, `iss`, и т.д.).
        - leeway (float | int, optional): Допустимое отклонение в проверке временных claim'ов (nbf, iat, exp). По умолчанию 0.

        Исключения:
        - TypeError: если `keys` не словарь или содержит значения, не являющиеся JWTKey.
        """
        if not isinstance(keys, dict):
            raise TypeError("keys must be a dict of {name: JWTKey}")

        for name, key in keys.items():
            if not isinstance(key, JWTKey):
                raise TypeError(f"Key for '{name}' is not a JWTKey instance")

        cls._keys = keys
        cls._options = options
        cls._leeway = leeway

    @classmethod
    def set_key(cls, name: str, key: JWTKey):
        if cls._keys is None:
            raise RuntimeError(
                "JWTStore is not initialized. Call init() first.")
        cls._keys[name] = key

    @classmethod
    def get_key(cls, name: str) -> JWTKey:
        if cls._keys is None:
            raise RuntimeError(
                "JWTStore is not initialized. Call init() first.")
        if name not in cls._keys:
            raise KeyError(f"Key '{name}' not found in JWTStore")
        return cls._keys[name]

    @classmethod
    def get_keys(cls) -> dict:
        if cls._keys is None:
            raise RuntimeError(
                "JWTStore is not initialized. Call init() first.")
        return cls._keys

    @classmethod
    def get_options(cls) -> Optional[dict]:
        return cls._options

    @classmethod
    def get_leeway(cls) -> Optional[Union[float, int]]:
        return cls._leeway
