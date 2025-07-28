import json
import os
from typing import Optional, Union
from jwtifypy.key import JWTKey
from jwtifypy.store import JWTStore

try:
    from dotenv import load_dotenv, find_dotenv
    dotenv_path = find_dotenv()
    if dotenv_path:
        load_dotenv(dotenv_path)
except ImportError:
    pass

KEY_INDICATORS = {'algorithm', 'alg', 'secret', 'private_key', 'public_key'}


class JWTConfig:
    @classmethod
    def init(cls, config: Optional[dict] = None,
             config_file: Optional[str] = None):
        """
        Универсальный инициализатор конфига

        Аргументы:
        - config: dict (один ключ или вложенный), JWTKey или список из dict/JWTKey
        - config_file: путь к json-файлу с конфигом
        """

        if config_file:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)

        if config is None:
            JWTStore.init({}, {}, 0)
            return

        JWTStore.init(
            cls._load_keys_from_config(config['keys']),
            config.get('options'),
            config.get('leeway')
        )

    @staticmethod
    def _read_value(val: str) -> str:
        """
        Если val начинается с "file:", пытаемся прочитать файл и вернуть содержимое.
        Если val начинается с "env:", читаем из os.environ.
        Иначе возвращаем val как есть.
        """
        if not isinstance(val, str):
            return val

        if val.startswith("file:"):
            path = val[5:]
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        elif val.startswith("env:"):
            env_var = val[4:]
            env_val = os.getenv(env_var)
            if env_val is None:
                raise ValueError(
                    f"Environment variable '{env_var}' is not set")
            return env_val.strip()
        else:
            return val

    @classmethod
    def _parse_dict(cls, data: dict) -> JWTKey:
        algorithm = data.get("algorithm") or data.get("alg") or "HS256"

        secret = data.get("secret")
        if secret is not None:
            secret = cls._read_value(secret)

        private_key = data.get("private_key")
        if private_key is not None:
            private_key = cls._read_value(private_key)

        public_key = data.get("public_key")
        if public_key is not None:
            public_key = cls._read_value(public_key)

        return JWTKey(algorithm=algorithm, secret=secret, private_key=private_key, public_key=public_key)

    @classmethod
    def _load_keys_from_config(cls, keys_config: Union[dict, JWTKey, list, None]) -> dict:
        loaded_keys = dict()

        if isinstance(keys_config, JWTKey):
            loaded_keys['default'] = keys_config
        elif isinstance(keys_config, dict):
            if not any(k in keys_config for k in KEY_INDICATORS):
                for key, val in keys_config.items():
                    loaded_keys[key] = cls._parse_dict(val)
            else:
                loaded_keys['default'] = cls._parse_dict(keys_config)
        else:
            raise TypeError(f"Unsupported config type: {type(keys_config)}")

        return loaded_keys
