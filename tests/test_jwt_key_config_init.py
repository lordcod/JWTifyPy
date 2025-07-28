import os
import tempfile
from jwtifypy import JWTConfig, JWTManager, JWTStore


def generate_rsa_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()


def test_jwt_key_config_init():
    # Генерируем ключи
    private_key, public_key = generate_rsa_keypair()

    # Создаём временные файлы
    with tempfile.NamedTemporaryFile("w+", delete=False) as priv_file, \
            tempfile.NamedTemporaryFile("w+", delete=False) as pub_file:

        priv_file.write(private_key)
        pub_file.write(public_key)
        priv_file.flush()
        pub_file.flush()

        config = {
            "leeway": 1.0,
            "options": {
                "verify_sub": False,
                "verify_aud": False,
                "verify_iss": False,
            },
            "keys": {
                "rsa_key": {
                    "algorithm": "RS256",
                    "private_key": f"file:{priv_file.name}",
                    "public_key": f"file:{pub_file.name}"
                },
                "symmetric_key": {
                    "algorithm": "HS256",
                    "secret": "my-secret-string"
                }
            }
        }

        # Инициализация
        JWTConfig.init(config=config)

        # Проверка
        rsa_key = JWTStore.get_key("rsa_key")
        symmetric_key = JWTStore.get_key("symmetric_key")

        assert rsa_key.algorithm == "RS256"
        assert rsa_key.private_key.strip().startswith("-----BEGIN PRIVATE KEY-----")
        assert rsa_key.public_key.strip().startswith("-----BEGIN PUBLIC KEY-----")

        assert symmetric_key.algorithm == "HS256"
        assert symmetric_key.secret == "my-secret-string"

        print()

        token = JWTManager('rsa_key').create_access_token(
            1, fresh=True, issuer="test")
        print(f"Токен (rsa): {token}")

        payload = JWTManager('rsa_key').decode_token(token)
        assert payload['sub'] == 1

        token = JWTManager('symmetric_key').create_access_token(2)
        print(f"Токен (symmetric): {token}")

    os.remove(priv_file.name)
    os.remove(pub_file.name)
