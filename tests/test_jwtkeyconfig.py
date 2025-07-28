import os
import tempfile
from jwtifypy.config import JWTConfig
from jwtifypy.store import JWTStore


def test_jwtkeyconfig_load_file_and_env(monkeypatch):
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("file-secret-value")
        tf_path = tf.name

    try:
        monkeypatch.setenv("MY_SECRET_ENV", "env-secret-value")

        conf = {
            "algorithm": "HS256",
            "secret": f"file:{tf_path}"
        }

        JWTConfig.init(config={'keys': conf})
        key_obj = JWTStore.get_key('default')
        assert key_obj.secret == "file-secret-value"

        conf_env = {
            "algorithm": "HS256",
            "secret": "env:MY_SECRET_ENV"
        }
        JWTConfig.init(config={'keys': conf_env})
        key_obj_env = JWTStore.get_key('default')
        assert key_obj_env.secret == "env-secret-value"
    finally:
        os.unlink(tf_path)
