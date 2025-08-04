# 🔐 JWTifyPy

**JWTifyPy** is a lightweight and extensible Python library for generating and verifying JWT tokens, with support for various algorithms like `HS256`, `ES256`, `RS256`, and more.
Built on top of [PyJWT](https://pyjwt.readthedocs.io/), it offers an intuitive interface, easy configuration, and secure key storage — everything you need to work with JWTs.

---

## 📦 Installation

```bash
pip install jwtifypy
```

---

## ⚙️ Optional Dependencies

To support environment variables (`.env`) and advanced cryptographic algorithms (`ES256`), you may install optional packages like `python-dotenv` and `cryptography`.

Use extras to include these:

* With dotenv support:

```bash
pip install jwtifypy[env]
```

* With cryptography support:

```bash
pip install jwtifypy[crypto]
```

* Full feature set:

```bash
pip install jwtifypy[full]
```

---

## 🚀 Quick Start

### 🔧 Initialization

```python
from jwtifypy import JWTConfig

JWTConfig.init(config={
    "keys": {
        "algorithm": "HS256",
        "secret": "env:MY_SECRET_ENV"
    }
})
```

---

### 🔹 Basic Examples

```python
from jwtifypy import JWTManager

# 📥 Default token using the "default" key
token = JWTManager.create_access_token("user123")
print(token)
# 👉 eyJhbGciOiJIUzI1NiIsInR5cCI6...

# 🔑 Token using a named key
admin_token = JWTManager.using("admin").create_access_token("admin42")
print(admin_token)
# 👉 eyJhbGciOiJSUzI1NiIsInR5cCI6...
```

---

### 📛 Add an Issuer (`iss`)

```python
token_with_issuer = (
    JWTManager.using("admin")
    .with_issuer("my-service")
    .create_access_token("issuer-user")
)
print(token_with_issuer)
```

---

### 🎯 Add an Audience (`aud`)

```python
# 🎯 Single audience
token_with_aud = (
    JWTManager.using("admin")
    .with_audience("client-app")
    .create_access_token("aud-user")
)
print(token_with_aud)

# 📦 Multiple audiences (for decoding)
token_with_multiple_aud = (
    JWTManager.using("admin")
    .with_audience(
        audience_for_encoding="web",
        audience_for_decoding=["web", "mobile"]
    )
    .create_access_token("multi-aud-user")
)
print(token_with_multiple_aud)
```

---

### 🤖 Reuse Manager Conveniently

```python
# 🤖 Create a separate manager using the "admin" key
JWTAdmin = JWTManager.using("admin")

# 🎯 Audience
token_with_aud = (
    JWTAdmin
    .with_audience("client-app")
    .create_access_token("aud-user")
)
print(token_with_aud)

# 🔗 Issuer + Audience together
token_full = (
    JWTAdmin
    .with_issuer("auth-server")
    .with_audience("bot")
    .create_access_token("full-user")
)
print(token_full)
```

---

### 🔍 Token Verification with `iss` and `aud`

```python
payload = (
    JWTManager.using("admin")
    .with_issuer("auth-server")
    .with_audience("bot")
    .decode_token(token_full)
)

print(payload["sub"])  # 👉 full-user
print(payload["aud"])  # 👉 web
print(payload["iss"])  # 👉 auth-server
```

---

## ⚙️ Key Features

* ✅ Supports `HS256`, `ES256`, `RS256`, and more
* 🔐 Named key store (`default`, `admin`, `service-X`, etc.)
* 📤 Simple JWT creation/decoding interface
* 🛠 Extensible for advanced scenarios
* ⏱ Supports standard claims: `sub`, `exp`, `iat`, `aud`, `iss`, etc.

---

## 🧩 Custom Configuration

```python
from jwtifypy import JWTConfig

JWTConfig.init(config={
    "keys": {
        # 🔑 Symmetric key (HS256) using a shared secret
        "default": {
            "alg": "HS256",
            "secret": "secret"
        },

        # 🔐 Asymmetric key (RS256) using RSA keys from files
        "admin": {
            "algorithm": "RS256",
            "private_key": "file:/path/to/private.pem",
            "public_key": "file:/path/to/public.pem"
        },

        # 🧬 Asymmetric key (ES256) using ECDSA, private key from env
        # public_key will be auto-generated if `cryptography` is installed
        "service": {
            "alg": "ES256",
            "private_key": "env:PRIVATE_KEY"
        }
    },

    # ⏱ Leeway in seconds for time validation (exp, iat)
    "leeway": 1.0,

    # ⚙️ Additional validation options (as in PyJWT)
    "options": {
        "verify_sub": False,
        "strict_aud": False
    }
})
```

---

## 🗂️ Project Structure

```
jwtifypy/
├── __init__.py       # Public interface
├── manager.py        # JWTManager class
├── config.py         # Config and initialization
├── key.py            # Key parsing/handling (HS/RS/ES)
├── store.py          # JWTKeyStore
├── exceptions.py     # Custom exceptions
└── utils.py          # Utilities
```

---

## 🧪 Running Tests

```bash
pytest tests/
```

---

## 🛡️ Security Recommendations

* ❗ **Never hardcode secrets.** Use environment variables.
* 🔐 Prefer `RS256`/`ES256` for service-to-service authentication.
* ⏳ Set short token expiration (`exp`).
* 🔎 Use and validate claims (`iss`, `aud`, `sub`) when security matters.

---

## 📜 License

MIT © 2025
Created by \[LordCode Projects] / \[Dybfuo Projects]
