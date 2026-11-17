# 🔐 Easy-JWT

> A simple, RFC-compliant Python library for issuing, verifying, and refreshing JWTs — without the boilerplate.

---

## ✨ Features

- 🪄 **One-liners** for issuing access & refresh tokens
- 🔄 **Token refresh** flow built-in
- 🏷️ **Custom claims** support
- 🛡️ **RFC 7515 / RFC 7519 compliant** — signature verified before decoding
- ⚙️ **Config via env vars** or plain Python objects
- 🔑 Supports **HS256, HS384, HS512**

---

## 📦 Installation

**Using `pip`:**
```bash
pip install git+https://github.com/arnabd64/Easy-JWT.git
```

**Using `uv`:**
```bash
uv add git+https://github.com/arnabd64/Easy-JWT.git
```

**From a `.whl` file** (download from [GitHub Releases](https://github.com/arnabd64/Easy-JWT/releases)):
```bash
pip install easy_jwt-0.1.0-py3-none-any.whl
```

> **Requires Python ≥ 3.12**

---

## ⚙️ Configuration

Easy-JWT needs six settings. You can provide them as **environment variables** (recommended) or construct a `JWTSettings` object directly in code.

### Option 1 — Environment Variables (recommended)

```bash
export JWT_SECRET="your-super-secret-key-at-least-32-bytes-long"
export JWT_ACCESS_TTL=900         # seconds (e.g. 15 minutes)
export JWT_REFRESH_TTL=604800     # seconds (e.g. 7 days)
export JWT_ISS="your-app-name"
export JWT_AUD="your-app-users"
export JWT_ALGORITHM="HS256"
```

When env vars are set, every function auto-loads config — **no settings object needed**.

### Option 2 — Explicit `JWTSettings`

```python
from easy_jwt import JWTSettings

settings = JWTSettings(
    secret="your-super-secret-key-at-least-32-bytes-long",
    access_ttl=900,
    refresh_ttl=604800,
    issuer="your-app-name",
    audience="your-app-users",
    algorithm="HS256",
)
```

Pass the `settings` object as a keyword argument to any function when you need explicit control (e.g. in tests or multi-tenant apps).

| Setting | Env Var | Type | Description |
|---|---|---|---|
| `secret` | `JWT_SECRET` | `str` | HMAC signing key (≥ 32 bytes for HS256, ≥ 48 for HS384, ≥ 64 for HS512) |
| `access_ttl` | `JWT_ACCESS_TTL` | `int` | Access token lifetime in **seconds** (min 30) |
| `refresh_ttl` | `JWT_REFRESH_TTL` | `int` | Refresh token lifetime in **seconds** (min 60, must be ≥ `access_ttl`) |
| `issuer` | `JWT_ISS` | `str` | Token issuer identifier |
| `audience` | `JWT_AUD` | `str` | Intended token audience |
| `algorithm` | `JWT_ALGORITHM` | `str` | `"HS256"`, `"HS384"`, or `"HS512"` |

---

## 🔑 Generating a Strong Secret

> [!WARNING]
> Easy-JWT enforces **strict** secret validation on every startup — a weak or short secret raises `InvalidSettings` and refuses to run. Your secret must satisfy **both** rules simultaneously:
>
> | Algorithm | Minimum length | Minimum entropy |
> |---|---|---|
> | HS256 | **32 bytes** (256 bits) | High randomness required |
> | HS384 | **48 bytes** (384 bits) | High randomness required |
> | HS512 | **64 bytes** (512 bits) | High randomness required |
>
> Human-readable passphrases and simple repeated strings **will be rejected** even if they are long enough — the library measures [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) and raises `InvalidSettings: secret is cryptographically weak` if the value isn't sufficiently random. **Always use a cryptographically secure random generator.**

Use the commands below to generate a secret that passes both checks. Each method produces a URL-safe, high-entropy string — copy the output directly into your env var or `.env` file.

---

### 🐧 Linux

**Method 1 — `openssl` base64 output**
```bash
# HS256 (32 bytes)
openssl rand -base64 32

# HS384 (48 bytes)
openssl rand -base64 48

# HS512 (64 bytes)
openssl rand -base64 64
```

---

### 🍎 macOS

**Method 1 — `openssl` (pre-installed on macOS)**
```bash
# HS256 (32 bytes)
openssl rand -base64 32

# HS384 (48 bytes)
openssl rand -base64 48

# HS512 (64 bytes)
openssl rand -base64 64
```

---

### 🪟 Windows

**Method 1 — PowerShell `RNGCryptoServiceProvider`**
```powershell
# HS256 (32 bytes)
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))

# HS384 (48 bytes)
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(48))

# HS512 (64 bytes)
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
```

---

### 🐍 Python (all platforms)

**Method 1 — `secrets` module** *(Python 3.6+, recommended)*
```bash
# HS256 (32 bytes)
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# HS384 (48 bytes)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# HS512 (64 bytes)
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

**Method 2 — `os.urandom` + `base64`** *(Python 2.7+ and all platforms)*
```bash
# HS256 (32 bytes)
python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"

# HS384 (48 bytes)
python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(48)).decode())"

# HS512 (64 bytes)
python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(64)).decode())"
```

> [!TIP]
> Export the secret directly into your shell in one step:
> ```bash
> export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
> ```

> [!CAUTION]
> **Never** use hardcoded, human-memorable, or dictionary-based strings as your secret (e.g. `"mysecretkey"`, `"password123"`, or `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`). These will either be rejected by the entropy check or will make your tokens trivially forgeable.

---

## 🚀 Quick Start

### 1️⃣ Issue Tokens

```python
from easy_jwt import issue_access_token, issue_refresh_token

user_id = "user-123"

# Returns (token_string, jti) — jti is the unique token ID
access_token, access_jti = issue_access_token(user_id)
refresh_token, refresh_jti = issue_refresh_token(user_id)

print(access_token)   # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### With custom claims

```python
access_token, jti = issue_access_token(
    sub=user_id,
    custom_claims={"role": "admin", "plan": "pro"},
)
```

---

### 2️⃣ Verify a Token

```python
from easy_jwt import verify_token

is_valid = verify_token(access_token, token_type="access")
# Returns True / False — never raises
```

---

### 3️⃣ Parse & Read a Token's Payload

```python
from easy_jwt import parse_token

payload = parse_token(access_token, token_type="access")

print(payload.sub)             # "user-123"
print(payload.jti)             # unique token ID (UUID)
print(payload.exp)             # expiry as a UNIX timestamp
print(payload.custom_claims)   # {"role": "admin", "plan": "pro"}
```

---

### 4️⃣ Refresh an Access Token

When an access token expires, swap the refresh token for a new access token:

```python
from easy_jwt import renew_access_token

new_access_token, new_jti = renew_access_token(refresh_token)
```

> 💡 The new access token inherits the subject and custom claims from the refresh token, and its expiry is capped to the refresh token's remaining lifetime.

---

### 5️⃣ Explicit Settings (optional)

```python
from easy_jwt import issue_access_token, verify_token, JWTSettings

settings = JWTSettings(
    secret="your-super-secret-key-at-least-32-bytes-long",
    access_ttl=900,
    refresh_ttl=604800,
    issuer="my-app",
    audience="my-users",
    algorithm="HS256",
)

token, jti = issue_access_token("user-456", settings=settings)
print(verify_token(token, token_type="access", settings=settings))  # True
```

---

## 🚨 Error Handling

All exceptions inherit from `JWTException`, so you can catch broadly or specifically:

```python
from easy_jwt import parse_token
from easy_jwt.exceptions import ExpiredToken, InvalidPayload, TokenException, JWTException

try:
    payload = parse_token(token, token_type="access")

except ExpiredToken:
    # Token existed but is past its expiry time
    print("Token has expired — ask the client to refresh.")

except InvalidPayload:
    # Token structure is valid but claims are wrong (bad issuer, audience, etc.)
    print("Token payload is invalid.")

except TokenException:
    # Covers malformed tokens, bad signatures, wrong token type, etc.
    print("Token is invalid.")

except JWTException:
    # Catch-all for any other Easy-JWT error (e.g. bad settings)
    print("A JWT error occurred.")
```

### Exception Hierarchy

```
JWTException
├── InvalidSettings      # Bad JWTSettings values
└── TokenException       # Any token-level error
    ├── InvalidPayload   # Claims validation failed
    └── ExpiredToken     # Token past its exp claim
```

---

## 📖 API Reference

### `issue_access_token(sub, custom_claims=None, *, settings=None) → (str, str)`

Issues a new **access token**.

| Parameter | Type | Description |
|---|---|---|
| `sub` | `str` | Subject — typically a user ID |
| `custom_claims` | `dict \| None` | Extra claims to embed in the token |
| `settings` | `JWTSettings \| None` | Override env-var config |

**Returns:** `(token: str, jti: str)` — the signed JWT and its unique ID.

---

### `issue_refresh_token(sub, custom_claims=None, *, settings=None) → (str, str)`

Issues a new **refresh token**. Same signature as `issue_access_token`.

---

### `verify_token(token, *, token_type, settings=None) → bool`

Validates a token. **Never raises** — returns `True` or `False`.

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The JWT string |
| `token_type` | `"access" \| "refresh"` | Expected token type |
| `settings` | `JWTSettings \| None` | Override env-var config |

---

### `parse_token(token, *, token_type, settings=None) → Payload`

Validates and decodes a token into a `Payload` object. **Raises** on any error.

**`Payload` attributes:**

| Attribute | Type | Description |
|---|---|---|
| `sub` | `str` | Subject (user ID) |
| `jti` | `str` | Unique token ID (UUID) |
| `iat` | `int` | Issued-at timestamp |
| `exp` | `int` | Expiry timestamp |
| `iss` | `str` | Issuer |
| `aud` | `str` | Audience |
| `token_type` | `str` | `"access"` or `"refresh"` |
| `custom_claims` | `dict` | Any extra claims |
| `nbf` | `int \| None` | Not-before timestamp (optional) |

---

### `renew_access_token(refresh_token, *, settings=None) → (str, str)`

Exchanges a valid **refresh token** for a new **access token**.

| Parameter | Type | Description |
|---|---|---|
| `refresh_token` | `str` | A valid, non-expired refresh token |
| `settings` | `JWTSettings \| None` | Override env-var config |

**Returns:** `(new_access_token: str, new_jti: str)`

**Raises:** `TokenException` if the refresh token is invalid or expired.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
