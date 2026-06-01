# SSO Authentication Gateway

A production-grade authentication gateway built with [FastAPI](https://fastapi.tiangolo.com/?utm_source=chatgpt.com) that provides centralized Single Sign-On (SSO) across multiple applications and subdomains.

The gateway acts as an Identity Provider (IdP), allowing external services and client applications to authenticate users through a unified authentication system. It supports secure JWT-based authentication, refresh token rotation, cross-subdomain session management, and role-based access control.

Typical client applications include:

* Django / DRF applications
* FastAPI services
* React / Next.js frontends
* Internal admin panels
* Microservices architectures

---

# Features

## Centralized SSO Authentication

Authenticate users once and share authenticated sessions across multiple services and subdomains.

Example:

* `admin.example.com`
* `staff.example.com`
* `dashboard.example.com`

---
![Project Architecture](login.png)

---
## Identity Provider (IdP)

The gateway functions as an authentication provider for external applications.

Client applications can:

* Redirect users to the SSO provider
* Validate JWT access tokens
* Refresh sessions securely
* Retrieve public signing keys via JWKS

---

## JWT Authentication (RS256)

Uses asymmetric cryptography with RS256 public/private key signing.

Benefits:

* Stateless access token validation
* Secure inter-service authentication
* Public key verification without exposing private keys

---

## Refresh Token Rotation

Implements secure refresh token rotation:

* Long-lived refresh tokens
* SHA-256 hashed storage
* Automatic rotation
* Revocation support
* Replay attack mitigation

---

## Secure Cookie-Based Authentication

Authentication tokens are stored in secure HttpOnly cookies.

Cookie configuration:

* `HttpOnly`
* `Secure`
* `SameSite=None`
* `Domain=.yourdomain.com`

Supports seamless authentication across subdomains.

---

## Role-Based Access Control

Users can be redirected automatically based on roles.

Example:

* `admin` → `admin.example.com`
* `staff` → `staff.example.com`

---

## Logout & Session Revocation

Secure logout flow:

* Refresh token revocation
* Session invalidation
* Cookie cleanup

---

## JWKS Endpoint

Exposes public signing keys through a JWKS endpoint for external service verification.

Useful for:

* Microservices
* API gateways
* Third-party integrations
* Distributed architectures

---

## CSRF Protection

Optional CSRF protection for state-changing requests.

---

## Rate Limiting

Protects authentication endpoints against:

* Brute-force attacks
* Credential stuffing
* Abuse attempts

---

## Production Security Practices

Includes:

* HTTPS enforcement
* HSTS headers
* Secure cookie policies
* Audit logging
* Secret-based key management
* Reverse proxy support via Nginx

---

# Architecture

```text
                    ┌────────────────────┐
                    │   Client App       │
                    │  (DRF / React)     │
                    └─────────┬──────────┘
                              │
                              │ Redirect/Login
                              ▼
                    ┌────────────────────┐
                    │  SSO Gateway       │
                    │   FastAPI IdP      │
                    └─────────┬──────────┘
                              │
          ┌───────────────────┴───────────────────┐
          │                                       │
          ▼                                       ▼
 ┌──────────────────┐                   ┌──────────────────┐
 │   PostgreSQL     │                   │      Redis       │
 │ Users & Tokens   │                   │ Revocation Cache │
 └──────────────────┘                   └──────────────────┘
```

---

# Technology Stack

| Component          | Technology                                                                   |
| ------------------ | ---------------------------------------------------------------------------- |
| API Framework      | [FastAPI](https://fastapi.tiangolo.com/?utm_source=chatgpt.com)              |
| Database           | [PostgreSQL](https://www.postgresql.org/?utm_source=chatgpt.com)             |
| Cache / Revocation | [Redis](https://redis.io/?utm_source=chatgpt.com)                            |
| ORM                | [SQLAlchemy](https://www.sqlalchemy.org/?utm_source=chatgpt.com)             |
| JWT Library        | [python-jose](https://github.com/mpdavis/python-jose?utm_source=chatgpt.com) |
| Reverse Proxy      | [Nginx](https://nginx.org/?utm_source=chatgpt.com)                           |
| Migrations         | [Alembic](https://alembic.sqlalchemy.org/?utm_source=chatgpt.com)            |

---

# Project Structure

```text
root project (idp)/
│
├── app/
│   ├── main.py
│   ├── models.py
│   ├── models.py
│   ├── core/
│   │   ├── authentication.py
│   │   ├── config.py
│   │   └── databae.py
│   │
│   ├── keys/
│   │   ├── private.pem
│   │   └── public.pem
│   │
│   ├── routers/
│   │   ├── auth.py
│   │   └── core.py
│   │
│   ├── tasks/
│   │   ├── celery.py
│   │   ├── redis.py
│   │   └── tass.py
│   │
│   ├── templates/
│   │   └── login.html
│   │
│   └── utils/
│       └── ......
│
├── migrations/
├── requirements.txt
├── .env.example
├── docker-compose.yml
└── README.md
```

---

# Environment Variables

```env
# JWT Configuration
JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/run/secrets/jwt_public.pem
JWT_ALGORITHM=RS256

# Token Expiration
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# Cookie Configuration
COOKIE_DOMAIN=.yourdomain.com
COOKIE_SECURE=true

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sso_db

# Redis
REDIS_URL=redis://localhost:6379/0
```

---

# Authentication Flow

## 1. Login

Client application redirects the user to the SSO provider.

```http
POST /api/auth/login
```

The gateway:

1. Validates credentials
2. Determines user roles
3. Issues access & refresh tokens
4. Stores tokens in secure cookies
5. Returns redirect target

---

## 2. Access Protected Resources

The browser automatically sends authentication cookies with requests.

Protected services:

* Validate JWT access tokens
* Verify token signatures using JWKS
* Extract user claims and roles

---

## 3. Token Refresh

```http
POST /api/auth/refresh
```

When the access token expires:

1. Refresh token is validated
2. Old refresh token is revoked
3. New token pair is generated
4. Cookies are updated

---

## 4. Logout

```http
POST /api/auth/logout
```

The logout process:

* Revokes refresh tokens
* Invalidates sessions
* Clears authentication cookies

---

# DRF Client Integration Example

A Django REST Framework application can use the gateway as its authentication provider.

## Example Flow

```text
User → DRF App → Redirect to SSO Gateway
                     ↓
               User Authenticated
                     ↓
        JWT Tokens Issued by FastAPI IdP
                     ↓
         DRF Validates Access Token
                     ↓
              User Logged In
```

---

## DRF JWT Validation

Example DRF middleware/authentication integration:

```python
from jose import jwt
from django.conf import settings

def verify_access_token(token: str):
    payload = jwt.decode(
        token,
        settings.SSO_PUBLIC_KEY,
        algorithms=["RS256"]
    )

    return payload
```

---

# Running Locally

## Clone Repository

```bash
git clone https://github.com/your-org/sso-auth-gateway.git
cd sso-auth-gateway
```

---

## Create Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

Windows:

```bash
.venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Run Database Migrations

```bash
alembic upgrade head
```

---

## Start Development Server

```bash
uvicorn app.main:app --reload
```

---

# Security Checklist

| Security Feature         | Status |
| ------------------------ | ------ |
| HTTPS Enforcement        | ✅      |
| HSTS Headers             | ✅      |
| HttpOnly Cookies         | ✅      |
| Secure Cookies           | ✅      |
| SameSite=None Cookies    | ✅      |
| Refresh Token Rotation   | ✅      |
| Refresh Token Revocation | ✅      |
| RS256 JWT Signing        | ✅      |
| Rate Limiting            | ✅      |
| CSRF Protection          | ✅      |
| Audit Logging            | ✅      |
| Secret-Based Key Storage | ✅      |

---

# Recommended Deployment

Production deployment recommendation:

* FastAPI application
* PostgreSQL database
* Redis revocation cache
* Nginx reverse proxy
* Dockerized infrastructure
* TLS termination at Nginx

---

# Use Cases

* Enterprise SSO systems
* Internal company platforms
* Multi-tenant SaaS applications
* Microservices authentication
* Cross-subdomain authentication
* Centralized authentication provider
* API gateway authentication

---

# License

MIT License
