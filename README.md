# AtlasCloak

A lightweight, self-hosted **Identity & Access Management (IAM)** system with full **OpenID Connect** support — written entirely in Lua and powered by the [Telamon](https://github.com/COXKPER/Telamon) HTTP server. Think of it as a minimal, single-binary-friendly Keycloak: no framework, no boilerplate, just `.lua` files as routes.

```
GET /auth/realms/master/.well-known/openid-configuration  →  discovery document
GET /auth/realms/master/protocol/openid-connect/auth      →  authorization endpoint
POST /auth/realms/master/protocol/openid-connect/token    →  token endpoint
```

---

## Features

### OpenID Connect Provider

| Endpoint | Description |
|---|---|
| `/auth/realms/master/.well-known/openid-configuration` | OIDC discovery document |
| `/auth/realms/master/protocol/openid-connect/auth` | Authorization endpoint |
| `/auth/realms/master/protocol/openid-connect/token` | Token endpoint |
| `/auth/realms/master/protocol/openid-connect/userinfo` | UserInfo endpoint |
| `/auth/realms/master/protocol/openid-connect/certs` | JWKS (`jwks_uri`) |
| `/auth/realms/master/protocol/openid-connect/token/introspect` | Token introspection |
| `/auth/realms/master/protocol/openid-connect/revoke` | Token revocation |
| `/auth/realms/master/protocol/openid-connect/logout` | End-session / RP-initiated logout |
| `/auth/realms/master/protocol/openid-connect/consent` | Consent screen |

- **Grant types:** `authorization_code`, `client_credentials`, `password`, `refresh_token`
- **PKCE:** `plain` and `S256`
- **Response types:** `code`, `id_token`, `token`, and hybrid combinations
- **Signing algorithms:** HS256, RS256
- **Subject types:** public, pairwise
- **Scopes:** `openid`, `profile`, `email`, `address`, `phone`, `offline_access`

### Admin Console (`/admin`)

- **Users** — create, edit, enable/disable, reset credentials
- **Groups** — organize users into groups
- **Roles** — realm roles (`admin`, `user`, `editor`, `viewer` out of the box)
- **Clients** — register OIDC clients with per-client secrets and redirect URIs
- **Sessions** — view and revoke active sessions
- **Events** — audit log viewer with clear action
- **Realm settings** — inspect and export realm configuration
- **Whitelist** — IP access control for the admin surface

### Account Self-Service (`/account`)

- View and edit profile
- Change password (PBKDF2-HMAC-SHA256 via Telamon's Go crypto bridge)
- Review and revoke own sessions
- Logout everywhere

### Authentication (New in v2.0)

- **TOTP two-factor authentication** — enroll Google Authenticator/Aegis/FreeOTP from the account console; mandatory challenge at login; policy-forced enrollment available
- **Passkeys / WebAuthn (FIDO2)** — register passkeys and sign in passwordless; ES256 assertions verified server-side via the Telamon `crypto.p256_verify` bridge
- **Device Authorization Grant** (RFC 8628) — sign in TVs, CLIs, and IoT devices using short codes at `/device`

### Core

- **Realm Policies** — per-realm toggles: require PKCE on all code flows, require MFA for all users/admins, enable/disable passkeys & device flow, default consent, session idle timeout
- **Multi-realm** — create/delete realms in the admin console; fully isolated users/clients/roles/settings served instantly under `/auth/realms/<name>/…` (`master` keeps legacy unprefixed data — zero migration)
- **Security headers** — CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, COOP on every response including redirects
- **Scope-aware consent** — per-scope descriptions of what each application can access, remembered per granted scope set
- **Zero-dependency storage** — embedded LevelDB key-value store through Telamon's `ldb` bridge; no external database required
- **Lazy initialization** — bootstrap admin and default realm data are created on first request
- **Forced password rotation** — the bootstrap admin must change its password at first login
- **Login & registration flows** under `/auth/realms/master/login-actions/`
- **Vendored Font Awesome** icons — works fully offline

---

## Requirements

> **AtlasCloak requires [Telamon](https://github.com/COXKPER/Telamon)** — a lightweight Lua-scriptable HTTP server written in Go.

- [Telamon](https://github.com/COXKPER/Telamon) (which itself needs Go 1.22+ to build)
- Linux (systemd optional, for production)

---

## Quick Start

```bash
# 1. Get Telamon and build it
git clone https://github.com/COXKPER/Telamon.git telamon
cd telamon && make deps && make build
cd ..

# 2. Get AtlasCloak — it lives in the server's public directory
git clone https://github.com/COXKPER/AtlasCloak.git telamon/public

# 3. Point Telamon's config at the public directory
cat > telamon/config.toml <<'EOF'
[server]
port       = 8081
host       = "0.0.0.0"
public_dir = "public"
base_url   = ""          # set your public origin in production, e.g. "https://id.example.com"

[lua]
unsandboxed = true        # AtlasCloak needs io/os access for LevelDB
EOF

# 4. Run
cd telamon
./telamon --config config.toml
```

Visit `http://localhost:8081`.

### Default Credentials

| Username | Password | Notes |
|---|---|---|
| `admin` | `admin` | Forced password change on first login |

---

## Project Layout

```
public/
├── index.lua                          # Landing page + OIDC auto-forward
├── lib/
│   ├── utils.lua                      # Sessions, users, rendering, DB helpers
│   └── sha256.lua                     # Pure-Lua SHA-256 (JWKS/JWT support)
├── auth/
│   └── realms/master/
│       ├── .well-known/
│       │   └── openid-configuration.lua
│       ├── login-actions/             # authenticate, registration
│       └── protocol/openid-connect/   # auth, token, userinfo, certs,
│                                      # introspect, revoke, consent, logout
├── admin/                             # Admin console routes
│   ├── clients/  groups/  roles/  users/
│   ├── events/   sessions/  whitelist/
│   └── realm-settings/                # incl. export
├── account/                           # User self-service routes
├── images/                            # Default avatar/logo assets
└── vendor/fontawesome/                # Vendored icon fonts (offline-ready)
```

Routes map 1:1 to files — `GET /admin/users/new` executes `public/admin/users/new.lua`.

---

## Configuration

AtlasCloak is configured through Telamon's `config.toml`. The important bits:

```toml
[server]
port       = 8081          # Port to listen on
host       = "0.0.0.0"     # Bind address
public_dir = "public"      # Where this application lives
base_url   = ""            # Public origin used for issuer/discovery URLs.
                           # MUST be set in production behind a reverse proxy.

[lua]
unsandboxed = true         # Required — LevelDB and file access need it
```

> **Security note:** always set `server.base_url` in production so issuer and redirect URLs are never derived from the untrusted `Host` header.

Runtime data (LevelDB databases) is stored inside the working directory and should never be committed:

```
social.db/     # user/realm database
storage/       # session and event storage
```

---

## Integrating an Application

Any app that speaks standard OIDC can use AtlasCloak as its identity provider:

```http
GET /auth/realms/master/protocol/openid-connect/auth?client_id=myapp&redirect_uri=https://myapp/callback&response_type=code&scope=openid+profile&state=xyz&nonce=abc
```

Or hit the root URL with OIDC parameters — requests carrying `client_id` / `response_type` / `redirect_uri` are automatically forwarded to the authorization endpoint.

---

## License

Copyright © 2026 COXKPER

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This license choice ensures that any modification of AtlasCloak running as a network service must also be made available in source form to its users. See the [LICENSE](LICENSE) file for details.

Third-party assets:

- [Font Awesome](https://fontawesome.com/) — bundled under `vendor/fontawesome/` (icons: CC BY 4.0, fonts: SIL OFL 1.1, code: MIT)
- [Telamon](https://github.com/COXKPER/Telamon) is licensed separately under the MIT license
