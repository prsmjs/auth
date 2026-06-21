<p align="center">
  <img src="logo.svg" width="80" height="80" alt="auth logo">
</p>

<h1 align="center">@prsm/auth</h1>

<p align="center">
  <a href="https://github.com/prsmjs/auth/actions/workflows/test.yml"><img src="https://github.com/prsmjs/auth/actions/workflows/test.yml/badge.svg" alt="test"></a>
  <a href="https://www.npmjs.com/package/@prsm/auth"><img src="https://img.shields.io/npm/v/@prsm/auth" alt="npm"></a>
</p>

PostgreSQL-backed authentication for Express. It owns its own auth tables and links to your user records through `user_id`, so it stays out of the way of however you model application users. One middleware attaches everything to `req.auth`: registration, login, sessions, remember-me, email confirmation, password reset, OAuth, role bitmasks, two-factor authentication, and audited impersonation.

It runs on a single shared PostgreSQL database behind any number of stateless app instances. Session storage is delegated to `express-session`, so you pick the store. Optional PostgreSQL `LISTEN/NOTIFY` propagates bans, role changes, and force-logouts across the fleet the instant they happen, with no Redis required.

## Install

```bash
npm install @prsm/auth express express-session pg
```

For remember-me cookies, also mount `cookie-parser`:

```bash
npm install cookie-parser
```

Requires Node 24+.

## Quick start

```js
import express from "express"
import session from "express-session"
import cookieParser from "cookie-parser"
import pg from "pg"
import { createAuthMiddleware, createAuthTables, AuthRole } from "@prsm/auth"

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })

const authConfig = {
  db: pool,
  tablePrefix: "auth_",
}

await createAuthTables(authConfig)

const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))
app.use(createAuthMiddleware(authConfig))

app.post("/register", async (req, res) => {
  const account = await req.auth.register(req.body.email, req.body.password)
  res.json({ id: account.id })
})

app.post("/login", async (req, res) => {
  await req.auth.login(req.body.email, req.body.password, req.body.remember)
  res.json({ ok: true })
})

app.get("/me", (req, res) => {
  if (!req.auth.isLoggedIn()) return res.status(401).json({ error: "not logged in" })
  res.json({ id: req.auth.getId(), email: req.auth.getEmail(), roles: req.auth.getRoleNames() })
})
```

Everything else hangs off `req.auth`. Mount `createAuthMiddleware` after `express-session` and `cookie-parser`, and call `createAuthTables(config)` once before the first request.

## Role-based access

Roles are integer bitmasks. Use the built-in `AuthRole` set or define your own:

```js
import { defineRoles } from "@prsm/auth"

export const Roles = defineRoles("owner", "editor", "viewer")

function requireRole(role) {
  return async (req, res, next) => {
    if (!req.auth.isLoggedIn()) return res.status(401).json({ error: "not logged in" })
    if (!(await req.auth.hasRole(role))) return res.status(403).json({ error: "forbidden" })
    next()
  }
}

app.get("/admin", requireRole(Roles.owner), (req, res) => res.json({ ok: true }))
```

Pass your role set as `config.roles` so `req.auth.getRoleNames()` and the devtools panel render the right names.

## Two-factor authentication

TOTP (authenticator apps), email OTP, SMS OTP, and backup codes are built in. Enable it in config, then drive enrollment and the second-factor login step through `req.auth.twoFactor`:

```js
const authConfig = { db: pool, twoFactor: { enabled: true, issuer: "MyApp" } }

// enrollment
const setup = await req.auth.twoFactor.setup.totp(true)
// render setup.qrCode, then confirm with a code from the app:
const backupCodes = await req.auth.twoFactor.complete.totp(req.body.code)

// login: req.auth.login throws SecondFactorRequiredError when 2FA is required
app.post("/login/2fa", async (req, res) => {
  await req.auth.twoFactor.verify.totp(req.body.code)
  await req.auth.completeTwoFactorLogin()
  res.json({ ok: true })
})
```

The TOTP implementation (RFC 6238) is built in, so there is no separate dependency to install or keep in sync.

## OAuth

GitHub, Google, and Azure are supported. Configure providers and the flow is route-driven through `req.auth.providers`:

```js
const authConfig = {
  db: pool,
  createUser: async (userData) => (await appDb.users.create(userData)).id,
  providers: {
    github: { clientId, clientSecret, redirectUri: "https://app.example.com/auth/github/callback" },
  },
}

app.get("/auth/github", (req, res) => res.redirect(req.auth.providers.github.getAuthUrl()))
app.get("/auth/github/callback", async (req, res) => {
  await req.auth.providers.github.handleCallback(req)
  res.redirect("/dashboard")
})
```

## Impersonation

Audited impersonation preserves the original actor so support sessions stay traceable:

```js
const authConfig = {
  db: pool,
  impersonation: {
    enabled: true,
    maxTtl: "1h",
    canImpersonate: (actor, target) => (actor.rolemask & AuthRole.Admin) !== 0,
  },
}

await req.auth.startImpersonation({ email: "customer@example.com" }, { reason: "ticket #123", ttl: "30m" })
// activity rows record actor_account_id throughout
await req.auth.stopImpersonation()
```

## Cross-instance invalidation

By default a session re-reads account state from the database on an interval (`resyncInterval`, default `30s`), so a ban or role change can take up to that long to reach instances that already cached the session. Turn on `LISTEN/NOTIFY` and those changes propagate immediately:

```js
const authConfig = {
  db: pool,
  invalidation: { listen: true },
}
```

When enabled, security-relevant writes (force-logout, status, role, password) emit a notification and every instance drops the affected session on its next request. It uses the PostgreSQL connection you already have. If the listener connection is unavailable (for example, a pooler in transaction mode), it falls back to interval-based resync automatically.

## Observability and rate limiting

Both are optional and duck-typed, so the package never depends on them:

```js
import { createTracer } from "@prsm/trace"
import { tokenBucket } from "@prsm/limit"

const authConfig = {
  db: pool,
  tracer: createTracer({ service: "api" }),       // login is wrapped in a span
  limiter: tokenBucket({ redis, capacity: 5, refillRate: 5, refillInterval: "1m" }), // throttles login
}
```

When a limiter is configured, login attempts are throttled per email and a `RateLimitedError` is thrown once the limit is hit. Without these options, behavior is unchanged.

## Requestless context and admin tooling

`createAuthContext(config)` gives you the same user-management operations without a request, for scripts, workers, and cron jobs. The same object is the binding surface for the [`@prsm/devtools`](https://github.com/prsmjs/devtools) admin panel: it exposes `listAccounts`, `getAccount`, `getStats`, `getRecentActivity`, `getRoles`, and the role/status/force-logout/impersonation actions.

```js
import { createAuthContext, AuthStatus } from "@prsm/auth"

const auth = createAuthContext(authConfig)
await auth.setStatusForUserBy({ email: "abusive@example.com" }, AuthStatus.Banned)
await auth.forceLogoutForUserBy({ email: "abusive@example.com" })

const { accounts, total } = await auth.listAccounts({ search: "@example.com", limit: 50 })
```

## Maintenance

```js
import { cleanupExpiredTokens, getAuthTableStats } from "@prsm/auth"

await cleanupExpiredTokens(authConfig)        // run on a schedule
const stats = await getAuthTableStats(authConfig)
```

## Documentation

Deeper guides live in [`docs/`](./docs):

- [Express middleware](./docs/middleware.md) - setup, the `req.auth` surface, and the full config reference
- [Sessions and resync](./docs/sessions.md) - how the middleware keeps session state fresh
- [Registration and confirmation](./docs/registration.md) - account creation with optional email verification
- [Authentication and MFA](./docs/authentication.md) - login flow, 2FA challenges, remember-me
- [MFA patterns](./docs/mfa.md) - TOTP, email and SMS OTP, backup codes, delivery
- [Roles](./docs/roles.md) - bitmask roles with `defineRoles` and built-in defaults
- [Password reset](./docs/password-reset.md) - forgot-password with secure tokens
- [Multi-tenant mapping](./docs/multi-tenant.md) - linking auth accounts to your own user tables
- [OAuth providers](./docs/providers.md) - GitHub, Google, and Azure
- [Impersonation](./docs/impersonation.md) - admin-as-user sessions with actor preservation and audit
- [Standalone and requestless auth](./docs/standalone.md) - `createAuthContext` and `authenticateRequest`
- [Admin panel with devtools](./docs/devtools.md) - binding the admin dashboard through `@prsm/devtools`
- [Cross-instance invalidation, tracing, and rate limiting](./docs/invalidation.md) - the optional prsm integrations
- [API reference](./docs/api.md) - the full method surface
- [Errors](./docs/errors.md) - every error, when and why it is thrown

## License

MIT
