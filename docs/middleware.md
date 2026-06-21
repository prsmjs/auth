# Express Middleware

## Setup

```js
import express from "express"
import session from "express-session"
import cookieParser from "cookie-parser"
import pg from "pg"
import { createAuthMiddleware, createAuthTables, defineRoles } from "@prsm/auth"

const app = express()
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })

app.use(express.json())
app.use(cookieParser())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}))

const Roles = defineRoles("admin", "owner", "editor", "viewer")

const authConfig = {
  db: pool,
  tablePrefix: "auth_",
  roles: Roles,
  resyncInterval: "30s",
}

await createAuthTables(authConfig)
app.use(createAuthMiddleware(authConfig))
```

Mount `createAuthMiddleware` after `express-session`. Mount `cookie-parser` as well if you use remember-me cookies.

## What `req.auth` gives you

**Session state:**
`isLoggedIn()`, `getId()`, `getEmail()`, `getStatus()`, `getStatusName()`, `getVerified()`, `hasPassword()`, `getRoleNames()`, `isRemembered()`

**Auth flows:**
`login()`, `register()`, `logout()`, `completeTwoFactorLogin()`

**Email:**
`changeEmail()`, `confirmEmail()`, `confirmEmailAndLogin()`

**Password:**
`resetPassword()`, `confirmResetPassword()`, `verifyPassword()`

**Roles:**
`hasRole()`, `isAdmin()`, `addRoleForUserBy()`, `removeRoleForUserBy()`, `hasRoleForUserBy()`

**Admin:**
`createUser()`, `deleteUserBy()`, `loginAsUserBy()`, `forceLogoutForUserBy()`, `changePasswordForUserBy()`, `setStatusForUserBy()`, `userExistsByEmail()`

**Impersonation:**
`startImpersonation()`, `stopImpersonation()`, `isImpersonating()`, `getActorId()`, `getActorEmail()`, `getImpersonationInfo()`

**Session management:**
`logoutEverywhere()`, `logoutEverywhereElse()`, `resyncSession()`

**OAuth:** `req.auth.providers.github`, `.google`, `.azure`

**MFA:** `req.auth.twoFactor` with setup, verify, complete, disable, and status methods

## Config reference

```js
const authConfig = {
  db: pool,                       // required pg Pool

  createUser,                     // (userData) => id | Promise<id>, for new OAuth users
  tablePrefix: "user_",           // default "user_"
  roles: Roles,                   // from defineRoles(), default AuthRole
  minPasswordLength: 8,           // default 8
  maxPasswordLength: 64,          // default 64
  rememberDuration: "30d",        // default "30d"
  rememberCookieName: "remember_token",
  resyncInterval: "30s",          // default "30s"

  cookie: {
    domain: undefined,
    secure: undefined,
    sameSite: undefined,          // "strict" | "lax" | "none"
  },

  activityLog: {
    enabled: true,
    maxEntries: undefined,
    actions: undefined,           // restrict which actions get logged
  },

  providers: {
    github: { clientId, clientSecret, redirectUri },
    google: { clientId, clientSecret, redirectUri },
    azure: { clientId, clientSecret, tenantId, redirectUri },
  },
  githubUserAgent: "prsm-auth",   // User-Agent sent to the GitHub API, default "prsm-auth"

  twoFactor: {
    enabled: false,
    requireForOAuth: false,
    issuer: undefined,            // shown in authenticator apps, default "prsm-auth"
    codeLength: 6,
    tokenExpiry: "5m",
    totpWindow: 1,
    backupCodesCount: 10,
  },

  impersonation: {
    enabled: false,
    defaultTtl: undefined,        // no default; an impersonation lasts until you stop it unless a ttl is given
    maxTtl: undefined,            // no default cap; set to bound the effective ttl
    canImpersonate: async (actor, target) => false,
  },

  // optional prsm integrations, all duck-typed - the package never imports them
  tracer,                         // a @prsm/trace tracer; login is wrapped in a span
  limiter,                        // a @prsm/limit limiter; throttles login per email
  invalidation: { listen: true, channel: "prsm_auth_invalidate" },
}
```

See [Cross-instance invalidation](./invalidation.md) for `tracer`, `limiter`, and `invalidation`.
