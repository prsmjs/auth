# API Reference

Most of the API lives on `req.auth` (an `AuthManager` instance). Standalone functions are importable directly from `@prsm/auth`.

## Session

| Method | Returns | Description |
|--------|---------|-------------|
| `isLoggedIn()` | `boolean` | Whether the user has an active session |
| `getId()` | `number \| null` | Account ID |
| `getEmail()` | `string \| null` | Account email |
| `getStatus()` | `number \| null` | Status code |
| `getStatusName()` | `string \| null` | Status name (Normal, Banned, etc.) |
| `getVerified()` | `boolean \| null` | Email verification status |
| `hasPassword()` | `boolean \| null` | Whether the account has a password (false for OAuth-only) |
| `getRoleNames(rolemask?)` | `string[]` | Role names for the current user or a given mask |
| `isRemembered()` | `boolean` | Whether the session was restored from a remember-me cookie |
| `resyncSession(force?)` | `Promise<void>` | Refresh session data from the database |

## Auth flows

| Method | Returns | Description |
|--------|---------|-------------|
| `login(email, password, remember?)` | `Promise<void>` | Authenticate and create a session |
| `register(email, password, userId?, callback?)` | `Promise<AuthAccount>` | Create an account |
| `logout()` | `Promise<void>` | End the current session |
| `completeTwoFactorLogin()` | `Promise<void>` | Complete login after 2FA verification |
| `confirmEmail(token)` | `Promise<string>` | Confirm email, returns the email |
| `confirmEmailAndLogin(token, remember?)` | `Promise<void>` | Confirm and auto-login |
| `changeEmail(newEmail, callback)` | `Promise<void>` | Request an email change with confirmation |

## Password

| Method | Returns | Description |
|--------|---------|-------------|
| `resetPassword(email, expiresAfter?, maxRequests?, callback?)` | `Promise<void>` | Initiate a reset |
| `confirmResetPassword(token, password, logout?)` | `Promise<void>` | Complete a reset |
| `verifyPassword(password)` | `Promise<boolean>` | Whether the password matches the current user |

## Roles

| Method | Returns | Description |
|--------|---------|-------------|
| `hasRole(role)` | `Promise<boolean>` | Whether the current user has the role |
| `isAdmin()` | `Promise<boolean>` | Check for the Admin role (bitmask 1) |
| `addRoleForUserBy(identifier, role)` | `Promise<void>` | Add a role by accountId, email, or userId |
| `removeRoleForUserBy(identifier, role)` | `Promise<void>` | Remove a role |
| `hasRoleForUserBy(identifier, role)` | `Promise<boolean>` | Check a role for any user |

## Admin

| Method | Returns | Description |
|--------|---------|-------------|
| `createUser(credentials, userId?, callback?)` | `Promise<AuthAccount>` | Create a user programmatically |
| `deleteUserBy(identifier)` | `Promise<void>` | Delete a user and all associated data |
| `loginAsUserBy(identifier)` | `Promise<void>` | Replace the session with another user (destructive; see [Impersonation](./impersonation.md)) |
| `forceLogoutForUserBy(identifier)` | `Promise<void>` | Force logout of all sessions |
| `changePasswordForUserBy(identifier, password)` | `Promise<void>` | Admin password change |
| `setStatusForUserBy(identifier, status)` | `Promise<void>` | Change account status |
| `initiatePasswordResetForUserBy(identifier, expiresAfter?, callback?)` | `Promise<void>` | Admin-initiated reset |
| `userExistsByEmail(email)` | `Promise<boolean>` | Whether the email is registered |

## Impersonation

| Method | Returns | Description |
|--------|---------|-------------|
| `startImpersonation(identifier, options?)` | `Promise<void>` | Begin acting as the target user |
| `stopImpersonation()` | `Promise<void>` | Revert to the actor |
| `isImpersonating()` | `boolean` | Whether an impersonation session is active |
| `getActorId()` | `number \| null` | The admin account ID while impersonating |
| `getActorEmail()` | `string \| null` | The admin email while impersonating |
| `getImpersonationInfo()` | `object \| null` | Structured impersonation summary |

## Session management

| Method | Returns | Description |
|--------|---------|-------------|
| `logoutEverywhere()` | `Promise<void>` | Clear all sessions and remember tokens |
| `logoutEverywhereElse()` | `Promise<void>` | Clear all except the current session |

## Two-factor (`req.auth.twoFactor`)

**Status:**
`isEnabled()`, `totpEnabled()`, `emailEnabled()`, `smsEnabled()`, `getEnabledMethods()`, `getTotpUri()`, `getContact(mechanism)`

**Setup:**
`setup.totp(requireVerification?)`, `setup.email(email?, requireVerification?)`, `setup.sms(phone, requireVerification?)`

**Complete (after setup with verification):**
`complete.totp(code)`, `complete.email(code)`, `complete.sms(code)`

**Verify (during login):**
`verify.totp(code)`, `verify.email(code)`, `verify.sms(code)`, `verify.backupCode(code)`, `verify.otp(code)`

**Manage:**
`disable(mechanism)`, `generateNewBackupCodes()`

## OAuth providers (`req.auth.providers`)

Each provider (`.github`, `.google`, `.azure`) exposes:

| Method | Returns | Description |
|--------|---------|-------------|
| `getAuthUrl(state?, scopes?)` | `string` | OAuth authorization URL |
| `handleCallback(req)` | `Promise<OAuthCallbackResult>` | Process the OAuth callback |
| `getUserData(req)` | `Promise<OAuthUserData>` | Fetch the user profile from the provider |

## Standalone functions

| Function | Description |
|----------|-------------|
| `defineRoles(...names)` | Create a custom role bitmask object |
| `createAuthContext(config)` | Auth operations without an Express request, and the devtools binding surface |
| `authenticateRequest(config, req, sessionMiddleware?)` | Authenticate raw HTTP or WebSocket requests |
| `createAuthTables(config)` | Create all auth tables (idempotent) |
| `dropAuthTables(config)` | Drop all auth tables |
| `cleanupExpiredTokens(config)` | Remove expired confirmations, resets, remembers, and 2FA tokens |
| `getAuthTableStats(config)` | Row counts and expired-token counts |
| `closeInvalidationListeners()` | Release `LISTEN/NOTIFY` connections (shutdown, tests) |
| `addRoleToUser(config, identifier, role)` | Add a role without request context |
| `removeRoleFromUser(config, identifier, role)` | Remove a role without request context |
| `setUserRoles(config, identifier, rolemask)` | Set the complete rolemask |
| `getUserRoles(config, identifier)` | Get the current rolemask |
| `isValidEmail(email)` / `validateEmail(email)` | Check or assert email format |

`createAuthContext(config)` returns the requestless operations above plus the read methods the admin dashboard binds to - see [Standalone and requestless auth](./standalone.md) and [Admin panel with devtools](./devtools.md).

## Enums and constants

Runtime values exported from the package, used for status, roles, mechanisms, and activity actions:

| Export | Members |
|--------|---------|
| `AuthStatus` | `Normal` (0), `Archived` (1), `Banned` (2), `Locked` (3), `PendingReview` (4), `Suspended` (5) |
| `AuthRole` | the 22 built-in roles (`Admin`, `Author`, `Editor`, `SuperAdmin`, …) used when `config.roles` is unset |
| `TwoFactorMechanism` | `TOTP` (1), `EMAIL` (2), `SMS` (3) |
| `AuthActivityAction` | activity log action strings (`login`, `failed_login`, `role_changed`, `impersonation_started`, …) |

```js
import { AuthStatus, AuthRole, TwoFactorMechanism } from "@prsm/auth"

await req.auth.setStatusForUserBy({ email }, AuthStatus.Banned)
await req.auth.twoFactor.disable(TwoFactorMechanism.TOTP)
```

## Classes

For advanced use, the underlying classes are exported too: `TwoFactorManager`, `TotpProvider`, `OtpProvider`, `ActivityLogger`, and the OAuth providers `GitHubProvider` / `GoogleProvider` / `AzureProvider` / `BaseOAuthProvider`. Most applications use the `req.auth` surface and the standalone functions instead.
