# Admin Panel with devtools

There is no separate admin package. Account management, role editing, MFA status, activity logs, and the overview dashboard are provided by [@prsm/devtools](https://github.com/prsmjs/devtools), which binds to the context returned by `createAuthContext`.

## Bind the context

`createAuthContext(config)` returns an object that doubles as the devtools binding surface. It exposes the user-management actions plus the read methods the dashboard renders. devtools consumes this object by duck typing, so it needs no `@prsm/auth` dependency.

```js
import { createAuthContext } from "@prsm/auth"

const authContext = createAuthContext(authConfig)
// pass authContext to your @prsm/devtools setup as the auth binding
```

## What the binding exposes

Read methods used by the dashboard:

| Method | Returns |
|--------|---------|
| `listAccounts({ limit, offset, search })` | `{ accounts, total }` - each account includes a `twoFactor` array of its enabled mechanism codes |
| `getAccount(identifier)` | the `AuthAccount` |
| `getProvidersForAccount(accountId)` | linked OAuth providers |
| `getTwoFactorMethods(accountId)` | configured 2FA methods |
| `getRoles()` | the role name to bitmask map (`config.roles` or `AuthRole`) |
| `getStatuses()` | the account status name to code map (`AuthStatus`) |
| `getMechanisms()` | the 2FA mechanism name to code map (`TwoFactorMechanism`) |
| `getStats()` | row counts and expired-token counts |
| `getRecentActivity(limit, accountId)` | recent activity rows |
| `getActivityStats()` | aggregated activity stats |

Control actions (the same operations available on `req.auth`):

`createUser`, `register`, `deleteUserBy`, `addRoleForUserBy`, `removeRoleForUserBy`, `hasRoleForUserBy`, `changePasswordForUserBy`, `setStatusForUserBy`, `initiatePasswordResetForUserBy`, `resetPassword`, `confirmResetPassword`, `userExistsByEmail`, `forceLogoutForUserBy`, `removeTwoFactorMethod`.

`removeTwoFactorMethod(identifier, methodId)` is the admin rescue path for a user who lost their authenticator device: it deletes one of the account's 2FA methods (after confirming it belongs to that account) and records an audit-log entry.

## Roles in the dashboard

If you define custom roles with `defineRoles` and pass them as `config.roles`, `getRoles()` returns them and the dashboard renders your names automatically. Otherwise it falls back to the built-in `AuthRole` set. See [Roles](./roles.md).

## Without devtools

The binding surface is plain functions, so you can drive the same operations from your own admin UI or scripts. `listAccounts`, `getAccount`, `getStats`, and `getRecentActivity` cover read views; the control actions cover moderation. See [Standalone and requestless auth](./standalone.md).
