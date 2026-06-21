# Standalone and Requestless Auth

For operations outside of Express routes - scripts, workers, cron jobs, WebSocket servers - the package provides two tools.

## createAuthContext

Creates a context object bound to your auth config, with the user-management operations that normally hang off `req.auth`. No `req` or `res` needed.

```js
import { createAuthContext, AuthStatus } from "@prsm/auth"

const auth = createAuthContext(authConfig)

const account = await auth.createUser({ email: "user@example.com", password: "password123" })
await auth.addRoleForUserBy({ email: "user@example.com" }, Roles.editor)
await auth.setStatusForUserBy({ accountId: account.id }, AuthStatus.Banned)
await auth.deleteUserBy({ email: "user@example.com" })
```

User-management methods:

- `createUser`, `register`
- `deleteUserBy`, `forceLogoutForUserBy`
- `addRoleForUserBy`, `removeRoleForUserBy`, `hasRoleForUserBy`
- `changePasswordForUserBy`, `setStatusForUserBy`
- `resetPassword`, `confirmResetPassword`, `initiatePasswordResetForUserBy`
- `userExistsByEmail`

The same object is also the binding surface for the [@prsm/devtools](https://github.com/prsmjs/devtools) admin panel, which adds read methods (`listAccounts`, `getAccount`, `getStats`, `getRecentActivity`, `getRoles`, and more) on top of the actions above. See [Admin panel with devtools](./devtools.md).

## authenticateRequest

For WebSocket upgrades or raw HTTP authentication outside of Express middleware. It takes an `IncomingMessage` and checks session data or remember-me cookies.

```js
import { authenticateRequest } from "@prsm/auth"

const result = await authenticateRequest(authConfig, req, sessionMiddleware)
```

Returns `{ account, source }` where:

- `account` is the `AuthAccount` or `null`
- `source` is `"session"`, `"remember"`, or `null`

It checks the session first, then falls back to the remember-me cookie. It validates that the account exists and has `Normal` status.

```js
wss.on("connection", async (ws, req) => {
  const { account } = await authenticateRequest(authConfig, req, sessionMiddleware)
  if (!account) {
    ws.close(4001, "unauthorized")
    return
  }
  // authenticated - account.id, account.email, etc.
})
```
