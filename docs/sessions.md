# Sessions and Resync

`express-session` backs everything. The middleware creates an `AuthManager` per request, attaches it to `req.auth`, and keeps the session state fresh against the database.

## Middleware flow

`createAuthMiddleware(config)` returns Express middleware that, on every request:

1. Creates an `AuthManager` with the current `req`, `res`, and config
2. Attaches it to `req.auth`
3. Calls `resyncSession()` to refresh session data from the database
4. Calls the remember-me check to restore a session from a remember cookie if one is present

## Resync

`resyncSession()` keeps the session in sync with the database and enforces force-logout.

- Skips if the request is not logged in
- If `shouldForceLogout` is set on the session, logs out immediately
- Throttled by `resyncInterval` (default `"30s"`, configurable)
- Fetches the account from the database, and logs out if the account is gone
- Compares the account's `force_logout` counter against the session's value, and logs out if the database value is higher
- Updates session fields: email, status, rolemask, verified, hasPassword

Force an immediate resync by passing `true`:

```js
await req.auth.resyncSession(true)
```

The throttle means a ban or role change made on one instance can take up to `resyncInterval` to reach an instance that already has the session cached. If you need those changes to land immediately across a fleet, turn on cross-instance invalidation - see [Cross-instance invalidation](./invalidation.md).

## Remember tokens

When a user logs in with `remember: true`, a token is stored in `{prefix}remembers` and set as an httpOnly cookie. On later requests, the middleware checks for the cookie and restores the session if the token is valid and unexpired. Invalid or expired tokens are cleared automatically.

Remember-me cookies need `cookie-parser` mounted before the auth middleware. Configure `rememberDuration` and `rememberCookieName` in the config.

## Activity logging

The `ActivityLogger` records actions like login, failed login, 2FA prompts, remember-token creation, role changes, and impersonation. It parses the user agent for browser, OS, and device, and stores metadata as JSON. Logging is on by default. See [Express middleware](./middleware.md) for the `activityLog` configuration options.
