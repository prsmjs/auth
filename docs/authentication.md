# Authentication and MFA

Login checks the password, account status, email verification, and optional two-factor authentication.

## Login

```js
await req.auth.login(email, password, remember)
```

The login method:

1. Finds the account by email
2. Verifies the password hash
3. Checks that the email is verified
4. Checks that the account status is `Normal` (not banned, locked, or otherwise restricted)
5. If 2FA is enabled and the user has verified methods, throws `SecondFactorRequiredError`
6. Otherwise creates a session and optionally sets a remember-me token

If a rate limiter is configured, login attempts are throttled per email before any of this runs, and a `RateLimitedError` is thrown once the limit is hit. See [Cross-instance invalidation](./invalidation.md#rate-limiting) for the limiter hook.

## Two-factor challenge

When `SecondFactorRequiredError` is thrown, the user is not logged in yet. The error includes `availableMethods` describing which mechanisms are available (TOTP, email, SMS). The session holds an `awaitingTwoFactor` state with an expiry.

Return the available methods to the client so it can show the right UI. Do not return raw OTP codes to the client - send them through your email or SMS service.

## Completing 2FA

After verification succeeds, call `completeTwoFactorLogin()` to finish the login:

```js
await req.auth.twoFactor.verify.totp(code)
await req.auth.completeTwoFactorLogin()
```

Verifiers: `verify.totp()`, `verify.email()`, `verify.sms()`, `verify.backupCode()`, and `verify.otp()` (tries email and SMS automatically).

See [MFA patterns](./mfa.md) for full implementation examples including OTP delivery.

## Remember me

Login with `remember: true` creates a persistent token in `{prefix}remembers` and sets an httpOnly cookie. On future requests, the middleware auto-restores the session from the cookie. Configure `rememberDuration` and `rememberCookieName` in the config.

## Logout

```js
await req.auth.logout()
await req.auth.logoutEverywhere()
await req.auth.logoutEverywhereElse()
```

- `logout()` clears the current session and remember token
- `logoutEverywhere()` clears all sessions and remember tokens
- `logoutEverywhereElse()` keeps the current session and clears everything else
