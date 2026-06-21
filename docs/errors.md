# Errors

All errors extend `AuthError`. Catch specific types with `instanceof` or check `error.name`.

## Registration

| Error | When |
|-------|------|
| `EmailTakenError` | Email already registered |
| `InvalidEmailError` | Email fails format validation |
| `InvalidPasswordError` | Password outside the configured min/max length |

## Email confirmation

| Error | When |
|-------|------|
| `ConfirmationNotFoundError` | Token does not exist |
| `ConfirmationExpiredError` | Token has expired |
| `InvalidTokenError` | Token format is invalid |

## Login

| Error | When |
|-------|------|
| `UserNotFoundError` | No account with that email |
| `InvalidPasswordError` | Password hash does not match |
| `EmailNotVerifiedError` | Account email not confirmed |
| `UserInactiveError` | Account status is not Normal (banned, locked, suspended, etc.) |
| `RateLimitedError` | A configured limiter rejected the attempt; carries `retryAfter` |

## Two-factor authentication

| Error | When |
|-------|------|
| `SecondFactorRequiredError` | Login paused, the user has verified 2FA methods. Includes `availableMethods` |
| `TwoFactorExpiredError` | 2FA session expired before completion |
| `InvalidTwoFactorCodeError` | Wrong TOTP, email, or SMS code |
| `InvalidBackupCodeError` | Backup code not recognized or already used |
| `TwoFactorNotSetupError` | Verification attempted before setup, or the method does not exist |
| `TwoFactorAlreadyEnabledError` | Trying to enable a mechanism that is already verified |
| `TwoFactorSetupIncompleteError` | Setup started but not completed |

## Password reset

| Error | When |
|-------|------|
| `ResetNotFoundError` | Reset token does not exist |
| `ResetExpiredError` | Reset token has expired |
| `ResetDisabledError` | Account has `resettable = false` |
| `TooManyResetsError` | Exceeded `maxOpenRequests` concurrent reset tokens |
| `InvalidPasswordError` | New password does not meet requirements |
| `InvalidTokenError` | Token verification failed |
| `UserNotFoundError` | Account no longer exists |

## Session

| Error | When |
|-------|------|
| `UserNotLoggedInError` | Action requires an authenticated session |

## Impersonation

| Error | When |
|-------|------|
| `ImpersonationDisabledError` | `config.impersonation.enabled` is not `true` |
| `ImpersonationNotAllowedError` | `canImpersonate` returned false, or the target is the actor |
| `AlreadyImpersonatingError` | Tried to start while already impersonating |
| `NotImpersonatingError` | Called `stopImpersonation` outside an impersonation session |

## Catching errors

```js
import { EmailTakenError, InvalidPasswordError } from "@prsm/auth"

app.post("/register", async (req, res) => {
  try {
    await req.auth.register(req.body.email, req.body.password)
    res.json({ success: true })
  } catch (error) {
    if (error instanceof EmailTakenError) {
      return res.status(409).json({ error: "Email already registered" })
    }
    if (error instanceof InvalidPasswordError) {
      return res.status(400).json({ error: "Password does not meet requirements" })
    }
    throw error
  }
})
```
