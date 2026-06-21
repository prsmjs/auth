# MFA Patterns

TOTP (authenticator apps), email OTP, SMS OTP, and backup codes are built in. The TOTP implementation follows RFC 6238 and lives inside the package, so there is no separate dependency to install or keep in sync.

## Enable MFA in config

```js
const authConfig = {
  db: pool,
  twoFactor: {
    enabled: true,
    issuer: "MyApp",
    codeLength: 6,
    tokenExpiry: "5m",
    totpWindow: 1,
    backupCodesCount: 10,
    requireForOAuth: false,
  },
}
```

## Enroll TOTP

### Without verification (immediate)

```js
app.post("/2fa/setup-totp", async (req, res) => {
  const { secret, qrCode, backupCodes } = await req.auth.twoFactor.setup.totp(false)
  res.json({ secret, qrCode, backupCodes })
})
```

The method is enabled immediately. The client should display the QR code and backup codes.

### With verification (recommended for production)

```js
app.post("/2fa/setup-totp", async (req, res) => {
  const { secret, qrCode } = await req.auth.twoFactor.setup.totp(true)
  res.json({ secret, qrCode, requiresVerification: true })
})

app.post("/2fa/verify-totp-setup", async (req, res) => {
  const backupCodes = await req.auth.twoFactor.complete.totp(req.body.code)
  res.json({ backupCodes })
})
```

The method stays unverified until the user provides a valid code from their authenticator app. Backup codes are generated on completion.

## Enroll email OTP

Enable immediately (the caller trusts the address):

```js
await req.auth.twoFactor.setup.email()
await req.auth.twoFactor.setup.email("alternate@example.com")
```

Or require a verification code first. With `requireVerification` true, setup issues a one-time code and returns it for you to deliver - the package never sends email or SMS itself. The method stays unverified until `complete.email()` validates that code:

```js
const { otpValue, maskedContact } = await req.auth.twoFactor.setup.email(email, true)
await sendEmail(email, `Your verification code is ${otpValue}`)
// later, with the code the user entered:
await req.auth.twoFactor.complete.email(req.body.code) // throws InvalidTwoFactorCodeError on mismatch
```

## Enroll SMS OTP

SMS setup requires verification by default - it returns a code for you to send, and the number is enabled only once `complete.sms()` validates it:

```js
const { otpValue, maskedContact } = await req.auth.twoFactor.setup.sms("+15551234567")
await sendSms("+15551234567", `Your verification code is ${otpValue}`)
await req.auth.twoFactor.complete.sms(req.body.code)
```

Pass `false` as the second argument to enable a number without a verification step.

## Login with 2FA

When 2FA is enabled and a user has verified methods, `login()` throws `SecondFactorRequiredError`. The error includes `availableMethods` with the mechanisms available.

For email and SMS OTP, the error also includes the generated OTP value. Send it through your email or SMS service - do not return it to the client.

```js
import { SecondFactorRequiredError } from "@prsm/auth"

app.post("/login", async (req, res) => {
  try {
    await req.auth.login(req.body.email, req.body.password, req.body.remember)
    res.json({ success: true })
  } catch (error) {
    if (error instanceof SecondFactorRequiredError) {
      if (error.availableMethods.email) {
        sendEmail(error.availableMethods.email.maskedContact, error.availableMethods.email.otpValue)
      }
      return res.status(202).json({
        requiresTwoFactor: true,
        methods: {
          totp: !!error.availableMethods.totp,
          email: error.availableMethods.email?.maskedContact,
          sms: error.availableMethods.sms?.maskedContact,
        },
      })
    }
    res.status(401).json({ error: error.message })
  }
})
```

## Complete login

```js
app.post("/verify-2fa", async (req, res) => {
  await req.auth.twoFactor.verify.totp(req.body.code)
  await req.auth.completeTwoFactorLogin()
  res.json({ success: true })
})
```

Other verifiers: `verify.email(code)`, `verify.sms(code)`, `verify.backupCode(code)`, and `verify.otp(code)` (tries email and SMS automatically).

## Management

```js
const enabled = await req.auth.twoFactor.isEnabled()
const methods = await req.auth.twoFactor.getEnabledMethods()

await req.auth.twoFactor.disable(TwoFactorMechanism.TOTP)

const newCodes = await req.auth.twoFactor.generateNewBackupCodes()

const contact = await req.auth.twoFactor.getContact(TwoFactorMechanism.EMAIL)
const uri = await req.auth.twoFactor.getTotpUri()
```
