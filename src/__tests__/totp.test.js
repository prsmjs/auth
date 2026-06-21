import { describe, it, expect } from "vitest"
import Otp, { InvalidSecretError, InvalidOtpLengthError, InvalidHashFunctionError, InvalidIntervalError } from "../totp.js"

// the totp primitive is inlined into @prsm/auth (not re-exported from the package
// index), but it is the crypto backing all 2fa, so it gets a direct suite. these
// port the @eaccess/totp tests and pin the RFC 6238 vectors, which also prove the
// self-contained base32 (decode) matches the @scure/base implementation it replaced

// base32 of the RFC 6238 ASCII seeds (verified equal to @scure/base output)
const SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
const SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA" // ...12 bytes more
const SHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"

describe("totp - secret generation", () => {
  it("generates base32 secrets sized by strength", () => {
    expect(Otp.createSecret(Otp.SHARED_SECRET_STRENGTH_LOW).length).toBe(16)
    expect(Otp.createSecret(Otp.SHARED_SECRET_STRENGTH_MODERATE).length).toBe(26)
    expect(Otp.createSecret(Otp.SHARED_SECRET_STRENGTH_HIGH).length).toBe(32)
    expect(Otp.createSecret().length).toBe(32) // default high
  })

  it("only emits base32 alphabet characters", () => {
    expect(Otp.createSecret()).toMatch(/^[A-Z2-7]+$/)
  })
})

describe("totp - generate and verify round-trip", () => {
  it("generates a 6-digit code that verifies (exercises base32 encode + decode)", () => {
    const secret = Otp.createSecret()
    const code = Otp.generateTotp(secret)
    expect(code).toHaveLength(6)
    expect(Otp.verifyTotp(secret, code)).toBe(true)
  })

  it("rejects a wrong code", () => {
    const secret = Otp.createSecret()
    expect(Otp.verifyTotp(secret, "000000")).toBe(false)
  })

  it("supports custom 8-digit length", () => {
    const secret = Otp.createSecret()
    const code = Otp.generateTotp(secret, undefined, 8)
    expect(code).toHaveLength(8)
    expect(Otp.verifyTotp(secret, code, undefined, undefined, undefined, 8)).toBe(true)
  })
})

describe("totp - QR provisioning URI", () => {
  it("builds an otpauth uri", () => {
    const uri = Otp.createTotpKeyUriForQrCode("app.example.com", "john.doe@example.org", "SECRET")
    expect(uri).toContain("otpauth://totp/app.example.com:john.doe%40example.org")
    expect(uri).toContain("secret=SECRET")
    expect(uri).toContain("issuer=app.example.com")
  })

  it("url-encodes issuer special characters", () => {
    const uri = Otp.createTotpKeyUriForQrCode("My App/Service", "user@example.com", "SECRET")
    expect(uri).toContain("otpauth://totp/My%20App%2FService:")
    expect(uri).toContain("issuer=My%20App%2FService")
  })
})

describe("totp - input validation", () => {
  it("throws on a secret shorter than 16 chars", () => {
    expect(() => Otp.generateTotp("shortsecret")).toThrow(InvalidSecretError)
  })

  it("throws on an out-of-range otp length", () => {
    const secret = Otp.createSecret()
    expect(() => Otp.generateTotp(secret, undefined, 5)).toThrow(InvalidOtpLengthError)
    expect(() => Otp.generateTotp(secret, undefined, 9)).toThrow(InvalidOtpLengthError)
  })

  it("throws on an unknown hash function", () => {
    const secret = Otp.createSecret()
    expect(() => Otp.generateTotp(secret, undefined, undefined, undefined, undefined, 999)).toThrow(InvalidHashFunctionError)
  })

  it("throws on a non-positive interval", () => {
    const secret = Otp.createSecret()
    expect(() => Otp.generateTotp(secret, undefined, 6, 0)).toThrow(InvalidIntervalError)
    expect(() => Otp.generateTotp(secret, undefined, 6, -30)).toThrow(InvalidIntervalError)
  })

  it("rejects codes of the wrong length without throwing", () => {
    const secret = Otp.createSecret()
    expect(Otp.verifyTotp(secret, "12345")).toBe(false) // too short
    expect(Otp.verifyTotp(secret, "123456789")).toBe(false) // too long
  })
})

describe("totp - drift window", () => {
  const now = 1000000000
  const step = 30

  it("accepts a one-step-ahead code within a symmetric window", () => {
    const secret = Otp.createSecret()
    const ahead = Otp.generateTotp(secret, now + step)
    expect(Otp.verifyTotp(secret, ahead, 0, undefined, now)).toBe(false) // window 0
    expect(Otp.verifyTotp(secret, ahead, 1, undefined, now)).toBe(true) // window 1 (symmetric)
  })

  it("honors an explicit asymmetric window", () => {
    const secret = Otp.createSecret()
    const ahead = Otp.generateTotp(secret, now + step)
    expect(Otp.verifyTotp(secret, ahead, 2, 0, now)).toBe(false) // look only behind
    expect(Otp.verifyTotp(secret, ahead, 0, 1, now)).toBe(true) // look ahead 1
  })

  it("is strict with a window of 0", () => {
    const secret = Otp.createSecret()
    const code = Otp.generateTotp(secret, now)
    expect(Otp.verifyTotp(secret, code, 0, undefined, now)).toBe(true)
    const old = Otp.generateTotp(secret, now - step)
    expect(Otp.verifyTotp(secret, old, 0, undefined, now)).toBe(false)
  })

  it("rejects codes well outside the window (expired and future)", () => {
    const secret = Otp.createSecret()
    expect(Otp.verifyTotp(secret, Otp.generateTotp(secret, now - 300), 2, 2, now)).toBe(false)
    expect(Otp.verifyTotp(secret, Otp.generateTotp(secret, now + 300), 2, 2, now)).toBe(false)
  })
})

describe("totp - RFC 6238 test vectors", () => {
  // exact generated values from RFC 6238 Appendix B; deterministic, no clock dependence
  it("matches the SHA-1 vectors (8 digits)", () => {
    const cases = [
      [59, "94287082"],
      [1111111109, "07081804"],
      [1111111111, "14050471"],
      [1234567890, "89005924"],
      [2000000000, "69279037"],
      [20000000000, "65353130"],
    ]
    for (const [t, expected] of cases) {
      expect(Otp.generateTotp(SHA1, t, 8, 30, 0, Otp.HASH_FUNCTION_SHA_1)).toBe(expected)
    }
  })

  it("matches the SHA-256 vector (8 digits)", () => {
    expect(Otp.generateTotp(SHA256, 59, 8, 30, 0, Otp.HASH_FUNCTION_SHA_256)).toBe("46119246")
  })

  it("matches the SHA-512 vector (8 digits)", () => {
    expect(Otp.generateTotp(SHA512, 59, 8, 30, 0, Otp.HASH_FUNCTION_SHA_512)).toBe("90693936")
  })

  it("verifies an RFC vector through verifyTotp at a fixed time", () => {
    expect(Otp.verifyTotp(SHA1, "94287082", 0, 0, 59, 8, 30, 0, Otp.HASH_FUNCTION_SHA_1)).toBe(true)
    expect(Otp.verifyTotp(SHA1, "94287082", 0, 0, 59 + 60, 8, 30, 0, Otp.HASH_FUNCTION_SHA_1)).toBe(false)
  })

  it("truncates to 6 digits consistently with the 8-digit vector", () => {
    // RFC 6238 6-digit value at t=59 is the last 6 digits of the 8-digit one
    expect(Otp.generateTotp(SHA1, 59, 6, 30, 0, Otp.HASH_FUNCTION_SHA_1)).toBe("287082")
  })
})
