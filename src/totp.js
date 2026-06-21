import * as crypto from "node:crypto"

// inlined RFC 6238 TOTP, ported from @eaccess/totp. internal to @prsm/auth -
// not re-exported, since a standalone totp primitive has no use outside 2fa.
// base32 (RFC 4648, no padding) is implemented here to avoid a dependency

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/**
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
function base32Encode(bytes) {
  let bits = 0
  let value = 0
  let output = ""
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
    value &= (1 << bits) - 1
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  }
  return output
}

/**
 * decodes a base32 string, ignoring any non-alphabet characters (padding, separators)
 * @param {string} str
 * @returns {Uint8Array}
 */
function base32Decode(str) {
  let bits = 0
  let value = 0
  /** @type {number[]} */
  const output = []
  for (const char of str) {
    const idx = BASE32_ALPHABET.indexOf(char)
    if (idx === -1) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
    value &= (1 << bits) - 1
  }
  return Uint8Array.from(output)
}

export class InvalidOtpLengthError extends Error {}
export class InvalidSecretError extends Error {}
export class InvalidHashFunctionError extends Error {}
export class InvalidSecretStrengthError extends Error {}
export class InvalidIntervalError extends Error {}

class Otp {
  static OTP_LENGTH_MIN = 6
  static OTP_LENGTH_MAX = 8
  static OTP_LENGTH_DEFAULT = 6
  static INTERVAL_LENGTH_DEFAULT = 30
  static EPOCH_DEFAULT = 0
  static HASH_FUNCTION_SHA_1 = 1
  static HASH_FUNCTION_SHA_256 = 2
  static HASH_FUNCTION_SHA_512 = 3
  static HASH_FUNCTION_DEFAULT = Otp.HASH_FUNCTION_SHA_1
  static SHARED_SECRET_STRENGTH_LOW = 1
  static SHARED_SECRET_STRENGTH_MODERATE = 2
  static SHARED_SECRET_STRENGTH_HIGH = 3

  /**
   * Generate a random Base32 shared secret (without padding).
   * @param {number} [strength] one of the SHARED_SECRET_STRENGTH_* constants, defaults to high (160 bits)
   * @returns {string}
   * @throws {InvalidSecretStrengthError}
   */
  static createSecret(strength = Otp.SHARED_SECRET_STRENGTH_HIGH) {
    const bits = this.determineBitsForSharedSecretStrength(strength)
    const bytes = Math.ceil(bits / 8)
    const buffer = crypto.randomBytes(bytes)
    return base32Encode(buffer).replace(/=+$/, "")
  }

  /**
   * Build an otpauth:// URI for QR-code provisioning in authenticator apps.
   * @param {string} issuer
   * @param {string} accountName
   * @param {string} secret
   * @returns {string}
   */
  static createTotpKeyUriForQrCode(issuer, accountName, secret) {
    return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`
  }

  /**
   * Generate a TOTP value.
   * @param {string} secret base32 shared secret, at least 16 chars after sanitization
   * @param {number} [t] unix time in seconds, defaults to now
   * @param {number} [otpLength] number of digits (6-8), defaults to 6
   * @param {number} [t_x] time step in seconds, defaults to 30
   * @param {number} [t_0] epoch start in seconds, defaults to 0
   * @param {number} [hashFunction] one of the HASH_FUNCTION_* constants, defaults to SHA-1
   * @returns {string}
   * @throws {InvalidOtpLengthError|InvalidIntervalError|InvalidSecretError|InvalidHashFunctionError}
   */
  static generateTotp(secret, t = Math.floor(Date.now() / 1000), otpLength = Otp.OTP_LENGTH_DEFAULT, t_x = Otp.INTERVAL_LENGTH_DEFAULT, t_0 = Otp.EPOCH_DEFAULT, hashFunction = Otp.HASH_FUNCTION_DEFAULT) {
    if (otpLength < Otp.OTP_LENGTH_MIN || otpLength > Otp.OTP_LENGTH_MAX) {
      throw new InvalidOtpLengthError()
    }

    if (t_x <= 0) {
      throw new InvalidIntervalError()
    }

    secret = secret ?? ""
    t = t ?? Math.floor(Date.now() / 1000)

    const c_t = Math.max(0, Math.floor((t - t_0) / t_x))

    secret = secret.replace(/[^A-Za-z2-7]/g, "").toUpperCase()

    if (secret.length < 16) {
      throw new InvalidSecretError()
    }

    const k = base32Decode(secret)

    const counter64BitBigEndian = Buffer.alloc(8)
    counter64BitBigEndian.writeUInt32BE(Math.floor(c_t / Math.pow(2, 32)), 0)
    counter64BitBigEndian.writeUInt32BE(c_t % Math.pow(2, 32), 4)

    let hashFunctionNameForHmac
    switch (hashFunction) {
      case Otp.HASH_FUNCTION_SHA_1:
        hashFunctionNameForHmac = "sha1"
        break
      case Otp.HASH_FUNCTION_SHA_256:
        hashFunctionNameForHmac = "sha256"
        break
      case Otp.HASH_FUNCTION_SHA_512:
        hashFunctionNameForHmac = "sha512"
        break
      default:
        throw new InvalidHashFunctionError()
    }

    const hmac = crypto.createHmac(hashFunctionNameForHmac, Buffer.from(k))
    hmac.update(counter64BitBigEndian)
    const mac = hmac.digest()

    const offset = mac[mac.length - 1] & 0x0f
    const macSubstring4Bytes = mac.slice(offset, offset + 4)

    const integer32Bit = macSubstring4Bytes.readUInt32BE(0) & 0x7fffffff

    const hotp = integer32Bit % Math.pow(10, otpLength)

    return hotp.toString().padStart(otpLength, "0")
  }

  /**
   * Verify a user-supplied TOTP across a drift window using a constant-time compare.
   * @param {string} secret
   * @param {string} otpValue
   * @param {number} [lookBehindSteps] defaults to 2
   * @param {number} [lookAheadSteps] defaults to lookBehindSteps (symmetric)
   * @param {number} [t]
   * @param {number} [otpLength]
   * @param {number} [t_x]
   * @param {number} [t_0]
   * @param {number} [hashFunction]
   * @returns {boolean}
   */
  static verifyTotp(secret, otpValue, lookBehindSteps = 2, lookAheadSteps, t = Math.floor(Date.now() / 1000), otpLength = Otp.OTP_LENGTH_DEFAULT, t_x = Otp.INTERVAL_LENGTH_DEFAULT, t_0 = Otp.EPOCH_DEFAULT, hashFunction = Otp.HASH_FUNCTION_DEFAULT) {
    const ahead = lookAheadSteps ?? lookBehindSteps

    otpValue = otpValue.replace(/[^0-9]/g, "")

    if (otpValue.length < Otp.OTP_LENGTH_MIN || otpValue.length > Otp.OTP_LENGTH_MAX) {
      return false
    }

    if (otpValue.length !== otpLength) {
      return false
    }

    for (let s = -lookBehindSteps; s <= ahead; s++) {
      const expectedOtpValue = this.generateTotp(secret, t + t_x * s, otpLength, t_x, t_0, hashFunction)
      if (crypto.timingSafeEqual(Buffer.from(expectedOtpValue), Buffer.from(otpValue))) {
        return true
      }
    }

    return false
  }

  /**
   * @param {number} strength
   * @returns {number}
   * @throws {InvalidSecretStrengthError}
   */
  static determineBitsForSharedSecretStrength(strength) {
    switch (strength) {
      case 1:
        return 80
      case 2:
        return 128
      case 3:
        return 160
      default:
        throw new InvalidSecretStrengthError()
    }
  }
}

export default Otp
