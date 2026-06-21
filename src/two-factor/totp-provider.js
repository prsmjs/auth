import Otp from "../totp.js"
import hash from "@prsm/hash"

/**
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 */

export class TotpProvider {
  /**
   * @param {AuthConfig} config
   */
  constructor(config) {
    this.config = config
  }

  /**
   * Generate a new base32 TOTP shared secret.
   * @returns {string}
   */
  generateSecret() {
    return Otp.createSecret()
  }

  /**
   * Build an otpauth:// URI for QR-code provisioning.
   * @param {string} email
   * @param {string} secret
   * @returns {string}
   */
  generateQRCode(email, secret) {
    const issuer = this.config.twoFactor?.issuer || "EasyAccess"
    return Otp.createTotpKeyUriForQrCode(issuer, email, secret)
  }

  /**
   * Verify a TOTP code against a secret using the configured drift window.
   * @param {string} secret
   * @param {string} code
   * @returns {boolean}
   */
  verify(secret, code) {
    const window = this.config.twoFactor?.totpWindow || 1
    return Otp.verifyTotp(secret, code, window)
  }

  /**
   * Generate random alphanumeric backup codes.
   * @param {number} [count]
   * @returns {string[]}
   */
  generateBackupCodes(count = 10) {
    const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    const codes = []
    for (let i = 0; i < count; i++) {
      const bytes = crypto.getRandomValues(new Uint8Array(8))
      codes.push(Array.from(bytes, (b) => chars[b % chars.length]).join(""))
    }
    return codes
  }

  /**
   * Hash a set of backup codes for storage.
   * @param {string[]} codes
   * @returns {Promise<string[]>}
   */
  async hashBackupCodes(codes) {
    return await Promise.all(codes.map((code) => hash.encode(code)))
  }

  /**
   * Verify an input backup code against hashed codes.
   * @param {string[]} hashedCodes
   * @param {string} inputCode
   * @returns {Promise<{ isValid: boolean, index: number }>}
   */
  async verifyBackupCode(hashedCodes, inputCode) {
    for (let i = 0; i < hashedCodes.length; i++) {
      if (await hash.verify(hashedCodes[i], inputCode.toUpperCase())) {
        return { isValid: true, index: i }
      }
    }

    return { isValid: false, index: -1 }
  }

  /**
   * Mask an email address for display.
   * @param {string} email
   * @returns {string}
   */
  maskEmail(email) {
    const [username, domain] = email.split("@")
    if (username.length <= 2) {
      return `${username[0]}***@${domain}`
    }
    return `${username[0]}${"*".repeat(username.length - 2)}${username[username.length - 1]}@${domain}`
  }
}
