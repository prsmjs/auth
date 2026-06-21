import ms from "@prsm/ms"
import hash from "@prsm/hash"
import { AuthQueries } from "../queries.js"

/**
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 * @typedef {import("../types.js").TwoFactorToken} TwoFactorToken
 */

export class OtpProvider {
  /**
   * @param {AuthConfig} config
   */
  constructor(config) {
    this.config = config
    this.queries = new AuthQueries(config)
  }

  /**
   * Generate a numeric one-time password.
   * @returns {string}
   */
  generateOTP() {
    const length = this.config.twoFactor?.codeLength || 6
    const bytes = crypto.getRandomValues(new Uint8Array(length))
    return Array.from(bytes, (b) => (b % 10).toString()).join("")
  }

  /**
   * Generate a random opaque selector for an OTP token.
   * @returns {string}
   */
  generateSelector() {
    return crypto.randomUUID().replace(/-/g, "")
  }

  /**
   * Create, hash, and store a new OTP for an account and mechanism.
   * @param {number} accountId
   * @param {number} mechanism EMAIL or SMS
   * @returns {Promise<{ otp: string, selector: string }>}
   */
  async createAndStoreOTP(accountId, mechanism) {
    const otp = this.generateOTP()
    const selector = this.generateSelector()
    const tokenHash = await hash.encode(otp)

    const expiryDuration = this.config.twoFactor?.tokenExpiry || "5m"
    const expiresAt = new Date(Date.now() + ms(expiryDuration))

    // delete any existing tokens for this account and mechanism
    await this.queries.deleteTwoFactorTokensByAccountAndMechanism(accountId, mechanism)

    // store the new token
    await this.queries.createTwoFactorToken({
      accountId,
      mechanism,
      selector,
      tokenHash,
      expiresAt,
    })

    return { otp, selector }
  }

  /**
   * Verify an OTP by selector, consuming the token on success.
   * @param {string} selector
   * @param {string} inputCode
   * @returns {Promise<{ isValid: boolean, token?: TwoFactorToken }>}
   */
  async verifyOTP(selector, inputCode) {
    const token = await this.queries.findTwoFactorTokenBySelector(selector)

    if (!token) {
      return { isValid: false }
    }

    // check if token has expired (extra check, even though query filters expired tokens)
    if (token.expires_at <= new Date()) {
      // clean up expired token
      await this.queries.deleteTwoFactorToken(token.id)
      return { isValid: false }
    }

    const isValid = await hash.verify(token.token_hash, inputCode)

    if (isValid) {
      // clean up used token
      await this.queries.deleteTwoFactorToken(token.id)
      return { isValid: true, token }
    }

    return { isValid: false }
  }

  /**
   * Mask a phone number for display.
   * @param {string} phone
   * @returns {string}
   */
  maskPhone(phone) {
    if (phone.length < 4) {
      return phone.replace(/./g, "*")
    }

    // show first digit and last 2 digits: +1234567890 -> +1*****90
    if (phone.startsWith("+")) {
      return phone[0] + phone[1] + "*".repeat(phone.length - 3) + phone.slice(-2)
    }

    // for regular numbers: 1234567890 -> 1*****90
    return phone[0] + "*".repeat(phone.length - 3) + phone.slice(-2)
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
