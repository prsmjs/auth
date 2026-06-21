import { TwoFactorMechanism } from "../types.js"
import { AuthQueries } from "../queries.js"
import { ActivityLogger } from "../activity-logger.js"
import { AuthActivityAction } from "../types.js"
import { TotpProvider } from "./totp-provider.js"
import { OtpProvider } from "./otp-provider.js"
import { TwoFactorNotSetupError, TwoFactorAlreadyEnabledError, TwoFactorSetupIncompleteError, InvalidTwoFactorCodeError, InvalidBackupCodeError, UserNotLoggedInError } from "../errors.js"

/**
 * @typedef {import("express").Request} Request
 * @typedef {import("express").Response} Response
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 * @typedef {import("../types.js").TwoFactorSetupResult} TwoFactorSetupResult
 * @typedef {import("../types.js").TwoFactorChallenge} TwoFactorChallenge
 */

export class TwoFactorManager {
  /**
   * @param {Request} req
   * @param {Response} res
   * @param {AuthConfig} config
   */
  constructor(req, res, config) {
    this.req = req
    this.res = res
    this.config = config
    this.queries = new AuthQueries(config)
    this.activityLogger = new ActivityLogger(config)
    this.totpProvider = new TotpProvider(config)
    this.otpProvider = new OtpProvider(config)

    this.setup = {
      /**
       * Begin TOTP setup, optionally deferring verification.
       * @param {boolean} [requireVerification]
       * @returns {Promise<TwoFactorSetupResult>}
       * @throws {UserNotLoggedInError|TwoFactorAlreadyEnabledError}
       */
      totp: async (requireVerification = false) => {
        const accountId = this.getAccountId()
        const email = this.getEmail()

        if (!accountId || !email) {
          throw new UserNotLoggedInError()
        }

        // check if TOTP is already enabled
        const existingMethod = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.TOTP)

        if (existingMethod?.verified) {
          throw new TwoFactorAlreadyEnabledError()
        }

        const secret = this.totpProvider.generateSecret()
        const qrCode = this.totpProvider.generateQRCode(email, secret)

        // generate backup codes immediately if no verification required
        let backupCodes
        if (!requireVerification) {
          const backupCodesCount = this.config.twoFactor?.backupCodesCount || 10
          backupCodes = this.totpProvider.generateBackupCodes(backupCodesCount)
        }

        const hashedBackupCodes = backupCodes ? await this.totpProvider.hashBackupCodes(backupCodes) : undefined
        const verified = !requireVerification

        // create or update the TOTP method
        if (existingMethod) {
          await this.queries.updateTwoFactorMethod(existingMethod.id, {
            secret,
            backup_codes: hashedBackupCodes || null,
            verified,
          })
        } else {
          await this.queries.createTwoFactorMethod({
            accountId,
            mechanism: TwoFactorMechanism.TOTP,
            secret,
            backupCodes: hashedBackupCodes,
            verified,
          })
        }

        if (verified) {
          await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorSetup, this.req, true, { mechanism: "totp" })
        }

        return { secret, qrCode, backupCodes }
      },

      /**
       * Begin email 2FA setup. When requireVerification is true, an OTP is
       * issued and returned for the application to deliver; the method stays
       * unverified until complete.email() validates that code. When false, the
       * method is enabled immediately (the caller is trusting the address).
       * @param {string} [email]
       * @param {boolean} [requireVerification]
       * @returns {Promise<{ otpValue: string, maskedContact: string } | void>}
       * @throws {UserNotLoggedInError|TwoFactorAlreadyEnabledError}
       */
      email: async (email, requireVerification = false) => {
        const accountId = this.getAccountId()
        const userEmail = email || this.getEmail()

        if (!accountId || !userEmail) {
          throw new UserNotLoggedInError()
        }

        // check if email 2FA is already enabled
        const existingMethod = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.EMAIL)

        if (existingMethod?.verified) {
          throw new TwoFactorAlreadyEnabledError()
        }

        const verified = !requireVerification

        // create or update the email method
        if (existingMethod) {
          await this.queries.updateTwoFactorMethod(existingMethod.id, {
            secret: userEmail,
            verified,
          })
        } else {
          await this.queries.createTwoFactorMethod({
            accountId,
            mechanism: TwoFactorMechanism.EMAIL,
            secret: userEmail,
            verified,
          })
        }

        if (verified) {
          await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorSetup, this.req, true, { mechanism: "email" })
          return
        }

        // issue an OTP for the caller to deliver, and stash its selector so
        // complete.email() can verify the entered code. the otp value is never
        // sent anywhere by this library
        const { otp, selector } = await this.otpProvider.createAndStoreOTP(accountId, TwoFactorMechanism.EMAIL)
        this.storeSetupSelector(TwoFactorMechanism.EMAIL, selector)
        return { otpValue: otp, maskedContact: this.otpProvider.maskEmail(userEmail) }
      },

      /**
       * Begin SMS 2FA setup. When requireVerification is true (the default), an
       * OTP is issued and returned for the application to deliver; the method
       * stays unverified until complete.sms() validates that code. When false,
       * the method is enabled immediately (the caller is trusting the number).
       * @param {string} phone
       * @param {boolean} [requireVerification]
       * @returns {Promise<{ otpValue: string, maskedContact: string } | void>}
       * @throws {UserNotLoggedInError|TwoFactorAlreadyEnabledError}
       */
      sms: async (phone, requireVerification = true) => {
        const accountId = this.getAccountId()

        if (!accountId) {
          throw new UserNotLoggedInError()
        }

        // check if SMS 2FA is already enabled
        const existingMethod = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.SMS)

        if (existingMethod?.verified) {
          throw new TwoFactorAlreadyEnabledError()
        }

        const verified = !requireVerification

        // create or update the SMS method
        if (existingMethod) {
          await this.queries.updateTwoFactorMethod(existingMethod.id, {
            secret: phone,
            verified,
          })
        } else {
          await this.queries.createTwoFactorMethod({
            accountId,
            mechanism: TwoFactorMechanism.SMS,
            secret: phone,
            verified,
          })
        }

        if (verified) {
          await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorSetup, this.req, true, { mechanism: "sms" })
          return
        }

        // issue an OTP for the caller to deliver, and stash its selector so
        // complete.sms() can verify the entered code. the otp value is never
        // sent anywhere by this library
        const { otp, selector } = await this.otpProvider.createAndStoreOTP(accountId, TwoFactorMechanism.SMS)
        this.storeSetupSelector(TwoFactorMechanism.SMS, selector)
        return { otpValue: otp, maskedContact: this.otpProvider.maskPhone(phone) }
      },
    }

    this.complete = {
      /**
       * Complete TOTP setup by verifying a code, returning backup codes.
       * @param {string} code
       * @returns {Promise<string[]>}
       * @throws {UserNotLoggedInError|TwoFactorNotSetupError|TwoFactorAlreadyEnabledError|InvalidTwoFactorCodeError}
       */
      totp: async (code) => {
        const accountId = this.getAccountId()

        if (!accountId) {
          throw new UserNotLoggedInError()
        }

        const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.TOTP)

        if (!method || !method.secret) {
          throw new TwoFactorNotSetupError()
        }

        if (method.verified) {
          throw new TwoFactorAlreadyEnabledError()
        }

        // verify the TOTP code
        const isValid = this.totpProvider.verify(method.secret, code)
        if (!isValid) {
          await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorFailed, this.req, false, { mechanism: "totp", reason: "invalid_code" })
          throw new InvalidTwoFactorCodeError()
        }

        // generate backup codes
        const backupCodesCount = this.config.twoFactor?.backupCodesCount || 10
        const backupCodes = this.totpProvider.generateBackupCodes(backupCodesCount)
        const hashedBackupCodes = await this.totpProvider.hashBackupCodes(backupCodes)

        // mark as verified and store backup codes
        await this.queries.updateTwoFactorMethod(method.id, {
          verified: true,
          backup_codes: hashedBackupCodes,
          last_used_at: new Date(),
        })

        await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorSetup, this.req, true, { mechanism: "totp" })

        return backupCodes
      },

      /**
       * Complete email 2FA setup with a verification code.
       * @param {string} code
       * @returns {Promise<void>}
       */
      email: async (code) => {
        await this.completeOtpSetup(TwoFactorMechanism.EMAIL, code)
      },

      /**
       * Complete SMS 2FA setup with a verification code.
       * @param {string} code
       * @returns {Promise<void>}
       */
      sms: async (code) => {
        await this.completeOtpSetup(TwoFactorMechanism.SMS, code)
      },
    }

    this.verify = {
      /**
       * Verify a TOTP code during the login flow.
       * @param {string} code
       * @returns {Promise<void>}
       * @throws {UserNotLoggedInError|TwoFactorNotSetupError|InvalidTwoFactorCodeError}
       */
      totp: async (code) => {
        const twoFactorState = this.req.session?.auth?.awaitingTwoFactor

        if (!twoFactorState) {
          throw new UserNotLoggedInError()
        }

        const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(twoFactorState.accountId, TwoFactorMechanism.TOTP)

        if (!method || !method.verified || !method.secret) {
          throw new TwoFactorNotSetupError()
        }

        const isValid = this.totpProvider.verify(method.secret, code)
        if (!isValid) {
          await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.TwoFactorFailed, this.req, false, { mechanism: "totp", reason: "invalid_code" })
          throw new InvalidTwoFactorCodeError()
        }

        // update last used
        await this.queries.updateTwoFactorMethod(method.id, {
          last_used_at: new Date(),
        })

        await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.TwoFactorVerified, this.req, true, { mechanism: "totp" })
      },

      /**
       * Verify an email OTP during the login flow.
       * @param {string} code
       * @returns {Promise<void>}
       */
      email: async (code) => {
        await this.verifyOtp(TwoFactorMechanism.EMAIL, code)
      },

      /**
       * Verify an SMS OTP during the login flow.
       * @param {string} code
       * @returns {Promise<void>}
       */
      sms: async (code) => {
        await this.verifyOtp(TwoFactorMechanism.SMS, code)
      },

      /**
       * Verify a backup code during the login flow, consuming it on success.
       * @param {string} code
       * @returns {Promise<void>}
       * @throws {UserNotLoggedInError|TwoFactorNotSetupError|InvalidBackupCodeError}
       */
      backupCode: async (code) => {
        const twoFactorState = this.req.session?.auth?.awaitingTwoFactor

        if (!twoFactorState) {
          throw new UserNotLoggedInError()
        }

        const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(twoFactorState.accountId, TwoFactorMechanism.TOTP)

        if (!method || !method.verified || !method.backup_codes) {
          throw new TwoFactorNotSetupError()
        }

        const { isValid, index } = await this.totpProvider.verifyBackupCode(method.backup_codes, code)

        if (!isValid) {
          await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.TwoFactorFailed, this.req, false, { mechanism: "backup_code", reason: "invalid_code" })
          throw new InvalidBackupCodeError()
        }

        // remove the used backup code
        const updatedBackupCodes = [...method.backup_codes]
        updatedBackupCodes.splice(index, 1)

        await this.queries.updateTwoFactorMethod(method.id, {
          backup_codes: updatedBackupCodes,
          last_used_at: new Date(),
        })

        await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.BackupCodeUsed, this.req, true, { remaining_codes: updatedBackupCodes.length })
      },

      /**
       * Verify an OTP against any available email/SMS mechanism during login.
       * @param {string} code
       * @returns {Promise<void>}
       * @throws {UserNotLoggedInError|TwoFactorNotSetupError|InvalidTwoFactorCodeError}
       */
      otp: async (code) => {
        const twoFactorState = this.req.session?.auth?.awaitingTwoFactor

        if (!twoFactorState) {
          throw new UserNotLoggedInError()
        }

        // try to find which mechanism this OTP is for based on available methods
        const availableMechanisms = twoFactorState.availableMechanisms.filter((m) => m === TwoFactorMechanism.EMAIL || m === TwoFactorMechanism.SMS)

        if (availableMechanisms.length === 0) {
          throw new TwoFactorNotSetupError()
        }

        // try each available OTP mechanism
        for (const mechanism of availableMechanisms) {
          try {
            await this.verifyOtp(mechanism, code)
            return // success, exit early
          } catch (error) {
            // continue to next mechanism
            continue
          }
        }

        // if we get here, none of the mechanisms worked
        await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.TwoFactorFailed, this.req, false, { mechanism: "otp", reason: "invalid_code" })
        throw new InvalidTwoFactorCodeError()
      },
    }
  }

  /**
   * @returns {number | null}
   */
  getAccountId() {
    return this.req.session?.auth?.accountId || null
  }

  /**
   * @returns {string | null}
   */
  getEmail() {
    return this.req.session?.auth?.email || null
  }

  // status queries

  /**
   * Whether the current account has any verified 2FA method.
   * @returns {Promise<boolean>}
   */
  async isEnabled() {
    const accountId = this.getAccountId()
    if (!accountId) return false

    const methods = await this.queries.findTwoFactorMethodsByAccountId(accountId)
    return methods.some((method) => method.verified)
  }

  /**
   * Whether the current account has TOTP enabled.
   * @returns {Promise<boolean>}
   */
  async totpEnabled() {
    const accountId = this.getAccountId()
    if (!accountId) return false

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.TOTP)
    return method?.verified || false
  }

  /**
   * Whether the current account has email 2FA enabled.
   * @returns {Promise<boolean>}
   */
  async emailEnabled() {
    const accountId = this.getAccountId()
    if (!accountId) return false

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.EMAIL)
    return method?.verified || false
  }

  /**
   * Whether the current account has SMS 2FA enabled.
   * @returns {Promise<boolean>}
   */
  async smsEnabled() {
    const accountId = this.getAccountId()
    if (!accountId) return false

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.SMS)
    return method?.verified || false
  }

  /**
   * List the verified 2FA mechanisms for the current account.
   * @returns {Promise<number[]>}
   */
  async getEnabledMethods() {
    const accountId = this.getAccountId()
    if (!accountId) return []

    const methods = await this.queries.findTwoFactorMethodsByAccountId(accountId)
    return methods.filter((method) => method.verified).map((method) => method.mechanism)
  }

  /**
   * Stash the OTP selector issued during email/sms setup so complete() can find
   * it on the follow-up request. Selectors live in the session, never reach the
   * client, and point at the hashed token verifyOTP consumes.
   * @param {number} mechanism EMAIL or SMS
   * @param {string} selector
   */
  storeSetupSelector(mechanism, selector) {
    if (!this.req.session?.auth) return
    const key = mechanism === TwoFactorMechanism.EMAIL ? "email" : "sms"
    this.req.session.auth.twoFactorSetup = {
      ...(this.req.session.auth.twoFactorSetup || {}),
      [key]: selector,
    }
  }

  /**
   * Complete email/SMS setup by verifying the OTP that setup issued. Marks the
   * method verified only when the supplied code matches the stored token.
   * @param {number} mechanism EMAIL or SMS
   * @param {string} code
   * @returns {Promise<void>}
   * @throws {UserNotLoggedInError|TwoFactorNotSetupError|TwoFactorAlreadyEnabledError|InvalidTwoFactorCodeError}
   */
  async completeOtpSetup(mechanism, code) {
    const accountId = this.getAccountId()

    if (!accountId) {
      throw new UserNotLoggedInError()
    }

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, mechanism)

    if (!method) {
      throw new TwoFactorNotSetupError()
    }

    if (method.verified) {
      throw new TwoFactorAlreadyEnabledError()
    }

    const key = mechanism === TwoFactorMechanism.EMAIL ? "email" : "sms"
    const selector = this.req.session?.auth?.twoFactorSetup?.[key]

    // no selector means setup was never started with verification (or it expired
    // out of the session) - there is nothing to validate the code against, so
    // fail closed rather than enabling the method
    const { isValid } = selector ? await this.otpProvider.verifyOTP(selector, code) : { isValid: false }

    if (!isValid) {
      await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorFailed, this.req, false, { mechanism: key, reason: "invalid_code" })
      throw new InvalidTwoFactorCodeError()
    }

    // clear the consumed selector
    if (this.req.session?.auth?.twoFactorSetup) {
      delete this.req.session.auth.twoFactorSetup[key]
    }

    await this.queries.updateTwoFactorMethod(method.id, {
      verified: true,
      last_used_at: new Date(),
    })

    await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorSetup, this.req, true, { mechanism: key })
  }

  /**
   * Verify an email/SMS OTP using the selector stored during login.
   * @param {number} mechanism EMAIL or SMS
   * @param {string} code
   * @returns {Promise<void>}
   * @throws {UserNotLoggedInError|TwoFactorNotSetupError|InvalidTwoFactorCodeError}
   */
  async verifyOtp(mechanism, code) {
    const twoFactorState = this.req.session?.auth?.awaitingTwoFactor

    if (!twoFactorState) {
      throw new UserNotLoggedInError()
    }

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(twoFactorState.accountId, mechanism)

    if (!method || !method.verified) {
      throw new TwoFactorNotSetupError()
    }

    // find the selector that was stored during login attempt
    const selector = mechanism === TwoFactorMechanism.EMAIL ? this.req.session?.auth?.awaitingTwoFactor?.selectors?.email : this.req.session?.auth?.awaitingTwoFactor?.selectors?.sms

    if (!selector) {
      throw new InvalidTwoFactorCodeError()
    }

    const { isValid } = await this.otpProvider.verifyOTP(selector, code)

    if (!isValid) {
      await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.TwoFactorFailed, this.req, false, {
        mechanism: mechanism === TwoFactorMechanism.EMAIL ? "email" : "sms",
        reason: "invalid_code",
      })
      throw new InvalidTwoFactorCodeError()
    }

    // update last used
    await this.queries.updateTwoFactorMethod(method.id, {
      last_used_at: new Date(),
    })

    await this.activityLogger.logActivity(twoFactorState.accountId, AuthActivityAction.TwoFactorVerified, this.req, true, { mechanism: mechanism === TwoFactorMechanism.EMAIL ? "email" : "sms" })
  }

  // management

  /**
   * Disable a 2FA mechanism for the current account.
   * @param {number} mechanism
   * @returns {Promise<void>}
   * @throws {UserNotLoggedInError|TwoFactorNotSetupError}
   */
  async disable(mechanism) {
    const accountId = this.getAccountId()

    if (!accountId) {
      throw new UserNotLoggedInError()
    }

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, mechanism)

    if (!method) {
      throw new TwoFactorNotSetupError()
    }

    await this.queries.deleteTwoFactorMethod(method.id)

    await this.activityLogger.logActivity(accountId, AuthActivityAction.TwoFactorDisabled, this.req, true, {
      mechanism: mechanism === TwoFactorMechanism.TOTP ? "totp" : mechanism === TwoFactorMechanism.EMAIL ? "email" : "sms",
    })
  }

  /**
   * Regenerate and store new backup codes for the TOTP method.
   * @returns {Promise<string[]>}
   * @throws {UserNotLoggedInError|TwoFactorNotSetupError}
   */
  async generateNewBackupCodes() {
    const accountId = this.getAccountId()

    if (!accountId) {
      throw new UserNotLoggedInError()
    }

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.TOTP)

    if (!method || !method.verified) {
      throw new TwoFactorNotSetupError()
    }

    const backupCodesCount = this.config.twoFactor?.backupCodesCount || 10
    const backupCodes = this.totpProvider.generateBackupCodes(backupCodesCount)
    const hashedBackupCodes = await this.totpProvider.hashBackupCodes(backupCodes)

    await this.queries.updateTwoFactorMethod(method.id, {
      backup_codes: hashedBackupCodes,
    })

    return backupCodes
  }

  /**
   * Get the stored contact (email/phone) for an OTP mechanism.
   * @param {number} mechanism EMAIL or SMS
   * @returns {Promise<string | null>}
   */
  async getContact(mechanism) {
    const accountId = this.getAccountId()

    if (!accountId) {
      return null
    }

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, mechanism)

    return method?.secret || null
  }

  /**
   * Build the otpauth:// URI for the current account's TOTP secret.
   * @returns {Promise<string | null>}
   */
  async getTotpUri() {
    const accountId = this.getAccountId()
    const email = this.getEmail()

    if (!accountId || !email) {
      return null
    }

    const method = await this.queries.findTwoFactorMethodByAccountAndMechanism(accountId, TwoFactorMechanism.TOTP)

    if (!method?.secret) {
      return null
    }

    return this.totpProvider.generateQRCode(email, method.secret)
  }

  // challenge creation (used during login)

  /**
   * Build a 2FA challenge for an account, issuing OTPs for email/SMS methods.
   * @param {number} accountId
   * @returns {Promise<TwoFactorChallenge>}
   */
  async createChallenge(accountId) {
    const methods = await this.queries.findTwoFactorMethodsByAccountId(accountId)
    const verifiedMethods = methods.filter((method) => method.verified)

    /** @type {TwoFactorChallenge} */
    const challenge = {
      selectors: {},
    }

    for (const method of verifiedMethods) {
      switch (method.mechanism) {
        case TwoFactorMechanism.TOTP:
          challenge.totp = true
          break

        case TwoFactorMechanism.EMAIL:
          if (method.secret) {
            const { otp, selector } = await this.otpProvider.createAndStoreOTP(accountId, method.mechanism)
            challenge.email = {
              otpValue: otp,
              maskedContact: this.otpProvider.maskEmail(method.secret),
            }
            challenge.selectors.email = selector
          }
          break

        case TwoFactorMechanism.SMS:
          if (method.secret) {
            const { otp, selector } = await this.otpProvider.createAndStoreOTP(accountId, method.mechanism)
            challenge.sms = {
              otpValue: otp,
              maskedContact: this.otpProvider.maskPhone(method.secret),
            }
            challenge.selectors.sms = selector
          }
          break
      }
    }

    return challenge
  }
}
