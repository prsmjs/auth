import hash from "@prsm/hash"
import ms from "@prsm/ms"
import { AuthStatus, AuthRole, AuthActivityAction } from "./types.js"
import { AuthQueries } from "./queries.js"
import { ActivityLogger } from "./activity-logger.js"
import { wasInvalidatedSince } from "./invalidation.js"
import { validateEmail, createMapFromEnum } from "./util.js"
import {
  ConfirmationExpiredError,
  ConfirmationNotFoundError,
  EmailNotVerifiedError,
  EmailTakenError,
  InvalidPasswordError,
  InvalidTokenError,
  ResetDisabledError,
  ResetExpiredError,
  ResetNotFoundError,
  TooManyResetsError,
  UserInactiveError,
  UserNotFoundError,
  UserNotLoggedInError,
  SecondFactorRequiredError,
  TwoFactorExpiredError,
  ImpersonationDisabledError,
  ImpersonationNotAllowedError,
  AlreadyImpersonatingError,
  NotImpersonatingError,
  RateLimitedError,
} from "./errors.js"
import { GitHubProvider, GoogleProvider, AzureProvider } from "./providers/index.js"
import { TwoFactorManager } from "./two-factor/index.js"
import * as authFunctions from "./auth-functions.js"
import { withSpan, consumeLimit } from "./hooks.js"

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 * @typedef {import("./types.js").AuthAccount} AuthAccount
 * @typedef {import("./types.js").AuthSession} AuthSession
 * @typedef {import("./types.js").TokenCallback} TokenCallback
 * @typedef {import("./types.js").OAuthProvider} OAuthProvider
 * @typedef {import("./types.js").StartImpersonationOptions} StartImpersonationOptions
 * @typedef {import("./types.js").ImpersonationInfo} ImpersonationInfo
 * @typedef {import("./types.js").ImpersonationActor} ImpersonationActor
 * @typedef {import("./types.js").UserIdentifier} UserIdentifier
 */

export class AuthManager {
  /**
   * @param {import("express").Request} req
   * @param {import("express").Response} res
   * @param {AuthConfig} config
   */
  constructor(req, res, config) {
    this.req = req
    this.res = res
    this.config = config
    this.queries = new AuthQueries(config)
    this.activityLogger = new ActivityLogger(config)
    this.providers = this.initializeProviders()
    this.twoFactor = new TwoFactorManager(req, res, config)
  }

  initializeProviders() {
    const providers = {}

    if (this.config.providers?.github) {
      providers.github = new GitHubProvider(this.config.providers.github, this.config, this)
    }

    if (this.config.providers?.google) {
      providers.google = new GoogleProvider(this.config.providers.google, this.config, this)
    }

    if (this.config.providers?.azure) {
      providers.azure = new AzureProvider(this.config.providers.azure, this.config, this)
    }

    return providers
  }

  generateAutoUserId() {
    return crypto.randomUUID()
  }

  async shouldRequire2FA(account) {
    // skip 2FA for OAuth users unless explicitly configured
    const providers = await this.queries.findProvidersByAccountId(account.id)
    const hasOAuthProviders = providers.length > 0

    if (hasOAuthProviders && !this.config.twoFactor?.requireForOAuth) {
      return false
    }
    return true
  }

  validatePassword(password) {
    const minLength = this.config.minPasswordLength || 8
    const maxLength = this.config.maxPasswordLength || 64

    if (typeof password !== "string") {
      throw new InvalidPasswordError()
    }

    if (password.length < minLength) {
      throw new InvalidPasswordError()
    }

    if (password.length > maxLength) {
      throw new InvalidPasswordError()
    }
  }

  getRoleMap() {
    return createMapFromEnum(this.config.roles || AuthRole)
  }

  getStatusMap() {
    return createMapFromEnum(AuthStatus)
  }

  async getAuthAccount() {
    if (!this.req.session?.auth?.accountId) {
      return null
    }

    return await this.queries.findAccountById(this.req.session.auth.accountId)
  }

  setRememberCookie(token, expires) {
    const cookieName = this.config.rememberCookieName || "remember_token"
    const cookieConfig = this.config.cookie || {}

    if (token === null) {
      this.res.clearCookie(cookieName, {
        domain: cookieConfig.domain,
        secure: cookieConfig.secure ?? this.req.secure,
        sameSite: cookieConfig.sameSite,
      })
    } else {
      this.res.cookie(cookieName, token, {
        expires,
        httpOnly: true,
        secure: cookieConfig.secure ?? this.req.secure,
        domain: cookieConfig.domain,
        sameSite: cookieConfig.sameSite,
      })
    }
  }

  getRememberToken() {
    const { cookies } = this.req
    if (!cookies) {
      return { token: null }
    }

    const cookieName = this.config.rememberCookieName || "remember_token"
    const token = cookies[cookieName]

    return { token: token || null }
  }

  async regenerateSession() {
    const { auth } = this.req.session

    return new Promise((resolve, reject) => {
      this.req.session.regenerate((err) => {
        if (err) {
          reject(err)
          return
        }
        this.req.session.auth = auth
        resolve()
      })
    })
  }

  /**
   * Resync the current session against the persisted account state.
   * @param {boolean} [force=false]
   * @returns {Promise<void>}
   */
  async resyncSession(force = false) {
    if (!this.isLoggedIn()) {
      return
    }

    if (this.req.session.auth.shouldForceLogout) {
      await this.logout()
      return
    }

    const interval = ms(this.config.resyncInterval || "30s")
    const lastResync = new Date(this.req.session.auth.lastResync)

    if (!force && lastResync && lastResync.getTime() > Date.now() - interval) {
      // honor the interval unless another instance signaled this account invalid
      // more recently than our last resync (cross-instance LISTEN/NOTIFY)
      if (!wasInvalidatedSince(this.config, this.req.session.auth.accountId, lastResync.getTime())) {
        return
      }
    }

    if (this.isImpersonating()) {
      const actorSnapshot = this.req.session.auth.actor

      // expiry first - revert to actor before any other action
      if (actorSnapshot.expiresAt && new Date() >= new Date(actorSnapshot.expiresAt)) {
        await this.stopImpersonationInternal("expired")
        return
      }

      const actorAccount = await this.queries.findAccountById(actorSnapshot.accountId)
      if (!actorAccount || actorAccount.status !== AuthStatus.Normal || actorAccount.force_logout > actorSnapshot.forceLogout) {
        // actor is no longer valid - kill the whole session.
        // clear actor first so the Logout activity row doesn't reference a deleted/invalid actor via FK
        this.req.session.auth.actor = undefined
        await this.logout()
        return
      }

      // target may have been modified by the admin while impersonating; refresh effective fields
      const target = await this.queries.findAccountById(this.req.session.auth.accountId)
      if (!target) {
        // target deleted mid-impersonation - revert to actor
        await this.stopImpersonationInternal("target_gone")
        return
      }

      this.req.session.auth.email = target.email
      this.req.session.auth.status = target.status
      this.req.session.auth.rolemask = target.rolemask
      this.req.session.auth.verified = target.verified
      this.req.session.auth.hasPassword = target.password !== null
      this.req.session.auth.lastResync = new Date()
      return
    }

    const account = await this.getAuthAccount()

    if (!account) {
      await this.logout()
      return
    }

    if (account.force_logout > this.req.session.auth.forceLogout) {
      await this.logout()
      return
    }

    this.req.session.auth.shouldForceLogout = false
    this.req.session.auth.email = account.email
    this.req.session.auth.status = account.status
    this.req.session.auth.rolemask = account.rolemask
    this.req.session.auth.verified = account.verified
    this.req.session.auth.hasPassword = account.password !== null
    this.req.session.auth.lastResync = new Date()
  }

  /**
   * Restore a session from a valid remember token when not already logged in.
   * @returns {Promise<void>}
   */
  async processRememberDirective() {
    if (this.isLoggedIn()) {
      return
    }

    const { token } = this.getRememberToken()
    if (!token) {
      return
    }

    const remember = await this.queries.findRememberToken(token)
    if (!remember) {
      this.setRememberCookie(null, new Date(0))
      return
    }

    // expired?
    if (new Date() > remember.expires) {
      await this.queries.deleteRememberToken(token)
      this.setRememberCookie(null, new Date(0))
      return
    }

    // clean up expired tokens for this account
    await this.queries.deleteExpiredRememberTokensForAccount(remember.account_id)

    // get the account and log in
    const account = await this.queries.findAccountById(remember.account_id)
    if (!account) {
      await this.queries.deleteRememberToken(token)
      this.setRememberCookie(null, new Date(0))
      return
    }

    // pass false to avoid creating a new remember token - we're restoring from an existing one
    await this.onLoginSuccessful(account, false)
  }

  async onLoginSuccessful(account, remember = false) {
    await this.queries.updateAccountLastLogin(account.id)

    return new Promise((resolve, reject) => {
      if (!this.req.session?.regenerate) {
        resolve()
        return
      }

      this.req.session.regenerate(async (err) => {
        if (err) {
          reject(err)
          return
        }

        const session = {
          loggedIn: true,
          accountId: account.id,
          userId: account.user_id,
          email: account.email,
          status: account.status,
          rolemask: account.rolemask,
          remembered: remember,
          lastResync: new Date(),
          lastRememberCheck: new Date(),
          forceLogout: account.force_logout,
          verified: account.verified,
          hasPassword: account.password !== null,
          shouldForceLogout: false,
        }

        this.req.session.auth = session

        if (remember) {
          await this.createRememberDirective(account)
        }

        this.req.session.save((err) => {
          if (err) {
            reject(err)
            return
          }
          resolve()
        })
      })
    })
  }

  async createRememberDirective(account) {
    const token = await hash.encode(account.email)
    const duration = this.config.rememberDuration || "30d"
    const expires = new Date(Date.now() + ms(duration))

    await this.queries.createRememberToken({
      accountId: account.id,
      token,
      expires,
    })

    this.setRememberCookie(token, expires)

    await this.activityLogger.logActivity(account.id, AuthActivityAction.RememberTokenCreated, this.req, true, { email: account.email, duration })

    return token
  }

  /**
   * Check if the current user is logged in.
   * @returns {boolean} true if user has an active authenticated session
   */
  isLoggedIn() {
    return this.req.session?.auth?.loggedIn ?? false
  }

  /**
   * Authenticate user with email and password, creating a session.
   * @param {string} email
   * @param {string} password
   * @param {boolean} [remember=false]
   * @returns {Promise<void>}
   * @throws {UserNotFoundError} Account with this email doesn't exist
   * @throws {InvalidPasswordError} Password is incorrect
   * @throws {EmailNotVerifiedError} Account exists but email is not verified
   * @throws {UserInactiveError} Account is banned, locked, or otherwise inactive
   * @throws {SecondFactorRequiredError} Two-factor authentication is required
   */
  async login(email, password, remember = false) {
    return withSpan(this.config.tracer, "auth.login", { email }, async () => {
      // optional brute-force throttle, keyed by email; only active when a limiter
      // is configured. behavior is unchanged when absent
      if (this.config.limiter) {
        const result = await consumeLimit(this.config.limiter, `login:${email}`)
        if (result && result.allowed === false) {
          await this.activityLogger.logActivity(null, AuthActivityAction.FailedLogin, this.req, false, { email, reason: "rate_limited" })
          throw new RateLimitedError(result.retryAfter)
        }
      }

      const account = await this.queries.findAccountByEmail(email)

      if (!account) {
        await this.activityLogger.logActivity(null, AuthActivityAction.FailedLogin, this.req, false, { email, reason: "account_not_found" })
        throw new UserNotFoundError()
      }

      if (!account.password || !(await hash.verify(account.password, password))) {
        await this.activityLogger.logActivity(account.id, AuthActivityAction.FailedLogin, this.req, false, { email, reason: "invalid_password" })
        throw new InvalidPasswordError()
      }

      if (!account.verified) {
        await this.activityLogger.logActivity(account.id, AuthActivityAction.FailedLogin, this.req, false, { email, reason: "email_not_verified" })
        throw new EmailNotVerifiedError()
      }

      if (account.status !== AuthStatus.Normal) {
        await this.activityLogger.logActivity(account.id, AuthActivityAction.FailedLogin, this.req, false, { email, reason: "account_inactive", status: account.status })
        throw new UserInactiveError()
      }

      // check if 2FA is enabled and required for this user
      if (this.config.twoFactor?.enabled && (await this.shouldRequire2FA(account))) {
        const twoFactorMethods = await this.queries.findTwoFactorMethodsByAccountId(account.id)
        const enabledMethods = twoFactorMethods.filter((method) => method.verified)

        if (enabledMethods.length > 0) {
          // create 2FA challenge
          const challenge = await this.twoFactor.createChallenge(account.id)

          // set 2FA session state (user NOT logged in yet)
          const expiryDuration = this.config.twoFactor?.tokenExpiry || "5m"
          const expiresAt = new Date(Date.now() + ms(expiryDuration))

          this.req.session.auth = {
            loggedIn: false,
            accountId: 0,
            userId: "",
            email: "",
            status: 0,
            rolemask: 0,
            remembered: false,
            lastResync: new Date(),
            lastRememberCheck: new Date(),
            forceLogout: 0,
            verified: false,
            hasPassword: false,
            awaitingTwoFactor: {
              accountId: account.id,
              expiresAt,
              remember,
              availableMechanisms: enabledMethods.map((m) => m.mechanism),
              attemptedMechanisms: [],
              originalEmail: account.email,
              selectors: challenge.selectors,
            },
          }

          await this.activityLogger.logActivity(account.id, AuthActivityAction.TwoFactorFailed, this.req, true, { prompt: true, mechanisms: enabledMethods.map((m) => m.mechanism) })

          throw new SecondFactorRequiredError(challenge)
        }
      }

      await this.onLoginSuccessful(account, remember)
      await this.activityLogger.logActivity(account.id, AuthActivityAction.Login, this.req, true, { email, remember })
    })
  }

  /**
   * Complete two-factor authentication and log in the user.
   * @returns {Promise<void>}
   * @throws {TwoFactorExpiredError} No pending 2FA state or it has expired
   * @throws {UserNotFoundError} Associated account no longer exists
   */
  async completeTwoFactorLogin() {
    const twoFactorState = this.req.session?.auth?.awaitingTwoFactor

    if (!twoFactorState) {
      throw new TwoFactorExpiredError()
    }

    // check if the 2FA session has expired
    if (twoFactorState.expiresAt <= new Date()) {
      // clear expired 2FA state
      delete this.req.session.auth.awaitingTwoFactor
      throw new TwoFactorExpiredError()
    }

    // get the account that was awaiting 2FA
    const account = await this.queries.findAccountById(twoFactorState.accountId)
    if (!account) {
      delete this.req.session.auth.awaitingTwoFactor
      throw new UserNotFoundError()
    }

    // complete the login process
    await this.onLoginSuccessful(account, twoFactorState.remember)

    // clear the 2FA state
    delete this.req.session.auth.awaitingTwoFactor

    await this.activityLogger.logActivity(account.id, AuthActivityAction.Login, this.req, true, { email: account.email, remember: twoFactorState.remember, twoFactorCompleted: true })
  }

  /**
   * Log out the current user, clearing the session and remember tokens.
   * @returns {Promise<void>}
   */
  async logout() {
    if (!this.isLoggedIn()) {
      return
    }

    const accountId = this.getId()
    const email = this.getEmail()
    const { token } = this.getRememberToken()

    if (token) {
      await this.queries.deleteRememberToken(token)
      this.setRememberCookie(null, new Date(0))
    }

    // log BEFORE clearing the session so actor_account_id auto-pickup catches
    // impersonation context (e.g. forced logout while impersonating)
    if (accountId && email) {
      await this.activityLogger.logActivity(accountId, AuthActivityAction.Logout, this.req, true, { email })
    }

    this.req.session.auth = undefined
  }

  /**
   * Register a new account.
   * @param {string} email
   * @param {string} password
   * @param {string|number} [userId] Optional user ID to link; a UUID is generated if omitted
   * @param {TokenCallback} [callback] If provided, account is created unverified and callback receives the confirmation token
   * @returns {Promise<AuthAccount>} The created account record
   * @throws {EmailTakenError} Email is already registered
   * @throws {InvalidPasswordError} Password doesn't meet length requirements
   */
  async register(email, password, userId, callback) {
    validateEmail(email)
    this.validatePassword(password)

    const existing = await this.queries.findAccountByEmail(email)
    if (existing) {
      throw new EmailTakenError()
    }

    const finalUserId = userId || this.generateAutoUserId()

    const hashedPassword = await hash.encode(password)
    const verified = typeof callback !== "function"

    const account = await this.queries.createAccount({
      userId: finalUserId,
      email,
      password: hashedPassword,
      verified,
      status: AuthStatus.Normal,
      rolemask: 0,
    })

    if (!verified && callback) {
      await this.createConfirmationToken(account, email, callback)
    }

    await this.activityLogger.logActivity(account.id, AuthActivityAction.Register, this.req, true, { email, verified, userId: finalUserId })

    return account
  }

  async createConfirmationToken(account, email, callback) {
    const token = await hash.encode(email)
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7) // 1 week

    await this.queries.createConfirmation({
      accountId: account.id,
      token,
      email,
      expires,
    })

    if (callback) {
      callback(token)
    }
  }

  /**
   * Get the current user's account ID.
   * @returns {number|null} Account ID if logged in, null otherwise
   */
  getId() {
    return this.req.session?.auth?.accountId || null
  }

  /**
   * Get the current user's email address.
   * @returns {string|null} Email if logged in, null otherwise
   */
  getEmail() {
    return this.req.session?.auth?.email || null
  }

  /**
   * Get the current user's account status.
   * @returns {number|null} Status number if logged in, null otherwise
   */
  getStatus() {
    return this.req.session?.auth?.status ?? null
  }

  /**
   * Check if the current user's email is verified.
   * @returns {boolean|null} true if verified, false if unverified, null if not logged in
   */
  getVerified() {
    return this.req.session?.auth?.verified ?? null
  }

  /**
   * Check if the current user has a password set.
   * @returns {boolean|null} true if user has a password, false if OAuth-only, null if not logged in
   */
  hasPassword() {
    return this.req.session?.auth?.hasPassword ?? null
  }

  /**
   * Get human-readable role names for the current user or a specific rolemask.
   * @param {number} [rolemask] Optional rolemask; defaults to the current user's roles
   * @returns {string[]} Array of role names
   */
  getRoleNames(rolemask) {
    const mask = rolemask !== undefined ? rolemask : (this.req.session?.auth?.rolemask ?? 0)

    if (!mask && mask !== 0) {
      return []
    }

    return Object.entries(this.getRoleMap())
      .filter(([key]) => mask & parseInt(key))
      .map(([, value]) => value)
  }

  /**
   * Get the human-readable status name for the current user.
   * @returns {string|null} Status name if logged in, null otherwise
   */
  getStatusName() {
    const status = this.getStatus()
    if (status === null) return null
    return this.getStatusMap()[status] || null
  }

  /**
   * Check if the current user has a specific role.
   * @param {number} role Role bitmask to check
   * @returns {Promise<boolean>} true if user has the role, false otherwise
   */
  async hasRole(role) {
    if (this.req.session?.auth) {
      return (this.req.session.auth.rolemask & role) === role
    }

    const account = await this.getAuthAccount()
    return account ? (account.rolemask & role) === role : false
  }

  /**
   * Check if the current user has admin privileges.
   * @returns {Promise<boolean>} true if user has Admin role, false otherwise
   */
  async isAdmin() {
    return this.hasRole(AuthRole.Admin)
  }

  /**
   * Check if the current user was automatically logged in via remember token.
   * @returns {boolean} true if auto-logged in from a persistent cookie, false otherwise
   */
  isRemembered() {
    return this.req.session?.auth?.remembered ?? false
  }

  /**
   * Request an email change for the current user, sending a confirmation token.
   * @param {string} newEmail
   * @param {TokenCallback} callback Called with the confirmation token
   * @returns {Promise<void>}
   * @throws {UserNotLoggedInError} User is not logged in
   * @throws {EmailTakenError} New email is already registered
   * @throws {UserNotFoundError} Current user account not found
   * @throws {EmailNotVerifiedError} Current account's email is not verified
   */
  async changeEmail(newEmail, callback) {
    if (!this.isLoggedIn()) {
      throw new UserNotLoggedInError()
    }

    validateEmail(newEmail)

    const existing = await this.queries.findAccountByEmail(newEmail)
    if (existing) {
      throw new EmailTakenError()
    }

    const account = await this.getAuthAccount()
    if (!account) {
      throw new UserNotFoundError()
    }

    if (!account.verified) {
      throw new EmailNotVerifiedError()
    }

    await this.createConfirmationToken(account, newEmail, callback)
  }

  /**
   * Confirm an email address using a token from registration or email change.
   * @param {string} token
   * @returns {Promise<string>} The confirmed email address
   * @throws {ConfirmationNotFoundError} Token is invalid or doesn't exist
   * @throws {ConfirmationExpiredError} Token has expired
   * @throws {InvalidTokenError} Token format is invalid
   */
  async confirmEmail(token) {
    const confirmation = await this.queries.findConfirmation(token)

    if (!confirmation) {
      throw new ConfirmationNotFoundError()
    }

    if (new Date(confirmation.expires) < new Date()) {
      throw new ConfirmationExpiredError()
    }

    if (!(await hash.verify(token, confirmation.email))) {
      throw new InvalidTokenError()
    }

    await this.queries.updateAccount(confirmation.account_id, {
      verified: true,
      email: confirmation.email,
    })

    if (this.isLoggedIn() && this.req.session?.auth?.accountId === confirmation.account_id) {
      this.req.session.auth.verified = true
      this.req.session.auth.email = confirmation.email
    }

    await this.queries.deleteConfirmation(token)

    await this.activityLogger.logActivity(confirmation.account_id, AuthActivityAction.EmailConfirmed, this.req, true, { email: confirmation.email })

    return confirmation.email
  }

  /**
   * Confirm an email address and automatically log in the user.
   * @param {string} token
   * @param {boolean} [remember=false]
   * @returns {Promise<void>}
   * @throws {ConfirmationNotFoundError} Token is invalid or doesn't exist
   * @throws {ConfirmationExpiredError} Token has expired
   * @throws {InvalidTokenError} Token format is invalid
   * @throws {UserNotFoundError} Associated account no longer exists
   * @throws {SecondFactorRequiredError} Two-factor authentication is required
   */
  async confirmEmailAndLogin(token, remember = false) {
    const email = await this.confirmEmail(token)

    if (this.isLoggedIn()) {
      return
    }

    const account = await this.queries.findAccountByEmail(email)
    if (!account) {
      throw new UserNotFoundError()
    }

    // check if 2FA is enabled and required for this user
    if (this.config.twoFactor?.enabled && (await this.shouldRequire2FA(account))) {
      const twoFactorMethods = await this.queries.findTwoFactorMethodsByAccountId(account.id)
      const enabledMethods = twoFactorMethods.filter((method) => method.verified)

      if (enabledMethods.length > 0) {
        // create 2FA challenge
        const challenge = await this.twoFactor.createChallenge(account.id)

        // set 2FA session state (user NOT logged in yet)
        const expiryDuration = this.config.twoFactor?.tokenExpiry || "5m"
        const expiresAt = new Date(Date.now() + ms(expiryDuration))

        this.req.session.auth = {
          loggedIn: false,
          accountId: 0,
          userId: "",
          email: "",
          status: 0,
          rolemask: 0,
          remembered: false,
          lastResync: new Date(),
          lastRememberCheck: new Date(),
          forceLogout: 0,
          verified: false,
          hasPassword: false,
          awaitingTwoFactor: {
            accountId: account.id,
            expiresAt,
            remember,
            availableMechanisms: enabledMethods.map((m) => m.mechanism),
            attemptedMechanisms: [],
            originalEmail: account.email,
            selectors: challenge.selectors,
          },
        }

        await this.activityLogger.logActivity(account.id, AuthActivityAction.TwoFactorFailed, this.req, true, { prompt: true, mechanisms: enabledMethods.map((m) => m.mechanism) })

        throw new SecondFactorRequiredError(challenge)
      }
    }

    await this.onLoginSuccessful(account, remember)
  }

  /**
   * Initiate a password reset for a user, creating a reset token.
   * @param {string} email
   * @param {string|number|null} [expiresAfter=null] Token expiration (default 6h)
   * @param {number|null} [maxOpenRequests=null] Maximum concurrent reset tokens (default 2)
   * @param {TokenCallback} [callback] Called with the reset token
   * @returns {Promise<void>}
   * @throws {EmailNotVerifiedError} Account doesn't exist or email not verified
   * @throws {ResetDisabledError} Account has password reset disabled
   * @throws {TooManyResetsError} Too many active reset requests
   */
  async resetPassword(email, expiresAfter = null, maxOpenRequests = null, callback) {
    validateEmail(email)

    const expiry = !expiresAfter ? ms("6h") : ms(expiresAfter)
    const maxRequests = maxOpenRequests === null ? 2 : Math.max(1, maxOpenRequests)

    const account = await this.queries.findAccountByEmail(email)

    if (!account || !account.verified) {
      throw new EmailNotVerifiedError()
    }

    if (!account.resettable) {
      throw new ResetDisabledError()
    }

    const openRequests = await this.queries.countActiveResetTokensForAccount(account.id)

    if (openRequests >= maxRequests) {
      throw new TooManyResetsError()
    }

    const token = await hash.encode(email)
    const expires = new Date(Date.now() + expiry)

    await this.queries.createResetToken({
      accountId: account.id,
      token,
      expires,
    })

    await this.activityLogger.logActivity(account.id, AuthActivityAction.PasswordResetRequested, this.req, true, { email })

    if (callback) {
      callback(token)
    }
  }

  /**
   * Complete a password reset using a reset token.
   * @param {string} token
   * @param {string} password New password (will be hashed)
   * @param {boolean} [logout=true] Whether to force logout all sessions
   * @returns {Promise<void>}
   * @throws {ResetNotFoundError} Token is invalid or doesn't exist
   * @throws {ResetExpiredError} Token has expired
   * @throws {UserNotFoundError} Associated account no longer exists
   * @throws {ResetDisabledError} Account has password reset disabled
   * @throws {InvalidPasswordError} New password doesn't meet requirements
   * @throws {InvalidTokenError} Token format is invalid
   */
  async confirmResetPassword(token, password, logout = true) {
    const reset = await this.queries.findResetToken(token)

    if (!reset) {
      throw new ResetNotFoundError()
    }

    if (new Date(reset.expires) < new Date()) {
      throw new ResetExpiredError()
    }

    const account = await this.queries.findAccountById(reset.account_id)
    if (!account) {
      throw new UserNotFoundError()
    }

    if (!account.resettable) {
      throw new ResetDisabledError()
    }

    this.validatePassword(password)

    if (!(await hash.verify(token, account.email))) {
      throw new InvalidTokenError()
    }

    await this.queries.updateAccount(account.id, {
      password: await hash.encode(password),
    })

    if (logout) {
      await this.forceLogoutForAccountById(account.id)
    }

    await this.queries.deleteResetToken(token)

    await this.activityLogger.logActivity(account.id, AuthActivityAction.PasswordResetCompleted, this.req, true, { email: account.email })
  }

  /**
   * Verify if a password matches the current user's password.
   * @param {string} password
   * @returns {Promise<boolean>} true if password matches, false otherwise
   * @throws {UserNotLoggedInError} User is not logged in
   * @throws {UserNotFoundError} Current user account not found
   */
  async verifyPassword(password) {
    if (!this.isLoggedIn()) {
      throw new UserNotLoggedInError()
    }

    const account = await this.getAuthAccount()

    if (!account) {
      throw new UserNotFoundError()
    }

    if (!account.password) {
      return false // OAuth users don't have passwords
    }

    return await hash.verify(account.password, password)
  }

  async forceLogoutForAccountById(accountId) {
    await this.queries.deleteRememberTokensForAccount(accountId)
    await this.queries.incrementForceLogout(accountId)
  }

  /**
   * Force logout all other sessions while keeping the current one active.
   * @returns {Promise<void>}
   */
  async logoutEverywhereElse() {
    if (!this.isLoggedIn()) {
      return
    }

    const accountId = this.getId()
    if (!accountId) {
      return
    }

    const account = await this.queries.findAccountById(accountId)
    if (!account) {
      await this.logout()
      return
    }

    await this.forceLogoutForAccountById(accountId)

    this.req.session.auth.forceLogout += 1

    await this.regenerateSession()
  }

  /**
   * Force logout all sessions including the current one.
   * @returns {Promise<void>}
   */
  async logoutEverywhere() {
    if (!this.isLoggedIn()) {
      return
    }

    await this.logoutEverywhereElse()
    await this.logout()
  }

  async findAccountByIdentifier(identifier) {
    if (identifier.accountId !== undefined) {
      return await this.queries.findAccountById(identifier.accountId)
    } else if (identifier.email !== undefined) {
      return await this.queries.findAccountByEmail(identifier.email)
    } else if (identifier.userId !== undefined) {
      return await this.queries.findAccountByUserId(identifier.userId)
    }

    return null
  }

  // admin/standalone functions (delegated to auth-functions.js due to lack of need for request context)

  /**
   * Create a user account (admin function).
   * @param {{ email: string, password: string }} credentials
   * @param {string|number} [userId]
   * @param {TokenCallback} [callback]
   * @returns {Promise<AuthAccount>}
   */
  async createUser(credentials, userId, callback) {
    return authFunctions.createUser(this.config, credentials, userId, callback)
  }

  /**
   * Delete a user account by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @returns {Promise<void>}
   */
  async deleteUserBy(identifier) {
    return authFunctions.deleteUserBy(this.config, identifier)
  }

  /**
   * Add a role for a user by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @param {number} role
   * @returns {Promise<void>}
   */
  async addRoleForUserBy(identifier, role) {
    return authFunctions.addRoleForUserBy(this.config, identifier, role)
  }

  /**
   * Remove a role for a user by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @param {number} role
   * @returns {Promise<void>}
   */
  async removeRoleForUserBy(identifier, role) {
    return authFunctions.removeRoleForUserBy(this.config, identifier, role)
  }

  /**
   * Check whether a user has a role by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @param {number} role
   * @returns {Promise<boolean>}
   */
  async hasRoleForUserBy(identifier, role) {
    return authFunctions.hasRoleForUserBy(this.config, identifier, role)
  }

  /**
   * Change a user's password by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @param {string} password
   * @returns {Promise<void>}
   */
  async changePasswordForUserBy(identifier, password) {
    return authFunctions.changePasswordForUserBy(this.config, identifier, password)
  }

  /**
   * Set a user's status by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @param {number} status
   * @returns {Promise<void>}
   */
  async setStatusForUserBy(identifier, status) {
    return authFunctions.setStatusForUserBy(this.config, identifier, status)
  }

  /**
   * Initiate a password reset for a user by identifier (admin function).
   * @param {UserIdentifier} identifier
   * @param {string|number|null} [expiresAfter]
   * @param {TokenCallback} [callback]
   * @returns {Promise<void>}
   */
  async initiatePasswordResetForUserBy(identifier, expiresAfter, callback) {
    return authFunctions.initiatePasswordResetForUserBy(this.config, identifier, expiresAfter, callback)
  }

  /**
   * Check whether a user exists by email (admin function).
   * @param {string} email
   * @returns {Promise<boolean>}
   */
  async userExistsByEmail(email) {
    return authFunctions.userExistsByEmail(this.config, email)
  }

  /**
   * Force logout a user by identifier; flags the current session if it is owned by that user.
   * @param {UserIdentifier} identifier
   * @returns {Promise<void>}
   */
  async forceLogoutForUserBy(identifier) {
    const result = await authFunctions.forceLogoutForUserBy(this.config, identifier)

    // the question is "did the owner of this session get force-logged-out?"
    // when impersonating, the session is owned by the actor, not the effective (target) identity.
    // force-logging-out the target should NOT kick the admin who is impersonating them.
    const sessionOwnerId = this.isImpersonating() ? this.getActorId() : this.getId()
    if (sessionOwnerId === result.accountId) {
      this.req.session.auth.shouldForceLogout = true
    }
  }

  /**
   * Log in as another user (admin function), replacing the current session.
   * @param {UserIdentifier} identifier
   * @returns {Promise<void>}
   * @throws {UserNotFoundError} No account matches the identifier
   */
  async loginAsUserBy(identifier) {
    const account = await this.findAccountByIdentifier(identifier)

    if (!account) {
      throw new UserNotFoundError()
    }

    await this.onLoginSuccessful(account, false)
  }

  /**
   * Check whether the current session is impersonating another user.
   * @returns {boolean}
   */
  isImpersonating() {
    return !!this.req.session?.auth?.actor
  }

  /**
   * Get the account id of the original (actor) user when impersonating.
   * @returns {number|null} Actor account id when impersonating, null otherwise
   */
  getActorId() {
    return this.req.session?.auth?.actor?.accountId ?? null
  }

  /**
   * Get the email of the original (actor) user when impersonating.
   * @returns {string|null} Actor email when impersonating, null otherwise
   */
  getActorEmail() {
    return this.req.session?.auth?.actor?.email ?? null
  }

  /**
   * Get a structured summary of the current impersonation session.
   * @returns {ImpersonationInfo|null} ImpersonationInfo when impersonating, null otherwise
   */
  getImpersonationInfo() {
    const auth = this.req.session?.auth
    if (!auth?.actor) return null

    return {
      actor: {
        accountId: auth.actor.accountId,
        userId: auth.actor.userId,
        email: auth.actor.email,
        rolemask: auth.actor.rolemask,
      },
      target: {
        accountId: auth.accountId,
        userId: auth.userId,
        email: auth.email,
        rolemask: auth.rolemask,
      },
      startedAt: new Date(auth.actor.startedAt),
      expiresAt: auth.actor.expiresAt ? new Date(auth.actor.expiresAt) : undefined,
      reason: auth.actor.reason,
    }
  }

  /**
   * Begin impersonating another user while preserving the actor identity.
   * @param {UserIdentifier} identifier
   * @param {StartImpersonationOptions} [options={}]
   * @returns {Promise<void>}
   * @throws {UserNotLoggedInError} No active session
   * @throws {ImpersonationDisabledError} config.impersonation.enabled is false
   * @throws {AlreadyImpersonatingError} Another impersonation session is already active
   * @throws {UserNotFoundError} No account matches the identifier
   * @throws {ImpersonationNotAllowedError} canImpersonate returned false, or target is the actor
   */
  async startImpersonation(identifier, options = {}) {
    if (!this.isLoggedIn()) {
      throw new UserNotLoggedInError()
    }

    if (!this.config.impersonation?.enabled) {
      throw new ImpersonationDisabledError()
    }

    if (this.isImpersonating()) {
      throw new AlreadyImpersonatingError()
    }

    const actor = await this.getAuthAccount()
    if (!actor) {
      throw new UserNotFoundError()
    }

    const target = await this.findAccountByIdentifier(identifier)
    if (!target) {
      throw new UserNotFoundError()
    }

    if (target.id === actor.id) {
      await this.activityLogger.logActivity(actor.id, AuthActivityAction.ImpersonationRejected, this.req, false, { reason: "self_impersonation", targetAccountId: target.id })
      throw new ImpersonationNotAllowedError()
    }

    // fail closed if the policy hook throws - never silently allow impersonation when the
    // policy can't be evaluated. preserves the underlying error message in audit metadata.
    let allowed = false
    try {
      allowed = (await this.config.impersonation.canImpersonate?.(actor, target)) ?? false
    } catch (err) {
      await this.activityLogger.logActivity(actor.id, AuthActivityAction.ImpersonationRejected, this.req, false, {
        reason: "policy_error",
        targetAccountId: target.id,
        policyError: err?.message ?? String(err),
      })
      throw new ImpersonationNotAllowedError()
    }

    if (!allowed) {
      await this.activityLogger.logActivity(actor.id, AuthActivityAction.ImpersonationRejected, this.req, false, { reason: "denied", targetAccountId: target.id })
      throw new ImpersonationNotAllowedError()
    }

    // resolve ttl: explicit option wins, then config default, capped by config.maxTtl
    const requestedMs = options.ttl !== undefined ? ms(options.ttl) : this.config.impersonation.defaultTtl ? ms(this.config.impersonation.defaultTtl) : null
    const maxMs = this.config.impersonation.maxTtl ? ms(this.config.impersonation.maxTtl) : null
    const effectiveMs = requestedMs !== null && maxMs !== null ? Math.min(requestedMs, maxMs) : (requestedMs ?? maxMs)
    const expiresAt = effectiveMs !== null ? new Date(Date.now() + effectiveMs) : undefined

    const actorSnapshot = {
      accountId: actor.id,
      userId: actor.user_id,
      email: actor.email,
      rolemask: actor.rolemask,
      forceLogout: actor.force_logout,
      startedAt: new Date(),
      expiresAt,
      reason: options.reason,
    }

    const newSession = {
      loggedIn: true,
      accountId: target.id,
      userId: target.user_id,
      email: target.email,
      status: target.status,
      rolemask: target.rolemask,
      remembered: false,
      lastResync: new Date(),
      lastRememberCheck: new Date(),
      forceLogout: target.force_logout,
      verified: target.verified,
      hasPassword: target.password !== null,
      shouldForceLogout: false,
      actor: actorSnapshot,
    }

    await this.regenerateSessionWith(newSession)

    // logged after session mutation so actor_account_id auto-pickup resolves to the admin
    await this.activityLogger.logActivity(target.id, AuthActivityAction.ImpersonationStarted, this.req, true, {
      targetAccountId: target.id,
      targetEmail: target.email,
      reason: options.reason,
      expiresAt: expiresAt?.toISOString(),
    })
  }

  /**
   * Stop the current impersonation session and revert to the actor's identity.
   * @returns {Promise<void>}
   * @throws {NotImpersonatingError} No active impersonation session
   */
  async stopImpersonation() {
    if (!this.isImpersonating()) {
      throw new NotImpersonatingError()
    }
    await this.stopImpersonationInternal("manual")
  }

  // internal stop that also handles auto-revert paths (expiry, target_gone) from resync
  async stopImpersonationInternal(cause) {
    const actor = this.req.session.auth.actor
    const targetAccountId = this.req.session.auth.accountId
    const targetEmail = this.req.session.auth.email

    // log BEFORE clearing actor so the audit row carries actor_account_id.
    // when the target has been deleted the account_id FK would fail, so log against null in that case.
    const action = cause === "expired" ? AuthActivityAction.ImpersonationExpired : AuthActivityAction.ImpersonationStopped
    const logAccountId = cause === "target_gone" ? null : targetAccountId
    await this.activityLogger.logActivity(logAccountId, action, this.req, true, {
      targetAccountId,
      targetEmail,
      cause,
      startedAt: new Date(actor.startedAt).toISOString(),
    })

    const actorAccount = await this.queries.findAccountById(actor.accountId)
    if (!actorAccount) {
      // actor account is gone - nothing to revert to
      this.req.session.auth = undefined
      return
    }

    const newSession = {
      loggedIn: true,
      accountId: actorAccount.id,
      userId: actorAccount.user_id,
      email: actorAccount.email,
      status: actorAccount.status,
      rolemask: actorAccount.rolemask,
      remembered: false,
      lastResync: new Date(),
      lastRememberCheck: new Date(),
      forceLogout: actorAccount.force_logout,
      verified: actorAccount.verified,
      hasPassword: actorAccount.password !== null,
      shouldForceLogout: false,
    }

    await this.regenerateSessionWith(newSession)
  }

  async regenerateSessionWith(newAuth) {
    return new Promise((resolve, reject) => {
      if (!this.req.session?.regenerate) {
        this.req.session.auth = newAuth
        resolve()
        return
      }

      this.req.session.regenerate((err) => {
        if (err) {
          reject(err)
          return
        }
        this.req.session.auth = newAuth
        this.req.session.save((saveErr) => {
          if (saveErr) {
            reject(saveErr)
            return
          }
          resolve()
        })
      })
    })
  }
}
