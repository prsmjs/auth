import hash from "@prsm/hash"
import ms from "@prsm/ms"
import { AuthQueries } from "./queries.js"
import { validateEmail } from "./util.js"
import { EmailTakenError, InvalidPasswordError, UserNotFoundError, EmailNotVerifiedError, ResetDisabledError, TooManyResetsError, ResetNotFoundError, ResetExpiredError, InvalidTokenError } from "./errors.js"
import { AuthStatus } from "./types.js"

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 * @typedef {import("./types.js").AuthAccount} AuthAccount
 * @typedef {import("./types.js").TokenCallback} TokenCallback
 * @typedef {import("./types.js").UserIdentifier} UserIdentifier
 * @typedef {import("./types.js").AuthenticateRequestResult} AuthenticateRequestResult
 */

/**
 * @param {string} cookieHeader
 * @returns {Record<string, string>}
 */
function parseCookies(cookieHeader) {
  /** @type {Record<string, string>} */
  const cookies = {}
  if (!cookieHeader) return cookies

  for (const pair of cookieHeader.split(";")) {
    const idx = pair.indexOf("=")
    if (idx === -1) continue
    const key = pair.slice(0, idx).trim()
    const value = pair.slice(idx + 1).trim()
    if (key) cookies[key] = decodeURIComponent(value)
  }

  return cookies
}

/**
 * Resolve the account for an incoming request via session or remember-me cookie.
 * @param {AuthConfig} config
 * @param {import("http").IncomingMessage} req
 * @param {(req: any, res: any, next: () => void) => void} [sessionMiddleware]
 * @returns {Promise<AuthenticateRequestResult>}
 */
export async function authenticateRequest(config, req, sessionMiddleware) {
  const queries = new AuthQueries(config)

  if (sessionMiddleware) {
    await new Promise(resolve => {
      sessionMiddleware(req, {}, resolve)
    })
  }

  const session = req.session
  if (session?.auth?.loggedIn && session.auth.accountId) {
    const account = await queries.findAccountById(session.auth.accountId)
    if (account && account.status === AuthStatus.Normal) {
      return { account, source: "session" }
    }
  }

  const cookies = parseCookies(req.headers.cookie || "")
  const cookieName = config.rememberCookieName || "remember_token"
  const token = cookies[cookieName]

  if (!token) {
    return { account: null, source: null }
  }

  const remember = await queries.findRememberToken(token)
  if (!remember || new Date() > remember.expires) {
    return { account: null, source: null }
  }

  const account = await queries.findAccountById(remember.account_id)
  if (!account || account.status !== AuthStatus.Normal) {
    return { account: null, source: null }
  }

  return { account, source: "remember" }
}

/**
 * @param {string} password
 * @param {AuthConfig} config
 * @throws {InvalidPasswordError}
 */
function validatePassword(password, config) {
  const minLength = config.minPasswordLength || 8
  const maxLength = config.maxPasswordLength || 64

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

/**
 * @returns {string}
 */
function generateAutoUserId() {
  return crypto.randomUUID()
}

/**
 * @param {AuthQueries} queries
 * @param {UserIdentifier} identifier
 * @returns {Promise<AuthAccount | null>}
 */
async function findAccountByIdentifier(queries, identifier) {
  if (identifier.accountId !== undefined) {
    return await queries.findAccountById(identifier.accountId)
  } else if (identifier.email !== undefined) {
    return await queries.findAccountByEmail(identifier.email)
  } else if (identifier.userId !== undefined) {
    return await queries.findAccountByUserId(identifier.userId)
  }
  return null
}

/**
 * @param {AuthQueries} queries
 * @param {AuthAccount} account
 * @param {string} email
 * @param {TokenCallback} callback
 * @returns {Promise<void>}
 */
async function createConfirmationToken(queries, account, email, callback) {
  const token = await hash.encode(email)
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7) // 1 week

  await queries.createConfirmation({
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
 * Create a new local account. When a callback is provided the account starts
 * unverified and a confirmation token is generated.
 * @param {AuthConfig} config
 * @param {{ email: string, password: string }} credentials
 * @param {string | number} [userId]
 * @param {TokenCallback} [callback]
 * @returns {Promise<AuthAccount>}
 * @throws {EmailTakenError}
 */
export async function createUser(config, credentials, userId, callback) {
  validateEmail(credentials.email)
  validatePassword(credentials.password, config)

  const queries = new AuthQueries(config)

  const existing = await queries.findAccountByEmail(credentials.email)
  if (existing) {
    throw new EmailTakenError()
  }

  const finalUserId = userId || generateAutoUserId()
  const hashedPassword = await hash.encode(credentials.password)
  const verified = typeof callback !== "function"

  const account = await queries.createAccount({
    userId: finalUserId,
    email: credentials.email,
    password: hashedPassword,
    verified,
    status: AuthStatus.Normal,
    rolemask: 0,
  })

  if (!verified && callback) {
    await createConfirmationToken(queries, account, credentials.email, callback)
  }

  return account
}

/**
 * Register a new local account. When a callback is provided the account starts
 * unverified and a confirmation token is generated.
 * @param {AuthConfig} config
 * @param {string} email
 * @param {string} password
 * @param {string | number} [userId]
 * @param {TokenCallback} [callback]
 * @returns {Promise<AuthAccount>}
 * @throws {EmailTakenError}
 */
export async function register(config, email, password, userId, callback) {
  validateEmail(email)
  validatePassword(password, config)

  const queries = new AuthQueries(config)

  const existing = await queries.findAccountByEmail(email)
  if (existing) {
    throw new EmailTakenError()
  }

  const finalUserId = userId || generateAutoUserId()
  const hashedPassword = await hash.encode(password)
  const verified = typeof callback !== "function"

  const account = await queries.createAccount({
    userId: finalUserId,
    email,
    password: hashedPassword,
    verified,
    status: AuthStatus.Normal,
    rolemask: 0,
  })

  if (!verified && callback) {
    await createConfirmationToken(queries, account, email, callback)
  }

  return account
}

/**
 * Delete the account matched by the identifier.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @returns {Promise<void>}
 * @throws {UserNotFoundError}
 */
export async function deleteUserBy(config, identifier) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  await queries.deleteAccount(account.id)
}

/**
 * Add a role bit to the account's rolemask.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} role
 * @returns {Promise<void>}
 * @throws {UserNotFoundError}
 */
export async function addRoleForUserBy(config, identifier, role) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  const rolemask = account.rolemask | role
  await queries.updateAccount(account.id, { rolemask })
}

/**
 * Remove a role bit from the account's rolemask.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} role
 * @returns {Promise<void>}
 * @throws {UserNotFoundError}
 */
export async function removeRoleForUserBy(config, identifier, role) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  const rolemask = account.rolemask & ~role
  await queries.updateAccount(account.id, { rolemask })
}

/**
 * Check whether the account has every bit in the given role mask.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} role
 * @returns {Promise<boolean>}
 * @throws {UserNotFoundError}
 */
export async function hasRoleForUserBy(config, identifier, role) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  return (account.rolemask & role) === role
}

/**
 * Change the password for the account matched by the identifier.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {string} password
 * @returns {Promise<void>}
 * @throws {UserNotFoundError}
 * @throws {InvalidPasswordError}
 */
export async function changePasswordForUserBy(config, identifier, password) {
  validatePassword(password, config)

  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  await queries.updateAccount(account.id, {
    password: await hash.encode(password),
  })
}

/**
 * Set the status code for the account matched by the identifier.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} status
 * @returns {Promise<void>}
 * @throws {UserNotFoundError}
 */
export async function setStatusForUserBy(config, identifier, status) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  await queries.updateAccount(account.id, { status })
}

/**
 * Create a password reset token for the account matched by the identifier.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {string | number | null} [expiresAfter]
 * @param {TokenCallback} [callback]
 * @returns {Promise<void>}
 * @throws {UserNotFoundError}
 * @throws {EmailNotVerifiedError}
 */
export async function initiatePasswordResetForUserBy(config, identifier, expiresAfter = null, callback) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  if (!account.verified) {
    throw new EmailNotVerifiedError()
  }

  const expiry = !expiresAfter ? ms("6h") : ms(expiresAfter)
  const token = await hash.encode(account.email)
  const expires = new Date(Date.now() + expiry)

  await queries.createResetToken({
    accountId: account.id,
    token,
    expires,
  })

  if (callback) {
    callback(token)
  }
}

/**
 * Request a password reset by email, subject to the open-request limit.
 * @param {AuthConfig} config
 * @param {string} email
 * @param {string | number | null} [expiresAfter]
 * @param {number | null} [maxOpenRequests]
 * @param {TokenCallback} [callback]
 * @returns {Promise<void>}
 * @throws {EmailNotVerifiedError}
 * @throws {ResetDisabledError}
 * @throws {TooManyResetsError}
 */
export async function resetPassword(config, email, expiresAfter = null, maxOpenRequests = null, callback) {
  validateEmail(email)

  const expiry = !expiresAfter ? ms("6h") : ms(expiresAfter)
  const maxRequests = maxOpenRequests === null ? 2 : Math.max(1, maxOpenRequests)

  const queries = new AuthQueries(config)
  const account = await queries.findAccountByEmail(email)

  if (!account || !account.verified) {
    throw new EmailNotVerifiedError()
  }

  if (!account.resettable) {
    throw new ResetDisabledError()
  }

  const openRequests = await queries.countActiveResetTokensForAccount(account.id)

  if (openRequests >= maxRequests) {
    throw new TooManyResetsError()
  }

  const token = await hash.encode(email)
  const expires = new Date(Date.now() + expiry)

  await queries.createResetToken({
    accountId: account.id,
    token,
    expires,
  })

  if (callback) {
    callback(token)
  }
}

/**
 * Confirm a password reset token and apply the new password.
 * @param {AuthConfig} config
 * @param {string} token
 * @param {string} password
 * @returns {Promise<{ accountId: number, email: string }>}
 * @throws {ResetNotFoundError}
 * @throws {ResetExpiredError}
 * @throws {UserNotFoundError}
 * @throws {ResetDisabledError}
 * @throws {InvalidPasswordError}
 * @throws {InvalidTokenError}
 */
export async function confirmResetPassword(config, token, password) {
  const queries = new AuthQueries(config)
  const reset = await queries.findResetToken(token)

  if (!reset) {
    throw new ResetNotFoundError()
  }

  if (new Date(reset.expires) < new Date()) {
    throw new ResetExpiredError()
  }

  const account = await queries.findAccountById(reset.account_id)
  if (!account) {
    throw new UserNotFoundError()
  }

  if (!account.resettable) {
    throw new ResetDisabledError()
  }

  validatePassword(password, config)

  if (!(await hash.verify(token, account.email))) {
    throw new InvalidTokenError()
  }

  await queries.updateAccount(account.id, {
    password: await hash.encode(password),
  })

  await queries.deleteResetToken(token)

  return { accountId: account.id, email: account.email }
}

/**
 * Check whether an account exists for the given email.
 * @param {AuthConfig} config
 * @param {string} email
 * @returns {Promise<boolean>}
 */
export async function userExistsByEmail(config, email) {
  validateEmail(email)

  const queries = new AuthQueries(config)
  const account = await queries.findAccountByEmail(email)

  return account !== null
}

/**
 * Force logout of all sessions for the account matched by the identifier.
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @returns {Promise<{ accountId: number }>}
 * @throws {UserNotFoundError}
 */
export async function forceLogoutForUserBy(config, identifier) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  if (!account) {
    throw new UserNotFoundError()
  }

  await queries.incrementForceLogout(account.id)

  return { accountId: account.id }
}
