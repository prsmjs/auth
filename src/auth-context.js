import * as authFunctions from "./auth-functions.js"
import { AuthQueries } from "./queries.js"
import { ActivityLogger } from "./activity-logger.js"
import { AuthRole, AuthStatus, TwoFactorMechanism, AuthActivityAction } from "./types.js"
import { UserNotFoundError, TwoFactorNotSetupError } from "./errors.js"

const MECHANISM_NAMES = { [TwoFactorMechanism.TOTP]: "totp", [TwoFactorMechanism.EMAIL]: "email", [TwoFactorMechanism.SMS]: "sms" }

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 * @typedef {import("./types.js").TokenCallback} TokenCallback
 * @typedef {import("./types.js").AuthAccount} AuthAccount
 * @typedef {import("./types.js").UserIdentifier} UserIdentifier
 */

/**
 * @param {AuthQueries} queries
 * @param {UserIdentifier} identifier
 * @returns {Promise<AuthAccount | null>}
 */
async function resolveAccount(queries, identifier) {
  if (identifier.accountId !== undefined) return queries.findAccountById(identifier.accountId)
  if (identifier.email !== undefined) return queries.findAccountByEmail(identifier.email)
  if (identifier.userId !== undefined) return queries.findAccountByUserId(identifier.userId)
  return null
}

/**
 * Create a requestless auth context for scripts, workers, cron jobs, and admin
 * tasks. The same object doubles as the binding surface for the @prsm/devtools
 * admin panel: it exposes read methods (listAccounts, getAccount, getStats,
 * recent activity, roles) and control actions (role/status/force-logout/etc),
 * all duck-typed so devtools needs no @prsm/auth dependency.
 * @param {AuthConfig} config
 */
export function createAuthContext(config) {
  const queries = new AuthQueries(config)
  const activityLogger = new ActivityLogger(config)

  return {
    // user management (requestless equivalents of the req.auth admin methods)
    createUser: (credentials, userId, callback) => authFunctions.createUser(config, credentials, userId, callback),
    register: (email, password, userId, callback) => authFunctions.register(config, email, password, userId, callback),
    deleteUserBy: (identifier) => authFunctions.deleteUserBy(config, identifier),
    addRoleForUserBy: (identifier, role) => authFunctions.addRoleForUserBy(config, identifier, role),
    removeRoleForUserBy: (identifier, role) => authFunctions.removeRoleForUserBy(config, identifier, role),
    hasRoleForUserBy: (identifier, role) => authFunctions.hasRoleForUserBy(config, identifier, role),
    changePasswordForUserBy: (identifier, password) => authFunctions.changePasswordForUserBy(config, identifier, password),
    setStatusForUserBy: (identifier, status) => authFunctions.setStatusForUserBy(config, identifier, status),
    initiatePasswordResetForUserBy: (identifier, expiresAfter, callback) => authFunctions.initiatePasswordResetForUserBy(config, identifier, expiresAfter, callback),
    resetPassword: (email, expiresAfter, maxOpenRequests, callback) => authFunctions.resetPassword(config, email, expiresAfter, maxOpenRequests, callback),
    confirmResetPassword: (token, password) => authFunctions.confirmResetPassword(config, token, password),
    userExistsByEmail: (email) => authFunctions.userExistsByEmail(config, email),
    forceLogoutForUserBy: (identifier) => authFunctions.forceLogoutForUserBy(config, identifier),

    /**
     * Remove a single two-factor method from an account - the admin rescue path
     * for a user who lost their authenticator device. Verifies the method
     * belongs to the account before deleting, and writes an audit-log entry.
     * @param {UserIdentifier} identifier
     * @param {number} methodId
     * @returns {Promise<void>}
     * @throws {UserNotFoundError|TwoFactorNotSetupError}
     */
    async removeTwoFactorMethod(identifier, methodId) {
      const account = await resolveAccount(queries, identifier)
      if (!account) throw new UserNotFoundError()

      const methods = await queries.findTwoFactorMethodsByAccountId(account.id)
      const method = methods.find((m) => m.id === methodId)
      if (!method) throw new TwoFactorNotSetupError()

      await queries.deleteTwoFactorMethod(method.id)
      await activityLogger.logActivity(account.id, AuthActivityAction.TwoFactorDisabled, {}, true, {
        mechanism: MECHANISM_NAMES[method.mechanism],
        by: "context",
      })
    },

    // introspection surface for @prsm/devtools

    /**
     * @param {{ limit?: number, offset?: number, search?: string }} [opts]
     * @returns {Promise<{ accounts: AuthAccount[], total: number }>}
     */
    async listAccounts(opts = {}) {
      const [accounts, total] = await Promise.all([queries.listAccounts(opts), queries.countAccounts(opts.search)])
      return { accounts, total }
    },

    /**
     * @param {UserIdentifier} identifier
     * @returns {Promise<AuthAccount>}
     */
    async getAccount(identifier) {
      const account = await resolveAccount(queries, identifier)
      if (!account) throw new UserNotFoundError()
      return account
    },

    /**
     * @param {number} accountId
     */
    getProvidersForAccount: (accountId) => queries.findProvidersByAccountId(accountId),

    /**
     * @param {number} accountId
     */
    getTwoFactorMethods: (accountId) => queries.findTwoFactorMethodsByAccountId(accountId),

    /**
     * The role name -> bit map devtools renders, defaulting to AuthRole.
     * @returns {Record<string, number>}
     */
    getRoles: () => config.roles || AuthRole,

    /**
     * The status code -> name map devtools renders for account status.
     * @returns {Record<string, number>}
     */
    getStatuses: () => AuthStatus,

    /**
     * The 2FA mechanism code -> name map devtools renders.
     * @returns {Record<string, number>}
     */
    getMechanisms: () => TwoFactorMechanism,

    /**
     * @returns {Promise<ReturnType<typeof import("./schema.js").getAuthTableStats>>}
     */
    getStats: () => import("./schema.js").then((m) => m.getAuthTableStats(config)),

    /**
     * @param {number} [limit]
     * @param {number} [accountId]
     */
    getRecentActivity: (limit, accountId) => activityLogger.getRecentActivity(limit, accountId),

    getActivityStats: () => activityLogger.getActivityStats(),
  }
}

/**
 * @typedef {ReturnType<typeof createAuthContext>} AuthContext
 */
