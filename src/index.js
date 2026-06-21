export { createAuthMiddleware } from "./middleware.js"
export { createAuthTables, dropAuthTables, cleanupExpiredTokens, getAuthTableStats } from "./schema.js"
export { createAuthContext } from "./auth-context.js"
export * as authFunctions from "./auth-functions.js"
export * from "./auth-functions.js"
export { defineRoles, addRoleToUser, removeRoleFromUser, setUserRoles, getUserRoles } from "./user-roles.js"

// types and runtime enums (AuthStatus, AuthRole, AuthActivityAction, TwoFactorMechanism)
export * from "./types.js"

// error classes
export * from "./errors.js"

export { isValidEmail, validateEmail } from "./util.js"

export { ActivityLogger } from "./activity-logger.js"

export { TwoFactorManager, TotpProvider, OtpProvider } from "./two-factor/index.js"

export { GitHubProvider, GoogleProvider, AzureProvider, BaseOAuthProvider } from "./providers/index.js"

// cross-instance invalidation teardown (graceful shutdown / tests)
export { closeInvalidationListeners } from "./invalidation.js"
