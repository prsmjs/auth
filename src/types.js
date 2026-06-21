// shared types and runtime constants for @prsm/auth
// the interfaces live here as jsdoc typedefs; tsc emits them as exported types

/**
 * @typedef {import("pg").Pool} Pool
 * @typedef {import("express").Request} ExpressRequest
 * @typedef {import("express").Response} ExpressResponse
 */

/**
 * @typedef {object} OAuthProviderConfig
 * @property {string} clientId
 * @property {string} clientSecret
 * @property {string} redirectUri
 */

/**
 * @typedef {OAuthProviderConfig} GitHubProviderConfig
 */

/**
 * @typedef {OAuthProviderConfig} GoogleProviderConfig
 */

/**
 * @typedef {OAuthProviderConfig & { tenantId: string }} AzureProviderConfig
 */

/**
 * optional tracer, duck-typed against @prsm/trace - any object with a span/startSpan
 * method works. auth never imports @prsm/trace; it only calls what's provided
 * @typedef {object} Tracer
 * @property {(name: string, fn: (span?: any) => any, attrs?: Record<string, any>) => any} [span]
 * @property {(name: string, attrs?: Record<string, any>) => any} [startSpan]
 */

/**
 * optional limiter, duck-typed against @prsm/limit. auth consumes one unit
 * before login when a limiter is provided. any @prsm/limit algorithm works -
 * tokenBucket (take), slidingWindow (hit), leakyBucket (drip) - all return
 * { allowed, retryAfter }
 * @typedef {object} Limiter
 * @property {(key: string) => Promise<{ allowed: boolean, retryAfter?: number }>} [take]
 * @property {(key: string) => Promise<{ allowed: boolean, retryAfter?: number }>} [hit]
 * @property {(key: string) => Promise<{ allowed: boolean, retryAfter?: number }>} [drip]
 * @property {(key: string) => Promise<{ allowed: boolean, retryAfter?: number }>} [consume]
 * @property {(key: string) => Promise<{ allowed: boolean, retryAfter?: number }>} [check]
 */

/**
 * @typedef {object} InvalidationConfig
 * @property {boolean} [listen] when true, the manager opens a dedicated postgres
 *   LISTEN connection and drops cached sessions the instant another instance
 *   issues a force-logout/role/status change. falls back to poll-based resync
 *   when the connection or NOTIFY is unavailable (e.g. pgbouncer txn pooling)
 * @property {string} [channel] notify channel name, defaults to "prsm_auth_invalidate"
 */

/**
 * @typedef {object} AuthConfig
 * @property {Pool} db required postgres pool (pg-compatible, exposes query())
 * @property {(userData: OAuthUserData) => string | number | Promise<string | number>} [createUser]
 *   called for new OAuth users to create your app user record and return its id;
 *   when omitted, OAuth users get an auto-generated uuid for user_id
 * @property {string} [tablePrefix] defaults to "user_"
 * @property {Record<string, number>} [roles] custom roles from defineRoles(), defaults to AuthRole
 * @property {number} [minPasswordLength] defaults to 8
 * @property {number} [maxPasswordLength] defaults to 64
 * @property {string} [rememberDuration] defaults to "30d", parsed by @prsm/ms
 * @property {string} [rememberCookieName] defaults to "remember_token"
 * @property {{ domain?: string, secure?: boolean, sameSite?: "strict" | "lax" | "none" }} [cookie]
 * @property {string} [resyncInterval] defaults to "30s"
 * @property {{ enabled?: boolean, maxEntries?: number, actions?: AuthActivityActionType[] }} [activityLog]
 * @property {{ github?: GitHubProviderConfig, google?: GoogleProviderConfig, azure?: AzureProviderConfig }} [providers]
 * @property {string} [githubUserAgent] defaults to "prsm-auth"
 * @property {{ enabled?: boolean, requireForOAuth?: boolean, issuer?: string, codeLength?: number, tokenExpiry?: string, totpWindow?: number, backupCodesCount?: number }} [twoFactor]
 * @property {{ enabled?: boolean, defaultTtl?: string | null, maxTtl?: string, canImpersonate?: (actor: AuthAccount, target: AuthAccount) => boolean | Promise<boolean> }} [impersonation]
 * @property {Tracer} [tracer] optional @prsm/trace tracer, duck-typed
 * @property {Limiter} [limiter] optional @prsm/limit limiter, duck-typed
 * @property {InvalidationConfig} [invalidation] optional cross-instance invalidation
 */

/**
 * @typedef {object} AuthAccount
 * @property {number} id
 * @property {string} user_id
 * @property {string} email
 * @property {string | null} password
 * @property {boolean} verified
 * @property {number} status
 * @property {number} rolemask
 * @property {Date | null} last_login
 * @property {number} force_logout
 * @property {boolean} resettable
 * @property {Date} registered
 */

/**
 * @typedef {object} AuthProvider
 * @property {number} id
 * @property {number} account_id
 * @property {string} provider
 * @property {string} provider_id
 * @property {string | null} provider_email
 * @property {string | null} provider_username
 * @property {string | null} provider_name
 * @property {string | null} provider_avatar
 * @property {Date} created_at
 * @property {Date} updated_at
 */

/**
 * @typedef {object} OAuthUserData
 * @property {string} id
 * @property {string} email
 * @property {string} [username]
 * @property {string} [name]
 * @property {string} [avatar]
 */

/**
 * @typedef {object} OAuthCallbackResult
 * @property {boolean} isNewUser
 */

/**
 * @typedef {object} OAuthProvider
 * @property {(state?: string, scopes?: string[]) => string} getAuthUrl
 * @property {(req: ExpressRequest) => Promise<OAuthCallbackResult>} handleCallback
 * @property {(req: ExpressRequest) => Promise<OAuthUserData>} getUserData
 */

/**
 * @typedef {object} AuthConfirmation
 * @property {number} id
 * @property {number} account_id
 * @property {string} token
 * @property {string} email
 * @property {Date} expires
 */

/**
 * @typedef {object} AuthRemember
 * @property {number} id
 * @property {number} account_id
 * @property {string} token
 * @property {Date} expires
 */

/**
 * @typedef {object} AuthenticateRequestResult
 * @property {AuthAccount | null} account
 * @property {"session" | "remember" | null} source
 */

/**
 * @typedef {object} AuthReset
 * @property {number} id
 * @property {number} account_id
 * @property {string} token
 * @property {Date} expires
 */

/**
 * @typedef {object} AuthActivity
 * @property {number} id
 * @property {number | null} account_id
 * @property {number | null} actor_account_id
 * @property {string} action
 * @property {string | null} ip_address
 * @property {string | null} user_agent
 * @property {string | null} browser
 * @property {string | null} os
 * @property {string | null} device
 * @property {boolean} success
 * @property {Record<string, any> | null} metadata
 * @property {Date} created_at
 */

/**
 * @typedef {object} ImpersonationActor
 * @property {number} accountId
 * @property {string} userId
 * @property {string} email
 * @property {number} rolemask
 * @property {number} forceLogout
 * @property {Date} startedAt
 * @property {Date} [expiresAt]
 * @property {string} [reason]
 */

/**
 * @typedef {object} AwaitingTwoFactor
 * @property {number} accountId
 * @property {Date} expiresAt
 * @property {boolean} remember
 * @property {number[]} availableMechanisms
 * @property {number[]} attemptedMechanisms
 * @property {string} originalEmail
 * @property {{ email?: string, sms?: string }} [selectors]
 */

/**
 * @typedef {object} AuthSession
 * @property {boolean} loggedIn
 * @property {number} accountId
 * @property {string} userId
 * @property {string} email
 * @property {number} status
 * @property {number} rolemask
 * @property {boolean} remembered
 * @property {Date} lastResync
 * @property {Date} lastRememberCheck
 * @property {number} forceLogout
 * @property {boolean} verified
 * @property {boolean} hasPassword
 * @property {boolean} [shouldForceLogout]
 * @property {ImpersonationActor} [actor]
 * @property {AwaitingTwoFactor} [awaitingTwoFactor]
 */

/**
 * @typedef {object} ImpersonationInfo
 * @property {{ accountId: number, userId: string, email: string, rolemask: number }} actor
 * @property {{ accountId: number, userId: string, email: string, rolemask: number }} target
 * @property {Date} startedAt
 * @property {Date} [expiresAt]
 * @property {string} [reason]
 */

/**
 * @typedef {object} StartImpersonationOptions
 * @property {string} [reason]
 * @property {string | number} [ttl]
 */

/**
 * @typedef {object} TwoFactorMethod
 * @property {number} id
 * @property {number} account_id
 * @property {number} mechanism
 * @property {string | null} secret
 * @property {string[] | null} backup_codes
 * @property {boolean} verified
 * @property {Date} created_at
 * @property {Date | null} last_used_at
 */

/**
 * @typedef {object} TwoFactorToken
 * @property {number} id
 * @property {number} account_id
 * @property {number} mechanism
 * @property {string} selector
 * @property {string} token_hash
 * @property {Date} expires_at
 * @property {Date} created_at
 */

/**
 * @typedef {object} TwoFactorSetupResult
 * @property {string} secret
 * @property {string} qrCode
 * @property {string[]} [backupCodes]
 */

/**
 * @typedef {object} TwoFactorChallenge
 * @property {boolean} [totp]
 * @property {{ otpValue: string, maskedContact: string }} [email]
 * @property {{ otpValue: string, maskedContact: string }} [sms]
 * @property {{ email?: string, sms?: string }} [selectors]
 */

/**
 * @typedef {(token: string) => void} TokenCallback
 */

/**
 * @typedef {{ accountId?: number, email?: string, userId?: string }} UserIdentifier
 */

/**
 * the public interface attached to req.auth by createAuthMiddleware
 * @typedef {object} AuthManager
 * @property {() => boolean} isLoggedIn
 * @property {(email: string, password: string, remember?: boolean) => Promise<void>} login
 * @property {() => Promise<void>} completeTwoFactorLogin
 * @property {() => Promise<void>} logout
 * @property {(email: string, password: string, userId?: string | number, callback?: TokenCallback) => Promise<AuthAccount>} register
 * @property {(force?: boolean) => Promise<void>} resyncSession
 * @property {() => number | null} getId
 * @property {() => string | null} getEmail
 * @property {() => number | null} getStatus
 * @property {() => boolean | null} getVerified
 * @property {() => boolean | null} hasPassword
 * @property {(rolemask?: number) => string[]} getRoleNames
 * @property {() => string | null} getStatusName
 * @property {(role: number) => Promise<boolean>} hasRole
 * @property {() => Promise<boolean>} isAdmin
 * @property {() => boolean} isRemembered
 * @property {(newEmail: string, callback: TokenCallback) => Promise<void>} changeEmail
 * @property {(token: string) => Promise<string>} confirmEmail
 * @property {(token: string, remember?: boolean) => Promise<void>} confirmEmailAndLogin
 * @property {(email: string, expiresAfter?: string | number | null, maxOpenRequests?: number | null, callback?: TokenCallback) => Promise<void>} resetPassword
 * @property {(token: string, password: string, logout?: boolean) => Promise<void>} confirmResetPassword
 * @property {(password: string) => Promise<boolean>} verifyPassword
 * @property {() => Promise<void>} logoutEverywhere
 * @property {() => Promise<void>} logoutEverywhereElse
 * @property {(credentials: { email: string, password: string }, userId?: string | number, callback?: TokenCallback) => Promise<AuthAccount>} createUser
 * @property {(identifier: UserIdentifier) => Promise<void>} deleteUserBy
 * @property {(identifier: UserIdentifier, role: number) => Promise<void>} addRoleForUserBy
 * @property {(identifier: UserIdentifier, role: number) => Promise<void>} removeRoleForUserBy
 * @property {(identifier: UserIdentifier, role: number) => Promise<boolean>} hasRoleForUserBy
 * @property {(identifier: UserIdentifier, password: string) => Promise<void>} changePasswordForUserBy
 * @property {(identifier: UserIdentifier, status: number) => Promise<void>} setStatusForUserBy
 * @property {(identifier: UserIdentifier, expiresAfter?: string | number | null, callback?: TokenCallback) => Promise<void>} initiatePasswordResetForUserBy
 * @property {(email: string) => Promise<boolean>} userExistsByEmail
 * @property {(identifier: UserIdentifier) => Promise<void>} forceLogoutForUserBy
 * @property {(identifier: UserIdentifier) => Promise<void>} loginAsUserBy
 * @property {(identifier: UserIdentifier, options?: StartImpersonationOptions) => Promise<void>} startImpersonation
 * @property {() => Promise<void>} stopImpersonation
 * @property {() => boolean} isImpersonating
 * @property {() => number | null} getActorId
 * @property {() => string | null} getActorEmail
 * @property {() => ImpersonationInfo | null} getImpersonationInfo
 * @property {{ github?: OAuthProvider, google?: OAuthProvider, azure?: OAuthProvider }} providers
 * @property {import("./two-factor/two-factor-manager.js").TwoFactorManager} twoFactor
 */

export const AuthStatus = Object.freeze({
  Normal: 0,
  Archived: 1,
  Banned: 2,
  Locked: 3,
  PendingReview: 4,
  Suspended: 5,
})

export const AuthRole = Object.freeze({
  Admin: 1,
  Author: 2,
  Collaborator: 4,
  Consultant: 8,
  Consumer: 16,
  Contributor: 32,
  Owner: 64,
  Creator: 128,
  Developer: 256,
  Director: 512,
  Editor: 1024,
  Employee: 2048,
  Member: 4096,
  Manager: 8192,
  Moderator: 16384,
  Publisher: 32768,
  Reviewer: 65536,
  Subscriber: 131072,
  SuperAdmin: 262144,
  SuperEditor: 524288,
  SuperModerator: 1048576,
  Translator: 2097152,
})

export const AuthActivityAction = Object.freeze({
  Login: "login",
  Logout: "logout",
  FailedLogin: "failed_login",
  Register: "register",
  EmailConfirmed: "email_confirmed",
  PasswordResetRequested: "password_reset_requested",
  PasswordResetCompleted: "password_reset_completed",
  PasswordChanged: "password_changed",
  EmailChanged: "email_changed",
  RoleChanged: "role_changed",
  StatusChanged: "status_changed",
  ForceLogout: "force_logout",
  OAuthConnected: "oauth_connected",
  RememberTokenCreated: "remember_token_created",
  TwoFactorSetup: "two_factor_setup",
  TwoFactorVerified: "two_factor_verified",
  TwoFactorFailed: "two_factor_failed",
  TwoFactorDisabled: "two_factor_disabled",
  BackupCodeUsed: "backup_code_used",
  ImpersonationStarted: "impersonation_started",
  ImpersonationStopped: "impersonation_stopped",
  ImpersonationExpired: "impersonation_expired",
  ImpersonationRejected: "impersonation_rejected",
})

/**
 * @typedef {(typeof AuthActivityAction)[keyof typeof AuthActivityAction]} AuthActivityActionType
 */

export const TwoFactorMechanism = Object.freeze({
  TOTP: 1,
  EMAIL: 2,
  SMS: 3,
})
