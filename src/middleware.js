import { AuthManager } from "./auth-manager.js"
import { ensureListener } from "./invalidation.js"

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 */

/**
 * Create the Express middleware that attaches an AuthManager to req.auth,
 * resyncs the session, and processes any remember-me token.
 * @param {AuthConfig} config
 * @returns {import("express").RequestHandler}
 */
export function createAuthMiddleware(config) {
  // start the cross-instance invalidation listener once if enabled; idempotent
  // and non-blocking, falls back to poll-based resync if unavailable
  ensureListener(config)

  return async (req, res, next) => {
    try {
      const authManager = new AuthManager(req, res, config)

      req.auth = authManager

      await authManager.resyncSession()
      await authManager.processRememberDirective()

      next()
    } catch (error) {
      next(error)
    }
  }
}
