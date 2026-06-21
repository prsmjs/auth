// hand-authored types entry: re-exports the JSDoc-generated declarations and layers
// on the express/express-session module augmentation, which jsdoc can't express
import type { AuthManager, AuthSession } from "./types/index.js"

export * from "./types/index.js"

declare global {
  namespace Express {
    interface Request {
      auth: AuthManager
    }
  }
}

declare module "express-session" {
  interface SessionData {
    auth?: AuthSession
  }
}
