import { BaseOAuthProvider } from "./base-provider.js"

/**
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 * @typedef {import("../types.js").OAuthUserData} OAuthUserData
 * @typedef {import("../types.js").GoogleProviderConfig} GoogleProviderConfig
 */

export class GoogleProvider extends BaseOAuthProvider {
  /**
   * @param {GoogleProviderConfig} config
   * @param {AuthConfig} authConfig
   * @param {import("../auth-manager.js").AuthManager} authManager
   */
  constructor(config, authConfig, authManager) {
    super(config, authConfig, authManager)
  }

  /**
   * Build the Google authorization URL.
   * @param {string} [state]
   * @param {string[]} [scopes]
   * @returns {string}
   */
  getAuthUrl(state, scopes) {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: scopes?.join(" ") || "openid profile email",
      state: state || crypto.randomUUID(),
      response_type: "code",
      access_type: "offline",
      prompt: "consent",
    })

    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`
  }

  /**
   * Exchange the callback code and resolve the Google user profile.
   * @param {import("express").Request} req
   * @returns {Promise<OAuthUserData>}
   * @throws {Error} when no code is provided or no email is found
   */
  async getUserData(req) {
    const code = req.query.code
    if (!code) {
      throw new Error("No authorization code provided")
    }

    // exchange code for access token
    const accessToken = await this.exchangeCodeForToken(code, "https://oauth2.googleapis.com/token")

    // fetch user data
    const user = await this.fetchUserFromAPI(accessToken, "https://www.googleapis.com/oauth2/v2/userinfo")

    if (!user.email) {
      throw new Error("No email found in Google account")
    }

    return {
      id: user.id,
      email: user.email,
      username: user.email.split("@")[0], // use email prefix as username
      name: user.name,
      avatar: user.picture,
    }
  }

  /**
   * @returns {string}
   */
  getProviderName() {
    return "google"
  }
}
