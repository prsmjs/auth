import { BaseOAuthProvider } from "./base-provider.js"

/**
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 * @typedef {import("../types.js").OAuthUserData} OAuthUserData
 * @typedef {import("../types.js").GitHubProviderConfig} GitHubProviderConfig
 */

export class GitHubProvider extends BaseOAuthProvider {
  /**
   * @param {GitHubProviderConfig} config
   * @param {AuthConfig} authConfig
   * @param {import("../auth-manager.js").AuthManager} authManager
   */
  constructor(config, authConfig, authManager) {
    super(config, authConfig, authManager)
  }

  /**
   * Build the GitHub authorization URL.
   * @param {string} [state]
   * @param {string[]} [scopes]
   * @returns {string}
   */
  getAuthUrl(state, scopes) {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: scopes?.join(" ") || "user:email",
      state: state || crypto.randomUUID(),
      response_type: "code",
    })

    return `https://github.com/login/oauth/authorize?${params}`
  }

  /**
   * Exchange the callback code and resolve the GitHub user profile.
   * @param {import("express").Request} req
   * @returns {Promise<OAuthUserData>}
   * @throws {Error} when no code is provided or no verified email is found
   */
  async getUserData(req) {
    const code = req.query.code
    if (!code) {
      throw new Error("No authorization code provided")
    }

    // exchange code for access token
    const accessToken = await this.exchangeCodeForToken(code, "https://github.com/login/oauth/access_token")

    const apiHeaders = {
      Accept: "application/vnd.github+json",
      "User-Agent": this.authConfig.githubUserAgent || "EasyAccess",
      "X-GitHub-Api-Version": "2022-11-28",
    }

    const [user, emails] = await Promise.all([
      this.fetchUserFromAPI(accessToken, "https://api.github.com/user", apiHeaders),
      this.fetchUserFromAPI(accessToken, "https://api.github.com/user/emails", apiHeaders),
    ])

    const verifiedEmails = Array.isArray(emails) ? emails.filter((email) => email.verified) : []
    const primaryEmail = verifiedEmails.find((email) => email.primary)?.email
    const fallbackEmail = primaryEmail || verifiedEmails[0]?.email

    if (!fallbackEmail) {
      throw new Error("No verified email found in GitHub account")
    }

    return {
      id: user.id.toString(),
      email: fallbackEmail,
      username: user.login,
      name: user.name || user.login,
      avatar: user.avatar_url,
    }
  }

  /**
   * @returns {string}
   */
  getProviderName() {
    return "github"
  }
}
