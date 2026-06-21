/**
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 * @typedef {import("../types.js").OAuthUserData} OAuthUserData
 * @typedef {import("../types.js").OAuthCallbackResult} OAuthCallbackResult
 * @typedef {import("../types.js").OAuthProviderConfig} OAuthProviderConfig
 */

export class BaseOAuthProvider {
  /**
   * @param {OAuthProviderConfig} config
   * @param {AuthConfig} authConfig
   * @param {import("../auth-manager.js").AuthManager} authManager
   */
  constructor(config, authConfig, authManager) {
    this.config = config
    this.authConfig = authConfig
    this.authManager = authManager
  }

  /**
   * Handle an OAuth provider callback request and resolve the login.
   * @param {import("express").Request} req
   * @returns {Promise<OAuthCallbackResult>}
   */
  async handleCallback(req) {
    const userData = await this.getUserData(req)
    return this.processOAuthLogin(userData, req)
  }

  /**
   * Resolve or create an account for the OAuth user and record the login.
   * @param {OAuthUserData} userData
   * @param {import("express").Request} req
   * @returns {Promise<OAuthCallbackResult>}
   * @throws {Error} when an account already exists for the user's email
   */
  async processOAuthLogin(userData, req) {
    const { queries } = this.authManager
    const providerName = this.getProviderName()

    const existingProvider = await queries.findProviderByProviderIdAndType(userData.id, providerName)

    if (existingProvider) {
      const account = await queries.findAccountById(existingProvider.account_id)
      if (account) {
        await this.authManager.onLoginSuccessful(account, true)
        return { isNewUser: false }
      }
    }

    // new OAuth user - check if email already exists
    if (userData.email) {
      const existingAccount = await queries.findAccountByEmail(userData.email)
      if (existingAccount) {
        throw new Error("You already have an account associated with this email address.")
      }
    }

    // create new user and account
    let userId

    if (this.authConfig.createUser) {
      userId = await this.authConfig.createUser(userData)
    } else {
      // Generate UUID for OAuth users when no createUser function is provided
      userId = crypto.randomUUID()
    }

    // create the auth account (no password for OAuth)
    const account = await queries.createAccount({
      userId,
      email: userData.email,
      password: null,
      verified: true, // OAuth providers are pre-verified
      status: 0, // AuthStatus.Normal
      rolemask: 0,
    })

    // create the provider record
    await queries.createProvider({
      accountId: account.id,
      provider: providerName,
      providerId: userData.id,
      providerEmail: userData.email,
      providerUsername: userData.username || null,
      providerName: userData.name || null,
      providerAvatar: userData.avatar || null,
    })

    await this.authManager.onLoginSuccessful(account, true)
    return { isNewUser: true }
  }

  /**
   * Exchange an authorization code for an access token.
   * @param {string} code
   * @param {string} tokenUrl
   * @returns {Promise<string>}
   * @throws {Error} when the exchange fails or no access token is returned
   */
  async exchangeCodeForToken(code, tokenUrl) {
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: this.config.redirectUri,
        grant_type: "authorization_code",
      }),
    })

    if (!response.ok) {
      throw new Error(`OAuth token exchange failed: ${response.status} ${response.statusText}`)
    }

    const data = await response.json()
    if (!data.access_token) {
      throw new Error("No access token received from OAuth provider")
    }

    return data.access_token
  }

  /**
   * Fetch the authenticated user profile from a provider API.
   * @param {string} accessToken
   * @param {string} apiUrl
   * @param {Record<string, string>} [headers]
   * @returns {Promise<any>}
   * @throws {Error} when the request fails
   */
  async fetchUserFromAPI(accessToken, apiUrl, headers = {}) {
    const response = await fetch(apiUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
        ...headers,
      },
    })

    if (!response.ok) {
      throw new Error(`Failed to fetch user data: ${response.status} ${response.statusText}`)
    }

    return response.json()
  }
}
