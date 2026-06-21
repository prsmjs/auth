import { BaseOAuthProvider } from "./base-provider.js"

/**
 * @typedef {import("../types.js").AuthConfig} AuthConfig
 * @typedef {import("../types.js").OAuthUserData} OAuthUserData
 * @typedef {import("../types.js").AzureProviderConfig} AzureProviderConfig
 */

export class AzureProvider extends BaseOAuthProvider {
  /**
   * @param {AzureProviderConfig} config
   * @param {AuthConfig} authConfig
   * @param {import("../auth-manager.js").AuthManager} authManager
   */
  constructor(config, authConfig, authManager) {
    super(config, authConfig, authManager)
  }

  /**
   * Build the Azure AD authorization URL.
   * @param {string} [state]
   * @param {string[]} [scopes]
   * @returns {string}
   */
  getAuthUrl(state, scopes) {
    const azureConfig = this.config
    const params = new URLSearchParams({
      client_id: azureConfig.clientId,
      redirect_uri: azureConfig.redirectUri,
      scope: scopes?.join(" ") || "openid profile email User.Read",
      state: state || crypto.randomUUID(),
      response_type: "code",
      response_mode: "query",
    })

    return `https://login.microsoftonline.com/${azureConfig.tenantId}/oauth2/v2.0/authorize?${params}`
  }

  /**
   * Exchange the callback code and resolve the Azure user profile.
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
    const azureConfig = this.config
    const accessToken = await this.exchangeCodeForToken(code, `https://login.microsoftonline.com/${azureConfig.tenantId}/oauth2/v2.0/token`)

    // fetch user data from Microsoft Graph
    const user = await this.fetchUserFromAPI(accessToken, "https://graph.microsoft.com/v1.0/me")

    if (!user.mail && !user.userPrincipalName) {
      throw new Error("No email found in Azure account")
    }

    return {
      id: user.id,
      email: user.mail || user.userPrincipalName,
      username: user.mailNickname || user.userPrincipalName?.split("@")[0],
      name: user.displayName,
      avatar: undefined, // Azure doesn't provide avatar in basic profile
    }
  }

  /**
   * @returns {string}
   */
  getProviderName() {
    return "azure"
  }

  /**
   * Exchange an authorization code for an Azure access token.
   * @param {string} code
   * @param {string} tokenUrl
   * @returns {Promise<string>}
   * @throws {Error} when the exchange fails or no access token is returned
   */
  async exchangeCodeForToken(code, tokenUrl) {
    const azureConfig = this.config
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: azureConfig.clientId,
        client_secret: azureConfig.clientSecret,
        code,
        redirect_uri: azureConfig.redirectUri,
        grant_type: "authorization_code",
        scope: "openid profile email User.Read",
      }),
    })

    if (!response.ok) {
      throw new Error(`OAuth token exchange failed: ${response.status} ${response.statusText}`)
    }

    const data = await response.json()
    if (!data.access_token) {
      throw new Error("No access token received from Azure")
    }

    return data.access_token
  }
}
