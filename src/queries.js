import { notifyInvalidation } from "./invalidation.js"

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 * @typedef {import("./types.js").AuthAccount} AuthAccount
 * @typedef {import("./types.js").AuthConfirmation} AuthConfirmation
 * @typedef {import("./types.js").AuthRemember} AuthRemember
 * @typedef {import("./types.js").AuthReset} AuthReset
 * @typedef {import("./types.js").AuthProvider} AuthProvider
 * @typedef {import("./types.js").TwoFactorMethod} TwoFactorMethod
 * @typedef {import("./types.js").TwoFactorToken} TwoFactorToken
 * @typedef {import("./types.js").TwoFactorMechanism} TwoFactorMechanism
 */

export class AuthQueries {
  /**
   * @param {AuthConfig} config
   */
  constructor(config) {
    this.config = config
    this.db = config.db
    this.tablePrefix = config.tablePrefix || "user_"
  }

  get accountsTable() {
    return `${this.tablePrefix}accounts`
  }

  get confirmationsTable() {
    return `${this.tablePrefix}confirmations`
  }

  get remembersTable() {
    return `${this.tablePrefix}remembers`
  }

  get resetsTable() {
    return `${this.tablePrefix}resets`
  }

  get providersTable() {
    return `${this.tablePrefix}providers`
  }

  get twoFactorMethodsTable() {
    return `${this.tablePrefix}2fa_methods`
  }

  get twoFactorTokensTable() {
    return `${this.tablePrefix}2fa_tokens`
  }

  /**
   * @param {number} id
   * @returns {Promise<AuthAccount | null>}
   */
  async findAccountById(id) {
    const sql = `SELECT * FROM ${this.accountsTable} WHERE id = $1`
    const result = await this.db.query(sql, [id])
    return result.rows[0] || null
  }

  /**
   * @param {string | number} userId
   * @returns {Promise<AuthAccount | null>}
   */
  async findAccountByUserId(userId) {
    const sql = `SELECT * FROM ${this.accountsTable} WHERE user_id = $1`
    const result = await this.db.query(sql, [userId])
    return result.rows[0] || null
  }

  /**
   * @param {string} email
   * @returns {Promise<AuthAccount | null>}
   */
  async findAccountByEmail(email) {
    const sql = `SELECT * FROM ${this.accountsTable} WHERE email = $1`
    const result = await this.db.query(sql, [email])
    return result.rows[0] || null
  }

  /**
   * List accounts with optional email search, newest first. Used by the
   * @prsm/devtools admin panel binding.
   * @param {{ limit?: number, offset?: number, search?: string }} [opts]
   * @returns {Promise<AuthAccount[]>}
   */
  async listAccounts({ limit = 50, offset = 0, search } = {}) {
    const params = []
    let where = ""
    if (search) {
      params.push(`%${search}%`)
      where = `WHERE email ILIKE $1`
    }
    const sql = `SELECT * FROM ${this.accountsTable} ${where} ORDER BY id DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`
    params.push(limit, offset)
    const result = await this.db.query(sql, params)
    return result.rows
  }

  /**
   * @param {string} [search]
   * @returns {Promise<number>}
   */
  async countAccounts(search) {
    const params = []
    let where = ""
    if (search) {
      params.push(`%${search}%`)
      where = `WHERE email ILIKE $1`
    }
    const result = await this.db.query(`SELECT COUNT(*) as count FROM ${this.accountsTable} ${where}`, params)
    return parseInt(result.rows[0]?.count || "0")
  }

  /**
   * Verified 2FA mechanisms for a set of accounts, grouped by account id. Used by
   * the devtools binding to show enabled mechanisms in the account list without an
   * N+1 query.
   * @param {number[]} accountIds
   * @returns {Promise<Map<number, number[]>>}
   */
  async findVerifiedTwoFactorMechanisms(accountIds) {
    const map = new Map()
    if (!accountIds.length) return map
    const result = await this.db.query(`SELECT account_id, mechanism FROM ${this.twoFactorMethodsTable} WHERE account_id = ANY($1) AND verified = true`, [accountIds])
    for (const row of result.rows) {
      if (!map.has(row.account_id)) map.set(row.account_id, [])
      map.get(row.account_id).push(row.mechanism)
    }
    return map
  }

  /**
   * @param {{ userId: string | number, email: string, password: string | null, verified: boolean, status: number, rolemask: number }} data
   * @returns {Promise<AuthAccount>}
   */
  async createAccount(data) {
    const sql = `
      INSERT INTO ${this.accountsTable} (
        user_id, email, password, verified, status, rolemask,
        force_logout, resettable, registered
      )
      VALUES ($1, $2, $3, $4, $5, $6, 0, true, NOW())
      RETURNING *
    `

    const result = await this.db.query(sql, [data.userId, data.email, data.password, data.verified, data.status, data.rolemask])

    return result.rows[0]
  }

  /**
   * @param {number} id
   * @param {Partial<AuthAccount>} updates
   * @returns {Promise<void>}
   */
  async updateAccount(id, updates) {
    const fields = []
    const values = []
    let paramIndex = 1

    for (const [key, value] of Object.entries(updates)) {
      if (key === "id") continue // don't update id
      fields.push(`${key} = $${paramIndex++}`)
      values.push(value)
    }

    if (fields.length === 0) return

    values.push(id)
    const sql = `UPDATE ${this.accountsTable} SET ${fields.join(", ")} WHERE id = $${paramIndex}`
    await this.db.query(sql, values)

    // signal other instances to resync this account when a security-relevant
    // field changed, so role/status/password updates propagate fleet-wide
    if ("status" in updates || "rolemask" in updates || "password" in updates || "verified" in updates || "force_logout" in updates) {
      await notifyInvalidation(this.config, id)
    }
  }

  /**
   * @param {number} id
   * @returns {Promise<void>}
   */
  async updateAccountLastLogin(id) {
    const sql = `UPDATE ${this.accountsTable} SET last_login = NOW() WHERE id = $1`
    await this.db.query(sql, [id])
  }

  /**
   * @param {number} id
   * @returns {Promise<void>}
   */
  async incrementForceLogout(id) {
    const sql = `UPDATE ${this.accountsTable} SET force_logout = force_logout + 1 WHERE id = $1`
    await this.db.query(sql, [id])
    await notifyInvalidation(this.config, id)
  }

  /**
   * @param {number} id
   * @returns {Promise<void>}
   */
  async deleteAccount(id) {
    await this.db.query(`DELETE FROM ${this.twoFactorTokensTable} WHERE account_id = $1`, [id])
    await this.db.query(`DELETE FROM ${this.twoFactorMethodsTable} WHERE account_id = $1`, [id])
    await this.db.query(`DELETE FROM ${this.providersTable} WHERE account_id = $1`, [id])
    await this.db.query(`DELETE FROM ${this.confirmationsTable} WHERE account_id = $1`, [id])
    await this.db.query(`DELETE FROM ${this.remembersTable} WHERE account_id = $1`, [id])
    await this.db.query(`DELETE FROM ${this.resetsTable} WHERE account_id = $1`, [id])

    await this.db.query(`DELETE FROM ${this.accountsTable} WHERE id = $1`, [id])
  }

  /**
   * @param {{ accountId: number, token: string, email: string, expires: Date }} data
   * @returns {Promise<void>}
   */
  async createConfirmation(data) {
    await this.db.query(`DELETE FROM ${this.confirmationsTable} WHERE account_id = $1`, [data.accountId])

    const sql = `
      INSERT INTO ${this.confirmationsTable} (account_id, token, email, expires)
      VALUES ($1, $2, $3, $4)
    `

    await this.db.query(sql, [data.accountId, data.token, data.email, data.expires])
  }

  /**
   * @param {string} token
   * @returns {Promise<AuthConfirmation | null>}
   */
  async findConfirmation(token) {
    const sql = `SELECT * FROM ${this.confirmationsTable} WHERE token = $1`
    const result = await this.db.query(sql, [token])
    return result.rows[0] || null
  }

  /**
   * @param {number} accountId
   * @returns {Promise<AuthConfirmation | null>}
   */
  async findLatestConfirmationForAccount(accountId) {
    const sql = `
      SELECT * FROM ${this.confirmationsTable}
      WHERE account_id = $1
      ORDER BY expires DESC
      LIMIT 1
    `
    const result = await this.db.query(sql, [accountId])
    return result.rows[0] || null
  }

  /**
   * @param {string} token
   * @returns {Promise<void>}
   */
  async deleteConfirmation(token) {
    await this.db.query(`DELETE FROM ${this.confirmationsTable} WHERE token = $1`, [token])
  }

  /**
   * @param {{ accountId: number, token: string, expires: Date }} data
   * @returns {Promise<void>}
   */
  async createRememberToken(data) {
    await this.db.query(`DELETE FROM ${this.remembersTable} WHERE account_id = $1`, [data.accountId])

    const sql = `
      INSERT INTO ${this.remembersTable} (account_id, token, expires)
      VALUES ($1, $2, $3)
    `

    await this.db.query(sql, [data.accountId, data.token, data.expires])
  }

  /**
   * @param {string} token
   * @returns {Promise<AuthRemember | null>}
   */
  async findRememberToken(token) {
    const sql = `SELECT * FROM ${this.remembersTable} WHERE token = $1`
    const result = await this.db.query(sql, [token])
    return result.rows[0] || null
  }

  /**
   * @param {string} token
   * @returns {Promise<void>}
   */
  async deleteRememberToken(token) {
    await this.db.query(`DELETE FROM ${this.remembersTable} WHERE token = $1`, [token])
  }

  /**
   * @param {number} accountId
   * @returns {Promise<void>}
   */
  async deleteRememberTokensForAccount(accountId) {
    await this.db.query(`DELETE FROM ${this.remembersTable} WHERE account_id = $1`, [accountId])
  }

  /**
   * @param {number} accountId
   * @returns {Promise<void>}
   */
  async deleteExpiredRememberTokensForAccount(accountId) {
    await this.db.query(`DELETE FROM ${this.remembersTable} WHERE account_id = $1 AND expires <= NOW()`, [accountId])
  }

  /**
   * @param {{ accountId: number, token: string, expires: Date }} data
   * @returns {Promise<void>}
   */
  async createResetToken(data) {
    const sql = `
      INSERT INTO ${this.resetsTable} (account_id, token, expires)
      VALUES ($1, $2, $3)
    `

    await this.db.query(sql, [data.accountId, data.token, data.expires])
  }

  /**
   * @param {string} token
   * @returns {Promise<AuthReset | null>}
   */
  async findResetToken(token) {
    const sql = `
      SELECT * FROM ${this.resetsTable}
      WHERE token = $1
      ORDER BY expires DESC
      LIMIT 1
    `
    const result = await this.db.query(sql, [token])
    return result.rows[0] || null
  }

  /**
   * @param {number} accountId
   * @returns {Promise<number>}
   */
  async countActiveResetTokensForAccount(accountId) {
    const sql = `
      SELECT COUNT(*) as count FROM ${this.resetsTable}
      WHERE account_id = $1 AND expires >= NOW()
    `
    const result = await this.db.query(sql, [accountId])
    return parseInt(result.rows[0]?.count || "0")
  }

  /**
   * @param {string} token
   * @returns {Promise<void>}
   */
  async deleteResetToken(token) {
    await this.db.query(`DELETE FROM ${this.resetsTable} WHERE token = $1`, [token])
  }

  /**
   * @param {number} accountId
   * @returns {Promise<void>}
   */
  async deleteResetTokensForAccount(accountId) {
    await this.db.query(`DELETE FROM ${this.resetsTable} WHERE account_id = $1`, [accountId])
  }

  /**
   * @param {{ accountId: number, provider: string, providerId: string, providerEmail: string | null, providerUsername: string | null, providerName: string | null, providerAvatar: string | null }} data
   * @returns {Promise<AuthProvider>}
   */
  async createProvider(data) {
    const sql = `
      INSERT INTO ${this.providersTable} (
        account_id, provider, provider_id, provider_email,
        provider_username, provider_name, provider_avatar
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `

    const result = await this.db.query(sql, [data.accountId, data.provider, data.providerId, data.providerEmail, data.providerUsername, data.providerName, data.providerAvatar])

    return result.rows[0]
  }

  /**
   * @param {string} providerId
   * @param {string} provider
   * @returns {Promise<AuthProvider | null>}
   */
  async findProviderByProviderIdAndType(providerId, provider) {
    const sql = `SELECT * FROM ${this.providersTable} WHERE provider_id = $1 AND provider = $2`
    const result = await this.db.query(sql, [providerId, provider])
    return result.rows[0] || null
  }

  /**
   * @param {number} accountId
   * @returns {Promise<AuthProvider[]>}
   */
  async findProvidersByAccountId(accountId) {
    const sql = `SELECT * FROM ${this.providersTable} WHERE account_id = $1 ORDER BY created_at DESC`
    const result = await this.db.query(sql, [accountId])
    return result.rows
  }

  /**
   * @param {number} id
   * @returns {Promise<void>}
   */
  async deleteProvider(id) {
    await this.db.query(`DELETE FROM ${this.providersTable} WHERE id = $1`, [id])
  }

  /**
   * @param {number} accountId
   * @returns {Promise<void>}
   */
  async deleteProvidersByAccountId(accountId) {
    await this.db.query(`DELETE FROM ${this.providersTable} WHERE account_id = $1`, [accountId])
  }

  // two-factor authentication methods

  /**
   * @param {number} accountId
   * @returns {Promise<TwoFactorMethod[]>}
   */
  async findTwoFactorMethodsByAccountId(accountId) {
    const sql = `SELECT * FROM ${this.twoFactorMethodsTable} WHERE account_id = $1 ORDER BY created_at DESC`
    const result = await this.db.query(sql, [accountId])
    return result.rows
  }

  /**
   * @param {number} accountId
   * @param {TwoFactorMechanism} mechanism
   * @returns {Promise<TwoFactorMethod | null>}
   */
  async findTwoFactorMethodByAccountAndMechanism(accountId, mechanism) {
    const sql = `SELECT * FROM ${this.twoFactorMethodsTable} WHERE account_id = $1 AND mechanism = $2`
    const result = await this.db.query(sql, [accountId, mechanism])
    return result.rows[0] || null
  }

  /**
   * @param {{ accountId: number, mechanism: TwoFactorMechanism, secret?: string, backupCodes?: string[], verified?: boolean }} data
   * @returns {Promise<TwoFactorMethod>}
   */
  async createTwoFactorMethod(data) {
    const sql = `
      INSERT INTO ${this.twoFactorMethodsTable} (
        account_id, mechanism, secret, backup_codes, verified
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `

    const result = await this.db.query(sql, [data.accountId, data.mechanism, data.secret || null, data.backupCodes || null, data.verified || false])

    return result.rows[0]
  }

  /**
   * @param {number} id
   * @param {Partial<Pick<TwoFactorMethod, "secret" | "backup_codes" | "verified" | "last_used_at">>} updates
   * @returns {Promise<void>}
   */
  async updateTwoFactorMethod(id, updates) {
    const fields = []
    const values = []
    let paramIndex = 1

    for (const [key, value] of Object.entries(updates)) {
      if (key === "id") continue
      fields.push(`${key} = $${paramIndex++}`)
      values.push(value)
    }

    if (fields.length === 0) return

    values.push(id)
    const sql = `UPDATE ${this.twoFactorMethodsTable} SET ${fields.join(", ")} WHERE id = $${paramIndex}`
    await this.db.query(sql, values)
  }

  /**
   * @param {number} id
   * @returns {Promise<void>}
   */
  async deleteTwoFactorMethod(id) {
    await this.db.query(`DELETE FROM ${this.twoFactorMethodsTable} WHERE id = $1`, [id])
  }

  /**
   * @param {number} accountId
   * @returns {Promise<void>}
   */
  async deleteTwoFactorMethodsByAccountId(accountId) {
    await this.db.query(`DELETE FROM ${this.twoFactorMethodsTable} WHERE account_id = $1`, [accountId])
  }

  // two-factor authentication tokens

  /**
   * @param {{ accountId: number, mechanism: TwoFactorMechanism, selector: string, tokenHash: string, expiresAt: Date }} data
   * @returns {Promise<TwoFactorToken>}
   */
  async createTwoFactorToken(data) {
    const sql = `
      INSERT INTO ${this.twoFactorTokensTable} (
        account_id, mechanism, selector, token_hash, expires_at
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `

    const result = await this.db.query(sql, [data.accountId, data.mechanism, data.selector, data.tokenHash, data.expiresAt])

    return result.rows[0]
  }

  /**
   * @param {string} selector
   * @returns {Promise<TwoFactorToken | null>}
   */
  async findTwoFactorTokenBySelector(selector) {
    const sql = `SELECT * FROM ${this.twoFactorTokensTable} WHERE selector = $1 AND expires_at > NOW()`
    const result = await this.db.query(sql, [selector])
    return result.rows[0] || null
  }

  /**
   * @param {number} id
   * @returns {Promise<void>}
   */
  async deleteTwoFactorToken(id) {
    await this.db.query(`DELETE FROM ${this.twoFactorTokensTable} WHERE id = $1`, [id])
  }

  /**
   * @param {number} accountId
   * @returns {Promise<void>}
   */
  async deleteTwoFactorTokensByAccountId(accountId) {
    await this.db.query(`DELETE FROM ${this.twoFactorTokensTable} WHERE account_id = $1`, [accountId])
  }

  /**
   * @param {number} accountId
   * @param {TwoFactorMechanism} mechanism
   * @returns {Promise<void>}
   */
  async deleteTwoFactorTokensByAccountAndMechanism(accountId, mechanism) {
    await this.db.query(`DELETE FROM ${this.twoFactorTokensTable} WHERE account_id = $1 AND mechanism = $2`, [accountId, mechanism])
  }
}
