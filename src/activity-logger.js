import Bowser from "bowser"

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 * @typedef {import("./types.js").AuthActivity} AuthActivity
 * @typedef {import("./types.js").AuthActivityActionType} AuthActivityActionType
 * @typedef {import("express").Request} Request
 */

export class ActivityLogger {
  /**
   * @param {AuthConfig} config
   */
  constructor(config) {
    this.config = config
    this.enabled = config.activityLog?.enabled !== false // default true
    this.maxEntries = config.activityLog?.maxEntries || 10000
    this.allowedActions = config.activityLog?.actions || null // null means all actions
    this.tablePrefix = config.tablePrefix || "user_"
  }

  get activityTable() {
    return `${this.tablePrefix}activity_log`
  }

  /**
   * @param {string | null} userAgent
   * @returns {{ browser: string | null, os: string | null, device: string | null }}
   */
  parseUserAgent(userAgent) {
    if (!userAgent) {
      return { browser: null, os: null, device: null }
    }

    try {
      const browser = Bowser.getParser(userAgent)
      const result = browser.getResult()

      return {
        browser: result.browser.name || null,
        os: result.os.name || null,
        device: result.platform.type || "desktop",
      }
    } catch (error) {
      // fallback to simple parsing if bowser fails
      return this.parseUserAgentSimple(userAgent)
    }
  }

  /**
   * @param {string} userAgent
   * @returns {{ browser: string | null, os: string | null, device: string | null }}
   */
  parseUserAgentSimple(userAgent) {
    let browser = null
    if (userAgent.includes("Chrome")) browser = "Chrome"
    else if (userAgent.includes("Firefox")) browser = "Firefox"
    else if (userAgent.includes("Safari")) browser = "Safari"
    else if (userAgent.includes("Edge")) browser = "Edge"

    let os = null
    if (userAgent.includes("Windows")) os = "Windows"
    else if (userAgent.includes("Mac OS")) os = "macOS"
    else if (userAgent.includes("Linux")) os = "Linux"
    else if (userAgent.includes("Android")) os = "Android"
    else if (userAgent.includes("iOS")) os = "iOS"

    let device = "desktop"
    if (userAgent.includes("Mobile")) device = "mobile"
    else if (userAgent.includes("Tablet")) device = "tablet"

    return { browser, os, device }
  }

  /**
   * @param {Request} req
   * @returns {string | null}
   */
  getIpAddress(req) {
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || req.connection?.socket?.remoteAddress || null
  }

  /**
   * @param {number | null} accountId
   * @param {AuthActivityActionType} action
   * @param {Request} req
   * @param {boolean} [success]
   * @param {Record<string, any>} [metadata]
   * @returns {Promise<void>}
   */
  async logActivity(accountId, action, req, success = true, metadata = {}) {
    if (!this.enabled) return

    // check if this action is allowed
    if (this.allowedActions && !this.allowedActions.includes(action)) {
      return
    }

    const userAgent = (typeof req.get === "function" ? req.get("User-Agent") : req.headers?.["user-agent"]) || null
    const ip = this.getIpAddress(req)
    const parsed = this.parseUserAgent(userAgent)

    // auto-pick up actor when an impersonation session is active so every existing
    // log call site is impersonation-aware without changes
    const actorAccountId = req.session?.auth?.actor?.accountId ?? null

    try {
      // insert new activity log entry
      await this.config.db.query(
        `
        INSERT INTO ${this.activityTable}
        (account_id, actor_account_id, action, ip_address, user_agent, browser, os, device, success, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `,
        [accountId, actorAccountId, action, ip, userAgent, parsed.browser, parsed.os, parsed.device, success, Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : null],
      )

      // occasionally cleanup old entries (1% chance per insert to avoid performance impact)
      if (Math.random() < 0.01) {
        await this.cleanup()
      }
    } catch (error) {
      // don't throw on logging errors - just log to console
      console.error("ActivityLogger: Failed to log activity:", error)
    }
  }

  /**
   * @returns {Promise<void>}
   */
  async cleanup() {
    if (!this.enabled) return

    try {
      // delete entries beyond maxEntries limit
      await this.config.db.query(
        `
        DELETE FROM ${this.activityTable}
        WHERE id NOT IN (
          SELECT id FROM ${this.activityTable}
          ORDER BY created_at DESC
          LIMIT $1
        )
        `,
        [this.maxEntries],
      )
    } catch (error) {
      console.error("ActivityLogger: Failed to cleanup old entries:", error)
    }
  }

  /**
   * @param {number} [limit]
   * @param {number} [accountId]
   * @returns {Promise<AuthActivity[]>}
   */
  async getRecentActivity(limit = 100, accountId) {
    if (!this.enabled) return []

    try {
      let sql = `
        SELECT
          al.*,
          a.email
        FROM ${this.activityTable} al
        LEFT JOIN ${this.tablePrefix}accounts a ON al.account_id = a.id
      `
      const params = []

      if (accountId !== undefined) {
        sql += " WHERE al.account_id = $1"
        params.push(accountId)
      }

      sql += ` ORDER BY al.created_at DESC LIMIT $${params.length + 1}`
      params.push(Math.min(limit, 1000)) // cap at 1000 entries max

      const result = await this.config.db.query(sql, params)
      return result.rows.map((row) => ({
        ...row,
        // metadata is a JSONB column, so node-pg already returns it parsed.
        // only parse when a driver hands it back as a raw string
        metadata: typeof row.metadata === "string" ? JSON.parse(row.metadata) : (row.metadata ?? null),
      }))
    } catch (error) {
      console.error("ActivityLogger: Failed to get recent activity:", error)
      return []
    }
  }

  /**
   * @returns {Promise<{ totalEntries: number, uniqueUsers: number, recentLogins: number, failedAttempts: number }>}
   */
  async getActivityStats() {
    if (!this.enabled) {
      return {
        totalEntries: 0,
        uniqueUsers: 0,
        recentLogins: 0,
        failedAttempts: 0,
      }
    }

    try {
      const [total, unique, recent, failed] = await Promise.all([
        this.config.db.query(`SELECT COUNT(*) as count FROM ${this.activityTable}`),
        this.config.db.query(`SELECT COUNT(DISTINCT account_id) as count FROM ${this.activityTable} WHERE account_id IS NOT NULL`),
        this.config.db.query(`SELECT COUNT(*) as count FROM ${this.activityTable} WHERE action = 'login' AND created_at > NOW() - INTERVAL '24 hours'`),
        this.config.db.query(`SELECT COUNT(*) as count FROM ${this.activityTable} WHERE success = false AND created_at > NOW() - INTERVAL '24 hours'`),
      ])

      return {
        totalEntries: parseInt(total.rows[0]?.count || "0"),
        uniqueUsers: parseInt(unique.rows[0]?.count || "0"),
        recentLogins: parseInt(recent.rows[0]?.count || "0"),
        failedAttempts: parseInt(failed.rows[0]?.count || "0"),
      }
    } catch (error) {
      console.error("ActivityLogger: Failed to get activity stats:", error)
      return {
        totalEntries: 0,
        uniqueUsers: 0,
        recentLogins: 0,
        failedAttempts: 0,
      }
    }
  }
}
