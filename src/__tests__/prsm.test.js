import { describe, it, expect, beforeAll, afterAll } from "vitest"
import request from "supertest"
import { createTestApp, createTestDatabase } from "./test-setup.js"
import { createAuthContext, createAuthTables, dropAuthTables, ActivityLogger, AuthStatus, AuthRole, AuthActivityAction, TwoFactorMechanism } from "../index.js"
import { ensureListener, notifyInvalidation, wasInvalidatedSince, closeInvalidationListeners } from "../invalidation.js"

/**
 * @param {() => boolean} predicate
 * @param {number} timeoutMs
 */
async function waitFor(predicate, timeoutMs = 4000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return true
    await new Promise((r) => setTimeout(r, 50))
  }
  return false
}

describe("optional limiter (duck-typed @prsm/limit)", () => {
  let app
  let cleanup
  let allowed = true

  beforeAll(async () => {
    // duck-typed limiter using the tokenBucket verb (take); auth should not care
    const limiter = { take: async () => ({ allowed, retryAfter: 1000 }) }
    const ctx = await createTestApp({ tablePrefix: "prsm_lim_", limiter })
    app = ctx.app
    cleanup = ctx.cleanup

    await request(app).post("/register").send({ email: "lim@example.com", password: "password123" })
    // verify so login can proceed when allowed
    const pool = ctx.pool
    await pool.query(`UPDATE prsm_lim_accounts SET verified = true WHERE email = $1`, ["lim@example.com"])
  })

  afterAll(async () => {
    await cleanup()
  })

  it("permits login when the limiter allows it", async () => {
    allowed = true
    const res = await request(app).post("/login").send({ email: "lim@example.com", password: "password123" })
    expect(res.status).toBe(200)
  })

  it("rejects login with RateLimitedError when the limiter denies it", async () => {
    allowed = false
    const res = await request(app).post("/login").send({ email: "lim@example.com", password: "password123" })
    expect(res.status).toBe(401)
    expect(res.body.errorType).toBe("RateLimitedError")
  })
})

describe("optional tracer (duck-typed @prsm/trace)", () => {
  let app
  let cleanup
  const spans = []

  beforeAll(async () => {
    const tracer = {
      span: (name, attributes, fn) => {
        spans.push(name)
        return fn()
      },
    }
    const ctx = await createTestApp({ tablePrefix: "prsm_trc_", tracer })
    app = ctx.app
    cleanup = ctx.cleanup

    await request(app).post("/register").send({ email: "trc@example.com", password: "password123" })
    await ctx.pool.query(`UPDATE prsm_trc_accounts SET verified = true WHERE email = $1`, ["trc@example.com"])
  })

  afterAll(async () => {
    await cleanup()
  })

  it("wraps login in a tracing span", async () => {
    await request(app).post("/login").send({ email: "trc@example.com", password: "password123" })
    expect(spans).toContain("auth.login")
  })
})

describe("createAuthContext devtools surface", () => {
  let pool
  let config
  let ctx

  beforeAll(async () => {
    pool = await createTestDatabase()
    config = { db: pool, tablePrefix: "prsm_ctx_", minPasswordLength: 6 }
    await dropAuthTables(config)
    await createAuthTables(config)
    ctx = createAuthContext(config)
  })

  afterAll(async () => {
    await closeInvalidationListeners()
    await pool.end()
  })

  it("lists accounts with a total count", async () => {
    await ctx.createUser({ email: "a@example.com", password: "password123" }, "u-a")
    await ctx.createUser({ email: "b@example.com", password: "password123" }, "u-b")
    const { accounts, total } = await ctx.listAccounts({ limit: 10 })
    expect(total).toBe(2)
    expect(accounts.length).toBe(2)
  })

  it("searches accounts by email", async () => {
    const { accounts, total } = await ctx.listAccounts({ search: "a@" })
    expect(total).toBe(1)
    expect(accounts[0].email).toBe("a@example.com")
  })

  it("gets a single account by identifier", async () => {
    const account = await ctx.getAccount({ email: "b@example.com" })
    expect(account.user_id).toBe("u-b")
  })

  it("throws UserNotFoundError for a missing account", async () => {
    await expect(ctx.getAccount({ email: "nope@example.com" })).rejects.toThrow("User not found")
  })

  it("exposes the role map", () => {
    expect(ctx.getRoles()).toBe(AuthRole)
  })

  it("returns table stats", async () => {
    const stats = await ctx.getStats()
    expect(stats.accounts).toBe(2)
  })

  it("returns recent activity entries", async () => {
    const activity = await ctx.getRecentActivity(10)
    expect(Array.isArray(activity)).toBe(true)
  })

  // regression: metadata is a JSONB column, so node-pg returns it already
  // parsed. getRecentActivity used to call JSON.parse on it unconditionally,
  // which threw and made the method silently return [] for any row with
  // metadata. it must round-trip metadata as a parsed object and surface the
  // parsed user-agent fields
  it("round-trips activity metadata and parses the user agent", async () => {
    const account = await ctx.getAccount({ email: "a@example.com" })
    const logger = new ActivityLogger(config)
    const req = {
      headers: { "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36" },
      socket: { remoteAddress: "10.0.0.9" },
    }
    await logger.logActivity(account.id, AuthActivityAction.Login, req, true, { email: "a@example.com", remember: true })

    const activity = await ctx.getRecentActivity(10, account.id)
    expect(activity.length).toBeGreaterThan(0)
    const entry = activity[0]
    expect(entry.action).toBe(AuthActivityAction.Login)
    expect(entry.metadata).toEqual({ email: "a@example.com", remember: true })
    expect(entry.browser).toBe("Chrome")
  })

  it("exposes the status map", () => {
    expect(ctx.getStatuses()).toBe(AuthStatus)
  })

  it("exposes the two-factor mechanism map", () => {
    expect(ctx.getMechanisms()).toBe(TwoFactorMechanism)
  })

  it("reflects role changes through getAccount", async () => {
    await ctx.addRoleForUserBy({ email: "a@example.com" }, AuthRole.Admin)
    const account = await ctx.getAccount({ email: "a@example.com" })
    expect((account.rolemask & AuthRole.Admin) === AuthRole.Admin).toBe(true)
  })

  it("removes a two-factor method by id (admin rescue path)", async () => {
    const account = await ctx.createUser({ email: "ctx2fa@example.com", password: "password123" }, "u-2fa")
    await pool.query(`INSERT INTO prsm_ctx_2fa_methods (account_id, mechanism, secret, verified) VALUES ($1, $2, $3, true)`, [account.id, TwoFactorMechanism.TOTP, "SECRETSECRETSECRET"])

    let methods = await ctx.getTwoFactorMethods(account.id)
    expect(methods).toHaveLength(1)

    await ctx.removeTwoFactorMethod({ accountId: account.id }, methods[0].id)

    methods = await ctx.getTwoFactorMethods(account.id)
    expect(methods).toHaveLength(0)
  })

  it("rejects removing a 2FA method that does not belong to the account", async () => {
    const account = await ctx.getAccount({ email: "ctx2fa@example.com" })
    await expect(ctx.removeTwoFactorMethod({ accountId: account.id }, 999999)).rejects.toThrow()
  })
})

describe("cross-instance invalidation (postgres LISTEN/NOTIFY)", () => {
  let pool
  let config

  beforeAll(async () => {
    pool = await createTestDatabase()
    config = { db: pool, tablePrefix: "prsm_inv_", minPasswordLength: 6, invalidation: { listen: true } }
    await dropAuthTables(config)
    await createAuthTables(config)
    ensureListener(config)
  })

  afterAll(async () => {
    await closeInvalidationListeners()
    await pool.end()
  })

  it("delivers an explicit notify to the listener", async () => {
    // give the LISTEN connection a moment to attach, then notify
    await waitFor(() => false, 300)
    await notifyInvalidation(config, 4242)
    const got = await waitFor(() => wasInvalidatedSince(config, 4242, 0))
    expect(got).toBe(true)
  })

  it("notifies when a security-relevant account field changes", async () => {
    const ctx = createAuthContext(config)
    const account = await ctx.createUser({ email: "inv@example.com", password: "password123" }, "u-inv")
    const since = Date.now() - 1
    await ctx.setStatusForUserBy({ accountId: account.id }, AuthStatus.Banned)
    const got = await waitFor(() => wasInvalidatedSince(config, account.id, since))
    expect(got).toBe(true)
  })

  it("does not report invalidation for an untouched account", () => {
    expect(wasInvalidatedSince(config, 999999, 0)).toBe(false)
  })
})
