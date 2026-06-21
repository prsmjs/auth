import express from "express"
import session from "express-session"
import cookieParser from "cookie-parser"
import pg from "pg"
import { createAuthMiddleware, createAuthTables, dropAuthTables, closeInvalidationListeners } from "../index.js"

const { Pool } = pg

export async function createTestDatabase() {
  const url = process.env.AUTH_TEST_POSTGRES_URL
  const poolOptions = { max: 15, idleTimeoutMillis: 1000 }
  const pool = url
    ? new Pool({ connectionString: url, ...poolOptions })
    : new Pool({
        host: process.env.PGHOST || "localhost",
        port: parseInt(process.env.PGPORT || "5432"),
        database: process.env.PGDATABASE || "auth_test",
        user: process.env.PGUSER || "auth",
        password: process.env.PGPASSWORD || "auth_password",
        ...poolOptions,
      })

  try {
    await pool.query("SELECT NOW()")
  } catch (error) {
    throw new Error("Failed to connect to test database. Make sure to run: make up")
  }

  return pool
}

export async function createOAuthTestApp() {
  const pool = await createTestDatabase()

  const app = express()

  app.use(express.json())
  app.use(cookieParser())
  app.use(
    session({
      secret: "oauth-test-secret-key-for-testing-only",
      resave: false,
      saveUninitialized: false,
      cookie: { secure: false, httpOnly: true },
    }),
  )

  const authConfig = {
    db: pool,
    createUser: async (userData) => {
      // simulate creating user in app's user table
      return `oauth-user-${userData.id}`
    },
    tablePrefix: "oauth_test_",
    minPasswordLength: 6,
    maxPasswordLength: 50,
    rememberDuration: "7d",
    rememberCookieName: "oauth_test_remember_token",
    resyncInterval: "30s",
  }

  await dropAuthTables(authConfig)
  await createAuthTables(authConfig)

  app.use(createAuthMiddleware(authConfig))

  // standard auth routes for testing
  app.post("/register", async (req, res) => {
    try {
      const { email, password, requireConfirmation } = req.body
      let confirmationToken

      const account = await req.auth.register(
        email,
        password,
        "oauth-test-user-123",
        requireConfirmation
          ? (token) => {
              confirmationToken = token
            }
          : undefined,
      )

      res.json({
        success: true,
        account: {
          id: account.id,
          email: account.email,
          verified: account.verified,
          status: account.status,
        },
        confirmationToken,
      })
    } catch (error) {
      res.status(400).json({ error: error.message })
    }
  })

  app.get("/profile", async (req, res) => {
    if (!req.auth.isLoggedIn()) {
      return res.status(401).json({ error: "Not logged in" })
    }

    res.json({
      id: req.auth.getId(),
      email: req.auth.getEmail(),
      status: req.auth.getStatus(),
      statusName: req.auth.getStatusName(),
      verified: req.auth.getVerified(),
      roles: req.auth.getRoleNames(),
      remembered: req.auth.isRemembered(),
      isAdmin: await req.auth.isAdmin(),
    })
  })

  // utility routes for OAuth tests
  app.post("/set-user-session", (req, res) => {
    req.session.userId = req.body.userId || "oauth-test-user-123"
    req.session.save((err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to save session" })
      }
      res.json({ success: true })
    })
  })

  return {
    app,
    pool,
    authConfig,
    cleanup: async () => {
      await closeInvalidationListeners()
      await pool.end()
    },
  }
}
