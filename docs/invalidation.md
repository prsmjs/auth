# Cross-instance Invalidation, Tracing, and Rate Limiting

These three integrations are optional and duck-typed. The package never imports `@prsm/trace` or `@prsm/limit`, and the invalidation feature uses the PostgreSQL connection you already have. When you leave them unconfigured, behavior is unchanged.

## Cross-instance invalidation

By default a session re-reads account state from the database on an interval (`resyncInterval`, default `"30s"`). A ban, role change, or force-logout made on one instance can therefore take up to that long to reach an instance that already has the session cached. See [Sessions and resync](./sessions.md) for the resync mechanics.

Turn on PostgreSQL `LISTEN/NOTIFY` and those changes propagate immediately:

```js
const authConfig = {
  db: pool,
  invalidation: { listen: true },
}
```

When enabled, security-relevant writes (force-logout, status, role, password) emit a notification, and every instance running a listener drops the affected session on its next request instead of waiting for the interval.

How it works:

- The middleware opens one dedicated `LISTEN` connection per pool and channel, lazily, on the first request. It is idempotent.
- The relevant account writes call `pg_notify` with the affected account ID.
- On its next request, an instance that received the signal forces a resync for that account even if the interval has not elapsed.
- Notification marks are pruned after a few minutes, since they only matter until the affected session resyncs.

It falls back to interval-based resync automatically when the listener connection or `NOTIFY` is unavailable, for example behind a pooler running in transaction mode. The notification is best-effort: if `pg_notify` fails, poll-based resync remains the backstop.

```js
const authConfig = {
  db: pool,
  invalidation: {
    listen: true,
    channel: "prsm_auth_invalidate", // default; override if you run multiple deployments on one database
  },
}
```

For graceful shutdown or test teardown, release the listener connections:

```js
import { closeInvalidationListeners } from "@prsm/auth"

await closeInvalidationListeners()
```

## Tracing

Pass a [@prsm/trace](https://github.com/prsmjs/trace) tracer (or anything with a compatible `span` method) as `config.tracer`. Login is wrapped in a span; without a tracer the call runs plain.

```js
import { createTracer } from "@prsm/trace"

const authConfig = {
  db: pool,
  tracer: createTracer({ service: "api" }),
}
```

## Rate limiting

Pass a [@prsm/limit](https://github.com/prsmjs/limit) limiter as `config.limiter`. One unit is consumed against the limiter, keyed by email, before each login attempt. When the limit is hit, login throws `RateLimitedError` with a `retryAfter` value, and the failed attempt is recorded in the activity log with reason `rate_limited`.

```js
import { tokenBucket } from "@prsm/limit"

const authConfig = {
  db: pool,
  limiter: tokenBucket({ redis, capacity: 5, refillRate: 5, refillInterval: "1m" }),
}
```

Any `@prsm/limit` algorithm works. The package duck-types the limiter against `take`, `hit`, `drip`, `consume`, and `check`, and each returns `{ allowed, retryAfter }`.

```js
import { RateLimitedError } from "@prsm/auth"

app.post("/login", async (req, res) => {
  try {
    await req.auth.login(req.body.email, req.body.password, req.body.remember)
    res.json({ ok: true })
  } catch (error) {
    if (error instanceof RateLimitedError) {
      res.set("Retry-After", String(error.retryAfter ?? 60))
      return res.status(429).json({ error: "too many attempts" })
    }
    res.status(401).json({ error: error.message })
  }
})
```
