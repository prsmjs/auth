// optional cross-instance session invalidation over postgres LISTEN/NOTIFY.
// when config.invalidation.listen is true, security-relevant account writes
// (force-logout, status, role, password) emit pg_notify, and every process
// running a listener drops the matching session on its next request instead of
// waiting up to resyncInterval. this needs no extra dependency - postgres is
// already required. it degrades silently to poll-based resync when the listener
// connection or NOTIFY is unavailable (e.g. pgbouncer in transaction mode)

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 */

const DEFAULT_CHANNEL = "prsm_auth_invalidate"

// prune invalidation marks older than this; a mark only matters until the
// affected session resyncs, which happens well within a minute
const MARK_TTL_MS = 5 * 60 * 1000

/**
 * @typedef {object} ListenerState
 * @property {string} channel
 * @property {Map<number, number>} invalidated accountId -> timestamp of last signal
 * @property {boolean} started
 * @property {boolean} broken
 * @property {import("pg").PoolClient | null} client
 */

// per-pool, per-channel listener state. pools are long-lived objects, so a Map
// keyed by the pool is the natural scope
/** @type {Map<import("pg").Pool, Map<string, ListenerState>>} */
const registry = new Map()

/**
 * @param {AuthConfig} config
 * @returns {string}
 */
function channelFor(config) {
  return config.invalidation?.channel || DEFAULT_CHANNEL
}

/**
 * @param {AuthConfig} config
 * @returns {ListenerState | null}
 */
function getState(config) {
  const pool = config.db
  const channel = channelFor(config)
  let byChannel = registry.get(pool)
  if (!byChannel) {
    byChannel = new Map()
    registry.set(pool, byChannel)
  }
  let state = byChannel.get(channel)
  if (!state) {
    state = { channel, invalidated: new Map(), started: false, broken: false, client: null }
    byChannel.set(channel, state)
  }
  return state
}

/**
 * Start the LISTEN connection for this config's pool/channel if it isn't already
 * running. Idempotent and non-blocking - the first call kicks off the connection
 * and returns; failures mark the listener broken so callers fall back to polling.
 * @param {AuthConfig} config
 */
export function ensureListener(config) {
  if (!config.invalidation?.listen) return

  const state = getState(config)
  if (!state || state.started || state.broken) return
  state.started = true

  const pool = config.db
  const channel = state.channel

  pool
    .connect()
    .then(async (client) => {
      state.client = client
      client.on("notification", (msg) => {
        if (msg.channel !== channel || !msg.payload) return
        const accountId = parseInt(msg.payload, 10)
        if (!Number.isNaN(accountId)) {
          state.invalidated.set(accountId, Date.now())
          pruneMarks(state)
        }
      })
      client.on("error", () => {
        state.broken = true
      })
      await client.query(`LISTEN ${channel}`)
    })
    .catch(() => {
      // listener unavailable (e.g. pooler without session support) - fall back to poll
      state.broken = true
      state.started = false
    })
}

/**
 * Broadcast that an account's auth state changed so other instances resync it
 * immediately. No-op unless invalidation is enabled.
 * @param {AuthConfig} config
 * @param {number} accountId
 * @returns {Promise<void>}
 */
export async function notifyInvalidation(config, accountId) {
  if (!config.invalidation?.listen) return
  try {
    await config.db.query("SELECT pg_notify($1, $2)", [channelFor(config), String(accountId)])
  } catch {
    // notify is best-effort; poll-based resync remains the backstop
  }
}

/**
 * Whether the given account was signaled invalid more recently than `sinceTs`.
 * @param {AuthConfig} config
 * @param {number} accountId
 * @param {number} sinceTs epoch millis
 * @returns {boolean}
 */
export function wasInvalidatedSince(config, accountId, sinceTs) {
  if (!config.invalidation?.listen) return false
  const pool = config.db
  const byChannel = registry.get(pool)
  if (!byChannel) return false
  const state = byChannel.get(channelFor(config))
  if (!state) return false
  const ts = state.invalidated.get(accountId)
  return ts != null && ts > sinceTs
}

/**
 * @param {ListenerState} state
 */
function pruneMarks(state) {
  const cutoff = Date.now() - MARK_TTL_MS
  for (const [accountId, ts] of state.invalidated) {
    if (ts < cutoff) state.invalidated.delete(accountId)
  }
}

/**
 * Release all listener connections. Intended for test teardown and graceful
 * shutdown - production processes normally keep listeners for their lifetime.
 * @returns {Promise<void>}
 */
export async function closeInvalidationListeners() {
  for (const byChannel of registry.values()) {
    for (const state of byChannel.values()) {
      if (state.client) {
        try {
          state.client.release()
        } catch {
          // ignore
        }
      }
      state.client = null
      state.started = false
      state.invalidated.clear()
    }
  }
  registry.clear()
}
