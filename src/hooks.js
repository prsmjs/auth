// thin, duck-typed adapters for the optional @prsm/trace and @prsm/limit
// instances. auth never imports those packages; it only calls what's passed in,
// so either can be absent without any coupling

/**
 * @typedef {import("./types.js").Tracer} Tracer
 * @typedef {import("./types.js").Limiter} Limiter
 */

/**
 * Run fn inside a tracing span when a tracer is provided, otherwise run it plain.
 * Matches the @prsm/trace tracer shape: tracer.span(name, attributes, fn).
 * @template T
 * @param {Tracer | undefined} tracer
 * @param {string} name
 * @param {Record<string, any>} attributes
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
export function withSpan(tracer, name, attributes, fn) {
  if (tracer && typeof tracer.span === "function") {
    return tracer.span(name, attributes, fn)
  }
  return fn()
}

/**
 * Consume one unit against a limiter for the given key. The @prsm/limit
 * algorithms expose different verbs (tokenBucket.take, slidingWindow.hit,
 * leakyBucket.drip); all return { allowed, retryAfter }. We accept any of them
 * plus a generic consume/check so callers can pass a limiter instance directly.
 * @param {Limiter | undefined} limiter
 * @param {string} key
 * @returns {Promise<{ allowed: boolean, retryAfter?: number } | null>}
 */
export async function consumeLimit(limiter, key) {
  if (!limiter) return null
  const fn = limiter.take || limiter.hit || limiter.drip || limiter.consume || limiter.check
  if (typeof fn !== "function") return null
  return fn.call(limiter, key)
}
