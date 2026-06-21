import { AuthQueries } from "./queries.js"
import { UserNotFoundError } from "./errors.js"

/**
 * @typedef {import("./types.js").AuthConfig} AuthConfig
 * @typedef {import("./types.js").AuthAccount} AuthAccount
 * @typedef {import("./types.js").UserIdentifier} UserIdentifier
 */

const MAX_ROLES = 31

/**
 * Define a set of named roles as a frozen bitmask map. Each role gets the next
 * power-of-two bit. Capped at 31 because postgres INTEGER is 32-bit signed.
 *
 * @template {string} K
 * @param {...K} names
 * @returns {Readonly<Record<K, number>>}
 */
export function defineRoles(...names) {
  if (names.length > MAX_ROLES) {
    throw new Error(`Cannot define more than ${MAX_ROLES} roles (postgres INTEGER is 32-bit signed)`)
  }

  if (names.length === 0) {
    throw new Error("At least one role name is required")
  }

  const seen = new Set()
  /** @type {Record<string, number>} */
  const roles = {}

  for (let i = 0; i < names.length; i++) {
    const name = names[i]
    if (seen.has(name)) {
      throw new Error(`Duplicate role name: ${name}`)
    }
    seen.add(name)
    roles[name] = 1 << i
  }

  return Object.freeze(roles)
}

/**
 * @param {AuthQueries} queries
 * @param {UserIdentifier} identifier
 * @returns {Promise<AuthAccount>}
 */
async function findAccountByIdentifier(queries, identifier) {
  /** @type {AuthAccount | null} */
  let account = null

  if (identifier.accountId !== undefined) {
    account = await queries.findAccountById(identifier.accountId)
  } else if (identifier.email !== undefined) {
    account = await queries.findAccountByEmail(identifier.email)
  } else if (identifier.userId !== undefined) {
    account = await queries.findAccountByUserId(identifier.userId)
  }

  if (!account) {
    throw new UserNotFoundError()
  }

  return account
}

/**
 * Add a role to a user's account using bitwise OR.
 *
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} role
 * @throws {UserNotFoundError}
 */
export async function addRoleToUser(config, identifier, role) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  const rolemask = account.rolemask | role
  await queries.updateAccount(account.id, { rolemask })
}

/**
 * Remove a role from a user's account using bitwise operations.
 *
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} role
 * @throws {UserNotFoundError}
 */
export async function removeRoleFromUser(config, identifier, role) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  const rolemask = account.rolemask & ~role
  await queries.updateAccount(account.id, { rolemask })
}

/**
 * Set a user's complete role mask, replacing any existing roles.
 *
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @param {number} rolemask
 * @throws {UserNotFoundError}
 */
export async function setUserRoles(config, identifier, rolemask) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  await queries.updateAccount(account.id, { rolemask })
}

/**
 * Get a user's current role mask.
 *
 * @param {AuthConfig} config
 * @param {UserIdentifier} identifier
 * @returns {Promise<number>}
 * @throws {UserNotFoundError}
 */
export async function getUserRoles(config, identifier) {
  const queries = new AuthQueries(config)
  const account = await findAccountByIdentifier(queries, identifier)

  return account.rolemask
}
