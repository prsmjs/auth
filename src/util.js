import { InvalidEmailError } from "./errors.js"

/**
 * @param {string} email
 * @returns {boolean}
 */
export const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/**
 * @param {string} email
 * @throws {InvalidEmailError}
 */
export const validateEmail = (email) => {
  if (typeof email !== "string") {
    throw new InvalidEmailError()
  }
  if (!email.trim()) {
    throw new InvalidEmailError()
  }
  if (!isValidEmail(email)) {
    throw new InvalidEmailError()
  }
}

/**
 * @param {Record<string, number>} enumObj
 * @returns {Record<number, string>}
 */
export const createMapFromEnum = (enumObj) => Object.fromEntries(Object.entries(enumObj).map(([key, value]) => [value, key]))
