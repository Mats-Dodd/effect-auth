/**
 * Shared reading of provider-controlled JSON.
 *
 * @internal
 */

/**
 * Narrows an unknown JSON value to a plain object, or `null`.
 *
 * Provider responses are attacker-influenced: every consumer reads the result
 * with an `Object.hasOwn`-guarded reader and never enumerates it.
 *
 * @internal
 */
export const asRecord = (value: unknown): Readonly<Record<string, unknown>> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : null
