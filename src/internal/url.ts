/**
 * Internal URL helpers. Not exported from the package: nothing here is part of
 * the public API.
 *
 * @internal
 */

/**
 * `value` with every trailing `/` removed.
 *
 * **Details**
 *
 * Trimmed in a loop rather than with a regex: a pattern anchored on a repeated
 * trailing character backtracks polynomially on hostile input, and the values
 * trimmed here — issuers, base URLs, provider endpoints — are configuration- or
 * provider-supplied.
 *
 * @internal
 */
export const trimTrailingSlashes = (value: string): string => {
  let trimmed = value
  while (trimmed.endsWith("/")) trimmed = trimmed.slice(0, -1)
  return trimmed
}
