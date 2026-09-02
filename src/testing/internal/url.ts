/**
 * One job: point a connection URL at another database on the same server.
 *
 * Not part of the public API.
 *
 * @internal
 */

/**
 * `url` with its database replaced by `database`, credentials and host intact.
 *
 * @internal
 */
export const withDatabase = (url: string, database: string): string => {
  const parsed = new URL(url)
  parsed.pathname = `/${database}`
  return parsed.toString()
}
