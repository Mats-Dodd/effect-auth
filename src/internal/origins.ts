/**
 * Origin parsing, shared by the configuration that computes a deployment's
 * trusted-origin set and by the HTTP guards that read it. Not exported from the
 * package: `http/OriginCheck.ts` is where this reaches the public API, and is
 * where the reasoning behind it is written down.
 *
 * @internal
 */
import { Array, Option, Schema } from "effect"

/** `new URL(s)` as a total function: an unparseable string decodes to `None`. */
const decodeUrl = Schema.decodeOption(Schema.URLFromString)

/**
 * The schemes an origin may be spoken over.
 *
 * @internal
 */
export const webProtocols: ReadonlySet<string> = new Set(["http:", "https:"])

/**
 * The origin of a URL, or `None` when it is not an absolute `http(s)` URL — so
 * the literal `"null"` that every opaque scheme parses to is never an origin.
 *
 * @internal
 */
export const originOf = (url: string): Option.Option<string> =>
  Option.flatMap(
    decodeUrl(url),
    (parsed) => webProtocols.has(parsed.protocol) ? Option.some(parsed.origin) : Option.none()
  )

/**
 * The set of origins a configuration trusts: the one `baseUrl` is served from,
 * plus whatever `trustedOrigins` adds. An entry with no origin is dropped.
 *
 * @internal
 */
export const trustedOriginSet = (options: {
  readonly baseUrl: string
  readonly trustedOrigins: ReadonlyArray<string>
}): ReadonlySet<string> => new Set(Array.getSomes([options.baseUrl, ...options.trustedOrigins].map(originOf)))
