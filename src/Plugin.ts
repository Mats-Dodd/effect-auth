/**
 * The pieces a plugin written outside this package needs and that belong to no
 * one module.
 *
 * **Details**
 *
 * A plugin is seams, not a registry: an `HttpApiGroup`, a Layer, a migrations
 * record, a client function, and the primitives — `AuthHooks`,
 * `Authenticators`, `Verifications`, `Challenges` — it hangs itself on. Each of
 * those lives in the module that owns it and needs nothing from here. What is
 * left over is the handful of helpers that are *how this library is written*
 * rather than *what it does*, and that a plugin must therefore share rather
 * than re-derive.
 *
 * There is exactly one today. Resist the temptation to make this a junk drawer:
 * anything with an owner goes to its owner.
 *
 * @since 0.1.0
 */
import { withDefaults as internalWithDefaults } from "./internal/records.js"

/**
 * `defaults`, with whatever `overrides` actually states applied over it.
 *
 * **When to use**
 *
 * To resolve a plugin's own options section. Every settings section in this
 * library resolves through this one shape, and a plugin's should too: a caller
 * may leave the section out entirely, or pass it with an explicit `undefined`
 * for any field, and neither may cost a default.
 *
 * That is the part worth sharing rather than rewriting. `{ ...defaults,
 * ...overrides }` is the obvious spelling and it is wrong — an explicitly
 * `undefined` field overwrites the default with `undefined`, and a section
 * built by spreading a caller's partial options has one of those for every
 * field they did not mention.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Duration } from "effect"
 * import { Plugin } from "effect-auth"
 *
 * interface OtpConfig {
 *   readonly ttl: Duration.Duration
 *   readonly digits: number
 * }
 *
 * const defaults: OtpConfig = { ttl: Duration.minutes(10), digits: 8 }
 *
 * const resolve = (options?: { readonly [K in keyof OtpConfig]?: OtpConfig[K] | undefined }): OtpConfig =>
 *   Plugin.withDefaults(defaults, options)
 * ```
 *
 * @category combinators
 * @since 0.1.0
 */
export const withDefaults: <A extends object>(
  defaults: A,
  overrides: { readonly [K in keyof A]?: A[K] | undefined } | undefined
) => A = internalWithDefaults
