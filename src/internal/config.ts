/**
 * Internal `Config` helpers. Not exported from the package: nothing here is
 * part of the public API.
 *
 * @internal
 */
import { Config } from "effect"

/**
 * A setting a caller left out, as a `Config` that resolves to `undefined`.
 *
 * **Details**
 *
 * Every `…makeConfig` in this library takes its optional settings as
 * `Config<A> | undefined`, and every one of them used to read those back with a
 * ladder of `x === undefined ? undefined : yield* x`. Wrapping the absent ones
 * instead makes the whole set a record of `Config`s, which `Config.unwrap`
 * resolves in one call — one description of what a deployment reads, rather
 * than one `yield*` and one conditional per setting.
 *
 * @internal
 */
export const optionalConfig = <A>(config: Config.Config<A> | undefined): Config.Config<A | undefined> =>
  config ?? Config.succeed(undefined)
