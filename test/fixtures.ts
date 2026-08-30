/**
 * The small values every suite in this repository reaches for.
 *
 * **Details**
 *
 * `uniqueEmail` is the load-bearing one. Tests inside a `layer()` block share
 * one database, so a fixed address (`ada@example.com` used thirty times in a
 * file) would collide on the unique index the moment two of them ran against
 * the same deployment. Every account a shared-block test creates gets its own
 * address, and every outbox assertion is scoped to it.
 */
import { assert } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"

/**
 * An address no other test will use.
 *
 * `label` is only there to make a failure readable — it says which account in
 * the test the row belongs to.
 */
export const uniqueEmail = (label = "user"): string => `${label}-${globalThis.crypto.randomUUID()}@example.com`

/**
 * The passphrase every test signs up with, redacted as the domain takes it.
 */
export const testPassword: Redacted.Redacted<string> = Redacted.make("correct horse battery staple")

/**
 * {@link testPassword} unwrapped, for the endpoints that take a plain string.
 */
export const testPasswordText = "correct horse battery staple"

/**
 * A replacement passphrase, long enough to satisfy the default policy.
 */
export const newPassword: Redacted.Redacted<string> = Redacted.make("a-much-longer-replacement-passphrase")

/**
 * The display name every test signs up with.
 */
export const testName = "Ada Lovelace"

/**
 * Unwraps an `Option`, failing the test with `message` when it is `None`.
 */
export const expectSome = <A>(option: Option.Option<A>, message: string): Effect.Effect<A> =>
  Option.isSome(option) ? Effect.succeed(option.value) : Effect.sync(() => assert.fail(message))

/**
 * The `_tag` of each element, in order — for asserting on a recorded event
 * stream without naming every payload.
 */
export const tagsOf = <A extends { readonly _tag: string }>(values: ReadonlyArray<A>): ReadonlyArray<string> =>
  values.map((value) => value._tag)
