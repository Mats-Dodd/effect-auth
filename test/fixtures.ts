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
 *
 * `signUpUser` and `forUser` are the two effects that follow from that: the
 * registration nearly every domain test opens with, and the filter that narrows
 * a deployment-wide event recording to the user the test is about. The HTTP
 * suites' equivalents — a client, a signed-in browser — live in
 * `test/http/helpers.ts`.
 */
import { assert } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"
import type { AuthEvent } from "../src/domain/Events.js"
import { Passwords } from "../src/domain/Passwords.js"

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
 * Registers a user and hands back the row, the session sign-up established and
 * that session's raw token.
 *
 * **Gotchas**
 *
 * Every test in a `layer()` block writes to one database, so `email` must be a
 * {@link uniqueEmail}: two tests registering `ada@example.com` would collide on
 * the unique index rather than testing anything.
 *
 * The session is unwrapped here, so this is for a deployment that establishes
 * one — `autoSignIn` on, verification not required. A test of the branch that
 * establishes none reads `signUp`'s own `Option` instead.
 */
export const signUpUser = Effect.fnUntraced(function* (email: string) {
  const passwords = yield* Passwords
  const result = yield* passwords.signUp({ name: testName, email, password: testPassword })
  const created = yield* expectSome(result.session, "sign-up should establish a session")
  return { user: result.user, session: created.session, token: created.token }
})

/**
 * The events one user's flows published.
 *
 * The event hub belongs to the deployment, and the deployment is shared by
 * every test in the block, so an assertion on the whole recording would also be
 * an assertion about whatever the siblings happened to be doing.
 */
export const forUser = (events: ReadonlyArray<AuthEvent>, userId: string): ReadonlyArray<AuthEvent> =>
  events.filter((event) => event.userId === userId)
