import { PgliteClient } from "@effect/sql-pglite"
import { assert } from "@effect/vitest"
import { Context, Effect, Layer, Option, PubSub, Redacted, Ref } from "effect"
import type {
  AuthConfigOptions,
  EmailPasswordConfig,
  PartialOptions,
  SessionConfig,
  TokenConfig
} from "../../src/config/AuthConfig.js"
import { layer as authConfigLayer } from "../../src/config/AuthConfig.js"
import { AuthEmails } from "../../src/config/AuthEmails.js"
import { EmailDeliveryError } from "../../src/domain/Errors.js"
import type { AuthEmail } from "../../src/config/AuthEmails.js"
import { layerScrypt, makeScrypt, PasswordHasher } from "../../src/crypto/PasswordHasher.js"
import { layer as tokenLayer } from "../../src/crypto/Token.js"
import { layer as accountsLayer } from "../../src/domain/Accounts.js"
import type { AuthEvent } from "../../src/domain/Events.js"
import { AuthEvents, layer as authEventsLayer } from "../../src/domain/Events.js"
import { layer as passwordsLayer } from "../../src/domain/Passwords.js"
import { layer as sessionsLayer } from "../../src/domain/Sessions.js"
import * as Migrations from "../../src/sql/Migrations.js"
import * as SqlStores from "../../src/sql/SqlStores.js"

/**
 * One delivered authentication e-mail, as the test harness saw it.
 */
export interface SentEmail extends AuthEmail {
  readonly kind: "verification" | "reset"
}

/**
 * Captures everything `AuthEmails` was asked to deliver.
 */
export class TestEmails extends Context.Service<TestEmails, {
  readonly all: Effect.Effect<ReadonlyArray<SentEmail>>
  readonly last: (kind: SentEmail["kind"]) => Effect.Effect<SentEmail>
}>()("test/TestEmails") {}

/**
 * Whether the mailer accepts what it is handed, or records it and then reports
 * a delivery failure.
 */
export type EmailDelivery = "ok" | "failing"

const emailsLayer = (delivery: EmailDelivery) =>
  Layer.effectContext(Effect.gen(function*() {
    const sent = yield* Ref.make<ReadonlyArray<SentEmail>>([])
    const record = (kind: SentEmail["kind"]) => (email: AuthEmail) =>
      Ref.update(sent, (all) => [...all, { ...email, kind }]).pipe(
        Effect.andThen(
          delivery === "ok"
            ? Effect.void
            : Effect.fail(new EmailDeliveryError({ reason: "TestMailerRefused" }))
        )
      )

    return Context.make(TestEmails, {
      all: Ref.get(sent),
      last: (kind) =>
        Effect.flatMap(Ref.get(sent), (all) => {
          const matching = all.filter((email) => email.kind === kind)
          const latest = matching[matching.length - 1]
          return latest === undefined
            ? Effect.sync(() => assert.fail(`no ${kind} e-mail was sent`))
            : Effect.succeed(latest)
        })
    }).pipe(
      Context.add(AuthEmails, {
        sendVerification: record("verification"),
        sendPasswordReset: record("reset")
      })
    )
  }))

/**
 * Collects every {@link AuthEvent} the domain services publish while `body`
 * runs, and hands them back alongside its result.
 *
 * **Gotchas**
 *
 * The subscription is opened *before* `body` starts: the hub drops rather than
 * replays, so a subscriber attached afterwards would see nothing.
 */
export const recordingEvents = <A, E, R>(body: Effect.Effect<A, E, R>) =>
  Effect.gen(function*() {
    const hub = yield* AuthEvents
    const subscription = yield* hub.subscribe
    const result = yield* body
    const buffered = yield* PubSub.remaining(subscription)
    const events: ReadonlyArray<AuthEvent> = buffered === 0
      ? []
      : yield* PubSub.takeUpTo(subscription, buffered)
    return { result, events }
  })

/**
 * The test configuration. Password hashing runs at a deliberately low cost:
 * production parameters cost tens of milliseconds per hash, and sign-in hashes
 * on every call by design.
 */
export const testConfig = (
  overrides?: {
    readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
    readonly session?: PartialOptions<SessionConfig> | undefined
    readonly tokens?: PartialOptions<TokenConfig> | undefined
    readonly trustedProviders?: ReadonlyArray<string> | undefined
  }
): AuthConfigOptions => ({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("test-secret-not-for-production"),
  trustedProviders: overrides?.trustedProviders ?? [],
  emailPassword: { enabled: true, ...overrides?.emailPassword },
  session: overrides?.session,
  tokens: overrides?.tokens
})

/**
 * A complete `effect-auth` domain on a fresh in-memory PGlite database.
 */
export const testLayer = (
  overrides?: Parameters<typeof testConfig>[0],
  hasher?: Layer.Layer<PasswordHasher>,
  options?: { readonly emailDelivery?: EmailDelivery | undefined }
) => {
  const database = PgliteClient.layer()
  const storage = SqlStores.layer.pipe(
    Layer.provide(Migrations.layer.pipe(Layer.provideMerge(database)))
  )
  const infrastructure = Layer.mergeAll(
    storage,
    authConfigLayer(testConfig(overrides)),
    tokenLayer,
    // See the crypto module's notes: reduced cost, identical stored format.
    hasher ?? layerScrypt(testScryptOptions),
    authEventsLayer(),
    emailsLayer(options?.emailDelivery ?? "ok")
  )
  const domain = Layer.mergeAll(sessionsLayer, accountsLayer).pipe(
    Layer.provideMerge(infrastructure)
  )
  return passwordsLayer.pipe(Layer.provideMerge(domain))
}

/**
 * Cost parameters small enough for a test suite. The stored format is
 * unchanged, so these hashes still verify under the production layer.
 */
export const testScryptOptions = { N: 1024, r: 8, p: 1 } as const

/**
 * A `PasswordHasher` that delegates to the real scrypt implementation and
 * counts what it was asked to do.
 *
 * **When to use**
 *
 * The timing defence in `Passwords.signIn` is invisible from the outside — an
 * unknown address and a wrong password produce the same error either way. What
 * distinguishes a correct implementation is that it *runs a verification* in
 * both cases, and that is what this counts.
 */
export const countingHasher = () => {
  const state = { hashes: 0, verifies: 0 }
  const inner = makeScrypt(globalThis.crypto, testScryptOptions)
  const layer = Layer.succeed(PasswordHasher)({
    hash: (password) =>
      Effect.suspend(() => {
        state.hashes++
        return inner.hash(password)
      }),
    verify: (password, hash) =>
      Effect.suspend(() => {
        state.verifies++
        return inner.verify(password, hash)
      })
  })
  return { layer, state }
}

/**
 * Unwraps an `Option`, failing the test with `message` when it is `None`.
 */
export const expectSome = <A>(option: Option.Option<A>, message: string): Effect.Effect<A> =>
  Option.isSome(option) ? Effect.succeed(option.value) : Effect.sync(() => assert.fail(message))

/**
 * The tags of the events collected by {@link recordingEvents}, in order.
 */
export const tagsOf = (events: ReadonlyArray<AuthEvent>): ReadonlyArray<string> => events.map((event) => event._tag)

/**
 * Per-test timeout. Every test builds its own PGlite database and runs the
 * migrations, which is the isolation that lets each one own its `TestClock`;
 * the default five seconds is not always enough for the first of them.
 */
export const testTimeout = 30_000
