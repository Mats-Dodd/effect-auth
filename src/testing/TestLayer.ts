/**
 * A complete `effect-auth` deployment for a test suite: an in-memory PGlite
 * database with the migrations already applied, a fixed secret, a mailer that
 * captures what it was asked to deliver instead of sending it, and password
 * hashing at a cost a suite can afford.
 *
 * Everything runs under `it.effect` and `TestClock`, so session expiry, the
 * rolling refresh and token TTLs are all reachable by moving virtual time.
 *
 * @since 1.0.0
 */
import { PgliteClient } from "@effect/sql-pglite"
import { Context, Effect, Layer, Option, Redacted, Ref } from "effect"
import type { SqlClient, SqlError } from "effect/unstable/sql"
import type { Migrator } from "effect/unstable/sql"
import type { Services } from "../config/Auth.js"
import { layer as authLayer } from "../config/Auth.js"
import type {
  AuthConfigOptions,
  CookieConfig,
  EmailPasswordConfig,
  EmailPathConfig,
  PartialOptions,
  RateLimitConfig,
  SessionConfig,
  TokenConfig
} from "../config/AuthConfig.js"
import type { AuthEmail } from "../config/AuthEmails.js"
import { AuthEmails } from "../config/AuthEmails.js"
import type { ScryptOptions } from "../crypto/PasswordHasher.js"
import { layerScrypt } from "../crypto/PasswordHasher.js"
import * as Migrations from "../sql/Migrations.js"

// -----------------------------------------------------------------------------
// Captured mail
// -----------------------------------------------------------------------------

/**
 * Which of the two authentication e-mails was delivered.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailKind = "verification" | "reset"

/**
 * One e-mail the application asked to have delivered.
 *
 * @category models
 * @since 1.0.0
 */
export interface SentEmail extends AuthEmail {
  readonly kind: EmailKind
}

/**
 * The captured outbox.
 *
 * **When to use**
 *
 * A verification or reset token exists exactly once, in the message that
 * carries it — nothing but its hash is stored. This service is how a test reads
 * that token, the way a person reads it out of their inbox.
 *
 * **Example**
 *
 * ```ts
 * import { Effect } from "effect"
 * import { AuthTest } from "effect-auth/testing"
 *
 * const token = Effect.gen(function*() {
 *   const emails = yield* AuthTest.TestEmails
 *   return yield* emails.tokenFor("reset")
 * })
 * ```
 *
 * @category services
 * @since 1.0.0
 */
export class TestEmails extends Context.Service<TestEmails, {
  /**
   * Every e-mail delivered so far, oldest first.
   */
  readonly all: Effect.Effect<ReadonlyArray<SentEmail>>

  /**
   * The most recent e-mail of a kind, or `None` when none was sent.
   */
  readonly last: (kind: EmailKind) => Effect.Effect<Option.Option<SentEmail>>

  /**
   * The raw token from the most recent e-mail of a kind.
   *
   * Fails with a defect when no such e-mail was sent — in a test that is a
   * broken assumption, not a condition to recover from.
   */
  readonly tokenFor: (kind: EmailKind) => Effect.Effect<Redacted.Redacted<string>>

  /**
   * Empties the outbox.
   */
  readonly clear: Effect.Effect<void>
}>()("effect-auth/testing/TestEmails") {}

/**
 * The capturing mailer, providing both {@link TestEmails} and the `AuthEmails`
 * seam that `Auth.layer` requires.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerEmails: Layer.Layer<TestEmails | AuthEmails> = Layer.effectContext(
  Effect.gen(function*() {
    const outbox = yield* Ref.make<ReadonlyArray<SentEmail>>([])
    const record = (kind: EmailKind) => (email: AuthEmail) =>
      Ref.update(outbox, (sent) => [...sent, { ...email, kind }])

    const last = (kind: EmailKind) =>
      Effect.map(Ref.get(outbox), (sent) => {
        const matching = sent.filter((email) => email.kind === kind)
        return Option.fromUndefinedOr(matching[matching.length - 1])
      })

    return Context.make(TestEmails, {
      all: Ref.get(outbox),
      last,
      tokenFor: (kind) =>
        Effect.flatMap(
          last(kind),
          Option.match({
            onNone: () => Effect.die(new Error(`effect-auth/testing: no ${kind} e-mail was sent`)),
            onSome: (email) => Effect.succeed(email.token)
          })
        ),
      clear: Ref.set(outbox, [])
    }).pipe(
      Context.add(AuthEmails, {
        sendVerification: record("verification"),
        sendPasswordReset: record("reset")
      })
    )
  })
)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * The secret every test deployment is keyed with. Fixed on purpose: a signature
 * produced in one test is verifiable in the next, and nothing here is a
 * credential worth protecting.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testSecret: Redacted.Redacted<string> = Redacted.make(
  "effect-auth-test-secret-do-not-use-in-production"
)

/**
 * The default base URL: plain HTTP, so the session cookie is written under its
 * un-prefixed name and a test can look for it without knowing whether TLS was
 * simulated.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testBaseUrl = "http://localhost:3000"

/**
 * Scrypt parameters small enough for a suite. The stored format records the
 * cost it was written at, so a hash produced here still verifies under the
 * production layer.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testScryptOptions: ScryptOptions = { N: 1024, r: 8, p: 1 }

/**
 * What a test may vary about the deployment under test. Everything is
 * optional; the defaults are a working e-mail/password deployment with the
 * rate limits switched off.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options {
  readonly baseUrl?: string | undefined
  readonly secret?: Redacted.Redacted<string> | undefined
  readonly basePath?: string | undefined
  readonly trustedOrigins?: ReadonlyArray<string> | undefined
  readonly trustedProviders?: ReadonlyArray<string> | undefined
  readonly session?: PartialOptions<SessionConfig> | undefined
  readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
  readonly cookie?: PartialOptions<CookieConfig> | undefined
  readonly tokens?: PartialOptions<TokenConfig> | undefined
  readonly rateLimit?: PartialOptions<RateLimitConfig> | undefined
  readonly emailPaths?: PartialOptions<EmailPathConfig> | undefined
  /**
   * Scrypt cost overrides. Defaults to {@link testScryptOptions}.
   */
  readonly scrypt?: ScryptOptions | undefined
}

/**
 * Resolves {@link Options} into the options `Auth.layer` takes.
 *
 * **Details**
 *
 * The two departures from the library defaults are deliberate:
 * `emailPassword.enabled` is `true` (a test that had to switch it on before it
 * could sign anybody up would say nothing about the library), and
 * `rateLimit.enabled` is `false` (three requests is fewer than most flows make,
 * so the limits would fire in tests that are not about them — switch them back
 * on in the tests that are).
 *
 * @category constructors
 * @since 1.0.0
 */
export const testConfig = (options?: Options): AuthConfigOptions => ({
  baseUrl: options?.baseUrl ?? testBaseUrl,
  secret: options?.secret ?? testSecret,
  basePath: options?.basePath,
  trustedOrigins: options?.trustedOrigins,
  trustedProviders: options?.trustedProviders,
  session: options?.session,
  emailPassword: { enabled: true, ...options?.emailPassword },
  cookie: options?.cookie,
  tokens: options?.tokens,
  rateLimit: { enabled: false, ...options?.rateLimit },
  emailPaths: options?.emailPaths
})

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * A fresh in-memory PGlite database with `effect-auth`'s migrations applied.
 *
 * **Gotchas**
 *
 * Every build is a new, empty database. Provide it once per test — not once per
 * suite — unless the tests in that suite are meant to share state.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerDatabase: Layer.Layer<
  SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> = Migrations.layer.pipe(Layer.provideMerge(PgliteClient.layer()))

/**
 * The whole test deployment: {@link layerDatabase}, the capturing mailer, and
 * `Auth.layer` at test cost.
 *
 * **Example**
 *
 * ```ts
 * import { it } from "@effect/vitest"
 * import { assert } from "@effect/vitest"
 * import { Effect, Redacted } from "effect"
 * import { Passwords } from "effect-auth"
 * import { AuthTest } from "effect-auth/testing"
 *
 * it.effect("signs a person up", () =>
 *   Effect.gen(function*() {
 *     const passwords = yield* Passwords.Passwords
 *     const { user } = yield* passwords.signUp({
 *       name: "Ada",
 *       email: "ada@example.com",
 *       password: Redacted.make("correct horse battery staple")
 *     })
 *     assert.strictEqual(user.email, "ada@example.com")
 *   }).pipe(Effect.provide(AuthTest.layer())))
 * ```
 *
 * **Gotchas**
 *
 * No OAuth provider is configured, so `OAuthFlow` is absent and no `HttpClient`
 * is needed. To exercise the OAuth flow, compose `Auth.layer` yourself with
 * `providers: [...]` over {@link layerDatabase} and {@link layerEmails} plus a
 * stubbed `HttpClient`.
 *
 * Booting PGlite and running the migrations costs a few hundred milliseconds,
 * which exceeds vitest's five-second default on a cold start when several
 * suites boot at once: give clock-moving tests their own layer and a longer
 * timeout ({@link testTimeout}).
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  Services<readonly []> | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  authLayer({
    ...testConfig(options),
    passwordHasher: layerScrypt(options?.scrypt ?? testScryptOptions)
  }).pipe(
    Layer.provideMerge(Layer.mergeAll(layerDatabase, layerEmails))
  )

/**
 * A per-test timeout that accommodates a cold PGlite boot plus the migrations.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testTimeout = 30_000
