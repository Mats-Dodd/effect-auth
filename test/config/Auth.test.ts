/**
 * The batteries entry point and the test harness built on it.
 *
 * These are the assembly tests: every module is exercised elsewhere, so what is
 * checked here is that `Auth.layer` wires them together — that a sign-up
 * reaches the database, that the event hub is connected, that virtual time
 * moves session expiry, and that `layerConfig` reads what it says it reads.
 */
import { assert, it } from "@effect/vitest"
import { Config, ConfigProvider, DateTime, Duration, Effect, Fiber, Layer, Option, Redacted, Stream } from "effect"
import { TestClock } from "effect/testing"
import { Auth, AuthConfig, Passwords, Sessions } from "../../src/index.js"
import { AuthTest } from "../../src/testing/index.js"

const password = Redacted.make("correct horse battery staple")

it.effect("signs a user up, through the whole stack", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const result = yield* passwords.signUp({
      name: "Ada Lovelace",
      email: "Ada@Example.COM",
      password
    })

    // The address was normalised on the way in.
    assert.strictEqual(result.user.email, "ada@example.com")
    assert.strictEqual(result.user.emailVerified, false)
    // `autoSignIn` defaults on and verification is not required here.
    assert.strictEqual(Option.isSome(result.session), true)

    // And the row is really in the database: signing in reads it back.
    const signedIn = yield* passwords.signIn({ email: "ada@example.com", password })
    assert.strictEqual(signedIn.user.id, result.user.id)
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)

it.effect("publishes events to `Auth.events`", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords

    // Subscribe before the traffic: the hub drops, it does not replay.
    const collected = yield* Effect.forkChild(Stream.runCollect(Stream.take(Auth.events, 2)))
    yield* Effect.yieldNow

    yield* passwords.signUp({ name: "Ada", email: "ada@example.com", password })

    const events = yield* Fiber.join(collected)
    assert.deepStrictEqual(events.map((event) => event._tag), ["UserCreated", "SignedIn"])
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)

it.effect("expires a session once its lifetime has elapsed", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const sessions = yield* Sessions.Sessions

    yield* passwords.signUp({ name: "Ada", email: "ada@example.com", password })
    const signedIn = yield* passwords.signIn({ email: "ada@example.com", password })

    // Well inside the default seven days: still good, and refreshed on the way.
    yield* TestClock.adjust(Duration.days(2))
    const live = yield* sessions.verify(signedIn.token)
    assert.strictEqual(live.refreshed, true)

    // Past the refreshed expiry: refused, and the dead row is cleaned up.
    yield* TestClock.adjust(Duration.days(8))
    const expired = yield* Effect.flip(sessions.verify(signedIn.token))
    assert.strictEqual(expired._tag, "SessionExpired")
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)

it.effect("captures the reset e-mail so a test can read its token", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const emails = yield* AuthTest.TestEmails

    yield* passwords.signUp({ name: "Ada", email: "ada@example.com", password })
    assert.strictEqual(Option.isNone(yield* emails.last("reset")), true)

    yield* passwords.requestReset({ email: "ada@example.com" })
    const token = yield* emails.tokenFor("reset")

    const newPassword = Redacted.make("a-much-longer-replacement-passphrase")
    yield* passwords.resetPassword({ token, newPassword })

    const signedIn = yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
    assert.strictEqual(signedIn.user.email, "ada@example.com")
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)

it.effect("asks nothing of an unknown address, and says nothing about it", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const emails = yield* AuthTest.TestEmails

    // No account: still a success, and no mail goes out.
    yield* passwords.requestReset({ email: "nobody@example.com" })
    assert.strictEqual(Option.isNone(yield* emails.last("reset")), true)
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)

it.effect("cleanupExpired reaps what has expired and leaves what has not", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const sessions = yield* Sessions.Sessions

    const { user } = yield* passwords.signUp({ name: "Ada", email: "ada@example.com", password })
    yield* passwords.requestReset({ email: "ada@example.com" })
    // A second session that outlives the first, so the sweep has to be
    // selective rather than a truncate.
    yield* sessions.create({ userId: user.id })

    // Past the one-hour reset TTL, and past the sign-up session's own life:
    // `rememberMe` defaults on, so both sessions run seven days.
    yield* TestClock.adjust(Duration.days(8))

    const first = yield* Auth.cleanupExpired
    assert.strictEqual(first.sessions, 2)
    assert.strictEqual(first.verifications, 1)

    // Nothing is left to reap, and reaping again is not an error.
    const second = yield* Auth.cleanupExpired
    assert.deepStrictEqual(second, { sessions: 0, verifications: 0 })

    // The user is untouched: only the dead rows went.
    yield* passwords.signIn({ email: "ada@example.com", password })
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)

it.effect("layerConfig reads the scalar settings from a ConfigProvider", () =>
  Effect.gen(function*() {
    const config = yield* AuthConfig.AuthConfig
    assert.strictEqual(config.baseUrl, "https://app.example.com")
    assert.strictEqual(Redacted.value(config.secret), "from-the-environment")
    // An https base URL implies a Secure cookie under the `__Secure-` prefix.
    assert.strictEqual(config.cookie.secure, true)
    assert.strictEqual(AuthConfig.cookieName(config), "__Secure-effect_auth.session")
    // Sections still get their defaults.
    assert.strictEqual(Duration.toSeconds(config.session.expiresIn), 7 * 24 * 60 * 60)
    assert.strictEqual(config.emailPassword.enabled, true)
  }).pipe(
    Effect.provide(
      Auth.layerConfig({
        baseUrl: Config.string("BASE_URL"),
        secret: Config.redacted("AUTH_SECRET"),
        emailPassword: { enabled: true }
      }).pipe(
        Layer.provideMerge(AuthTest.layerDatabase),
        Layer.provideMerge(AuthTest.layerEmails),
        Layer.provide(
          ConfigProvider.layer(
            ConfigProvider.fromUnknown({
              BASE_URL: "https://app.example.com",
              AUTH_SECRET: "from-the-environment"
            })
          )
        )
      )
    )
  ), AuthTest.testTimeout)

it.effect("test deployments share one fixed secret and a normalised clock", () =>
  Effect.gen(function*() {
    const config = yield* AuthConfig.AuthConfig
    assert.strictEqual(config.secret, AuthTest.testSecret)
    assert.strictEqual(config.baseUrl, AuthTest.testBaseUrl)
    // The limits are off unless a test asks for them: three requests is fewer
    // than most flows make.
    assert.strictEqual(config.rateLimit.enabled, false)
    assert.strictEqual(config.emailPassword.enabled, true)

    // Everything is on the test clock, so a token minted now is dated now.
    const before = yield* DateTime.now
    yield* TestClock.adjust(Duration.hours(1))
    const after = yield* DateTime.now
    assert.strictEqual(DateTime.toEpochMillis(after) - DateTime.toEpochMillis(before), 3_600_000)
  }).pipe(Effect.provide(AuthTest.layer())), AuthTest.testTimeout)
