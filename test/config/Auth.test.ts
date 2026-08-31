/**
 * The batteries entry point and the test harness built on it.
 *
 * These are the assembly tests: every module is exercised elsewhere, so what is
 * checked here is that `Auth.layer` wires them together — that a sign-up
 * reaches the database, that the event hub is connected, that virtual time
 * moves session expiry, that `layerConfig` reads what it says it reads, that
 * `layerWithOAuth` is the same stack with the flow in it, and that the redacted
 * header names reach the context the application actually runs on.
 *
 * The default-deployment tests share one database through `layer()`. The event
 * hub and `cleanupExpired` tests stay on per-test deployments: the hub is
 * shared by everything in a block, so a shared subscription would also record
 * the siblings, and the sweep is table-wide, so a shared database would lose
 * the siblings' live rows to it.
 */
import { assert, it, layer } from "@effect/vitest"
import {
  Config,
  ConfigProvider,
  DateTime,
  Duration,
  Effect,
  Fiber,
  Layer,
  Option,
  Redactable,
  Redacted,
  Stream
} from "effect"
import { TestClock } from "effect/testing"
import type { HttpClient } from "effect/unstable/http"
import { FetchHttpClient, Headers } from "effect/unstable/http"
import { Auth, AuthConfig, AuthCookies, Github, OAuthFlow, Passwords, Sessions } from "../../src/index.js"
import { AuthTest } from "../../src/testing/index.js"
import { newPassword, signUpUser, testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * A transport that refuses to be used. `start` mints a state row and builds a
 * URL; it never talks to the provider, so a test of the assembly must not need
 * a network — and must fail loudly if that ever stops being true.
 */
const noNetwork: Layer.Layer<HttpClient.HttpClient> = FetchHttpClient.layer.pipe(
  Layer.provide(
    Layer.succeed(FetchHttpClient.Fetch)(() =>
      Promise.reject(new Error("effect-auth test: no request should have been made"))
    )
  )
)

layer(AuthTest.layer())("config/Auth assembly", (it) => {
  it.effect("signs a user up, through the whole stack", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords.Passwords
      const email = uniqueEmail("assembly")
      const result = yield* passwords.signUp({
        name: testName,
        // The address was normalised on the way in.
        email: email.toUpperCase(),
        password: testPassword
      })

      assert.strictEqual(result.user.email, email)
      assert.strictEqual(result.user.emailVerified, false)
      // `autoSignIn` defaults on and verification is not required here.
      assert.strictEqual(Option.isSome(result.session), true)

      // And the row is really in the database: signing in reads it back.
      const signedIn = yield* passwords.signIn({ email, password: testPassword })
      assert.strictEqual(signedIn.user.id, result.user.id)
    }))

  it.effect("expires a session once its lifetime has elapsed", () =>
    AuthTest.freshClock(Effect.gen(function*() {
      const passwords = yield* Passwords.Passwords
      const sessions = yield* Sessions.Sessions
      const email = uniqueEmail("expiry")

      yield* signUpUser(email)
      const signedIn = yield* passwords.signIn({ email, password: testPassword })

      // Well inside the default seven days: still good, and refreshed on the way.
      yield* TestClock.adjust(Duration.days(2))
      const live = yield* sessions.verify(signedIn.token)
      assert.strictEqual(live.refreshed, true)

      // Past the refreshed expiry: refused, and the dead row is cleaned up.
      yield* TestClock.adjust(Duration.days(8))
      const expired = yield* Effect.flip(sessions.verify(signedIn.token))
      assert.strictEqual(expired._tag, "SessionExpired")
    })))

  it.effect("captures the reset e-mail so a test can read its token", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords.Passwords
      const emails = yield* AuthTest.TestEmails
      const email = uniqueEmail("reset")

      yield* signUpUser(email)
      assert.strictEqual(Option.isNone(yield* emails.last("reset", email)), true)

      yield* passwords.requestReset({ email })
      const token = yield* emails.tokenFor("reset", email)

      yield* passwords.resetPassword({ token, newPassword })

      const signedIn = yield* passwords.signIn({ email, password: newPassword })
      assert.strictEqual(signedIn.user.email, email)
    }))

  it.effect("asks nothing of an unknown address, and says nothing about it", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords.Passwords
      const emails = yield* AuthTest.TestEmails
      const email = uniqueEmail("nobody")

      // No account: still a success, and no mail goes out.
      yield* passwords.requestReset({ email })
      assert.strictEqual(Option.isNone(yield* emails.last("reset", email)), true)
      assert.deepStrictEqual(yield* emails.to(email), [])
    }))

  it.effect("test deployments share one fixed secret and a normalised clock", () =>
    AuthTest.freshClock(Effect.gen(function*() {
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
    })))
})

it.effect("publishes events to `Auth.events`", () =>
  Effect.gen(function*() {
    // Subscribe before the traffic: the hub drops, it does not replay.
    const collected = yield* Effect.forkChild(Stream.runCollect(Stream.take(Auth.events, 2)))
    yield* Effect.yieldNow

    yield* signUpUser(uniqueEmail("events"))

    const events = yield* Fiber.join(collected)
    assert.deepStrictEqual(events.map((event) => event._tag), ["UserCreated", "SignedIn"])
  }).pipe(Effect.provide(AuthTest.layer())))

it.effect("cleanupExpired reaps what has expired and leaves what has not", () =>
  Effect.gen(function*() {
    const passwords = yield* Passwords.Passwords
    const sessions = yield* Sessions.Sessions
    const email = uniqueEmail("cleanup")

    const { user } = yield* signUpUser(email)
    yield* passwords.requestReset({ email })
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
    yield* passwords.signIn({ email, password: testPassword })
  }).pipe(Effect.provide(AuthTest.layer())))

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
        Layer.provideMerge(AuthTest.layerEmails()),
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
  ))

it.effect("layerWithOAuth assembles the flow over the providers it is handed", () =>
  Effect.gen(function*() {
    const flow = yield* OAuthFlow.OAuthFlow
    const started = yield* flow.start({ providerId: "github" })

    // The provider value reached the registry, and the flow addressed it.
    const url = new URL(started.url)
    assert.strictEqual(url.origin + url.pathname, "https://github.com/login/oauth/authorize")
    assert.strictEqual(url.searchParams.get("client_id"), "gh-client-id")

    // And an id that was never registered still misses.
    const missing = yield* Effect.flip(flow.start({ providerId: "gitlab" }))
    assert.strictEqual(missing._tag, "OAuthProviderError")
  }).pipe(
    Effect.provide(
      Auth.layerWithOAuth({
        ...AuthTest.testConfig(),
        providers: [
          Github.make({ clientId: "gh-client-id", clientSecret: Redacted.make("gh-client-secret") })
        ]
      }).pipe(
        Layer.provideMerge(Layer.mergeAll(AuthTest.layerDatabase, AuthTest.layerEmails())),
        Layer.provide(noNetwork)
      )
    )
  ))

it.effect("layerConfigWithOAuth reads the provider credentials from a ConfigProvider", () =>
  Effect.gen(function*() {
    const config = yield* AuthConfig.AuthConfig
    assert.strictEqual(config.baseUrl, "https://app.example.com")

    const flow = yield* OAuthFlow.OAuthFlow
    const started = yield* flow.start({ providerId: "github" })
    assert.strictEqual(
      new URL(started.url).searchParams.get("client_id"),
      "id-from-the-environment"
    )
  }).pipe(
    Effect.provide(
      Auth.layerConfigWithOAuth({
        baseUrl: Config.string("BASE_URL"),
        secret: Config.redacted("AUTH_SECRET"),
        rateLimit: { enabled: false },
        providers: [
          Github.makeConfig({
            clientId: Config.string("GITHUB_CLIENT_ID"),
            clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
          })
        ]
      }).pipe(
        Layer.provideMerge(Layer.mergeAll(AuthTest.layerDatabase, AuthTest.layerEmails())),
        Layer.provide(noNetwork),
        Layer.provide(
          ConfigProvider.layer(
            ConfigProvider.fromUnknown({
              BASE_URL: "https://app.example.com",
              AUTH_SECRET: "from-the-environment",
              GITHUB_CLIENT_ID: "id-from-the-environment",
              GITHUB_CLIENT_SECRET: "secret-from-the-environment"
            })
          )
        )
      )
    )
  ))

it.effect("registers the redacted header names on the application's own context", () =>
  Effect.gen(function*() {
    // `Headers` reads `CurrentRedactedNames` from the *current* context when a
    // header set is logged, so the names have to reach the context the
    // application runs on — not merely the one the stack was built with. This
    // is a `Layer.provideMerge`, and it is load-bearing: with `Layer.provide`
    // the reference falls back to its default and `Auth.layer`'s
    // `redactedHeaders` option silently does nothing.
    const names = yield* Effect.service(Headers.CurrentRedactedNames)

    for (const name of AuthCookies.redactedHeaderNames) {
      assert.include(names, name)
    }
    assert.include(names, "x-tenant-token")

    // And the header really renders redacted under it: `Redactable.redact` is
    // what a log line goes through, and it reads the reference off the fiber.
    assert.strictEqual(
      JSON.stringify(
        Redactable.redact(Headers.fromInput({ "x-tenant-token": "hunter2", "x-public": "fine" }))
      ),
      `{"x-tenant-token":"<redacted>","x-public":"fine"}`
    )
  }).pipe(
    Effect.provide(
      Auth.layer({
        baseUrl: "http://localhost:3000",
        secret: Redacted.make("effect-auth-test-secret-do-not-use-in-production"),
        rateLimit: { enabled: false },
        redactedHeaders: ["x-tenant-token"]
      }).pipe(Layer.provideMerge(Layer.mergeAll(AuthTest.layerDatabase, AuthTest.layerEmails())))
    )
  ))
