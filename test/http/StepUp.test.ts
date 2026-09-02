import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted, Schema } from "effect"
import { Cookies } from "effect/unstable/http"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import type { AuthenticatorSummary } from "../../src/domain/Authenticators.js"
import type { SignInPipelineService } from "../../src/domain/SignIn.js"
import { proceed, SignInDecision } from "../../src/domain/SignIn.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AuthApi } from "../../src/http/AuthApi.js"
import { pluginCookieFor } from "../../src/http/Cookies.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import { Authenticated, CurrentSession, freshSession, RequireAssurance } from "../../src/http/Middleware.js"
import { setSessionCookie } from "../../src/http/MiddlewareLive.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * The pending token this deployment's decider hands out.
 *
 * A fixed value, because nothing here spends it: what is under test is where it
 * travels, not what it addresses. A real factor plugin mints one through
 * `Verifications` and answers its own endpoint against it.
 */
const pendingToken = "pending-authentication-token-for-the-test"

/** How long the challenge this deployment issues is good for. */
const challengeTtl = Duration.minutes(10)

/** The one authenticator these people could step up with. */
const totp: AuthenticatorSummary = {
  type: "totp",
  id: "totp-1",
  name: null,
  verifiedAt: null,
  lastUsedAt: null,
  signIn: false,
  secondFactor: true,
  restricted: false
}

/**
 * The addresses this deployment's decider owes a second factor to.
 *
 * A test enrols an account *after* registering it, so that sign-up mints the
 * session it always did and only the sign-in that follows is challenged — which
 * is what enrolling a second factor actually looks like.
 */
const enrolled = new Set<string>()

/**
 * A factor plugin's decider, without the plugin: it owes a second factor to
 * anybody who has enrolled one, and lets everybody else through.
 */
const pipeline: SignInPipelineService = {
  decide: (options) =>
    enrolled.has(options.user.email)
      ? Effect.map(DateTime.now, (now) =>
          SignInDecision.Challenge({
            kind: "mfa",
            available: ["totp"],
            token: Redacted.make(pendingToken),
            expiresAt: DateTime.addDuration(now, challengeTtl)
          })
        )
      : Effect.succeed(proceed)
}

const Aal = Schema.Struct({ aal: Schema.String })

/**
 * The three endpoints a factor plugin would declare, plus its step-up.
 *
 * `elevated` carries `RequireAssurance` and deliberately *not*
 * `AuthoritativeSession`: it is what proves the assurance annotation bypasses
 * the cookie cache on its own rather than by riding on the other one.
 */
const GuardedGroup = HttpApiGroup.make("guarded")
  .add(
    HttpApiEndpoint.get("elevated", "/elevated", { success: Aal })
      .middleware(Authenticated)
      .annotate(RequireAssurance, { aal: "aal2" })
  )
  .add(
    HttpApiEndpoint.get("recent", "/recent", { success: Aal })
      .middleware(Authenticated)
      .annotate(RequireAssurance, freshSession)
  )
  .add(HttpApiEndpoint.get("open", "/open", { success: Aal }).middleware(Authenticated))
  .add(HttpApiEndpoint.post("totp", "/totp", { success: Aal }).middleware(Authenticated))
  .prefix("/auth/guarded")

const GuardedApi = HttpApi.make("step-up-app").addHttpApi(AuthApi).add(GuardedGroup)

const answerAal = Effect.map(CurrentSession, (session) => ({ aal: session.aal }))

/**
 * A second factor's verify endpoint, in miniature: it elevates the session with
 * a possession factor and re-sets the cookie the rotated token now needs. Every
 * factor plugin's own endpoint does exactly this.
 */
const guardedHandlers = AuthHandlers.forGroup(GuardedGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const sessions = yield* Sessions
    return handlers
      .handle("elevated", () => answerAal)
      .handle("recent", () => answerAal)
      .handle("open", () => answerAal)
      .handle("totp", () =>
        Effect.gen(function* () {
          const session = yield* CurrentSession
          const elevated = yield* sessions
            .elevate(session, {
              method: "totp",
              factor: "possession",
              phishingResistant: false,
              restricted: false
            })
            .pipe(AuthHandlers.serverFault)
          yield* setSessionCookie(config, elevated.session, elevated.token, {
            persistent: elevated.session.rememberMe
          })
          return { aal: elevated.session.aal }
        })
      )
  })
)

/**
 * The session store every deployment in this file wraps, so "and that request
 * read the row" is a count rather than a claim.
 *
 * One counter for the file, which is why the block runs sequentially.
 */
const store = AuthTest.countingSessionStore()

/**
 * The hasher, for the same reason: "one verification either way" is a count and
 * not an assertion about wall-clock time.
 */
const hasher = AuthTest.countingHasher()

const stepUp = AuthTest.layerHttpApi(
  GuardedApi,
  {
    cookieCache: { enabled: true },
    authenticators: { list: () => Effect.succeed([totp]) },
    signInPipeline: pipeline,
    sessionStore: store.layer,
    hasher: hasher.layer
  },
  guardedHandlers(GuardedApi)
)

describe.sequential("http/step-up", () => {
  layer(stepUp)("", (it) => {
    /** Registers an account through the API and returns the browser holding it. */
    const registered = (label: string) =>
      Effect.gen(function* () {
        const email = uniqueEmail(label)
        const made = yield* TestHttpClient.makeClient(GuardedApi)
        yield* made.client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        return { ...made, email }
      })

    describe("RequireAssurance", () => {
      it.effect("refuses an aal1 session and names the policy, the level and the factors", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("aal1-refused")

          const error = yield* Effect.flip(client.guarded.elevated())

          assert.strictEqual(error._tag, "StepUpRequired")
          if (error._tag !== "StepUpRequired") return
          // The endpoint asked for aal2 and stated no maxAge, so the middleware
          // resolved it against `assurance.stepUpWindow` — twelve hours.
          assert.deepStrictEqual(error.required, { aal: "aal2", maxAge: 43_200 })
          assert.strictEqual(error.current.aal, "aal1")
          // What this person could step up with, from the `Authenticators` seam
          // and nothing else: kinds of factor, no identifier, no address.
          assert.deepStrictEqual(error.current.available, ["totp"])
          assert.isTrue(DateTime.isUtc(error.current.authenticatedAt))
          // And nothing that is not in the contract.
          assert.deepStrictEqual(Object.keys(error.current).sort(), ["aal", "authenticatedAt", "available"])
        })
      )

      it.effect("lets an unannotated endpoint through at aal1", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("aal1-open")
          assert.deepStrictEqual(yield* client.guarded.open(), { aal: "aal1" })
          // And one whose policy is only "recently, please".
          assert.deepStrictEqual(yield* client.guarded.recent(), { aal: "aal1" })
        })
      )

      it.effect("cannot be satisfied by a cookie-cache snapshot written at aal1", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("snapshot-aal1")

          // Warm the cache: this request leaves a snapshot in the jar, and the
          // next unannotated one is served from it without touching the store.
          yield* client.guarded.open()
          const cached = store.state.reads
          yield* client.guarded.open()
          assert.strictEqual(store.state.reads, cached, "an unannotated endpoint must be served from the snapshot")

          // The guarded one is not, even though the same snapshot is in the jar
          // and the endpoint carries no `AuthoritativeSession`.
          const before = store.state.reads
          const error = yield* Effect.flip(client.guarded.elevated())
          assert.strictEqual(error._tag, "StepUpRequired")
          assert.isAbove(store.state.reads, before, "an assurance policy must be decided against the row")
        })
      )

      it.effect("accepts the session the moment a factor elevates it, stale snapshot and all", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("snapshot-elevated")

          // A snapshot written while the session was still aal1.
          yield* client.guarded.open()
          assert.strictEqual((yield* Effect.flip(client.guarded.elevated()))._tag, "StepUpRequired")

          // A second factor: knowledge plus possession is aal2.
          assert.deepStrictEqual(yield* client.guarded.totp(), { aal: "aal2" })

          // No cache invalidation dance: the annotation reads the row, and the
          // row says aal2.
          assert.deepStrictEqual(yield* client.guarded.elevated(), { aal: "aal2" })
        })
      )
    })

    describe("reauthenticate", () => {
      it.effect("re-stamps the session, appends the evidence and keeps the id", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("reauth")
          const before = yield* client.auth.getSession()
          assert.strictEqual(before.session.aal, "aal1")

          const after = yield* client.auth.reauthenticate({ payload: { password: testPassword } })

          assert.strictEqual(after.session.id, before.session.id, "an open tab must survive a step-up")
          assert.strictEqual(after.user.id, before.user.id)
          // Two knowledge entries are still one kind of factor, so the level is
          // unchanged — what moved is `authenticatedAt`, which is what every
          // freshness policy is measured from.
          assert.strictEqual(after.session.aal, "aal1")
          assert.deepStrictEqual(
            after.session.methods.map((entry) => entry.method),
            ["password", "password"]
          )
          assert.deepStrictEqual(
            after.session.methods.map((entry) => entry.factor),
            ["knowledge", "knowledge"]
          )
          assert.isTrue(DateTime.isGreaterThanOrEqualTo(after.session.authenticatedAt, before.session.authenticatedAt))
          // The rolling refresh's own columns are not what this touched.
          assert.deepStrictEqual(after.session.createdAt, before.session.createdAt)
        })
      )

      it.effect("rotates the token, so the cookie the browser now holds is a new one", () =>
        Effect.gen(function* () {
          const { client, cookies } = yield* registered("reauth-rotate")
          const before = yield* TestHttpClient.sessionCookieValue(cookies)

          yield* client.auth.reauthenticate({ payload: { password: testPassword } })

          const after = yield* TestHttpClient.sessionCookieValue(cookies)
          assert.notStrictEqual(after, before, "the elevated session must not answer to the old token")
          // The raw token is 32 random bytes, base64url encoded.
          assert.strictEqual(after.length, 43)
          // And the browser is still signed in, on the new one.
          yield* client.auth.getSession()
        })
      )

      it.effect("refuses a wrong password with InvalidCredentials and moves nothing", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("reauth-wrong")
          const before = yield* client.auth.getSession()

          const error = yield* Effect.flip(
            client.auth.reauthenticate({ payload: { password: Redacted.make("not the password") } })
          )

          assert.strictEqual(error._tag, "InvalidCredentials")
          const after = yield* client.auth.getSession()
          assert.deepStrictEqual(after.session.authenticatedAt, before.session.authenticatedAt)
          assert.strictEqual(after.session.methods.length, before.session.methods.length)
        })
      )

      it.effect("spends exactly one hash verification whether the password is right or wrong", () =>
        Effect.gen(function* () {
          const { client } = yield* registered("reauth-timing")

          const start = hasher.state.verifies
          yield* Effect.flip(client.auth.reauthenticate({ payload: { password: Redacted.make("wrong") } }))
          const wrong = hasher.state.verifies - start
          yield* client.auth.reauthenticate({ payload: { password: testPassword } })
          const right = hasher.state.verifies - start - wrong

          // The equal-cost rule `Passwords.verifyPassword` owns, asserted at the
          // endpoint: one verification each way, so a wrong answer takes what a
          // right one does — the same discipline `signIn` runs.
          assert.strictEqual(wrong, 1)
          assert.strictEqual(right, 1)
        })
      )
    })

    describe("MfaRequired", () => {
      /** Signs `email` in and hands back both the decoded body and the response. */
      const signIn = (email: string) =>
        Effect.gen(function* () {
          const made = yield* TestHttpClient.makeClient(GuardedApi)
          yield* made.client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
          // Sign-up minted a session for this browser; drop it, so what the
          // sign-in writes is the only thing in the jar. The factor is enrolled
          // afterwards, exactly as a person would enrol one.
          yield* made.client.auth.signOut()
          enrolled.add(email)
          const answer = yield* made.client.auth.signInEmail({
            payload: { email, password: testPassword },
            responseMode: "decoded-and-response"
          })
          return { ...made, body: answer[0], response: answer[1] }
        })

      it.effect("answers 202 with the factor kinds and nothing that names the person", () =>
        Effect.gen(function* () {
          const { body, response } = yield* signIn(uniqueEmail("mfa-202"))

          assert.strictEqual(response.status, 202)
          assert.isTrue("_tag" in body, "a challenged sign-in must not answer a session")
          if (!("_tag" in body)) return
          assert.strictEqual(body._tag, "MfaRequired")
          assert.deepStrictEqual(body.available, ["totp"])
          assert.isTrue(DateTime.isUtc(body.expiresAt))
          // No user id, no address, no token: a 202 tells somebody who guessed a
          // password nothing they could not already infer.
          const json = yield* response.text
          assert.isFalse(json.includes("@example.com"))
          assert.isFalse(json.includes(pendingToken))
          // Every key on the wire, so a member added to `MfaRequired` that
          // named the person would have to change this line.
          assert.deepStrictEqual(Object.keys(Object(JSON.parse(json))).sort(), ["_tag", "available", "expiresAt"])
        })
      )

      it.effect("sets the pending cookie and no session cookie on the same response", () =>
        Effect.gen(function* () {
          const { cookies, response } = yield* signIn(uniqueEmail("mfa-cookies"))

          // Read off `Set-Cookie` itself rather than out of the jar: the rule is
          // about one response, and a jar would hide a session cookie that was
          // set and then replaced.
          const written = Cookies.toRecord(response.cookies)
          assert.deepStrictEqual(Object.keys(written), ["effect_auth.pending"])

          const config = yield* AuthConfig
          const expected = pluginCookieFor(config, {
            baseName: AuthHandlers.pendingCookieBaseName,
            hostOnly: true,
            maxAge: challengeTtl
          })
          const pending = Option.getOrThrow(Cookies.get(response.cookies, expected.name))
          assert.strictEqual(pending.value, pendingToken)
          assert.strictEqual(pending.options?.httpOnly, true)
          assert.strictEqual(pending.options?.path, "/")
          assert.isUndefined(pending.options?.domain)
          assert.strictEqual(
            Duration.toSeconds(Duration.fromInputUnsafe(pending.options?.maxAge ?? 0)),
            Duration.toSeconds(challengeTtl)
          )

          // And the jar agrees: what is left there is the emptied cookie the
          // sign-out wrote, which authenticates nothing.
          assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")
        })
      )

      it.effect("writes the session cookie, and no pending cookie, when nothing is owed", () =>
        Effect.gen(function* () {
          // The control for the assertion above: the same reading of
          // `Set-Cookie` on an unchallenged sign-in sees a session cookie, so
          // its absence on the 202 is the handler's doing and not the harness's.
          const email = uniqueEmail("no-mfa-cookies")
          const { client } = yield* TestHttpClient.makeClient(GuardedApi)
          yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
          yield* client.auth.signOut()

          const [, response] = yield* client.auth.signInEmail({
            payload: { email, password: testPassword },
            responseMode: "decoded-and-response"
          })

          assert.strictEqual(response.status, 200)
          const written = Object.keys(Cookies.toRecord(response.cookies))
          assert.isTrue(written.includes("effect_auth.session"))
          assert.isFalse(written.includes(AuthHandlers.pendingCookieBaseName))
        })
      )

      it.effect("mints no session, so the browser is still signed out", () =>
        Effect.gen(function* () {
          const { client } = yield* signIn(uniqueEmail("mfa-nosession"))
          const refused = yield* Effect.flip(client.auth.getSession())
          assert.strictEqual(refused._tag, "Unauthorized")
        })
      )

      it.effect("marks the redirect a browser leaves by, without putting the token on it", () =>
        Effect.sync(() => {
          // The OAuth callback cannot answer a 202: the browser arrived by a
          // top-level navigation and has to leave by one. `?mfa=required` is
          // the same shape `?error=` already uses.
          const marked = AuthHandlers.withMfaRequired("https://app.example.com/welcome?next=%2Fhome")
          assert.strictEqual(marked, "https://app.example.com/welcome?next=%2Fhome&mfa=required")
          assert.isFalse(marked.includes(pendingToken))
          assert.strictEqual(AuthHandlers.mfaRequiredParam, "mfa")
          // Setting it twice does not accumulate.
          assert.strictEqual(AuthHandlers.withMfaRequired(marked), marked)
        })
      )

      it.effect("expires the pending cookie with the attributes it was set with", () =>
        Effect.gen(function* () {
          const config = yield* AuthConfig
          const cookie = AuthHandlers.pendingCookie(config, challengeTtl)
          // A browser replaces a cookie only when the name, path and domain all
          // match, so the expiry has to repeat them.
          assert.strictEqual(cookie.expiredOptions.path, cookie.options.path)
          assert.strictEqual(cookie.expiredOptions.domain, cookie.options.domain)
          assert.strictEqual(cookie.expiredOptions.sameSite, cookie.options.sameSite)
          assert.strictEqual(cookie.expiredOptions.httpOnly, true)
          assert.isUndefined(cookie.expiredOptions.maxAge)
          assert.deepStrictEqual(cookie.expiredOptions.expires, new Date(0))
          assert.strictEqual(cookie.security.key, cookie.name)
        })
      )

      it.effect("names __Host- on a TLS deployment and the bare name on plain HTTP", () =>
        Effect.gen(function* () {
          const plain = yield* AuthConfig
          assert.strictEqual(
            pluginCookieFor(plain, { baseName: "effect_auth.pending", hostOnly: true, maxAge: challengeTtl }).name,
            "effect_auth.pending"
          )
          assert.strictEqual(
            pluginCookieFor(
              { ...plain, cookie: { ...plain.cookie, secure: true } },
              {
                baseName: "effect_auth.pending",
                hostOnly: true,
                maxAge: challengeTtl
              }
            ).name,
            "__Host-effect_auth.pending"
          )
        })
      )
    })
  })
})
