import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted, Ref } from "effect"
import { TestClock } from "effect/testing"
import { Cookies } from "effect/unstable/http"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import type { SignInPipelineService } from "../../src/domain/SignIn.js"
import { proceed } from "../../src/domain/SignIn.js"
import { pluginCookieFor } from "../../src/http/Cookies.js"
import { ceremonyCookieBaseName } from "../../src/passkeys/Handlers.js"
import { PasskeyId } from "../../src/passkeys/Schema.js"
import * as PasskeysTest from "../../src/testing/PasskeysTest.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

const client = (options?: TestHttpClient.ClientOptions) => TestHttpClient.makeClient(PasskeysTest.TestApi, options)

/** A browser that has signed up and is holding that session. */
const signedUp = Effect.fnUntraced(function* (email: string, options?: TestHttpClient.ClientOptions) {
  const made = yield* client(options)
  const result = yield* made.client.auth.signUpEmail({
    payload: { name: testName, email, password: testPassword }
  })
  return { ...made, user: result.user }
})

type Browser = Effect.Success<ReturnType<typeof client>>

/** Registers a credential through the endpoints, exactly as a page would. */
const enrol = Effect.fnUntraced(function* (api: Browser) {
  const authenticator = yield* PasskeysTest.makeAuthenticator()
  const options = yield* api.client.passkeys.registerOptions({ payload: {} })
  const response = yield* authenticator.register(options)
  const summary = yield* api.client.passkeys.registerVerify({ payload: { response, name: "laptop" } })
  return { authenticator, summary }
})

describe.sequential("passkeys/Handlers", () => {
  layer(PasskeysTest.layerHttp())("the ceremony over HTTP", (it) => {
    it.effect("registers a credential and signs a fresh browser in with it", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-round-trip"))
        const { authenticator, summary } = yield* enrol(owner)
        assert.strictEqual(summary.name, "laptop")
        assert.deepStrictEqual(summary.transports, ["internal"])

        // A browser that has never seen this deployment.
        const fresh = yield* client()
        const options = yield* fresh.client.passkeys.authenticateOptions({ payload: {} })
        const response = yield* authenticator.authenticate(options)
        const [body, http] = yield* fresh.client.passkeys.authenticateVerify({
          payload: { response },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(http.status, 200)
        assert.isFalse("_tag" in body, "nothing is owed, so this must be a session")
        if ("_tag" in body) return
        assert.strictEqual(body.user.id, owner.user.id)
        assert.strictEqual(body.session.aal, "aal2")
        // And the browser is genuinely signed in afterwards.
        const session = yield* fresh.client.auth.getSession()
        assert.strictEqual(session.user.id, owner.user.id)
      })
    )

    it.effect("the ceremony handle travels in a cookie and nothing else", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-cookie"))
        const [document, response] = yield* owner.client.passkeys.registerOptions({
          payload: {},
          responseMode: "decoded-and-response"
        })

        const config = yield* AuthConfig
        const expected = pluginCookieFor(config, {
          baseName: ceremonyCookieBaseName,
          hostOnly: true,
          maxAge: Duration.minutes(5)
        })
        const written = Cookies.toRecord(response.cookies)
        assert.deepStrictEqual(Object.keys(written), [expected.name])

        const cookie = Option.getOrThrow(Cookies.get(response.cookies, expected.name))
        assert.strictEqual(cookie.options?.httpOnly, true)
        assert.strictEqual(cookie.options?.path, "/")
        assert.isUndefined(cookie.options?.domain)
        assert.strictEqual(Duration.toSeconds(Duration.fromInputUnsafe(cookie.options?.maxAge ?? 0)), 300)

        // The option document is script-readable, so the handle must not be in it.
        const json = yield* response.text
        assert.isFalse(json.includes(cookie.value))
        assert.strictEqual(document.attestation, "none")
      })
    )

    it.effect("a verify clears the ceremony cookie even when it refuses", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-clear"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const options = yield* owner.client.passkeys.registerOptions({ payload: {} })
        const response = yield* authenticator.register(options, { origin: "https://evil.example" })

        const config = yield* AuthConfig
        const expected = pluginCookieFor(config, {
          baseName: ceremonyCookieBaseName,
          hostOnly: true,
          maxAge: Duration.minutes(5)
        })
        // The jar holds the handle right up to the moment it is spent.
        const held = Cookies.get(yield* Ref.get(owner.cookies), expected.name)
        assert.isTrue(Option.isSome(held))
        assert.notStrictEqual(Option.getOrThrow(held).value, "")

        const refused = yield* Effect.flip(owner.client.passkeys.registerVerify({ payload: { response } }))
        assert.strictEqual(refused._tag, "PasskeyVerificationFailed")

        // The row was claimed before anything the response said was looked at,
        // so the handle now names nothing and the browser must not keep it.
        const cleared = Option.getOrThrow(Cookies.get(yield* Ref.get(owner.cookies), expected.name))
        assert.strictEqual(cleared.value, "")
      })
    )

    it.effect("presenting no ceremony cookie is the same answer as a spent one", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-no-cookie"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const options = yield* owner.client.passkeys.registerOptions({ payload: {} })
        const response = yield* authenticator.register(options)

        // A second browser holds no ceremony cookie at all.
        const stranger = yield* signedUp(uniqueEmail("http-no-cookie-other"))
        const refused = yield* Effect.flip(stranger.client.passkeys.registerVerify({ payload: { response } }))
        assert.strictEqual(refused._tag, "ChallengeExpired")
      })
    )

    it.effect("raises the caller's own session in place rather than minting a second", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-elevate"))
        const { authenticator } = yield* enrol(owner)
        const before = yield* owner.client.auth.getSession()
        assert.strictEqual(before.session.aal, "aal1")

        const options = yield* owner.client.passkeys.authenticateOptions({ payload: {} })
        const response = yield* authenticator.authenticate(options)
        const body = yield* owner.client.passkeys.authenticateVerify({ payload: { response } })

        assert.isFalse("_tag" in body)
        if ("_tag" in body) return
        assert.strictEqual(body.session.id, before.session.id)
        assert.strictEqual(body.session.aal, "aal2")
        // One session on the device list, not two.
        const listed = yield* owner.client.auth.listSessions()
        assert.strictEqual(listed.length, 1)
        // And the rotated token is the one in the jar: the next request works.
        const after = yield* owner.client.auth.getSession()
        assert.strictEqual(after.session.id, before.session.id)
      })
    )

    it.effect("an unauthenticated caller cannot begin a registration", () =>
      Effect.gen(function* () {
        const stranger = yield* client()
        const refused = yield* Effect.flip(stranger.client.passkeys.registerOptions({ payload: {} }))
        assert.strictEqual(refused._tag, "Unauthorized")
      })
    )

    it.effect("an untrusted Origin cannot begin an authentication", () =>
      Effect.gen(function* () {
        const hostile = yield* client({ headers: { origin: "https://evil.example" } })
        const refused = yield* Effect.flip(hostile.client.passkeys.authenticateOptions({ payload: {} }))
        assert.strictEqual(refused._tag, "OriginNotAllowed")
      })
    )

    it.effect("lists, renames and removes, and only the owner's own", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-manage"))
        const { summary } = yield* enrol(owner)
        const stranger = yield* signedUp(uniqueEmail("http-manage-other"))

        const listed = yield* owner.client.passkeys.listPasskeys()
        assert.deepStrictEqual(
          listed.map((entry) => entry.id),
          [summary.id]
        )
        // No credential id and no public key reach the browser.
        assert.deepStrictEqual(Object.keys(listed[0] ?? {}).sort(), [
          "aaguid",
          "backedUp",
          "createdAt",
          "id",
          "lastUsedAt",
          "name",
          "transports"
        ])

        const renamed = yield* owner.client.passkeys.renamePasskey({ payload: { id: summary.id, name: "phone" } })
        assert.strictEqual(renamed.name, "phone")

        const refused = yield* Effect.flip(
          stranger.client.passkeys.renamePasskey({ payload: { id: summary.id, name: "mine" } })
        )
        assert.strictEqual(refused._tag, "NotFound")
        const refusedDelete = yield* Effect.flip(
          stranger.client.passkeys.deletePasskey({ payload: { id: summary.id } })
        )
        assert.strictEqual(refusedDelete._tag, "NotFound")

        assert.deepStrictEqual(yield* owner.client.passkeys.deletePasskey({ payload: { id: summary.id } }), {
          success: true
        })
        assert.deepStrictEqual(yield* owner.client.passkeys.listPasskeys(), [])
      })
    )
  })

  layer(PasskeysTest.layerHttpMovingClock())("freshness", (it) => {
    it.effect("a stale session may not enrol a credential, and is told what it could step up with", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-stale"))
        yield* enrol(owner)

        // Past the deployment's `session.freshAge`.
        yield* TestClock.adjust(Duration.days(2))

        const refused = yield* Effect.flip(owner.client.passkeys.registerOptions({ payload: {} }))
        assert.strictEqual(refused._tag, "StepUpRequired")
        if (refused._tag !== "StepUpRequired") return
        // The `Authenticators` seam is wired: the plugin's own credential is
        // named as a way to raise this session.
        assert.deepStrictEqual(refused.current.available, ["passkey"])
        assert.strictEqual(refused.current.aal, "aal1")

        // Removing one is guarded too.
        const listed = yield* Effect.flip(
          owner.client.passkeys.deletePasskey({ payload: { id: PasskeyId.make("whatever") } })
        )
        assert.strictEqual(listed._tag, "StepUpRequired")
      })
    )

    it.effect("a ceremony expires with its challenge", () =>
      Effect.gen(function* () {
        const owner = yield* signedUp(uniqueEmail("http-expiry"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const options = yield* owner.client.passkeys.registerOptions({ payload: {} })
        const response = yield* authenticator.register(options)

        yield* TestClock.adjust(Duration.minutes(6))
        const refused = yield* Effect.flip(owner.client.passkeys.registerVerify({ payload: { response } }))
        assert.strictEqual(refused._tag, "ChallengeExpired")
      })
    )
  })
})

// -----------------------------------------------------------------------------
// A deployment that owes a second factor
// -----------------------------------------------------------------------------

const challengeTtl = Duration.minutes(10)
const pendingToken = "pending-token-for-the-test"

/**
 * A decider that asks for one more thing after a *plugin* sign-in, and lets the
 * password paths through.
 *
 * Challenging everything would be simpler and would test nothing: a challenged
 * sign-up mints no session, so nobody could enrol the credential the test is
 * about.
 */
const challenging: SignInPipelineService = {
  decide: (options) =>
    options.source._tag !== "Plugin"
      ? Effect.succeed(proceed)
      : Effect.map(DateTime.now, (now) => ({
          _tag: "Challenge" as const,
          kind: "mfa",
          available: ["totp"],
          token: Redacted.make(pendingToken),
          expiresAt: DateTime.addDuration(now, challengeTtl)
        }))
}

describe.sequential("passkeys/Handlers with a second factor owed", () => {
  layer(PasskeysTest.layerHttp({ signInPipeline: challenging }))("a challenged passkey sign-in", (it) => {
    it.effect("answers 202 and carries the pending cookie alone", () =>
      Effect.gen(function* () {
        // The credential is enrolled first: enrolment is authenticated, and the
        // decider only ever runs on a sign-in.
        const owner = yield* signedUp(uniqueEmail("mfa-passkey"))
        const { authenticator } = yield* enrol(owner)

        const fresh = yield* client()
        const options = yield* fresh.client.passkeys.authenticateOptions({ payload: {} })
        const response = yield* authenticator.authenticate(options)
        const [body, http] = yield* fresh.client.passkeys.authenticateVerify({
          payload: { response },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(http.status, 202)
        assert.isTrue("_tag" in body)
        if (!("_tag" in body)) return
        assert.strictEqual(body._tag, "MfaRequired")
        assert.deepStrictEqual(body.available, ["totp"])

        // One cookie on the response, and it is not a session.
        const written = Object.keys(Cookies.toRecord(http.cookies))
        assert.isTrue(written.includes("effect_auth.pending"))
        assert.isFalse(written.includes("effect_auth.session"))

        // No session was minted, so the browser is still signed out.
        const refused = yield* Effect.flip(fresh.client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")
      })
    )
  })
})
