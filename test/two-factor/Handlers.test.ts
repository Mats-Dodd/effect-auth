import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Effect, Option, Redacted, Ref, Result } from "effect"
import { Cookies } from "effect/unstable/http"
import * as Totp from "../../src/crypto/Totp.js"
import { decode as decodeBase32 } from "../../src/internal/base32.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import * as TwoFactorTest from "../../src/testing/TwoFactorTest.js"
import { trustedDeviceCookieBaseName } from "../../src/two-factor/TwoFactor.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

/** The plain-HTTP names of the two cookies this flow rides on. */
const pendingCookieName = "effect_auth.pending"
const deviceCookieName = trustedDeviceCookieBaseName
const sessionCookieName = "effect_auth.session"

const bytesOf = (secret: Redacted.Redacted): Uint8Array => {
  const decoded = decodeBase32(Redacted.value(secret))
  if (Result.isFailure(decoded)) throw new Error("the enrolment secret must be base32")
  return decoded.success
}

const codeAt = (secret: Redacted.Redacted, offset: number) =>
  Effect.gen(function* () {
    const now = yield* DateTime.now
    return Redacted.make(yield* Totp.generate({ secret: bytesOf(secret), step: Totp.stepAt(now) + offset }))
  })

/** One browser addressing this block's deployment, with a jar a test can read. */
const browser = (headers?: Record<string, string>) =>
  Effect.gen(function* () {
    const made = yield* TestHttpClient.makeClient(
      TwoFactorTest.TestApi,
      headers === undefined ? undefined : { headers }
    )
    return {
      ...made,
      /** Signs in, answering with both the decoded body and the response. */
      signIn: (email: string) =>
        made.client.auth.signInEmail({
          payload: { email, password: testPassword },
          responseMode: "decoded-and-response" as const
        }),
      /** What is in the jar right now. */
      jar: Ref.get(made.cookies)
    }
  })

describe.sequential("two-factor/http", () => {
  layer(TwoFactorTest.layerHttp())("", (it) => {
    /**
     * A browser that has registered, enrolled an authenticator app and signed
     * out again — which is exactly the state a second factor exists for.
     */
    const enrolled = (label: string) =>
      Effect.gen(function* () {
        const email = uniqueEmail(label)
        const made = yield* browser()
        yield* made.client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        const started = yield* made.client.twoFactor.totpEnroll()
        const { codes } = yield* made.client.twoFactor.totpConfirm({
          payload: { code: yield* codeAt(started.secret, 0) }
        })
        yield* made.client.auth.signOut()
        return { ...made, email, secret: started.secret, codes }
      })

    it.effect("answers 202 with the pending cookie and no session cookie", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-challenge")
        const { client, email } = made

        const [body, response] = yield* made.signIn(email)

        assert.strictEqual(response.status, 202)
        assert.isTrue("_tag" in body)
        if (!("_tag" in body)) return
        assert.strictEqual(body._tag, "MfaRequired")
        assert.deepStrictEqual(body.available, ["totp", "recoveryCode"])
        // One response, one cookie: a challenge never travels beside a session.
        assert.deepStrictEqual(Object.keys(Cookies.toRecord(response.cookies)), [pendingCookieName])
        // And no user id, address or token in the body.
        const json = yield* response.text
        assert.isFalse(json.includes(email))
        assert.deepStrictEqual(Object.keys(Object(JSON.parse(json))).sort(), ["_tag", "available", "expiresAt"])
        // The browser is still signed out.
        const refused = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")
        // The jar holds the pending cookie, and whatever session cookie is
        // left in it is the emptied one signing out expired.
        const jar = yield* made.jar
        assert.isTrue(Option.isSome(Cookies.get(jar, pendingCookieName)))
        assert.strictEqual(
          Option.match(Cookies.get(jar, sessionCookieName), { onNone: () => "", onSome: (cookie) => cookie.value }),
          ""
        )
      })
    )

    it.effect("completes the sign-in when the code is answered, and clears the pending cookie", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-complete")
        const { client, email, secret } = made
        yield* made.signIn(email)

        const [body, response] = yield* client.twoFactor.totpVerify({
          payload: { code: yield* codeAt(secret, 1) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 200)
        assert.strictEqual(body.session.aal, "aal2")
        assert.deepStrictEqual(
          body.session.methods.map((entry) => entry.method),
          ["password", "totp"]
        )
        const written = Cookies.toRecord(response.cookies)
        assert.isTrue(Object.keys(written).includes(sessionCookieName))
        // The pending cookie is expired on the way out: a single-use value
        // never rides a second request.
        const pending = Option.getOrThrow(Cookies.get(response.cookies, pendingCookieName))
        assert.strictEqual(pending.value, "")
        // And the browser is signed in.
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.session.aal, "aal2")
      })
    )

    it.effect("costs an attempt and not the sign-in when the code is wrong", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-typo")
        const { client, email, secret } = made
        yield* made.signIn(email)

        const error = yield* Effect.flip(client.twoFactor.totpVerify({ payload: { code: Redacted.make("000000") } }))
        assert.strictEqual(error._tag, "InvalidCode")

        // The pending authentication is still there, under the same cookie.
        const completed = yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1) } })
        assert.strictEqual(completed.session.aal, "aal2")
      })
    )

    it.effect("survives a double-submitted wrong code, which used to throw the sign-in away", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-double-submit")
        const { client, email, secret } = made
        yield* made.signIn(email)
        const wrong = { payload: { code: Redacted.make("000000") } }

        // Two requests carrying the same typo at once. One of them will find
        // the row momentarily claimed by the other and be answered
        // `InvalidToken` rather than `InvalidCode`; neither answer may take
        // the browser's handle away, because the row is put straight back
        // under it.
        const both = yield* Effect.all(
          [Effect.flip(client.twoFactor.totpVerify(wrong)), Effect.flip(client.twoFactor.totpVerify(wrong))],
          { concurrency: 2 }
        )
        for (const error of both) {
          assert.isTrue(error._tag === "InvalidCode" || error._tag === "InvalidToken", error._tag)
        }

        const completed = yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1) } })
        assert.strictEqual(completed.session.aal, "aal2")
      })
    )

    it.effect("refuses a caller that presents neither a pending authentication nor a session", () =>
      Effect.gen(function* () {
        const made = yield* browser()

        const error = yield* Effect.flip(
          made.client.twoFactor.totpVerify({ payload: { code: Redacted.make("123456") } })
        )

        assert.strictEqual(error._tag, "Unauthorized")
      })
    )

    it.effect("refuses a cross-origin form post", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-origin")
        yield* made.signIn(made.email)

        // The same browser — the same cookie jar, so it is holding the pending
        // handle this sign-in just set — now posting the code with an `Origin`
        // somebody else's page put there. The sign-in itself has to come from a
        // trusted origin, because core refuses a cross-origin one too.
        const attacker = yield* TestHttpClient.makeClient(TwoFactorTest.TestApi, {
          cookies: made.cookies,
          headers: { origin: "https://evil.example.com" }
        })

        const error = yield* Effect.flip(
          attacker.client.twoFactor.totpVerify({ payload: { code: yield* codeAt(made.secret, 1) } })
        )

        assert.strictEqual(error._tag, "OriginNotAllowed")
      })
    )

    it.effect("remembers the browser when it asks, and does not ask it again", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-trust")
        const { client, email, secret } = made
        yield* made.signIn(email)
        yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1), trustDevice: true } })
        const first = Option.getOrThrow(Cookies.get(yield* made.jar, deviceCookieName))
        yield* client.auth.signOut()

        // The second sign-in is not challenged at all: 200, with a session.
        const [body, response] = yield* made.signIn(email)

        assert.strictEqual(response.status, 200)
        assert.isFalse("_tag" in body, "a trusted browser is not asked for a second factor")
        if ("_tag" in body) return
        // The skip proves nothing, so the session is still single-factor.
        assert.strictEqual(body.session.aal, "aal1")
        // And the device token was rotated by the use.
        const rotated = Option.getOrThrow(Cookies.get(yield* made.jar, deviceCookieName))
        assert.notStrictEqual(rotated.value, first.value)
      })
    )

    it.effect("does not trust a browser that never asked", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-untrusted")
        const { client, email, secret } = made
        yield* made.signIn(email)
        yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1), trustDevice: true } })
        yield* client.auth.signOut()

        // A different browser, same account.
        const other = yield* browser()
        const [body, response] = yield* other.signIn(email)

        assert.strictEqual(response.status, 202)
        assert.isTrue("_tag" in body)
      })
    )

    it.effect("lists the remembered browsers, marks the one asking, and forgets them all", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-devices")
        const { client, email, secret } = made
        yield* made.signIn(email)
        yield* client.twoFactor.totpVerify({
          payload: { code: yield* codeAt(secret, 1), trustDevice: true, label: "laptop" }
        })

        const listed = yield* client.twoFactor.devices()
        assert.strictEqual(listed.length, 1)
        assert.strictEqual(listed[0]?.label, "laptop")
        assert.isTrue(listed[0]?.current)
        // No token and no digest on the wire.
        assert.deepStrictEqual(Object.keys(listed[0] ?? {}).sort(), [
          "createdAt",
          "current",
          "expiresAt",
          "id",
          "ipAddress",
          "label",
          "lastUsedAt",
          "userAgent"
        ])

        yield* client.twoFactor.devicesRevokeAll()
        assert.deepStrictEqual(yield* client.twoFactor.devices(), [])
        // And the browser is asked again next time.
        yield* client.auth.signOut()
        const [, response] = yield* made.signIn(email)
        assert.strictEqual(response.status, 202)
      })
    )

    it.effect("guards turning the second factor off behind a real second factor", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-disable")
        const { client, email, secret } = made
        yield* made.signIn(email)
        yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1) } })
        // The session's log now carries a `totp` entry, which is what the
        // endpoint asks for.
        yield* client.twoFactor.totpDisable()
        // And the account is back to one factor: the next sign-in is not
        // challenged.
        yield* client.auth.signOut()
        const [, response] = yield* made.signIn(email)
        assert.strictEqual(response.status, 200)
      })
    )

    it.effect("refuses to turn it off from a session that has only proved a password", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-disable-aal1")
        const { client, email, secret } = made
        // Complete the sign-in, then let the session fall back to aal1 by
        // signing in again on a browser this deployment trusts.
        yield* made.signIn(email)
        yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1), trustDevice: true } })
        yield* client.auth.signOut()
        yield* made.signIn(email)

        const error = yield* Effect.flip(client.twoFactor.totpDisable())

        assert.strictEqual(error._tag, "StepUpRequired")
        if (error._tag !== "StepUpRequired") return
        // The endpoint asks for this plugin's own factor by name, not for a
        // level: a level is unreachable for an account whose first factor is
        // possession, and `aal2` there would be a trap rather than a guard.
        assert.deepStrictEqual(error.required.methods, ["totp", "recoveryCode"])
        assert.strictEqual(error.required.aal, undefined)
        assert.strictEqual(error.current.aal, "aal1")
        assert.deepStrictEqual([...error.current.available].sort(), ["recoveryCodes", "totp"])
      })
    )

    it.effect("answers a second factor with a recovery code, and forgets every browser", () =>
      Effect.gen(function* () {
        const made = yield* enrolled("http-recovery")
        const { client, email, secret, codes } = made
        yield* made.signIn(email)
        yield* client.twoFactor.totpVerify({ payload: { code: yield* codeAt(secret, 1), trustDevice: true } })
        yield* client.auth.signOut()
        yield* made.signIn(email)
        // Trusted, so that sign-in was not challenged; sign out and come back
        // from a browser that is not.
        yield* client.auth.signOut()
        const other = yield* browser()
        yield* other.signIn(email)

        const completed = yield* other.client.twoFactor.recoveryVerify({ payload: { code: codes[0]! } })

        assert.strictEqual(completed.session.aal, "aal2")
        assert.deepStrictEqual(
          completed.session.methods.map((entry) => entry.method),
          ["password", "recoveryCode"]
        )
        // Spending one means the authenticator is gone: every remembered
        // browser is forgotten, so the first one is asked again.
        assert.deepStrictEqual(yield* other.client.twoFactor.devices(), [])
        const [, response] = yield* made.signIn(email)
        assert.strictEqual(response.status, 202)
      })
    )

    it.effect("hands the enrolment secret over exactly once, and never reads it back", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-enrol")
        const made = yield* browser()
        yield* made.client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })

        const [started, response] = yield* made.client.twoFactor.totpEnroll({
          responseMode: "decoded-and-response"
        })

        const json = yield* response.text
        assert.include(json, Redacted.value(started.secret))
        // The stored form is a ciphertext, and nothing in this group answers
        // with it: the group has no endpoint that reads an enrolment at all.
        assert.isFalse(json.includes("secretCiphertext"))
        const { codes } = yield* made.client.twoFactor.totpConfirm({
          payload: { code: yield* codeAt(started.secret, 0) }
        })
        assert.strictEqual(codes.length, 10)
      })
    )
  })
})
