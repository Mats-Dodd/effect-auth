import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { Cookies } from "effect/unstable/http"
import { insecureSessionCookieName } from "../../src/http/Cookies.js"
import { pendingCookieBaseName } from "../../src/http/Handlers.js"
import { proceed } from "../../src/domain/SignIn.js"
import { verifyCookieBaseName, signInCookieBaseName, stepUpCookieBaseName } from "../../src/phone/index.js"
import * as PhoneTest from "../../src/testing/PhoneTest.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

let counter = 0
const uniqueNumber = (): string => `+1555${String(3000000 + counter++)}`

const makeClient = (options?: TestHttpClient.ClientOptions) => TestHttpClient.makeClient(PhoneTest.TestApi, options)

/** Registers an account on this deployment's own API and returns the browser. */
const signedUp = Effect.fnUntraced(function* (email: string) {
  const browser = yield* makeClient()
  yield* browser.client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
  return browser
})

/** Every `Set-Cookie` name on a response, read the way a browser reads them. */
const setCookieNames = (response: { readonly cookies: Cookies.Cookies }): ReadonlyArray<string> =>
  Object.keys(Cookies.toRecord(response.cookies))

// Every capability on, and the restricted-factor rule deliberately off: these
// tests model a deployment that has decided SMS may stand alone. `stepUp` and
// `requireAlternateSecondFactor` are both stated rather than defaulted, because
// the shipped defaults are contact-only and would serve no step-up endpoint.
const allowed = {
  phone: { allowedCountries: ["1"], signIn: true, stepUp: true, requireAlternateSecondFactor: false }
}

describe.sequential("phone/Handlers", () => {
  layer(PhoneTest.layerHttp(allowed))("attaching a number", (it) => {
    it.effect("carries the handle in a host-only, http-only cookie and never in the body", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { client } = yield* signedUp(uniqueEmail("http-attach"))

        const [body, response] = yield* client.phone.sendVerification({
          payload: { phoneNumber: number },
          responseMode: "decoded-and-response"
        })
        assert.deepStrictEqual(body, { success: true })

        const cookie = Cookies.get(response.cookies, verifyCookieBaseName)
        assert.isTrue(Option.isSome(cookie))
        if (Option.isNone(cookie)) return
        assert.isTrue(cookie.value.options?.httpOnly)
        assert.strictEqual(cookie.value.options?.path, "/")
        assert.isUndefined(cookie.value.options?.domain)
        assert.isDefined(cookie.value.options?.maxAge)
        // The code went to the handset; the handle went to the browser. Neither
        // is the other.
        assert.notStrictEqual(cookie.value.value, yield* PhoneTest.codeFor(number))
      })
    )

    it.effect("attaches the number when the browser answers with its cookie", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { client } = yield* signedUp(uniqueEmail("http-verify"))

        yield* client.phone.sendVerification({ payload: { phoneNumber: number } })
        const attached = yield* client.phone.verify({
          payload: { code: yield* PhoneTest.codeFor(number) }
        })
        assert.strictEqual(attached.phoneNumber, number)
      })
    )

    it.effect("normalises whatever spelling arrived on the wire", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { client } = yield* signedUp(uniqueEmail("http-normalise"))
        const spelled = `+1 (${number.slice(2, 5)}) ${number.slice(5, 8)}-${number.slice(8)}`

        yield* client.phone.sendVerification({ payload: { phoneNumber: spelled } })
        const attached = yield* client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })
        assert.strictEqual(attached.phoneNumber, number)
      })
    )

    it.effect("spends the handle cookie on success and keeps it on a wrong guess", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { client } = yield* signedUp(uniqueEmail("http-cookie-life"))

        yield* client.phone.sendVerification({ payload: { phoneNumber: number } })
        const wrong = yield* Effect.result(client.phone.verify({ payload: { code: "000000" } }))
        assert.strictEqual(wrong._tag, "Failure")
        // The cookie survived, so the person can try again with the code they
        // were actually sent.
        const attached = yield* client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })
        assert.strictEqual(attached.phoneNumber, number)

        // And now it is gone.
        const replay = yield* Effect.result(
          client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })
        )
        assert.strictEqual(replay._tag, "Failure")
      })
    )

    it.effect("refuses an unauthenticated caller", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const outcome = yield* Effect.result(
          client.phone.sendVerification({ payload: { phoneNumber: uniqueNumber() } })
        )
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "Unauthorized")
      })
    )
  })

  layer(PhoneTest.layerHttp(allowed))("signing in", (it) => {
    it.effect("signs the browser in and sets a session cookie", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const owner = yield* signedUp(uniqueEmail("http-sign-in"))
        yield* owner.client.phone.sendVerification({ payload: { phoneNumber: number } })
        yield* owner.client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })

        // A different browser entirely.
        const { client, cookies } = yield* makeClient()
        yield* client.phone.signInSend({ payload: { phoneNumber: number } })
        const [result, response] = yield* client.phone.signInVerify({
          payload: { code: yield* PhoneTest.codeFor(number) },
          responseMode: "decoded-and-response"
        })

        assert.isFalse("_tag" in result)
        if ("_tag" in result) return
        assert.strictEqual(response.status, 200)
        assert.include(setCookieNames(response), insecureSessionCookieName)
        // And the browser really is signed in.
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.id, result.user.id)
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))
      })
    )

    it.effect("lets the sign-in say it should not be remembered", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const owner = yield* signedUp(uniqueEmail("http-sign-in-forget"))
        yield* owner.client.phone.sendVerification({ payload: { phoneNumber: number } })
        yield* owner.client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })

        const { client } = yield* makeClient()
        yield* client.phone.signInSend({ payload: { phoneNumber: number } })
        const [result, response] = yield* client.phone.signInVerify({
          payload: { code: yield* PhoneTest.codeFor(number), rememberMe: false },
          responseMode: "decoded-and-response"
        })

        assert.isFalse("_tag" in result)
        if ("_tag" in result) return
        // Every other door that mints a session takes this answer; a code read
        // off a shared handset is exactly the sign-in somebody says no to.
        assert.isFalse(result.session.rememberMe)
        // And the cookie follows the row, so the browser really does forget it.
        assert.include(setCookieNames(response), insecureSessionCookieName)
        const cookie = Cookies.toRecord(response.cookies)[insecureSessionCookieName]
        assert.isDefined(cookie)
      })
    )

    it.effect("answers a number nobody holds exactly as it answers one somebody does", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const answer = yield* client.phone.signInSend({ payload: { phoneNumber: uniqueNumber() } })
        assert.deepStrictEqual(answer, { success: true })
      })
    )

    it.effect("refuses a cross-origin post from an untrusted origin", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient({ headers: { origin: "https://evil.example" } })
        const outcome = yield* Effect.result(client.phone.signInSend({ payload: { phoneNumber: uniqueNumber() } }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "OriginNotAllowed")
      })
    )

    it.effect("refuses a cross-origin answer too, so a known code cannot sign a visitor in", () =>
      Effect.gen(function* () {
        // The send is the endpoint that costs money; the answer is the one that
        // mints a session. A site that already held a code — its own handset's
        // — could otherwise post it from a visitor's browser and leave that
        // browser signed into somebody else's account.
        const { client } = yield* makeClient({ headers: { origin: "https://evil.example" } })
        const outcome = yield* Effect.result(client.phone.signInVerify({ payload: { code: "000000" } }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "OriginNotAllowed")
      })
    )

    it.effect("lets a request with no Origin at all through, as a server-to-server caller has none", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        assert.deepStrictEqual(yield* client.phone.signInSend({ payload: { phoneNumber: uniqueNumber() } }), {
          success: true
        })
      })
    )
  })

  layer(PhoneTest.layerHttp(allowed))("raising a session", (it) => {
    it.effect("rotates the session cookie and raises the level", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { client, cookies } = yield* signedUp(uniqueEmail("http-step-up"))
        yield* client.phone.sendVerification({ payload: { phoneNumber: number } })
        yield* client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })

        const before = yield* TestHttpClient.sessionCookieValue(cookies)
        assert.strictEqual((yield* client.auth.getSession()).session.aal, "aal1")

        yield* client.phone.stepUpSend({ payload: {} })
        const [raised, response] = yield* client.phone.stepUpVerify({
          payload: { code: yield* PhoneTest.codeFor(number) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(raised.session.aal, "aal2")
        assert.include(setCookieNames(response), insecureSessionCookieName)
        const after = yield* TestHttpClient.sessionCookieValue(cookies)
        assert.notStrictEqual(after, before)
        // The session survived the rotation, id and all.
        const current = yield* client.auth.getSession()
        assert.strictEqual(current.session.id, raised.session.id)
        assert.strictEqual(current.session.aal, "aal2")
      })
    )

    it.effect("refuses a caller with no verified number", () =>
      Effect.gen(function* () {
        const { client } = yield* signedUp(uniqueEmail("http-no-number"))
        const outcome = yield* Effect.result(client.phone.stepUpSend({ payload: {} }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "PhoneNotVerified")
      })
    )
  })

  layer(
    PhoneTest.layerHttp({
      ...allowed,
      // A decider that owes a second factor on a *phone* sign-in and nothing
      // else, so that the sign-up this test opens with still establishes a
      // session — a decider that challenged everything would challenge that too.
      signInPipeline: {
        decide: (options) =>
          options.source._tag !== "Plugin" || options.source.plugin !== "phone"
            ? Effect.succeed(proceed)
            : Effect.map(DateTime.now, (now) => ({
                _tag: "Challenge" as const,
                kind: "totp",
                available: ["totp"],
                token: Redacted.make("pending-token-for-the-test"),
                expiresAt: DateTime.addDuration(now, Duration.minutes(10))
              }))
      }
    })
  )("when a second factor is owed", (it) => {
    it.effect("answers 202 with the pending cookie and no session cookie", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const owner = yield* signedUp(uniqueEmail("http-mfa-owner"))
        // Attaching is not a sign-in, so the challenging decider does not touch it.
        yield* owner.client.phone.sendVerification({ payload: { phoneNumber: number } })
        yield* owner.client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })

        const { client, cookies } = yield* makeClient()
        yield* client.phone.signInSend({ payload: { phoneNumber: number } })
        const [result, response] = yield* client.phone.signInVerify({
          payload: { code: yield* PhoneTest.codeFor(number) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 202)
        assert.isTrue("_tag" in result)
        if (!("_tag" in result)) return
        assert.strictEqual(result._tag, "MfaRequired")
        assert.deepStrictEqual(result.available, ["totp"])
        assert.notProperty(result, "token")

        // The response that owes a factor carries the pending cookie and the
        // spent handle's expiry, and no session cookie at all.
        const names = setCookieNames(response)
        assert.include(names, pendingCookieBaseName)
        assert.notInclude(names, insecureSessionCookieName)
        assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCookie(cookies)))
        // And the browser is not signed in.
        const session = yield* Effect.result(client.auth.getSession())
        assert.strictEqual(session._tag, "Failure")
      })
    )
  })

  layer(PhoneTest.layerHttp({ phone: { allowedCountries: ["1"] } }))("a capability that is off", (it) => {
    it.effect("answers 404 rather than disappearing from the document", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const outcome = yield* TestHttpClient.refusedStatus(
          client.phone.signInSend({ payload: { phoneNumber: uniqueNumber() } })
        )
        assert.strictEqual(outcome, 404)
      })
    )

    it.effect("still serves the capability that is on", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { client } = yield* signedUp(uniqueEmail("http-contact-only"))
        yield* client.phone.sendVerification({ payload: { phoneNumber: number } })
        const attached = yield* client.phone.verify({ payload: { code: yield* PhoneTest.codeFor(number) } })
        assert.strictEqual(attached.phoneNumber, number)
      })
    )
  })

  layer(PhoneTest.layerHttp({ ...allowed, cookie: { secure: true }, baseUrl: "https://app.example" }))(
    "on a TLS deployment",
    (it) => {
      it.effect("the handle cookies carry the __Host- prefix", () =>
        Effect.gen(function* () {
          const { client } = yield* makeClient({ baseUrl: "https://app.example" })
          const [, response] = yield* client.phone.signInSend({
            payload: { phoneNumber: uniqueNumber() },
            responseMode: "decoded-and-response"
          })
          assert.include(setCookieNames(response), `__Host-${signInCookieBaseName}`)
          assert.notInclude(setCookieNames(response), signInCookieBaseName)
        })
      )

      it.effect("and so does the step-up one, under its own name", () =>
        Effect.gen(function* () {
          assert.notStrictEqual(verifyCookieBaseName, signInCookieBaseName)
          assert.notStrictEqual(signInCookieBaseName, stepUpCookieBaseName)
          assert.notStrictEqual(verifyCookieBaseName, stepUpCookieBaseName)
        })
      )
    }
  )
})
