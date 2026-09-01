import { assert, describe, it, layer } from "@effect/vitest"
// oxlint-disable-next-line effecttsgo/node-builtin-import -- a grep-level pin has to read the source text, and effect ships no FileSystem implementation for node to read it with
import { readdirSync, readFileSync } from "node:fs"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { Cookies } from "effect/unstable/http"
import { proceed } from "../../src/domain/SignIn.js"
import { insecureSessionCookieName } from "../../src/http/Cookies.js"
import { pendingCookieBaseName } from "../../src/http/Handlers.js"
import { nonceCookieBaseName } from "../../src/one-tap/index.js"
import * as OneTapTest from "../../src/testing/OneTapTest.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import { uniqueEmail } from "../fixtures.js"

let counter = 0
const uniqueSubject = (): string => `one-tap-http-${counter++}`

const makeClient = (options?: TestHttpClient.ClientOptions) => TestHttpClient.makeClient(OneTapTest.TestApi, options)

const setCookieNames = (response: { readonly cookies: Cookies.Cookies }): ReadonlyArray<string> =>
  Object.keys(Cookies.toRecord(response.cookies))

describe.sequential("one-tap/Handlers", () => {
  layer(OneTapTest.layerHttp())("the two endpoints", (it) => {
    it.effect("mints a nonce into a host-only, http-only cookie and into the body", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const [body, response] = yield* client.oneTap.nonce({ responseMode: "decoded-and-response" })

        const cookie = Cookies.get(response.cookies, nonceCookieBaseName)
        assert.isTrue(Option.isSome(cookie))
        if (Option.isNone(cookie)) return
        // The page needs the value; the server needs a copy the page cannot
        // write. Both halves carry the same nonce.
        assert.strictEqual(cookie.value.value, body.nonce)
        assert.isTrue(cookie.value.options?.httpOnly)
        assert.strictEqual(cookie.value.options?.path, "/")
        assert.isUndefined(cookie.value.options?.domain)
      })
    )

    it.effect("signs the browser in with a credential minted against that nonce", () =>
      Effect.gen(function* () {
        const { client, cookies } = yield* makeClient()
        const email = uniqueEmail("http-one-tap")
        const { nonce } = yield* client.oneTap.nonce()
        const credential = yield* OneTapTest.credential({ subject: uniqueSubject(), email, nonce })

        const [result, response] = yield* client.oneTap.callback({
          payload: { credential, nonce },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 200)
        assert.isFalse("_tag" in result)
        if ("_tag" in result) return
        assert.strictEqual(result.user.email, email)
        assert.include(setCookieNames(response), insecureSessionCookieName)
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))
        assert.strictEqual((yield* client.auth.getSession()).user.id, result.user.id)
      })
    )

    it.effect("spends the nonce cookie, so the same credential cannot be presented twice", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const { nonce } = yield* client.oneTap.nonce()
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("http-replay"),
          nonce
        })

        yield* client.oneTap.callback({ payload: { credential, nonce } })
        const replay = yield* Effect.result(client.oneTap.callback({ payload: { credential, nonce } }))
        assert.strictEqual(replay._tag, "Failure")
        if (replay._tag === "Failure") assert.strictEqual(replay.failure._tag, "OneTapRejected")
      })
    )

    it.effect("refuses a credential from a browser that never asked for a nonce", () =>
      Effect.gen(function* () {
        const asker = yield* makeClient()
        const { nonce } = yield* asker.client.oneTap.nonce()
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("http-other-browser"),
          nonce
        })

        // A different jar entirely: the cookie is not this browser's.
        const { client } = yield* makeClient()
        const outcome = yield* Effect.result(client.oneTap.callback({ payload: { credential, nonce } }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "OneTapRejected")
      })
    )

    it.effect("refuses a cross-origin post from an untrusted origin", () =>
      Effect.gen(function* () {
        const { client, cookies } = yield* makeClient()
        const { nonce } = yield* client.oneTap.nonce()
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("http-origin"),
          nonce
        })

        const evil = yield* makeClient({ cookies, headers: { origin: "https://evil.example" } })
        const outcome = yield* Effect.result(evil.client.oneTap.callback({ payload: { credential, nonce } }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "OriginNotAllowed")
      })
    )
  })

  layer(
    OneTapTest.layerHttp({
      // Owes a second factor on a One Tap sign-in and nothing else.
      signInPipeline: {
        decide: (options) =>
          options.source._tag !== "OAuth"
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
        const { client, cookies } = yield* makeClient()
        const { nonce } = yield* client.oneTap.nonce()
        const credential = yield* OneTapTest.credential({
          subject: uniqueSubject(),
          email: uniqueEmail("http-one-tap-mfa"),
          nonce
        })

        const [result, response] = yield* client.oneTap.callback({
          payload: { credential, nonce },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 202)
        assert.isTrue("_tag" in result)
        if (!("_tag" in result)) return
        assert.strictEqual(result._tag, "MfaRequired")
        const names = setCookieNames(response)
        assert.include(names, pendingCookieBaseName)
        assert.notInclude(names, insecureSessionCookieName)
        assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCookie(cookies)))
      })
    )
  })
})

describe("one-tap verifies nothing itself", () => {
  const directory = new URL("../../src/one-tap/", import.meta.url)
  const sources = readdirSync(directory)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => ({ name, text: readFileSync(new URL(name, directory), "utf8") }))

  it("has files to look at", () => {
    assert.isAtLeast(sources.length, 3)
  })

  for (const { name, text } of sources) {
    it(`${name} imports no JWS library of its own`, () => {
      assert.notMatch(text, /from "jose"/)
      assert.notMatch(text, /jwtVerify|createLocalJWKSet|createRemoteJWKSet|SignJWT/)
    })

    it(`${name} fetches no key set of its own`, () => {
      // No URL, no request builder, no transport call: the keys come from the
      // provider's configuration through `IdToken.Jwks`, which is the cache the
      // redirect flow already uses.
      assert.notMatch(text, /jwks_uri|googleapis\.com|\bfetch\(/)
      assert.notMatch(text, /HttpClientRequest\./)
    })
  }

  it("calls the verifier that already exists", () => {
    const oneTap = sources.find((source) => source.name === "OneTap.ts")
    if (oneTap === undefined) {
      assert.fail("src/one-tap/OneTap.ts should be one of the files read")
      return
    }
    assert.match(oneTap.text, /from "\.\.\/oauth\/IdToken\.js"/)
    assert.match(oneTap.text, /verifyIdToken\(/)
    assert.match(oneTap.text, /accounts\.linkOAuth\(/)
  })
})
