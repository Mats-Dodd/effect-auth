import { assert, describe, it } from "@effect/vitest"
import { Config, ConfigProvider, Effect, Option, Redacted } from "effect"
import * as Facebook from "../../../src/oauth/providers/Facebook.js"
import { providerIssuer, resolveClientSecret } from "../../../src/oauth/Provider.js"
import * as MockProvider from "../../../src/testing/MockProvider.js"
import { withServer, claimsOf } from "./helpers.js"

const clientId = "1234567890"
const clientSecret = Redacted.make("facebook-app-secret")

const facebook = Facebook.make({ clientId, clientSecret })
const endpoints = Facebook.endpointsFor(Facebook.defaultGraphVersion)

/** `GET /me` and `GET /debug_token`, stubbed. */
const graph = (profile: unknown, debug: unknown) =>
  withServer(
    (server) => {
      server.on(endpoints.userInfoUrl, () => MockProvider.json(profile))
      server.on(endpoints.debugTokenUrl, () => MockProvider.json(debug))
    },
    (server) =>
      Effect.map(Effect.result(facebook.userInfo(MockProvider.tokensOf("graph-token"))), (result) => ({
        result,
        server
      }))
  )

const validDebug = { data: { app_id: clientId, user_id: "10000001", is_valid: true } }
const validProfile = {
  id: "10000001",
  name: "Ada Lovelace",
  email: "ada@example.com",
  picture: { data: { url: "https://cdn.test/ada.png" } }
}

describe("oauth/providers/Facebook", () => {
  describe("configuration", () => {
    it("is a plain OAuth2 provider under a synthetic issuer by default", () => {
      assert.strictEqual(facebook.id, "facebook")
      assert.isUndefined(facebook.oidc)
      assert.strictEqual(providerIssuer(facebook), "local:oauth:facebook")
      assert.strictEqual(facebook.authorizationUrl, endpoints.authorizationUrl)
      assert.strictEqual(facebook.tokenUrl, endpoints.tokenUrl)
      assert.deepStrictEqual([...facebook.scopes], ["email", "public_profile"])
    })

    it("can never claim a verified address, on either path", () => {
      // Graph states no verification flag and the Limited Login token carries
      // none, so neither may implicitly link.
      assert.strictEqual(facebook.emailVerified, "never")
      assert.strictEqual(Facebook.make({ clientId, clientSecret, limitedLogin: true }).emailVerified, "never")
    })

    it("becomes an OIDC provider for Limited Login", () => {
      const limited = Facebook.make({ clientId, clientSecret, limitedLogin: true })
      assert.strictEqual(limited.oidc?.issuer, Facebook.issuer)
      assert.deepStrictEqual(limited.oidc?.keys, { jwksUrl: Facebook.jwksUrl })
      assert.strictEqual(providerIssuer(limited), Facebook.issuer)
    })

    it("pins the Graph version, and lets a deployment move it deliberately", () => {
      const pinned = Facebook.make({ clientId, clientSecret, graphVersion: "v19.0" })
      assert.isTrue(pinned.authorizationUrl.includes("/v19.0/"))
      assert.isTrue(pinned.tokenUrl.includes("/v19.0/"))
    })
  })

  describe("bindsToken", () => {
    it("requires all three statements, and disbelieves a body it cannot read", () => {
      const options = { clientId, userId: "10000001" }
      assert.isTrue(Facebook.bindsToken(validDebug, options))
      // Somebody else's application.
      assert.isFalse(Facebook.bindsToken({ data: { ...validDebug.data, app_id: "999" } }, options))
      // Somebody else's account.
      assert.isFalse(Facebook.bindsToken({ data: { ...validDebug.data, user_id: "999" } }, options))
      // A token Facebook says is dead.
      assert.isFalse(Facebook.bindsToken({ data: { ...validDebug.data, is_valid: false } }, options))
      // An answer that cannot support the check is not evidence.
      assert.isFalse(Facebook.bindsToken({ data: {} }, options))
      assert.isFalse(Facebook.bindsToken(null, options))
    })
  })

  describe("userInfo (Graph)", () => {
    it.effect("reads the profile and binds the token to this app and this person", () =>
      Effect.gen(function* () {
        const { result, server } = yield* graph(validProfile, validDebug)
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.id, "10000001")
        assert.strictEqual(result.success.email, "ada@example.com")
        // The value this function produces is honest on its own; the provider's
        // `"never"` policy is what makes it stick.
        assert.isFalse(result.success.emailVerified)
        assert.strictEqual(result.success.image, "https://cdn.test/ada.png")

        // The debug call carried the *app* access token, which is the thing an
        // attacker holding somebody else's user token does not have.
        const [debug] = server.to(endpoints.debugTokenUrl)
        assert.isDefined(debug)
        assert.strictEqual(debug?.headers["authorization"], `Bearer ${clientId}|${Redacted.value(clientSecret)}`)
        assert.isTrue(debug?.url.includes("input_token=graph-token"))
      })
    )

    it.effect("refuses a token minted for another application", () =>
      Effect.gen(function* () {
        const { result } = yield* graph(validProfile, { data: { ...validDebug.data, app_id: "another-app" } })
        assert.strictEqual(result._tag, "Failure")
        assert.strictEqual(result._tag === "Failure" ? result.failure.reason : null, "UserInfoFailed")
      })
    )

    it.effect("refuses a token that belongs to another person", () =>
      Effect.gen(function* () {
        const { result } = yield* graph(validProfile, { data: { ...validDebug.data, user_id: "20000002" } })
        assert.strictEqual(result._tag, "Failure")
        assert.strictEqual(result._tag === "Failure" ? result.failure.reason : null, "UserInfoFailed")
      })
    )

    it.effect("refuses a profile with no address, because there is no identity in one", () =>
      Effect.gen(function* () {
        const { result } = yield* graph({ id: "10000001", name: "Ada" }, validDebug)
        assert.strictEqual(result._tag, "Failure")
        assert.strictEqual(result._tag === "Failure" ? result.failure.reason : null, "UserInfoFailed")
      })
    )
  })

  describe("userInfo (Limited Login)", () => {
    const limited = Facebook.make({ clientId, clientSecret, limitedLogin: true })

    it.effect("takes the identity from the verified token and makes no request", () =>
      Effect.gen(function* () {
        const outcome = yield* withServer(
          () => {},
          (server) =>
            Effect.map(
              Effect.result(
                limited.userInfo(
                  MockProvider.tokensOf("unused", {
                    idTokenClaims: claimsOf({ subject: "fb-sub", emailVerified: true })
                  })
                )
              ),
              (result) => ({ result, server })
            )
        )
        assert.strictEqual(outcome.result._tag, "Success")
        if (outcome.result._tag !== "Success") return
        assert.strictEqual(outcome.result.success.id, "fb-sub")
        assert.strictEqual(outcome.server.requests.length, 0)
      })
    )

    it.effect("refuses a callback that carried no verified token at all", () =>
      Effect.gen(function* () {
        const outcome = yield* withServer(
          () => {},
          () => Effect.result(limited.userInfo(MockProvider.tokensOf("unused")))
        )
        assert.strictEqual(outcome._tag, "Failure")
        assert.strictEqual(outcome._tag === "Failure" ? outcome.failure.reason : null, "IdTokenInvalid")
      })
    )
  })

  describe("makeConfig", () => {
    it.effect("builds the same value from the environment", () =>
      Effect.gen(function* () {
        const provider = yield* Facebook.makeConfig({
          clientId: Config.string("FACEBOOK_CLIENT_ID"),
          clientSecret: Config.redacted("FACEBOOK_CLIENT_SECRET")
        })
        assert.strictEqual(provider.id, "facebook")
        assert.strictEqual(provider.emailVerified, "never")
        assert.deepStrictEqual(
          yield* Effect.map(resolveClientSecret(provider), Option.map(Redacted.value)),
          Option.some("from-the-environment")
        )
      }).pipe(
        Effect.provideService(
          ConfigProvider.ConfigProvider,
          ConfigProvider.fromUnknown({
            FACEBOOK_CLIENT_ID: "1234567890",
            FACEBOOK_CLIENT_SECRET: "from-the-environment"
          })
        )
      )
    )
  })
})
