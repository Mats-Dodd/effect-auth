import { assert, describe, it } from "@effect/vitest"
import { Effect, Redacted } from "effect"
import { providerIssuer } from "../../../src/oauth/Provider.js"
import * as Twitter from "../../../src/oauth/providers/Twitter.js"
import * as MockProvider from "../../../src/testing/MockProvider.js"
import { withServer } from "./helpers.js"

const clientId = "twitter-client"
const clientSecret = Redacted.make("twitter-client-secret")

const twitter = Twitter.make({ clientId, clientSecret })
const publicClient = Twitter.make({ clientId })

/** `GET /2/users/me`, answering differently for the profile call and the address call. */
const usersMe = (profile: unknown, withEmail: { readonly body: unknown; readonly status?: number }) =>
  withServer(
    (server) => {
      let call = 0
      server.on(Twitter.userInfoUrl, () => {
        call += 1
        return call === 1 ? MockProvider.json(profile) : MockProvider.json(withEmail.body, withEmail.status ?? 200)
      })
    },
    (server) =>
      Effect.map(Effect.result(twitter.userInfo(MockProvider.tokensOf("x-token"))), (result) => ({ result, server }))
  )

const profile = { data: { id: "1000", username: "ada", name: "Ada Lovelace", profile_image_url: "https://cdn/x.png" } }

describe("oauth/providers/Twitter", () => {
  describe("configuration", () => {
    it("is a plain OAuth2 provider under a synthetic issuer", () => {
      assert.strictEqual(twitter.id, "twitter")
      assert.isUndefined(twitter.oidc)
      assert.strictEqual(providerIssuer(twitter), "local:oauth:twitter")
      assert.strictEqual(twitter.authorizationUrl, Twitter.authorizationUrl)
      assert.strictEqual(twitter.tokenUrl, Twitter.tokenUrl)
      // `confirmed_email` is X's own statement that it checked the address.
      assert.strictEqual(twitter.emailVerified, "derived")
      assert.deepStrictEqual([...twitter.scopes], ["users.read", "tweet.read", "offline.access", "users.email"])
    })

    it("declares HTTP Basic, because X rejects client_secret_post", () => {
      // Stated on the provider, not solved with an `exchange` override: an
      // override covers the authorization code and not the refresh, and
      // `offline.access` is in the default scopes — so a bespoke exchange would
      // sign somebody in and then fail to refresh them two hours later, with
      // nothing before then to say so. `Flow.tokenRequest` honours it on both
      // grants; `test/oauth/Flow.test.ts` holds that assertion.
      assert.strictEqual(twitter.tokenAuth, "client_secret_basic")
      assert.isUndefined(twitter.exchange)
      assert.strictEqual(publicClient.tokenAuth, "client_secret_basic")
      // A public client sends no secret at all whatever that says; PKCE is what
      // proves it.
      assert.isUndefined(publicClient.clientSecret)
    })
  })

  describe("selectEmail", () => {
    it("believes a confirmed address and nothing else", () => {
      assert.deepStrictEqual(
        Twitter.selectEmail({ confirmedEmail: "ada@example.com", username: "ada", userId: "1000" }),
        { email: "ada@example.com", emailVerified: true }
      )
    })

    it("mints an undeliverable placeholder keyed on the id, never the handle", () => {
      const placeholder = Twitter.selectEmail({ confirmedEmail: null, username: "ada", userId: "1000" })
      // The id, although a username was there to use. X releases handles and
      // reassigns them, and `users.email` is unique: `ada@twitter.invalid`
      // would collide with the account of whoever held `@ada` before, and the
      // new person could then never sign in — the address is unverified, so
      // implicit linking refuses, permanently.
      assert.strictEqual(placeholder.email, `1000@${Twitter.placeholderDomain}`)
      // Never verified: a name nobody proved cannot claim somebody's account.
      assert.isFalse(placeholder.emailVerified)
      assert.strictEqual(
        Twitter.selectEmail({ confirmedEmail: null, username: null, userId: "1000" }).email,
        `1000@${Twitter.placeholderDomain}`
      )
    })
  })

  describe("userInfo", () => {
    it.effect("asks for the address separately, and anchors on the numeric id", () =>
      Effect.gen(function* () {
        const { result, server } = yield* usersMe(profile, {
          body: { data: { id: "1000", confirmed_email: "ada@example.com" } }
        })
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.id, "1000")
        assert.strictEqual(result.success.email, "ada@example.com")
        assert.isTrue(result.success.emailVerified)
        assert.strictEqual(result.success.name, "Ada Lovelace")

        // Two calls: the profile, then the address. Asking for
        // `confirmed_email` up front fails the whole request without the scope.
        assert.strictEqual(server.to(Twitter.userInfoUrl).length, 2)
      })
    )

    it.effect("keeps the sign-in when the address call is refused", () =>
      Effect.gen(function* () {
        const { result } = yield* usersMe(profile, { body: null, status: 403 })
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        // A placeholder, never verified — the refusal costs the address and not
        // the identity.
        assert.strictEqual(result.success.email, `1000@${Twitter.placeholderDomain}`)
        assert.isFalse(result.success.emailVerified)
      })
    )

    it.effect("refuses a body it cannot read", () =>
      Effect.gen(function* () {
        const { result } = yield* usersMe({ nonsense: true }, { body: null })
        assert.strictEqual(result._tag, "Failure")
        assert.strictEqual(result._tag === "Failure" ? result.failure.reason : null, "UserInfoFailed")
      })
    )
  })
})
