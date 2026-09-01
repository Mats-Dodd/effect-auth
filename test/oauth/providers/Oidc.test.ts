import { assert, describe, it } from "@effect/vitest"
import { Effect, Redacted } from "effect"
import { providerIssuer } from "../../../src/oauth/Provider.js"
import * as LinkedIn from "../../../src/oauth/providers/LinkedIn.js"
import * as Slack from "../../../src/oauth/providers/Slack.js"
import * as Twitch from "../../../src/oauth/providers/Twitch.js"
import * as MockProvider from "../../../src/testing/MockProvider.js"
import { claimsOf, withServer } from "./helpers.js"

const clientId = "client"
const clientSecret = Redacted.make("secret")

describe("oauth/providers/LinkedIn", () => {
  const linkedin = LinkedIn.make({ clientId, clientSecret })

  it("is an OIDC provider whose accounts are stored under LinkedIn's issuer", () => {
    assert.strictEqual(linkedin.id, "linkedin")
    assert.strictEqual(linkedin.oidc?.issuer, LinkedIn.issuer)
    assert.deepStrictEqual(linkedin.oidc?.keys, { jwksUrl: LinkedIn.jwksUrl })
    assert.strictEqual(providerIssuer(linkedin), LinkedIn.issuer)
    // The `email_verified` claim of a signed token is a claim it can point at.
    assert.strictEqual(linkedin.emailVerified, "derived")
    assert.deepStrictEqual([...linkedin.scopes], ["openid", "profile", "email"])
  })

  it.effect("takes the identity from the verified token, making no request", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        () => {},
        (server) =>
          Effect.map(
            Effect.result(
              linkedin.userInfo(
                MockProvider.tokensOf("token", { idTokenClaims: claimsOf({ subject: "li-sub", emailVerified: true }) })
              )
            ),
            (result) => ({ result, server })
          )
      )
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      assert.strictEqual(outcome.result.success.id, "li-sub")
      assert.isTrue(outcome.result.success.emailVerified)
      assert.strictEqual(outcome.server.requests.length, 0)
    })
  )

  it.effect("consults the userinfo endpoint only when the token carries no address", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        (server) =>
          server.on(LinkedIn.userInfoUrl, () =>
            MockProvider.json({ email: "ada@example.com", email_verified: true, name: "Ada" })
          ),
        (server) =>
          Effect.map(
            Effect.result(
              linkedin.userInfo(
                MockProvider.tokensOf("token", { idTokenClaims: claimsOf({ subject: "li-sub", email: null }) })
              )
            ),
            (result) => ({ result, server })
          )
      )
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      // The subject still comes from the signature, never from a body an access
      // token alone can obtain.
      assert.strictEqual(outcome.result.success.id, "li-sub")
      assert.strictEqual(outcome.result.success.email, "ada@example.com")
      assert.strictEqual(outcome.server.to(LinkedIn.userInfoUrl).length, 1)
    })
  )

  it.effect("refuses a callback that carried no verified token", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        () => {},
        () => Effect.result(linkedin.userInfo(MockProvider.tokensOf("token")))
      )
      assert.strictEqual(outcome._tag, "Failure")
      assert.strictEqual(outcome._tag === "Failure" ? outcome.failure.reason : null, "IdTokenInvalid")
    })
  )
})

describe("oauth/providers/Slack", () => {
  const slack = Slack.make({ clientId, clientSecret })

  it("is an OIDC provider under Slack's issuer", () => {
    assert.strictEqual(slack.id, "slack")
    assert.strictEqual(slack.oidc?.issuer, Slack.issuer)
    assert.deepStrictEqual(slack.oidc?.keys, { jwksUrl: Slack.jwksUrl })
    assert.strictEqual(slack.emailVerified, "derived")
  })

  it("sends the workspace hint when one is configured, and nothing when not", () => {
    assert.isUndefined(slack.authorizationParams?.["team"])
    assert.strictEqual(Slack.make({ clientId, clientSecret, team: "T123" }).authorizationParams?.["team"], "T123")
  })

  it("reads the subject out of the URI-namespaced claim", () => {
    assert.strictEqual(Slack.subjectOf({ [Slack.userIdClaim]: "U0123" }), "U0123")
    // A body that does not state it states nothing this can anchor on.
    assert.isNull(Slack.subjectOf({ sub: "U0123-T0123" }))
    assert.isNull(Slack.subjectOf({ [Slack.userIdClaim]: 42 }))
  })

  it.effect("anchors the account on the person, not on the installation", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        () => {},
        () =>
          Effect.result(
            slack.userInfo(
              MockProvider.tokensOf("token", {
                idTokenClaims: claimsOf({
                  subject: "U0123-T0123",
                  raw: { [Slack.userIdClaim]: "U0123" }
                })
              })
            )
          )
      )
      assert.strictEqual(outcome._tag, "Success")
      if (outcome._tag !== "Success") return
      // `sub` is scoped to the installation; a reinstall would change it and
      // re-provision the same person.
      assert.strictEqual(outcome.success.id, "U0123")
      assert.strictEqual(outcome.success.email, "ada@example.com")
    })
  )

  it.effect("refuses a token that does not carry the claim rather than falling back to sub", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        () => {},
        () => Effect.result(slack.userInfo(MockProvider.tokensOf("token", { idTokenClaims: claimsOf({ raw: {} }) })))
      )
      assert.strictEqual(outcome._tag, "Failure")
      assert.strictEqual(outcome._tag === "Failure" ? outcome.failure.reason : null, "UserInfoFailed")
    })
  )
})

describe("oauth/providers/Twitch", () => {
  const twitch = Twitch.make({ clientId, clientSecret })

  it("is an OIDC provider under Twitch's issuer", () => {
    assert.strictEqual(twitch.id, "twitch")
    assert.strictEqual(twitch.oidc?.issuer, Twitch.issuer)
    assert.deepStrictEqual(twitch.oidc?.keys, { jwksUrl: Twitch.jwksUrl })
    assert.strictEqual(twitch.emailVerified, "derived")
  })

  it("sends the claims parameter, without which the token carries a subject and nothing else", () => {
    const claims = twitch.authorizationParams?.["claims"]
    assert.isDefined(claims)
    const parsed: unknown = JSON.parse(claims)
    // Narrowed rather than asserted: the document is Twitch's own shape and a
    // test that told the compiler what it is would stop noticing when it moves.
    assert.isTrue(typeof parsed === "object" && parsed !== null && "id_token" in parsed)
    if (typeof parsed !== "object" || parsed === null || !("id_token" in parsed)) return
    const idToken: unknown = parsed.id_token
    assert.isTrue(typeof idToken === "object" && idToken !== null)
    if (typeof idToken !== "object" || idToken === null) return
    // OpenID Connect Core §5.5's shape: `null` means "voluntary", and the nulls
    // are load-bearing rather than placeholders.
    assert.isTrue("email" in idToken)
    assert.isTrue("email_verified" in idToken)
    if (!("email" in idToken)) return
    assert.isNull(idToken.email)

    assert.strictEqual(
      Twitch.make({ clientId, clientSecret, forceVerify: true }).authorizationParams?.["force_verify"],
      "true"
    )
    assert.strictEqual(Twitch.make({ clientId, clientSecret, claims: "{}" }).authorizationParams?.["claims"], "{}")
  })

  it.effect("takes the identity from the verified token", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        () => {},
        () =>
          Effect.result(
            twitch.userInfo(
              MockProvider.tokensOf("token", { idTokenClaims: claimsOf({ subject: "tw-sub", emailVerified: false }) })
            )
          )
      )
      assert.strictEqual(outcome._tag, "Success")
      if (outcome._tag !== "Success") return
      assert.strictEqual(outcome.success.id, "tw-sub")
      // Derived from the claim, so an unverified address stays unverified.
      assert.isFalse(outcome.success.emailVerified)
    })
  )

  it.effect("falls back to userinfo when a replaced claims document dropped the address", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        (server) =>
          server.on(Twitch.userInfoUrl, () => MockProvider.json({ email: "ada@example.com", email_verified: true })),
        (server) =>
          Effect.map(
            Effect.result(
              twitch.userInfo(
                MockProvider.tokensOf("token", { idTokenClaims: claimsOf({ subject: "tw-sub", email: null }) })
              )
            ),
            (result) => ({ result, server })
          )
      )
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      assert.strictEqual(outcome.result.success.id, "tw-sub")
      assert.strictEqual(outcome.server.to(Twitch.userInfoUrl).length, 1)
    })
  )
})
