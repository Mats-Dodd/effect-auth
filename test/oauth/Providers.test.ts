import { assert, describe, it } from "@effect/vitest"
import { DateTime, Effect, Redacted } from "effect"
import type { IdTokenClaims } from "../../src/oauth/IdToken.js"
import { providerIssuer } from "../../src/oauth/Provider.js"
import * as Github from "../../src/oauth/providers/Github.js"
import * as Google from "../../src/oauth/providers/Google.js"
import { json, mockServer, safeHttpLayer, tokensOf } from "./harness.js"

const githubApi = "https://api.github.com"

const github = Github.make({
  clientId: "Iv1.github-client",
  clientSecret: Redacted.make("github-client-secret")
})

const claims = (overrides?: Partial<IdTokenClaims>): IdTokenClaims => ({
  subject: "google-subject-1",
  issuer: Google.issuer,
  audience: ["google-client"],
  email: "ada@example.com",
  emailVerified: true,
  name: "Ada Lovelace",
  picture: "https://cdn.test/ada.png",
  nonce: "the-nonce",
  expiresAt: DateTime.makeUnsafe(3_600_000),
  raw: {},
  ...overrides
})

describe("oauth/providers/Github", () => {
  describe("selectEmail", () => {
    it("prefers the primary address, and only calls it verified when it is", () => {
      assert.deepStrictEqual(
        Github.selectEmail(null, [
          { email: "other@example.com", primary: false, verified: true },
          { email: "ada@example.com", primary: true, verified: true }
        ]),
        { email: "ada@example.com", emailVerified: true }
      )
      assert.deepStrictEqual(
        Github.selectEmail(null, [{ email: "ada@example.com", primary: true, verified: false }]),
        { email: "ada@example.com", emailVerified: false }
      )
    })

    it("never trusts the public profile address on its own", () => {
      // The profile address is a free-text field. Corroborated by the list, it
      // carries that entry's flag; absent from the list, it is unverified —
      // otherwise anybody could claim a local account by typing its address
      // into a GitHub profile.
      assert.deepStrictEqual(
        Github.selectEmail("ada@example.com", []),
        { email: "ada@example.com", emailVerified: false }
      )
      assert.deepStrictEqual(
        Github.selectEmail("Ada@Example.com", [
          { email: "ada@example.com", primary: false, verified: true }
        ]),
        { email: "Ada@Example.com", emailVerified: true }
      )
    })

    it("falls back to any verified address, then to the first one", () => {
      assert.deepStrictEqual(
        Github.selectEmail(null, [
          { email: "unverified@example.com", primary: false, verified: false },
          { email: "verified@example.com", primary: false, verified: true }
        ]),
        { email: "verified@example.com", emailVerified: true }
      )
      assert.deepStrictEqual(
        Github.selectEmail(null, [{ email: "only@example.com", primary: false, verified: false }]),
        { email: "only@example.com", emailVerified: false }
      )
    })

    it("answers null when GitHub reported no address at all", () => {
      assert.isNull(Github.selectEmail(null, []))
    })
  })

  describe("decodeEmails", () => {
    it("keeps what it can read and drops the rest", () => {
      assert.deepStrictEqual(
        Github.decodeEmails([
          { email: "ada@example.com", primary: true, verified: true },
          { email: "", primary: true, verified: true },
          { primary: true },
          "not an object",
          null,
          { email: "other@example.com", primary: "yes", verified: "true" }
        ]),
        [
          { email: "ada@example.com", primary: true, verified: true },
          // Only a real `true` counts: a truthy string is not a claim.
          { email: "other@example.com", primary: false, verified: false }
        ]
      )
      assert.deepStrictEqual(Github.decodeEmails({ not: "an array" }), [])
    })
  })

  describe("configuration", () => {
    it("is a plain OAuth2 provider stored under a synthetic issuer", () => {
      assert.strictEqual(github.id, "github")
      assert.isUndefined(github.issuer)
      assert.strictEqual(providerIssuer(github), "local:oauth:github")
      assert.strictEqual(github.authorizationUrl, "https://github.com/login/oauth/authorize")
      assert.strictEqual(github.tokenUrl, "https://github.com/login/oauth/access_token")
      assert.deepStrictEqual([...github.scopes], ["read:user", "user:email"])
    })

    it("points at a GitHub Enterprise deployment when told to", () => {
      const enterprise = Github.make({
        clientId: "id",
        clientSecret: Redacted.make("secret"),
        webUrl: "https://github.acme.internal/",
        apiUrl: "https://github.acme.internal/api/v3/",
        scopes: ["repo"]
      })
      assert.strictEqual(enterprise.authorizationUrl, "https://github.acme.internal/login/oauth/authorize")
      assert.deepStrictEqual([...enterprise.scopes], ["read:user", "user:email", "repo"])
    })
  })

  describe("userInfo", () => {
    const withProfile = (
      profile: unknown,
      emails: { readonly body: unknown; readonly status?: number }
    ) => {
      const server = mockServer()
      server.on(`${githubApi}/user`, () => json(profile))
      server.on(
        `${githubApi}/user/emails`,
        () => json(emails.body, emails.status ?? 200)
      )
      return {
        server,
        run: Effect.result(github.userInfo(tokensOf("github-access-token"))).pipe(
          Effect.provide(safeHttpLayer(server.fetch))
        )
      }
    }

    it.effect("reads the subject from the numeric id and the address from the list", () => {
      const { run, server } = withProfile(
        { id: 1234567, login: "ada", name: "Ada Lovelace", email: null, avatar_url: "https://cdn.test/ada.png" },
        { body: [{ email: "ada@example.com", primary: true, verified: true }] }
      )
      return Effect.gen(function*() {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.id, "1234567")
        assert.strictEqual(result.success.email, "ada@example.com")
        assert.isTrue(result.success.emailVerified)
        assert.strictEqual(result.success.name, "Ada Lovelace")
        assert.strictEqual(result.success.image, "https://cdn.test/ada.png")
        // Both calls are bearer-authenticated and refuse redirects.
        assert.strictEqual(server.requests.length, 2)
        for (const request of server.requests) {
          assert.strictEqual(request.redirect, "manual")
          assert.strictEqual(request.headers.authorization, "Bearer github-access-token")
        }
      })
    })

    it.effect("survives a refused /user/emails, and reports the address unverified", () => {
      const { run } = withProfile(
        { id: 42, login: "ada", email: "ada@example.com" },
        { body: { message: "Requires authentication" }, status: 403 }
      )
      return Effect.gen(function*() {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.email, "ada@example.com")
        assert.isFalse(result.success.emailVerified)
      })
    })

    it.effect("falls back to the login when the profile has no name", () => {
      const { run } = withProfile(
        { id: 42, login: "ada" },
        { body: [{ email: "ada@example.com", primary: true, verified: true }] }
      )
      return Effect.gen(function*() {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.name, "ada")
        assert.isNull(result.success.image)
      })
    })

    it.effect("fails when there is no address to be had", () => {
      const { run } = withProfile({ id: 42, login: "ada" }, { body: [], status: 403 })
      return Effect.gen(function*() {
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "UserInfoFailed")
      })
    })

    it.effect("fails when the profile carries no id", () => {
      const { run } = withProfile(
        { login: "ada" },
        { body: [{ email: "ada@example.com", primary: true, verified: true }] }
      )
      return Effect.gen(function*() {
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "UserInfoFailed")
      })
    })
  })
})

describe("oauth/providers/Google", () => {
  const google = Google.make({
    clientId: "google-client",
    clientSecret: Redacted.make("google-client-secret")
  })

  it("is an OIDC provider with an issuer, a key set and offline access", () => {
    assert.strictEqual(google.id, "google")
    assert.strictEqual(google.issuer, "https://accounts.google.com")
    assert.strictEqual(providerIssuer(google), "https://accounts.google.com")
    assert.strictEqual(google.jwksUrl, "https://www.googleapis.com/oauth2/v3/certs")
    assert.strictEqual(google.authorizationUrl, "https://accounts.google.com/o/oauth2/v2/auth")
    assert.strictEqual(google.tokenUrl, "https://oauth2.googleapis.com/token")
    assert.deepStrictEqual([...google.scopes], ["openid", "email", "profile"])
    assert.strictEqual(google.authorizationParams?.access_type, "offline")
  })

  it("passes prompt and a hosted domain through as authorization parameters", () => {
    const restricted = Google.make({
      clientId: "id",
      clientSecret: Redacted.make("secret"),
      accessType: "online",
      prompt: "consent",
      hostedDomain: "acme.test"
    })
    assert.deepStrictEqual({ ...restricted.authorizationParams }, {
      access_type: "online",
      prompt: "consent",
      hd: "acme.test"
    })
  })

  it.effect("takes the identity from the verified id_token, with no request at all", () => {
    const server = mockServer()
    return Effect.gen(function*() {
      const info = yield* google.userInfo(tokensOf("google-access-token", { idTokenClaims: claims() }))
      assert.strictEqual(info.id, "google-subject-1")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isTrue(info.emailVerified)
      assert.strictEqual(info.name, "Ada Lovelace")
      assert.strictEqual(info.image, "https://cdn.test/ada.png")
      assert.strictEqual(server.requests.length, 0)
    }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
  })

  it.effect("consults the userinfo endpoint only when the token carries no address", () => {
    const server = mockServer()
    server.on(Google.userInfoUrl, () =>
      json({ sub: "somebody-else", email: "ada@example.com", email_verified: true, name: "From userinfo" }))
    return Effect.gen(function*() {
      const info = yield* google.userInfo(
        tokensOf("google-access-token", { idTokenClaims: claims({ email: null, name: null, picture: null }) })
      )
      // The address may come from the bearer-authenticated body; the subject
      // never does — it stays the one the signature covered.
      assert.strictEqual(info.id, "google-subject-1")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isTrue(info.emailVerified)
      assert.strictEqual(server.requests.length, 1)
      assert.strictEqual(server.requests[0]?.redirect, "manual")
    }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
  })

  it.effect("refuses a token from outside the configured hosted domain", () => {
    const server = mockServer()
    server.on(Google.userInfoUrl, () => json({ sub: "s", email: "ada@personal.test", email_verified: true }))
    const restricted = Google.make({
      clientId: "google-client",
      clientSecret: Redacted.make("google-client-secret"),
      hostedDomain: "acme.test"
    })
    return Effect.gen(function*() {
      // `hd` on the authorization request only pre-filters Google's account
      // chooser and can be stripped from the URL, so the restriction is only
      // real if the *claim* is checked. A personal account carries none.
      const personal = yield* Effect.result(
        restricted.userInfo(tokensOf("google-access-token", { idTokenClaims: claims() }))
      )
      assert.strictEqual(personal._tag, "Failure")
      if (personal._tag === "Failure") {
        assert.strictEqual(personal.failure.reason, "IdTokenInvalid")
      }

      // Another Workspace domain is refused just the same.
      const elsewhere = yield* Effect.result(
        restricted.userInfo(
          tokensOf("google-access-token", { idTokenClaims: claims({ raw: { hd: "evil.test" } }) })
        )
      )
      assert.strictEqual(elsewhere._tag, "Failure")

      // The configured domain passes.
      const admitted = yield* restricted.userInfo(
        tokensOf("google-access-token", { idTokenClaims: claims({ raw: { hd: "acme.test" } }) })
      )
      assert.strictEqual(admitted.email, "ada@example.com")

      // And the check runs before the userinfo fallback, so a token with no
      // address does not even reach the network.
      const noAddress = yield* Effect.result(
        restricted.userInfo(
          tokensOf("google-access-token", { idTokenClaims: claims({ email: null }) })
        )
      )
      assert.strictEqual(noAddress._tag, "Failure")
      assert.strictEqual(server.requests.length, 0)
    }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
  })

  it.effect("fails closed when the flow handed it no verified claims", () => {
    const server = mockServer()
    return Effect.gen(function*() {
      const result = yield* Effect.result(google.userInfo(tokensOf("google-access-token")))
      assert.strictEqual(result._tag, "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure.reason, "IdTokenInvalid")
      assert.strictEqual(server.requests.length, 0)
    }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
  })
})
