import { assert, describe, it } from "@effect/vitest"
import { Config, ConfigProvider, DateTime, Effect, Option, Redacted } from "effect"
import type { IdTokenClaims } from "../../src/oauth/IdToken.js"
import type { OAuthProviderConfig } from "../../src/oauth/Provider.js"
import { providerIssuer, resolveClientSecret } from "../../src/oauth/Provider.js"
import * as Discord from "../../src/oauth/providers/Discord.js"
import * as Github from "../../src/oauth/providers/Github.js"
import * as Gitlab from "../../src/oauth/providers/Gitlab.js"
import * as Google from "../../src/oauth/providers/Google.js"
import { MockProvider } from "../../src/testing/index.js"

const githubApi = "https://api.github.com"

/**
 * The client secret a provider will actually send, unwrapped. `clientSecret` is
 * one of three shapes — absent for a public PKCE client, fixed, or minted per
 * request — so a test reads it the way the flow does.
 */
const secretOf = (provider: OAuthProviderConfig) =>
  Effect.map(resolveClientSecret(provider), Option.map(Redacted.value))

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
      assert.deepStrictEqual(Github.selectEmail(null, [{ email: "ada@example.com", primary: true, verified: false }]), {
        email: "ada@example.com",
        emailVerified: false
      })
    })

    it("never trusts the public profile address on its own", () => {
      // The profile address is a free-text field. Corroborated by the list, it
      // carries that entry's flag; absent from the list, it is unverified —
      // otherwise anybody could claim a local account by typing its address
      // into a GitHub profile.
      assert.deepStrictEqual(Github.selectEmail("ada@example.com", []), {
        email: "ada@example.com",
        emailVerified: false
      })
      assert.deepStrictEqual(
        Github.selectEmail("Ada@Example.com", [{ email: "ada@example.com", primary: false, verified: true }]),
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
      assert.isUndefined(github.oidc)
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

  describe("makeConfig", () => {
    it.effect("builds the same value from the environment", () =>
      Effect.gen(function* () {
        const provider = yield* Github.makeConfig({
          clientId: Config.string("GITHUB_CLIENT_ID"),
          clientSecret: Config.redacted("GITHUB_CLIENT_SECRET"),
          webUrl: Config.string("GITHUB_WEB_URL")
        })
        assert.strictEqual(provider.id, "github")
        assert.strictEqual(provider.clientId, "Iv1.from-the-environment")
        // The secret is `Redacted` from the moment it leaves the environment.
        assert.deepStrictEqual(yield* secretOf(provider), Option.some("github-secret-from-the-environment"))
        assert.strictEqual(provider.authorizationUrl, "https://github.acme.internal/login/oauth/authorize")
      }).pipe(
        Effect.provide(
          ConfigProvider.layer(
            ConfigProvider.fromUnknown({
              GITHUB_CLIENT_ID: "Iv1.from-the-environment",
              GITHUB_CLIENT_SECRET: "github-secret-from-the-environment",
              GITHUB_WEB_URL: "https://github.acme.internal"
            })
          )
        )
      )
    )

    it.effect("fails rather than defaulting when a credential is absent", () =>
      Effect.gen(function* () {
        const result = yield* Effect.result(
          Github.makeConfig({
            clientId: Config.string("GITHUB_CLIENT_ID"),
            clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
          })
        )
        assert.strictEqual(result._tag, "Failure")
      }).pipe(Effect.provide(ConfigProvider.layer(ConfigProvider.fromUnknown({}))))
    )
  })

  describe("userInfo", () => {
    const withProfile = (profile: unknown, emails: { readonly body: unknown; readonly status?: number }) => {
      const server = MockProvider.mockServer()
      server.on(`${githubApi}/user`, () => MockProvider.json(profile))
      server.on(`${githubApi}/user/emails`, () => MockProvider.json(emails.body, emails.status ?? 200))
      return {
        server,
        run: Effect.result(github.userInfo(MockProvider.tokensOf("github-access-token"))).pipe(
          Effect.provide(MockProvider.safeHttpLayer(server.fetch))
        )
      }
    }

    it.effect("reads the subject from the numeric id and the address from the list", () => {
      const { run, server } = withProfile(
        { id: 1234567, login: "ada", name: "Ada Lovelace", email: null, avatar_url: "https://cdn.test/ada.png" },
        { body: [{ email: "ada@example.com", primary: true, verified: true }] }
      )
      return Effect.gen(function* () {
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
      return Effect.gen(function* () {
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
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.name, "ada")
        assert.isNull(result.success.image)
      })
    })

    it.effect("fails when there is no address to be had", () => {
      const { run } = withProfile({ id: 42, login: "ada" }, { body: [], status: 403 })
      return Effect.gen(function* () {
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
      return Effect.gen(function* () {
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
    assert.strictEqual(google.oidc?.issuer, "https://accounts.google.com")
    assert.strictEqual(providerIssuer(google), "https://accounts.google.com")
    // The key source is a union, and Google's arm of it is a URL to fetch.
    assert.deepStrictEqual(google.oidc?.keys, { jwksUrl: "https://www.googleapis.com/oauth2/v3/certs" })
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
    assert.deepStrictEqual(
      { ...restricted.authorizationParams },
      {
        access_type: "online",
        prompt: "consent",
        hd: "acme.test"
      }
    )
  })

  it.effect("takes the identity from the verified id_token, with no request at all", () => {
    const server = MockProvider.mockServer()
    return Effect.gen(function* () {
      const info = yield* google.userInfo(MockProvider.tokensOf("google-access-token", { idTokenClaims: claims() }))
      assert.strictEqual(info.id, "google-subject-1")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isTrue(info.emailVerified)
      assert.strictEqual(info.name, "Ada Lovelace")
      assert.strictEqual(info.image, "https://cdn.test/ada.png")
      assert.strictEqual(server.requests.length, 0)
    }).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
  })

  it.effect("consults the userinfo endpoint only when the token carries no address", () => {
    const server = MockProvider.mockServer()
    server.on(Google.userInfoUrl, () =>
      MockProvider.json({ sub: "somebody-else", email: "ada@example.com", email_verified: true, name: "From userinfo" })
    )
    return Effect.gen(function* () {
      const info = yield* google.userInfo(
        MockProvider.tokensOf("google-access-token", {
          idTokenClaims: claims({ email: null, name: null, picture: null })
        })
      )
      // The address may come from the bearer-authenticated body; the subject
      // never does — it stays the one the signature covered.
      assert.strictEqual(info.id, "google-subject-1")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isTrue(info.emailVerified)
      assert.strictEqual(server.requests.length, 1)
      assert.strictEqual(server.requests[0]?.redirect, "manual")
    }).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
  })

  it.effect("refuses a token from outside the configured hosted domain", () => {
    const server = MockProvider.mockServer()
    server.on(Google.userInfoUrl, () =>
      MockProvider.json({ sub: "s", email: "ada@personal.test", email_verified: true })
    )
    const restricted = Google.make({
      clientId: "google-client",
      clientSecret: Redacted.make("google-client-secret"),
      hostedDomain: "acme.test"
    })
    return Effect.gen(function* () {
      // `hd` on the authorization request only pre-filters Google's account
      // chooser and can be stripped from the URL, so the restriction is only
      // real if the *claim* is checked. A personal account carries none.
      const personal = yield* Effect.result(
        restricted.userInfo(MockProvider.tokensOf("google-access-token", { idTokenClaims: claims() }))
      )
      assert.strictEqual(personal._tag, "Failure")
      if (personal._tag === "Failure") {
        assert.strictEqual(personal.failure.reason, "IdTokenInvalid")
      }

      // Another Workspace domain is refused just the same.
      const elsewhere = yield* Effect.result(
        restricted.userInfo(
          MockProvider.tokensOf("google-access-token", { idTokenClaims: claims({ raw: { hd: "evil.test" } }) })
        )
      )
      assert.strictEqual(elsewhere._tag, "Failure")

      // The configured domain passes.
      const admitted = yield* restricted.userInfo(
        MockProvider.tokensOf("google-access-token", { idTokenClaims: claims({ raw: { hd: "acme.test" } }) })
      )
      assert.strictEqual(admitted.email, "ada@example.com")

      // And the check runs before the userinfo fallback, so a token with no
      // address does not even reach the network.
      const noAddress = yield* Effect.result(
        restricted.userInfo(MockProvider.tokensOf("google-access-token", { idTokenClaims: claims({ email: null }) }))
      )
      assert.strictEqual(noAddress._tag, "Failure")
      assert.strictEqual(server.requests.length, 0)
    }).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
  })

  it.effect("builds the same value from the environment", () =>
    Effect.gen(function* () {
      const provider = yield* Google.makeConfig({
        clientId: Config.string("GOOGLE_CLIENT_ID"),
        clientSecret: Config.redacted("GOOGLE_CLIENT_SECRET"),
        hostedDomain: Config.string("GOOGLE_HOSTED_DOMAIN")
      })
      assert.strictEqual(provider.id, "google")
      assert.strictEqual(provider.clientId, "0123.from-the-environment")
      assert.deepStrictEqual(yield* secretOf(provider), Option.some("google-secret-from-the-environment"))
      assert.strictEqual(provider.oidc?.issuer, "https://accounts.google.com")
      assert.strictEqual(provider.authorizationParams?.hd, "acme.test")
    }).pipe(
      Effect.provide(
        ConfigProvider.layer(
          ConfigProvider.fromUnknown({
            GOOGLE_CLIENT_ID: "0123.from-the-environment",
            GOOGLE_CLIENT_SECRET: "google-secret-from-the-environment",
            GOOGLE_HOSTED_DOMAIN: "acme.test"
          })
        )
      )
    )
  )

  it.effect("fails closed when the flow handed it no verified claims", () => {
    const server = MockProvider.mockServer()
    return Effect.gen(function* () {
      const result = yield* Effect.result(google.userInfo(MockProvider.tokensOf("google-access-token")))
      assert.strictEqual(result._tag, "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure.reason, "IdTokenInvalid")
      assert.strictEqual(server.requests.length, 0)
    }).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
  })
})

describe("oauth/providers/Discord", () => {
  const discord = Discord.make({
    clientId: "discord-client",
    clientSecret: Redacted.make("discord-client-secret")
  })

  const withProfile = (profile: unknown) => {
    const server = MockProvider.mockServer()
    server.on(Discord.userInfoUrl, () => MockProvider.json(profile))
    return {
      server,
      run: Effect.result(discord.userInfo(MockProvider.tokensOf("discord-access-token"))).pipe(
        Effect.provide(MockProvider.safeHttpLayer(server.fetch))
      )
    }
  }

  it("is a plain OAuth2 provider that asks for identify and email", () => {
    assert.strictEqual(discord.id, "discord")
    assert.isUndefined(discord.oidc)
    assert.strictEqual(providerIssuer(discord), "local:oauth:discord")
    assert.strictEqual(discord.authorizationUrl, "https://discord.com/api/oauth2/authorize")
    assert.strictEqual(discord.tokenUrl, "https://discord.com/api/oauth2/token")
    assert.deepStrictEqual([...discord.scopes], ["identify", "email"])
    // `none` is what makes a repeat sign-in a single redirect rather than a
    // consent screen somebody has already agreed to.
    assert.strictEqual(discord.authorizationParams?.prompt, "none")
  })

  it("lets a deployment ask for the consent screen every time", () => {
    const consenting = Discord.make({
      clientId: "id",
      clientSecret: Redacted.make("secret"),
      prompt: "consent",
      scopes: ["guilds"],
      authorizationParams: { permissions: "8" }
    })
    assert.deepStrictEqual({ ...consenting.authorizationParams }, { prompt: "consent", permissions: "8" })
    assert.deepStrictEqual([...consenting.scopes], ["identify", "email", "guilds"])
  })

  describe("avatarUrl", () => {
    it("builds the CDN URL for an avatar, animated ones as a gif", () => {
      assert.strictEqual(
        Discord.avatarUrl({ id: "80351110224678912", avatar: "8342729096ea3675442027381ff50dfe", discriminator: "0" }),
        "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png"
      )
      assert.strictEqual(
        Discord.avatarUrl({
          id: "80351110224678912",
          avatar: "a_1269e74af4df7417b13759eae50c83dc",
          discriminator: "0"
        }),
        "https://cdn.discordapp.com/avatars/80351110224678912/a_1269e74af4df7417b13759eae50c83dc.gif"
      )
    })

    it("picks a default avatar from the snowflake, or from the legacy discriminator", () => {
      // The new username system: `(id >> 22) % 6`, which overflows a `number`
      // and is why the shift is done in `BigInt`.
      assert.strictEqual(
        Discord.avatarUrl({ id: "80351110224678912", avatar: null, discriminator: "0" }),
        "https://cdn.discordapp.com/embed/avatars/5.png"
      )
      // The legacy one: `discriminator % 5`.
      assert.strictEqual(
        Discord.avatarUrl({ id: "80351110224678912", avatar: null, discriminator: "1337" }),
        "https://cdn.discordapp.com/embed/avatars/2.png"
      )
    })

    it("answers something for a profile whose fields make no sense", () => {
      // A provider body is not to be surprised by: `BigInt("nonsense")` throws
      // and `parseInt("")` is NaN, and neither may reach the caller.
      assert.strictEqual(
        Discord.avatarUrl({ id: "not-a-snowflake", avatar: null, discriminator: null }),
        "https://cdn.discordapp.com/embed/avatars/0.png"
      )
      assert.strictEqual(
        Discord.avatarUrl({ id: "1", avatar: null, discriminator: "not-a-number" }),
        "https://cdn.discordapp.com/embed/avatars/0.png"
      )
    })
  })

  describe("userInfo", () => {
    it.effect("reads the identity from one bearer-authenticated call", () => {
      const { run, server } = withProfile({
        id: "80351110224678912",
        username: "ada",
        global_name: "Ada Lovelace",
        discriminator: "0",
        avatar: "8342729096ea3675442027381ff50dfe",
        email: "ada@example.com",
        verified: true
      })
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.id, "80351110224678912")
        assert.strictEqual(result.success.email, "ada@example.com")
        assert.isTrue(result.success.emailVerified)
        assert.strictEqual(result.success.name, "Ada Lovelace")
        assert.strictEqual(
          result.success.image,
          "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png"
        )
        assert.strictEqual(server.requests.length, 1)
        assert.strictEqual(server.requests[0]?.redirect, "manual")
        assert.strictEqual(server.requests[0]?.headers.authorization, "Bearer discord-access-token")
      })
    })

    it.effect("falls back to the username, and calls an unverified address unverified", () => {
      const { run } = withProfile({
        id: "1",
        username: "ada",
        discriminator: "0",
        avatar: null,
        email: "ada@example.com",
        // Discord spells this `false` for an unconfirmed address, and nothing
        // but a literal `true` counts as a claim.
        verified: false
      })
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.name, "ada")
        assert.isFalse(result.success.emailVerified)
      })
    })

    it.effect("fails when the email scope was refused", () => {
      // Discord omits `email` entirely rather than sending null, and an identity
      // with no address can be neither linked nor provisioned.
      const { run } = withProfile({ id: "1", username: "ada", discriminator: "0", avatar: null, verified: true })
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "UserInfoFailed")
      })
    })

    it.effect("fails when the profile carries no id", () => {
      const { run } = withProfile({ username: "ada", email: "ada@example.com" })
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
      })
    })
  })

  it.effect("builds the same value from the environment", () =>
    Effect.gen(function* () {
      const provider = yield* Discord.makeConfig({
        clientId: Config.string("DISCORD_CLIENT_ID"),
        clientSecret: Config.redacted("DISCORD_CLIENT_SECRET"),
        prompt: Config.literals(["none", "consent"], "DISCORD_PROMPT")
      })
      assert.strictEqual(provider.id, "discord")
      assert.strictEqual(provider.clientId, "discord-from-the-environment")
      assert.deepStrictEqual(yield* secretOf(provider), Option.some("discord-secret-from-the-environment"))
      assert.strictEqual(provider.authorizationParams?.prompt, "consent")
    }).pipe(
      Effect.provide(
        ConfigProvider.layer(
          ConfigProvider.fromUnknown({
            DISCORD_CLIENT_ID: "discord-from-the-environment",
            DISCORD_CLIENT_SECRET: "discord-secret-from-the-environment",
            DISCORD_PROMPT: "consent"
          })
        )
      )
    )
  )
})

describe("oauth/providers/Gitlab", () => {
  const gitlab = Gitlab.make({
    clientId: "gitlab-client",
    clientSecret: Redacted.make("gitlab-client-secret")
  })

  const withProfile = (profile: unknown, provider: OAuthProviderConfig = gitlab) => {
    const server = MockProvider.mockServer()
    server.on(Gitlab.endpointsOf().userInfoUrl, () => MockProvider.json(profile))
    server.on("https://gitlab.acme.internal/api/v4/user", () => MockProvider.json(profile))
    return {
      server,
      run: Effect.result(provider.userInfo(MockProvider.tokensOf("gitlab-access-token"))).pipe(
        Effect.provide(MockProvider.safeHttpLayer(server.fetch))
      )
    }
  }

  const active = {
    id: 4321,
    username: "ada",
    name: "Ada Lovelace",
    email: "ada@example.com",
    state: "active",
    avatar_url: "https://gitlab.com/uploads/ada.png"
  }

  it("is a plain OAuth2 provider pointed at gitlab.com by default", () => {
    assert.strictEqual(gitlab.id, "gitlab")
    assert.isUndefined(gitlab.oidc)
    assert.strictEqual(providerIssuer(gitlab), "local:oauth:gitlab")
    assert.strictEqual(gitlab.authorizationUrl, "https://gitlab.com/oauth/authorize")
    assert.strictEqual(gitlab.tokenUrl, "https://gitlab.com/oauth/token")
    assert.deepStrictEqual([...gitlab.scopes], ["read_user"])
  })

  it("derives every endpoint from a self-hosted instance, trailing slashes and all", () => {
    assert.deepStrictEqual(Gitlab.endpointsOf("https://gitlab.acme.internal///"), {
      authorizationUrl: "https://gitlab.acme.internal/oauth/authorize",
      tokenUrl: "https://gitlab.acme.internal/oauth/token",
      userInfoUrl: "https://gitlab.acme.internal/api/v4/user"
    })
  })

  describe("userInfo", () => {
    it.effect("reads the identity from the API, with the numeric id as a string", () => {
      const { run, server } = withProfile(active)
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.id, "4321")
        assert.strictEqual(result.success.email, "ada@example.com")
        // GitLab does not promise `email_verified`, and absent means no.
        assert.isFalse(result.success.emailVerified)
        assert.strictEqual(result.success.name, "Ada Lovelace")
        assert.strictEqual(result.success.image, "https://gitlab.com/uploads/ada.png")
        assert.strictEqual(server.requests[0]?.redirect, "manual")
        assert.strictEqual(server.requests[0]?.headers.authorization, "Bearer gitlab-access-token")
      })
    })

    it.effect("believes email_verified when GitLab does state it", () => {
      const { run } = withProfile({ ...active, email_verified: true })
      return Effect.gen(function* () {
        const result = yield* run
        assert.isTrue(result._tag === "Success" && result.success.emailVerified)
      })
    })

    it.effect("refuses an account that is not active", () => {
      // A blocked, deactivated or banned account still holds a working token.
      return Effect.gen(function* () {
        for (const state of ["blocked", "deactivated", "banned", "ldap_blocked"]) {
          const { run } = withProfile({ ...active, state })
          const result = yield* run
          assert.strictEqual(result._tag, "Failure", state)
          if (result._tag === "Failure") assert.strictEqual(result.failure.reason, "UserInfoFailed")
        }

        // And an answer that names no state at all fails closed.
        const { run } = withProfile({ ...active, state: undefined })
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
      })
    })

    it.effect("refuses a locked account", () => {
      const { run } = withProfile({ ...active, locked: true })
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
      })
    })

    it.effect("talks to the self-hosted instance it was configured with", () => {
      const enterprise = Gitlab.make({
        clientId: "id",
        clientSecret: Redacted.make("secret"),
        baseUrl: "https://gitlab.acme.internal"
      })
      const { run, server } = withProfile(active, enterprise)
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        assert.strictEqual(server.requests[0]?.url, "https://gitlab.acme.internal/api/v4/user")
      })
    })

    it.effect("fails when the profile carries no address", () => {
      const { run } = withProfile({ ...active, email: undefined })
      return Effect.gen(function* () {
        const result = yield* run
        assert.strictEqual(result._tag, "Failure")
      })
    })
  })

  it.effect("builds the same value from the environment", () =>
    Effect.gen(function* () {
      const provider = yield* Gitlab.makeConfig({
        clientId: Config.string("GITLAB_CLIENT_ID"),
        clientSecret: Config.redacted("GITLAB_CLIENT_SECRET"),
        baseUrl: Config.string("GITLAB_BASE_URL")
      })
      assert.strictEqual(provider.clientId, "gitlab-from-the-environment")
      assert.deepStrictEqual(yield* secretOf(provider), Option.some("gitlab-secret-from-the-environment"))
      assert.strictEqual(provider.authorizationUrl, "https://gitlab.acme.internal/oauth/authorize")
    }).pipe(
      Effect.provide(
        ConfigProvider.layer(
          ConfigProvider.fromUnknown({
            GITLAB_CLIENT_ID: "gitlab-from-the-environment",
            GITLAB_CLIENT_SECRET: "gitlab-secret-from-the-environment",
            GITLAB_BASE_URL: "https://gitlab.acme.internal"
          })
        )
      )
    )
  )
})
