import { assert, describe, it } from "@effect/vitest"
import { Effect, Redacted } from "effect"
import { providerIssuer } from "../../../src/oauth/Provider.js"
import * as Linear from "../../../src/oauth/providers/Linear.js"
import * as Notion from "../../../src/oauth/providers/Notion.js"
import * as Spotify from "../../../src/oauth/providers/Spotify.js"
import * as MockProvider from "../../../src/testing/MockProvider.js"
import { withServer } from "./helpers.js"

const clientId = "client"
const clientSecret = Redacted.make("secret")

/**
 * The three providers that report an address and say nothing about it. Each is
 * checked for the same four things: what it is, what its exchange does where it
 * owns one, what its user body is read as, and — the one that matters — that
 * the account is anchored on the provider's own subject and the address can
 * never be believed.
 */

// -----------------------------------------------------------------------------
// Spotify
// -----------------------------------------------------------------------------

const spotify = Spotify.make({ clientId, clientSecret })

/** `GET /v1/me`, stubbed. */
const spotifyMe = (profile: unknown, status = 200) =>
  withServer(
    (server) => {
      server.on(Spotify.userInfoUrl, () => MockProvider.json(profile, status))
    },
    (server) =>
      Effect.map(Effect.result(spotify.userInfo(MockProvider.tokensOf("spotify-token"))), (result) => ({
        result,
        server
      }))
  )

describe("oauth/providers/Spotify", () => {
  it("is a plain OAuth2 provider under a synthetic issuer", () => {
    assert.strictEqual(spotify.id, "spotify")
    assert.isUndefined(spotify.oidc)
    assert.strictEqual(providerIssuer(spotify), "local:oauth:spotify")
    assert.strictEqual(spotify.authorizationUrl, Spotify.authorizationUrl)
    assert.strictEqual(spotify.tokenUrl, Spotify.tokenUrl)
    assert.deepStrictEqual([...spotify.scopes], ["user-read-email", "user-read-private"])
    // The generic exchange is enough: Spotify accepts client_secret_post.
    assert.isUndefined(spotify.exchange)
  })

  it("can never claim a verified address", () => {
    // The Web API has no verification flag at all, so an address it reports may
    // never implicitly link onto a local account holding the same one.
    assert.strictEqual(spotify.emailVerified, "never")
  })

  it("sends show_dialog only when the deployment asked for it", () => {
    assert.isUndefined(spotify.authorizationParams?.["show_dialog"])
    assert.strictEqual(
      Spotify.make({ clientId, clientSecret, showDialog: true }).authorizationParams?.["show_dialog"],
      "true"
    )
  })

  it("takes the first usable image rather than asserting the order", () => {
    assert.strictEqual(Spotify.avatarUrl([{ url: "https://cdn.test/a.png" }]), "https://cdn.test/a.png")
    // An entry may carry no URL, and the array may be absent entirely.
    assert.strictEqual(Spotify.avatarUrl([{}, { url: "https://cdn.test/b.png" }]), "https://cdn.test/b.png")
    assert.isNull(Spotify.avatarUrl([]))
    assert.isNull(Spotify.avatarUrl(undefined))
  })

  it.effect("anchors the account on the Spotify user id and disbelieves the address", () =>
    Effect.gen(function* () {
      const outcome = yield* spotifyMe({
        id: "spotify-1000",
        email: "ada@example.com",
        display_name: "Ada Lovelace",
        images: [{ url: "https://cdn.test/ada.png" }]
      })
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      const info = outcome.result.success
      assert.strictEqual(info.id, "spotify-1000")
      assert.strictEqual(spotify.accountId(info), "spotify-1000")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isFalse(info.emailVerified)
      assert.strictEqual(info.name, "Ada Lovelace")
      assert.strictEqual(info.image, "https://cdn.test/ada.png")
      assert.strictEqual(outcome.server.to(Spotify.userInfoUrl).length, 1)
    })
  )

  it.effect("falls back to the address for a display name it was not given", () =>
    Effect.gen(function* () {
      const outcome = yield* spotifyMe({ id: "spotify-1000", email: "ada@example.com" })
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      assert.strictEqual(outcome.result.success.name, "ada@example.com")
      assert.isNull(outcome.result.success.image)
    })
  )

  it.effect("refuses a body with no address, and one it cannot read at all", () =>
    Effect.gen(function* () {
      // The scope was refused: there is no identity to provision or link.
      const noEmail = yield* spotifyMe({ id: "spotify-1000", display_name: "Ada" })
      assert.strictEqual(noEmail.result._tag, "Failure")
      assert.strictEqual(noEmail.result._tag === "Failure" ? noEmail.result.failure.reason : null, "UserInfoFailed")

      const noId = yield* spotifyMe({ email: "ada@example.com" })
      assert.strictEqual(noId.result._tag, "Failure")
      assert.strictEqual(noId.result._tag === "Failure" ? noId.result.failure.reason : null, "UserInfoFailed")
    })
  )
})

// -----------------------------------------------------------------------------
// Notion
// -----------------------------------------------------------------------------

const notion = Notion.make({ clientId, clientSecret })

const botUser = (overrides?: Record<string, unknown>) => ({
  bot: {
    owner: {
      user: {
        id: "notion-user-1",
        name: "Ada Lovelace",
        avatar_url: "https://cdn.test/ada.png",
        person: { email: "ada@example.com" },
        ...overrides
      }
    }
  }
})

/** `GET /v1/users/me`, stubbed. */
const notionMe = (body: unknown) =>
  withServer(
    (server) => {
      server.on(Notion.userInfoUrl, () => MockProvider.json(body))
    },
    (server) =>
      Effect.map(Effect.result(notion.userInfo(MockProvider.tokensOf("notion-token"))), (result) => ({
        result,
        server
      }))
  )

describe("oauth/providers/Notion", () => {
  it("is a plain OAuth2 provider that owns its exchange and never refreshes", () => {
    assert.strictEqual(notion.id, "notion")
    assert.isUndefined(notion.oidc)
    assert.strictEqual(providerIssuer(notion), "local:oauth:notion")
    // The token request is Basic + JSON, which the generic form post is not.
    assert.isDefined(notion.exchange)
    // Notion issues no refresh token, so nothing may try to spend one.
    assert.deepStrictEqual(notion.tokenRefresh, { enabled: false })
    // The authorization request carries no scope at all.
    assert.deepStrictEqual([...notion.scopes], [])
    assert.strictEqual(notion.authorizationParams?.["owner"], "user")
  })

  it("can never claim a verified address", () => {
    // The address belongs to the bot's owner and Notion never says it checked it.
    assert.strictEqual(notion.emailVerified, "never")
  })

  it.effect("exchanges with Basic authentication, a JSON body and the version header", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        (server) => {
          server.on(Notion.tokenUrl, () => MockProvider.json({ access_token: "notion-token", token_type: "bearer" }))
        },
        (server) =>
          Effect.map(
            Effect.result(
              notion.exchange!({
                code: "the-code",
                codeVerifier: "unused",
                redirectUri: "https://app.test/auth/callback/notion",
                fallback: Effect.die("the generic exchange must not run")
              })
            ),
            (result) => ({ result, server })
          )
      )
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      assert.strictEqual(Redacted.value(outcome.result.success.accessToken), "notion-token")

      const sent = outcome.server.to(Notion.tokenUrl)[0]!
      assert.strictEqual(sent.method, "POST")
      // Basic, not client_secret_post: Notion rejects the credentials in the body.
      assert.strictEqual(sent.headers["authorization"], `Basic ${btoa(`${clientId}:${Redacted.value(clientSecret)}`)}`)
      assert.strictEqual(sent.headers[Notion.versionHeader.toLowerCase()], Notion.defaultVersion)
      assert.deepStrictEqual(JSON.parse(sent.body), {
        grant_type: "authorization_code",
        code: "the-code",
        redirect_uri: "https://app.test/auth/callback/notion"
      })
      // The secret is never spelled out in the body it signs the request with.
      assert.isFalse(sent.body.includes(Redacted.value(clientSecret)))
    })
  )

  it.effect("reports the token exchange failing rather than decoding a refusal", () =>
    Effect.gen(function* () {
      const outcome = yield* withServer(
        (server) => {
          server.on(Notion.tokenUrl, () => MockProvider.json({ error: "invalid_grant" }, 400))
        },
        () =>
          Effect.result(
            notion.exchange!({
              code: "spent",
              codeVerifier: "unused",
              redirectUri: "https://app.test/auth/callback/notion",
              fallback: Effect.die("the generic exchange must not run")
            })
          )
      )
      assert.strictEqual(outcome._tag, "Failure")
      assert.strictEqual(outcome._tag === "Failure" ? outcome.failure.reason : null, "TokenExchangeFailed")
    })
  )

  it.effect("anchors the account on the person behind the bot, and versions the request", () =>
    Effect.gen(function* () {
      const outcome = yield* notionMe(botUser())
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      const info = outcome.result.success
      // The owner's id, never the bot's: a reinstall mints a new bot and the
      // same person must resolve to the same account.
      assert.strictEqual(info.id, "notion-user-1")
      assert.strictEqual(notion.accountId(info), "notion-user-1")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isFalse(info.emailVerified)
      assert.strictEqual(info.image, "https://cdn.test/ada.png")

      const sent = outcome.server.to(Notion.userInfoUrl)[0]!
      assert.strictEqual(sent.headers[Notion.versionHeader.toLowerCase()], Notion.defaultVersion)
    })
  )

  it.effect("lets a deployment pin the API version deliberately", () =>
    Effect.gen(function* () {
      const pinned = Notion.make({ clientId, clientSecret, version: "2021-08-16" })
      const outcome = yield* withServer(
        (server) => {
          server.on(Notion.userInfoUrl, () => MockProvider.json(botUser()))
        },
        (server) =>
          Effect.map(Effect.result(pinned.userInfo(MockProvider.tokensOf("notion-token"))), (result) => ({
            result,
            server
          }))
      )
      assert.strictEqual(outcome.result._tag, "Success")
      assert.strictEqual(
        outcome.server.to(Notion.userInfoUrl)[0]!.headers[Notion.versionHeader.toLowerCase()],
        "2021-08-16"
      )
    })
  )

  it.effect("refuses a workspace-owned integration, which has no person behind it", () =>
    Effect.gen(function* () {
      const workspace = yield* notionMe({ bot: { owner: { workspace: true } } })
      assert.strictEqual(workspace.result._tag, "Failure")
      assert.strictEqual(workspace.result._tag === "Failure" ? workspace.result.failure.reason : null, "UserInfoFailed")

      // And an owner whose address the integration was not granted.
      const noEmail = yield* notionMe(botUser({ person: undefined }))
      assert.strictEqual(noEmail.result._tag, "Failure")
      assert.strictEqual(noEmail.result._tag === "Failure" ? noEmail.result.failure.reason : null, "UserInfoFailed")
    })
  )
})

// -----------------------------------------------------------------------------
// Linear
// -----------------------------------------------------------------------------

const linear = Linear.make({ clientId, clientSecret })

/** The GraphQL endpoint, stubbed. */
const linearViewer = (body: unknown) =>
  withServer(
    (server) => {
      server.on(Linear.graphqlUrl, () => MockProvider.json(body))
    },
    (server) =>
      Effect.map(Effect.result(linear.userInfo(MockProvider.tokensOf("linear-token"))), (result) => ({
        result,
        server
      }))
  )

describe("oauth/providers/Linear", () => {
  it("is a plain OAuth2 provider that pins the actor to the person", () => {
    assert.strictEqual(linear.id, "linear")
    assert.isUndefined(linear.oidc)
    assert.strictEqual(providerIssuer(linear), "local:oauth:linear")
    assert.strictEqual(linear.authorizationUrl, Linear.authorizationUrl)
    assert.strictEqual(linear.tokenUrl, Linear.tokenUrl)
    assert.deepStrictEqual([...linear.scopes], ["read"])
    // `actor=application` yields a token whose viewer is the integration —
    // not an identity anybody can sign in as.
    assert.strictEqual(linear.authorizationParams?.["actor"], "user")
    // The token endpoint is an ordinary form post; only userinfo needs a seam.
    assert.isUndefined(linear.exchange)
  })

  it("can never claim a verified address", () => {
    assert.strictEqual(linear.emailVerified, "never")
  })

  it.effect("asks GraphQL for the viewer and anchors the account on its id", () =>
    Effect.gen(function* () {
      const outcome = yield* linearViewer({
        data: {
          viewer: {
            id: "linear-user-1",
            email: "ada@example.com",
            name: "Ada Lovelace",
            avatarUrl: "https://cdn.test/ada.png"
          }
        }
      })
      assert.strictEqual(outcome.result._tag, "Success")
      if (outcome.result._tag !== "Success") return
      const info = outcome.result.success
      assert.strictEqual(info.id, "linear-user-1")
      assert.strictEqual(linear.accountId(info), "linear-user-1")
      assert.strictEqual(info.email, "ada@example.com")
      assert.isFalse(info.emailVerified)
      assert.strictEqual(info.image, "https://cdn.test/ada.png")

      const sent = outcome.server.to(Linear.graphqlUrl)[0]!
      // A POST, with the query in the body and the token in the header — the
      // one shape a REST-shaped `userInfo` could not have expressed.
      assert.strictEqual(sent.method, "POST")
      assert.deepStrictEqual(JSON.parse(sent.body), { query: Linear.viewerQuery })
      assert.strictEqual(sent.headers["authorization"], "Bearer linear-token")
    })
  )

  it.effect("refuses a viewer with no address and a GraphQL error document", () =>
    Effect.gen(function* () {
      const noEmail = yield* linearViewer({ data: { viewer: { id: "linear-user-1", name: "Ada" } } })
      assert.strictEqual(noEmail.result._tag, "Failure")
      assert.strictEqual(noEmail.result._tag === "Failure" ? noEmail.result.failure.reason : null, "UserInfoFailed")

      // GraphQL answers 200 with an `errors` array and no `data`; a decoder
      // that read the status alone would have believed it.
      const errored = yield* linearViewer({ errors: [{ message: "authentication required" }] })
      assert.strictEqual(errored.result._tag, "Failure")
      assert.strictEqual(errored.result._tag === "Failure" ? errored.result.failure.reason : null, "UserInfoFailed")
    })
  )
})
