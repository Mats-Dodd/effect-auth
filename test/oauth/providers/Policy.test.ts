/**
 * The `emailVerified` declaration, as a rule rather than a comment.
 *
 * **Details**
 *
 * The field is required on `OAuthProviderConfig` so that a new provider has to
 * decide rather than fall into the permissive answer by saying nothing, and
 * `makeRegistry` puts every provider through `applyEmailVerifiedPolicy` on the
 * way in — which is what makes `"never"` hold whatever the provider's own
 * `userInfo` read, wrote or forgot. These are the assertions that pin both
 * halves; the per-provider files assert which tier each one chose.
 */
import { assert, describe, it } from "@effect/vitest"
import { Effect, type Layer, Redacted } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { OAuthProviderConfig, OAuthUserInfo } from "../../../src/oauth/Provider.js"
import { applyEmailVerifiedPolicy, makeRegistry } from "../../../src/oauth/Provider.js"
import * as Apple from "../../../src/oauth/providers/Apple.js"
import * as Discord from "../../../src/oauth/providers/Discord.js"
import * as Facebook from "../../../src/oauth/providers/Facebook.js"
import * as Github from "../../../src/oauth/providers/Github.js"
import * as Gitlab from "../../../src/oauth/providers/Gitlab.js"
import * as Google from "../../../src/oauth/providers/Google.js"
import * as Linear from "../../../src/oauth/providers/Linear.js"
import * as LinkedIn from "../../../src/oauth/providers/LinkedIn.js"
import * as Microsoft from "../../../src/oauth/providers/Microsoft.js"
import * as Notion from "../../../src/oauth/providers/Notion.js"
import * as Slack from "../../../src/oauth/providers/Slack.js"
import * as Spotify from "../../../src/oauth/providers/Spotify.js"
import * as Twitch from "../../../src/oauth/providers/Twitch.js"
import * as Twitter from "../../../src/oauth/providers/Twitter.js"
import * as MockProvider from "../../../src/testing/MockProvider.js"

const clientId = "client"
const clientSecret = Redacted.make("secret")
const credentials = { clientId, clientSecret }

/** Every provider this library ships, built with nothing but credentials. */
const shipped: ReadonlyArray<readonly [string, OAuthProviderConfig]> = [
  ["apple", Apple.make({ clientId, teamId: "TEAM", keyId: "KEY", privateKey: Redacted.make("-----BEGIN-----") })],
  ["discord", Discord.make(credentials)],
  ["facebook", Facebook.make(credentials)],
  ["github", Github.make(credentials)],
  ["gitlab", Gitlab.make(credentials)],
  ["google", Google.make(credentials)],
  ["linear", Linear.make(credentials)],
  ["linkedin", LinkedIn.make(credentials)],
  ["microsoft", Microsoft.make(credentials)],
  ["notion", Notion.make(credentials)],
  ["slack", Slack.make(credentials)],
  ["spotify", Spotify.make(credentials)],
  ["twitch", Twitch.make(credentials)],
  ["twitter", Twitter.make(credentials)]
]

/** A provider whose `userInfo` insists on a verified address. */
const insistent = (emailVerified: "derived" | "never"): OAuthProviderConfig => ({
  ...MockProvider.mockProvider(),
  id: "insistent",
  emailVerified,
  userInfo: () =>
    Effect.succeed({
      id: "subject-1",
      email: "victim@example.com",
      // The claim the declaration has to survive.
      emailVerified: true
    } satisfies OAuthUserInfo)
})

/**
 * The redirect-refusing client the flow provides, over a server with no routes
 * at all: nothing in this file makes a request, and a transport that would
 * answer one would hide it if something did.
 */
const noNetwork: Layer.Layer<HttpClient.HttpClient> = MockProvider.safeHttpLayer(MockProvider.mockServer().fetch)

describe("oauth/providers/emailVerified", () => {
  it("is declared by every provider this library ships", () => {
    for (const [name, provider] of shipped) {
      assert.include(["derived", "never"], provider.emailVerified, `${name} declares a tier`)
    }
  })

  it("declares 'never' for exactly the four that report an address nobody checked", () => {
    // Facebook (Graph states nothing, Limited Login carries no flag), Spotify
    // (no flag in the Web API at all), Notion (the bot owner's address) and
    // Linear (the `viewer` query). Every one of them may still be linked
    // deliberately from a session the person already holds.
    assert.deepStrictEqual(
      shipped.filter(([, provider]) => provider.emailVerified === "never").map(([name]) => name),
      ["facebook", "linear", "notion", "spotify"]
    )
  })

  it.effect("forces the address unverified for a 'never' provider, whatever its userInfo said", () =>
    Effect.gen(function* () {
      const forced = applyEmailVerifiedPolicy(insistent("never"))
      const info = yield* forced.userInfo(MockProvider.tokensOf("token"))
      // The declaration is applied *after* the provider ran, so it holds
      // whatever the provider read, wrote or forgot.
      assert.isFalse(info.emailVerified)
      // And nothing else about the identity is edited.
      assert.strictEqual(info.id, "subject-1")
      assert.strictEqual(info.email, "victim@example.com")
    }).pipe(Effect.provide(noNetwork))
  )

  it("hands a 'derived' provider back untouched", () => {
    const provider = insistent("derived")
    assert.strictEqual(applyEmailVerifiedPolicy(provider), provider)
  })

  it.effect("is enforced by the registry, which is the only way the flow reaches a provider", () =>
    Effect.gen(function* () {
      // A provider value read straight out of an application's own array does
      // not honour its own declaration; one resolved through the registry does,
      // and the flow only ever has the second.
      const raw = insistent("never")
      const registry = makeRegistry([raw])
      const direct = yield* raw.userInfo(MockProvider.tokensOf("token"))
      assert.isTrue(direct.emailVerified)

      const resolved = yield* registry.get("insistent")
      const info = yield* resolved.userInfo(MockProvider.tokensOf("token"))
      assert.isFalse(info.emailVerified)
    }).pipe(Effect.provide(noNetwork))
  )

  it.effect("cannot be escaped by a 'never' provider that ships its own userInfo", () =>
    Effect.gen(function* () {
      // The one that matters in practice: Facebook's Graph path reads a profile
      // and reports an address. Whatever it decides, the registry's copy says
      // unverified — so it can never implicitly link onto a local account.
      const registry = makeRegistry(shipped.map(([, provider]) => provider))
      for (const id of ["facebook", "spotify", "notion", "linear"]) {
        const provider = yield* registry.get(id)
        assert.strictEqual(provider.emailVerified, "never")
      }
    }).pipe(Effect.provide(noNetwork))
  )
})
