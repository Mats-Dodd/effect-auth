/**
 * What every provider test in this directory reaches for.
 *
 * A provider's `userInfo` is exercised on its own — no flow, no deployment,
 * just the stubbed transport wrapped the way the flow wraps it — so these are
 * the two values that shape does need: a verified `id_token`'s claims, and a
 * mock server bound as `HttpClient`.
 */
import { DateTime, Effect } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { IdTokenClaims } from "../../../src/oauth/IdToken.js"
import * as MockProvider from "../../../src/testing/MockProvider.js"

/**
 * A verified `id_token`'s claims, as the flow hands them to a provider's
 * `userInfo`.
 */
export const claimsOf = (overrides?: Partial<IdTokenClaims>): IdTokenClaims => ({
  subject: "subject-1",
  issuer: "https://issuer.test",
  audience: ["client"],
  email: "ada@example.com",
  emailVerified: true,
  name: "Ada Lovelace",
  picture: "https://cdn.test/ada.png",
  nonce: null,
  expiresAt: DateTime.makeUnsafe(3_600_000),
  raw: {},
  ...overrides
})

/**
 * Runs `effect` against a stubbed provider, under the same redirect-refusing
 * client the flow uses.
 */
export const withServer = <A, E>(
  routes: (server: MockProvider.MockServer) => void,
  effect: (server: MockProvider.MockServer) => Effect.Effect<A, E, HttpClient.HttpClient>
): Effect.Effect<A, E> => {
  const server = MockProvider.mockServer()
  routes(server)
  // A test is an entry point, so it may provide — and it provides exactly what
  // the flow would: the redirect-refusing client.
  return Effect.provide(effect(server), MockProvider.safeHttpLayer(server.fetch))
}
