/**
 * The composite ceremony atoms.
 *
 * **Details**
 *
 * `register` and `authenticate` are the only atoms in this package whose body is
 * more than one request, so they are the only ones whose *shape* is worth
 * asserting: options, then the browser, then verify, as one effect with no
 * intermediate state an application could hold, drop or leak. The transport is a
 * stub — the point is the generated client's real encoding and decoding, without
 * a socket — and `navigator.credentials` is the `WebAuthnClient` seam, which is
 * exactly what that seam exists for.
 */
import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer } from "effect"
import type { HttpClientError } from "effect/unstable/http"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import { AtomRegistry } from "effect/unstable/reactivity"
import * as AuthClient from "../../src/client/AuthClient.js"
import * as PasskeysClient from "../../src/client/PasskeysClient.js"
import type { WebAuthnClientService } from "../../src/client/internal/webauthn.js"
import { WebAuthnClientError } from "../../src/client/internal/webauthn.js"
import type { AuthenticationResponse, RegistrationResponse } from "../../src/passkeys/Wire.js"

const now = "2024-01-01T00:00:00.000Z"

const registrationOptionsJson = {
  rp: { id: "example.com", name: "Example" },
  user: { id: "aGFuZGxl", name: "ada@example.com", displayName: "Ada Lovelace" },
  challenge: "Y2hhbGxlbmdl",
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  timeout: 60000,
  excludeCredentials: [],
  authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred" },
  attestation: "none"
}

const authenticationOptionsJson = {
  challenge: "Y2hhbGxlbmdl",
  timeout: 60000,
  rpId: "example.com",
  allowCredentials: [],
  userVerification: "preferred"
}

const summaryJson = {
  id: "0192e5a0-0000-7000-8000-000000000001",
  name: "laptop",
  aaguid: "00000000-0000-0000-0000-000000000000",
  transports: ["internal"],
  backedUp: false,
  createdAt: now,
  lastUsedAt: null
}

const sessionWithUserJson = {
  user: {
    id: "0192e5a0-0000-7000-8000-000000000002",
    name: "Ada Lovelace",
    email: "ada@example.com",
    emailVerified: true,
    image: null,
    createdAt: now,
    updatedAt: now
  },
  session: {
    id: "0192e5a0-0000-7000-8000-000000000003",
    userId: "0192e5a0-0000-7000-8000-000000000002",
    expiresAt: "2024-01-08T00:00:00.000Z",
    ipAddress: null,
    userAgent: null,
    authenticatedAt: now,
    aal: "aal2",
    methods: "[]",
    rememberMe: true,
    createdAt: now,
    updatedAt: now
  }
}

const registrationResponse: RegistrationResponse = {
  id: "Y3JlZC1pZA",
  rawId: "Y3JlZC1pZA",
  type: "public-key",
  response: { clientDataJSON: "Y2xpZW50", attestationObject: "YXR0" }
}

const authenticationResponse: AuthenticationResponse = {
  id: "Y3JlZC1pZA",
  rawId: "Y3JlZC1pZA",
  type: "public-key",
  response: { clientDataJSON: "Y2xpZW50", authenticatorData: "YXV0aA", signature: "c2ln" }
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

const preprocess: HttpClient.HttpClient.Preprocess<HttpClientError.HttpClientError, never> = Effect.succeed

/** A transport that answers the four ceremony endpoints and records the calls. */
const stub = () => {
  const calls: Array<string> = []
  const bodies: Array<unknown> = []
  const routes: Record<string, () => Response> = {
    "POST /auth/passkeys/register/options": () => json(200, registrationOptionsJson),
    "POST /auth/passkeys/register/verify": () => json(200, summaryJson),
    "POST /auth/passkeys/authenticate/options": () => json(200, authenticationOptionsJson),
    "POST /auth/passkeys/authenticate/verify": () => json(200, sessionWithUserJson)
  }
  const client = HttpClient.makeWith(
    Effect.fnUntraced(function* (requestEffect) {
      const request = yield* requestEffect
      const path = new URL(request.url, "http://auth.test").pathname
      calls.push(`${request.method} ${path}`)
      const body = request.body
      bodies.push(body._tag === "Uint8Array" ? JSON.parse(new TextDecoder().decode(body.body)) : null)
      const route = Object.hasOwn(routes, `${request.method} ${path}`) ? routes[`${request.method} ${path}`] : undefined
      return HttpClientResponse.fromWeb(request, route?.() ?? json(404, { _tag: "NotFound" }))
    }),
    preprocess
  )
  return { layer: Layer.succeed(HttpClient.HttpClient, client), calls, bodies }
}

/** A browser that always produces the fixture responses. */
const willing: WebAuthnClientService = {
  isSupported: Effect.succeed(true),
  isConditionalMediationAvailable: Effect.succeed(true),
  create: () => Effect.succeed(registrationResponse),
  get: () => Effect.succeed(authenticationResponse)
}

/** A browser whose owner dismissed the prompt. */
const dismissing: WebAuthnClientService = {
  ...willing,
  create: () => Effect.fail(WebAuthnClientError.make({ reason: "Cancelled" })),
  get: () => Effect.fail(WebAuthnClientError.make({ reason: "Cancelled" }))
}

const registry = Effect.acquireRelease(
  Effect.sync(() => AtomRegistry.make()),
  (made) => Effect.sync(() => made.dispose())
)

describe("PasskeysClient", () => {
  it.effect("register is one effect: options, the browser, then verify", () =>
    Effect.gen(function* () {
      const transport = stub()
      const client = PasskeysClient.make({ httpClient: transport.layer, webauthn: willing })
      const reg = yield* registry

      const summary = yield* AuthClient.run(client.register, { name: "laptop" }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(summary.id, summaryJson.id)
      assert.strictEqual(summary.name, "laptop")
      assert.deepStrictEqual(transport.calls, [
        "POST /auth/passkeys/register/options",
        "POST /auth/passkeys/register/verify"
      ])
      // What the browser produced is what was sent back, unedited.
      assert.deepStrictEqual(transport.bodies[1], { response: registrationResponse, name: "laptop" })
    })
  )

  it.effect("authenticate is one effect too", () =>
    Effect.gen(function* () {
      const transport = stub()
      const client = PasskeysClient.make({ httpClient: transport.layer, webauthn: willing })
      const reg = yield* registry

      const result = yield* AuthClient.run(client.authenticate, { rememberMe: false }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.isFalse("_tag" in result, "nothing was owed, so this is a session")
      assert.deepStrictEqual(transport.calls, [
        "POST /auth/passkeys/authenticate/options",
        "POST /auth/passkeys/authenticate/verify"
      ])
      assert.deepStrictEqual(transport.bodies[1], { response: authenticationResponse, rememberMe: false })
    })
  )

  it.effect("a dismissed prompt never reaches the verify endpoint", () =>
    Effect.gen(function* () {
      const transport = stub()
      const client = PasskeysClient.make({ httpClient: transport.layer, webauthn: dismissing })
      const reg = yield* registry

      const result = yield* Effect.flip(
        AuthClient.run(client.authenticate, {}).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))
      )

      assert.strictEqual(result._tag, "WebAuthnClientError")
      if (result._tag !== "WebAuthnClientError") return
      assert.strictEqual(result.reason, "Cancelled")
      // The ceremony was asked for and then abandoned: nothing was verified.
      assert.deepStrictEqual(transport.calls, ["POST /auth/passkeys/authenticate/options"])
    })
  )

  it.effect("the browser seam is what isSupported reports", () =>
    Effect.gen(function* () {
      const transport = stub()
      const client = PasskeysClient.make({ httpClient: transport.layer, webauthn: willing })
      assert.isTrue(yield* client.isSupported)
      assert.isTrue(yield* client.isConditionalMediationAvailable)
    })
  )

  it("names the reactivity key the credential list is held under", () => {
    assert.strictEqual(PasskeysClient.passkeysKey, "auth.passkeys")
  })
})
