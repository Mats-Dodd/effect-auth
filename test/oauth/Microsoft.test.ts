import { assert, describe, it, layer } from "@effect/vitest"
import { Config, ConfigProvider, Effect, Option, Redacted } from "effect"
import type { JWTPayload } from "jose"
import type { IdTokenClaims } from "../../src/oauth/IdToken.js"
import { verify } from "../../src/oauth/IdToken.js"
import type { OAuthProviderConfig } from "../../src/oauth/Provider.js"
import { providerIssuer, resolveClientSecret } from "../../src/oauth/Provider.js"
import * as Microsoft from "../../src/oauth/providers/Microsoft.js"
import { MockProvider } from "../../src/testing/index.js"

/** The audience {@link MockProvider.IdTokenSigner} mints for by default. */
const clientId = "mock-client-id"

const authority = Microsoft.defaultAuthority

/** A work/school tenant, and Microsoft's fixed personal-account one. */
const workTenant = "11111111-2222-3333-4444-555555555555"
const consumerTenant = Microsoft.consumerTenantId

const issuerOfTenant = (tenant: string) => `${authority}/${tenant}/v2.0`

const microsoft = (options?: Partial<Microsoft.Options>) => Microsoft.make({ clientId, ...options })

/**
 * Verification exactly as `OAuthFlow.withIdToken` does it: the provider's
 * `issuerOf` when it has one — the multi-tenant case — and its fixed `issuer`
 * otherwise. This is the only place the *function* form of
 * `IdToken.verify`'s `issuer` is exercised end to end.
 */
const verifying = (
  provider: OAuthProviderConfig,
  signer: MockProvider.IdTokenSignerService,
  payload: JWTPayload,
  sign?: MockProvider.SignOptions
) =>
  Effect.gen(function* () {
    const token = Redacted.make(yield* Effect.promise(() => signer.sign(payload, sign)))
    return yield* Effect.result(
      verify({
        providerId: Microsoft.id,
        token,
        issuer: provider.oidc?.issuerOf ?? provider.oidc?.issuer ?? "",
        audience: provider.oidc?.audience ?? provider.clientId,
        keys: signer.jwks,
        nonce: null,
        algorithms: ["RS256"]
      })
    )
  })

/** A token from `tenant`, signed with that tenant's issuer, and its claims. */
const tokenFrom = (
  provider: OAuthProviderConfig,
  signer: MockProvider.IdTokenSignerService,
  tenant: string,
  claims?: JWTPayload
) =>
  verifying(
    provider,
    signer,
    { sub: "app-scoped-subject", oid: "the-object-id", tid: tenant, ...claims },
    { issuer: issuerOfTenant(tenant), audience: clientId }
  )

/** The tokens a provider's `userInfo` is called with, carrying verified claims. */
const tokensOf = (claims: IdTokenClaims) => MockProvider.tokensOf("entra-access-token", { idTokenClaims: claims })

/**
 * A transport for providers that never make a request: every route on it is a
 * 404, so an accidental fetch fails loudly rather than silently passing.
 */
const noNetwork = MockProvider.safeHttpLayer(MockProvider.mockServer().fetch)

describe("oauth/providers/Microsoft", () => {
  describe("configuration", () => {
    it("derives every endpoint from the authority and the tenant", () => {
      const provider = microsoft()
      assert.strictEqual(provider.id, "microsoft")
      assert.strictEqual(provider.authorizationUrl, `${authority}/common/oauth2/v2.0/authorize`)
      assert.strictEqual(provider.tokenUrl, `${authority}/common/oauth2/v2.0/token`)
      assert.deepStrictEqual(provider.oidc?.keys, { jwksUrl: `${authority}/common/discovery/v2.0/keys` })
      // Inert for `common`: `issuerOf` is what a token is actually checked
      // against. It is still the issuer accounts are stored under.
      assert.strictEqual(provider.oidc?.issuer, `${authority}/common/v2.0`)
      assert.strictEqual(providerIssuer(provider), `${authority}/common/v2.0`)
      assert.deepStrictEqual([...provider.scopes], ["openid", "profile", "email", "User.Read", "offline_access"])
      // Entra answers a refresh with a token for the default resource unless the
      // scopes are repeated.
      assert.strictEqual(provider.tokenRefresh?.params?.scope, "openid profile email User.Read offline_access")
    })

    it("trims a trailing slash off the authority", () => {
      // Left in, the expected issuer would be `https://host//<tid>/v2.0` and
      // every token would be refused.
      const ciam = Microsoft.endpointsOf({ authority: "https://acme.ciamlogin.com//", tenantId: workTenant })
      assert.strictEqual(ciam.authorizationUrl, `https://acme.ciamlogin.com/${workTenant}/oauth2/v2.0/authorize`)
      assert.strictEqual(ciam.issuer, `https://acme.ciamlogin.com/${workTenant}/v2.0`)
    })

    it("is a public client when no secret was configured", () => {
      // Entra supports PKCE-only public clients, and a secret shipped inside a
      // native or single-page application would not be one.
      assert.isUndefined(microsoft().clientSecret)
    })

    it("pins the issuer for a single tenant, and derives it for the three that are not one", () => {
      assert.isUndefined(microsoft({ tenantId: workTenant }).oidc?.issuerOf)
      for (const tenant of ["common", "organizations", "consumers"]) {
        assert.isFunction(microsoft({ tenantId: tenant }).oidc?.issuerOf)
      }
    })
  })

  layer(MockProvider.IdTokenSigner.layer)("tenant rules", (it) => {
    it.effect("accepts a token whose issuer names its own tenant", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()
        const result = yield* tokenFrom(provider, signer, workTenant)
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.issuer, issuerOfTenant(workTenant))
      })
    )

    it.effect("refuses a token whose issuer names a tenant other than its own tid", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()
        // The forgery this check exists for: a token minted in the attacker's
        // own tenant, claiming to have been issued by somebody else's.
        const result = yield* verifying(
          provider,
          signer,
          { sub: "s", oid: "o", tid: workTenant },
          { issuer: issuerOfTenant("99999999-9999-9999-9999-999999999999"), audience: clientId }
        )
        assert.strictEqual(result._tag, "Failure")
      })
    )

    it.effect("refuses a token with no tid at all", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()
        const result = yield* verifying(
          provider,
          signer,
          { sub: "s", oid: "o" },
          { issuer: issuerOfTenant(workTenant), audience: clientId }
        )
        // `issuerOf` returning null rejects, exactly as a mismatch does.
        assert.strictEqual(result._tag, "Failure")
      })
    )

    it.effect("refuses a personal account under `organizations`", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft({ tenantId: "organizations" })

        const personal = yield* tokenFrom(provider, signer, consumerTenant)
        assert.strictEqual(personal._tag, "Failure")

        const work = yield* tokenFrom(provider, signer, workTenant)
        assert.strictEqual(work._tag, "Success")
      })
    )

    it.effect("requires a personal account under `consumers`", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft({ tenantId: "consumers" })

        // The `organizations` and `consumers` key sets overlap, so without this
        // a work token would sign in through the consumer endpoint.
        const work = yield* tokenFrom(provider, signer, workTenant)
        assert.strictEqual(work._tag, "Failure")

        const personal = yield* tokenFrom(provider, signer, consumerTenant)
        assert.strictEqual(personal._tag, "Success")
      })
    )

    it.effect("pins one tenant's issuer when one tenant was configured", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft({ tenantId: workTenant })

        const own = yield* tokenFrom(provider, signer, workTenant)
        assert.strictEqual(own._tag, "Success")

        // A token from another tenant is refused by the fixed issuer alone —
        // there is no `issuerOf` in this configuration.
        const other = yield* tokenFrom(provider, signer, consumerTenant)
        assert.strictEqual(other._tag, "Failure")
      })
    )
  })

  layer(MockProvider.IdTokenSigner.layer)("userInfo", (it) => {
    const verifiedClaims = (
      provider: OAuthProviderConfig,
      signer: MockProvider.IdTokenSignerService,
      claims?: JWTPayload
    ) =>
      Effect.gen(function* () {
        const result = yield* tokenFrom(provider, signer, workTenant, claims)
        if (result._tag !== "Success") return yield* Effect.die("the token did not verify")
        return result.success
      })

    it.effect("anchors the identity on oid, not on the app-scoped sub", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()
        const claims = yield* verifiedClaims(provider, signer, {
          email: "ada@acme.test",
          name: "Ada Lovelace",
          picture: "https://cdn.test/ada.png"
        })

        const info = yield* provider.userInfo(tokensOf(claims))
        // `sub` is per application; `oid` is the account in its tenant.
        assert.strictEqual(info.id, "the-object-id")
        assert.notStrictEqual(info.id, claims.subject)
        assert.strictEqual(info.email, "ada@acme.test")
        assert.strictEqual(info.name, "Ada Lovelace")
        assert.strictEqual(info.image, "https://cdn.test/ada.png")
        // The account's issuer is the one the *verified* token named, per tenant.
        assert.strictEqual(info.issuer, issuerOfTenant(workTenant))
      }).pipe(Effect.provide(noNetwork))
    )

    it.effect("refuses a token with no oid", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()
        const claims = yield* verifiedClaims(provider, signer, { oid: undefined, email: "ada@acme.test" })

        const result = yield* Effect.result(provider.userInfo(tokensOf(claims)))
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "IdTokenInvalid")
      }).pipe(Effect.provide(noNetwork))
    )

    it.effect("defaults emailVerified to false, and reads both of Entra's statements", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()

        // The optional claim was never configured: no evidence, no verification.
        const silent = yield* verifiedClaims(provider, signer, { email: "ada@acme.test" })
        assert.isFalse((yield* provider.userInfo(tokensOf(silent))).emailVerified)

        const claimed = yield* verifiedClaims(provider, signer, {
          email: "ada@acme.test",
          email_verified: true
        })
        assert.isTrue((yield* provider.userInfo(tokensOf(claimed))).emailVerified)

        // The fallback: the address appears in Entra's own verified list.
        const listed = yield* verifiedClaims(provider, signer, {
          email: "ada@acme.test",
          verified_primary_email: ["ada@acme.test"]
        })
        assert.isTrue((yield* provider.userInfo(tokensOf(listed))).emailVerified)

        // A list that does not contain the address being reported is not
        // evidence about that address.
        const elsewhere = yield* verifiedClaims(provider, signer, {
          email: "ada@acme.test",
          verified_primary_email: ["somebody@acme.test"]
        })
        assert.isFalse((yield* provider.userInfo(tokensOf(elsewhere))).emailVerified)
      }).pipe(Effect.provide(noNetwork))
    )

    it.effect("falls back to the UPN as an address, and never as a verified one", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const provider = microsoft()
        const claims = yield* verifiedClaims(provider, signer, {
          preferred_username: "ada@acme.onmicrosoft.com",
          // A flag about an absent `email` claim is not a statement about the UPN.
          email_verified: true
        })

        const info = yield* provider.userInfo(tokensOf(claims))
        assert.strictEqual(info.email, "ada@acme.onmicrosoft.com")
        assert.isFalse(info.emailVerified)
      }).pipe(Effect.provide(noNetwork))
    )

    it.effect("fails closed when the flow handed it no verified claims", () =>
      Effect.gen(function* () {
        const provider = microsoft()
        const result = yield* Effect.result(provider.userInfo(MockProvider.tokensOf("entra-access-token")))
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "IdTokenInvalid")
      }).pipe(Effect.provide(noNetwork))
    )
  })

  describe("makeConfig", () => {
    it.effect("builds the same value from the environment, secret and all", () =>
      Effect.gen(function* () {
        const provider = yield* Microsoft.makeConfig({
          clientId: Config.string("MS_CLIENT_ID"),
          clientSecret: Config.redacted("MS_CLIENT_SECRET"),
          tenantId: Config.string("MS_TENANT_ID")
        })
        assert.strictEqual(provider.clientId, "ms-from-the-environment")
        assert.deepStrictEqual(
          yield* Effect.map(resolveClientSecret(provider), Option.map(Redacted.value)),
          Option.some("ms-secret-from-the-environment")
        )
        assert.strictEqual(provider.oidc?.issuer, issuerOfTenant(workTenant))
        assert.isUndefined(provider.oidc?.issuerOf)
      }).pipe(
        Effect.provide(
          ConfigProvider.layer(
            ConfigProvider.fromUnknown({
              MS_CLIENT_ID: "ms-from-the-environment",
              MS_CLIENT_SECRET: "ms-secret-from-the-environment",
              MS_TENANT_ID: workTenant
            })
          )
        )
      )
    )

    it.effect("leaves a public client without a secret rather than failing", () =>
      Effect.gen(function* () {
        const provider = yield* Microsoft.makeConfig({ clientId: Config.string("MS_CLIENT_ID") })
        assert.deepStrictEqual(
          yield* Effect.map(resolveClientSecret(provider), Option.map(Redacted.value)),
          Option.none()
        )
      }).pipe(Effect.provide(ConfigProvider.layer(ConfigProvider.fromUnknown({ MS_CLIENT_ID: "public-client" }))))
    )
  })
})
