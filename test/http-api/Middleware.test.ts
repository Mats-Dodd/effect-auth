import { assert, describe, it } from "@effect/vitest"
import { Context, Duration, Effect, Redacted, Schema } from "effect"
import { HttpApiEndpoint, HttpApiMiddleware } from "effect/unstable/httpapi"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import type { AuthenticatorSummary } from "../../src/domain/Authenticators.js"
import {
  Authenticated,
  AuthoritativeSession,
  CurrentSession,
  CurrentUser,
  freshSession,
  RequireAssurance
} from "../../src/http/Middleware.js"
import { availableFactors, resolveAssurancePolicy } from "../../src/http/MiddlewareLive.js"
import { UserId } from "../../src/domain/Schema.js"

const configWith = (options?: {
  readonly freshAge?: Duration.Duration
  readonly stepUpWindow?: Duration.Duration
}): AuthConfig.AuthConfigService =>
  AuthConfig.make({
    baseUrl: "https://app.example.com",
    secret: Redacted.make("test-secret-at-least-32-bytes-long"),
    ...(options?.freshAge === undefined ? {} : { session: { freshAge: options.freshAge } }),
    ...(options?.stepUpWindow === undefined ? {} : { assurance: { stepUpWindow: options.stepUpWindow } })
  })

const userId = UserId.make("0193f6f0-0000-7000-8000-000000000001")

const summary = (options: {
  readonly type: string
  readonly signIn?: boolean
  readonly secondFactor?: boolean
}): AuthenticatorSummary => ({
  type: options.type,
  id: `${options.type}-1`,
  name: null,
  verifiedAt: null,
  lastUsedAt: null,
  signIn: options.signIn ?? false,
  secondFactor: options.secondFactor ?? false,
  restricted: false
})

const security = Authenticated.security

describe("http/Middleware", () => {
  describe("Authenticated", () => {
    it("is security middleware", () => {
      // `isSecurity` takes `HttpApiMiddleware.AnyService`, whose static side
      // declares a `provides` property that `HttpApiMiddleware.ServiceClass` —
      // the type of every middleware class effect itself produces — never has.
      // No middleware value can satisfy that parameter, so the runtime check
      // (`hasProperty(u, SecurityTypeId)`, and `SecurityTypeId` is not exported)
      // is reachable only through a cast. Upstream typing gap, not ours.
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion
      assert.isTrue(HttpApiMiddleware.isSecurity(Authenticated as unknown as HttpApiMiddleware.AnyService))
    })

    it("tries the secure cookie, then the plain cookie, then a bearer token", () => {
      assert.deepStrictEqual(Object.keys(security), ["secureSessionCookie", "sessionCookie", "bearer"])

      assert.strictEqual(security.secureSessionCookie._tag, "ApiKey")
      assert.strictEqual(security.secureSessionCookie.key, "__Secure-effect_auth.session")
      assert.strictEqual(security.secureSessionCookie.in, "cookie")

      assert.strictEqual(security.sessionCookie._tag, "ApiKey")
      assert.strictEqual(security.sessionCookie.key, "effect_auth.session")
      assert.strictEqual(security.sessionCookie.in, "cookie")

      assert.strictEqual(security.bearer._tag, "Http")
    })

    it("declares Unauthorized and StepUpRequired, and is required on generated clients", () => {
      // Two, not one. An endpoint annotation is erased from the endpoint's
      // *type*, so the refusal the annotation produces has nowhere to be
      // declared but here — which is why every authenticated endpoint's union
      // carries `StepUpRequired` whether or not it asks for any assurance.
      assert.deepStrictEqual(
        Array.from(Authenticated.error, (schema) => schema.ast.annotations?.["identifier"]),
        ["effect/HttpApiError/Unauthorized", "effect-auth/StepUpRequired"]
      )
      assert.isTrue(Authenticated.requiredForClient)
    })

    it("keys the principal under distinct service ids", () => {
      assert.strictEqual(CurrentSession.key, "effect-auth/http/Middleware/CurrentSession")
      assert.strictEqual(CurrentUser.key, "effect-auth/http/Middleware/CurrentUser")
    })
  })

  /**
   * The annotation the cookie cache is switched off by, read exactly as
   * `MiddlewareLive` reads it.
   *
   * **Gotchas**
   *
   * *Which* of this library's endpoints carry it is pinned in
   * `test/http-api/AuthApi.test.ts`; what is pinned here is the mechanism a
   * plugin's own endpoint opts in through, and the default an endpoint that says
   * nothing gets.
   */
  describe("AuthoritativeSession", () => {
    const plain = HttpApiEndpoint.get("plain", "/plain", { success: Schema.String }).middleware(Authenticated)

    const authoritative = HttpApiEndpoint.get("authoritative", "/authoritative", { success: Schema.String })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)

    it("defaults to false, so an endpoint that says nothing is cacheable", () => {
      assert.isFalse(Context.get(plain.annotations, AuthoritativeSession))
    })

    it("is true on an endpoint that annotates it", () => {
      assert.isTrue(Context.get(authoritative.annotations, AuthoritativeSession))
    })

    it("is a reference on the endpoint's annotations, not a middleware of its own", () => {
      assert.strictEqual(AuthoritativeSession.key, "effect-auth/AuthoritativeSession")
      // Annotating changes nothing else about the endpoint: the same middleware,
      // the same declared errors, and therefore the same client and the same
      // OpenAPI document.
      assert.deepStrictEqual(Array.from(authoritative.middlewares), Array.from(plain.middlewares))
    })
  })

  /**
   * The annotation the assurance guard is driven by, read exactly as
   * `MiddlewareLive` reads it. Which of this library's endpoints carry it is
   * pinned in `test/http-api/AuthApi.test.ts`; what is pinned here is the
   * mechanism and the defaults.
   */
  describe("RequireAssurance", () => {
    const plain = HttpApiEndpoint.get("plain", "/plain", { success: Schema.String }).middleware(Authenticated)

    const guarded = HttpApiEndpoint.get("guarded", "/guarded", { success: Schema.String })
      .middleware(Authenticated)
      .annotate(RequireAssurance, freshSession)

    it("defaults to undefined, so an endpoint that says nothing requires nothing", () => {
      assert.isUndefined(Context.get(plain.annotations, RequireAssurance))
    })

    it("carries the policy an endpoint annotates", () => {
      assert.deepStrictEqual(Context.get(guarded.annotations, RequireAssurance), {})
    })

    it("is a reference on the endpoint's annotations, not a middleware of its own", () => {
      assert.strictEqual(RequireAssurance.key, "effect-auth/RequireAssurance")
      assert.deepStrictEqual(Array.from(guarded.middlewares), Array.from(plain.middlewares))
    })

    it("freshSession states nothing at all — the deployment supplies the age", () => {
      assert.deepStrictEqual(freshSession, {})
    })
  })

  describe("resolveAssurancePolicy", () => {
    it("fills an absent maxAge from session.freshAge", () => {
      assert.deepStrictEqual(resolveAssurancePolicy(configWith({ freshAge: Duration.minutes(5) }), freshSession), {
        maxAge: Duration.minutes(5)
      })
    })

    it("fills it from assurance.stepUpWindow when the policy asks for aal2", () => {
      assert.deepStrictEqual(
        resolveAssurancePolicy(configWith({ freshAge: Duration.minutes(5), stepUpWindow: Duration.hours(2) }), {
          aal: "aal2"
        }),
        { aal: "aal2", maxAge: Duration.hours(2) }
      )
    })

    it("leaves a stated maxAge alone, infinity included", () => {
      const config = configWith({ freshAge: Duration.minutes(5) })
      assert.deepStrictEqual(resolveAssurancePolicy(config, { maxAge: Duration.seconds(30) }), {
        maxAge: Duration.seconds(30)
      })
      assert.deepStrictEqual(resolveAssurancePolicy(config, { aal: "aal2", maxAge: Duration.infinity }), {
        aal: "aal2",
        maxAge: Duration.infinity
      })
    })

    it("keeps every other member of the policy", () => {
      assert.deepStrictEqual(
        resolveAssurancePolicy(configWith({ freshAge: Duration.days(1), stepUpWindow: Duration.hours(2) }), {
          methods: ["passkey"],
          allowRecovery: false
        }),
        { methods: ["passkey"], allowRecovery: false, maxAge: Duration.hours(2) }
      )
    })

    it("a policy naming methods is a step-up policy, whether or not it says aal2", () => {
      // The two spellings of "a second factor is required" have to get the same
      // window. `{ methods: [...] }` is if anything stricter than
      // `{ aal: "aal2" }`, so admitting a twenty-hour-old proof there while
      // refusing it beside the other spelling would be backwards.
      const config = configWith({ freshAge: Duration.days(1), stepUpWindow: Duration.hours(12) })
      assert.deepStrictEqual(resolveAssurancePolicy(config, { methods: ["totp", "passkey"] }), {
        methods: ["totp", "passkey"],
        maxAge: Duration.hours(12)
      })
      assert.deepStrictEqual(resolveAssurancePolicy(config, { aal: "aal2" }), {
        aal: "aal2",
        maxAge: Duration.hours(12)
      })
      // And a policy that names neither is still the freshness rule.
      assert.deepStrictEqual(resolveAssurancePolicy(config, { allowRecovery: false }), {
        allowRecovery: false,
        maxAge: Duration.days(1)
      })
    })

    it("refuses a stepUpWindow that is not a positive duration", () => {
      assert.throws(() => configWith({ stepUpWindow: Duration.zero }), /assurance.stepUpWindow must be positive/)
    })

    it("defaults twelve hours for aal2 and one day otherwise", () => {
      const config = configWith()
      assert.deepStrictEqual(resolveAssurancePolicy(config, {}), { maxAge: Duration.days(1) })
      assert.deepStrictEqual(resolveAssurancePolicy(config, { aal: "aal2" }), {
        aal: "aal2",
        maxAge: Duration.hours(12)
      })
    })
  })

  describe("availableFactors", () => {
    it.effect("is empty when nothing contributes to the seam", () =>
      Effect.map(availableFactors({}, userId), (names) => {
        assert.deepStrictEqual(names, [])
      })
    )

    it.effect("names the kinds that can sign in or serve as a second factor", () =>
      Effect.map(
        availableFactors(
          {
            list: () =>
              Effect.succeed([
                summary({ type: "passkey", signIn: true, secondFactor: true }),
                summary({ type: "totp", secondFactor: true }),
                // Neither: an enrolment in progress contributes no prompt.
                summary({ type: "half-enrolled" })
              ])
          },
          userId
        ),
        (names) => {
          assert.deepStrictEqual(names, ["passkey", "totp"])
        }
      )
    )

    it.effect("reports each kind once, in the order the contributors listed them", () =>
      Effect.map(
        availableFactors(
          {
            list: () =>
              Effect.succeed([
                summary({ type: "totp", secondFactor: true }),
                summary({ type: "passkey", secondFactor: true }),
                summary({ type: "totp", secondFactor: true })
              ])
          },
          userId
        ),
        (names) => {
          assert.deepStrictEqual(names, ["totp", "passkey"])
        }
      )
    )

    it.effect("carries no identifier, address or secret — kinds only", () =>
      Effect.map(
        availableFactors({ list: () => Effect.succeed([summary({ type: "passkey", secondFactor: true })]) }, userId),
        (names) => {
          assert.deepStrictEqual(names, ["passkey"])
        }
      )
    )
  })
})
