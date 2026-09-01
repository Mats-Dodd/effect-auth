import { assert, describe, it } from "@effect/vitest"
import { Context, type Schema } from "effect"
import { Authenticated, AuthoritativeSession, RequireAssurance } from "../../src/http/Middleware.js"
import { PasskeysApiGroup, passkeysPrefix } from "../../src/passkeys/Api.js"

/**
 * The part of an endpoint these assertions read, keyed by identifier — the same
 * view `test/http-api/AuthApi.test.ts` takes, and for the same reason:
 * `HttpApiEndpoint.Top` fixes `"~Request"` to a shape a concrete endpoint is not
 * assignable to.
 */
interface EndpointView {
  readonly method: string
  readonly path: string
  readonly error: ReadonlySet<Schema.Top>
  readonly annotations: Context.Context<never>
  readonly middlewares: ReadonlySet<Context.Key<unknown, unknown>>
}

const endpoints: Readonly<Record<string, EndpointView>> = PasskeysApiGroup.endpoints

const endpoint = (name: string): EndpointView => {
  const found = Object.hasOwn(endpoints, name) ? endpoints[name] : undefined
  if (found === undefined) throw new Error(`no endpoint called ${name}`)
  return found
}

/** Every endpoint that adds or removes a way into the account. */
const guarded = ["registerOptions", "registerVerify", "deletePasskey"]
/** Every endpoint that must decide against the row rather than a snapshot. */
const authoritative = [...guarded, "renamePasskey"]
/** The two halves of a sign-in: a passkey *is* the credential. */
const unauthenticated = ["authenticateOptions", "authenticateVerify"]

describe("passkeys/Api", () => {
  it("serves seven endpoints under /auth/passkeys", () => {
    assert.strictEqual(passkeysPrefix, "/auth/passkeys")
    assert.deepStrictEqual(Object.keys(endpoints).sort(), [
      "authenticateOptions",
      "authenticateVerify",
      "deletePasskey",
      "listPasskeys",
      "registerOptions",
      "registerVerify",
      "renamePasskey"
    ])
    for (const [name, one] of Object.entries(endpoints)) {
      assert.isTrue(one.path.startsWith(passkeysPrefix), `${name} is served under the prefix`)
    }
  })

  it("guards every endpoint that adds or removes a way into the account", () => {
    for (const name of guarded) {
      assert.deepStrictEqual(
        Context.get(endpoint(name).annotations, RequireAssurance),
        {},
        `${name} carries the empty policy, which resolves to session.freshAge`
      )
    }
  })

  it("leaves the reading and renaming endpoints unguarded by assurance", () => {
    assert.isUndefined(Context.get(endpoint("listPasskeys").annotations, RequireAssurance))
    assert.isUndefined(Context.get(endpoint("renamePasskey").annotations, RequireAssurance))
  })

  it("decides against the row on every endpoint that changes a credential", () => {
    for (const name of authoritative) {
      assert.isTrue(Context.get(endpoint(name).annotations, AuthoritativeSession), `${name} is authoritative`)
    }
  })

  it("requires a session everywhere except the two halves of a sign-in", () => {
    const actual = Object.keys(endpoints).filter((name) => endpoint(name).middlewares.has(Authenticated))
    assert.deepStrictEqual(
      actual.sort(),
      Object.keys(endpoints)
        .filter((name) => !unauthenticated.includes(name))
        .sort()
    )
  })

  it("declares the two ceremony failures where they can happen", () => {
    const identifiers = (name: string) =>
      Array.from(endpoint(name).error, (schema) => schema.ast.annotations?.["identifier"])

    for (const name of ["registerVerify", "authenticateVerify"]) {
      const declared = identifiers(name)
      assert.include(declared, "effect-auth/passkeys/ChallengeExpired")
      assert.include(declared, "effect-auth/passkeys/PasskeyVerificationFailed")
    }
    // The options endpoints cannot fail either way: nothing is presented yet.
    assert.notInclude(identifiers("registerOptions"), "effect-auth/passkeys/PasskeyVerificationFailed")
    // An unauthenticated POST that writes a row declares the origin guard.
    assert.include(identifiers("authenticateOptions"), "effect-auth/OriginNotAllowed")
  })
})
