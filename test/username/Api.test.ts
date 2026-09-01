import { assert, describe, it } from "@effect/vitest"
import { Context, type Schema } from "effect"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../../src/http/Middleware.js"
import { UsernameApiGroup, usernamePrefix } from "../../src/username/Api.js"

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
  readonly success: ReadonlySet<Schema.Top>
  readonly annotations: Context.Context<never>
  readonly middlewares: ReadonlySet<Context.Key<unknown, unknown>>
}

const endpoints: Readonly<Record<string, EndpointView>> = UsernameApiGroup.endpoints

const endpoint = (name: string): EndpointView => {
  const found = Object.hasOwn(endpoints, name) ? endpoints[name] : undefined
  if (found === undefined) throw new Error(`no endpoint called ${name}`)
  return found
}

const identifiers = (name: string): ReadonlyArray<unknown> =>
  Array.from(endpoint(name).error, (schema) => schema.ast.annotations?.["identifier"])

describe("username/Api", () => {
  it("serves three endpoints under /auth/username, all of them POSTs", () => {
    assert.strictEqual(usernamePrefix, "/auth/username")
    assert.deepStrictEqual(Object.keys(endpoints).sort(), ["available", "set", "signIn"])
    for (const [name, one] of Object.entries(endpoints)) {
      assert.isTrue(one.path.startsWith(usernamePrefix), `${name} is served under the prefix`)
      // Every one of them either mints, writes or costs something; none is a
      // GET a link could carry.
      assert.strictEqual(one.method, "POST", `${name} is a POST`)
    }
  })

  it("requires a session only for choosing a name", () => {
    assert.isTrue(endpoint("set").middlewares.has(Authenticated))
    // Signing in cannot require a session, and the oracle is reachable by
    // somebody with no account at all — which is the point of it.
    assert.isFalse(endpoint("signIn").middlewares.has(Authenticated))
    assert.isFalse(endpoint("available").middlewares.has(Authenticated))
  })

  it("decides `set` against the row, at an assurance a stale cookie cannot reach", () => {
    // A username is a way into the account, so a snapshot written before the
    // last revocation may not answer for it...
    assert.isTrue(Context.get(endpoint("set").annotations, AuthoritativeSession))
    // ...and a stolen but stale cookie must not be enough to take somebody's
    // name, or to move one's own out of reach of a recovery flow.
    assert.deepStrictEqual(Context.get(endpoint("set").annotations, RequireAssurance), freshSession)
  })

  it("annotates nothing on the two endpoints no session reaches", () => {
    for (const name of ["signIn", "available"]) {
      assert.isUndefined(Context.get(endpoint(name).annotations, RequireAssurance), `${name} states no policy`)
      assert.isFalse(Context.get(endpoint(name).annotations, AuthoritativeSession), `${name} is not authoritative`)
    }
  })

  it("declares the origin guard and a limit on every unauthenticated POST", () => {
    for (const name of ["signIn", "available"]) {
      assert.include(identifiers(name), "effect-auth/OriginNotAllowed", `${name} declares the origin guard`)
      assert.include(identifiers(name), "effect-auth/RateLimited", `${name} declares a limit`)
    }
    // `set` is inside `Authenticated`, whose cookie transport already applies
    // the origin check, and it is not an endpoint anybody can drive anonymously.
    assert.notInclude(identifiers("set"), "effect-auth/OriginNotAllowed")
  })

  it("answers one thing for an unknown name, a wrong password and an account with no credential", () => {
    const declared = identifiers("signIn")
    assert.include(declared, "effect-auth/InvalidCredentials")
    // The shape of the name is never a sign-in failure: a name stored under an
    // earlier policy must still work, and a refusal in front of the password
    // verification would be a timing signal.
    assert.notInclude(declared, "effect-auth/username/UsernameInvalid")
    assert.notInclude(declared, "effect-auth/username/UsernameTaken")
  })

  it("keeps the two username refusals on the two endpoints that can raise them", () => {
    assert.include(identifiers("set"), "effect-auth/username/UsernameInvalid")
    assert.include(identifiers("set"), "effect-auth/username/UsernameTaken")
    // "Nobody has it and you still cannot have it" is a refusal, not `false`.
    assert.include(identifiers("available"), "effect-auth/username/UsernameInvalid")
    // Whether somebody holds it is the answer, never an error.
    assert.notInclude(identifiers("available"), "effect-auth/username/UsernameTaken")
  })

  it("answers the same two-status union /auth/sign-in/email does", () => {
    const statuses = Array.from(endpoint("signIn").success, (schema) => schema.ast.annotations?.["httpApiStatus"])
    // Two members, on two statuses: the 202 is what says a second factor is
    // owed, and it is what lets a client tell the two apart without parsing a
    // body. A challenge and a session are never the same response.
    assert.strictEqual(statuses.length, 2)
    assert.include(statuses, 202)
    assert.strictEqual(endpoint("set").success.size, 1)
  })

  it("names no secret in any schema it publishes", () => {
    // The OpenAPI gate, applied at the group: this plugin stores no secret at
    // all, and the day it does the snapshot must not learn about it.
    const rendered = JSON.stringify(
      Object.values(endpoints).map((one) => [
        Array.from(one.success, (schema) => schema.ast),
        Array.from(one.error, (schema) => schema.ast)
      ])
    )
    for (const secret of ["tokenHash", "passwordHash", "valueHash", "secretCiphertext", "codeHash"]) {
      assert.isFalse(rendered.includes(secret), `no ${secret} on the wire`)
    }
  })
})
