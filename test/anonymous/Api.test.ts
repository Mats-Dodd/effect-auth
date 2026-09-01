import { assert, describe, it } from "@effect/vitest"
import { Context, type Schema } from "effect"
import { AnonymousApiGroup, anonymousPrefix } from "../../src/anonymous/Api.js"
import { identifiedPolicy } from "../../src/anonymous/Anonymous.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../../src/http/Middleware.js"

/** The part of an endpoint these assertions read. See `test/username/Api.test.ts`. */
interface EndpointView {
  readonly method: string
  readonly path: string
  readonly error: ReadonlySet<Schema.Top>
  readonly success: ReadonlySet<Schema.Top>
  /** The decoded request's fields, keyed by name — empty for a body-less POST. */
  readonly payload: ReadonlyMap<unknown, unknown>
  readonly annotations: Context.Context<never>
  readonly middlewares: ReadonlySet<Context.Key<unknown, unknown>>
}

const endpoints: Readonly<Record<string, EndpointView>> = AnonymousApiGroup.endpoints

const endpoint = (name: string): EndpointView => {
  const found = Object.hasOwn(endpoints, name) ? endpoints[name] : undefined
  if (found === undefined) throw new Error(`no endpoint called ${name}`)
  return found
}

const identifiers = (name: string): ReadonlyArray<unknown> =>
  Array.from(endpoint(name).error, (schema) => schema.ast.annotations?.["identifier"])

describe("anonymous/Api", () => {
  it("serves two endpoints under /auth/anonymous", () => {
    assert.strictEqual(anonymousPrefix, "/auth/anonymous")
    assert.deepStrictEqual(Object.keys(endpoints).sort(), ["delete", "signIn"])
    for (const [name, one] of Object.entries(endpoints)) {
      assert.isTrue(one.path.startsWith(anonymousPrefix), `${name} is served under the prefix`)
      assert.strictEqual(one.method, "POST", `${name} is a POST`)
    }
  })

  it("takes no body to become nobody", () => {
    // The endpoint that writes two rows for a caller who has proved nothing
    // reads nothing from them either: there is no field a request could carry
    // that would name somebody, which is what closes better-auth's
    // `anonymousUserId` injection.
    assert.strictEqual(endpoint("signIn").payload.size, 0)
  })

  it("requires a session to discard one, and none to acquire one", () => {
    assert.isFalse(endpoint("signIn").middlewares.has(Authenticated))
    assert.isTrue(endpoint("delete").middlewares.has(Authenticated))
  })

  it("decides `delete` against the row, at a level an anonymous visitor can reach", () => {
    // "Is this account still anonymous" is a question a cookie-cache snapshot
    // cannot answer: it was written before whatever adopted it.
    assert.isTrue(Context.get(endpoint("delete").annotations, AuthoritativeSession))
    // The empty policy, which resolves to session.freshAge and states no level
    // — an aal0 visitor must be able to throw themselves away.
    assert.deepStrictEqual(Context.get(endpoint("delete").annotations, RequireAssurance), freshSession)
    assert.isUndefined(freshSession.aal)
    // And it is deliberately not the policy that excludes them.
    assert.notDeepEqual(Context.get(endpoint("delete").annotations, RequireAssurance), identifiedPolicy)
  })

  it("guards the unauthenticated POST that invents a person", () => {
    const declared = identifiers("signIn")
    // A cross-origin form post reaches it with no cookie at all, so the
    // middleware's own origin check never sees it.
    assert.include(declared, "effect-auth/OriginNotAllowed")
    // Each call writes a users row, a marker row and a session row.
    assert.include(declared, "effect-auth/RateLimited")
    // A deployment's own hook may decline to invent anybody.
    assert.include(declared, "effect-auth/PolicyRefused")
  })

  it("refuses to destroy a real account rather than doing it quietly", () => {
    // Deleting an adopted account is `/auth/delete-user`'s job, with the
    // confirmation that endpoint requires.
    assert.deepStrictEqual(identifiers("delete"), ["effect-auth/anonymous/NotAnonymous"])
  })

  it("names no secret in any schema it publishes", () => {
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
