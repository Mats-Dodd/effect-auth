/**
 * The magic link plugin under a deployment's own policy hooks.
 *
 * **Details**
 *
 * Four claims. A link provisions through `Users.provision`, so
 * `beforeUserCreate` sees `{ _tag: "MagicLink" }` and its rewrite is what the
 * row ends up saying; a refusal leaves no user behind, and neither does an
 * `afterUserCreate` that fails, because the provisioning holds a transaction of
 * its own. `beforeSessionCreate` is asked after the token has been claimed, so
 * a banned account's link is spent and no session is minted. And the two entry
 * points report a refusal the way their shape demands: the browser endpoint
 * redirects with `?error=policy_refused&code=`, the JSON twin answers the typed
 * error with the deployment's code on it.
 *
 * **Gotchas — why these blocks build their own layers**
 *
 * `AuthHooks` is a reference the services that consult it read when they are
 * *built*, and this plugin is one of them: it is layered over a deployment
 * rather than inside it, so a hook set provided underneath `Auth.layer` alone
 * never reaches it. `MagicLinkTest.layer` and `MagicLinkTest.layerHttp` provide
 * `options.hooks` to the deployment only, so the composition below provides it
 * to both halves — which is exactly what a consumer's single `Layer.provide`
 * over `MagicLink.layer().pipe(Layer.provideMerge(AuthLive))` does.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Effect, Layer, Option, Redacted, Schema } from "effect"
import type { AuthHooksService } from "../../src/domain/Hooks.js"
import { layer as hooksLayer, PolicyRefused } from "../../src/domain/Hooks.js"
import { UserStore } from "../../src/domain/Stores.js"
import { handlers as magicLinkHandlers } from "../../src/magic-link/Handlers.js"
import { MagicLink } from "../../src/magic-link/MagicLink.js"
import { AuthTest, MagicLinkTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

/** A deployment whose plugin and whose domain services see the same hooks. */
const deployment = (hooks: AuthHooksService) =>
  MagicLinkTest.layerMagicLink().pipe(Layer.provide(hooksLayer(hooks)), Layer.provideMerge(AuthTest.layer({ hooks })))

/** {@link deployment}, with the endpoints in front of it. */
const httpDeployment = (hooks: AuthHooksService) =>
  AuthTest.layerHttpApi(
    MagicLinkTest.TestApi,
    { hooks },
    magicLinkHandlers(MagicLinkTest.TestApi).pipe(
      Layer.provide(MagicLinkTest.layerMagicLink().pipe(Layer.provide(hooksLayer(hooks))))
    )
  )

/** A browser addressing the block's deployment, with a jar the test can read. */
const makeClient = () => TestHttpClient.makeClient(MagicLinkTest.TestApi)

/** The token out of the most recent link mailed to an address. */
const linkToken = (email: string) =>
  Effect.flatMap(AuthTest.TestEmails, (emails) => emails.tokenFor(MagicLinkTest.magicLinkKind, email))

/** The schema's own runtime check, rather than a prototype test. */
const isPolicyRefused = Schema.is(PolicyRefused)

/**
 * The refusal a failure carries, failing the test when it is something else.
 *
 * A narrowing rather than a cast: every error channel here is a tagged union,
 * so the compiler is the one that decides `code` is readable.
 */
const refusal = (error: { readonly _tag: string }): PolicyRefused => {
  if (!isPolicyRefused(error)) {
    return assert.fail(`expected a PolicyRefused, got ${error._tag}`)
  }
  return error
}

describe.sequential("magic-link/Hooks", () => {
  layer(
    deployment({
      // The source is what this hook branches on: one policy covers every flow a
      // deployment serves, and only the magic link half is refused here.
      beforeUserCreate: ({ candidate, source }) =>
        source._tag === "MagicLink" && candidate.email.startsWith("refused-")
          ? Effect.fail(PolicyRefused.make({ code: "magic_link_not_allowed", detail: "no links for that address" }))
          : Effect.succeed({ ...candidate, name: `${candidate.name} (by link)` })
    })
  )("a policy that vets the accounts links create", (it) => {
    it.effect("refuses the account, and leaves no row behind", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("refused")
        const magic = yield* MagicLink
        const users = yield* UserStore

        yield* magic.request({ email })
        const refused = yield* Effect.flip(magic.verify({ token: yield* linkToken(email) }))

        assert.strictEqual(refusal(refused).code, "magic_link_not_allowed")
        // Nothing was written: the refusal happened before the insert, and the
        // transaction the provisioning holds would have taken it back anyway.
        assert.isTrue(Option.isNone(yield* users.findByEmail(email)))
      })
    )

    it.effect("writes the rewrite the hook made onto the account it creates", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("rewritten")
        const magic = yield* MagicLink
        const users = yield* UserStore

        yield* magic.request({ email, name: "Ada" })
        const verified = yield* magic.verify({ token: yield* linkToken(email) })

        // The name the request asked for, as the hook rewrote it — and the same
        // string in the row, so the rewrite was stored and not merely returned.
        assert.strictEqual(verified.user.name, "Ada (by link)")
        const stored = yield* users.findByEmail(email)
        assert.isTrue(Option.isSome(stored))
        assert.strictEqual(Option.isSome(stored) ? stored.value.name : undefined, "Ada (by link)")
        // And the link still did its job: a session, on a verified address.
        assert.strictEqual(verified.session.userId, verified.user.id)
        assert.isTrue(verified.user.emailVerified)
      })
    )
  })

  layer(
    deployment({
      // The related row a tenant-shaped deployment writes beside the user, here
      // standing in for one that cannot be written.
      afterUserCreate: () => Effect.fail(PolicyRefused.make({ code: "tenant_unavailable" }))
    })
  )("a policy whose after-hook fails", (it) => {
    it.effect("leaves no user row when the related write is refused", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("aborted")
        const magic = yield* MagicLink
        const users = yield* UserStore

        yield* magic.request({ email })
        const refused = yield* Effect.flip(magic.verify({ token: yield* linkToken(email) }))

        assert.strictEqual(refused._tag, "PolicyRefused")
        // The provisioning holds a transaction of its own precisely for this:
        // an `afterUserCreate` that cannot write takes the user down with it,
        // exactly as it does on the password and OAuth sources.
        assert.isTrue(Option.isNone(yield* users.findByEmail(email)))
      })
    )
  })

  layer(
    httpDeployment({
      beforeUserCreate: ({ candidate }) =>
        candidate.email.startsWith("http-refused-")
          ? Effect.fail(PolicyRefused.make({ code: "domain_not_allowed" }))
          : Effect.succeed(candidate),
      beforeSessionCreate: ({ user }) =>
        user.email.startsWith("banned-") ? Effect.fail(PolicyRefused.make({ code: "account_suspended" })) : Effect.void
    })
  )("the endpoints under a policy", (it) => {
    it.effect("redirects a refused link to its own error page with the hook's code", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-refused")
        const { client, cookies } = yield* makeClient()
        const users = yield* UserStore

        // The link's own error page, exactly as an expired token's would be: the
        // payload carrying it is claimed before either hook is asked, so the URL
        // is in hand when the refusal arrives and a policy does not silently
        // drop the page every other failure of this link lands on. `?error=` is
        // this library's classification and `&code=` the deployment's own.
        yield* client.magicLink.signIn({ payload: { email, errorCallbackURL: "/oops" } })
        const [, response] = yield* client.magicLink.verify({
          query: { token: Redacted.value(yield* linkToken(email)) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(
          response.headers["location"],
          `${AuthTest.testBaseUrl}/oops?error=policy_refused&code=domain_not_allowed`
        )
        // No account, and no session cookie to go with it.
        assert.isTrue(Option.isNone(yield* users.findByEmail(email)))
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
        assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCookie(cookies)))
      })
    )

    it.effect("refuses a banned account's link without minting a session", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("banned")
        const { client, cookies } = yield* makeClient()

        // The account exists and is somebody's: the ban is on the session, not
        // on the person's right to have a row.
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })

        yield* client.magicLink.signIn({ payload: { email } })
        const [, response] = yield* client.magicLink.verify({
          query: { token: Redacted.value(yield* linkToken(email)) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(
          response.headers["location"],
          `${AuthTest.testBaseUrl}/?error=policy_refused&code=account_suspended`
        )
        // Nothing was signed in: no cookie on the redirect, and none in the jar.
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
        assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCookie(cookies)))
        const unauthorized = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(unauthorized._tag, "Unauthorized")
      })
    )

    it.effect("answers the JSON twin with the typed refusal", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("banned")
        const { client } = yield* makeClient()

        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        yield* client.magicLink.signIn({ payload: { email } })
        const token = yield* linkToken(email)

        const refused = yield* Effect.flip(client.magicLink.exchange({ payload: { token } }))

        // A caller that reads bodies gets the error itself, carrying the code
        // the deployment wrote — not a redirect, and not an opaque 500.
        assert.strictEqual(refusal(refused).code, "account_suspended")
      })
    )

    it.effect("burns the refused link, so it cannot be tried again", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("banned")
        const { client } = yield* makeClient()

        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        yield* client.magicLink.signIn({ payload: { email } })
        const token = yield* linkToken(email)

        const first = yield* Effect.flip(client.magicLink.exchange({ payload: { token } }))
        assert.strictEqual(first._tag, "PolicyRefused")

        // The hook is asked after the claim, so the token is spent whichever way
        // it answered: a policy that is relaxed a minute later does not make an
        // old link live again.
        const second = yield* Effect.flip(client.magicLink.exchange({ payload: { token } }))
        assert.strictEqual(second._tag, "InvalidToken")
      })
    )
  })
})
