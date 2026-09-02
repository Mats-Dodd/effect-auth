/**
 * A deployment's own policy, seen from the OAuth callback.
 *
 * **Details**
 *
 * The callback is the one sign-in path with nowhere to put an error: the
 * browser arrived by a top-level navigation from the provider and has to leave
 * by one. So a refusal here is not a `403` — it is a redirect to the error URL
 * the flow was started with, carrying this library's classification
 * (`?error=policy_refused`) and, beside it, whichever rule the deployment named
 * (`&code=`). These tests pin both halves of that, and the two things a refusal
 * must not leave behind: a user row the policy declined to provision, and a
 * session for an account it has suspended.
 *
 * The block is sequential because its two policies are mutable sets a test
 * writes into, and because it shares one stubbed provider server.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Effect, Option, Redacted, Result } from "effect"
import type { AuthHooksService } from "../../src/domain/Hooks.js"
import { PolicyRefused } from "../../src/domain/Hooks.js"
import { SessionStore, UserStore } from "../../src/domain/Stores.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"
import { testName, uniqueEmail } from "../fixtures.js"

/** The origin this deployment is served from. */
const appOrigin = "https://app.example.com"

/** The addresses this deployment's policy will not provision an account for. */
const denied = new Set<string>()

/** The people it will not mint a session for any more. */
const suspended = new Set<string>()

/**
 * The policy itself.
 *
 * `beforeUserCreate` answers off `source.info` rather than off the candidate —
 * that is what the tagged source is for, and the rewritten name is how a test
 * sees that the hook, and not the flow's own defaulting, wrote the row.
 */
const hooks: AuthHooksService = {
  beforeUserCreate: ({ candidate, source }) =>
    source._tag !== "OAuth"
      ? Effect.succeed(candidate)
      : denied.has(source.info.email)
        ? Effect.fail(PolicyRefused.make({ code: "domain_not_allowed", detail: source.providerId }))
        : Effect.succeed({ ...candidate, name: `${source.providerId}:${source.info.id}` }),
  beforeSessionCreate: ({ user }) =>
    suspended.has(user.email) ? Effect.fail(PolicyRefused.make({ code: "account_suspended" })) : Effect.void
}

/**
 * One stubbed provider for the whole block, which is why the block is
 * sequential: a test that replaces a route is describing the server every one
 * of its siblings shares.
 */
const server = MockProvider.mockServer()

/** An address, and the provider subject that reports it. */
const someone = (label: string) => {
  const email = uniqueEmail(label)
  return { sub: email, email }
}

/**
 * Points the shared server at one identity and forgets what earlier tests asked
 * for.
 *
 * Every test gives its own, since the block shares one database and two tests
 * presenting the same subject would collide on the account's unique index
 * rather than testing anything.
 */
const wellBehaved = (identity: { readonly sub: string; readonly email: string }) =>
  Effect.sync(() => {
    server.clear()
    server.on(MockProvider.tokenUrl, () =>
      MockProvider.json({
        access_token: "provider-access-token",
        token_type: "bearer",
        expires_in: 3600,
        scope: "profile email"
      })
    )
    server.on(MockProvider.userInfoUrl, () =>
      MockProvider.json({
        sub: identity.sub,
        email: identity.email,
        email_verified: true,
        name: testName,
        picture: "https://cdn.test/ada.png"
      })
    )
  })

const provider = MockProvider.mockProvider()

const flowLayer = AuthTest.layerFlow({
  providers: [provider],
  fetch: server.fetch,
  baseUrl: appOrigin,
  hooks
})

/** Starts a flow and hands the callback the state it minted, as a browser would. */
const complete = Effect.fnUntraced(function* (errorCallbackURL?: string) {
  const flow = yield* OAuthFlow
  const started = yield* flow.start({
    providerId: provider.id,
    ...(errorCallbackURL === undefined ? {} : { errorCallbackURL })
  })
  return yield* flow.complete({
    providerId: provider.id,
    code: "authorization-code",
    state: Redacted.value(started.state)
  })
})

/** The same round trip, but asking for the failure rather than a redirect. */
const callback = Effect.fnUntraced(function* () {
  const flow = yield* OAuthFlow
  const started = yield* flow.start({ providerId: provider.id })
  return yield* Effect.result(
    flow.callback({
      providerId: provider.id,
      code: "authorization-code",
      state: Redacted.value(started.state)
    })
  )
})

describe.sequential("oauth/Hooks", () => {
  layer(flowLayer)((it) => {
    it.effect("provisions a first sign-in through the hook, which reads the verified profile", () =>
      Effect.gen(function* () {
        const identity = someone("oauth-hooks-new")
        yield* wellBehaved(identity)

        const outcome = yield* complete()

        assert.isTrue(Result.isSuccess(outcome))
        if (!Result.isSuccess(outcome)) return
        assert.isTrue(outcome.success.userCreated)
        // Written by the hook off `source.info`, not by the flow off the
        // identity — the flow's own default would have been the display name.
        assert.strictEqual(outcome.success.user.name, `${provider.id}:${identity.sub}`)
        assert.notStrictEqual(outcome.success.user.name, testName)
        assert.isNotNull(outcome.success.session)
      })
    )

    it.effect("sends the browser away with the policy's own code, and provisions nobody", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const identity = someone("oauth-hooks-denied")
        denied.add(identity.email)
        yield* wellBehaved(identity)

        const outcome = yield* complete("/sign-in")

        assert.isTrue(Result.isFailure(outcome))
        if (!Result.isFailure(outcome)) return
        // This library's classification, and the deployment's beside it.
        assert.strictEqual(outcome.failure.code, "policy_refused")
        assert.strictEqual(outcome.failure.error._tag, "PolicyRefused")
        const query = MockProvider.queryOf(outcome.failure.redirectTo)
        assert.strictEqual(query["error"], "policy_refused")
        assert.strictEqual(query["code"], "domain_not_allowed")
        // The error URL the flow was started with, not the base URL.
        assert.isTrue(outcome.failure.redirectTo.startsWith(`${appOrigin}/sign-in?`))

        // The refusal aborted the transaction that would have written the row.
        const found = yield* users.findByEmail(identity.email)
        assert.isTrue(Option.isNone(found))
      })
    )

    it.effect("hands the same refusal to a caller that asked for the error rather than a redirect", () =>
      Effect.gen(function* () {
        const identity = someone("oauth-hooks-denied-typed")
        denied.add(identity.email)
        yield* wellBehaved(identity)

        const result = yield* callback()

        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure._tag, "PolicyRefused")
        if (result.failure._tag !== "PolicyRefused") return
        assert.strictEqual(result.failure.code, "domain_not_allowed")
        assert.strictEqual(result.failure.detail, provider.id)
      })
    )

    it.effect("refuses a suspended account at the callback without minting a session for it", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const identity = someone("oauth-hooks-suspended")
        yield* wellBehaved(identity)

        // The account exists and signs in exactly once, before the policy
        // changes its mind about it.
        const first = yield* complete()
        assert.isTrue(Result.isSuccess(first))
        if (!Result.isSuccess(first)) return
        const user = first.success.user
        const held = yield* sessions.listByUserId(user.id)
        assert.strictEqual(held.length, 1)

        suspended.add(identity.email)
        // The same subject: an ordinary sign-in through an identity the store
        // already knows, which is the shape a ban has to catch.
        const second = yield* complete()

        assert.isTrue(Result.isFailure(second))
        if (!Result.isFailure(second)) return
        assert.strictEqual(second.failure.code, "policy_refused")
        const query = MockProvider.queryOf(second.failure.redirectTo)
        assert.strictEqual(query["error"], "policy_refused")
        assert.strictEqual(query["code"], "account_suspended")

        // The session the refused callback would have written is not there, and
        // the one from before it is untouched: a ban governs new sessions only.
        const after = yield* sessions.listByUserId(user.id)
        assert.deepStrictEqual(
          after.map((session) => session.id),
          held.map((session) => session.id)
        )
      })
    )
  })
})
