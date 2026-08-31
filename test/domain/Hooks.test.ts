/**
 * The hook kernel: how two hook sets compose, how a plugin adds to a set it
 * cannot see, and what `Users.provision` does with whatever it is handed.
 *
 * **Details**
 *
 * Most of this file needs no deployment at all — `combine`, `layer` and
 * `append` are ordinary values over an ordinary `Context.Reference`, and the
 * composition rules they encode (chain left to right, first refusal wins, an
 * appended set never shadows the one already installed) are the whole contract
 * a plugin author writes against.
 *
 * The `Layer.updateService` block below is a *checkpoint* rather than a
 * behavioural test: `append` is built on reading a reference from the context a
 * layer is being built in, and if that did not resolve the reference's default
 * when nothing provided one, appending to a deployment with no hooks would
 * silently do nothing. It is asserted here so that a change in `effect` breaks a
 * test rather than a deployment.
 */
import { assert, describe, it, layer } from "@effect/vitest"
import { Context, Effect, Layer, Option, Redacted } from "effect"
import type { OAuthIdentity } from "../../src/domain/Accounts.js"
import { Accounts } from "../../src/domain/Accounts.js"
import type { AuthHooksService, ProvisionSource } from "../../src/domain/Hooks.js"
import { append, AuthHooks, combine, hooksOf, layer as hooksLayer, PolicyRefused } from "../../src/domain/Hooks.js"
import { Passwords } from "../../src/domain/Passwords.js"
import type { UserInsertOf } from "../../src/domain/Schema.js"
import { baseUserModel, oauthIssuer } from "../../src/domain/Schema.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { Users } from "../../src/domain/Users.js"
import { MagicLink } from "../../src/magic-link/MagicLink.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, MagicLinkTest, MockProvider, TestEmails } from "../../src/testing/index.js"
import { expectSome, newPassword, testName, testPassword, uniqueEmail } from "../fixtures.js"

/** The source every test here provisions with, unless it is testing the source. */
const testSource: ProvisionSource = { _tag: "Plugin", plugin: "test" }

/** A candidate row, built the way every provisioning flow builds one. */
const candidateFor = (email: string): Effect.Effect<UserInsertOf<{}>> =>
  baseUserModel.makeInsert({ name: testName, email, emailVerified: false, image: null })

/**
 * A hook set that appends `label` to `trace` and lets the operation through.
 *
 * `beforeUserCreate` also rewrites the name, so a chain's *order* is readable
 * off the row it produced and not only off the trace it left.
 */
const recording = (trace: Array<string>, label: string): AuthHooksService => ({
  beforeUserCreate: ({ candidate }) =>
    Effect.sync(() => {
      trace.push(`before:${label}`)
      return { ...candidate, name: `${candidate.name}/${label}` }
    }),
  afterUserCreate: () => Effect.sync(() => void trace.push(`after:${label}`)),
  beforeUserDelete: () => Effect.sync(() => void trace.push(`delete:${label}`))
})

/** A hook set that refuses everything, naming itself in the code. */
const refusing = (trace: Array<string>, label: string): AuthHooksService => ({
  beforeUserCreate: () =>
    Effect.suspend(() => {
      trace.push(`before:${label}`)
      return Effect.fail(new PolicyRefused({ code: label }))
    }),
  beforeUserDelete: () =>
    Effect.suspend(() => {
      trace.push(`delete:${label}`)
      return Effect.fail(new PolicyRefused({ code: label }))
    })
})

/** The hooks a layer built under a given composition actually ends up with. */
class Installed extends Context.Service<Installed, AuthHooksService>()("test/InstalledHooks") {}

/**
 * A layer that copies whatever `AuthHooks` resolves to at *build* time — which
 * is exactly how the domain services read it.
 */
const installed: Layer.Layer<Installed> = Layer.effect(Installed, AuthHooks)

/** Builds `composition` and answers the hook set it left in the reference. */
const resolve = (composition: Layer.Layer<never>): Effect.Effect<AuthHooksService> =>
  Effect.provide(Effect.map(Installed, (hooks): AuthHooksService => hooks), installed.pipe(Layer.provide(composition)))

/** Unwraps an optional hook member, failing the test when the composition dropped it. */
const declared = <A>(member: A | undefined, name: string): Effect.Effect<A> =>
  member === undefined ? Effect.sync(() => assert.fail(`the composed set should declare ${name}`)) : Effect.succeed(member)

/** The `beforeUserCreate` of a composed set, which the composition must have declared. */
const beforeCreateOf = (hooks: AuthHooksService) => declared(hooks.beforeUserCreate, "beforeUserCreate")

describe("domain/Hooks", () => {
  // ---------------------------------------------------------------------------
  // combine
  // ---------------------------------------------------------------------------

  it("leaves a member absent when neither side declared it", () => {
    assert.deepStrictEqual(combine({}, {}), {})
    // `{}` is the reference's default, so it has to be a true identity: a
    // combined set that answered with six no-op functions would turn "nobody
    // installed a hook" into "somebody installed a hook that does nothing".
    const only: AuthHooksService = { beforeUserDelete: () => Effect.void }
    assert.strictEqual(combine(only, {}).beforeUserDelete, only.beforeUserDelete)
    assert.strictEqual(combine({}, only).beforeUserDelete, only.beforeUserDelete)
    assert.isUndefined(combine(only, {}).beforeUserCreate)
  })

  it.effect("chains beforeUserCreate left to right, each seeing the previous rewrite", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const combined = combine(recording(trace, "one"), recording(trace, "two"))
      const candidate = yield* candidateFor("chain@example.com")

      const beforeCreate = yield* beforeCreateOf(combined)
      const rewritten = yield* beforeCreate({ candidate, source: testSource })

      assert.deepStrictEqual(trace, ["before:one", "before:two"])
      // The second hook was handed what the first answered with, not the
      // original: the suffixes are in the order the hooks ran.
      assert.strictEqual(rewritten.name, `${testName}/one/two`)
    }))

  it.effect("sequences afterUserCreate and the veto members in the same order", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const combined = combine(recording(trace, "one"), recording(trace, "two"))
      const user = yield* baseUserModel.decodeRow({
        id: "0193f6f0-0000-7000-8000-0000000000aa",
        name: testName,
        email: "sequence@example.com",
        emailVerified: false,
        image: null,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z"
      })

      const after = yield* declared(combined.afterUserCreate, "afterUserCreate")
      const beforeDelete = yield* declared(combined.beforeUserDelete, "beforeUserDelete")
      yield* after({ user, source: testSource })
      yield* beforeDelete({ user })

      assert.deepStrictEqual(trace, ["after:one", "after:two", "delete:one", "delete:two"])
    }))

  it.effect("stops at the first refusal, whichever side it came from", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const candidate = yield* candidateFor("refused@example.com")

      const firstRefuses = yield* beforeCreateOf(combine(refusing(trace, "one"), recording(trace, "two")))
      const refused = yield* Effect.flip(firstRefuses({ candidate, source: testSource }))
      assert.strictEqual(refused._tag, "PolicyRefused")
      assert.strictEqual(refused.code, "one")
      // The second hook never ran: a refusal is the end of the chain, so a
      // policy after a refusing one cannot undo it or observe the attempt.
      assert.deepStrictEqual(trace, ["before:one"])

      trace.length = 0
      const secondRefuses = yield* beforeCreateOf(combine(recording(trace, "one"), refusing(trace, "two")))
      const later = yield* Effect.flip(secondRefuses({ candidate, source: testSource }))
      assert.strictEqual(later.code, "two")
      assert.deepStrictEqual(trace, ["before:one", "before:two"])
    }))

  // ---------------------------------------------------------------------------
  // layer / append — the checkpoint
  // ---------------------------------------------------------------------------

  it.effect("resolves to no hooks at all when nothing provided any", () =>
    Effect.gen(function*() {
      assert.deepStrictEqual(yield* resolve(Layer.empty), {})
    }))

  it.effect("applies Layer.updateService over the reference's own default", () =>
    Effect.gen(function*() {
      // The checkpoint `hooks.md` calls for. `append` is `updateService`'s own
      // definition written out, so what is asserted here is the property both
      // depend on: the function is handed the *default* when nothing in the
      // context provided the reference, rather than being skipped entirely.
      const trace: Array<string> = []
      const updated = Layer.updateService(installed, AuthHooks, (hooks) => combine(hooks, recording(trace, "only")))
      const hooks = yield* Effect.provide(Effect.map(Installed, (h): AuthHooksService => h), updated)

      const beforeCreate = yield* beforeCreateOf(hooks)
      const rewritten = yield* beforeCreate({ candidate: yield* candidateFor("default@example.com"), source: testSource })
      assert.strictEqual(rewritten.name, `${testName}/only`)
      assert.deepStrictEqual(trace, ["before:only"])
    }))

  it.effect("appends over the default, so a plugin needs no consumer set to exist", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const beforeCreate = yield* beforeCreateOf(yield* resolve(append(recording(trace, "plugin"))))

      const rewritten = yield* beforeCreate({
        candidate: yield* candidateFor("append-default@example.com"),
        source: testSource
      })
      assert.strictEqual(rewritten.name, `${testName}/plugin`)
      assert.deepStrictEqual(trace, ["before:plugin"])
    }))

  it.effect("appends after a consumer's set rather than shadowing it", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      // The composition a deployment writes: the application's set is provided
      // underneath the plugin's, so the plugin reads it and adds to it.
      const hooks = yield* resolve(
        append(recording(trace, "plugin")).pipe(Layer.provide(hooksLayer(recording(trace, "app"))))
      )

      const beforeCreate = yield* beforeCreateOf(hooks)
      const rewritten = yield* beforeCreate({
        candidate: yield* candidateFor("append-over@example.com"),
        source: testSource
      })
      assert.strictEqual(rewritten.name, `${testName}/app/plugin`)
      assert.deepStrictEqual(trace, ["before:app", "before:plugin"])
    }))

  it.effect("lets the application's refusal short-circuit an appended plugin", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const hooks = yield* resolve(
        append(recording(trace, "plugin")).pipe(Layer.provide(hooksLayer(refusing(trace, "app"))))
      )

      const beforeCreate = yield* beforeCreateOf(hooks)
      const refused = yield* Effect.flip(
        beforeCreate({ candidate: yield* candidateFor("append-refused@example.com"), source: testSource })
      )
      assert.strictEqual(refused.code, "app")
      assert.deepStrictEqual(trace, ["before:app"])
    }))

  it.effect("gives the typed view the same slot as the base reference", () =>
    Effect.gen(function*() {
      // A typed view is the same key with a narrower shape, so a set installed
      // through it is the set core reads back through the base one.
      const typed = hooksOf(baseUserModel)
      const hooks = yield* resolve(Layer.succeed(typed)({ beforeUserDelete: () => Effect.void }))
      assert.isDefined(hooks.beforeUserDelete)
    }))
})

// -----------------------------------------------------------------------------
// The choke point
// -----------------------------------------------------------------------------

/** A hook set that refuses the addresses a test marked, and rewrites the rest. */
const provisionHooks: AuthHooksService = {
  beforeUserCreate: ({ candidate, source }) =>
    candidate.email.includes("refused")
      ? Effect.fail(new PolicyRefused({ code: "not_welcome", detail: source._tag }))
      : Effect.succeed({ ...candidate, name: "Rewritten", emailVerified: true })
}

layer(AuthTest.layer())("domain/Hooks — provision", (it) => {
  it.effect("writes the candidate through unchanged when no hook is installed", () =>
    Effect.gen(function*() {
      const users = yield* Users
      const email = uniqueEmail("provision-plain")
      const candidate = yield* candidateFor(email)

      const user = yield* users.provision({ candidate, source: testSource })

      assert.strictEqual(user.email, email)
      assert.strictEqual(user.name, testName)
      // The id is the caller's: it was generated before this was called, so the
      // flow that is about to write related rows already knows it.
      assert.strictEqual(user.id, candidate.id)
    }))

  it.layer(AuthTest.layer({ hooks: provisionHooks }))("with beforeUserCreate installed", (it) => {
    it.effect("stores what the hook rewrote, re-validated by the model", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("provision-rewrite")

        const user = yield* users.provision({ candidate: yield* candidateFor(email), source: testSource })

        assert.strictEqual(user.name, "Rewritten")
        assert.isTrue(user.emailVerified)
        // The row that was written, not the value the hook answered with.
        const stored = yield* expectSome(yield* store.findById(user.id), "the provisioned row")
        assert.strictEqual(stored.name, "Rewritten")
      }))

    it.effect("refuses, and writes no row", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("provision-refused")

        const refused = yield* Effect.flip(
          users.provision({ candidate: yield* candidateFor(email), source: testSource })
        )
        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") {
          assert.strictEqual(refused.code, "not_welcome")
          // The source reaches the hook, which is what lets one policy cover
          // every flow that provisions a person.
          assert.strictEqual(refused.detail, "Plugin")
        }

        assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
      }))
  })
})

// -----------------------------------------------------------------------------
// The password source
// -----------------------------------------------------------------------------

/**
 * A hook set the password flows are exercised against, keyed off the label a
 * test built its address with.
 *
 * **Gotchas**
 *
 * One set rather than one per case: the deployment is built once per `it.layer`
 * block and shared by every test inside it, so a hook that answered differently
 * per test would have to be mutable — and then the tests could not run beside
 * each other. Branching on the address is what keeps them independent.
 */
const passwordHooks: AuthHooksService = {
  beforeUserCreate: ({ candidate, source }) =>
    candidate.email.includes("veto")
      ? Effect.fail(new PolicyRefused({ code: "not_welcome", detail: source._tag }))
      : Effect.succeed({
        ...candidate,
        name: `${candidate.name} (${source._tag})`,
        // A policy that rewrites the *address* — moving a sign-up onto a
        // canonical domain is the real shape of this — and does not normalize
        // what it wrote. Normalizing is the library's job: see the test below
        // for what a row stored in the hook's own casing would cost.
        ...(candidate.email.includes("recase") ? { email: candidate.email.toUpperCase() } : {})
      }),
  afterUserCreate: ({ user }) =>
    user.email.includes("after-fails")
      ? Effect.fail(new PolicyRefused({ code: "related_row_refused" }))
      : Effect.void,
  beforeSessionCreate: ({ user }) =>
    user.email.includes("banned")
      ? Effect.fail(new PolicyRefused({ code: "banned" }))
      : Effect.void
}

layer(AuthTest.layer({ hooks: passwordHooks }))("domain/Hooks — password source", (it) => {
  it.effect("rewrites the row a sign-up creates, and says where it came from", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const store = yield* UserStore
      const email = uniqueEmail("hooks-password-rewrite")

      const { user } = yield* passwords.signUp({ name: testName, email, password: testPassword })

      // The source a password sign-up reports, seen by the hook and written
      // into the row it answered with.
      assert.strictEqual(user.name, `${testName} (EmailPassword)`)
      const stored = yield* expectSome(yield* store.findByEmail(email), "the registered row")
      assert.strictEqual(stored.name, `${testName} (EmailPassword)`)
    }))

  it.effect("normalizes an address a hook rewrote, so the account is still reachable", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const store = yield* UserStore
      const email = uniqueEmail("hooks-password-recase")

      const { user } = yield* passwords.signUp({ name: testName, email, password: testPassword })

      // The address is stored normalized whatever casing the hook answered
      // with — `email` is a plain string in the schema, so nothing else would
      // have caught this.
      assert.strictEqual(user.email, email)
      assert.isTrue(Option.isSome(yield* store.findByEmail(email)))

      // And the consequence that makes it matter: every read of a user by
      // address goes through `normalizeEmail`, so a row stored as the hook
      // typed it would be one no sign-in, no reset and no link could ever find
      // again — while a second sign-up for the same mailbox would sail past
      // both the duplicate check and the unique index.
      const signedIn = yield* passwords.signIn({ email, password: testPassword })
      assert.strictEqual(signedIn.user.id, user.id)
      const duplicate = yield* Effect.flip(
        passwords.signUp({ name: testName, email, password: testPassword })
      )
      assert.strictEqual(duplicate._tag, "UserAlreadyExists")
    }))

  it.effect("refuses a sign-up the policy rejects, leaving no user and no credential", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const store = yield* UserStore
      const email = uniqueEmail("hooks-password-veto")

      const refused = yield* Effect.flip(
        passwords.signUp({ name: testName, email, password: testPassword })
      )
      assert.strictEqual(refused._tag, "PolicyRefused")
      if (refused._tag === "PolicyRefused") {
        assert.strictEqual(refused.code, "not_welcome")
        assert.strictEqual(refused.detail, "EmailPassword")
      }

      // Nothing was written: the hook runs inside the sign-up's transaction,
      // ahead of the row it would have created.
      assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
    }))

  it.effect("leaves no user row behind when afterUserCreate fails", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const store = yield* UserStore
      const email = uniqueEmail("hooks-password-after-fails")

      const refused = yield* Effect.flip(
        passwords.signUp({ name: testName, email, password: testPassword })
      )
      assert.strictEqual(refused._tag, "PolicyRefused")

      // The row existed when the hook ran — that is the whole point of
      // `afterUserCreate` — and the transaction took it away again. A
      // half-provisioned account, a user with no credential to sign in with,
      // is what this is here to rule out.
      assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
    }))

  it.effect("succeeds with no session when the policy refuses the auto sign-in", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const store = yield* UserStore
      const email = uniqueEmail("hooks-password-banned")

      const result = yield* passwords.signUp({ name: testName, email, password: testPassword })

      // Pinned semantics: the account was accepted and committed before the
      // session was asked about, so a refusal answers the shape a deployment
      // that withholds a session already answers — not a failed registration.
      assert.isTrue(Option.isNone(result.session))
      assert.strictEqual(result.user.email, email)
      assert.isTrue(Option.isSome(yield* store.findByEmail(email)))
    }))
})

// The counter belongs to the hashing layer and the layer is built once for the
// block, so this must not run beside anything else that hashes.
describe.sequential("domain/Hooks — beforeSessionCreate (timing defence)", () => {
  const hasher = AuthTest.countingHasher()

  it.layer(AuthTest.layer({ hasher: hasher.layer, hooks: passwordHooks }))((it) => {
    it.effect("refuses a banned user only after verifying their password once", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const email = uniqueEmail("banned")
        yield* passwords.signUp({ name: testName, email, password: testPassword })

        const before = hasher.state.verifies
        const refused = yield* Effect.flip(passwords.signIn({ email, password: testPassword }))
        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") assert.strictEqual(refused.code, "banned")
        // Exactly one, and it happened: the hook is consulted after the
        // constant-cost verification rather than in place of it, so a suspended
        // account costs what an ordinary one costs and a wrong password against
        // a suspended account is still `InvalidCredentials`.
        assert.strictEqual(hasher.state.verifies - before, 1)

        const wrong = hasher.state.verifies
        const invalid = yield* Effect.flip(passwords.signIn({ email, password: newPassword }))
        assert.strictEqual(invalid._tag, "InvalidCredentials")
        assert.strictEqual(hasher.state.verifies - wrong, 1)
      }))
  })
})

// -----------------------------------------------------------------------------
// The OAuth source
// -----------------------------------------------------------------------------

/** What a provider hands back, with a subject no other test will claim. */
const oauthIdentity = (email: string): OAuthIdentity => ({
  providerId: "github",
  issuer: oauthIssuer("github"),
  accountId: `gh-${globalThis.crypto.randomUUID()}`,
  email,
  emailVerified: true,
  name: testName
})

/** A hook set the OAuth flows are exercised against. */
const oauthHooks: AuthHooksService = {
  beforeUserCreate: ({ candidate, source }) =>
    Effect.succeed({
      ...candidate,
      // The whole point of the tagged source: one hook, every provider, and the
      // verified profile to read a role or a plan off.
      name: source._tag === "OAuth" ? `${source.providerId}:${source.info.id}` : candidate.name
    }),
  beforeAccountLink: ({ info, providerId, user }) =>
    user.email.includes("no-link")
      ? Effect.fail(new PolicyRefused({ code: "linking_disabled", detail: `${providerId}:${info.id}` }))
      : Effect.void
}

layer(AuthTest.layer({ hooks: oauthHooks, trustedProviders: ["github"] }))("domain/Hooks — OAuth source", (it) => {
  it.effect("provisions a first-time identity through the hook, which sees the profile", () =>
    Effect.gen(function*() {
      const accounts = yield* Accounts
      const identity = oauthIdentity(uniqueEmail("hooks-oauth-new"))

      const result = yield* accounts.linkOAuth(identity)

      assert.isTrue(result.userCreated)
      assert.strictEqual(result.user.name, `github:${identity.accountId}`)
    }))

  it.effect("refuses to attach an identity to an existing user when the policy says not to", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const accounts = yield* Accounts
      const store = yield* AccountStore
      const email = uniqueEmail("hooks-oauth-no-link")
      const { user } = yield* passwords.signUp({ name: testName, email, password: testPassword })

      const identity = oauthIdentity(email)
      const refused = yield* Effect.flip(accounts.linkOAuth(identity))

      assert.strictEqual(refused._tag, "PolicyRefused")
      if (refused._tag === "PolicyRefused") {
        assert.strictEqual(refused.code, "linking_disabled")
        assert.strictEqual(refused.detail, `github:${identity.accountId}`)
      }
      // The refusal is the reason there is no second sign-in method: only the
      // credential the sign-up wrote.
      const held = yield* store.listByUserId(user.id)
      assert.deepStrictEqual(held.map((account) => account.providerId), ["credential"])
    }))

  it.effect("refuses the same link asked for deliberately, and allows one it does not object to", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const accounts = yield* Accounts
      const refusedEmail = uniqueEmail("hooks-oauth-no-link")
      const { user: refusedUser } = yield* passwords.signUp({
        name: testName,
        email: refusedEmail,
        password: testPassword
      })

      // `linkSocial`: the person proved they hold both sides, and the policy
      // still gets to say no.
      const refused = yield* Effect.flip(
        accounts.linkToUser(refusedUser.id, oauthIdentity(uniqueEmail("hooks-oauth-other")))
      )
      assert.strictEqual(refused._tag, "PolicyRefused")

      const allowedEmail = uniqueEmail("hooks-oauth-link-ok")
      const { user } = yield* passwords.signUp({ name: testName, email: allowedEmail, password: testPassword })
      const identity = oauthIdentity(uniqueEmail("hooks-oauth-other"))
      const linked = yield* accounts.linkToUser(user.id, identity)
      assert.isTrue(linked.accountCreated)

      // Re-presenting an identity the user already holds attaches nothing, so
      // the hook has nothing to be asked about — it only refreshes the tokens.
      const again = yield* accounts.linkToUser(user.id, identity)
      assert.isFalse(again.accountCreated)
    }))
})

// -----------------------------------------------------------------------------
// One policy, every source
// -----------------------------------------------------------------------------

/**
 * What the cross-source policy saw, in the order it saw it.
 *
 * Shared by every test in the block below and reset by each of them, which is
 * why that block is `describe.sequential`: two tests writing into one array
 * would read each other's entries.
 */
const crossTrace: Array<string> = []

/**
 * The single policy all three provisioning sources are held to.
 *
 * **Details**
 *
 * This is the claim the whole design rests on: a deployment writes *one* hook
 * set and every way a person can come into existence passes through it, naming
 * itself as it goes. The rewrite is deliberately keyed off `source._tag` rather
 * than off anything a flow supplied, so a row that came out with the wrong
 * suffix means a flow reported the wrong source — and a row with no suffix at
 * all means a flow wrote a user without going through the provisioning
 * sequence, which is the drift this file exists to catch: `Passwords` and
 * `Accounts` reimplement `Users.provision` rather than calling it (`Users`
 * reads `Passwords`, so the other direction would close a layer cycle), and
 * three copies of one sequence are three chances to fall out of step.
 *
 * `afterUserCreate` refuses the addresses a test marked, which is how the same
 * set covers atomicity: the row exists when the hook runs, so a refusal that
 * leaves nothing behind can only be the enclosing transaction unwinding.
 */
const crossHooks: AuthHooksService = {
  beforeUserCreate: ({ candidate, source }) =>
    Effect.sync(() => {
      crossTrace.push(`before:${source._tag}`)
      return { ...candidate, name: `${candidate.name} via ${source._tag}` }
    }),
  afterUserCreate: ({ source, user }) =>
    Effect.suspend(() => {
      crossTrace.push(`after:${source._tag}`)
      return user.email.includes("abort")
        ? Effect.fail(new PolicyRefused({ code: "related_row_refused", detail: source._tag }))
        : Effect.void
    })
}

/** The provider the OAuth source signs in through, and the server behind it. */
const crossServer = MockProvider.mockServer()
const crossProvider = MockProvider.mockProvider()

/**
 * A deployment that serves all three sources under one installation of
 * {@link crossHooks}.
 *
 * **Details**
 *
 * Installed the way a *plugin* installs, with {@link append} over whatever the
 * deployment already had — which here is the reference's own default — and
 * provided once, underneath the whole composition, so the plugin and the
 * deployment it is layered over resolve the very same set. That is the
 * composition a consumer writes, and it is what makes the assertions below
 * about one policy rather than about three copies of one that happen to agree.
 */
const crossDeployment = MagicLinkTest.layerMagicLink().pipe(
  Layer.provideMerge(AuthTest.layerFlow({ providers: [crossProvider], fetch: crossServer.fetch })),
  Layer.provide(append(crossHooks))
)

/** Points the shared provider server at one subject, forgetting the last one. */
const crossProviderReturns = (identity: { readonly sub: string; readonly email: string }) =>
  Effect.sync(() => {
    crossServer.clear()
    crossServer.on(MockProvider.tokenUrl, () =>
      MockProvider.json({ access_token: "provider-access-token", token_type: "bearer", expires_in: 3600 }))
    crossServer.on(MockProvider.userInfoUrl, () =>
      MockProvider.json({ sub: identity.sub, email: identity.email, email_verified: true, name: testName }))
  })

/** A whole OAuth round trip, as a browser makes it. */
const crossOAuthSignIn = Effect.fnUntraced(function*(email: string) {
  yield* crossProviderReturns({ sub: `sub-${globalThis.crypto.randomUUID()}`, email })
  const flow = yield* OAuthFlow
  const started = yield* flow.start({ providerId: crossProvider.id })
  return yield* flow.complete({
    providerId: crossProvider.id,
    code: "authorization-code",
    state: Redacted.value(started.state)
  })
})

/** A whole magic-link round trip: ask for the link, then follow it. */
const crossMagicLinkSignIn = Effect.fnUntraced(function*(email: string) {
  const magic = yield* MagicLink
  yield* magic.request({ email, name: testName })
  const emails = yield* TestEmails.TestEmails
  return yield* magic.verify({ token: yield* emails.tokenFor(MagicLinkTest.magicLinkKind, email) })
})

// One policy, one trace, three sources: the tests share the array the hooks
// write into, so they must not run beside each other.
describe.sequential("domain/Hooks — one policy, every source", () => {
  layer(crossDeployment)((it) => {
    it.effect("is consulted by all three provisioning sources, each naming itself", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const store = yield* UserStore
        crossTrace.length = 0

        const password = uniqueEmail("cross-password")
        const oauth = uniqueEmail("cross-oauth")
        const magic = uniqueEmail("cross-magic")

        const registered = yield* passwords.signUp({ name: testName, email: password, password: testPassword })
        const outcome = yield* crossOAuthSignIn(oauth)
        const linked = yield* crossMagicLinkSignIn(magic)

        // Both hooks, once per source, in the order the flows ran — no source
        // consulted twice, and none that skipped the choke point.
        assert.deepStrictEqual(crossTrace, [
          "before:EmailPassword",
          "after:EmailPassword",
          "before:OAuth",
          "after:OAuth",
          "before:MagicLink",
          "after:MagicLink"
        ])

        assert.strictEqual(outcome._tag, "Success")
        if (outcome._tag !== "Success") return
        // The rewrite the one policy made, on the row each source wrote — read
        // back from the store, so it was stored and not merely answered with.
        assert.strictEqual(registered.user.name, `${testName} via EmailPassword`)
        assert.strictEqual(outcome.user.name, `${testName} via OAuth`)
        assert.strictEqual(linked.user.name, `${testName} via MagicLink`)
        const rows: ReadonlyArray<readonly [string, string]> = [
          [password, "EmailPassword"],
          [oauth, "OAuth"],
          [magic, "MagicLink"]
        ]
        for (const [email, source] of rows) {
          const stored = yield* expectSome(yield* store.findByEmail(email), `the ${source} row`)
          assert.strictEqual(stored.name, `${testName} via ${source}`)
        }
      }))

    it.effect("aborts every source's provisioning when the same after-hook fails", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const store = yield* UserStore
        crossTrace.length = 0

        const password = uniqueEmail("cross-abort-password")
        const oauth = uniqueEmail("cross-abort-oauth")
        const magic = uniqueEmail("cross-abort-magic")

        const refusedPassword = yield* Effect.flip(
          passwords.signUp({ name: testName, email: password, password: testPassword })
        )
        const outcome = yield* crossOAuthSignIn(oauth)
        const refusedMagic = yield* Effect.flip(crossMagicLinkSignIn(magic))

        // The typed sources report the refusal itself; the callback, which is a
        // top-level browser navigation, reports it as the redirect its shape
        // demands. Same hook, same code, two ways of saying it.
        assert.strictEqual(refusedPassword._tag, "PolicyRefused")
        if (refusedPassword._tag === "PolicyRefused") assert.strictEqual(refusedPassword.detail, "EmailPassword")
        assert.strictEqual(refusedMagic._tag, "PolicyRefused")
        if (refusedMagic._tag === "PolicyRefused") assert.strictEqual(refusedMagic.detail, "MagicLink")
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") {
          assert.strictEqual(outcome.code, "policy_refused")
          assert.strictEqual(MockProvider.queryOf(outcome.redirectTo)["code"], "related_row_refused")
        }

        // The row existed when the hook ran — that is what `afterUserCreate` is
        // for — and not one of the three survived. Whichever door a person came
        // through, a policy that cannot write the rows beside a user leaves no
        // half-provisioned account behind it.
        assert.deepStrictEqual(crossTrace, [
          "before:EmailPassword",
          "after:EmailPassword",
          "before:OAuth",
          "after:OAuth",
          "before:MagicLink",
          "after:MagicLink"
        ])
        for (const email of [password, oauth, magic]) {
          assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
        }
      }))
  })
})
