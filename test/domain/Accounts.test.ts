import { assert, describe, it } from "@effect/vitest"
import { DateTime, Effect, Redacted } from "effect"
import { Accounts, canLinkImplicitly } from "../../src/domain/Accounts.js"
import type { OAuthIdentity } from "../../src/domain/Accounts.js"
import { Passwords } from "../../src/domain/Passwords.js"
import { CredentialIssuer, oauthIssuer } from "../../src/domain/Schema.js"
import type { UserId } from "../../src/domain/Schema.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { expectSome, recordingEvents, tagsOf, testLayer, testTimeout } from "./harness.js"

const password = Redacted.make("correct-horse-battery")

/**
 * What a provider hands back. `accountId` is the provider's stable subject, and
 * it — not the address — is what identifies the account.
 */
const github = (overrides?: Partial<OAuthIdentity>): OAuthIdentity => ({
  providerId: "github",
  issuer: oauthIssuer("github"),
  accountId: "gh-1000",
  email: "ada@example.com",
  emailVerified: true,
  name: "Ada Lovelace",
  ...overrides
})

/** Registers a local email/password user, optionally with a verified address. */
const localUser = Effect.fnUntraced(function*(email: string, emailVerified: boolean) {
  const passwords = yield* Passwords
  const users = yield* UserStore
  const { user } = yield* passwords.signUp({ name: "Ada Lovelace", email, password })
  if (!emailVerified) return user
  return yield* expectSome(yield* users.update(user.id, { emailVerified: true }), "expected the updated user")
})

// -----------------------------------------------------------------------------
// The gate, in isolation
// -----------------------------------------------------------------------------

describe("domain/Accounts/canLinkImplicitly", () => {
  it("requires a verified provider address plus one proven side", () => {
    const gate = (
      providerEmailVerified: boolean,
      localEmailVerified: boolean,
      trusted: boolean
    ) =>
      canLinkImplicitly({
        providerId: "github",
        providerEmailVerified,
        localEmailVerified,
        trustedProviders: trusted ? ["github"] : []
      })

    // An unverified provider address is never enough, however much we trust
    // the provider: the "match" is a string somebody typed into a profile.
    assert.strictEqual(gate(false, true, true), false)
    assert.strictEqual(gate(false, false, false), false)

    // Verified at the provider, and either side proven.
    assert.strictEqual(gate(true, true, false), true)
    assert.strictEqual(gate(true, false, true), true)

    // Verified at the provider, but nothing else proven.
    assert.strictEqual(gate(true, false, false), false)
  })
})

// -----------------------------------------------------------------------------
// Step 1 — the identity is already known
// -----------------------------------------------------------------------------

describe("domain/Accounts/linkOAuth (existing account)", () => {
  it.effect(
    "signs the owner in and refreshes the provider tokens without creating anything",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const store = yield* AccountStore

        const first = yield* accounts.linkOAuth(github({ tokens: { accessToken: "at-1" } }))
        assert.strictEqual(first.userCreated, true)
        assert.strictEqual(first.accountCreated, true)

        const expiresAt = DateTime.addDuration(yield* DateTime.now, "1 hour")
        const { events, result } = yield* recordingEvents(
          accounts.linkOAuth(github({
            // A changed display name and address must not move the identity:
            // `(issuer, accountId)` is what matches.
            email: "ada-new@example.com",
            name: "A. Lovelace",
            tokens: { accessToken: "at-2", accessTokenExpiresAt: expiresAt }
          }))
        )

        assert.strictEqual(result.userCreated, false)
        assert.strictEqual(result.accountCreated, false)
        assert.strictEqual(result.user.id, first.user.id)
        assert.strictEqual(result.account.id, first.account.id)
        assert.strictEqual(result.account.accessToken, "at-2")
        // An ordinary sign-in is not a linking event.
        assert.deepStrictEqual(tagsOf(events), [])

        // The local identity is untouched by what the provider now reports.
        assert.strictEqual(result.user.email, "ada@example.com")
        assert.strictEqual((yield* store.listByUserId(first.user.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Step 2 — an address match
// -----------------------------------------------------------------------------

describe("domain/Accounts/linkOAuth (address match)", () => {
  it.effect(
    "links implicitly when the local address is verified",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const user = yield* localUser("ada@example.com", true)

        const { events, result } = yield* recordingEvents(accounts.linkOAuth(github()))
        assert.strictEqual(result.userCreated, false)
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(tagsOf(events), ["AccountLinked"])

        // The user now has two ways in.
        const held = yield* accounts.listForUser(user.id)
        assert.deepStrictEqual(
          held.map((account) => account.issuer).sort(),
          [CredentialIssuer, oauthIssuer("github")].sort()
        )
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "links implicitly when the provider is trusted, even with an unverified local address",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const user = yield* localUser("ada@example.com", false)

        const result = yield* accounts.linkOAuth(github())
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.id, user.id)
      }).pipe(Effect.provide(testLayer({ trustedProviders: ["github"] }))),
    testTimeout
  )

  it.effect(
    "refuses when the provider has not verified the address",
    () =>
      Effect.gen(function*() {
        // The dangerous case: anybody who can put someone else's address into
        // an unverified provider profile could otherwise claim their account.
        const accounts = yield* Accounts
        const user = yield* localUser("ada@example.com", true)

        const failure = yield* Effect.flip(accounts.linkOAuth(github({ emailVerified: false })))
        if (failure._tag !== "AccountAlreadyLinked") return assert.fail(`unexpected ${failure._tag}`)
        assert.strictEqual(failure.providerId, "github")

        // Nothing was written.
        assert.strictEqual((yield* accounts.listForUser(user.id)).length, 1)
      }).pipe(Effect.provide(testLayer({ trustedProviders: ["github"] }))),
    testTimeout
  )

  it.effect(
    "refuses when neither the provider is trusted nor the local address verified",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const user = yield* localUser("ada@example.com", false)

        const failure = yield* Effect.flip(accounts.linkOAuth(github()))
        assert.strictEqual(failure._tag, "AccountAlreadyLinked")
        assert.strictEqual((yield* accounts.listForUser(user.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "matches the address case-insensitively",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const user = yield* localUser("ada@example.com", true)

        const result = yield* accounts.linkOAuth(github({ email: "Ada@Example.COM" }))
        assert.strictEqual(result.user.id, user.id)
        assert.strictEqual(result.accountCreated, true)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Step 3 — a new person
// -----------------------------------------------------------------------------

describe("domain/Accounts/linkOAuth (new user)", () => {
  it.effect(
    "creates the user and the account together and takes emailVerified from the claim",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const users = yield* UserStore

        const { events, result } = yield* recordingEvents(accounts.linkOAuth(github()))
        assert.strictEqual(result.userCreated, true)
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.emailVerified, true)
        assert.strictEqual(result.user.name, "Ada Lovelace")
        assert.deepStrictEqual(tagsOf(events), ["UserCreated", "AccountLinked"])

        assert.strictEqual(
          (yield* expectSome(yield* users.findByEmail("ada@example.com"), "expected the user")).id,
          result.user.id
        )
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "does not mark the address verified when the provider did not",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const result = yield* accounts.linkOAuth(github({ emailVerified: false, name: undefined }))
        assert.strictEqual(result.user.emailVerified, false)
        // With no display name from the provider, the address stands in.
        assert.strictEqual(result.user.name, "ada@example.com")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Explicit linking
// -----------------------------------------------------------------------------

describe("domain/Accounts/linkToUser", () => {
  it.effect(
    "attaches an identity to a signed-in user regardless of addresses",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        // A completely different address: the person proved both sides, so no
        // matching is needed and none is done.
        const user = yield* localUser("ada@example.com", false)

        const { events, result } = yield* recordingEvents(
          accounts.linkToUser(user.id, github({ email: "someone-else@example.com", emailVerified: false }))
        )
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(tagsOf(events), ["AccountLinked"])
        assert.strictEqual((yield* accounts.listForUser(user.id)).length, 2)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses an identity that belongs to somebody else, and re-links its owner harmlessly",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const owner = yield* accounts.linkOAuth(github())
        const other = yield* localUser("bob@example.com", true)

        const failure = yield* Effect.flip(accounts.linkToUser(other.id, github()))
        assert.strictEqual(failure._tag, "AccountAlreadyLinked")
        assert.strictEqual((yield* accounts.listForUser(other.id)).length, 1)

        // The rightful owner re-linking is a no-op that refreshes tokens.
        const again = yield* accounts.linkToUser(owner.user.id, github({ tokens: { accessToken: "at-9" } }))
        assert.strictEqual(again.accountCreated, false)
        assert.strictEqual(again.account.accessToken, "at-9")
        assert.strictEqual((yield* accounts.listForUser(owner.user.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "fails UserNotFound for an unknown user",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const failure = yield* Effect.flip(
          accounts.linkToUser("01890000-0000-7000-8000-000000000000" as UserId, github())
        )
        assert.strictEqual(failure._tag, "UserNotFound")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Unlinking
// -----------------------------------------------------------------------------

describe("domain/Accounts/unlink", () => {
  it.effect(
    "refuses to remove the last sign-in method",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const linked = yield* accounts.linkOAuth(github())

        const failure = yield* Effect.flip(accounts.unlink(linked.account.id, linked.user.id))
        assert.strictEqual(failure._tag, "CannotUnlinkLastAccount")
        assert.strictEqual((yield* accounts.listForUser(linked.user.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "removes one of several methods and emits AccountUnlinked",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const user = yield* localUser("ada@example.com", true)
        const linked = yield* accounts.linkOAuth(github())
        assert.strictEqual(linked.user.id, user.id)

        const { events } = yield* recordingEvents(accounts.unlink(linked.account.id, user.id))
        assert.deepStrictEqual(tagsOf(events), ["AccountUnlinked"])

        const held = yield* accounts.listForUser(user.id)
        assert.strictEqual(held.length, 1)
        assert.strictEqual(held[0]?.issuer, CredentialIssuer)

        // And now it is the last one again.
        const failure = yield* Effect.flip(accounts.unlink(held[0]!.id, user.id))
        assert.strictEqual(failure._tag, "CannotUnlinkLastAccount")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "gives two concurrent callbacks for one brand-new identity the same user",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const identity = github({ accountId: "gh-race", email: "race@example.com" })

        // Both fibers get past the `(issuer, accountId)` lookup and the e-mail
        // lookup before either insert lands, so one of them loses the unique
        // index. That is the retry path: it re-runs the resolution, which now
        // finds the winner's row and completes as an ordinary sign-in.
        const { events, result } = yield* recordingEvents(
          Effect.all(
            [Effect.result(accounts.linkOAuth(identity)), Effect.result(accounts.linkOAuth(identity))],
            { concurrency: 2 }
          )
        )

        const successes = result.filter((one) => one._tag === "Success")
        assert.strictEqual(successes.length, 2, "both callers must be signed in")
        const [first, second] = successes
        if (first?._tag !== "Success" || second?._tag !== "Success") return
        assert.strictEqual(first.success.user.id, second.success.user.id)
        assert.strictEqual(first.success.account.id, second.success.account.id)

        // Exactly one of them provisioned; the loser did not re-publish the
        // events of the write it lost.
        assert.strictEqual(
          [first.success.userCreated, second.success.userCreated].filter(Boolean).length,
          1
        )
        assert.deepStrictEqual(tagsOf(events), ["UserCreated", "AccountLinked"])

        // And one user, one account, in the database.
        const users = yield* UserStore
        const owner = yield* expectSome(yield* users.findByEmail("race@example.com"), "expected the user")
        assert.strictEqual((yield* accounts.listForUser(owner.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses to unlink an account that belongs to another user",
    () =>
      Effect.gen(function*() {
        const accounts = yield* Accounts
        const ada = yield* localUser("ada@example.com", true)
        const bob = yield* localUser("bob@example.com", true)
        yield* accounts.linkToUser(ada.id, github())

        const adasAccounts = yield* accounts.listForUser(ada.id)
        const target = adasAccounts.find((account) => account.providerId === "github")
        if (target === undefined) return assert.fail("expected the linked GitHub account")

        // Bob has one account, so his own guard would fire first; give him a
        // second so the ownership check is what refuses.
        yield* accounts.linkToUser(bob.id, github({ accountId: "gh-2000" }))

        const failure = yield* Effect.flip(accounts.unlink(target.id, bob.id))
        assert.strictEqual(failure._tag, "NotFound")
        assert.strictEqual((yield* accounts.listForUser(ada.id)).length, 2)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})
