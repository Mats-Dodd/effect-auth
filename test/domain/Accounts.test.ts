import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Effect } from "effect"
import { Accounts, canLinkImplicitly } from "../../src/domain/Accounts.js"
import type { OAuthIdentity } from "../../src/domain/Accounts.js"
import { CredentialIssuer, oauthIssuer } from "../../src/domain/Schema.js"
import type { UserId } from "../../src/domain/Schema.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, forUser, signUpUser, testName, uniqueEmail } from "../fixtures.js"

/**
 * A provider subject no other test will claim.
 *
 * Every test in the block writes to one database, so `gh-1000` twice over would
 * be the *same* identity — the second test would find the first one's account
 * and assert nothing.
 */
const uniqueAccountId = (label = "gh"): string => `${label}-${globalThis.crypto.randomUUID()}`

/**
 * What a provider hands back. `accountId` is the provider's stable subject, and
 * it — not the address — is what identifies the account, so a test that links
 * the same identity twice must reuse one of these rather than build two.
 */
const identity = (overrides?: Partial<OAuthIdentity>): OAuthIdentity => ({
  providerId: "github",
  issuer: oauthIssuer("github"),
  accountId: uniqueAccountId(),
  email: uniqueEmail("github"),
  emailVerified: true,
  name: testName,
  ...overrides
})

/** Registers a local email/password user, optionally with a verified address. */
const localUser = Effect.fnUntraced(function* (email: string, emailVerified: boolean) {
  const users = yield* UserStore
  const { user } = yield* signUpUser(email)
  if (!emailVerified) return user
  return yield* expectSome(yield* users.update(user.id, { emailVerified: true }), "expected the updated user")
})

// -----------------------------------------------------------------------------
// The gate, in isolation
// -----------------------------------------------------------------------------

describe("domain/Accounts/canLinkImplicitly", () => {
  it("requires a verified provider address plus one proven side", () => {
    const gate = (providerEmailVerified: boolean, localEmailVerified: boolean, trusted: boolean) =>
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

layer(AuthTest.layer())("domain/Accounts", (it) => {
  // ---------------------------------------------------------------------------
  // Step 1 — the identity is already known
  // ---------------------------------------------------------------------------

  describe("linkOAuth (existing account)", () => {
    it.effect("signs the owner in and refreshes the provider tokens without creating anything", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const store = yield* AccountStore
        const email = uniqueEmail("known")
        const github = identity({ email })

        const first = yield* accounts.linkOAuth({ ...github, tokens: { accessToken: "at-1" } })
        assert.strictEqual(first.userCreated, true)
        assert.strictEqual(first.accountCreated, true)

        const expiresAt = DateTime.addDuration(yield* DateTime.now, "1 hour")
        const { events, result } = yield* AuthTest.recordingEvents(
          accounts.linkOAuth({
            ...github,
            // A changed display name and address must not move the identity:
            // `(issuer, accountId)` is what matches.
            email: uniqueEmail("known-renamed"),
            name: "A. Lovelace",
            tokens: { accessToken: "at-2", accessTokenExpiresAt: expiresAt }
          })
        )

        assert.strictEqual(result.userCreated, false)
        assert.strictEqual(result.accountCreated, false)
        assert.strictEqual(result.user.id, first.user.id)
        assert.strictEqual(result.account.id, first.account.id)
        assert.strictEqual(result.account.accessToken, "at-2")
        // An ordinary sign-in is not a linking event.
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, first.user.id)), [])

        // The local identity is untouched by what the provider now reports.
        assert.strictEqual(result.user.email, email)
        assert.strictEqual((yield* store.listByUserId(first.user.id)).length, 1)
      })
    )
  })

  // ---------------------------------------------------------------------------
  // Step 2 — an address match
  // ---------------------------------------------------------------------------

  describe("linkOAuth (address match)", () => {
    it.effect("links implicitly when the local address is verified", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const email = uniqueEmail("verified")
        const user = yield* localUser(email, true)

        const { events, result } = yield* AuthTest.recordingEvents(accounts.linkOAuth(identity({ email })))
        assert.strictEqual(result.userCreated, false)
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, user.id)), ["AccountLinked"])

        // The user now has two ways in.
        const held = yield* accounts.listForUser(user.id)
        assert.deepStrictEqual(
          held.map((account) => account.issuer).sort(),
          [CredentialIssuer, oauthIssuer("github")].sort()
        )
      })
    )

    it.effect("refuses when neither the provider is trusted nor the local address verified", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const email = uniqueEmail("unproven")
        const user = yield* localUser(email, false)

        const failure = yield* Effect.flip(accounts.linkOAuth(identity({ email })))
        assert.strictEqual(failure._tag, "AccountAlreadyLinked")
        assert.strictEqual((yield* accounts.listForUser(user.id)).length, 1)
      })
    )

    it.effect("matches the address case-insensitively", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const email = uniqueEmail("case")
        const user = yield* localUser(email, true)

        const result = yield* accounts.linkOAuth(identity({ email: email.toUpperCase() }))
        assert.strictEqual(result.user.id, user.id)
        assert.strictEqual(result.accountCreated, true)
      })
    )

    // A configuration variant: everything above the database is rebuilt for
    // this sub-block, and the database itself is inherited from the block above.
    it.layer(AuthTest.layer({ trustedProviders: ["github"] }))("with github trusted", (it) => {
      it.effect("links implicitly even with an unverified local address", () =>
        Effect.gen(function* () {
          const accounts = yield* Accounts
          const email = uniqueEmail("trusted")
          const user = yield* localUser(email, false)

          const result = yield* accounts.linkOAuth(identity({ email }))
          assert.strictEqual(result.accountCreated, true)
          assert.strictEqual(result.user.id, user.id)
        })
      )

      it.effect("refuses when the provider has not verified the address", () =>
        Effect.gen(function* () {
          // The dangerous case: anybody who can put someone else's address into
          // an unverified provider profile could otherwise claim their account.
          const accounts = yield* Accounts
          const email = uniqueEmail("unverified-claim")
          const user = yield* localUser(email, true)

          const failure = yield* Effect.flip(accounts.linkOAuth(identity({ email, emailVerified: false })))
          if (failure._tag !== "AccountAlreadyLinked") return assert.fail(`unexpected ${failure._tag}`)
          assert.strictEqual(failure.providerId, "github")

          // Nothing was written.
          assert.strictEqual((yield* accounts.listForUser(user.id)).length, 1)
        })
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Step 3 — a new person
  // ---------------------------------------------------------------------------

  describe("linkOAuth (new user)", () => {
    it.effect("creates the user and the account together and takes emailVerified from the claim", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const users = yield* UserStore
        const email = uniqueEmail("provisioned")

        const { events, result } = yield* AuthTest.recordingEvents(accounts.linkOAuth(identity({ email })))
        assert.strictEqual(result.userCreated, true)
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.emailVerified, true)
        assert.strictEqual(result.user.name, testName)
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, result.user.id)), ["UserCreated", "AccountLinked"])

        assert.strictEqual((yield* expectSome(yield* users.findByEmail(email), "expected the user")).id, result.user.id)
      })
    )

    it.effect("does not mark the address verified when the provider did not", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const email = uniqueEmail("nameless")
        const result = yield* accounts.linkOAuth(identity({ email, emailVerified: false, name: undefined }))
        assert.strictEqual(result.user.emailVerified, false)
        // With no display name from the provider, the address stands in.
        assert.strictEqual(result.user.name, email)
      })
    )
  })

  // ---------------------------------------------------------------------------
  // Explicit linking
  // ---------------------------------------------------------------------------

  describe("linkToUser", () => {
    it.effect("attaches an identity to a signed-in user regardless of addresses", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        // A completely different address: the person proved both sides, so no
        // matching is needed and none is done.
        const user = yield* localUser(uniqueEmail("explicit"), false)

        const { events, result } = yield* AuthTest.recordingEvents(
          accounts.linkToUser(user.id, identity({ email: uniqueEmail("stranger"), emailVerified: false }))
        )
        assert.strictEqual(result.accountCreated, true)
        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, user.id)), ["AccountLinked"])
        assert.strictEqual((yield* accounts.listForUser(user.id)).length, 2)
      })
    )

    it.effect("refuses an identity that belongs to somebody else, and re-links its owner harmlessly", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const github = identity()
        const owner = yield* accounts.linkOAuth(github)
        const other = yield* localUser(uniqueEmail("bob"), true)

        const failure = yield* Effect.flip(accounts.linkToUser(other.id, github))
        assert.strictEqual(failure._tag, "AccountAlreadyLinked")
        assert.strictEqual((yield* accounts.listForUser(other.id)).length, 1)

        // The rightful owner re-linking is a no-op that refreshes tokens.
        const again = yield* accounts.linkToUser(owner.user.id, {
          ...github,
          tokens: { accessToken: "at-9" }
        })
        assert.strictEqual(again.accountCreated, false)
        assert.strictEqual(again.account.accessToken, "at-9")
        assert.strictEqual((yield* accounts.listForUser(owner.user.id)).length, 1)
      })
    )

    it.effect("fails UserNotFound for an unknown user", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const failure = yield* Effect.flip(
          accounts.linkToUser("01890000-0000-7000-8000-000000000000" as UserId, identity())
        )
        assert.strictEqual(failure._tag, "UserNotFound")
      })
    )
  })

  // ---------------------------------------------------------------------------
  // Unlinking
  // ---------------------------------------------------------------------------

  describe("unlink", () => {
    it.effect("refuses to remove the last sign-in method", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const linked = yield* accounts.linkOAuth(identity())

        const failure = yield* Effect.flip(accounts.unlink(linked.account.id, linked.user.id))
        assert.strictEqual(failure._tag, "CannotUnlinkLastAccount")
        assert.strictEqual((yield* accounts.listForUser(linked.user.id)).length, 1)
      })
    )

    it.effect("removes one of several methods and emits AccountUnlinked", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const email = uniqueEmail("two-methods")
        const user = yield* localUser(email, true)
        const linked = yield* accounts.linkOAuth(identity({ email }))
        assert.strictEqual(linked.user.id, user.id)

        const { events } = yield* AuthTest.recordingEvents(accounts.unlink(linked.account.id, user.id))
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, user.id)), ["AccountUnlinked"])

        const held = yield* accounts.listForUser(user.id)
        assert.strictEqual(held.length, 1)
        assert.strictEqual(held[0]?.issuer, CredentialIssuer)

        // And now it is the last one again.
        const failure = yield* Effect.flip(accounts.unlink(held[0]!.id, user.id))
        assert.strictEqual(failure._tag, "CannotUnlinkLastAccount")
      })
    )

    it.effect("refuses to unlink an account that belongs to another user", () =>
      Effect.gen(function* () {
        const accounts = yield* Accounts
        const adaEmail = uniqueEmail("ada")
        const ada = yield* localUser(adaEmail, true)
        const bob = yield* localUser(uniqueEmail("bob"), true)
        yield* accounts.linkToUser(ada.id, identity({ email: adaEmail }))

        const adasAccounts = yield* accounts.listForUser(ada.id)
        const target = adasAccounts.find((account) => account.providerId === "github")
        if (target === undefined) return assert.fail("expected the linked GitHub account")

        // Bob has one account, so his own guard would fire first; give him a
        // second so the ownership check is what refuses.
        yield* accounts.linkToUser(bob.id, identity())

        const failure = yield* Effect.flip(accounts.unlink(target.id, bob.id))
        assert.strictEqual(failure._tag, "NotFound")
        assert.strictEqual((yield* accounts.listForUser(ada.id)).length, 2)
      })
    )
  })
})

// -----------------------------------------------------------------------------
// The provisioning race, on a database of its own
// -----------------------------------------------------------------------------

/**
 * This one keeps its own deployment. The losing fibre's transaction is rolled
 * back, and PGlite serves the whole block from a single connection, so a
 * rollback here would take a concurrent sibling's uncommitted writes with it.
 */
describe("domain/Accounts/linkOAuth (provisioning race)", () => {
  it.effect("gives two concurrent callbacks for one brand-new identity the same user", () =>
    Effect.gen(function* () {
      const accounts = yield* Accounts
      const email = uniqueEmail("race")
      const github = identity({ email })

      // Both fibers get past the `(issuer, accountId)` lookup and the e-mail
      // lookup before either insert lands, so one of them loses the unique
      // index. That is the retry path: it re-runs the resolution, which now
      // finds the winner's row and completes as an ordinary sign-in.
      const { events, result } = yield* AuthTest.recordingEvents(
        Effect.all([Effect.result(accounts.linkOAuth(github)), Effect.result(accounts.linkOAuth(github))], {
          concurrency: 2
        })
      )

      const successes = result.filter((one) => one._tag === "Success")
      assert.strictEqual(successes.length, 2, "both callers must be signed in")
      const [first, second] = successes
      if (first?._tag !== "Success" || second?._tag !== "Success") return
      assert.strictEqual(first.success.user.id, second.success.user.id)
      assert.strictEqual(first.success.account.id, second.success.account.id)

      // Exactly one of them provisioned; the loser did not re-publish the
      // events of the write it lost.
      assert.strictEqual([first.success.userCreated, second.success.userCreated].filter(Boolean).length, 1)
      assert.deepStrictEqual(AuthTest.tagsOf(events), ["UserCreated", "AccountLinked"])

      // And one user, one account, in the database.
      const users = yield* UserStore
      const owner = yield* expectSome(yield* users.findByEmail(email), "expected the user")
      assert.strictEqual((yield* accounts.listForUser(owner.id)).length, 1)
    }).pipe(Effect.provide(AuthTest.layer()))
  )
})
