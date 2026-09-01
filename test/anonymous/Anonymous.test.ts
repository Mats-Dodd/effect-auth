import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { SqlClient } from "effect/unstable/sql"
import {
  Anonymous,
  anonymousDomain,
  defaultAdoptEndpoints,
  identifiedPolicy,
  makeConfig,
  isSyntheticEmail,
  syntheticEmail
} from "../../src/anonymous/index.js"
import { PolicyRefused } from "../../src/domain/Hooks.js"
import { Passwords } from "../../src/domain/Passwords.js"
import { Users } from "../../src/domain/Users.js"
import type { User } from "../../src/domain/Schema.js"
import { requireAssuranceFor } from "../../src/domain/Sessions.js"
import { SessionStore, UserStore } from "../../src/domain/Stores.js"
import * as AnonymousTest from "../../src/testing/AnonymousTest.js"
import { TestEmails } from "../../src/testing/TestEmails.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { expectSome, signUpUser, testPassword, uniqueEmail } from "../fixtures.js"

describe("anonymous/adoptEndpoints", () => {
  it("ships every way this library has of acquiring a credential", () => {
    // The four flows phase 1 named, spelled as the endpoints that serve them —
    // registration and the address change each being two halves of one
    // ceremony an anonymous visitor has to reach both of.
    assert.deepStrictEqual([...defaultAdoptEndpoints].sort(), [
      "changeEmailSend",
      "changeEmailVerify",
      "linkSocial",
      "registerOptions",
      "registerVerify",
      "setPassword"
    ])
  })

  it("is replaced by a deployment's own list, never added to", () => {
    // Spread it to keep it. A list that silently grew would be a permit a
    // deployment did not write.
    assert.deepStrictEqual([...makeConfig({ adoptEndpoints: ["setPassword"] }).adoptEndpoints], ["setPassword"])
    assert.deepStrictEqual(makeConfig().adoptEndpoints, defaultAdoptEndpoints)
  })
})

describe("anonymous/addresses", () => {
  it("mints and recognises addresses in the reserved domain", () => {
    const email = syntheticEmail("0192f0c0-0000-7000-8000-000000000000")
    assert.isTrue(email.endsWith(`@${anonymousDomain}`))
    assert.isTrue(isSyntheticEmail(email))
    assert.isTrue(isSyntheticEmail(email.toUpperCase()))
    assert.isFalse(isSyntheticEmail("ada@example.com"))
    // RFC 2606 reserves `.invalid`, so nothing here can ever be delivered to.
    assert.strictEqual(anonymousDomain, "anonymous.invalid")
  })
})

layer(AnonymousTest.layer())("anonymous/the service", (it) => {
  it.effect("provisions a real user at aal0 with an undeliverable address", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const { session, user } = yield* anonymous.signIn()

      assert.isTrue(isSyntheticEmail(user.email))
      assert.isFalse(user.emailVerified)
      // The address names the row, so a support query can go either way.
      assert.strictEqual(user.email, syntheticEmail(user.id))
      // Empty evidence is the whole of what makes this session anonymous.
      assert.deepStrictEqual([...session.methods], [])
      assert.strictEqual(session.aal, "aal0")
      assert.isTrue(yield* anonymous.isAnonymous(user.id))
    })
  )

  it.effect("is excluded by one guard, and a real session is not", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const visitor = yield* anonymous.signIn()
      const member = yield* signUpUser(uniqueEmail("guarded"))

      const refused = yield* Effect.flip(requireAssuranceFor(visitor.session, identifiedPolicy, []))
      assert.strictEqual(refused._tag, "StepUpRequired")
      assert.strictEqual(refused.current.aal, "aal0")
      assert.strictEqual(refused.required.aal, "aal1")

      // The same policy admits somebody who proved a password.
      yield* requireAssuranceFor(member.session, identifiedPolicy, [])
    })
  )

  it.effect("lets a visitor reach exactly the endpoints the adopt list names", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const visitor = yield* anonymous.signIn()
      const member = yield* signUpUser(uniqueEmail("adoptable"))

      // On the list, at aal0: every way this library ships of acquiring a
      // credential without leaving the account already in hand.
      for (const endpoint of [
        "setPassword",
        "linkSocial",
        "registerOptions",
        "registerVerify",
        "changeEmailSend",
        "changeEmailVerify"
      ]) {
        yield* anonymous.requireAdoptable(visitor.session, endpoint)
      }

      // Off it, refused — as the ordinary assurance failure, not a bespoke error.
      const refused = yield* Effect.flip(anonymous.requireAdoptable(visitor.session, "changeEmail"))
      assert.strictEqual(refused._tag, "StepUpRequired")

      // A person who has proved something reaches everything.
      yield* anonymous.requireAdoptable(member.session, "changeEmail")
    })
  )

  it.effect("adopts only once the account really holds a way in", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const passwords = yield* Passwords
      const users = yield* UserStore
      const { user } = yield* anonymous.signIn()

      // Nothing proved yet: the marker stays, which is the answer that cannot
      // lock anybody out.
      assert.strictEqual(yield* anonymous.adopt({ userId: user.id }), "NoCredential")
      assert.isTrue(yield* anonymous.isAnonymous(user.id))

      yield* passwords.setPassword({ userId: user.id, newPassword: testPassword })
      const real = uniqueEmail("adopted")
      assert.strictEqual(yield* anonymous.adopt({ userId: user.id, email: real }), "Adopted")

      assert.isFalse(yield* anonymous.isAnonymous(user.id))
      const stored = yield* expectSome(yield* users.findById(user.id), "the user should still exist")
      assert.strictEqual(stored.email, real)
      assert.isTrue(stored.emailVerified)

      // Twice is not an error; there is simply nothing left to do.
      assert.strictEqual(yield* anonymous.adopt({ userId: user.id }), "NotAnonymous")
    })
  )

  it.effect("keeps the synthetic address when adoption names none", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const passwords = yield* Passwords
      const users = yield* UserStore
      const { user } = yield* anonymous.signIn()

      yield* passwords.setPassword({ userId: user.id, newPassword: testPassword })
      assert.strictEqual(yield* anonymous.adopt({ userId: user.id }), "Adopted")

      const stored = yield* expectSome(yield* users.findById(user.id), "the user should still exist")
      assert.isTrue(isSyntheticEmail(stored.email))
    })
  )

  it.effect("discards a visitor and everything they had, and refuses a real account", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const sessions = yield* SessionStore
      const users = yield* UserStore
      const { user } = yield* anonymous.signIn()

      assert.strictEqual((yield* sessions.listByUserId(user.id)).length, 1)
      yield* anonymous.discard(user)
      assert.isTrue(Option.isNone(yield* users.findById(user.id)))
      assert.strictEqual((yield* sessions.listByUserId(user.id)).length, 0)

      const member = yield* signUpUser(uniqueEmail("discard-real"))
      const refused = yield* Effect.flip(anonymous.discard(member.user))
      assert.strictEqual(refused._tag, "NotAnonymous")
      assert.isTrue(Option.isSome(yield* users.findById(member.user.id)))
    })
  )

  it.effect("never puts a synthetic address in a message", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const outbox = yield* TestEmails
      const { user } = yield* anonymous.signIn()

      // The address really is one nothing can deliver to...
      assert.isTrue(isSyntheticEmail(user.email))
      // ...and every message this deployment has sent, whoever sent it, names
      // an address that is not.
      const sent = yield* outbox.all
      assert.isTrue(sent.every((message) => !isSyntheticEmail(message.to)))
    })
  )

  it.layer(AnonymousTest.layer({ emailPassword: { requireEmailVerification: true } }))((it) => {
    it.effect("sends nothing at all, even where the deployment verifies addresses", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const outbox = yield* TestEmails
        const before = (yield* outbox.all).length
        const { user } = yield* anonymous.signIn()

        // The one setting that would otherwise mail a brand-new account.
        // Provisioning a visitor goes through `Users.provision` and not through
        // a sign-up, so there is no branch that could reach for the mailer with
        // an address in the reserved domain — a bounce and a reputational cost
        // for a person who asked for nothing.
        const after = yield* outbox.all
        assert.strictEqual(after.length, before)
        assert.isTrue(isSyntheticEmail(user.email))
        // And the visitor is not silently treated as a verified person either.
        assert.isFalse(user.emailVerified)
      })
    )
  })

  it.effect("touch moves the visitor out of the sweep's reach", () =>
    Effect.gen(function* () {
      const anonymous = yield* Anonymous
      const { user } = yield* anonymous.signIn()
      assert.isTrue(yield* anonymous.touch(user.id))
      // A person with no marker has nothing to stamp.
      const member = yield* signUpUser(uniqueEmail("touch-real"))
      assert.isFalse(yield* anonymous.touch(member.user.id))
    })
  )
})

describe.sequential("anonymous/sweep", () => {
  layer(AnonymousTest.layer())("garbage collection", (it) => {
    it.effect("removes an idle visitor with no live session and leaves the others", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const anonymous = yield* Anonymous
          const users = yield* UserStore
          const sessions = yield* SessionStore

          const stale = yield* anonymous.signIn()
          const busy = yield* anonymous.signIn()

          // Older than the 30-day default, so both markers qualify on age.
          yield* TestClock.adjust(Duration.days(40))
          // One of them has since been seen, and still holds a live session.
          yield* anonymous.touch(busy.user.id)
          yield* anonymous.signIn()

          // The stale visitor's session is gone; the busy one's is not.
          yield* sessions.deleteByUserId(stale.user.id)

          const removed = yield* anonymous.sweep()
          assert.strictEqual(removed, 1)
          assert.isTrue(Option.isNone(yield* users.findById(stale.user.id)))
          assert.isTrue(Option.isSome(yield* users.findById(busy.user.id)))
        })
      )
    )

    it.effect("never removes more than the limit in one pass", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const anonymous = yield* Anonymous
          const sessions = yield* SessionStore

          const first = yield* anonymous.signIn()
          const second = yield* anonymous.signIn()
          yield* sessions.deleteByUserId(first.user.id)
          yield* sessions.deleteByUserId(second.user.id)
          yield* TestClock.adjust(Duration.days(40))

          assert.strictEqual(yield* anonymous.sweep({ limit: 1 }), 1)
          // The rest are still there for the next pass, which is what a bounded
          // sweep means.
          assert.isAtLeast(yield* anonymous.sweep({ limit: 10 }), 1)
        })
      )
    )

    it.effect("never sweeps a visitor who has since acquired a way in", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const anonymous = yield* Anonymous
          const passwords = yield* Passwords
          const users = yield* UserStore
          const sessions = yield* SessionStore

          // `POST /auth/set-password` is on the adopt list and reachable at
          // aal0 by design — and core cannot call a plugin, so nothing clears
          // the marker when it succeeds. The marker therefore says "arrived as
          // a visitor", never "is disposable", and the sweep has to read the
          // account rather than the marker.
          const { user } = yield* anonymous.signIn()
          yield* passwords.setPassword({ userId: user.id, newPassword: testPassword })
          yield* sessions.deleteByUserId(user.id)
          yield* TestClock.adjust(Duration.days(40))

          assert.strictEqual(yield* anonymous.sweep(), 0)
          assert.isTrue(Option.isSome(yield* users.findById(user.id)))
          // Still marked — nothing adopted them — and still swept over.
          assert.isTrue(yield* anonymous.isAnonymous(user.id))
        })
      )
    )

    it.effect("leaves a visitor younger than idleFor alone", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const anonymous = yield* Anonymous
          const users = yield* UserStore
          const sessions = yield* SessionStore
          const { user } = yield* anonymous.signIn()
          yield* sessions.deleteByUserId(user.id)

          assert.strictEqual(yield* anonymous.sweep({ idleFor: Duration.days(30) }), 0)
          assert.isTrue(Option.isSome(yield* users.findById(user.id)))
        })
      )
    )
  })
})

/** What the merge callback of the block below recorded. */
const merged: Array<{ readonly anonymous: string; readonly target: string }> = []

describe.sequential("anonymous/merge on sign-in", () => {
  layer(
    AnonymousTest.layer({
      anonymous: {
        onMerge: (options: { readonly anonymous: User; readonly target: User }) =>
          Effect.sync(() => {
            merged.push({ anonymous: options.anonymous.id, target: options.target.id })
          })
      }
    })
  )("with a merge callback", (it) => {
    it.effect("deletes the visitor and their sessions when they sign in as somebody", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const passwords = yield* Passwords
        const users = yield* UserStore
        const sessions = yield* SessionStore

        const visitor = yield* anonymous.signIn()
        const email = uniqueEmail("merge-target")
        const member = yield* signUpUser(email)

        const before = merged.length
        const result = yield* passwords.signIn({
          email,
          password: testPassword,
          current: { session: visitor.session, user: visitor.user }
        })
        assert.strictEqual(result._tag, "Complete")

        assert.strictEqual(merged.length - before, 1)
        assert.deepStrictEqual(merged[merged.length - 1], {
          anonymous: visitor.user.id,
          target: member.user.id
        })

        // A is gone, and its sessions with it.
        assert.isTrue(Option.isNone(yield* users.findById(visitor.user.id)))
        assert.strictEqual((yield* sessions.listByUserId(visitor.user.id)).length, 0)
        // B is untouched.
        assert.isTrue(Option.isSome(yield* users.findById(member.user.id)))
      })
    )

    it.effect("does not merge a visitor into themselves", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const passwords = yield* Passwords
        const users = yield* UserStore
        const { session, user } = yield* anonymous.signIn()

        yield* passwords.setPassword({ userId: user.id, newPassword: testPassword })
        const before = merged.length
        yield* passwords.signIn({ email: user.email, password: testPassword, current: { session, user } })

        assert.strictEqual(merged.length, before)
        assert.isTrue(Option.isSome(yield* users.findById(user.id)))
      })
    )

    it.effect("never merges away a visitor who has since acquired a way in", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const passwords = yield* Passwords
        const users = yield* UserStore

        // The same rule as the sweep's, at the other destructive door. A person
        // who set a password as a visitor and then signs in to a second account
        // must not have their first one deleted underneath them.
        const visitor = yield* anonymous.signIn()
        yield* passwords.setPassword({ userId: visitor.user.id, newPassword: testPassword })

        const email = uniqueEmail("merge-settled")
        yield* signUpUser(email)
        const before = merged.length
        yield* passwords.signIn({
          email,
          password: testPassword,
          current: { session: visitor.session, user: visitor.user }
        })

        assert.strictEqual(merged.length, before)
        assert.isTrue(Option.isSome(yield* users.findById(visitor.user.id)))
      })
    )

    it.effect("leaves a caller who was never anonymous alone", () =>
      Effect.gen(function* () {
        const passwords = yield* Passwords
        const users = yield* UserStore
        const first = yield* signUpUser(uniqueEmail("merge-not-anon"))
        const email = uniqueEmail("merge-other")
        yield* signUpUser(email)

        const before = merged.length
        yield* passwords.signIn({
          email,
          password: testPassword,
          current: { session: first.session, user: first.user }
        })

        assert.strictEqual(merged.length, before)
        assert.isTrue(Option.isSome(yield* users.findById(first.user.id)))
      })
    )
  })
})

describe.sequential("anonymous/merge refusal", () => {
  layer(AnonymousTest.layer({ anonymous: { onMerge: () => PolicyRefused.make({ code: "merge_failed" }) } }))(
    "with a refusing merge callback",
    (it) => {
      it.effect("aborts the mint and leaves both accounts intact", () =>
        Effect.gen(function* () {
          const anonymous = yield* Anonymous
          const passwords = yield* Passwords
          const users = yield* UserStore
          const sessions = yield* SessionStore

          const visitor = yield* anonymous.signIn()
          const email = uniqueEmail("refused-target")
          const member = yield* signUpUser(email)
          const before = (yield* sessions.listByUserId(member.user.id)).length

          const failure = yield* Effect.flip(
            passwords.signIn({
              email,
              password: testPassword,
              current: { session: visitor.session, user: visitor.user }
            })
          )
          assert.strictEqual(failure._tag, "PolicyRefused")
          assert.strictEqual(failure._tag === "PolicyRefused" ? failure.code : null, "merge_failed")

          // Neither account changed, and no session was minted — the ordering
          // better-auth got wrong, where the cookie was already set.
          assert.isTrue(Option.isSome(yield* users.findById(visitor.user.id)))
          assert.isTrue(Option.isSome(yield* users.findById(member.user.id)))
          assert.strictEqual((yield* sessions.listByUserId(member.user.id)).length, before)
          assert.isTrue(yield* anonymous.isAnonymous(visitor.user.id))
        })
      )
    }
  )
})

describe.sequential("anonymous/synthetic addresses are never mailed", () => {
  layer(AnonymousTest.layer({ emailPassword: { requireEmailVerification: true } }))("core mail paths", (it) => {
    it.effect("no core endpoint hands a reserved-domain address to the mailer", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const passwords = yield* Passwords
        const users = yield* Users
        const emails = yield* TestEmails

        const { user } = yield* anonymous.signIn()

        // Every core flow an aal0 visitor can reach that sends mail. None of
        // them knows this plugin exists, and the address they would be handed
        // is `anon-…@anonymous.invalid` — RFC 2606 reserved, so a real relay
        // answers a bounce and the deployment pays for it in reputation.
        yield* passwords.sendVerificationEmail({ email: user.email })
        yield* passwords.requestReset({ email: user.email })
        yield* users.requestEmailChange({ user, newEmail: uniqueEmail("moved-to") })

        assert.deepStrictEqual(yield* emails.to(user.email), [])
      })
    )
  })
})

describe.sequential("anonymous/refused sign-in", () => {
  layer(
    AnonymousTest.layer({
      hooks: { beforeSessionCreate: () => PolicyRefused.make({ code: "no_visitors" }) }
    })
  )("with a deployment that refuses visitors", (it) => {
    it.effect("leaves neither a user row nor a marker behind", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const users = yield* UserStore
        const sql = yield* SqlClient.SqlClient

        const before = yield* sql<{ readonly id: string }>`SELECT id FROM users`
        const markers = yield* sql<{ readonly user_id: string }>`SELECT user_id FROM effect_auth_anonymous`

        const refused = yield* Effect.flip(anonymous.signIn())
        assert.strictEqual(refused._tag, "PolicyRefused")

        // An unauthenticated caller reaches this endpoint, so a refusal that
        // still committed the row would let anybody fill the table at the rate
        // limit and leave it for the sweep.
        const after = yield* sql<{ readonly id: string }>`SELECT id FROM users`
        const stillMarkers = yield* sql<{ readonly user_id: string }>`SELECT user_id FROM effect_auth_anonymous`
        assert.strictEqual(after.length, before.length)
        assert.strictEqual(stillMarkers.length, markers.length)
        assert.isTrue(Option.isNone(yield* users.findByEmail("nobody@anonymous.invalid")))
      })
    )
  })
})

describe.sequential("anonymous/merge under a challenging pipeline", () => {
  /** Whether the merge callback of the block below was entered. */
  let mergeRan = false
  /** Whether the decider owes a second factor — see the note on it below. */
  let challenging = false

  layer(
    AnonymousTest.layer({
      anonymous: {
        onMerge: () =>
          Effect.sync(() => {
            mergeRan = true
          })
      },
      // A deployment with a second factor installed. The flag is what makes the
      // block usable: a decider that challenged unconditionally would also
      // challenge `anonymous.signIn`, which fails closed because a visitor
      // invented a millisecond ago has no factor to answer with.
      signInPipeline: {
        decide: () =>
          challenging
            ? Effect.map(DateTime.now, (now) => ({
                _tag: "Challenge" as const,
                kind: "totp",
                available: ["totp"],
                token: Redacted.make("pending-token"),
                expiresAt: DateTime.addDuration(now, Duration.minutes(10))
              }))
            : Effect.succeed({ _tag: "Proceed" as const })
      }
    })
  )("with a decider that owes a second factor", (it) => {
    it.effect("does not merge, and does not delete the visitor, on a challenge", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const passwords = yield* Passwords
        const users = yield* UserStore

        const visitor = yield* anonymous.signIn()
        const email = uniqueEmail("challenged-merge")
        const member = yield* signUpUser(email)
        mergeRan = false
        challenging = true

        const result = yield* passwords.signIn({
          email,
          password: testPassword,
          current: { session: visitor.session, user: visitor.user }
        })

        // The password was right, but a second factor is owed and no session
        // exists yet. If the merge had run at `beforeSessionCreate` the
        // visitor would already be deleted — and if the person now abandons the
        // prompt, their data is gone and they are signed in as nobody.
        assert.strictEqual(result._tag, "Challenge")
        assert.isFalse(mergeRan)
        assert.isTrue(Option.isSome(yield* users.findById(visitor.user.id)))
        assert.isTrue(yield* anonymous.isAnonymous(visitor.user.id))
        assert.isTrue(Option.isSome(yield* users.findById(member.user.id)))

        // And the visitor's own session still works, so they are still whoever
        // they were before they tried.
        const still = yield* anonymous.isAnonymous(visitor.user.id)
        assert.isTrue(still)
      })
    )
  })
})
