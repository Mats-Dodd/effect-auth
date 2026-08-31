/**
 * The self-service endpoints, over HTTP: update-user, the two-hop change of
 * address, and account deletion in both of its shapes.
 *
 * **Details**
 *
 * These are the tests that exercise what only the endpoints own — the
 * configuration gate, the freshness guard, the rate-limit bucket, the cookies a
 * deletion clears and the redirect a confirmed one answers with. The service's
 * own rules are proved next door in `test/domain/Users.test.ts`; what is asserted
 * here is that a browser sees them.
 *
 * The generated client decodes every response through the API's own schemas, so
 * a body that did not match the contract fails the request rather than quietly
 * going unasserted.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { AuthHooksService } from "../../src/domain/Hooks.js"
import { PolicyRefused } from "../../src/domain/Hooks.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { expectSome, testPassword, uniqueEmail } from "../fixtures.js"
import { makeClient, signedUp } from "./helpers.js"

/** The deployment these tests run against: both opt-in flows switched on. */
const served: AuthTest.Options = {
  user: { changeEmail: { enabled: true }, deleteUser: { enabled: true } }
}

/**
 * A policy that allows the first deletion it is asked about and refuses every
 * one after it — which, on the mail-confirmed flow, is "yes" when the link is
 * asked for and "no" when it is followed.
 *
 * The counter is per-deployment, so the block built with it holds one test.
 */
const relentingHooks = (): AuthHooksService => {
  let consulted = 0
  return {
    beforeUserDelete: () =>
      Effect.suspend(() =>
        ++consulted === 1 ? Effect.void : Effect.fail(new PolicyRefused({ code: "changed_my_mind" }))
      )
  }
}

/** The token of the most recent e-mail of a kind sent to one address. */
const tokenFor = Effect.fnUntraced(function*(kind: string, address: string) {
  const emails = yield* AuthTest.TestEmails
  const sent = yield* expectSome(
    yield* emails.last(kind, address),
    `expected a ${kind} e-mail for ${address}`
  )
  return TestHttpClient.tokenOf(sent)
})

layer(AuthTest.layerHttp(served))("http/Users", (it) => {
  // ---------------------------------------------------------------------------
  // update-user
  // ---------------------------------------------------------------------------

  it.effect("edits the caller's own profile and answers with the stored row", () =>
    Effect.gen(function*() {
      const { client } = yield* signedUp(uniqueEmail("update"))

      const updated = yield* client.auth.updateUser({
        payload: { name: "Grace Hopper", image: "https://example.com/g.png" }
      })
      assert.strictEqual(updated.user.name, "Grace Hopper")
      assert.strictEqual(updated.user.image, "https://example.com/g.png")

      // The next request sees it too — this is a write, not a projection of the
      // request body.
      const current = yield* client.auth.getSession()
      assert.strictEqual(current.user.name, "Grace Hopper")

      // An absent key leaves the column alone; an explicit null clears it.
      const renamed = yield* client.auth.updateUser({ payload: { name: "Ada Byron" } })
      assert.strictEqual(renamed.user.image, "https://example.com/g.png")
      const cleared = yield* client.auth.updateUser({ payload: { image: null } })
      assert.strictEqual(cleared.user.image, null)
      assert.strictEqual(cleared.user.name, "Ada Byron")

      // The response is the public projection: no hash, no digest, no address
      // change smuggled in through a body key the schema does not declare.
      assert.notInclude(JSON.stringify(cleared), "passwordHash")
    }))

  it.effect("refuses to edit a profile without a session", () =>
    Effect.gen(function*() {
      const { client } = yield* makeClient()
      const refused = yield* Effect.flip(client.auth.updateUser({ payload: { name: "Nobody" } }))
      assert.strictEqual(refused._tag, "Unauthorized")
    }))

  // ---------------------------------------------------------------------------
  // change-email
  // ---------------------------------------------------------------------------

  it.effect("moves a verified account in two hops, and only the second one moves it", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("hop-http")
      const newEmail = uniqueEmail("hop-http-new")
      const { client } = yield* signedUp(email)

      // Give the account a verified address, so the flow has somebody to warn.
      yield* client.auth.sendVerificationEmail({ payload: { email } })
      yield* client.auth.verifyEmail({ query: { token: yield* tokenFor("verification", email) } })
      assert.isTrue((yield* client.auth.getSession()).user.emailVerified)

      // --- hop one: the address the account has now is told ----------------
      const started = yield* client.auth.changeEmail({ payload: { newEmail } })
      assert.strictEqual(started.success, true)
      const confirmation = yield* tokenFor(AuthTest.changeEmailConfirmationKind, email)

      yield* client.auth.confirmEmailChange({ query: { token: confirmation } })
      // Nothing has moved yet.
      assert.strictEqual((yield* client.auth.getSession()).user.email, email)

      // --- hop two: the new address proves it is read ----------------------
      const verification = yield* tokenFor(AuthTest.changeEmailVerificationKind, newEmail)
      yield* client.auth.verifyEmailChange({ query: { token: verification } })

      const moved = yield* client.auth.getSession()
      assert.strictEqual(moved.user.email, newEmail)
      // The link was delivered to the new address, which is the whole of what
      // verification means.
      assert.isTrue(moved.user.emailVerified)

      // The credential moved with the row.
      yield* client.auth.signOut()
      const back = yield* client.auth.signInEmail({ payload: { email: newEmail, password: testPassword } })
      assert.strictEqual(back.user.email, newEmail)
    }))

  it.effect("starts an unverified account at the second hop", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("hop-http-unverified")
      const newEmail = uniqueEmail("hop-http-unverified-new")
      const { client } = yield* signedUp(email)
      const emails = yield* AuthTest.TestEmails

      yield* client.auth.changeEmail({ payload: { newEmail } })

      // No first hop: an unverified address is no evidence that anybody reads it.
      assert.deepStrictEqual(yield* emails.to(email), [])
      yield* client.auth.verifyEmailChange({
        query: { token: yield* tokenFor(AuthTest.changeEmailVerificationKind, newEmail) }
      })
      assert.strictEqual((yield* client.auth.getSession()).user.email, newEmail)
    }))

  it.effect("answers an address somebody else has exactly as one that is free", () =>
    Effect.gen(function*() {
      const occupied = uniqueEmail("taken-http")
      yield* signedUp(occupied)
      const { client } = yield* signedUp(uniqueEmail("taken-http-caller"))
      const emails = yield* AuthTest.TestEmails

      // 200, like every other outcome: a signed-in session must not be an
      // oracle for who else is registered here.
      const answered = yield* client.auth.changeEmail({ payload: { newEmail: occupied } })
      assert.strictEqual(answered.success, true)
      // And the occupant hears nothing about it.
      assert.deepStrictEqual(yield* emails.to(occupied), [])
    }))

  it.effect("refuses the address the account already has", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("unchanged-http")
      const { client } = yield* signedUp(email)

      const refused = yield* Effect.flip(client.auth.changeEmail({ payload: { newEmail: email } }))
      assert.strictEqual(refused._tag, "EmailUnchanged")
    }))

  it.effect("reports a link that is not one of ours as InvalidToken", () =>
    Effect.gen(function*() {
      const { client } = yield* makeClient()

      // Both hops are unauthenticated: the person following the link may be in
      // a browser that holds nobody's session.
      const confirm = yield* Effect.flip(client.auth.confirmEmailChange({ query: { token: "nonsense" } }))
      assert.strictEqual(confirm._tag, "InvalidToken")
      const verify = yield* Effect.flip(client.auth.verifyEmailChange({ query: { token: "nonsense" } }))
      assert.strictEqual(verify._tag, "InvalidToken")
    }))

  // ---------------------------------------------------------------------------
  // delete-user, direct
  // ---------------------------------------------------------------------------

  it.effect("deletes the account outright, and the browser is signed out with it", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("delete-http")
      const { client, cookies } = yield* signedUp(email)

      const deleted = yield* client.auth.deleteUser({ payload: {} })
      assert.deepStrictEqual(deleted, { success: true, status: "Deleted" })

      // The credential in this browser is dead and must not look alive.
      assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")
      const refused = yield* Effect.flip(client.auth.getSession())
      assert.strictEqual(refused._tag, "Unauthorized")

      // And the address is free again.
      const revived = yield* signedUp(email)
      assert.strictEqual(revived.user.email, email)
    }))

  it.effect("refuses a password that is not the caller's, and keeps the account", () =>
    Effect.gen(function*() {
      const { client } = yield* signedUp(uniqueEmail("delete-http-password"))

      const refused = yield* Effect.flip(
        client.auth.deleteUser({ payload: { password: Redacted.make("not the password") } })
      )
      assert.strictEqual(refused._tag, "InvalidCredentials")
      // Still signed in, still there.
      yield* client.auth.getSession()

      const gone = yield* client.auth.deleteUser({ payload: { password: testPassword } })
      assert.strictEqual(gone.status, "Deleted")
    }))

  it.effect("does not serve the callback to a browser with no session", () =>
    Effect.gen(function*() {
      const { client } = yield* makeClient()
      const refused = yield* Effect.flip(
        client.auth.deleteUserCallback({ query: { token: "nonsense" } })
      )
      assert.strictEqual(refused._tag, "Unauthorized")
    }))

  // ---------------------------------------------------------------------------
  // delete-user, confirmed by mail
  // ---------------------------------------------------------------------------

  it.layer(AuthTest.layerHttp({ user: { deleteUser: { enabled: true, confirmByEmail: true } } }))(
    "with deletion confirmed by e-mail",
    (it) => {
      it.effect("mails a link, and the account goes when that link is followed", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("delete-confirm-http")
          const { client, cookies } = yield* signedUp(email)

          const asked = yield* client.auth.deleteUser({ payload: { callbackURL: "/farewell" } })
          assert.deepStrictEqual(asked, { success: true, status: "ConfirmationSent" })
          // Nothing has been deleted: the session still resolves.
          yield* client.auth.getSession()

          const token = yield* tokenFor(AuthTest.deleteAccountKind, email)
          const [, response] = yield* client.auth.deleteUserCallback({
            query: { token },
            responseMode: "decoded-and-response"
          })

          assert.strictEqual(response.status, 302)
          assert.strictEqual(response.headers["location"], "http://localhost:3000/farewell")
          assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")
          const refused = yield* Effect.flip(client.auth.getSession())
          assert.strictEqual(refused._tag, "Unauthorized")
        }))

      it.effect("burns a link presented by somebody else's browser", () =>
        Effect.gen(function*() {
          const owner = yield* signedUp(uniqueEmail("delete-confirm-owner"))
          const stranger = yield* signedUp(uniqueEmail("delete-confirm-stranger"))

          yield* owner.client.auth.deleteUser({ payload: {} })
          const token = yield* tokenFor(AuthTest.deleteAccountKind, owner.email)

          // The token is claimed before the caller is checked, so a link read
          // out of somebody else's mailbox is spent as well as refused.
          const refused = yield* Effect.flip(stranger.client.auth.deleteUserCallback({ query: { token } }))
          assert.strictEqual(refused._tag, "InvalidToken")
          // Neither account went anywhere.
          yield* owner.client.auth.getSession()
          yield* stranger.client.auth.getSession()

          const spent = yield* Effect.flip(owner.client.auth.deleteUserCallback({ query: { token } }))
          assert.strictEqual(spent._tag, "InvalidToken")
        }))
    }
  )

  // ---------------------------------------------------------------------------
  // The deployment's own policy hooks
  // ---------------------------------------------------------------------------

  it.layer(AuthTest.layerHttp({
    ...served,
    hooks: {
      beforeEmailChange: ({ newEmail }) =>
        Effect.fail(new PolicyRefused({ code: "address_frozen", detail: newEmail.length.toString() })),
      beforeUserDelete: () => Effect.fail(new PolicyRefused({ code: "under_contract" }))
    }
  }))("with a policy that refuses both flows", (it) => {
    it.effect("answers a refused change of address with 403 and the hook's code", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("veto-change")
        const { client } = yield* signedUp(email)
        const emails = yield* AuthTest.TestEmails

        const refused = yield* Effect.flip(
          client.auth.changeEmail({ payload: { newEmail: uniqueEmail("veto-change-new") } })
        )
        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") {
          assert.strictEqual(refused.code, "address_frozen")
        }

        // The hook runs before anything is minted or mailed, so a refusal leaves
        // the flow exactly where it was.
        assert.deepStrictEqual(yield* emails.to(email), [])
        assert.strictEqual((yield* client.auth.getSession()).user.email, email)
      }))

    it.effect("answers a refused deletion with 403, and the account is still there", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("veto-delete")
        const { client } = yield* signedUp(email)

        const refused = yield* Effect.flip(client.auth.deleteUser({ payload: {} }))
        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") {
          assert.strictEqual(refused.code, "under_contract")
        }

        // Still signed in, still there — a refusal is a caller error, not a
        // half-finished deletion.
        assert.strictEqual((yield* client.auth.getSession()).user.email, email)
      }))

    it.effect("still refuses the address the account already has before consulting the hook", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("veto-unchanged")
        const { client } = yield* signedUp(email)

        // `EmailUnchanged` is decided from the caller's own address and leaks
        // nothing, so a policy does not get to reclassify it.
        const refused = yield* Effect.flip(client.auth.changeEmail({ payload: { newEmail: email } }))
        assert.strictEqual(refused._tag, "EmailUnchanged")
      }))
  })

  // A hook that allows the request and refuses the confirmation, so the link is
  // minted and then declined. It closes over a counter, so the block holds
  // exactly one test: a sibling would move it.
  it.layer(AuthTest.layerHttp({
    user: { deleteUser: { enabled: true, confirmByEmail: true } },
    hooks: relentingHooks()
  }))("with a policy that changes its mind between the two hops", (it) => {
    it.effect("redirects a refused link and burns it anyway", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("veto-callback")
        const { client, cookies } = yield* signedUp(email)

        // Consultation one: allowed, so the link goes out.
        const asked = yield* client.auth.deleteUser({ payload: { callbackURL: "/farewell" } })
        assert.strictEqual(asked.status, "ConfirmationSent")
        const token = yield* tokenFor(AuthTest.deleteAccountKind, email)

        // Consultation two: refused. The browser arrived by a top-level
        // navigation, so it leaves by one carrying the classification and the
        // deployment's own code.
        const [, response] = yield* client.auth.deleteUserCallback({
          query: { token },
          responseMode: "decoded-and-response"
        })
        assert.strictEqual(response.status, 302)
        const location = response.headers["location"] ?? ""
        assert.include(location, "error=policy_refused")
        assert.include(location, "code=changed_my_mind")

        // Nothing was deleted and nobody was signed out.
        assert.notStrictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")
        assert.strictEqual((yield* client.auth.getSession()).user.email, email)

        // The token was claimed before the hook was asked, so the refused link
        // is spent: presenting it again is an unknown token, not a second
        // refusal.
        const spent = yield* Effect.flip(client.auth.deleteUserCallback({ query: { token } }))
        assert.strictEqual(spent._tag, "InvalidToken")
      }))
  })

  // ---------------------------------------------------------------------------
  // The guards that need a clock of their own
  // ---------------------------------------------------------------------------

  // Nested rather than a second top-level `layer()`: an `it.layer` forks this
  // block's memo map, so the deployment below reuses the PGlite the block above
  // already booted instead of standing up a second one for the file.
  it.layer(AuthTest.layerHttpMovingClock(served))("freshness and expiry", (it) => {
    // The three of them share the deployment's clock, so they have to run in
    // order: a sibling's `adjust` would otherwise age this test's session out
    // from under it.
    describe.sequential("on the deployment's own clock", () => {
      it.effect("refuses to start an e-mail change from a stale session", () =>
        Effect.gen(function*() {
          const { client } = yield* signedUp(uniqueEmail("stale-change"))

          // `session.freshAge` is a day. The address is the account's recovery
          // path, so a cookie that has been lying around must not be enough to
          // start moving it.
          yield* TestClock.adjust(Duration.days(2))
          const refused = yield* Effect.flip(
            client.auth.changeEmail({ payload: { newEmail: uniqueEmail("stale-change-new") } })
          )
          assert.strictEqual(refused._tag, "SessionNotFresh")
        }))

      it.effect("refuses to delete an account from a stale session", () =>
        Effect.gen(function*() {
          const { client } = yield* signedUp(uniqueEmail("stale-delete"))

          yield* TestClock.adjust(Duration.days(2))
          const refused = yield* Effect.flip(client.auth.deleteUser({ payload: {} }))
          assert.strictEqual(refused._tag, "SessionNotFresh")
          // And the account is still there — the session simply has to be renewed.
          yield* client.auth.getSession()
        }))

      it.effect("expires a change-email link an hour after it was minted", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("expiring-link")
          const newEmail = uniqueEmail("expiring-link-new")
          const { client } = yield* signedUp(email)

          yield* client.auth.changeEmail({ payload: { newEmail } })
          const token = yield* tokenFor(AuthTest.changeEmailVerificationKind, newEmail)

          // `tokens.changeEmailTtl` is an hour by default.
          yield* TestClock.adjust(Duration.hours(2))
          const refused = yield* Effect.flip(client.auth.verifyEmailChange({ query: { token } }))
          assert.strictEqual(refused._tag, "InvalidToken")
          assert.strictEqual((yield* client.auth.getSession()).user.email, email)
        }))
    })
  })

  // ---------------------------------------------------------------------------
  // The counters
  // ---------------------------------------------------------------------------

  it.layer(AuthTest.layerHttp({
    ...served,
    rateLimit: { enabled: true, ipHeaders: ["x-forwarded-for"] }
  }))(
    "with the rate limits switched on",
    (it) => {
      it.effect("refuses the fourth change-email attempt in a window", () =>
        Effect.gen(function*() {
          const headers = { "x-forwarded-for": "203.0.113.21" }
          const { client } = yield* signedUp(uniqueEmail("limited-change"), { headers })

          // The endpoint answers 200 whatever the address, so the counter is the
          // only thing standing between a signed-in session and an unbounded
          // supply of outbound mail.
          for (let i = 0; i < 3; i++) {
            yield* client.auth.changeEmail({ payload: { newEmail: uniqueEmail(`limited-${i}`) } })
          }
          const limited = yield* Effect.flip(
            client.auth.changeEmail({ payload: { newEmail: uniqueEmail("limited-4") } })
          )
          assert.strictEqual(limited._tag, "RateLimited")
          if (limited._tag === "RateLimited") {
            assert.isAbove(limited.retryAfterSeconds, 0)
          }
        }))

      it.effect("counts delete-user on a bucket of its own", () =>
        Effect.gen(function*() {
          const headers = { "x-forwarded-for": "203.0.113.22" }
          const { client } = yield* signedUp(uniqueEmail("limited-delete"), { headers })

          // Three refusals of the wrong password, and the fourth attempt is
          // refused by the counter instead — the key carries the path, so this
          // browser's change-email attempts are counted separately.
          for (let i = 0; i < 3; i++) {
            const refused = yield* Effect.flip(
              client.auth.deleteUser({ payload: { password: Redacted.make("guess number one") } })
            )
            assert.strictEqual(refused._tag, "InvalidCredentials")
          }
          const limited = yield* Effect.flip(
            client.auth.deleteUser({ payload: { password: Redacted.make("guess number two") } })
          )
          assert.strictEqual(limited._tag, "RateLimited")

          // A different caller is counted separately, and still gets in.
          const innocent = yield* signedUp(uniqueEmail("limited-delete-other"), {
            headers: { "x-forwarded-for": "203.0.113.23" }
          })
          assert.strictEqual((yield* innocent.client.auth.deleteUser({ payload: {} })).status, "Deleted")
        }))
    }
  )
})
