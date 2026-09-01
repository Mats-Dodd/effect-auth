import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Layer, Option, Redacted, Result } from "effect"
import { TestClock } from "effect/testing"
import * as Totp from "../../src/crypto/Totp.js"
import type { ProvisionSource } from "../../src/domain/Hooks.js"
import type { User } from "../../src/domain/Schema.js"
import type { Evidence } from "../../src/domain/Sessions.js"
import { meetsAssurance, Sessions } from "../../src/domain/Sessions.js"
import { provedSecondFactor } from "../../src/two-factor/Api.js"
import { SignIn } from "../../src/domain/SignIn.js"
import { encodeSubjectToken } from "../../src/domain/Verifications.js"
import { decode as decodeBase32 } from "../../src/internal/base32.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import * as TwoFactorTest from "../../src/testing/TwoFactorTest.js"
import { layer as storeLayer, TwoFactorStore } from "../../src/two-factor/Store.js"
import { TwoFactor } from "../../src/two-factor/TwoFactor.js"
import { signUpUser, uniqueEmail } from "../fixtures.js"

const testLayer = storeLayer.pipe(Layer.provideMerge(TwoFactorTest.layer()))

/** What a password sign-in proves, as the password flow states it. */
const passwordEvidence = {
  method: "password",
  factor: "knowledge",
  phishingResistant: false,
  restricted: false
} as const

/** What a user-verified passkey proves: two factors in one ceremony. */
const passkeyEvidence = {
  method: "passkey",
  factor: "possession",
  phishingResistant: true,
  restricted: false,
  userVerified: true
} as const

/** What a mailed link or code proves: control of the mailbox, and nothing else. */
const mailboxEvidence = {
  method: "emailOtp",
  factor: "possession",
  phishingResistant: false,
  restricted: false
} as const

const bytesOf = (secret: Redacted.Redacted): Uint8Array => {
  const decoded = decodeBase32(Redacted.value(secret))
  if (Result.isFailure(decoded)) throw new Error("the enrolment secret must be base32")
  return decoded.success
}

const codeAt = (secret: Redacted.Redacted, offset: number) =>
  Effect.gen(function* () {
    const now = yield* DateTime.now
    return Redacted.make(yield* Totp.generate({ secret: bytesOf(secret), step: Totp.stepAt(now) + offset }))
  })

layer(testLayer)("two-factor/pipeline", (it) => {
  const signInAs = (
    user: User,
    options?: {
      readonly evidence?: ReadonlyArray<Evidence>
      readonly source?: ProvisionSource
      readonly rememberMe?: boolean | undefined
    }
  ) =>
    Effect.gen(function* () {
      const signIn = yield* SignIn
      return yield* signIn.complete({
        user,
        source: options?.source ?? { _tag: "EmailPassword" },
        evidence: options?.evidence ?? [passwordEvidence],
        current: Option.none(),
        request: { rememberMe: options?.rememberMe, ipAddress: null, userAgent: null }
      })
    })

  const registered = (label: string) =>
    Effect.gen(function* () {
      const twoFactor = yield* TwoFactor
      const account = yield* signUpUser(uniqueEmail(label))
      return { twoFactor, ...account }
    })

  const enrolled = (label: string) =>
    Effect.gen(function* () {
      const account = yield* registered(label)
      const started = yield* account.twoFactor.startEnrolment(account.user)
      const codes = yield* account.twoFactor.confirmEnrolment(account.user, yield* codeAt(started.secret, 0))
      return { ...account, secret: started.secret, codes }
    })

  describe("the decider", () => {
    it.effect("challenges a password sign-in and mints nothing", () =>
      Effect.gen(function* () {
        const { user } = yield* enrolled("decide-password")
        const sessions = yield* Sessions
        const before = (yield* sessions.list(user.id)).length

        const result = yield* signInAs(user)

        assert.strictEqual(result._tag, "Challenge")
        if (result._tag !== "Challenge") return
        assert.strictEqual(result.kind, "two-factor")
        assert.deepStrictEqual(result.available, ["totp", "recoveryCode"])
        assert.isTrue(DateTime.isUtc(result.expiresAt))
        // A `sessions` row is a working credential everywhere in this library:
        // one that had cleared only the first factor would be a total bypass.
        assert.strictEqual((yield* sessions.list(user.id)).length, before)
      })
    )

    it.effect("lets somebody with no enrolment straight through", () =>
      Effect.gen(function* () {
        const { user } = yield* registered("decide-none")

        const result = yield* signInAs(user)

        assert.strictEqual(result._tag, "Complete")
      })
    )

    it.effect("lets somebody whose enrolment is still pending through, and does not ask for it", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("decide-pending")
        yield* twoFactor.startEnrolment(user)

        const result = yield* signInAs(user)

        // A pending enrolment is not a second factor. Challenging on one would
        // lock somebody out of the account they were half-way through securing.
        assert.strictEqual(result._tag, "Complete")
      })
    )

    it.effect("does not challenge a ceremony that already reached two factors", () =>
      Effect.gen(function* () {
        const { user } = yield* enrolled("decide-passkey")

        const result = yield* signInAs(user, { evidence: [passkeyEvidence] })

        // A user-verified passkey is a multi-factor authenticator in one
        // ceremony: asking for a code as well would be a second prompt for
        // nothing.
        assert.strictEqual(result._tag, "Complete")
        if (result._tag !== "Complete") return
        assert.strictEqual(result.session.aal, "aal2")
      })
    )

    it.effect("challenges every other path, which is the whole point of the seam", () =>
      Effect.gen(function* () {
        const { user } = yield* enrolled("decide-every-path")

        // A mailed link or code proves one factor, whatever flow sent it. The
        // prior art this is modelled on gated three named sign-in paths and let
        // a TOTP user in through the fourth with no second factor at all.
        const sources: ReadonlyArray<ProvisionSource> = [
          { _tag: "MagicLink" },
          { _tag: "Plugin", plugin: "email-otp" },
          {
            _tag: "OAuth",
            providerId: "github",
            info: { id: "1", email: "provider@example.com", emailVerified: true }
          }
        ]
        for (const source of sources) {
          const result = yield* signInAs(user, { evidence: [mailboxEvidence], source })
          assert.strictEqual(result._tag, "Challenge", `${source._tag} must be challenged like every other path`)
        }
      })
    )

    it.effect("offers only the factors this person can actually answer with", () =>
      Effect.gen(function* () {
        const { user } = yield* enrolled("decide-available")
        const store = yield* TwoFactorStore
        yield* store.deleteRecoveryCodes(user.id)

        const result = yield* signInAs(user)

        assert.strictEqual(result._tag, "Challenge")
        if (result._tag !== "Challenge") return
        assert.deepStrictEqual(result.available, ["totp"])
      })
    )
  })

  describe("the pending authentication", () => {
    /** Signs in far enough to be challenged, and hands back the token. */
    const challenged = (
      label: string,
      options?: {
        readonly rememberMe?: boolean
        readonly evidence?: ReadonlyArray<Evidence>
        readonly source?: ProvisionSource
      }
    ) =>
      Effect.gen(function* () {
        const account = yield* enrolled(label)
        const result = yield* signInAs(account.user, {
          rememberMe: options?.rememberMe,
          ...(options?.evidence === undefined ? {} : { evidence: options.evidence }),
          ...(options?.source === undefined ? {} : { source: options.source })
        })
        assert.strictEqual(result._tag, "Challenge")
        if (result._tag !== "Challenge") throw new Error("expected a challenge")
        return { ...account, token: result.token, expiresAt: result.expiresAt }
      })

    it.effect("completes the sign-in with the evidence of both factors", () =>
      Effect.gen(function* () {
        const { twoFactor, user, secret, token } = yield* challenged("pending-complete")

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: "203.0.113.9",
          userAgent: "a browser"
        })

        assert.strictEqual(result.user.id, user.id)
        assert.strictEqual(result.session.aal, "aal2")
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["password", "totp"]
        )
        // The first factor keeps the moment it actually happened rather than
        // being back-dated to the second.
        const [first, second] = result.session.methods
        assert.isTrue(DateTime.isLessThanOrEqualTo(first!.completedAt, second!.completedAt))
        assert.strictEqual(result.session.ipAddress, "203.0.113.9")
      })
    )

    it.effect("carries the interrupted sign-in's own answer about being remembered", () =>
      Effect.gen(function* () {
        const { twoFactor, secret, token } = yield* challenged("pending-remember", { rememberMe: false })

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        assert.isFalse(result.session.rememberMe)
        assert.isFalse(result.rememberMe)
      })
    )

    it.effect("is single-use", () =>
      Effect.gen(function* () {
        const { twoFactor, secret, token } = yield* challenged("pending-once")
        yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        const error = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "Totp", code: yield* codeAt(secret, 2) },
            subject: { _tag: "PendingAuth", token },
            ipAddress: null,
            userAgent: null
          })
        )

        assert.strictEqual(error._tag, "InvalidToken")
      })
    )

    it.effect("cannot be redeemed for a different user", () =>
      Effect.gen(function* () {
        const victim = yield* challenged("pending-victim")
        const attacker = yield* enrolled("pending-attacker")
        // The row is found by (purpose, subject) *and* the digest of the
        // secret, so re-addressing a token at another account names no row at
        // all — the subject is not a claim the holder gets to make.
        const parts = Redacted.value(victim.token).split(".")
        const forged = encodeSubjectToken(attacker.user.id, Redacted.make(parts[1]!))

        const error = yield* Effect.flip(
          attacker.twoFactor.verify({
            factor: { _tag: "Totp", code: yield* codeAt(attacker.secret, 1) },
            subject: { _tag: "PendingAuth", token: forged },
            ipAddress: null,
            userAgent: null
          })
        )

        assert.strictEqual(error._tag, "InvalidToken")
      })
    )

    it.effect("stops being answerable when it expires", () =>
      Effect.gen(function* () {
        const account = yield* enrolled("pending-expiry")

        const error = yield* AuthTest.freshClock(
          Effect.gen(function* () {
            const result = yield* signInAs(account.user)
            if (result._tag !== "Challenge") throw new Error("expected a challenge")
            yield* TestClock.adjust(Duration.minutes(11))
            return yield* Effect.flip(
              account.twoFactor.verify({
                factor: { _tag: "Totp", code: yield* codeAt(account.secret, 1) },
                subject: { _tag: "PendingAuth", token: result.token },
                ipAddress: null,
                userAgent: null
              })
            )
          })
        )

        assert.strictEqual(error._tag, "InvalidToken")
      })
    )

    it.effect("survives a wrong code: an attempt is spent, the sign-in is not", () =>
      Effect.gen(function* () {
        const { twoFactor, secret, token } = yield* challenged("pending-typo")

        const wrong = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "Totp", code: Redacted.make("000000") },
            subject: { _tag: "PendingAuth", token },
            ipAddress: null,
            userAgent: null
          })
        )
        assert.strictEqual(wrong._tag, "InvalidCode")

        // The row went back under the *same* handle, so the cookie the browser
        // is holding still names it.
        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })
        assert.strictEqual(result.session.aal, "aal2")
      })
    )

    it.effect("does not extend its own expiry when it is guessed at", () =>
      Effect.gen(function* () {
        const account = yield* enrolled("pending-no-extension")

        const error = yield* AuthTest.freshClock(
          Effect.gen(function* () {
            const result = yield* signInAs(account.user)
            if (result._tag !== "Challenge") throw new Error("expected a challenge")
            // Six minutes in, a wrong guess; the re-issue keeps what is left of
            // the original ten rather than starting them again.
            yield* TestClock.adjust(Duration.minutes(6))
            yield* Effect.flip(
              account.twoFactor.verify({
                factor: { _tag: "Totp", code: Redacted.make("000000") },
                subject: { _tag: "PendingAuth", token: result.token },
                ipAddress: null,
                userAgent: null
              })
            )
            yield* TestClock.adjust(Duration.minutes(5))
            return yield* Effect.flip(
              account.twoFactor.verify({
                factor: { _tag: "Totp", code: yield* codeAt(account.secret, 1) },
                subject: { _tag: "PendingAuth", token: result.token },
                ipAddress: null,
                userAgent: null
              })
            )
          })
        )

        assert.strictEqual(error._tag, "InvalidToken")
      })
    )

    it.effect("completes exactly once under concurrency", () =>
      Effect.gen(function* () {
        const { twoFactor, user, secret, token } = yield* challenged("pending-race")
        const sessions = yield* Sessions
        // Signing up established one; exactly one more may exist afterwards.
        const before = (yield* sessions.list(user.id)).length
        const code = yield* codeAt(secret, 1)
        const attempt = twoFactor.verify({
          factor: { _tag: "Totp", code },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        const outcomes = yield* Effect.all([Effect.result(attempt), Effect.result(attempt)], {
          concurrency: "unbounded"
        })

        assert.strictEqual(outcomes.filter((outcome) => outcome._tag === "Success").length, 1)
        assert.strictEqual((yield* sessions.list(user.id)).length, before + 1)
      })
    )

    it.effect("publishes the sign-in the interrupted flow would have published", () =>
      Effect.gen(function* () {
        const { twoFactor, user, secret, token } = yield* challenged("pending-event")

        const recorded = yield* AuthTest.recordingEvents(
          twoFactor.verify({
            factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
            subject: { _tag: "PendingAuth", token },
            ipAddress: null,
            userAgent: null
          })
        )

        const signedIn = recorded.events.find((event) => event._tag === "SignedIn" && event.userId === user.id)
        assert.isDefined(signedIn)
        if (signedIn === undefined || signedIn._tag !== "SignedIn") return
        // The entry point the sign-in came in through, carried across the
        // interruption, so a subscriber cannot tell a challenged password
        // sign-in from an unchallenged one by its `method`.
        assert.strictEqual(signedIn.method, "password")
        assert.deepStrictEqual(
          signedIn.methods.map((entry) => entry.method),
          ["password", "totp"]
        )
      })
    )
  })

  describe("a possession-only first factor", () => {
    /** Signs in far enough to be challenged from a first factor that is not a password. */
    const challengedBy = (label: string, evidence: ReadonlyArray<Evidence>, source: ProvisionSource) =>
      Effect.gen(function* () {
        const account = yield* enrolled(label)
        const result = yield* signInAs(account.user, { evidence, source })
        assert.strictEqual(result._tag, "Challenge")
        if (result._tag !== "Challenge") throw new Error("expected a challenge")
        return { ...account, token: result.token }
      })

    it.effect("completes a mailed-code sign-in, and lands at aal1", () =>
      Effect.gen(function* () {
        const { twoFactor, user, secret, token } = yield* challengedBy("possession-mail", [mailboxEvidence], {
          _tag: "Plugin",
          plugin: "email-otp"
        })

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["emailOtp", "totp"]
        )
        // Two possession entries are one factor kind, so the derivation is
        // aal1 and not aal2 — which is exactly why the decider's idempotence
        // test is keyed on the method rather than on the level. Keyed on the
        // level, this call would have been challenged a second time and
        // failed `PolicyRefused("mfa_required")` with the code already spent.
        assert.strictEqual(result.session.aal, "aal1")
      })
    )

    it.effect("completes an OAuth sign-in", () =>
      Effect.gen(function* () {
        const oauthEvidence = { ...mailboxEvidence, method: "oauth:github" } as const
        const { twoFactor, user, secret, token } = yield* challengedBy("possession-oauth", [oauthEvidence], {
          _tag: "OAuth",
          providerId: "github",
          info: { id: "1", email: "provider@example.com", emailVerified: true }
        })

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["oauth:github", "totp"]
        )
      })
    )

    it.effect("completes a passkey sign-in the authenticator did not verify a person for", () =>
      Effect.gen(function* () {
        const unverified = { ...passkeyEvidence, userVerified: false } as const
        const { twoFactor, user, secret, token } = yield* challengedBy("possession-passkey", [unverified], {
          _tag: "Plugin",
          plugin: "passkeys"
        })

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["passkey", "totp"]
        )
      })
    )

    it.effect("can still manage its enrolment afterwards, which `aal2` would have made impossible", () =>
      Effect.gen(function* () {
        const oauthEvidence = { ...mailboxEvidence, method: "oauth:github" } as const
        const { twoFactor, secret, token } = yield* challengedBy("possession-manage", [oauthEvidence], {
          _tag: "OAuth",
          providerId: "github",
          info: { id: "1", email: "provider@example.com", emailVerified: true }
        })

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })
        const now = yield* DateTime.now

        // This is the session that has *just* answered a second factor, and it
        // is `aal1` — two possession entries are one factor kind. An
        // `{ aal: "aal2" }` guard on `totp/disable` would refuse it, and no
        // call this library serves would ever change that answer: the account
        // would be permanently unable to turn off the factor it just enrolled.
        assert.strictEqual(result.session.aal, "aal1")
        assert.isFalse(meetsAssurance(result.session, { aal: "aal2" }, now))
        assert.isTrue(meetsAssurance(result.session, provedSecondFactor, now))
      })
    )

    it.effect("completes with a recovery code too", () =>
      Effect.gen(function* () {
        const { twoFactor, user, codes, token } = yield* challengedBy("possession-recovery", [mailboxEvidence], {
          _tag: "Plugin",
          plugin: "email-otp"
        })

        const result = yield* twoFactor.verify({
          factor: { _tag: "RecoveryCode", code: codes[0]! },
          subject: { _tag: "PendingAuth", token },
          ipAddress: null,
          userAgent: null
        })

        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["emailOtp", "recoveryCode"]
        )
      })
    )
  })
})
