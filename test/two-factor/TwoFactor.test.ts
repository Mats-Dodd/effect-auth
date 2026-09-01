import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Layer, Option, Redacted, Result } from "effect"
import { TestClock } from "effect/testing"
import * as Totp from "../../src/crypto/Totp.js"
import { AuthEvents } from "../../src/domain/Events.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { decode as decodeBase32 } from "../../src/internal/base32.js"
import { TestEmails } from "../../src/testing/TestEmails.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import * as TwoFactorTest from "../../src/testing/TwoFactorTest.js"
import { layer as storeLayer, TwoFactorStore } from "../../src/two-factor/Store.js"
import { TwoFactor } from "../../src/two-factor/TwoFactor.js"
import { signUpUser, uniqueEmail } from "../fixtures.js"

/** The raw bytes behind the base32 secret an enrolment answers with. */
const bytesOf = (secret: Redacted.Redacted): Uint8Array => {
  const decoded = decodeBase32(Redacted.value(secret))
  if (Result.isFailure(decoded)) throw new Error("the enrolment secret must be base32")
  return decoded.success
}

/** The code an authenticator app would be showing `offset` steps from now. */
const codeAt = (secret: Redacted.Redacted, offset: number) =>
  Effect.gen(function* () {
    const now = yield* DateTime.now
    const code = yield* Totp.generate({ secret: bytesOf(secret), step: Totp.stepAt(now) + offset })
    return Redacted.make(code)
  })

/**
 * The plugin over a test deployment, with its store beside it so a test can
 * look at the rows the service wrote rather than only at what it answered.
 */
const testLayer = storeLayer.pipe(Layer.provideMerge(TwoFactorTest.layer()))

layer(testLayer)("two-factor/TwoFactor", (it) => {
  /** A registered account with nothing enrolled. */
  const registered = (label: string) =>
    Effect.gen(function* () {
      const twoFactor = yield* TwoFactor
      const account = yield* signUpUser(uniqueEmail(label))
      return { twoFactor, ...account }
    })

  /**
   * A registered account with a confirmed enrolment.
   *
   * The confirming code is the one for the current step, and confirming records
   * it — so everything after this authenticates with `codeAt(secret, 1)`, which
   * is the next step and inside the default window.
   */
  const enrolled = (label: string) =>
    Effect.gen(function* () {
      const account = yield* registered(label)
      const started = yield* account.twoFactor.startEnrolment(account.user)
      const codes = yield* account.twoFactor.confirmEnrolment(account.user, yield* codeAt(started.secret, 0))
      return { ...account, secret: started.secret, codes }
    })

  describe("enrolment", () => {
    it.effect("answers a base32 secret and the URI an authenticator app scans", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("enrol")

        const started = yield* twoFactor.startEnrolment(user)

        const secret = Redacted.value(started.secret)
        assert.match(secret, /^[A-Z2-7]+$/, "RFC 4648 base32, uppercase and unpadded")
        assert.strictEqual(bytesOf(started.secret).length, 20)
        const uri = Redacted.value(started.otpauthUri)
        assert.isTrue(uri.startsWith("otpauth://totp/"))
        assert.include(uri, `secret=${secret}`)
        assert.include(uri, encodeURIComponent(user.email))
        // Redacted, so nothing between here and the page can log either.
        assert.strictEqual(String(started.secret), "<redacted>")
        assert.strictEqual(String(started.otpauthUri), "<redacted>")
      })
    )

    it.effect("is pending until a code proves it, and a pending enrolment never authenticates", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session } = yield* registered("enrol-pending")
        const store = yield* TwoFactorStore
        const started = yield* twoFactor.startEnrolment(user)

        const stored = yield* store.findTotp(user.id)
        assert.strictEqual(Option.getOrThrow(stored).verifiedAt, null)

        // A code that is arithmetically correct, against an enrolment nobody
        // has proved: refused, and indistinguishably from a wrong one.
        const error = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "Totp", code: yield* codeAt(started.secret, 0) },
            subject: { _tag: "Session", session, user },
            ipAddress: null,
            userAgent: null
          })
        )
        assert.strictEqual(error._tag, "InvalidCode")
      })
    )

    it.effect("abandoning a pending enrolment regenerates it", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("enrol-again")

        const first = yield* twoFactor.startEnrolment(user)
        const second = yield* twoFactor.startEnrolment(user)

        assert.notStrictEqual(Redacted.value(second.secret), Redacted.value(first.secret))
        // And the abandoned secret is gone: only the newest one can confirm.
        const stale = yield* Effect.flip(twoFactor.confirmEnrolment(user, yield* codeAt(first.secret, 0)))
        assert.strictEqual(stale._tag, "InvalidCode")
      })
    )

    it.effect("refuses to re-enrol over a confirmed enrolment", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* enrolled("enrol-confirmed")

        const error = yield* Effect.flip(twoFactor.startEnrolment(user))

        assert.strictEqual(error._tag, "TotpAlreadyEnrolled")
      })
    )

    it.effect("refuses a wrong code and leaves the enrolment pending", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("enrol-wrong")
        const store = yield* TwoFactorStore
        yield* twoFactor.startEnrolment(user)

        const error = yield* Effect.flip(twoFactor.confirmEnrolment(user, Redacted.make("000000")))

        assert.strictEqual(error._tag, "InvalidCode")
        assert.strictEqual(Option.getOrThrow(yield* store.findTotp(user.id)).verifiedAt, null)
      })
    )

    it.effect("answers ten recovery codes, once, in the printed format", () =>
      Effect.gen(function* () {
        const { codes } = yield* enrolled("enrol-codes")

        assert.strictEqual(codes.length, 10)
        for (const code of codes) {
          assert.match(Redacted.value(code), /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/)
          assert.strictEqual(String(code), "<redacted>")
        }
        assert.strictEqual(new Set(codes.map(Redacted.value)).size, 10)
      })
    )

    it.effect("stores a keyed digest of each code and not the code", () =>
      Effect.gen(function* () {
        const { user, codes } = yield* enrolled("enrol-hashes")
        const store = yield* TwoFactorStore
        const normalised = Redacted.value(codes[0]!).replaceAll("-", "")
        const now = yield* DateTime.now

        // The code itself is not what the row is matched by, and neither is
        // any unkeyed digest of it: the only thing that spends a code is the
        // keyed digest the service computes.
        assert.isFalse(yield* store.consumeRecoveryCode(user.id, normalised, now))
        assert.strictEqual(yield* store.countRecoveryCodes(user.id), 10)
      })
    )

    it.effect("cannot be confirmed twice, and the confirming code cannot then sign anybody in", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, secret } = yield* enrolled("enrol-twice")

        const again = yield* Effect.flip(twoFactor.confirmEnrolment(user, yield* codeAt(secret, 0)))
        assert.strictEqual(again._tag, "TotpAlreadyEnrolled")

        // The step that proved the enrolment was recorded by the same
        // statement that made it active.
        const replayed = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "Totp", code: yield* codeAt(secret, 0) },
            subject: { _tag: "Session", session, user },
            ipAddress: null,
            userAgent: null
          })
        )
        assert.strictEqual(replayed._tag, "InvalidCode")
      })
    )

    it.effect("refuses a pending enrolment nobody finished within the window", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("enrol-expired")
        const started = yield* twoFactor.startEnrolment(user)

        const error = yield* AuthTest.freshClock(
          Effect.gen(function* () {
            yield* TestClock.adjust(Duration.minutes(16))
            return yield* Effect.flip(twoFactor.confirmEnrolment(user, yield* codeAt(started.secret, 0)))
          })
        )

        assert.strictEqual(error._tag, "TotpNotEnrolled")
      })
    )
  })

  describe("raising a session", () => {
    it.effect("elevates it to aal2, records the evidence and rotates the token", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, token, secret } = yield* enrolled("raise")
        const sessions = yield* Sessions

        const result = yield* twoFactor.verify({
          factor: { _tag: "Totp", code: yield* codeAt(secret, 1) },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })

        assert.strictEqual(result.session.id, session.id, "an open tab must survive a step-up")
        assert.strictEqual(result.session.aal, "aal2")
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["password", "totp"]
        )
        assert.notStrictEqual(Redacted.value(result.token), Redacted.value(token))
        // The token captured at aal1 does not inherit aal2.
        const stale = yield* Effect.flip(sessions.verify(token))
        assert.strictEqual(stale._tag, "Unauthorized")
      })
    )

    it.effect("refuses the same code twice", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, secret } = yield* enrolled("raise-replay")
        const code = yield* codeAt(secret, 1)

        const first = yield* twoFactor.verify({
          factor: { _tag: "Totp", code },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })
        const error = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "Totp", code },
            subject: { _tag: "Session", session: first.session, user },
            ipAddress: null,
            userAgent: null
          })
        )

        assert.strictEqual(error._tag, "InvalidCode")
      })
    )

    it.effect("lets exactly one of two concurrent submissions of one code through", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, secret } = yield* enrolled("raise-race")
        const code = yield* codeAt(secret, 1)
        const attempt = twoFactor.verify({
          factor: { _tag: "Totp", code },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })

        const outcomes = yield* Effect.all([Effect.result(attempt), Effect.result(attempt)], {
          concurrency: "unbounded"
        })

        assert.strictEqual(outcomes.filter((outcome) => outcome._tag === "Success").length, 1)
      })
    )

    it.effect("refuses a code that belongs to somebody else's enrolment", () =>
      Effect.gen(function* () {
        const mine = yield* enrolled("raise-mine")
        const theirs = yield* enrolled("raise-theirs")

        const error = yield* Effect.flip(
          mine.twoFactor.verify({
            factor: { _tag: "Totp", code: yield* codeAt(theirs.secret, 1) },
            subject: { _tag: "Session", session: mine.session, user: mine.user },
            ipAddress: null,
            userAgent: null
          })
        )

        assert.strictEqual(error._tag, "InvalidCode")
      })
    )
  })

  describe("recovery codes", () => {
    it.effect("spends one, records that it was used, and notifies its owner", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, codes } = yield* enrolled("recovery-use")
        const emails = yield* TestEmails

        const result = yield* twoFactor.verify({
          factor: { _tag: "RecoveryCode", code: codes[0]! },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })

        assert.strictEqual(result.session.aal, "aal2")
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["password", "recoveryCode"]
        )
        const sent = yield* emails.last(TwoFactorTest.recoveryCodeUsedKind, user.email)
        assert.isTrue(Option.isSome(sent), "spending a recovery code must reach the account's owner")
        assert.strictEqual(Redacted.value(Option.getOrThrow(sent).token), "9")
      })
    )

    it.effect("accepts a code however it was transcribed, and only once", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, codes } = yield* enrolled("recovery-format")
        const printed = Redacted.value(codes[0]!)

        const result = yield* twoFactor.verify({
          // Lower case, no dashes, and a stray space: the same code.
          factor: { _tag: "RecoveryCode", code: Redacted.make(` ${printed.toLowerCase().replaceAll("-", "")} `) },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })

        const again = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "RecoveryCode", code: codes[0]! },
            subject: { _tag: "Session", session: result.session, user },
            ipAddress: null,
            userAgent: null
          })
        )
        assert.strictEqual(again._tag, "InvalidCode")
      })
    )

    it.effect("regenerating retires every previous code", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, codes } = yield* enrolled("recovery-regenerate")

        const replacement = yield* twoFactor.regenerateRecoveryCodes(user)

        assert.strictEqual(replacement.length, 10)
        assert.strictEqual(
          new Set([...codes, ...replacement].map(Redacted.value)).size,
          20,
          "a regenerated set shares nothing with the old one"
        )
        const error = yield* Effect.flip(
          twoFactor.verify({
            factor: { _tag: "RecoveryCode", code: codes[0]! },
            subject: { _tag: "Session", session, user },
            ipAddress: null,
            userAgent: null
          })
        )
        assert.strictEqual(error._tag, "InvalidCode")
      })
    )

    it.effect("cannot be regenerated by somebody with no confirmed enrolment", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("recovery-none")
        yield* twoFactor.startEnrolment(user)

        const error = yield* Effect.flip(twoFactor.regenerateRecoveryCodes(user))

        assert.strictEqual(error._tag, "TotpNotEnrolled")
      })
    )
  })

  describe("turning it off", () => {
    it.effect("removes the enrolment, the codes and the devices", () =>
      Effect.gen(function* () {
        const { twoFactor, user, codes } = yield* enrolled("disable")
        const store = yield* TwoFactorStore
        yield* twoFactor.trustDevice({ userId: user.id, ipAddress: null, userAgent: null })

        yield* twoFactor.disable(user)

        assert.isTrue(Option.isNone(yield* store.findTotp(user.id)))
        assert.strictEqual(yield* store.countRecoveryCodes(user.id), 0)
        assert.strictEqual((yield* twoFactor.listDevices(user.id, Option.none())).length, 0)
        // And the codes are worth nothing afterwards.
        const now = yield* DateTime.now
        assert.isFalse(yield* store.consumeRecoveryCode(user.id, Redacted.value(codes[0]!), now))
      })
    )

    it.effect("refuses when there is nothing to remove", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* registered("disable-none")

        const error = yield* Effect.flip(twoFactor.disable(user))

        assert.strictEqual(error._tag, "TotpNotEnrolled")
      })
    )
  })

  describe("trusted devices", () => {
    it.effect("remembers a browser and marks the one that asked", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* enrolled("device-current")

        const issued = yield* twoFactor.trustDevice({
          userId: user.id,
          ipAddress: "198.51.100.4",
          userAgent: "a browser",
          label: "laptop"
        })

        const listed = yield* twoFactor.listDevices(user.id, Option.some(Redacted.value(issued.value)))
        assert.strictEqual(listed.length, 1)
        assert.strictEqual(listed[0]?.label, "laptop")
        assert.isTrue(listed[0]?.current, "the browser presenting the cookie is its own device")
        // And to a browser holding nothing, or somebody else's cookie, it is
        // just a row.
        const anonymous = yield* twoFactor.listDevices(user.id, Option.none())
        assert.isFalse(anonymous[0]?.current)
      })
    )

    it.effect("is a cookie the deployment signed, bound to its owner", () =>
      Effect.gen(function* () {
        const mine = yield* enrolled("device-bound")
        const theirs = yield* enrolled("device-bound-other")
        const issued = yield* mine.twoFactor.trustDevice({
          userId: mine.user.id,
          ipAddress: null,
          userAgent: null
        })

        // The envelope names the user it was minted for, so it cannot be tried
        // against another account even before the row is consulted.
        const listed = yield* theirs.twoFactor.listDevices(theirs.user.id, Option.some(Redacted.value(issued.value)))
        assert.deepStrictEqual(listed, [])
        // And a value this deployment did not sign is not a cookie at all.
        const forged = yield* mine.twoFactor.listDevices(mine.user.id, Option.some("not-an-envelope"))
        assert.isFalse(forged[0]?.current)
      })
    )

    it.effect("forgets one, and forgets them all", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* enrolled("device-revoke")
        const first = yield* twoFactor.trustDevice({ userId: user.id, ipAddress: null, userAgent: null })
        yield* twoFactor.trustDevice({ userId: user.id, ipAddress: null, userAgent: null })

        assert.isTrue(yield* twoFactor.revokeDevice(first.device.id, user.id))
        assert.isFalse(yield* twoFactor.revokeDevice(first.device.id, user.id))
        assert.strictEqual(yield* twoFactor.revokeDevices(user.id), 1)
        assert.deepStrictEqual(yield* twoFactor.listDevices(user.id, Option.none()), [])
      })
    )

    it.effect("is forgotten when a recovery code is spent", () =>
      Effect.gen(function* () {
        const { twoFactor, user, session, codes } = yield* enrolled("device-recovery")
        yield* twoFactor.trustDevice({ userId: user.id, ipAddress: null, userAgent: null })

        yield* twoFactor.verify({
          factor: { _tag: "RecoveryCode", code: codes[0]! },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })

        assert.deepStrictEqual(yield* twoFactor.listDevices(user.id, Option.none()), [])
      })
    )

    it.effect("is forgotten when the password or the address changes, or every session is revoked", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* enrolled("device-sweep")

        const swept = (event: Parameters<typeof twoFactor.sweepOn>[0]) =>
          Effect.gen(function* () {
            yield* twoFactor.trustDevice({ userId: user.id, ipAddress: null, userAgent: null })
            yield* twoFactor.sweepOn(event)
            return (yield* twoFactor.listDevices(user.id, Option.none())).length
          })

        assert.strictEqual(yield* swept({ _tag: "PasswordChanged", userId: user.id, viaReset: false }), 0)
        assert.strictEqual(yield* swept({ _tag: "PasswordChanged", userId: user.id, viaReset: true }), 0)
        assert.strictEqual(
          yield* swept({ _tag: "EmailChanged", userId: user.id, previousEmail: "a@b.c", email: user.email }),
          0
        )
        assert.strictEqual(
          yield* swept({ _tag: "SessionRevoked", userId: user.id, sessionId: null, scope: "all", count: 2 }),
          0
        )
        // And nothing else sweeps: signing in on one device must not sign the
        // others' trust away.
        assert.strictEqual(
          yield* swept({
            _tag: "SessionRevoked",
            userId: user.id,
            sessionId: null,
            scope: "others",
            count: 1
          }),
          1
        )
        yield* twoFactor.revokeDevices(user.id)
      })
    )

    it.effect("is forgotten by the plugin's own subscription, not only by a call to sweepOn", () =>
      Effect.gen(function* () {
        const { twoFactor, user } = yield* enrolled("device-sweep-live")
        const events = yield* AuthEvents
        yield* twoFactor.trustDevice({ userId: user.id, ipAddress: null, userAgent: null })
        assert.strictEqual((yield* twoFactor.listDevices(user.id, Option.none())).length, 1)

        // Published the way the library publishes it, with nothing calling
        // `sweepOn`. `layer` runs the subscription, so the matrix is a live
        // control rather than a five-line recipe every deployment has to
        // remember — and forgetting it left a phished, remembered browser
        // working for thirty days after the password was reset.
        yield* events.publish({ _tag: "PasswordChanged", userId: user.id, viaReset: true })

        // The reaction is a forked fiber, so yield to the scheduler until it
        // has run rather than sleeping on a clock a test may be holding.
        let remaining = 0
        for (let turn = 0; turn < 200; turn++) {
          remaining = (yield* twoFactor.listDevices(user.id, Option.none())).length
          if (remaining === 0) break
          yield* Effect.yieldNow
        }

        assert.strictEqual(remaining, 0)
      })
    )
  })
})

/**
 * The per-account lockout, under the test deployment's default of
 * `rateLimit.enabled: false`: the budget is a security control, not a throttle,
 * and is spent whether or not the IP throttles are on.
 *
 * A block of its own rather than a nested variant: the budget is counted per
 * user, so it must not be spent by the tests above.
 */
const lockedDown = storeLayer.pipe(Layer.provideMerge(TwoFactorTest.layer()))

layer(lockedDown)("two-factor/TwoFactor lockout", (it) => {
  const enrolled = (label: string) =>
    Effect.gen(function* () {
      const twoFactor = yield* TwoFactor
      const account = yield* signUpUser(uniqueEmail(label))
      const started = yield* twoFactor.startEnrolment(account.user)
      // Confirming is itself an attempt against the budget, which is what
      // "across totp and recovery" means: there is one budget per account, not
      // one per endpoint.
      const codes = yield* twoFactor.confirmEnrolment(account.user, yield* codeAt(started.secret, 0))
      return { twoFactor, ...account, secret: started.secret, codes }
    })

  it.effect("locks an account out after ten attempts, and counts both endpoints against one budget", () =>
    Effect.gen(function* () {
      const { twoFactor, user, session, codes } = yield* enrolled("lockout")

      const attempt = (code: string) =>
        Effect.flip(
          twoFactor.verify({
            factor: { _tag: "Totp", code: Redacted.make(code) },
            subject: { _tag: "Session", session, user },
            ipAddress: null,
            userAgent: null
          })
        )

      // Confirming spent one of the ten, so nine wrong codes still answer
      // "wrong code" — and the tenth attempt is refused before anything is
      // compared.
      for (let index = 0; index < 9; index++) {
        const error = yield* attempt("000000")
        assert.strictEqual(error._tag, "InvalidCode", `attempt ${index + 1} should still be checked`)
      }
      const locked = yield* attempt("000000")
      assert.strictEqual(locked._tag, "RateLimited")

      // And the other endpoint is the same budget: starting a recovery attempt
      // is how the prior art's per-challenge cap was escaped.
      const viaRecovery = yield* Effect.flip(
        twoFactor.verify({
          factor: { _tag: "RecoveryCode", code: codes[0]! },
          subject: { _tag: "Session", session, user },
          ipAddress: null,
          userAgent: null
        })
      )
      assert.strictEqual(viaRecovery._tag, "RateLimited")
    })
  )

  it.effect("is one budget per account, so nobody can lock anybody else out", () =>
    Effect.gen(function* () {
      const victim = yield* enrolled("lockout-victim")
      const other = yield* enrolled("lockout-other")

      for (let index = 0; index < 12; index++) {
        yield* Effect.flip(
          victim.twoFactor.verify({
            factor: { _tag: "Totp", code: Redacted.make("000000") },
            subject: { _tag: "Session", session: victim.session, user: victim.user },
            ipAddress: null,
            userAgent: null
          })
        )
      }

      // The other account's budget is untouched: its code is still checked, and
      // still works.
      const result = yield* other.twoFactor.verify({
        factor: { _tag: "Totp", code: yield* codeAt(other.secret, 1) },
        subject: { _tag: "Session", session: other.session, user: other.user },
        ipAddress: null,
        userAgent: null
      })
      assert.strictEqual(result.session.aal, "aal2")
    })
  )
})
