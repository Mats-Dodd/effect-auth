import { assert, layer } from "@effect/vitest"
import { Duration, Effect, Encoding, Layer, Redacted, Schema } from "effect"
import { TestClock } from "effect/testing"
import type { SqlError } from "effect/unstable/sql"
import { SqlClient } from "effect/unstable/sql"
import { Token } from "../../src/crypto/Token.js"
import {
  Challenges,
  codeNamespace,
  layer as challengesLayer,
  make as makeChallenges
} from "../../src/domain/Challenges.js"
import type { VerificationStoreService } from "../../src/domain/Stores.js"
import { PersistenceError, VerificationStore } from "../../src/domain/Stores.js"
import type { TokenPurpose } from "../../src/domain/Verifications.js"
import { make as makeVerifications, purpose, Verifications } from "../../src/domain/Verifications.js"
import { AuthTest } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"

/**
 * The `verifications.identifier` a challenge row is written under: the caller's
 * purpose in the namespace of its own that keeps a handle from ever being
 * redeemable through `Verifications.claim`.
 */
const codeIdentifier = (p: TokenPurpose<never> | TokenPurpose<unknown>, subject: string): string =>
  `${codeNamespace(p.name)}:${subject}`

/** A challenge that carries something, as a second-factor hand-off would. */
const signIn = purpose("test-code-signin", Schema.Struct({ rememberMe: Schema.Boolean }))

/** A challenge that carries nothing. */
const confirm = purpose("test-code-confirm")

const ttl = Duration.minutes(10)

/** A code of the right shape that is not the one that was issued. */
const wrongCode = (code: Redacted.Redacted): Redacted.Redacted => {
  const raw = Redacted.value(code)
  return Redacted.make(`${raw.slice(0, -1)}${(Number(raw.slice(-1)) + 1) % 10}`)
}

interface Row {
  readonly payload: string | null
  readonly value_hash: string
  readonly expires_at: string
}

/** What the `verifications` table actually holds for one challenge. */
const rowsFor = (identifier: string): Effect.Effect<ReadonlyArray<Row>, SqlError.SqlError, SqlClient.SqlClient> =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    return yield* sql<Row>`SELECT payload, value_hash, expires_at FROM verifications WHERE identifier = ${identifier}`
  })

/** The stored envelope, read the way the module writes it. */
const StoredChallenge = Schema.fromJsonString(
  Schema.Struct({
    codeHash: Schema.String,
    attemptsLeft: Schema.Finite,
    payload: Schema.NullOr(Schema.String)
  })
)

const decodeStored = Schema.decodeUnknownEffect(StoredChallenge)

const storedFor = (
  identifier: string
): Effect.Effect<typeof StoredChallenge.Type | null, SqlError.SqlError, SqlClient.SqlClient> =>
  Effect.gen(function* () {
    const rows = yield* rowsFor(identifier)
    return rows.length === 0 ? null : yield* Effect.orDie(decodeStored(rows[0]!.payload))
  })

const budgetOf = (identifier: string): Effect.Effect<number | null, SqlError.SqlError, SqlClient.SqlClient> =>
  Effect.map(storedFor(identifier), (stored) => (stored === null ? null : stored.attemptsLeft))

layer(challengesLayer.pipe(Layer.provideMerge(AuthTest.layer())))("domain/Challenges", (it) => {
  it.effect("issues a handle and a code that are not the same secret", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("issue")

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 5,
        payload: { rememberMe: true }
      })

      assert.match(Redacted.value(issued.code), /^[0-9]{6}$/)
      // The handle names the row and is what a wrong guess is charged against;
      // the code is what goes to the mailbox. Confusing the two is the bug this
      // shape exists to prevent.
      assert.notStrictEqual(Redacted.value(issued.handle), Redacted.value(issued.code))
      assert.strictEqual(Redacted.value(issued.handle).includes(Redacted.value(issued.code)), false)
      assert.strictEqual(Redacted.value(issued.handle).startsWith(`${Encoding.encodeBase64Url(subject)}.`), true)

      const claimed = yield* challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      assert.strictEqual(claimed.subject, subject)
      assert.strictEqual(claimed.payload.rememberMe, true)
      assert.strictEqual(claimed.identifier, codeIdentifier(signIn, subject))

      // Single use: the row went with the answer.
      const replayed = yield* Effect.flip(
        challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      )
      assert.strictEqual(replayed._tag, "InvalidCode")
    })
  )

  it.effect("answers `null` for a purpose that declares no payload", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("nopayload")

      const issued = yield* challenges.issueCode({
        purpose: confirm,
        subject,
        digits: 8,
        ttl,
        attempts: 3,
        payload: null
      })
      assert.match(Redacted.value(issued.code), /^[0-9]{8}$/)

      const claimed = yield* challenges.verifyCode({ purpose: confirm, handle: issued.handle, code: issued.code })
      assert.strictEqual(claimed.payload, null)
    })
  )

  it.effect("spends one attempt on a wrong guess, keeps the handle, and buys no time", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("budget")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: false }
      })
      const before = yield* rowsFor(identifier)
      assert.strictEqual(before.length, 1)
      assert.strictEqual(yield* budgetOf(identifier), 3)

      const refused = yield* Effect.flip(
        challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: wrongCode(issued.code) })
      )
      assert.strictEqual(refused._tag, "InvalidCode")

      const after = yield* rowsFor(identifier)
      assert.strictEqual(after.length, 1)
      assert.strictEqual(yield* budgetOf(identifier), 2)
      // The same handle, so the caller's cookie still names the challenge...
      assert.strictEqual(after[0]!.value_hash, before[0]!.value_hash)
      // ...and the same expiry, so guessing wrong is not a way to extend a
      // challenge indefinitely.
      assert.strictEqual(after[0]!.expires_at, before[0]!.expires_at)

      // And the real code still works.
      const claimed = yield* challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      assert.strictEqual(claimed.subject, subject)
    })
  )

  it.effect("runs out of attempts, and the handle is then gone for good", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("exhausted")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 2,
        payload: { rememberMe: false }
      })

      const wrong = wrongCode(issued.code)
      assert.strictEqual(
        (yield* Effect.flip(challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: wrong })))._tag,
        "InvalidCode"
      )
      assert.strictEqual(yield* budgetOf(identifier), 1)

      assert.strictEqual(
        (yield* Effect.flip(challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: wrong })))._tag,
        "InvalidCode"
      )

      // Nothing is written back at zero: the row is the budget, so an exhausted
      // challenge cannot be re-entered by anybody, including whoever holds the
      // correct code.
      assert.deepStrictEqual(yield* rowsFor(identifier), [])
      const withTheRealCode = yield* Effect.flip(
        challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      )
      assert.strictEqual(withTheRealCode._tag, "InvalidCode")
      assert.deepStrictEqual(yield* rowsFor(identifier), [])
    })
  )

  it.effect("spends at most one attempt per wrong guess, however many arrive at once", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("concurrent-wrong")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 5,
        payload: { rememberMe: false }
      })
      const wrong = wrongCode(issued.code)

      const outcomes = yield* Effect.forEach(
        Array.from({ length: 3 }),
        () => Effect.flip(challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: wrong })),
        { concurrency: "unbounded" }
      )
      for (const outcome of outcomes) assert.strictEqual(outcome._tag, "InvalidCode")

      // Three wrong guesses cost at most three attempts — the losers of the
      // atomic claim never reach a comparison, so they never charge one — and at
      // least one, because one of them did.
      const left = yield* budgetOf(identifier)
      assert.strictEqual(left !== null && left >= 2, true, `${left} attempts left`)
      assert.strictEqual(left !== null && left <= 4, true, `${left} attempts left`)
      assert.strictEqual((yield* rowsFor(identifier)).length, 1)
    })
  )

  it.effect("never revives an exhausted handle, however many guesses are in flight", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("concurrent-exhaust")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 1,
        payload: { rememberMe: false }
      })
      const wrong = wrongCode(issued.code)

      const outcomes = yield* Effect.forEach(
        Array.from({ length: 4 }),
        () => Effect.flip(challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: wrong })),
        { concurrency: "unbounded" }
      )
      for (const outcome of outcomes) assert.strictEqual(outcome._tag, "InvalidCode")

      // A losing guess must not write a row back — that would hand the budget
      // back after it was spent.
      assert.deepStrictEqual(yield* rowsFor(identifier), [])
    })
  )

  it.effect("answers exactly one of two correct submissions", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("concurrent-right")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 5,
        payload: { rememberMe: true }
      })

      const outcomes = yield* Effect.forEach(
        Array.from({ length: 4 }),
        () => Effect.exit(challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })),
        { concurrency: "unbounded" }
      )

      const claimed = outcomes.filter((exit) => exit._tag === "Success")
      assert.strictEqual(claimed.length, 1, "a code is spendable exactly once")
      assert.deepStrictEqual(yield* rowsFor(identifier), [])
    })
  )

  it.effect("leaves the budget untouched when the store fails before the comparison", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("store-fault")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: false }
      })

      // A `Challenges` over a store whose claim fails: the row is never
      // deleted, so nothing was compared and nothing may be charged.
      const store = yield* VerificationStore
      const broken: VerificationStoreService = VerificationStore.of({
        ...store,
        consume: () => Effect.fail(PersistenceError.make({ operation: "VerificationStore.consume" }))
      })
      const verifications = yield* Effect.provideService(makeVerifications, VerificationStore, broken)
      const faulty = yield* Effect.provideService(makeChallenges, Verifications, verifications)

      const failed = yield* Effect.flip(
        faulty.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      )
      assert.strictEqual(failed._tag, "PersistenceError")

      assert.strictEqual(yield* budgetOf(identifier), 3)
      const claimed = yield* challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      assert.strictEqual(claimed.subject, subject)
    })
  )

  it.effect("reads a budget it cannot decode as exhausted", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const sql = yield* SqlClient.SqlClient
      const subject = uniqueEmail("corrupt")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: false }
      })
      yield* sql`UPDATE verifications SET payload = ${'{"attemptsLeft":"lots"}'} WHERE identifier = ${identifier}`

      // Fail closed: a row this deployment cannot read is not a row anybody
      // gets the benefit of the doubt on.
      const refused = yield* Effect.flip(
        challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
      )
      assert.strictEqual(refused._tag, "InvalidCode")
      assert.deepStrictEqual(yield* rowsFor(identifier), [])
    })
  )

  it.effect("retires the outstanding code when a new one is issued", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("resend")
      const identifier = codeIdentifier(signIn, subject)

      const first = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: false }
      })
      const second = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: true }
      })

      // Two live codes for one person is two chances to guess, and the one they
      // are looking at is the one that just arrived.
      assert.strictEqual((yield* rowsFor(identifier)).length, 1)
      const stale = yield* Effect.flip(
        challenges.verifyCode({ purpose: signIn, handle: first.handle, code: first.code })
      )
      assert.strictEqual(stale._tag, "InvalidCode")

      const claimed = yield* challenges.verifyCode({ purpose: signIn, handle: second.handle, code: second.code })
      assert.strictEqual(claimed.payload.rememberMe, true)
    })
  )

  it.effect("never answers a code under another purpose", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const subject = uniqueEmail("crossed")

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: false }
      })

      // The handle and the code are both genuine; the purpose names another
      // namespace, so there is nothing to claim — and the real challenge is
      // untouched by the attempt.
      const crossed = yield* Effect.flip(
        challenges.verifyCode({ purpose: confirm, handle: issued.handle, code: issued.code })
      )
      assert.strictEqual(crossed._tag, "InvalidCode")
      assert.strictEqual(yield* budgetOf(codeIdentifier(signIn, subject)), 3)

      const nonsense = yield* Effect.flip(
        challenges.verifyCode({ purpose: signIn, handle: Redacted.make("not-a-handle"), code: issued.code })
      )
      assert.strictEqual(nonsense._tag, "InvalidCode")
    })
  )

  it.effect("a handle is not a token: `Verifications.claim` cannot redeem one", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const verifications = yield* Verifications
      const subject = uniqueEmail("handle-not-a-token")

      // The shape that matters: one purpose used for both a code and the link
      // beside it, which is what a hybrid delivery is. A requester who holds
      // the handle — it rides in a cookie the browser was handed — and who
      // never received the mailed code must not be able to spend it as a link.
      const issued = yield* challenges.issueCode({
        purpose: confirm,
        subject,
        digits: 8,
        ttl,
        attempts: 5,
        payload: null
      })

      // Refused on both counts, independently: the row lives in a namespace of
      // its own (`codeNamespace`), so the identifier `claim` addresses holds
      // nothing at all; and a payload-less purpose refuses a row that carries a
      // payload, so even at one identifier the challenge row is not a token.
      const refused = yield* Effect.flip(verifications.claim(confirm, issued.handle))
      assert.strictEqual(refused._tag, "InvalidToken")

      // And it cost the requester nothing they held: the code is still good.
      const claimed = yield* challenges.verifyCode({ purpose: confirm, handle: issued.handle, code: issued.code })
      assert.strictEqual(claimed.subject, subject)
    })
  )

  it.effect("a payload-less purpose refuses a row that carries a payload", () =>
    Effect.gen(function* () {
      const verifications = yield* Verifications
      const subject = uniqueEmail("payload-mismatch")

      // Two purposes of one name, one declaring a payload and one not — the
      // arrangement a plugin falls into by writing `purpose(name)` at the link
      // door and `purpose(name, Payload)` at the other. The bare one must not
      // read the other's rows.
      const carrying = purpose("test-payload-mismatch", Schema.Struct({ rememberMe: Schema.Boolean }))
      const bare = purpose("test-payload-mismatch")

      const issued = yield* verifications.issue({
        purpose: carrying,
        subject,
        ttl,
        payload: { rememberMe: true }
      })
      const refused = yield* Effect.flip(verifications.claim(bare, issued.token))
      assert.strictEqual(refused._tag, "InvalidToken")
    })
  )

  it.effect("stores a peppered tag, never the code and never a bare digest of it", () =>
    Effect.gen(function* () {
      const challenges = yield* Challenges
      const tokens = yield* Token
      const subject = uniqueEmail("pepper")
      const identifier = codeIdentifier(signIn, subject)

      const issued = yield* challenges.issueCode({
        purpose: signIn,
        subject,
        digits: 6,
        ttl,
        attempts: 3,
        payload: { rememberMe: false }
      })
      const rows = yield* rowsFor(identifier)
      const payload = rows[0]!.payload!
      const code = Redacted.value(issued.code)

      assert.strictEqual(payload.includes(code), false)
      // A bare SHA-256 over a million codes is a table an attacker with the
      // dump builds in microseconds, so the digest has to be keyed on the
      // deployment secret. Neither the digest of the code nor the digest of the
      // code and its row may appear.
      const bare = yield* tokens.hashToken(Redacted.make(code))
      const withIdentifier = yield* tokens.hashToken(Redacted.make(`${code}\n${identifier}`))
      assert.strictEqual(payload.includes(bare), false)
      assert.strictEqual(payload.includes(withIdentifier), false)

      const stored = yield* storedFor(identifier)
      assert.strictEqual(stored?.attemptsLeft, 3)
      assert.strictEqual(stored?.codeHash.length, 43)
      assert.strictEqual(stored?.payload, `{"rememberMe":false}`)
    })
  )

  it.effect("expires, and a wrong guess does not put the expiry off", () =>
    AuthTest.freshClock(
      Effect.gen(function* () {
        const challenges = yield* Challenges
        const subject = uniqueEmail("expiry")

        const issued = yield* challenges.issueCode({
          purpose: signIn,
          subject,
          digits: 6,
          ttl: Duration.minutes(10),
          attempts: 5,
          payload: { rememberMe: false }
        })

        yield* TestClock.adjust(Duration.minutes(5))
        const refused = yield* Effect.flip(
          challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: wrongCode(issued.code) })
        )
        assert.strictEqual(refused._tag, "InvalidCode")

        // Five more minutes takes it past the *original* ten, which is the
        // expiry the re-issued row has to have kept.
        yield* TestClock.adjust(Duration.minutes(6))
        const expired = yield* Effect.flip(
          challenges.verifyCode({ purpose: signIn, handle: issued.handle, code: issued.code })
        )
        assert.strictEqual(expired._tag, "InvalidCode")
      })
    )
  )
})
