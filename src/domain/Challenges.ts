/**
 * Short codes — the six or eight digits a person reads off a screen and types
 * back — over the same rows and the same atomic claim as every other
 * single-use credential.
 *
 * **Details**
 *
 * `Verifications` is already the challenge primitive, and for a 43-character
 * token it is the whole answer. A short code is different in exactly two ways,
 * and this module is those two ways and nothing else.
 *
 * *The secret in the row is not the code.* It is a **handle**: a full-entropy
 * token the caller keeps — in a `__Host-` cookie, or in the response to the
 * request that asked for the code — while the code itself travels out of band
 * to a mailbox or a handset. The row stores a peppered hash of the code beside
 * an attempt budget, and a guess has to arrive holding the handle. That is what
 * binds the budget to the person who asked: without it, anybody who knows a
 * victim's address can burn the victim's three attempts from anywhere.
 *
 * *A wrong guess costs something.* `verifyCode` claims the row — the same
 * atomic `DELETE ... RETURNING` — compares in constant time, and on a mismatch
 * writes the row back under the *same* handle with one attempt fewer and the
 * original expiry. At zero it is not written back, so the handle is simply
 * gone. An attempt is spent only by a comparison that actually ran: a fault
 * before it restores the budget untouched, and a budget that will not decode
 * reads as exhausted.
 *
 * The stored hash is `Hmac` — the deployment secret — never `Token.hashToken`.
 * A bare SHA-256 over a space of a million codes is a table an attacker with
 * the database builds in microseconds; a pepper they do not have makes the
 * digest useless to them.
 *
 * **Gotchas**
 *
 * A budget is not a rate limit. Nothing here stops somebody asking for a
 * hundred codes; that is a `RateLimiter` bucket on the issuing endpoint, keyed
 * on the identifier, and every caller owes one.
 *
 * @since 0.2.0
 */
import { Context, DateTime, type Duration, Effect, Encoding, Exit, Layer, Redacted, Result, Schema } from "effect"
import { Hmac } from "../crypto/Hmac.js"
import { Token } from "../crypto/Token.js"
import { encodeUtf8 } from "../internal/crypto.js"
import { InvalidCode } from "./Errors.js"
import type { PersistenceError } from "./Stores.js"
import type { Claimed, TokenPurpose } from "./Verifications.js"
import { decodeSubjectToken, identifierOf, purpose, Verifications } from "./Verifications.js"

// -----------------------------------------------------------------------------
// The row
// -----------------------------------------------------------------------------

/**
 * What every challenge's `Hmac` tag covers before the code itself.
 *
 * **Details**
 *
 * Domain separation. `Hmac` is a published service, so a tag is only ever a tag
 * *for* something: prefixing the signed bytes with a string nothing else writes
 * is what stops a tag produced elsewhere — by a plugin signing values a caller
 * chose — from being usable as a code hash here.
 *
 * It is part of the stored format, so changing it invalidates every outstanding
 * code.
 *
 * @category constructors
 * @since 0.2.0
 */
export const codeHashContext = "effect-auth/challenge-code/v1\n"

/**
 * The `verifications` namespace a challenge row of the given purpose is written
 * under: the purpose's own name with `#code` appended.
 *
 * **Details**
 *
 * A challenge row is not a link and must not be redeemable as one. Giving it a
 * namespace of its own means `Verifications.claim(purpose, handle)` addresses
 * an identifier no challenge was ever written under, whatever payload that
 * purpose declares — so a handle cannot be spent as a token even by a caller
 * holding it, and cannot burn the code by trying.
 *
 * The hybrid a purpose may still want — one code and one link for the same
 * subject, where consuming either retires the other — is carried by
 * {@link ChallengesService.issueCode} and {@link ChallengesService.retire},
 * which act on both namespaces.
 *
 * **Gotchas**
 *
 * Part of the stored format: changing it strands every outstanding code.
 *
 * @category combinators
 * @since 0.2.0
 */
export const codeNamespace = (name: string): string => `${name}#code`

/**
 * What a challenge writes into the `verifications.payload` column: the code's
 * peppered digest, what is left of its attempt budget, and the caller's own
 * payload still in the form its purpose encodes to.
 *
 * **Gotchas**
 *
 * The caller's payload is carried as its already-encoded JSON string rather
 * than nested as a value, so that a purpose's payload schema is decoded by the
 * purpose, once, exactly as it would be for a link.
 */
const ChallengeRow = Schema.Struct({
  codeHash: Schema.String,
  attemptsLeft: Schema.Int,
  payload: Schema.NullOr(Schema.String)
})

type ChallengeRow = typeof ChallengeRow.Type

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * What {@link ChallengesService.issueCode} needs to know.
 *
 * @category models
 * @since 0.2.0
 */
export interface IssueCodeOptions<P> {
  /** The class of challenge, which namespaces the row exactly as it does for a link. */
  readonly purpose: TokenPurpose<P>
  /** Who or what the challenge is about — a user id, a normalized address, a phone number. */
  readonly subject: string
  /**
   * How many digits the code has.
   *
   * **Gotchas**
   *
   * Six is the norm for something typed off a handset; eight is the better
   * default for e-mail, where the code is copied and pasted and two more digits
   * are two orders of magnitude for free.
   */
  readonly digits: number
  /** How long the challenge may be answered for. NIST caps a mailed code at ten minutes. */
  readonly ttl: Duration.Duration
  /** How many wrong guesses the challenge survives. */
  readonly attempts: number
  /** What travels with it, `null` for a purpose that declares no payload. */
  readonly payload: P
}

/**
 * An issued challenge: the two halves that leave the server by two different
 * roads.
 *
 * @category models
 * @since 0.2.0
 */
export interface IssuedCode {
  /**
   * The handle. Goes back to the caller who asked — a cookie, a response body —
   * and comes back with the guess. It is not the code and must never be mailed.
   */
  readonly handle: Redacted.Redacted
  /** The code. Goes to the mailbox or the handset, and nowhere else. */
  readonly code: Redacted.Redacted
  /** When the challenge stops being answerable. A wrong guess does not move it. */
  readonly expiresAt: DateTime.Utc
}

/**
 * What {@link ChallengesService.verifyCode} needs to know.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyCodeOptions<P> {
  /** The class of challenge. A code issued under another purpose can never match. */
  readonly purpose: TokenPurpose<P>
  /** The handle the caller was given when the code was issued. */
  readonly handle: Redacted.Redacted
  /** Exactly what the person typed. */
  readonly code: Redacted.Redacted
}

/**
 * The {@link Challenges} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface ChallengesService {
  /**
   * Mints a code, stores its peppered digest and an attempt budget under a
   * fresh handle, and retires whatever was outstanding for the same purpose and
   * subject.
   *
   * **Details**
   *
   * Retiring first is the point: two live codes for one person is two chances
   * to guess, and the one they are looking at is the one that just arrived.
   */
  readonly issueCode: <P>(options: IssueCodeOptions<P>) => Effect.Effect<IssuedCode, PersistenceError>

  /**
   * Answers a challenge.
   *
   * **Details**
   *
   * The row is claimed atomically before anything is compared, so a code can be
   * spent exactly once however many requests arrive at once. A wrong guess
   * writes the row back under the same handle with one attempt fewer and the
   * expiry it already had; the last wrong guess writes nothing back, which is
   * what "out of attempts" is made of.
   *
   * **Gotchas**
   *
   * `InvalidCode` is every way of being wrong — unknown handle, wrong code,
   * expired, already answered, out of attempts, issued under another purpose.
   * Telling them apart would say whether a code was ever issued and how much
   * budget is left.
   */
  readonly verifyCode: <P>(options: VerifyCodeOptions<P>) => Effect.Effect<Claimed<P>, InvalidCode | PersistenceError>

  /**
   * Retires whatever code this purpose and subject hold, without answering it.
   *
   * **When to use**
   *
   * On the *other* half of a hybrid. A purpose that mints a link beside its
   * code — email-otp's sign-in — retires the link with
   * `Verifications.retire(purpose, subject)`; this is the matching call that
   * retires the code, because the two live in different namespaces
   * ({@link codeNamespace}). Following the link should kill the code and
   * answering the code should kill the link, and each door owes the other one
   * call.
   *
   * A no-op when nothing is outstanding.
   */
  readonly retire: (purpose: TokenPurpose<unknown>, subject: string) => Effect.Effect<void, PersistenceError>
}

/**
 * Issues and answers short codes. See {@link ChallengesService}.
 *
 * @category services
 * @since 0.2.0
 */
export class Challenges extends Context.Service<Challenges, ChallengesService>()(
  "effect-auth/domain/Challenges/Challenges"
) {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Challenges} implementation.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: Effect.Effect<ChallengesService, never, Hmac | Token | Verifications> = Effect.gen(function* () {
  const hmac = yield* Hmac
  const tokens = yield* Token
  const verifications = yield* Verifications

  // One purpose per name, built the once: a purpose is inert data, and the set
  // of names is the set of purposes a deployment declares at module scope.
  const rowPurposes = new Map<string, TokenPurpose<ChallengeRow>>()
  const rowPurpose = (name: string): TokenPurpose<ChallengeRow> => {
    const existing = rowPurposes.get(name)
    if (existing !== undefined) return existing
    // A namespace of its own, so that a challenge row can never be reached by
    // `Verifications.claim` under the caller's purpose at all — whatever
    // payload that purpose declares. The handle is then a handle and nothing
    // else, and the hybrid "a code and a link at one subject" semantics are
    // carried by `issueCode` and `retire` retiring both namespaces rather than
    // by the two sharing one.
    const built = purpose(codeNamespace(name), ChallengeRow)
    rowPurposes.set(name, built)
    return built
  }

  /** The bytes a code's tag covers: the context, the code, the row it belongs to. */
  const signedBytes = (identifier: string, code: Redacted.Redacted): Uint8Array =>
    encodeUtf8(`${codeHashContext}${Redacted.value(code)}\n${identifier}`)

  const codeHash = (identifier: string, code: Redacted.Redacted): Effect.Effect<string> =>
    Effect.map(hmac.sign(signedBytes(identifier, code)), Encoding.encodeBase64Url)

  /**
   * Compares in the storage domain and in constant time: the presented code is
   * carried into the tag, and `subtle.verify` does the comparison. Nothing here
   * ever produces the stored code, because nothing here can.
   */
  const codeMatches = (identifier: string, code: Redacted.Redacted, stored: string): Effect.Effect<boolean> => {
    const mac = Encoding.decodeBase64Url(stored)
    return Result.isFailure(mac) ? Effect.succeed(false) : hmac.verify(signedBytes(identifier, code), mac.success)
  }

  const issueCode = Effect.fnUntraced(function* <P>(options: IssueCodeOptions<P>) {
    if (!Number.isInteger(options.attempts) || options.attempts < 1) {
      return yield* Effect.die(new Error("a challenge needs at least one attempt"))
    }
    // The row the tag is bound to is the row it is stored in — the challenge
    // namespace, not the caller's. `verifyCode` recomputes it from the claimed
    // row's own identifier, so the two agree by construction.
    const identifier = identifierOf(rowPurpose(options.purpose.name), options.subject)
    const code = yield* tokens.generateNumericCode(options.digits)
    // A payload that does not fit the schema its own purpose declared is a
    // programming error, not a request the caller can fix.
    const payload =
      options.purpose.payload === null
        ? null
        : yield* Effect.orDie(Schema.encodeEffect(options.purpose.payload)(options.payload))

    // Both namespaces: whatever this subject held — an outstanding code, a link
    // of the same purpose, or both halves of a hybrid — is retired before the
    // new code exists. Two live codes for one person is two chances to guess.
    yield* verifications.retire(options.purpose, options.subject)
    yield* verifications.retire(rowPurpose(options.purpose.name), options.subject)
    const issued = yield* verifications.issue({
      purpose: rowPurpose(options.purpose.name),
      subject: options.subject,
      ttl: options.ttl,
      payload: { codeHash: yield* codeHash(identifier, code), attemptsLeft: options.attempts, payload }
    })
    return { handle: issued.token, code, expiresAt: issued.expiresAt } satisfies IssuedCode
  })

  const verifyCode = Effect.fnUntraced(function* <P>(options: VerifyCodeOptions<P>) {
    // The handle's own secret, kept so a wrong guess can put the row back under
    // it. A handle that is not one at all never reaches the store.
    const handle = yield* Effect.fromOption(decodeSubjectToken(options.handle), () => InvalidCode.make())
    const wrapped = rowPurpose(options.purpose.name)

    // Consume first, compare second: a read-then-write here is the replay bug
    // this whole module exists to make unrepresentable. An unknown, expired or
    // already-answered handle — and a row whose budget will not decode — are
    // one answer.
    const claimed = yield* Effect.catchTag(verifications.claim(wrapped, options.handle), "InvalidToken", () =>
      Effect.fail(InvalidCode.make())
    )
    const row = claimed.payload

    /**
     * Writes the row back under the handle the caller is still holding.
     *
     * **Gotchas**
     *
     * A restore that interleaves with a *fresh* issuance for the same subject
     * can leave two live rows: this one claimed (deleted) the row, the resend
     * then found nothing to retire and inserted its own, and this puts the old
     * one back. `verifications.identifier` carries a non-unique index, so
     * nothing refuses it.
     *
     * Bounded, and left: both codes are independent fresh entropy, so the odds
     * per guess are unchanged; the budget of the revived handle is already one
     * lower; neither expiry is extended; and the caller's own resend cooldown
     * is what limits how often the race can be attempted at all. Closing it
     * needs `Verifications.issue` to retire and insert inside one transaction,
     * which is a change to the core token primitive rather than to this module.
     */
    const restore = (attemptsLeft: number): Effect.Effect<void, PersistenceError> =>
      Effect.flatMap(DateTime.now, (now) =>
        Effect.asVoid(
          verifications.issue({
            purpose: wrapped,
            subject: claimed.subject,
            // What is left of the original lifetime, so a wrong guess buys no
            // time — the expiry a challenge was issued with is the expiry it has.
            ttl: DateTime.distance(now, claimed.verification.expiresAt),
            payload: { ...row, attemptsLeft },
            secret: handle.secret
          })
        )
      )

    // Everything between the claim and the answer runs under one exit: an
    // attempt is spent by a comparison that ran, and by nothing else, so a
    // broken runtime cannot eat somebody's budget.
    const outcome = yield* Effect.exit(codeMatches(claimed.identifier, options.code, row.codeHash))
    if (Exit.isFailure(outcome)) {
      yield* restore(row.attemptsLeft)
      return yield* Effect.failCause(outcome.cause)
    }

    if (outcome.value) {
      const payload = yield* Effect.mapError(options.purpose.decodePayload(row.payload), () => InvalidCode.make())
      return { subject: claimed.subject, payload, identifier: claimed.identifier, verification: claimed.verification }
    }

    // Spent. At zero the row is not written back at all, which is the whole of
    // "out of attempts": the handle names nothing, and no later request can
    // bring it back.
    if (row.attemptsLeft > 1) yield* restore(row.attemptsLeft - 1)
    return yield* InvalidCode.make()
  })

  const retire = (challengePurpose: TokenPurpose<unknown>, subject: string): Effect.Effect<void, PersistenceError> =>
    Effect.asVoid(verifications.retire(rowPurpose(challengePurpose.name), subject))

  return Challenges.of({ issueCode, verifyCode, retire })
})

/**
 * Provides {@link Challenges}.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<Challenges, never, Hmac | Token | Verifications> = Layer.effect(Challenges, make)
