/**
 * Opaque token minting and hashing.
 *
 * Session tokens, e-mail verification tokens, password reset tokens and OAuth
 * state nonces are all produced here: 32 cryptographically random bytes,
 * base64url encoded into a 43-character string. Short numeric codes — the kind
 * a challenge asks somebody to read off a screen — are minted here too, so that
 * randomness enters this library through exactly one seam and that seam is
 * `effect/Crypto`, never the seedable `Random`.
 *
 * **Details**
 *
 * Nothing keeps a raw token. A token is returned to its owner exactly once —
 * in a `Set-Cookie`, a response body, or an e-mail link — and only
 * `hashToken`'s SHA-256 digest is stored. A leaked database therefore yields no
 * usable session or reset link, and every lookup hashes the presented value
 * first.
 *
 * @since 0.1.0
 */
import { Context, Crypto, Effect, Encoding, Layer, Redacted } from "effect"
import { encodeUtf8 } from "../internal/crypto.js"

/**
 * The number of random bytes in a token.
 *
 * @category constructors
 * @since 0.1.0
 */
export const tokenBytes = 32

/**
 * The length of the base64url encoding of {@link tokenBytes} bytes.
 *
 * @category constructors
 * @since 0.1.0
 */
export const tokenLength = 43

/**
 * The largest number of digits {@link TokenService.generateNumericCode} will
 * mint.
 *
 * **Details**
 *
 * A code is drawn from one 32-bit sample, so ten digits do not fit — and a code
 * long enough to need a second sample is a token, which this module already
 * mints. Asking for more is a programming error, not a request that can fail.
 *
 * @category constructors
 * @since 0.2.0
 */
export const maxCodeDigits = 9

/**
 * The {@link Token} service definition.
 *
 * @category models
 * @since 0.1.0
 */
export interface TokenService {
  /**
   * Mints a fresh token: 32 random bytes, base64url encoded, `Redacted` so it
   * cannot be logged on its way to its single recipient.
   */
  readonly generateToken: Effect.Effect<Redacted.Redacted>

  /**
   * The base64url SHA-256 digest of a token — the only form that is ever
   * stored, and the value every lookup matches on.
   *
   * **Details**
   *
   * A plain digest with no salt or stretching is correct here and only here:
   * the input is 256 bits of uniform randomness, so there is nothing to guess
   * and nothing to precompute.
   */
  readonly hashToken: (token: Redacted.Redacted) => Effect.Effect<string>

  /**
   * Mints a uniformly random decimal code of `digits` digits, zero-padded, for
   * a challenge somebody has to read off a screen and type back.
   *
   * **Details**
   *
   * Rejection sampling over four random bytes: a sample at or above the largest
   * multiple of `10^digits` that fits in 32 bits is thrown away and redrawn, so
   * every code is equally likely. Taking `value % 10^digits` without that
   * discard would make the low codes measurably more likely — for six digits,
   * about one code in fifty thousand of extra weight on the first 967,296 of
   * them, which is a bias an attacker guessing a six-digit code can use.
   *
   * The result is `Redacted`, like every other secret this module mints: a code
   * is delivered once, to one mailbox or one handset.
   *
   * **Gotchas**
   *
   * `digits` must be between 1 and {@link maxCodeDigits}; anything else is a
   * defect, because there is no request a caller could retry.
   */
  readonly generateNumericCode: (digits: number) => Effect.Effect<Redacted.Redacted>
}

/**
 * Mints and hashes opaque tokens. See {@link TokenService}.
 *
 * @category services
 * @since 0.1.0
 */
export class Token extends Context.Service<Token, TokenService>()("effect-auth/crypto/Token") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds a {@link Token} implementation over a `Crypto.Crypto` instance.
 *
 * **When to use**
 *
 * Use to bind the service to a specific `Crypto` — a deterministic stub in a
 * test, or a platform implementation — without going through {@link layer}.
 *
 * **Details**
 *
 * Both operations are infallible from the caller's point of view: a `Crypto`
 * failure here means the runtime is broken, not that the request is bad, so it
 * surfaces as a defect rather than a typed error.
 *
 * @category constructors
 * @since 0.1.0
 */
export const make = (crypto: Crypto.Crypto): TokenService => {
  const sample = (digits: number, limit: number, modulus: number): Effect.Effect<string> =>
    Effect.flatMap(Effect.orDie(crypto.randomBytes(4)), (bytes) => {
      // Big-endian, by arithmetic rather than by a `DataView`, so a pooled
      // buffer's byte offset cannot come into it.
      const value = bytes[0]! * 0x1000000 + bytes[1]! * 0x10000 + bytes[2]! * 0x100 + bytes[3]!
      return value >= limit
        ? sample(digits, limit, modulus)
        : Effect.succeed(String(value % modulus).padStart(digits, "0"))
    })

  return Token.of({
    generateToken: Effect.map(Effect.orDie(crypto.randomBytes(tokenBytes)), (bytes) =>
      Redacted.make(Encoding.encodeBase64Url(bytes))
    ),
    hashToken: (token) =>
      Effect.map(Effect.orDie(crypto.digest("SHA-256", encodeUtf8(Redacted.value(token)))), Encoding.encodeBase64Url),
    generateNumericCode: (digits) => {
      if (!Number.isInteger(digits) || digits < 1 || digits > maxCodeDigits) {
        return Effect.die(new Error(`a numeric code must have between 1 and ${maxCodeDigits} digits`))
      }
      const modulus = 10 ** digits
      return Effect.map(sample(digits, Math.floor(0x100000000 / modulus) * modulus, modulus), Redacted.make)
    }
  })
}

/**
 * Provides {@link Token} over the ambient `Crypto.Crypto`.
 *
 * **Details**
 *
 * `Auth.layer` provides a WebCrypto-backed default underneath this, so an
 * application never has to think about it; a deployment that wants a platform
 * implementation provides its own `Crypto.Crypto` layer instead.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer: Layer.Layer<Token, never, Crypto.Crypto> = Layer.effect(Token, Crypto.Crypto.useSync(make))
