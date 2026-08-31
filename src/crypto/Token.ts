/**
 * Opaque token minting and hashing.
 *
 * Session tokens, e-mail verification tokens, password reset tokens and OAuth
 * state nonces are all produced here: 32 cryptographically random bytes,
 * base64url encoded into a 43-character string.
 *
 * **Details**
 *
 * Nothing keeps a raw token. A token is returned to its owner exactly once —
 * in a `Set-Cookie`, a response body, or an e-mail link — and only
 * `hashToken`'s SHA-256 digest is stored. A leaked database therefore yields no
 * usable session or reset link, and every lookup hashes the presented value
 * first.
 *
 * @since 1.0.0
 */
import { Context, Crypto, Effect, Encoding, Layer, Redacted } from "effect"
import { encodeUtf8 } from "../internal/crypto.js"

/**
 * The number of random bytes in a token.
 *
 * @category constructors
 * @since 1.0.0
 */
export const tokenBytes = 32

/**
 * The length of the base64url encoding of {@link tokenBytes} bytes.
 *
 * @category constructors
 * @since 1.0.0
 */
export const tokenLength = 43

/**
 * The {@link Token} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface TokenService {
  /**
   * Mints a fresh token: 32 random bytes, base64url encoded, `Redacted` so it
   * cannot be logged on its way to its single recipient.
   */
  readonly generateToken: Effect.Effect<Redacted.Redacted<string>>

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
  readonly hashToken: (token: Redacted.Redacted<string>) => Effect.Effect<string>
}

/**
 * Mints and hashes opaque tokens. See {@link TokenService}.
 *
 * @category services
 * @since 1.0.0
 */
export class Token extends Context.Service<Token, TokenService>()("effect-auth/Token") {}

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
 * @since 1.0.0
 */
export const make = (crypto: Crypto.Crypto): TokenService =>
  Token.of({
    generateToken: Effect.map(
      Effect.orDie(crypto.randomBytes(tokenBytes)),
      (bytes) => Redacted.make(Encoding.encodeBase64Url(bytes))
    ),
    hashToken: (token) =>
      Effect.map(
        Effect.orDie(crypto.digest("SHA-256", encodeUtf8(Redacted.value(token)))),
        Encoding.encodeBase64Url
      )
  })

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
 * @since 1.0.0
 */
export const layer: Layer.Layer<Token, never, Crypto.Crypto> = Layer.effect(
  Token,
  Crypto.Crypto.useSync(make)
)
