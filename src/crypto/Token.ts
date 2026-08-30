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
import { Context, Effect, Encoding, Layer, Redacted } from "effect"

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

const utf8 = new TextEncoder()

/**
 * `crypto.subtle.digest` wants an `ArrayBuffer` that it owns; a `Uint8Array`
 * view over a pooled buffer (which is what `TextEncoder` and Node's `Buffer`
 * hand back) can be a window onto a much larger allocation.
 */
const toArrayBuffer = (data: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(data.byteLength)
  new Uint8Array(buffer).set(data)
  return buffer
}

/**
 * Builds a {@link Token} implementation over any WebCrypto instance.
 *
 * **When to use**
 *
 * Use to bind the service to something other than `globalThis.crypto` — a
 * deterministic stub in a test, or a platform shim.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (crypto: Crypto): TokenService =>
  Token.of({
    generateToken: Effect.sync(() =>
      Redacted.make(Encoding.encodeBase64Url(crypto.getRandomValues(new Uint8Array(tokenBytes))))
    ),
    hashToken: (token) =>
      Effect.map(
        Effect.promise(() => crypto.subtle.digest("SHA-256", toArrayBuffer(utf8.encode(Redacted.value(token))))),
        (digest) => Encoding.encodeBase64Url(new Uint8Array(digest))
      )
  })

/**
 * Provides {@link Token} over the runtime's WebCrypto (`globalThis.crypto`).
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Token> = Layer.sync(Token, () => make(globalThis.crypto))
