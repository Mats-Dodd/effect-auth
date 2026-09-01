/**
 * HMAC-SHA-256 behind a service, keyed from `AuthConfig.secret`.
 *
 * Used wherever a value leaves the server and must come back unmodified without
 * a database round-trip: the session cookie cache, a trusted-device marker, a
 * plugin's own signed cookie. {@link HmacService.signedValue} is the envelope
 * all of those share, so the format is written once.
 *
 * @since 0.1.0
 */
import { Context, Effect, Encoding, Layer, Option, Redacted, Result } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import { ambientCrypto, encodeUtf8, toArrayBuffer } from "../internal/crypto.js"

/**
 * The {@link Hmac} service definition.
 *
 * @category models
 * @since 0.1.0
 */
export interface HmacService {
  /**
   * Produces the 32-byte HMAC-SHA-256 tag of `data`.
   */
  readonly sign: (data: Uint8Array) => Effect.Effect<Uint8Array>

  /**
   * Checks a tag against `data` in constant time.
   *
   * **Gotchas**
   *
   * Always verify through this method rather than recomputing a tag and
   * comparing it yourself — a naive comparison short-circuits on the first
   * differing byte and turns the tag into something an attacker can search for.
   */
  readonly verify: (data: Uint8Array, mac: Uint8Array) => Effect.Effect<boolean>

  /**
   * Wraps `payload` in the signed envelope a cookie carries:
   * `base64url(payload).base64url(tag)`, where the tag covers `context`
   * followed by the payload bytes.
   *
   * **Details**
   *
   * `context` is domain separation, and it is the whole of what makes a tag
   * mean something. This service is published — a plugin signs values of its
   * own with the same key — so a tag is only ever a tag *for* something.
   * Prefixing the signed bytes with a string nothing else writes is what makes
   * a tag produced elsewhere useless here: a forged envelope would have to be
   * signed under this exact prefix.
   *
   * The context is part of the format. Changing it invalidates every
   * outstanding value signed under the old one — which must always be a miss,
   * never an error.
   *
   * **Gotchas**
   *
   * The payload is *encoded*, not encrypted: anyone holding the value can read
   * it. The envelope buys integrity and nothing else.
   */
  readonly signedValue: (context: string, payload: Uint8Array) => Effect.Effect<string>

  /**
   * Unwraps a {@link HmacService.signedValue} envelope, or `None` when it is
   * not one this deployment wrote under `context`.
   *
   * **Details**
   *
   * One answer for every way of being wrong — a value that is not an envelope
   * at all, one whose halves are not base64url, and one whose tag does not
   * check out — because a caller cannot act on the difference and a cookie that
   * fails to verify is a cache miss, not a `401`. The tag is checked before
   * anything is parsed, so everything downstream is looking at bytes this
   * deployment signed.
   */
  readonly verifySignedValue: (context: string, value: string) => Effect.Effect<Option.Option<Uint8Array>>
}

/**
 * Signs and verifies byte strings with the instance secret. See
 * {@link HmacService}.
 *
 * @category services
 * @since 0.1.0
 */
export class Hmac extends Context.Service<Hmac, HmacService>()("effect-auth/crypto/Hmac") {}

/**
 * What separates the two halves of a {@link HmacService.signedValue} envelope.
 *
 * **Details**
 *
 * Neither half can contain it: both are base64url.
 *
 * @category constructors
 * @since 0.2.0
 */
export const signedValueSeparator = "."

/**
 * The bytes a {@link HmacService.signedValue} tag actually covers: the context
 * string, UTF-8, followed by the payload.
 */
const withContext = (context: string, payload: Uint8Array): Uint8Array => {
  const prefix = encodeUtf8(context)
  const signed = new Uint8Array(prefix.length + payload.length)
  signed.set(prefix)
  signed.set(payload, prefix.length)
  return signed
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds an {@link Hmac} implementation from a WebCrypto instance and a secret.
 *
 * **Details**
 *
 * This is the one service that cannot be written against `Crypto.Crypto`:
 * that interface offers random bytes and message digests, and HMAC is neither.
 * Recomputing a tag from `digest` by hand would also give up
 * `subtle.verify`'s constant-time comparison, which is the point of
 * {@link HmacService.verify}. So the WebCrypto instance stays an explicit
 * parameter here.
 *
 * The secret is imported as a non-extractable `CryptoKey` once, at layer
 * construction, and the `Redacted` wrapper is unwrapped only for that single
 * call — after which the plaintext secret exists nowhere in this module.
 *
 * Both operations are infallible from the caller's point of view: a WebCrypto
 * failure here means the runtime is broken, not that the request is bad, so it
 * surfaces as a defect rather than a typed error.
 *
 * @category constructors
 * @since 0.1.0
 */
export const make = (crypto: Crypto, secret: Redacted.Redacted): Effect.Effect<HmacService> =>
  Effect.map(
    Effect.promise(() =>
      crypto.subtle.importKey(
        "raw",
        toArrayBuffer(encodeUtf8(Redacted.value(secret))),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      )
    ),
    (key) => {
      const sign = (data: Uint8Array): Effect.Effect<Uint8Array> =>
        Effect.map(
          Effect.promise(() => crypto.subtle.sign("HMAC", key, toArrayBuffer(data))),
          (mac) => new Uint8Array(mac)
        )
      // `subtle.verify` is the constant-time comparison; recomputing the tag
      // and comparing it by hand would be the mistake this method exists to
      // prevent.
      const verify = (data: Uint8Array, mac: Uint8Array): Effect.Effect<boolean> =>
        Effect.promise(() => crypto.subtle.verify("HMAC", key, toArrayBuffer(mac), toArrayBuffer(data)))

      return Hmac.of({
        sign,
        verify,
        signedValue: (context, payload) =>
          Effect.map(
            sign(withContext(context, payload)),
            (mac) => `${Encoding.encodeBase64Url(payload)}${signedValueSeparator}${Encoding.encodeBase64Url(mac)}`
          ),
        verifySignedValue: (context, value) =>
          Effect.gen(function* () {
            const at = value.indexOf(signedValueSeparator)
            if (at <= 0 || at === value.length - 1) return Option.none<Uint8Array>()

            const payload = Encoding.decodeBase64Url(value.slice(0, at))
            const mac = Encoding.decodeBase64Url(value.slice(at + 1))
            if (Result.isFailure(payload) || Result.isFailure(mac)) return Option.none<Uint8Array>()

            const authentic = yield* verify(withContext(context, payload.success), mac.success)
            return authentic ? Option.some(payload.success) : Option.none<Uint8Array>()
          })
      })
    }
  )

/**
 * Provides {@link Hmac} over WebCrypto, with the key imported once from
 * `AuthConfig.secret`.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer: Layer.Layer<Hmac, never, AuthConfig> = Layer.effect(
  Hmac,
  AuthConfig.use((config) => make(ambientCrypto(), config.secret))
)
