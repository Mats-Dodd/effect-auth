/**
 * HMAC-SHA-256 behind a service, keyed from `AuthConfig.secret`.
 *
 * Used wherever a value leaves the server and must come back unmodified without
 * a database round-trip.
 *
 * @since 1.0.0
 */
import { Context, Effect, Layer, Redacted } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"

/**
 * Signs and verifies byte strings with the instance secret.
 *
 * @category services
 * @since 1.0.0
 */
export class Hmac extends Context.Service<Hmac, {
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
}>()("effect-auth/Hmac") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

const utf8 = new TextEncoder()

const toArrayBuffer = (data: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(data.byteLength)
  new Uint8Array(buffer).set(data)
  return buffer
}

/**
 * Builds an {@link Hmac} implementation from a WebCrypto instance and a secret.
 *
 * **Details**
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
 * @since 1.0.0
 */
export const make = (
  crypto: Crypto,
  secret: Redacted.Redacted<string>
): Effect.Effect<Hmac["Service"]> =>
  Effect.map(
    Effect.promise(() =>
      crypto.subtle.importKey(
        "raw",
        toArrayBuffer(utf8.encode(Redacted.value(secret))),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      )
    ),
    (key) =>
      Hmac.of({
        sign: (data) =>
          Effect.map(
            Effect.promise(() => crypto.subtle.sign("HMAC", key, toArrayBuffer(data))),
            (mac) => new Uint8Array(mac)
          ),
        // `subtle.verify` is the constant-time comparison; recomputing the tag
        // and comparing it by hand would be the mistake this method exists to
        // prevent.
        verify: (data, mac) =>
          Effect.promise(() => crypto.subtle.verify("HMAC", key, toArrayBuffer(mac), toArrayBuffer(data)))
      })
  )

/**
 * Provides {@link Hmac} over WebCrypto, with the key imported once from
 * `AuthConfig.secret`.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Hmac, never, AuthConfig> = Layer.effect(
  Hmac,
  AuthConfig.use((config) => make(globalThis.crypto, config.secret))
)
