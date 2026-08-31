/**
 * The plumbing every `crypto/` module used to keep its own copy of: the one
 * `TextEncoder`, the one `ArrayBuffer` copy, and the default `Crypto.Crypto`
 * implementation this library falls back to when nothing else provides one.
 *
 * Not part of the public API.
 *
 * @internal
 */
import { Crypto, Effect, Layer } from "effect"

const utf8 = new TextEncoder()

/**
 * UTF-8 encodes `text`.
 *
 * @internal
 */
export const encodeUtf8 = (text: string): Uint8Array => utf8.encode(text)

/**
 * `crypto.subtle` wants an `ArrayBuffer` that it owns; a `Uint8Array` view over
 * a pooled buffer (which is what `TextEncoder` and Node's `Buffer` hand back)
 * can be a window onto a much larger allocation.
 *
 * @internal
 */
export const toArrayBuffer = (data: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(data.byteLength)
  new Uint8Array(buffer).set(data)
  return buffer
}

/**
 * `Crypto.Crypto` over the runtime's WebCrypto (`globalThis.crypto`).
 *
 * **Details**
 *
 * Runtime-neutral: `getRandomValues` and `subtle.digest` are the only two
 * globals it touches, and both are present on Node, Bun, Deno and every edge
 * runtime. A deployment that would rather bind a platform implementation
 * provides its own `Crypto.Crypto` layer instead.
 *
 * A digest failure means the runtime's WebCrypto is broken, not that the
 * request was bad, so it surfaces as a defect rather than a `PlatformError`.
 *
 * @internal
 */
export const webCrypto: Crypto.Crypto = Crypto.make({
  randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
  digest: (algorithm, data) =>
    Effect.map(
      Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, toArrayBuffer(data))),
      (digest) => new Uint8Array(digest)
    )
})

/**
 * {@link webCrypto} as a layer.
 *
 * @internal
 */
export const layerWebCrypto: Layer.Layer<Crypto.Crypto> = Layer.succeed(Crypto.Crypto)(webCrypto)
