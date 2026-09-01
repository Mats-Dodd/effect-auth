/**
 * Authenticated encryption for the secrets a deployment has to be able to read
 * back: a TOTP shared secret, a provider credential, anything that is not a
 * password and therefore cannot be hashed away.
 *
 * **Details**
 *
 * AES-256-GCM under a key derived from `AuthConfig.secret` by HKDF-SHA-256,
 * with a distinct `info` per class of secret — so a TOTP secret and an OAuth
 * refresh token are encrypted under different keys derived from the same
 * deployment secret, and a ciphertext moved between the two is not readable.
 *
 * Every ciphertext is bound to where it is stored by its additional
 * authenticated data: a row's own identity goes into the AAD, so a ciphertext
 * copied into another row does not decrypt. That is the property a bare
 * `encrypt`/`decrypt` pair does not have, and the reason a plugin should never
 * write its own AES-GCM.
 *
 * **Gotchas**
 *
 * Encryption is reversible by anyone holding `AuthConfig.secret`. It defends a
 * leaked database dump, not a compromised process, and it is not a substitute
 * for hashing anything that never needs to be read back.
 *
 * @since 0.2.0
 */
import { Context, Effect, Encoding, Layer, Redacted, Result, Schema } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import { ambientCrypto, encodeUtf8, toArrayBuffer } from "../internal/crypto.js"

/**
 * A ciphertext this deployment did not write, or did not write *there*.
 *
 * **Details**
 *
 * One answer for a malformed envelope, a corrupt ciphertext, a tag that does
 * not check out and a value lifted out of another row: they are the same event
 * — the bytes are not what this deployment stored at this address — and telling
 * them apart would describe the key to whoever is probing.
 *
 * Not an HTTP error. A caller that reaches one is looking at a database its own
 * key no longer opens, which is an operational fault, not a bad request.
 *
 * @category errors
 * @since 0.2.0
 */
export class CipherError extends Schema.TaggedError<CipherError>("effect-auth/CipherError")(
  "CipherError",
  {},
  { description: "A stored ciphertext could not be decrypted at the location it was read from" }
) {}

/**
 * The {@link AuthCipher} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface AuthCipherService {
  /**
   * Encrypts `plain` and binds the ciphertext to `aad`.
   *
   * **Details**
   *
   * `aad` names where the ciphertext is about to be stored — a row id, a
   * column, a user id, joined however the caller likes. Whatever goes in here
   * has to be reproduced exactly at {@link AuthCipherService.decrypt}, and
   * anything that can change without the ciphertext being rewritten does not
   * belong in it.
   *
   * A string plaintext is UTF-8 encoded; bytes go in as they are.
   */
  readonly encrypt: (plain: Redacted.Redacted<Uint8Array | string>, aad: string) => Effect.Effect<string>

  /**
   * Decrypts a ciphertext read from the location `aad` names, as bytes.
   */
  readonly decrypt: (cipher: string, aad: string) => Effect.Effect<Redacted.Redacted<Uint8Array>, CipherError>

  /**
   * {@link AuthCipherService.decrypt}, UTF-8 decoded — for a secret that went
   * in as text.
   */
  readonly decryptText: (cipher: string, aad: string) => Effect.Effect<Redacted.Redacted, CipherError>
}

/**
 * Encrypts and decrypts stored secrets. See {@link AuthCipherService}.
 *
 * **Gotchas**
 *
 * One key class per provided instance: the key material is derived when the
 * layer is built, so a module wanting its own class of secret provides
 * {@link layer} with its own `keyInfo` privately, rather than expecting two
 * ciphers to coexist under one key.
 *
 * @category services
 * @since 0.2.0
 */
export class AuthCipher extends Context.Service<AuthCipher, AuthCipherService>()(
  "effect-auth/crypto/Cipher/AuthCipher"
) {}

/**
 * The envelope version. A change here is a format change, and every outstanding
 * ciphertext fails to decrypt rather than mis-decoding.
 *
 * @category constructors
 * @since 0.2.0
 */
export const formatVersion = "v1"

/** GCM's nonce length, in bytes — 96 bits, the only size the mode is defined for. */
const ivBytes = 12

/**
 * The HKDF salt. Domain separation, not password hardening: `AuthConfig`
 * already requires at least 32 bytes of input key material.
 */
const keySalt = encodeUtf8("effect-auth/cipher-key/v1")

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds an {@link AuthCipher} for one class of secret.
 *
 * **Details**
 *
 * `keyInfo` is the HKDF `info` *and* the prefix of every AAD, so it separates
 * the class twice over: two classes derive different keys, and a ciphertext
 * from one class presented to the other fails its tag check even if the keys
 * were somehow equal. Name it for the secret and version it —
 * `"effect-auth/totp-secret/v1"`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (keyInfo: string): Effect.Effect<AuthCipherService, never, AuthConfig> =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const crypto = ambientCrypto()

    const material = yield* Effect.promise(() =>
      crypto.subtle.importKey("raw", toArrayBuffer(encodeUtf8(Redacted.value(config.secret))), "HKDF", false, [
        "deriveKey"
      ])
    )
    const key = yield* Effect.promise(() =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(keySalt), info: toArrayBuffer(encodeUtf8(keyInfo)) },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      )
    )

    const additionalData = (aad: string): ArrayBuffer => toArrayBuffer(encodeUtf8(`${keyInfo}\n${aad}`))

    const decryptBytes = Effect.fnUntraced(function* (cipher: string, aad: string) {
      const segments = cipher.split(".")
      if (segments.length !== 3 || segments[0] !== formatVersion) return yield* CipherError.make()

      const iv = Encoding.decodeBase64Url(segments[1]!)
      const ciphertext = Encoding.decodeBase64Url(segments[2]!)
      if (Result.isFailure(iv) || iv.success.length !== ivBytes || Result.isFailure(ciphertext)) {
        return yield* CipherError.make()
      }

      // GCM reports a tag failure by rejecting; that rejection is the whole of
      // "this is not what we stored here", so it is a typed failure, not a
      // defect.
      const plaintext = yield* Effect.mapError(
        Effect.tryPromise(() =>
          crypto.subtle.decrypt(
            { name: "AES-GCM", iv: toArrayBuffer(iv.success), additionalData: additionalData(aad), tagLength: 128 },
            key,
            toArrayBuffer(ciphertext.success)
          )
        ),
        () => CipherError.make()
      )
      return new Uint8Array(plaintext)
    })

    return AuthCipher.of({
      encrypt: (plain, aad) =>
        Effect.gen(function* () {
          const value = Redacted.value(plain)
          const bytes = typeof value === "string" ? encodeUtf8(value) : value
          const iv = crypto.getRandomValues(new Uint8Array(ivBytes))
          const ciphertext = yield* Effect.promise(() =>
            crypto.subtle.encrypt(
              { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: additionalData(aad), tagLength: 128 },
              key,
              toArrayBuffer(bytes)
            )
          )
          return `${formatVersion}.${Encoding.encodeBase64Url(iv)}.${Encoding.encodeBase64Url(
            new Uint8Array(ciphertext)
          )}`
        }),
      decrypt: (cipher, aad) => Effect.map(decryptBytes(cipher, aad), Redacted.make),
      decryptText: (cipher, aad) =>
        Effect.map(decryptBytes(cipher, aad), (bytes) => Redacted.make(new TextDecoder().decode(bytes)))
    })
  })

/**
 * Provides {@link AuthCipher} for one class of secret, keyed from
 * `AuthConfig.secret`.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (keyInfo: string): Layer.Layer<AuthCipher, never, AuthConfig> =>
  Layer.effect(AuthCipher, make(keyInfo))
