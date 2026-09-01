/** Authenticated encryption for OAuth credentials persisted by the SQL store. */
import { Effect, Encoding, Redacted, Result } from "effect"
import { ambientCrypto, encodeUtf8, toArrayBuffer } from "./crypto.js"

const formatVersion = "v1"
const keySalt = encodeUtf8("effect-auth/provider-token-key/v1")
const keyInfo = encodeUtf8("AES-256-GCM")
const context = "effect-auth/provider-token/v1"
const ivBytes = 12

export type ProviderTokenField = "access_token" | "refresh_token" | "id_token"

export interface ProviderTokenCipher {
  readonly encrypt: (accountId: string, field: ProviderTokenField, value: string) => Effect.Effect<string>
  readonly decrypt: (accountId: string, field: ProviderTokenField, value: string) => Effect.Effect<string>
}

const aad = (accountId: string, field: ProviderTokenField): ArrayBuffer =>
  toArrayBuffer(encodeUtf8(`${context}\n${accountId}\n${field}`))

/**
 * Derives a non-extractable AES key from the deployment secret. The static
 * salt is domain separation, not password hardening: AuthConfig requires the
 * input key material to contain at least 32 bytes.
 */
export const make = (secret: Redacted.Redacted): Effect.Effect<ProviderTokenCipher> =>
  Effect.gen(function* () {
    const crypto = ambientCrypto()
    const material = yield* Effect.promise(() =>
      crypto.subtle.importKey("raw", toArrayBuffer(encodeUtf8(Redacted.value(secret))), "HKDF", false, ["deriveKey"])
    )
    const key = yield* Effect.promise(() =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(keySalt), info: toArrayBuffer(keyInfo) },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      )
    )

    return {
      encrypt: (accountId, field, value) =>
        Effect.gen(function* () {
          const iv = crypto.getRandomValues(new Uint8Array(ivBytes))
          const ciphertext = yield* Effect.promise(() =>
            crypto.subtle.encrypt(
              { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: aad(accountId, field), tagLength: 128 },
              key,
              toArrayBuffer(encodeUtf8(value))
            )
          )
          return `${formatVersion}.${Encoding.encodeBase64Url(iv)}.${Encoding.encodeBase64Url(new Uint8Array(ciphertext))}`
        }),
      decrypt: (accountId, field, value) =>
        Effect.gen(function* () {
          const segments = value.split(".")
          if (segments.length !== 3 || segments[0] !== formatVersion) {
            return yield* Effect.die(new Error("invalid encrypted provider token format"))
          }
          const iv = Encoding.decodeBase64Url(segments[1]!)
          const ciphertext = Encoding.decodeBase64Url(segments[2]!)
          if (Result.isFailure(iv) || iv.success.length !== ivBytes || Result.isFailure(ciphertext)) {
            return yield* Effect.die(new Error("invalid encrypted provider token encoding"))
          }
          const plaintext = yield* Effect.promise(() =>
            crypto.subtle.decrypt(
              {
                name: "AES-GCM",
                iv: toArrayBuffer(iv.success),
                additionalData: aad(accountId, field),
                tagLength: 128
              },
              key,
              toArrayBuffer(ciphertext.success)
            )
          )
          return new TextDecoder().decode(plaintext)
        })
    }
  })
