/**
 * RFC 4648 base32, the alphabet every authenticator app speaks.
 *
 * A TOTP secret is exchanged as base32 — in the QR code's `otpauth://` URI and
 * in the "enter this key manually" fallback — because the alphabet survives
 * being read aloud, typed in caps, and printed on a recovery card. `Encoding`
 * ships base64, base64url and hex, and nothing else; this is the missing one.
 *
 * Not part of the public API.
 *
 * @internal
 */
import { Encoding, Result } from "effect"

/** The RFC 4648 base32 alphabet, uppercase. */
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/** The inverse of {@link alphabet}, built once: character code to 5-bit value. */
const lowercase = alphabet.toLowerCase()
const values = new Int8Array(128).fill(-1)
for (let index = 0; index < alphabet.length; index++) {
  values[alphabet.charCodeAt(index)] = index
  values[lowercase.charCodeAt(index)] = index
}

/** The character counts a whole number of bytes can encode to, by `length % 8`. */
const wholeGroups = new Set([0, 2, 4, 5, 7])

/**
 * Base32-encodes `bytes`: uppercase, and unpadded because `otpauth://` URIs
 * and manual-entry keys never carry `=`.
 *
 * @internal
 */
export const encode = (bytes: Uint8Array): string => {
  let out = ""
  let bits = 0
  let buffer = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += alphabet[(buffer >>> bits) & 0x1f]
    }
  }
  // The trailing partial group is left-aligned and zero-filled, which is what
  // makes the encoding canonical and what `decode` checks on the way back.
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 0x1f]
  return out
}

/**
 * Decodes a base32 string, in either case and with or without `=` padding.
 *
 * **Details**
 *
 * Strict on the way in: a length that no byte string encodes to, a character
 * outside the alphabet, and a trailing group whose fill bits are not zero are
 * all failures, so one byte string has exactly one accepted spelling. That
 * matters for a secret — two spellings of the same key is two rows that look
 * different and authenticate the same person.
 *
 * @internal
 */
export const decode = (text: string): Result.Result<Uint8Array, Encoding.EncodingError> => {
  const fail = (message: string): Result.Result<Uint8Array, Encoding.EncodingError> =>
    Result.fail(new Encoding.EncodingError({ kind: "Decode", module: "Base32", input: text, message }))

  let end = text.length
  while (end > 0 && text[end - 1] === "=") end--
  const body = text.slice(0, end)
  if (!wholeGroups.has(body.length % 8)) return fail("invalid base32 length")

  const out = new Uint8Array(Math.floor((body.length * 5) / 8))
  let at = 0
  let bits = 0
  let buffer = 0
  for (let index = 0; index < body.length; index++) {
    const code = body.charCodeAt(index)
    const value = code < 128 ? values[code]! : -1
    if (value < 0) return fail("invalid base32 character")
    buffer = (buffer << 5) | value
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out[at++] = (buffer >>> bits) & 0xff
    }
  }
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return fail("non-canonical base32 padding bits")
  return Result.succeed(out)
}
