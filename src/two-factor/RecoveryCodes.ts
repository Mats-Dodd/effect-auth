/**
 * What a recovery code looks like, and how one is read back.
 *
 * **Details**
 *
 * Twelve characters of Crockford's base32 — sixty bits — printed in three
 * groups of four, `ABCD-EFGH-JKMN`. Crockford's alphabet is the one to use for
 * something a person copies off a screen onto paper and types back months
 * later: it has no `I`, `L`, `O` or `U`, and it says what to do with the
 * characters somebody will type anyway — `I` and `L` are `1`, `O` is `0`.
 * {@link normalise} applies exactly that, plus case folding and the removal of
 * whatever separators the person kept, so one code has one stored form and a
 * transcription that is right in substance is not refused on presentation.
 *
 * Sixty bits is the number that matters: ten codes are ten independent
 * 2⁻⁶⁰ guesses against a keyed hash, which is why the code can afford to be
 * short enough to write down. Shortening it further is not a formatting choice.
 *
 * @since 0.2.0
 */
import { Crypto, Effect, Redacted } from "effect"

/**
 * Crockford's base32 alphabet: the digits, then the letters, less `I`, `L`,
 * `O` and `U`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

/**
 * How many characters a code has.
 *
 * @category constructors
 * @since 0.2.0
 */
export const codeLength = 12

/**
 * How many characters go between the dashes.
 *
 * @category constructors
 * @since 0.2.0
 */
export const groupSize = 4

/**
 * The separator a printed code carries.
 *
 * @category constructors
 * @since 0.2.0
 */
export const separator = "-"

/**
 * Puts the dashes into a normalised code: `ABCDEFGHJKMN` → `ABCD-EFGH-JKMN`.
 *
 * **When to use**
 *
 * On the way out, once, when the codes are shown. The stored form and the form
 * every comparison happens in is the *normalised* one.
 *
 * @category combinators
 * @since 0.2.0
 */
export const format = (code: string): string => {
  const groups: Array<string> = []
  for (let at = 0; at < code.length; at += groupSize) groups.push(code.slice(at, at + groupSize))
  return groups.join(separator)
}

/**
 * The one accepted spelling of whatever somebody typed.
 *
 * **Details**
 *
 * Upper-cases, drops every character outside the alphabet — the dashes it was
 * printed with, the spaces a mail client inserted — and folds Crockford's
 * documented confusables: `O` is `0`, `I` and `L` are `1`. Nothing else is
 * interpreted, so a code with a genuinely wrong character normalises to
 * something that simply does not match.
 *
 * **Gotchas**
 *
 * This is not a validity check. It is the function both {@link generate}'s
 * output and a presented code go through, so that "the same code" means the
 * same string before either is hashed.
 *
 * @category combinators
 * @since 0.2.0
 */
export const normalise = (input: string): string => {
  let out = ""
  for (const character of input.toUpperCase()) {
    if (character === "O") out += "0"
    else if (character === "I" || character === "L") out += "1"
    else if (alphabet.includes(character)) out += character
  }
  return out
}

/**
 * Mints `count` fresh codes, normalised.
 *
 * **Details**
 *
 * One random byte per character, taken modulo 32 — which is exact, since 32
 * divides 256, so no character is more likely than another and no rejection
 * sampling is needed. The randomness is `effect/Crypto`'s, never `Random`,
 * which is seedable.
 *
 * Each code is `Redacted`: it exists in the response that shows it once and
 * nowhere else, since only a keyed digest is stored.
 *
 * @category constructors
 * @since 0.2.0
 */
export const generate = (count: number): Effect.Effect<ReadonlyArray<Redacted.Redacted>, never, Crypto.Crypto> =>
  Effect.gen(function* () {
    const crypto = yield* Crypto.Crypto
    const bytes = yield* Effect.orDie(crypto.randomBytes(count * codeLength))
    const codes: Array<Redacted.Redacted> = []
    for (let index = 0; index < count; index++) {
      let code = ""
      for (let position = 0; position < codeLength; position++) {
        code += alphabet[bytes[index * codeLength + position]! & 0x1f]
      }
      codes.push(Redacted.make(code))
    }
    return codes
  })
