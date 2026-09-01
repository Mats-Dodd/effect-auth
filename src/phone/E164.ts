/**
 * E.164, hand-rolled: one parse, one canonical form, applied at every boundary.
 *
 * **Details**
 *
 * A phone number is the primary key of this plugin's table and the subject of
 * its challenges, so `+1 (555) 010-0000` and `+15550100000` must not be two
 * different people. Everything here is a *transform* rather than a predicate:
 * {@link normalize} either produces the one canonical spelling or refuses, and
 * nothing in the plugin ever stores, keys or compares anything else. That is
 * the whole reason this module exists — a validator called on two of six paths
 * is how the same handset ends up owning two accounts.
 *
 * The grammar is deliberately narrow: a leading `+`, then between
 * {@link minDigits} and {@link maxDigits} ASCII digits, the first of which is
 * not `0`. Spaces, tabs, hyphens, dots, slashes and parentheses are cosmetic
 * and dropped; everything else — letters, an extension marker, a `00`
 * international prefix, full-width digits — is refused rather than guessed at,
 * because guessing is how a number becomes a different number.
 *
 * **Gotchas**
 *
 * This is not a national-format parser and does not know that `+1 555 0100` is
 * short for anything. A deployment that wants `libphonenumber`'s knowledge
 * normalises with it first and hands the result in; this module then agrees
 * with it, because a `libphonenumber` E.164 output is a member of this grammar.
 *
 * @since 0.2.0
 */
import { Option } from "effect"

// -----------------------------------------------------------------------------
// The grammar
// -----------------------------------------------------------------------------

/**
 * The most digits an E.164 number may carry, country code included — ITU-T
 * E.164 §6.2.1.
 *
 * @category constructors
 * @since 0.2.0
 */
export const maxDigits = 15

/**
 * The fewest digits this module accepts.
 *
 * **Gotchas**
 *
 * Seven, which is the shortest assignment in use (a two-digit country code and
 * a five-digit subscriber number). It is a sanity bound rather than a
 * validation: E.164 states no global minimum, so a number shorter than this is
 * far more likely to be a truncated one than a real one.
 *
 * @category constructors
 * @since 0.2.0
 */
export const minDigits = 7

/**
 * The most digits a country calling code has — ITU-T E.164 assigns one, two or
 * three.
 *
 * @category constructors
 * @since 0.2.0
 */
export const maxCountryCodeDigits = 3

/**
 * The longest input {@link normalize} will look at.
 *
 * Nothing legitimate is anywhere near this; it is here so that a caller cannot
 * hand the parser a megabyte of text to walk.
 *
 * @category constructors
 * @since 0.2.0
 */
export const maxInputLength = 64

/** Cosmetic characters a person types and a keypad shows, dropped on the way in. */
const separators: ReadonlySet<string> = new Set([" ", "\t", "-", ".", "/", "(", ")", "\u00a0"])

const isAsciiDigit = (character: string): boolean => character >= "0" && character <= "9"

// -----------------------------------------------------------------------------
// Normalisation
// -----------------------------------------------------------------------------

/**
 * The one canonical spelling of a number, or nothing at all.
 *
 * **When to use**
 *
 * At every boundary that takes a number from a caller — the endpoint payload,
 * the service method, the store key. It is cheap and idempotent, so calling it
 * twice costs nothing and forgetting it once costs a duplicate account.
 *
 * **Example**
 *
 * ```ts
 * import { Option } from "effect"
 * import { Phone } from "effect-auth"
 *
 * const number = Phone.E164.normalize("+1 (555) 010-0000")
 * // Option.some("+15550100000")
 * const refused = Option.isNone(Phone.E164.normalize("555-0100"))
 * // true — no country code, so there is nothing to normalise it against
 * ```
 *
 * @category combinators
 * @since 0.2.0
 */
export const normalize = (input: string): Option.Option<string> => {
  if (input.length > maxInputLength) return Option.none()
  let digits = ""
  let plus = false
  for (const character of input) {
    if (separators.has(character)) continue
    if (character === "+") {
      // A `+` anywhere but in front is not a formatting flourish; it is a
      // second number, an extension, or something this module cannot read.
      if (plus || digits.length > 0) return Option.none()
      plus = true
      continue
    }
    if (isAsciiDigit(character)) {
      digits += character
      continue
    }
    return Option.none()
  }
  if (!plus) return Option.none()
  if (digits.length < minDigits || digits.length > maxDigits) return Option.none()
  // No assigned country code begins with zero, and a leading zero is what a
  // national trunk prefix looks like when somebody has pasted one in.
  if (digits.startsWith("0")) return Option.none()
  return Option.some(`+${digits}`)
}

/**
 * Whether `input` names exactly one E.164 number.
 *
 * **Gotchas**
 *
 * A guard, for a schema check. Everything that goes on to *use* the number
 * calls {@link normalize} instead — a predicate that passes and a value that is
 * still in the caller's spelling is the bug this module is written against.
 *
 * @category guards
 * @since 0.2.0
 */
export const isValid = (input: string): boolean => Option.isSome(normalize(input))

/**
 * The digits of a canonical number, without the `+`.
 *
 * @category combinators
 * @since 0.2.0
 */
export const digitsOf = (e164: string): string => (e164.startsWith("+") ? e164.slice(1) : e164)

// -----------------------------------------------------------------------------
// Country codes
// -----------------------------------------------------------------------------

/** Whether `candidate` could be a country calling code at all. */
const isCallingCode = (candidate: string): boolean => {
  if (candidate.length < 1 || candidate.length > maxCountryCodeDigits) return false
  if (candidate.startsWith("0")) return false
  for (let index = 0; index < candidate.length; index++) {
    if (!isAsciiDigit(candidate.charAt(index))) return false
  }
  return true
}

/**
 * The country calling code of `e164`, chosen from the codes a deployment opted
 * in to.
 *
 * **Details**
 *
 * There is no country-code table here, and there is deliberately not going to
 * be one: this library does not know that `+1` is shared by twenty countries or
 * that `+2` is not a code at all. What it knows is which codes the deployment
 * said it would send to, and the longest of those that this number starts with
 * is its country. A number matching none of them belongs to no country this
 * deployment serves, which is the only question the plugin ever asks.
 *
 * The longest match wins, so a deployment listing overlapping entries gets the
 * same answer whatever order it wrote them in, and each gets a prefix bucket of
 * its own.
 *
 * @category combinators
 * @since 0.2.0
 */
export const countryCodeOf = (allowed: ReadonlyArray<string>, e164: string): Option.Option<string> => {
  const digits = digitsOf(e164)
  let best: string | null = null
  for (const candidate of allowed) {
    if (!isCallingCode(candidate)) continue
    if (!digits.startsWith(candidate)) continue
    if (best === null || candidate.length > best.length) best = candidate
  }
  return best === null ? Option.none() : Option.some(best)
}

/**
 * Whether a deployment that opted in to `allowed` will send to this number.
 *
 * **Gotchas**
 *
 * An empty `allowed` refuses everything. That is the default, and it is the
 * point: an SMS is the one thing this library does that costs money per
 * request, so the deployment states where its messages may go before the first
 * one leaves.
 *
 * @category guards
 * @since 0.2.0
 */
export const isAllowed = (allowed: ReadonlyArray<string>, e164: string): boolean =>
  Option.isSome(countryCodeOf(allowed, e164))

/**
 * How many digits of a number a destination-prefix rate limit counts against.
 *
 * @category constructors
 * @since 0.2.0
 */
export const prefixDigits = 3

/**
 * The destination prefix a toll-fraud bucket is keyed on: the country code and
 * the {@link prefixDigits} digits after it.
 *
 * **Details**
 *
 * A stolen credential card pays for traffic to one expensive range, not to one
 * number, so the per-number bucket alone does not see the attack. The prefix is
 * the coarsest thing that is still a real destination.
 *
 * @category combinators
 * @since 0.2.0
 */
export const prefixOf = (countryCode: string, e164: string): string =>
  `+${digitsOf(e164).slice(0, countryCode.length + prefixDigits)}`

// -----------------------------------------------------------------------------
// Display
// -----------------------------------------------------------------------------

/**
 * A number with its middle hidden — `+15550100000` reads `+15…0000`.
 *
 * **When to use**
 *
 * Wherever a number is shown back to somebody rather than used: the name of an
 * `Authenticators` summary, a log line. The full number is stored and the
 * account's owner can always read it from their own record; nothing else needs
 * to.
 *
 * @category combinators
 * @since 0.2.0
 */
export const mask = (e164: string): string => {
  const digits = digitsOf(e164)
  if (digits.length <= 6) return `+${digits}`
  return `+${digits.slice(0, 2)}…${digits.slice(-4)}`
}
