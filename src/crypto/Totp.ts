/**
 * HOTP and TOTP — RFC 4226 and RFC 6238 — on WebCrypto.
 *
 * The one-time codes an authenticator app produces. A shared secret and a
 * counter derived from the clock go in; six digits come out, and the server
 * recomputes them to check a code somebody typed.
 *
 * **Details**
 *
 * Hand-rolled on `subtle`, and it has to be: `effect/Crypto` offers random
 * bytes and digests, HMAC is neither, and {@link Hmac} is the wrong shape
 * anyway — it is keyed once from `AuthConfig.secret`, whereas every enrolment
 * here has a key of its own. So the key is imported per call, from the secret
 * the caller holds.
 *
 * The defaults are SHA-1, six digits and a thirty-second period, and they are
 * not a shrug: Google Authenticator silently ignores `algorithm` and `period`
 * (and, on Android, `digits`) in the `otpauth://` URI it scans, so a deployment
 * that enrols with stronger parameters gets an authenticator producing codes it
 * will reject. The interoperable choice is the weak-looking one, and the
 * strength that matters — the secret, its storage, the attempt budget and the
 * replay rule — is elsewhere.
 *
 * @since 0.2.0
 */
import { DateTime, Effect, Option } from "effect"
import { encode as encodeBase32 } from "../internal/base32.js"
import { ambientCrypto, toArrayBuffer } from "../internal/crypto.js"

/**
 * The hash a TOTP enrolment is parameterized by.
 *
 * **Gotchas**
 *
 * Anything but {@link defaultAlgorithm} is understood by 1Password, Authy and
 * Aegis, and ignored by Google Authenticator. See the module header.
 *
 * @category models
 * @since 0.2.0
 */
export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512"

/**
 * The hash every authenticator app agrees on.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultAlgorithm: TotpAlgorithm = "SHA-1"

/**
 * How many digits a code has, by default.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultDigits = 6

/**
 * How many seconds a step lasts, by default.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultPeriod = 30

/**
 * How many steps either side of the current one {@link verify} accepts by
 * default.
 *
 * **Details**
 *
 * One, which is RFC 6238 §5.2's recommendation: it covers a phone whose clock
 * drifts and a code typed as the period turns over, and it costs a factor of
 * three in guessing advantage — 3 in 10⁶ per attempt, against a budget that
 * ends in single digits.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultWindow = 1

// -----------------------------------------------------------------------------
// Mechanics
// -----------------------------------------------------------------------------

/** RFC 4226 fixes the counter at eight bytes, big-endian. */
const counterBytes = (counter: number): Uint8Array => {
  const bytes = new Uint8Array(8)
  // Split rather than shift: `<<` is 32-bit, and a step count outlives 2³² in
  // the year 138,000, which the RFC's own last test vector already anticipates.
  let high = Math.floor(counter / 0x100000000)
  let low = counter >>> 0
  for (let index = 7; index >= 4; index--) {
    bytes[index] = low & 0xff
    low = Math.floor(low / 0x100)
  }
  for (let index = 3; index >= 0; index--) {
    bytes[index] = high & 0xff
    high = Math.floor(high / 0x100)
  }
  return bytes
}

/**
 * RFC 4226 §5.4 dynamic truncation: the last nibble of the tag picks four
 * bytes out of it, the top bit of those goes (so the result is positive on a
 * signed 32-bit machine), and what is left is reduced to `digits` digits.
 */
const truncate = (mac: Uint8Array, digits: number): string => {
  const offset = mac[mac.length - 1]! & 0x0f
  const binary = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!
  return String(binary % 10 ** digits).padStart(digits, "0")
}

/** Imports one enrolment's secret as an HMAC key for the duration of a call. */
const importKey = (secret: Uint8Array, algorithm: TotpAlgorithm): Effect.Effect<CryptoKey> =>
  Effect.promise(() =>
    ambientCrypto().subtle.importKey("raw", toArrayBuffer(secret), { name: "HMAC", hash: algorithm }, false, ["sign"])
  )

/** The code for one counter under an already-imported key. */
const codeFor = (key: CryptoKey, counter: number, digits: number): Effect.Effect<string> =>
  Effect.map(
    Effect.promise(() => ambientCrypto().subtle.sign("HMAC", key, toArrayBuffer(counterBytes(counter)))),
    (mac) => truncate(new Uint8Array(mac), digits)
  )

/**
 * Compares two codes without short-circuiting on the first differing digit.
 * The length is not a secret; the digits are.
 */
const equalCodes = (presented: string, expected: string): boolean => {
  if (presented.length !== expected.length) return false
  let difference = 0
  for (let index = 0; index < presented.length; index++) {
    difference |= presented.charCodeAt(index) ^ expected.charCodeAt(index)
  }
  return difference === 0
}

const assertDigits = (digits: number): void => {
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new Error("a TOTP code must have between 6 and 8 digits (RFC 4226 §5.3)")
  }
}

// -----------------------------------------------------------------------------
// API
// -----------------------------------------------------------------------------

/**
 * What {@link generate} needs to know.
 *
 * @category models
 * @since 0.2.0
 */
export interface GenerateOptions {
  /** The enrolment's shared secret, raw bytes — base32 is a transport form. */
  readonly secret: Uint8Array
  /** The counter: for TOTP, `floor(epochSeconds / period)`. See {@link stepAt}. */
  readonly step: number
  /** How many digits the code has. Defaults to {@link defaultDigits}. */
  readonly digits?: number
  /** Which hash to key. Defaults to {@link defaultAlgorithm}. */
  readonly algorithm?: TotpAlgorithm
}

/**
 * Produces the code for one counter value.
 *
 * **When to use**
 *
 * To show a caller what their authenticator should be showing — a test
 * fixture, a recovery tool, an enrolment confirmation. A verifier uses
 * {@link verify}, which owns the window and the replay rule.
 *
 * @category constructors
 * @since 0.2.0
 */
export const generate = (options: GenerateOptions): Effect.Effect<string> =>
  Effect.suspend(() => {
    const digits = options.digits ?? defaultDigits
    assertDigits(digits)
    return Effect.flatMap(importKey(options.secret, options.algorithm ?? defaultAlgorithm), (key) =>
      codeFor(key, options.step, digits)
    )
  })

/**
 * The TOTP step a moment falls in: `floor(epochSeconds / period)`.
 *
 * @category combinators
 * @since 0.2.0
 */
export const stepAt = (now: DateTime.Utc, period: number = defaultPeriod): number =>
  Math.floor(DateTime.toEpochMillis(now) / 1000 / period)

/**
 * What {@link verify} needs to know.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyOptions {
  /** The enrolment's shared secret, raw bytes. */
  readonly secret: Uint8Array
  /** Exactly what the person typed, already stripped of spaces by the caller. */
  readonly code: string
  /** Now, from the `Clock` — never `Date`. */
  readonly now: DateTime.Utc
  /** How many steps either side of the current one to accept. Defaults to {@link defaultWindow}. */
  readonly window?: number
  /**
   * The step this enrolment last authenticated with, or `null` if it never has.
   *
   * **Details**
   *
   * The replay rule, and it is not optional: within one period an accepted
   * code stays valid, so a code read off a shoulder, a phishing page or a
   * proxied form works a second time unless the step it belongs to is refused
   * afterwards. Persist the returned step against the enrolment and pass it
   * back here.
   */
  readonly lastUsedStep: number | null
  /** How many seconds a step lasts. Defaults to {@link defaultPeriod}. */
  readonly period?: number
  /** How many digits a code has. Defaults to {@link defaultDigits}. */
  readonly digits?: number
  /** Which hash is keyed. Defaults to {@link defaultAlgorithm}. */
  readonly algorithm?: TotpAlgorithm
}

/**
 * Checks a code against every step in the window, and answers the step it
 * matched.
 *
 * **Details**
 *
 * `None` is every way of being wrong: a code of the wrong length, a code for
 * no step in the window, and a code for a step at or below `lastUsedStep`.
 * A step at or below `lastUsedStep` is refused *before* it is compared, so a
 * replay cannot succeed even when the digits are right.
 *
 * Every candidate in the window is computed, and the comparison does not
 * short-circuit, so the time this takes says nothing about which step matched
 * or how close a wrong code was.
 *
 * **Gotchas**
 *
 * A match is not by itself an authentication: the caller still owes the attempt
 * budget that stops an attacker spending a million guesses, and owes storing
 * the returned step so the same code cannot be presented twice.
 *
 * @category combinators
 * @since 0.2.0
 */
export const verify = (options: VerifyOptions): Effect.Effect<Option.Option<number>> =>
  Effect.suspend(() => {
    const digits = options.digits ?? defaultDigits
    assertDigits(digits)
    const window = options.window ?? defaultWindow
    const current = stepAt(options.now, options.period ?? defaultPeriod)

    const candidates: Array<number> = []
    for (let delta = -window; delta <= window; delta++) {
      const step = current + delta
      if (options.lastUsedStep !== null && step <= options.lastUsedStep) continue
      candidates.push(step)
    }
    if (candidates.length === 0 || options.code.length !== digits) return Effect.succeedNone

    return Effect.flatMap(importKey(options.secret, options.algorithm ?? defaultAlgorithm), (key) =>
      Effect.map(
        Effect.forEach(candidates, (step) => codeFor(key, step, digits)),
        (codes) => {
          // Every candidate is compared, and the earliest match wins: an early
          // return would make the wall clock report which step it was.
          let matched: number | null = null
          for (let index = 0; index < codes.length; index++) {
            if (equalCodes(options.code, codes[index]!) && matched === null) matched = candidates[index]!
          }
          return matched === null ? Option.none<number>() : Option.some(matched)
        }
      )
    )
  })

/**
 * What {@link otpauthUri} needs to know.
 *
 * @category models
 * @since 0.2.0
 */
export interface UriOptions {
  /** The deployment's name, as the authenticator app should list it. */
  readonly issuer: string
  /** Who the enrolment belongs to — an address or a username, not an id. */
  readonly account: string
  /** The shared secret, raw bytes; base32 is what goes on the wire. */
  readonly secret: Uint8Array
  /** Defaults to {@link defaultAlgorithm}. */
  readonly algorithm?: TotpAlgorithm
  /** Defaults to {@link defaultDigits}. */
  readonly digits?: number
  /** Defaults to {@link defaultPeriod}. */
  readonly period?: number
}

/**
 * Builds the `otpauth://totp/…` URI an authenticator app scans out of a QR
 * code.
 *
 * **Details**
 *
 * The label is `issuer:account` and the `issuer` parameter repeats it, which is
 * what the Key Uri Format asks for and what stops two deployments' enrolments
 * for the same address colliding in the app's list. The secret is base32,
 * uppercase and unpadded.
 *
 * **Gotchas**
 *
 * The URI carries the secret in the clear. It is shown once, over TLS, to the
 * person enrolling, and never logged or stored.
 *
 * @category constructors
 * @since 0.2.0
 */
export const otpauthUri = (options: UriOptions): string => {
  const label = `${encodeURIComponent(options.issuer)}:${encodeURIComponent(options.account)}`
  const parameters = [
    `secret=${encodeBase32(options.secret)}`,
    `issuer=${encodeURIComponent(options.issuer)}`,
    // The Key Uri Format spells the hash without its dash.
    `algorithm=${(options.algorithm ?? defaultAlgorithm).replace("-", "")}`,
    `digits=${options.digits ?? defaultDigits}`,
    `period=${options.period ?? defaultPeriod}`
  ]
  return `otpauth://totp/${label}?${parameters.join("&")}`
}
