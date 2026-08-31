/**
 * Password hashing behind a service.
 *
 * Two interchangeable layers: {@link layerScrypt}, the default, backed by
 * `node:crypto`'s scrypt; and {@link layerPbkdf2}, backed by WebCrypto and
 * therefore available on every runtime. Both write a self-describing hash
 * string, and both `verify` implementations dispatch on that description, so a
 * deployment can move between them — and to a future algorithm — without
 * invalidating stored passwords.
 *
 * Stored format, `$`-separated:
 *
 * ```
 * scrypt$n=16384,r=16,p=1$<base64url salt>$<base64url key>
 * pbkdf2$i=600000$<base64url salt>$<base64url key>
 * ```
 *
 * @since 1.0.0
 */
import { Context, Crypto, Effect, Encoding, Layer, Redacted, Result } from "effect"
import { PasswordHashError } from "../domain/Errors.js"
import { ambientCrypto, encodeUtf8, toArrayBuffer } from "../internal/crypto.js"

/**
 * The {@link PasswordHasher} service definition.
 *
 * **Details**
 *
 * The plaintext only ever appears as `Redacted<string>`, so it cannot be
 * printed by a log line, a `toString`, or an error report. Implementations
 * unwrap it immediately before handing the bytes to the KDF.
 *
 * @category models
 * @since 1.0.0
 */
export interface PasswordHasherService {
  /**
   * Derives a hash for a new password, with a fresh random salt.
   */
  readonly hash: (password: Redacted.Redacted<string>) => Effect.Effect<string, PasswordHashError>

  /**
   * Checks a password against a stored hash.
   *
   * **Details**
   *
   * Returns `false` for a wrong password and fails with `PasswordHashError`
   * only when the stored string cannot be interpreted or the primitive is
   * unavailable — the two must stay distinguishable, because sign-in treats a
   * `false` as invalid credentials and a failure as a server fault.
   *
   * The digest comparison is constant time (see {@link timingSafeEqualUint8}).
   */
  readonly verify: (
    password: Redacted.Redacted<string>,
    hash: string
  ) => Effect.Effect<boolean, PasswordHashError>
}

/**
 * Hashes and verifies passwords. See {@link PasswordHasherService}.
 *
 * @category services
 * @since 1.0.0
 */
export class PasswordHasher
  extends Context.Service<PasswordHasher, PasswordHasherService>()("effect-auth/PasswordHasher")
{}

// -----------------------------------------------------------------------------
// Parameters
// -----------------------------------------------------------------------------

/**
 * scrypt cost parameters.
 *
 * @category models
 * @since 1.0.0
 */
export interface ScryptOptions {
  /**
   * CPU/memory cost. A power of two. Default 16384.
   */
  readonly N?: number | undefined
  /**
   * Block size. Default 16.
   */
  readonly r?: number | undefined
  /**
   * Parallelization. Default 1.
   */
  readonly p?: number | undefined
  /**
   * Derived key length in bytes. Default 64.
   */
  readonly dkLen?: number | undefined
}

/**
 * PBKDF2 parameters.
 *
 * @category models
 * @since 1.0.0
 */
export interface Pbkdf2Options {
  /**
   * Iteration count. Default 600000, the OWASP figure for PBKDF2-HMAC-SHA512.
   */
  readonly iterations?: number | undefined
  /**
   * Derived key length in bytes. Default 64.
   */
  readonly dkLen?: number | undefined
}

/**
 * The default scrypt parameters: `N=16384, r=16, p=1`, 64-byte key.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultScryptOptions = {
  N: 16384,
  r: 16,
  p: 1,
  dkLen: 64
} as const

/**
 * The default PBKDF2 parameters: 600000 iterations of HMAC-SHA-512, 64-byte
 * key.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultPbkdf2Options = {
  iterations: 600_000,
  dkLen: 64
} as const

/**
 * The number of random salt bytes each hash is given.
 *
 * @category constructors
 * @since 1.0.0
 */
export const saltBytes = 16

/**
 * The algorithm labels that can begin a stored hash.
 *
 * @category models
 * @since 1.0.0
 */
export type HashAlgorithm = "scrypt" | "pbkdf2"

/**
 * A stored hash string taken apart.
 *
 * @category models
 * @since 1.0.0
 */
export interface ParsedHash {
  readonly algorithm: HashAlgorithm
  /**
   * The comma-separated parameter segment, for example `"n=16384,r=16,p=1"`,
   * parsed into an own-property-only dictionary.
   */
  readonly params: Record<string, string>
  readonly salt: Uint8Array
  readonly key: Uint8Array
}

// -----------------------------------------------------------------------------
// Constant-time comparison
// -----------------------------------------------------------------------------

/**
 * Compares two byte strings in time that does not depend on where they first
 * differ.
 *
 * **Gotchas**
 *
 * Length is not secret here — digest lengths are fixed by the algorithm — so an
 * early return on differing lengths is safe. Never compare digests with `===`
 * on their encoded strings: a short-circuiting comparison leaks a byte at a
 * time.
 *
 * @category combinators
 * @since 1.0.0
 */
export const timingSafeEqualUint8 = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!
  }
  return diff === 0
}

// -----------------------------------------------------------------------------
// Hash format
// -----------------------------------------------------------------------------

const hashError = (reason: string, cause?: unknown): PasswordHashError => new PasswordHashError({ reason, cause })

/**
 * The shortest digest a stored hash may carry.
 *
 * **Details**
 *
 * Both KDFs here are prefix-stable in their output length, so a stored hash
 * truncated to a handful of bytes would still verify — against a
 * correspondingly tiny search space. Refusing short digests outright removes
 * that class of database-tampering attack.
 */
const minimumDigestBytes = 16

const formatHash = (
  algorithm: HashAlgorithm,
  params: string,
  salt: Uint8Array,
  key: Uint8Array
): string => `${algorithm}$${params}$${Encoding.encodeBase64Url(salt)}$${Encoding.encodeBase64Url(key)}`

/**
 * Splits a stored hash string into its parts.
 *
 * **Details**
 *
 * The parameter segment is read into a dictionary created with a `null`
 * prototype: the string comes out of the database, and a `__proto__=` pair in
 * it must be an ordinary key rather than a way to reach `Object.prototype`.
 *
 * @category combinators
 * @since 1.0.0
 */
export const parseHash = (hash: string): Effect.Effect<ParsedHash, PasswordHashError> =>
  Effect.suspend(() => {
    const segments = hash.split("$")
    if (segments.length !== 4) {
      return Effect.fail(hashError("MalformedHash"))
    }
    const [algorithm, parameterSegment, saltSegment, keySegment] = segments as [string, string, string, string]
    if (algorithm !== "scrypt" && algorithm !== "pbkdf2") {
      return Effect.fail(hashError("UnknownAlgorithm"))
    }

    const params: Record<string, string> = Object.create(null)
    if (parameterSegment.length > 0) {
      for (const pair of parameterSegment.split(",")) {
        const separator = pair.indexOf("=")
        if (separator <= 0) {
          return Effect.fail(hashError("MalformedParameters"))
        }
        params[pair.slice(0, separator)] = pair.slice(separator + 1)
      }
    }

    const salt = Encoding.decodeBase64Url(saltSegment)
    if (Result.isFailure(salt) || salt.success.length === 0) {
      return Effect.fail(hashError("MalformedSalt"))
    }
    const key = Encoding.decodeBase64Url(keySegment)
    if (Result.isFailure(key) || key.success.length < minimumDigestBytes) {
      return Effect.fail(hashError("MalformedDigest"))
    }

    return Effect.succeed<ParsedHash>({
      algorithm,
      params,
      salt: salt.success,
      key: key.success
    })
  })

/**
 * The largest cost parameters a *stored* hash may ask verification to spend.
 *
 * **Details**
 *
 * The stored string names its own cost, which is what lets an old hash keep
 * verifying after the defaults move. It also means the cost of a sign-in
 * attempt is read out of the database — so a single tampered row could ask for
 * hundreds of gibibytes of `maxmem` (an allocation failure, i.e. a `500`) or
 * minutes of CPU, once per attempt, from an unauthenticated caller. These
 * ceilings are generous next to the defaults (N=16384, r=16, p=1;
 * i=600_000) and refuse anything beyond them, in the same spirit as
 * {@link minimumDigestBytes}.
 */
const parameterCeiling = (name: string): number | undefined => {
  switch (name) {
    // 2^22 scrypt iterations: ~4 GiB at r=8, far past any sane deployment.
    case "n":
      return 4_194_304
    case "r":
      return 32
    case "p":
      return 16
    case "i":
      return 10_000_000
    default:
      return undefined
  }
}

const positiveIntParam = (
  params: Record<string, string>,
  name: string,
  reason: string
): Effect.Effect<number, PasswordHashError> => {
  if (!Object.hasOwn(params, name)) {
    return Effect.fail(hashError(reason))
  }
  const value = Number(params[name])
  if (!Number.isSafeInteger(value) || value <= 0) {
    return Effect.fail(hashError(reason))
  }
  const ceiling = parameterCeiling(name)
  return ceiling !== undefined && value > ceiling
    ? Effect.fail(hashError(reason))
    : Effect.succeed(value)
}

// -----------------------------------------------------------------------------
// Primitives
// -----------------------------------------------------------------------------

/**
 * `node:crypto` is imported dynamically so that this module stays importable —
 * and {@link layerPbkdf2} stays usable — on runtimes that have no such builtin.
 *
 * **Details**
 *
 * There is no memo around this: the runtime's own module registry already
 * resolves a repeated `import("node:crypto")` from cache, and hoisting the
 * import to layer construction would mean {@link layerScrypt} could *fail to
 * build* where `node:crypto` is missing — which is exactly the case
 * {@link layerPbkdf2} exists to keep working.
 */
const loadNodeCrypto = Effect.tryPromise({
  try: () => import("node:crypto"),
  catch: (cause) => hashError("ScryptUnavailable", cause)
})

interface ScryptParams {
  readonly N: number
  readonly r: number
  readonly p: number
  readonly dkLen: number
}

/**
 * Node refuses a scrypt call whose working set exceeds `maxmem`, and its
 * 32 MiB default is exactly the amount `N=16384, r=16` needs — so the specified
 * parameters fail unless the bound is raised explicitly.
 */
const scryptMaxmem = (params: ScryptParams): number => 2 * 128 * params.N * params.r + 1024 * 1024

const scryptDerive = (
  password: string,
  salt: Uint8Array,
  params: ScryptParams
): Effect.Effect<Uint8Array, PasswordHashError> =>
  Effect.flatMap(loadNodeCrypto, (nodeCrypto) =>
    Effect.callback<Uint8Array, PasswordHashError>((resume) => {
      nodeCrypto.scrypt(
        password,
        salt,
        params.dkLen,
        { N: params.N, r: params.r, p: params.p, maxmem: scryptMaxmem(params) },
        (error, derived) =>
          resume(
            error === null
              ? Effect.succeed(new Uint8Array(derived))
              : Effect.fail(hashError("ScryptFailed", error))
          )
      )
      // Node rejects some parameter combinations — a non-power-of-two `N`, for
      // instance — by throwing before it ever reaches the callback. A stored
      // hash is attacker-writable, so that has to stay a typed failure rather
      // than become a defect.
    }).pipe(Effect.catchDefect((cause) => Effect.fail(hashError("ScryptFailed", cause)))))

interface Pbkdf2Params {
  readonly iterations: number
  readonly dkLen: number
}

/**
 * PBKDF2 is a WebCrypto `subtle` operation, and `Crypto.Crypto` offers random
 * bytes and message digests only — so this one reaches for the ambient
 * WebCrypto handle (via `internal/crypto`) directly. The salt, which *is* just random bytes, comes from the service.
 */
const pbkdf2Derive = (
  password: string,
  salt: Uint8Array,
  params: Pbkdf2Params
): Effect.Effect<Uint8Array, PasswordHashError> =>
  Effect.tryPromise({
    try: async () => {
      const subtle = ambientCrypto().subtle
      const key = await subtle.importKey(
        "raw",
        toArrayBuffer(encodeUtf8(password)),
        "PBKDF2",
        false,
        ["deriveBits"]
      )
      const bits = await subtle.deriveBits(
        { name: "PBKDF2", salt: toArrayBuffer(salt), iterations: params.iterations, hash: "SHA-512" },
        key,
        params.dkLen * 8
      )
      return new Uint8Array(bits)
    },
    catch: (cause) => hashError("Pbkdf2Failed", cause)
  })

// -----------------------------------------------------------------------------
// Cross-format verification
// -----------------------------------------------------------------------------

/**
 * Verifies a password against a hash in either stored format.
 *
 * **Details**
 *
 * This is the single `verify` both layers install, which is what lets a
 * deployment switch layers — or roll one out gradually — without logging
 * everybody out. The stored string names its own algorithm and cost, so a hash
 * written years ago verifies with the parameters it was written with, not with
 * today's.
 *
 * A wrong password is `false`; an uninterpretable stored string or an
 * unavailable primitive is a `PasswordHashError`. Collapsing those two would
 * turn a broken deployment into a wave of "invalid credentials".
 *
 * @category combinators
 * @since 1.0.0
 */
export const verifyHash = (
  password: Redacted.Redacted<string>,
  hash: string
): Effect.Effect<boolean, PasswordHashError> =>
  Effect.flatMap(parseHash(hash), (parsed) => {
    const plaintext = Redacted.value(password)
    return parsed.algorithm === "scrypt"
      ? Effect.gen(function*() {
        const N = yield* positiveIntParam(parsed.params, "n", "MalformedScryptParameters")
        const r = yield* positiveIntParam(parsed.params, "r", "MalformedScryptParameters")
        const p = yield* positiveIntParam(parsed.params, "p", "MalformedScryptParameters")
        const derived = yield* scryptDerive(plaintext, parsed.salt, { N, r, p, dkLen: parsed.key.length })
        return timingSafeEqualUint8(derived, parsed.key)
      })
      : Effect.gen(function*() {
        const iterations = yield* positiveIntParam(parsed.params, "i", "MalformedPbkdf2Parameters")
        const derived = yield* pbkdf2Derive(plaintext, parsed.salt, {
          iterations,
          dkLen: parsed.key.length
        })
        return timingSafeEqualUint8(derived, parsed.key)
      })
  })

// -----------------------------------------------------------------------------
// Implementations
// -----------------------------------------------------------------------------

/**
 * Builds the scrypt implementation over an explicit `Crypto` (used only for the
 * salt) and `node:crypto` (used for the KDF).
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeScrypt = (crypto: Crypto.Crypto, options?: ScryptOptions): PasswordHasherService => {
  const params: ScryptParams = {
    N: options?.N ?? defaultScryptOptions.N,
    r: options?.r ?? defaultScryptOptions.r,
    p: options?.p ?? defaultScryptOptions.p,
    dkLen: options?.dkLen ?? defaultScryptOptions.dkLen
  }
  const parameterSegment = `n=${params.N},r=${params.r},p=${params.p}`

  return PasswordHasher.of({
    hash: Effect.fnUntraced(function*(password: Redacted.Redacted<string>) {
      const salt = yield* Effect.orDie(crypto.randomBytes(saltBytes))
      const key = yield* scryptDerive(Redacted.value(password), salt, params)
      return formatHash("scrypt", parameterSegment, salt, key)
    }),
    verify: verifyHash
  })
}

/**
 * Builds the PBKDF2 implementation over an explicit `Crypto` (used only for the
 * salt) and WebCrypto's `subtle` (used for the KDF).
 *
 * @category constructors
 * @since 1.0.0
 */
export const makePbkdf2 = (crypto: Crypto.Crypto, options?: Pbkdf2Options): PasswordHasherService => {
  const params: Pbkdf2Params = {
    iterations: options?.iterations ?? defaultPbkdf2Options.iterations,
    dkLen: options?.dkLen ?? defaultPbkdf2Options.dkLen
  }
  const parameterSegment = `i=${params.iterations}`

  return PasswordHasher.of({
    hash: Effect.fnUntraced(function*(password: Redacted.Redacted<string>) {
      const salt = yield* Effect.orDie(crypto.randomBytes(saltBytes))
      const key = yield* pbkdf2Derive(Redacted.value(password), salt, params)
      return formatHash("pbkdf2", parameterSegment, salt, key)
    }),
    verify: verifyHash
  })
}

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * The default layer: scrypt via `node:crypto`.
 *
 * **Details**
 *
 * `verify` also accepts `pbkdf2$…` hashes, so a deployment can migrate between
 * the two layers in either direction.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerScrypt = (
  options?: ScryptOptions
): Layer.Layer<PasswordHasher, never, Crypto.Crypto> =>
  Layer.effect(PasswordHasher, Crypto.Crypto.useSync((crypto) => makeScrypt(crypto, options)))

/**
 * The portable layer: PBKDF2-HMAC-SHA512 over WebCrypto, for runtimes without
 * `node:crypto`.
 *
 * **Details**
 *
 * `verify` accepts `scrypt$…` hashes only where `node:crypto` is present;
 * otherwise it fails with `PasswordHashError` rather than reporting a wrong
 * password.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerPbkdf2 = (
  options?: Pbkdf2Options
): Layer.Layer<PasswordHasher, never, Crypto.Crypto> =>
  Layer.effect(PasswordHasher, Crypto.Crypto.useSync((crypto) => makePbkdf2(crypto, options)))
