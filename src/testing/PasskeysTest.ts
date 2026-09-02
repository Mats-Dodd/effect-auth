/**
 * The passkeys plugin, wired into a test deployment — and a **real**
 * authenticator to drive it with.
 *
 * **Details**
 *
 * The composition half is what every plugin harness looks like: a layer that
 * adds the plugin's services to `AuthTest.layer`'s deployment ({@link layer}), an
 * API that composes the plugin's group beside this library's ({@link TestApi}),
 * and the whole server stack for it ({@link layerHttp}).
 *
 * The other half is {@link makeAuthenticator}, and it is the point of this
 * module. A WebAuthn test that stubs the verifier tests the stub. This one
 * generates a real P-256 key pair with WebCrypto and mints real attestation and
 * assertion responses — CBOR attestation objects, COSE public keys, authenticator
 * data with the real flag bits, and DER-encoded ECDSA signatures over
 * `authenticatorData ‖ SHA-256(clientDataJSON)` — so `@simplewebauthn/server`
 * verifies signatures it would verify in a browser. It is the
 * `MockProvider.IdTokenSigner` shape: expensive to build, so build one per
 * `layer()` block or per test that needs a distinct credential.
 *
 * **Gotchas**
 *
 * Every ceremony takes overrides, and they exist so that a test can forge the
 * ceremonies the server has to refuse: the wrong origin, the wrong `type`, a
 * challenge from another ceremony, a `userHandle` that was never issued, a
 * counter that went backwards, UV claimed and UV withheld. A harness that could
 * only mint *valid* responses could not test a single one of the checks the
 * plugin exists for.
 *
 * @since 0.2.0
 */
import type { PgliteClient } from "@effect/sql-pglite"
import { Effect, Encoding, Layer, Result } from "effect"
import { TestClock } from "effect/testing"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlError } from "effect/unstable/sql"
import type { Services } from "../config/Auth.js"
import { AuthApi } from "../http/AuthApi.js"
import { PasskeysApiGroup } from "../passkeys/Api.js"
import { handlers as passkeyHandlers } from "../passkeys/Handlers.js"
import { layer as migrationsLayer } from "../passkeys/Migrations.js"
import type { Options as PasskeyOptions, Passkeys as PasskeysService } from "../passkeys/Passkeys.js"
import { layer as passkeysLayer, layerAuthenticators as passkeyAuthenticators } from "../passkeys/Passkeys.js"
import type { PasskeyStore as PasskeyStoreService } from "../passkeys/Store.js"
import { layer as storeLayer } from "../passkeys/Store.js"
import { layerSimple } from "../passkeys/WebAuthn.js"
import type {
  AuthenticationOptions,
  AuthenticationResponse,
  AuthenticatorTransport,
  RegistrationOptions,
  RegistrationResponse
} from "../passkeys/Wire.js"
import * as AuthTest from "./TestLayer.js"

// -----------------------------------------------------------------------------
// Deployment defaults
// -----------------------------------------------------------------------------

/**
 * The relying party id every test in this harness uses.
 *
 * @category constructors
 * @since 0.2.0
 */
export const testRpId = "localhost"

/**
 * The origin every test in this harness uses.
 *
 * **Gotchas**
 *
 * It must agree with `AuthTest`'s own `baseUrl`, because that is where the
 * generated client sends requests from and what a real browser would put in
 * `clientDataJSON`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const testOrigin = "http://localhost:3000"

/**
 * What a test may vary about a deployment serving passkeys.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings. `rpId` and `origin` are defaulted for you. */
  readonly passkeys?: Partial<PasskeyOptions> | undefined
}

const passkeyOptions = (options?: Partial<PasskeyOptions>): PasskeyOptions => ({
  rpId: testRpId,
  origin: testOrigin,
  ...options
})

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * The plugin's table over the harness's own database, with its migrations
 * applied.
 *
 * **Gotchas**
 *
 * It composes `AuthTest.layerDatabase`, the memoised module constant, so it
 * shares the one PGlite the rest of the deployment uses rather than booting a
 * second, empty one. `Layer.orDie` because a test harness is an entry point: a
 * migration that will not apply is a broken test run, not an outcome to thread
 * through every signature.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerStore: Layer.Layer<PasskeyStoreService> = Layer.orDie(
  storeLayer.pipe(Layer.provideMerge(migrationsLayer), Layer.provide(AuthTest.layerDatabase))
)

/**
 * The plugin's contribution to the `Authenticators` seam, over
 * {@link layerStore}.
 *
 * **When to use**
 *
 * Underneath a deployment, which is where a reference has to be installed. Both
 * {@link layer} and {@link layerHttp} already do it.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerAuthenticators: Layer.Layer<never> = passkeyAuthenticators.pipe(Layer.provide(layerStore))

/**
 * The plugin's own services over a test deployment's.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerPasskeys = (
  options?: Partial<PasskeyOptions>
): Layer.Layer<PasskeysService | PasskeyStoreService, never, Services> =>
  passkeysLayer(passkeyOptions(options)).pipe(Layer.provide(Layer.orDie(layerSimple)), Layer.provideMerge(layerStore))

/**
 * A whole test deployment with the passkeys plugin on top of it.
 *
 * **When to use**
 *
 * For the domain-level tests. {@link layerHttp} is the same deployment with the
 * endpoints in front of it.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  PasskeysService | PasskeyStoreService | Services | AuthTest.DeploymentServices,
  Migrator.MigrationError | SqlError.SqlError
> =>
  layerPasskeys(options?.passkeys).pipe(
    Layer.provideMerge(AuthTest.layer(options).pipe(Layer.provide(layerAuthenticators)))
  )

/**
 * An application API that embeds this library's group *and* the plugin's,
 * exactly as a consumer composes them.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(PasskeysApiGroup)

/**
 * Everything a request has to cross: the deployment, both groups' handlers, and
 * the platform services a response is encoded with.
 *
 * **Gotchas**
 *
 * `layerAuthenticators` is provided *under the whole stack* rather than through
 * `AuthTest.Settings.authenticators`, because the contribution needs the
 * plugin's store and the setting takes a plain value. The `Authenticators`
 * reference is read when the domain services are built, so underneath is where
 * it has to be.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<
  "test-app",
  HttpApiGroup.Service<"test-app", "passkeys"> | PasskeysService | PasskeyStoreService
> =>
  AuthTest.layerHttpApi(
    TestApi,
    options,
    passkeyHandlers(TestApi).pipe(Layer.provideMerge(layerPasskeys(options?.passkeys)))
  ).pipe(Layer.provide(layerAuthenticators))

/**
 * {@link layerHttp} on a `TestClock` of its own, which a test in the block may
 * move.
 *
 * **When to use**
 *
 * For any HTTP test that adjusts virtual time — a ceremony that expired, a
 * session that is no longer fresh enough to enrol a credential.
 * `AuthTest.freshClock` is the wrong tool over HTTP: `HttpApiBuilder` captures
 * each handler's services when the *layer* is built, so a clock provided inside
 * a test body governs the client and nothing behind the router.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttpMovingClock = (
  options?: Options
): AuthTest.HttpApiLayer<
  "test-app",
  HttpApiGroup.Service<"test-app", "passkeys"> | PasskeysService | PasskeyStoreService | TestClock.TestClock
> => layerHttp(options).pipe(Layer.provideMerge(Layer.fresh(TestClock.layer())))

// -----------------------------------------------------------------------------
// CBOR — the smallest encoder an attestation object needs
// -----------------------------------------------------------------------------

const concat = (...parts: ReadonlyArray<Uint8Array>): Uint8Array<ArrayBuffer> => {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at = at + part.length
  }
  return out
}

/** A CBOR head: the major type in the top three bits, then the argument. */
const head = (major: number, value: number): Uint8Array<ArrayBuffer> => {
  const tag = major << 5
  if (value < 24) return Uint8Array.of(tag | value)
  if (value < 0x100) return Uint8Array.of(tag | 24, value)
  if (value < 0x10000) return Uint8Array.of(tag | 25, (value >> 8) & 0xff, value & 0xff)
  return Uint8Array.of(tag | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)
}

const cborUnsigned = (value: number): Uint8Array<ArrayBuffer> => head(0, value)
/** CBOR negative integers encode `-1 - n`, which is how COSE spells `-7`. */
const cborNegative = (value: number): Uint8Array<ArrayBuffer> => head(1, -1 - value)
const cborInt = (value: number): Uint8Array<ArrayBuffer> => (value < 0 ? cborNegative(value) : cborUnsigned(value))
const cborBytes = (value: Uint8Array): Uint8Array<ArrayBuffer> => concat(head(2, value.length), value)
const cborText = (value: string): Uint8Array<ArrayBuffer> => {
  const encoded = new TextEncoder().encode(value)
  return concat(head(3, encoded.length), encoded)
}
const cborMap = (entries: ReadonlyArray<readonly [Uint8Array, Uint8Array]>): Uint8Array<ArrayBuffer> =>
  concat(head(5, entries.length), ...entries.flatMap(([key, value]) => [key, value]))

// -----------------------------------------------------------------------------
// DER — WebAuthn signatures are DER, WebCrypto's are raw
// -----------------------------------------------------------------------------

/**
 * One DER `INTEGER`: leading zero bytes stripped, and a zero byte prepended when
 * the high bit is set so the value stays positive.
 */
const derInteger = (value: Uint8Array): Uint8Array<ArrayBuffer> => {
  let start = 0
  while (start < value.length - 1 && value[start] === 0) start = start + 1
  const trimmed = value.slice(start)
  const first = trimmed[0] ?? 0
  const body = (first & 0x80) === 0 ? trimmed : concat(Uint8Array.of(0), trimmed)
  return concat(Uint8Array.of(0x02, body.length), body)
}

/**
 * WebCrypto signs ECDSA as raw `r ‖ s`; WebAuthn carries the DER
 * `SEQUENCE { INTEGER r, INTEGER s }`. A P-256 sequence is always short enough
 * for the one-byte length form.
 */
const rawSignatureToDer = (raw: Uint8Array): Uint8Array<ArrayBuffer> => {
  const body = concat(derInteger(raw.slice(0, 32)), derInteger(raw.slice(32)))
  return concat(Uint8Array.of(0x30, body.length), body)
}

// -----------------------------------------------------------------------------
// Authenticator data
// -----------------------------------------------------------------------------

/** User present. Set by every ceremony a person actually completed. */
const flagUserPresent = 0x01
/** User verified: a PIN or a biometric was checked. This is the `aal2` bit. */
const flagUserVerified = 0x04
/** Backup eligible: this credential may ever be synced. Immutable. */
const flagBackupEligible = 0x08
/** Backup state: it currently is. */
const flagBackedUp = 0x10
/** Attested credential data is present — registration only. */
const flagAttested = 0x40

const sha256 = (data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> =>
  globalThis.crypto.subtle.digest("SHA-256", data).then((digest) => new Uint8Array(digest))

const uint32 = (value: number): Uint8Array<ArrayBuffer> =>
  Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)

const uint16 = (value: number): Uint8Array<ArrayBuffer> => Uint8Array.of((value >> 8) & 0xff, value & 0xff)

const hexBytes = (hex: string): Uint8Array<ArrayBuffer> => {
  const clean = hex.replaceAll("-", "")
  const out = new Uint8Array(clean.length / 2)
  for (let index = 0; index < out.length; index = index + 1) {
    out[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16)
  }
  return out
}

const base64UrlBytes = (value: string): Uint8Array<ArrayBuffer> => {
  const decoded = Encoding.decodeBase64Url(value)
  if (Result.isFailure(decoded)) throw new Error(`not base64url: ${value}`)
  return new Uint8Array(decoded.success)
}

// -----------------------------------------------------------------------------
// The test authenticator
// -----------------------------------------------------------------------------

/**
 * What a ceremony may be forged to say.
 *
 * **When to use**
 *
 * To mint the responses the server has to refuse. Everything here overrides what
 * an honest authenticator would have produced.
 *
 * @category models
 * @since 0.2.0
 */
export interface CeremonyOverrides {
  /** The `origin` written into `clientDataJSON`. Defaults to the authenticator's. */
  readonly origin?: string | undefined
  /** The `type` written into `clientDataJSON` — `"webauthn.create"` or `"webauthn.get"`. */
  readonly type?: string | undefined
  /** The challenge to sign, base64url. Defaults to the one in the option document. */
  readonly challenge?: string | undefined
  /** The rp id whose hash goes into `authenticatorData`. Defaults to the authenticator's. */
  readonly rpId?: string | undefined
  /** The UV bit. Defaults to the authenticator's own setting. */
  readonly userVerified?: boolean | undefined
  /** The BS bit. */
  readonly backedUp?: boolean | undefined
  /** The counter to report. Defaults to one more than the last. */
  readonly signCount?: number | undefined
}

/**
 * What an authentication ceremony may additionally say.
 *
 * @category models
 * @since 0.2.0
 */
export interface AssertionOverrides extends CeremonyOverrides {
  /**
   * The `userHandle` to hand back, base64url — what a *discoverable* credential
   * reports. Omit it for a ceremony that named the credential in
   * `allowCredentials`.
   */
  readonly userHandle?: string | undefined
}

/**
 * How a {@link makeAuthenticator} behaves.
 *
 * @category models
 * @since 0.2.0
 */
export interface AuthenticatorOptions {
  /** The rp id it will sign for. Defaults to {@link testRpId}. */
  readonly rpId?: string | undefined
  /** The origin it will claim. Defaults to {@link testOrigin}. */
  readonly origin?: string | undefined
  /** Its credential id, base64url. Defaults to a value derived from its public key. */
  readonly credentialId?: string | undefined
  /** Its model identifier. Defaults to the all-zero UUID, which is what "none" attestation reports. */
  readonly aaguid?: string | undefined
  /** Whether it verifies the person to itself. Defaults to `true` — the `aal2` case. */
  readonly userVerified?: boolean | undefined
  /** Whether its credentials may be synced. Defaults to `false`. */
  readonly backupEligible?: boolean | undefined
  /** Whether they currently are. Defaults to `false`. */
  readonly backedUp?: boolean | undefined
  /** The counter it starts from. Defaults to `0`, which is what a synced passkey reports for ever. */
  readonly signCount?: number | undefined
  /** What it says about how it is reached. Defaults to `["internal"]`. */
  readonly transports?: ReadonlyArray<AuthenticatorTransport> | undefined
}

/**
 * A real authenticator, in a test.
 *
 * @category models
 * @since 0.2.0
 */
export interface TestAuthenticator {
  /** Its credential id, base64url — the value the server stores and looks it up by. */
  readonly credentialId: string
  /** The counter it will report next. */
  readonly signCount: () => number
  /** Completes a registration ceremony against the server's own option document. */
  readonly register: (
    options: RegistrationOptions,
    overrides?: CeremonyOverrides
  ) => Effect.Effect<RegistrationResponse>
  /** Completes an authentication ceremony against the server's own option document. */
  readonly authenticate: (
    options: AuthenticationOptions,
    overrides?: AssertionOverrides
  ) => Effect.Effect<AuthenticationResponse>
}

const zeroAaguid = "00000000-0000-0000-0000-000000000000"

/**
 * Generates a P-256 key pair and wraps it in an authenticator that mints real
 * WebAuthn responses.
 *
 * **Gotchas**
 *
 * Key generation costs a few milliseconds, so build one per credential rather
 * than one per assertion — and build a second one when a test needs a *different*
 * credential, which is what makes "somebody else's passkey" testable.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeAuthenticator = (options?: AuthenticatorOptions): Effect.Effect<TestAuthenticator> =>
  Effect.promise(async () => {
    const rpId = options?.rpId ?? testRpId
    const origin = options?.origin ?? testOrigin
    const aaguid = hexBytes(options?.aaguid ?? zeroAaguid)
    const transports = options?.transports ?? ["internal"]

    const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify"
    ])
    const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey)
    const x = base64UrlBytes(jwk.x ?? "")
    const y = base64UrlBytes(jwk.y ?? "")

    // COSE_Key for ES256: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y.
    const cosePublicKey = cborMap([
      [cborInt(1), cborInt(2)],
      [cborInt(3), cborInt(-7)],
      [cborInt(-1), cborInt(1)],
      [cborInt(-2), cborBytes(x)],
      [cborInt(-3), cborBytes(y)]
    ])

    const credentialIdBytes =
      options?.credentialId === undefined
        ? (await sha256(cosePublicKey)).slice(0, 32)
        : base64UrlBytes(options.credentialId)
    const credentialId = Encoding.encodeBase64Url(credentialIdBytes)

    let counter = options?.signCount ?? 0

    const flagsFor = (attested: boolean, overrides?: CeremonyOverrides): number => {
      const verified = overrides?.userVerified ?? options?.userVerified ?? true
      const backedUp = overrides?.backedUp ?? options?.backedUp ?? false
      return (
        flagUserPresent |
        (verified ? flagUserVerified : 0) |
        (options?.backupEligible === true ? flagBackupEligible : 0) |
        (backedUp ? flagBackedUp : 0) |
        (attested ? flagAttested : 0)
      )
    }

    const clientData = (type: string, challenge: string, at: string): Uint8Array<ArrayBuffer> =>
      new TextEncoder().encode(JSON.stringify({ type, challenge, origin: at, crossOrigin: false }))

    const nextCount = (overrides?: CeremonyOverrides): number => {
      if (overrides?.signCount !== undefined) return overrides.signCount
      // A synced passkey never counts: an authenticator that started at zero
      // stays there, which is exactly the case the server has to skip.
      if (counter === 0 && (options?.signCount ?? 0) === 0) return 0
      counter = counter + 1
      return counter
    }

    return {
      credentialId,
      signCount: () => counter,

      register: (document, overrides) =>
        Effect.promise(async () => {
          const challenge = overrides?.challenge ?? document.challenge
          const at = overrides?.origin ?? origin
          const collected = clientData(overrides?.type ?? "webauthn.create", challenge, at)
          const rpIdHash = await sha256(new TextEncoder().encode(overrides?.rpId ?? rpId))
          const attested = concat(aaguid, uint16(credentialIdBytes.length), credentialIdBytes, cosePublicKey)
          const authData = concat(
            rpIdHash,
            Uint8Array.of(flagsFor(true, overrides)),
            uint32(nextCount(overrides)),
            attested
          )
          const attestationObject = cborMap([
            [cborText("fmt"), cborText("none")],
            [cborText("attStmt"), cborMap([])],
            [cborText("authData"), cborBytes(authData)]
          ])
          return {
            id: credentialId,
            rawId: credentialId,
            type: "public-key" as const,
            authenticatorAttachment: "platform" as const,
            response: {
              clientDataJSON: Encoding.encodeBase64Url(collected),
              attestationObject: Encoding.encodeBase64Url(attestationObject),
              transports
            }
          } satisfies RegistrationResponse
        }),

      authenticate: (document, overrides) =>
        Effect.promise(async () => {
          const challenge = overrides?.challenge ?? document.challenge
          const at = overrides?.origin ?? origin
          const collected = clientData(overrides?.type ?? "webauthn.get", challenge, at)
          const rpIdHash = await sha256(new TextEncoder().encode(overrides?.rpId ?? document.rpId ?? rpId))
          const authData = concat(rpIdHash, Uint8Array.of(flagsFor(false, overrides)), uint32(nextCount(overrides)))
          const signed = concat(authData, await sha256(collected))
          const raw = new Uint8Array(
            await globalThis.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed)
          )
          return {
            id: credentialId,
            rawId: credentialId,
            type: "public-key" as const,
            authenticatorAttachment: "platform" as const,
            response: {
              clientDataJSON: Encoding.encodeBase64Url(collected),
              authenticatorData: Encoding.encodeBase64Url(authData),
              signature: Encoding.encodeBase64Url(rawSignatureToDer(raw)),
              ...(overrides?.userHandle === undefined ? {} : { userHandle: overrides.userHandle })
            }
          } satisfies AuthenticationResponse
        })
    }
  })

/** Re-exported so a test can name the type the harness's database layer carries. */
export type { PgliteClient }
