/**
 * Passkeys: WebAuthn credentials as a first-class way into an account.
 *
 * `Passkeys` owns six operations — mint a registration ceremony, complete one,
 * mint an authentication ceremony, complete one, and the three management
 * operations a person performs on their own credentials.
 *
 * **Details — what this module decides, and what it delegates**
 *
 * Parsing and signature verification are behind the {@link WebAuthn} seam. What
 * is here is everything a verifier cannot know: which challenge this response
 * belongs to, which ceremony it was minted for, whether the credential belongs
 * to the person the challenge was minted for, whether the `userHandle` is one
 * this deployment issued, what a counter regression means, and what assurance
 * the ceremony earned.
 *
 * **Gotchas — the four checks that are the point of this module**
 *
 * *The ceremony tag.* A challenge carries `ceremony: "registration" |
 * "authentication"` and a response is refused unless the tags agree. Without it
 * a registration challenge completes an authentication and the other way round,
 * which is exactly the bug better-auth fixed in `baeaa00bc`.
 *
 * *The origin.* `rpId` and `origin` are **required configuration**. A relying
 * party that falls back to the request's own `Origin` header — better-auth
 * does — has an attacker-controlled RP origin, and origin binding is the whole
 * of what makes WebAuthn phishing-resistant.
 *
 * *The bound user.* When a challenge was minted for a known user, the credential
 * presented must belong to that user. Without it, "re-authenticate as *this*
 * person" is a sentence with no enforcement behind it: anybody's passkey would
 * satisfy anybody's step-up.
 *
 * *The user handle.* A discoverable sign-in hands back the `userHandle` the
 * authenticator stored. It must equal the handle this deployment issued for the
 * credential's owner, or the credential is not the one this deployment
 * registered.
 *
 * And one derivation: the evidence records the authenticator's own **UV bit**,
 * never the `userVerification` the request asked for. A `UV=1` ceremony is a
 * multi-factor authenticator by NIST's own definition and reaches `aal2` in one
 * step with no second prompt; a `UV=0` tap is one factor and reaches `aal1`.
 * `Assurance.deriveAal` is what turns the bit into the level.
 *
 * @since 0.2.0
 */
import { Context, Data, DateTime, Duration, Effect, Encoding, Layer, Option, Redacted, Result, Schema } from "effect"
import { Token } from "../crypto/Token.js"
import { Hmac } from "../crypto/Hmac.js"
import type { AuthenticatorsService, AuthenticatorSummary } from "../domain/Authenticators.js"
import { Authenticators, combine, list as listAuthenticators } from "../domain/Authenticators.js"
import { AuthEvents, PluginEvent, publishSafely } from "../domain/Events.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import { ProvisionSource } from "../domain/Hooks.js"
import type { Session, User, UserId } from "../domain/Schema.js"
import { CredentialIssuer, normalizeEmail, UserId as UserIdSchema } from "../domain/Schema.js"
import type { ElevatedSession, Evidence } from "../domain/Sessions.js"
import { Sessions } from "../domain/Sessions.js"
import type { SignInRequest, SignInResult } from "../domain/SignIn.js"
import { SignIn } from "../domain/SignIn.js"
import type { PersistenceError } from "../domain/Stores.js"
import { AccountStore, isUniqueViolation, UserStore } from "../domain/Stores.js"
import type { TokenPurpose } from "../domain/Verifications.js"
import { purpose, Verifications } from "../domain/Verifications.js"
import { insertRow } from "../internal/effects.js"
import { encodeUtf8 } from "../internal/crypto.js"
import { withDefaults } from "../internal/records.js"
import { CannotRemoveLastAuthenticator, ChallengeExpired, PasskeyVerificationFailed } from "./Errors.js"
import type { PasskeyId } from "./Schema.js"
import { Passkey } from "./Schema.js"
import type { PasskeyStoreService } from "./Store.js"
import { PasskeyStore } from "./Store.js"
import { WebAuthn } from "./WebAuthn.js"
import type {
  AuthenticationOptions,
  AuthenticationResponse,
  AuthenticatorAttachment,
  CredentialDescriptor,
  RegistrationOptions,
  RegistrationResponse,
  ResidentKeyRequirement,
  UserVerificationRequirement
} from "./Wire.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The name this plugin publishes `PluginEvent`s under, and the `plugin` of its
 * `ProvisionSource`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const passkeysPlugin = "passkeys"

/**
 * The `method` a passkey ceremony records on a session's authentication log.
 *
 * @category constructors
 * @since 0.2.0
 */
export const passkeyMethod = "passkey"

/**
 * The `AuthenticatorSummary.type` this plugin contributes to the
 * `Authenticators` seam.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authenticatorType = "passkey"

/**
 * The `PluginEvent.event` published when an authenticator reports a counter at
 * or below the one already stored.
 *
 * @category constructors
 * @since 0.2.0
 */
export const counterRegressionEvent = "PasskeyCounterRegression"

/**
 * The `PluginEvent.event` published when a credential is registered.
 *
 * @category constructors
 * @since 0.2.0
 */
export const registeredEvent = "PasskeyRegistered"

/**
 * The `PluginEvent.event` published when a credential is removed by its owner.
 *
 * @category constructors
 * @since 0.2.0
 */
export const removedEvent = "PasskeyRemoved"

/** COSE algorithm identifier for ECDSA over P-256 with SHA-256. */
const es256 = -7
/** COSE algorithm identifier for RSASSA-PKCS1-v1_5 with SHA-256. */
const rs256 = -257
/** COSE algorithm identifier for EdDSA (Ed25519). */
const eddsa = -8

/**
 * The signature algorithms this library accepts, most preferred first.
 *
 * **Details**
 *
 * ES256, RS256, EdDSA — the three every deployed authenticator produces, and
 * nothing else. An allowlist rather than "whatever the authenticator offered":
 * an algorithm this library cannot reason about is one whose security it cannot
 * state.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultAlgorithms: ReadonlyArray<number> = [es256, rs256, eddsa]

/**
 * What completing a passkey ceremony proves.
 *
 * **Details**
 *
 * Possession of the key always; *inherence* as well when the authenticator
 * reports the user-verification bit, because a PIN or a biometric was checked
 * against the person before the key would sign. Phishing-resistant in both
 * cases — the signature covers an origin the browser, not the page, chose — and
 * never restricted.
 *
 * **Gotchas**
 *
 * `userVerified` is the authenticator's own bit, and it is what makes a single
 * passkey tap reach `aal2`. Deriving it from the *requested*
 * `userVerification` would let a `"preferred"` request that the authenticator
 * quietly declined be recorded as two factors.
 *
 * @category combinators
 * @since 0.2.0
 */
export const passkeyEvidence = (userVerified: boolean): Evidence => ({
  method: passkeyMethod,
  factor: userVerified ? "inherence" : "possession",
  phishingResistant: true,
  restricted: false,
  userVerified
})

/**
 * What every user this plugin signs in came from. One value rather than a
 * literal per call site.
 */
const passkeySource: ProvisionSource = ProvisionSource.Plugin({ plugin: passkeysPlugin })

// -----------------------------------------------------------------------------
// Challenges
// -----------------------------------------------------------------------------

/**
 * What travels with a passkey challenge.
 *
 * **Details**
 *
 * Server-side state in the `verifications` table, never a claim in the option
 * document. The browser is handed the challenge and the handle cookie; what the
 * ceremony *is* — and who it was minted for — is here, where the browser cannot
 * edit it.
 *
 * @category models
 * @since 0.2.0
 */
export const PasskeyChallengePayload = Schema.Struct({
  /** Which ceremony this challenge may complete, and only this one. */
  ceremony: Schema.Literals(["registration", "authentication"]),
  /** The user it was minted for, or `null` for a discoverable sign-in. */
  userId: Schema.NullOr(UserIdSchema),
  /** What was asked of the authenticator, which is what the verifier enforces. */
  userVerification: Schema.Literals(["required", "preferred", "discouraged"])
})

/**
 * The type of a {@link PasskeyChallengePayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type PasskeyChallengePayload = typeof PasskeyChallengePayload.Type

/**
 * The purpose passkey challenges are minted under.
 *
 * **Gotchas**
 *
 * Its *subject* is the challenge itself — 32 base64url-encoded random bytes —
 * so every ceremony gets an identifier of its own and two ceremonies can never
 * collide, whether or not they belong to the same person. The challenge is
 * public (the browser is handed it); what makes the row single-use is the
 * secret half of the token, which is only ever in the `__Host-` cookie.
 *
 * @category constructors
 * @since 0.2.0
 */
export const passkeyChallengePurpose: TokenPurpose<PasskeyChallengePayload> = purpose(
  "passkey-challenge",
  PasskeyChallengePayload
)

/**
 * The domain separation the decoy credential ids are derived under.
 *
 * **Details**
 *
 * `Hmac` is a published service, so a tag is only ever a tag *for* something —
 * the same discipline `SessionCache.macContext` and `Challenges.codeHashContext`
 * follow. It is part of the derivation: changing it changes every decoy this
 * deployment answers with, which is harmless (they are decoys) but it would make
 * two deployments' answers differ where an operator expected them to match.
 *
 * @category constructors
 * @since 0.2.0
 */
export const decoyContext = "effect-auth/passkey-decoy/v1\n"

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/**
 * What a deployment may vary about the passkey flow.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /**
   * The relying party id: the registrable domain, with no scheme and no port.
   *
   * **Gotchas**
   *
   * Required, and never derived from the request. A credential is bound to this
   * value for its whole life, so changing it in a live deployment orphans every
   * passkey already registered.
   */
  readonly rpId: string
  /** The name a browser shows the person. Defaults to {@link Config.rpId}. */
  readonly rpName: string
  /**
   * Every origin this deployment serves the sign-in page from, scheme, host and
   * port included.
   *
   * **Gotchas**
   *
   * Required, for the reason in the module header: an RP origin read off the
   * request's `Origin` header is chosen by whoever sent the request.
   */
  readonly origins: ReadonlyArray<string>
  /**
   * What is asked of the authenticator. Defaults to `"preferred"`.
   *
   * **Gotchas**
   *
   * This is what is *asked*, and the assurance a ceremony earns is read off what
   * the authenticator actually did. `"required"` additionally makes the verifier
   * refuse a response whose UV bit is clear.
   */
  readonly userVerification: UserVerificationRequirement
  /**
   * Whether the credential must be discoverable. Defaults to `"required"`,
   * which is what makes usernameless and conditional-UI sign-in work.
   */
  readonly residentKey: ResidentKeyRequirement
  /** The COSE algorithms accepted, most preferred first. */
  readonly algorithms: ReadonlyArray<number>
  /** How long a ceremony may be completed for. Defaults to five minutes. */
  readonly challengeTtl: Duration.Duration
  /** The `timeout` written into the option document. Defaults to one minute. */
  readonly timeout: Duration.Duration
  /**
   * Refuse an authentication whose signature counter did not advance. Defaults
   * to `false`.
   *
   * **Gotchas**
   *
   * A regression is a real signal of a cloned authenticator — and it is also
   * what a perfectly healthy synced passkey looks like on a second device that
   * has not seen the counter move. The event is published either way; turning
   * this on trades a rare lockout for a rare detection, and is the right trade
   * only for a deployment that knows its authenticators keep counters.
   */
  readonly rejectCounterRegression: boolean
}

/**
 * {@link Config}, with everything but the two required members optional.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  /** See {@link Config.rpId}. Required. */
  readonly rpId: string
  /** See {@link Config.origins}. Required; one origin or several. */
  readonly origin: string | ReadonlyArray<string>
  readonly rpName?: string | undefined
  readonly userVerification?: UserVerificationRequirement | undefined
  readonly residentKey?: ResidentKeyRequirement | undefined
  readonly algorithms?: ReadonlyArray<number> | undefined
  readonly challengeTtl?: Duration.Duration | undefined
  readonly timeout?: Duration.Duration | undefined
  readonly rejectCounterRegression?: boolean | undefined
}

/**
 * The defaults every unstated optional {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Omit<Config, "rpId" | "rpName" | "origins"> = {
  userVerification: "preferred",
  residentKey: "required",
  algorithms: defaultAlgorithms,
  challengeTtl: Duration.minutes(5),
  timeout: Duration.minutes(1),
  rejectCounterRegression: false
}

/**
 * Resolves {@link Options} against {@link defaults}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options: Options): Config => ({
  ...withDefaults(defaults, options),
  rpId: options.rpId,
  rpName: options.rpName ?? options.rpId,
  origins: typeof options.origin === "string" ? [options.origin] : options.origin
})

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * A ceremony that has been minted and is waiting for the browser to finish it.
 *
 * **Gotchas**
 *
 * `handle` addresses the challenge row and is a credential: it goes in the
 * `__Host-effect_auth.passkey` cookie and nowhere else — never in the option
 * document, which is script-readable.
 *
 * @category models
 * @since 0.2.0
 */
export interface IssuedCeremony<Document> {
  /** The document to hand `navigator.credentials`. */
  readonly options: Document
  /** The single-use handle addressing the challenge row. */
  readonly handle: Redacted.Redacted
  /** When the challenge stops being claimable. */
  readonly expiresAt: DateTime.Utc
}

/**
 * What {@link PasskeysService.registrationOptions} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface RegistrationOptionsRequest {
  /** Whose credential this will be. Always known: registration is authenticated. */
  readonly user: User
  /** Narrow the ceremony to a platform or a roaming authenticator. */
  readonly authenticatorAttachment?: AuthenticatorAttachment | undefined
}

/**
 * What {@link PasskeysService.verifyRegistration} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyRegistrationOptions {
  /** Whose credential this is. Taken from the session, never from the body. */
  readonly user: User
  /** The handle out of the ceremony cookie. */
  readonly handle: Redacted.Redacted
  readonly response: RegistrationResponse
  /** What the person called it. */
  readonly name?: string | null | undefined
}

/**
 * What {@link PasskeysService.authenticationOptions} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface AuthenticationOptionsRequest {
  /**
   * The session the request already carried, if any.
   *
   * **Details**
   *
   * Present for a step-up: the ceremony is then *bound* to that user, and only
   * their credentials will complete it. Absent for a sign-in, where the account
   * is what the ceremony discovers.
   */
  readonly session: Option.Option<Session>
  /**
   * An address to scope `allowCredentials` to, for a deployment that asks for
   * one first.
   *
   * **Gotchas**
   *
   * It scopes the list and binds nothing: an address is a claim, and a ceremony
   * bound to an unproved claim would refuse a person's own second passkey on
   * another account. Only a session binds.
   */
  readonly email?: string | undefined
}

/**
 * What {@link PasskeysService.verifyAuthentication} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyAuthenticationOptions {
  /** The handle out of the ceremony cookie. */
  readonly handle: Redacted.Redacted
  readonly response: AuthenticationResponse
  /**
   * The session the request carried, if any. A ceremony bound to a user is only
   * completed as an *elevation* when this is that user's own live session.
   */
  readonly session: Option.Option<Session>
}

/**
 * A verified assertion: who it was, which credential, and what it proved.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifiedPasskey {
  readonly user: User
  /** The credential row, as it stands after the ceremony was recorded. */
  readonly passkey: Passkey
  /** The authentication-log entry this ceremony earned. */
  readonly evidence: Evidence
  /** The authenticator's own user-verification bit. */
  readonly userVerified: boolean
}

/**
 * What completing an authentication ceremony came to.
 *
 * **Details**
 *
 * `Elevated` when the ceremony was bound to a user and that user's own live
 * session made the request — the session keeps its id, gains the passkey on its
 * log, is re-stamped and has its token rotated. `SignedIn` otherwise, and then
 * it is an ordinary sign-in through the one choke point: `beforeSessionCreate`
 * runs, the pipeline is consulted, and a second factor may still be owed.
 *
 * @category models
 * @since 0.2.0
 */
export type PasskeyAuthentication = Data.TaggedEnum<{
  /** The ceremony minted a session through the one sign-in door. */
  SignedIn: { readonly result: SignInResult; readonly verified: VerifiedPasskey }
  /** The ceremony raised the caller's own live session in place. */
  Elevated: ElevatedSession & { readonly verified: VerifiedPasskey }
}>

/**
 * Constructors and matchers for {@link PasskeyAuthentication}.
 *
 * **Details**
 *
 * `PasskeyAuthentication.$is("Elevated")` is how the HTTP layer tells the two
 * apart, and `$match` branches over both exhaustively.
 *
 * **Gotchas**
 *
 * `$is` checks the tag and nothing else, so point it only at a value this
 * plugin produced — never at something decoded from a request.
 *
 * @category constructors
 * @since 0.2.0
 */
export const PasskeyAuthentication = Data.taggedEnum<PasskeyAuthentication>()

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Passkeys} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface PasskeysService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Mints a registration ceremony for a user, excluding the credentials they
   * already hold so the browser refuses a duplicate.
   *
   * Issues the user's WebAuthn handle if they have never been offered one.
   */
  readonly registrationOptions: (
    request: RegistrationOptionsRequest
  ) => Effect.Effect<IssuedCeremony<RegistrationOptions>, PersistenceError>

  /**
   * Completes a registration ceremony and stores the credential.
   *
   * **Gotchas**
   *
   * A credential id already registered — to this person or to anybody else — is
   * {@link PasskeyVerificationFailed}, not a distinguishable "already yours".
   * The unique index is what enforces it, so two concurrent registrations of one
   * credential cannot both win.
   */
  readonly verifyRegistration: (
    options: VerifyRegistrationOptions
  ) => Effect.Effect<Passkey, ChallengeExpired | PasskeyVerificationFailed | PersistenceError>

  /**
   * Mints an authentication ceremony.
   *
   * **Gotchas**
   *
   * An address with no account is answered with *decoy* credential
   * descriptors derived from the address by HMAC — plausible, stable, and
   * indistinguishable in shape from a real answer (WebAuthn L3 §14.6.2). The
   * decoys are computed whether or not the account exists, so the two branches
   * cost the same HMAC.
   */
  readonly authenticationOptions: (
    request: AuthenticationOptionsRequest
  ) => Effect.Effect<IssuedCeremony<AuthenticationOptions>, PersistenceError>

  /**
   * Checks an assertion: the ceremony tag, the bound user, the user handle, the
   * signature and the counter. Records the ceremony on the credential row.
   *
   * **When to use**
   *
   * From {@link PasskeysService.authenticate}, and from a plugin that has its
   * own idea of what a verified passkey should do next — completing a pending
   * second factor, for instance.
   */
  readonly verifyAuthentication: (
    options: VerifyAuthenticationOptions
  ) => Effect.Effect<VerifiedPasskey, ChallengeExpired | PasskeyVerificationFailed | PersistenceError>

  /**
   * {@link PasskeysService.verifyAuthentication}, turned into a session: an
   * elevation of the caller's own session where the ceremony was bound to it,
   * and otherwise a sign-in through `SignIn.complete`.
   */
  readonly authenticate: (
    options: VerifyAuthenticationOptions & { readonly request: SignInRequest }
  ) => Effect.Effect<
    PasskeyAuthentication,
    ChallengeExpired | PasskeyVerificationFailed | PolicyRefused | PersistenceError
  >

  /** A person's own credentials, oldest first. */
  readonly list: (userId: UserId) => Effect.Effect<ReadonlyArray<Passkey>, PersistenceError>

  /** Renames one of a person's own credentials. Ownership is in the statement. */
  readonly rename: (
    userId: UserId,
    id: PasskeyId,
    name: string | null
  ) => Effect.Effect<Option.Option<Passkey>, PersistenceError>

  /** Removes one of a person's own credentials, answering whether a row went. */
  readonly remove: (
    userId: UserId,
    id: PasskeyId
  ) => Effect.Effect<boolean, CannotRemoveLastAuthenticator | PersistenceError>
}

/**
 * WebAuthn credentials as a way into an account. See {@link PasskeysService}.
 *
 * @category services
 * @since 0.2.0
 */
export class Passkeys extends Context.Service<Passkeys, PasskeysService>()("effect-auth/passkeys/Passkeys") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * **Gotchas**
 *
 * Everything but {@link PasskeyStore} and {@link WebAuthn} is published by
 * `Auth.layer`, so a consumer composes this plugin over their deployment and
 * supplies the plugin's own two.
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements =
  | PasskeyStore
  | WebAuthn
  | Verifications
  | UserStore
  | AccountStore
  | SignIn
  | Sessions
  | AuthEvents
  | Hmac
  | Token

/**
 * How many decoy credential descriptors an unknown address is answered with.
 *
 * One or two, derived from the address so that the same address always gets the
 * same answer: a caller that asked twice and got a different number of
 * descriptors would have learned something.
 */
const decoyCount = (mac: Uint8Array): number => (mac[0] === undefined ? 1 : (mac[0] % 2) + 1)

/**
 * The `AuthenticatorSummary` one credential contributes to the `Authenticators`
 * seam.
 *
 * **Details**
 *
 * `signIn` and `secondFactor` are both true, which is the honest description: a
 * passkey starts a session on its own *and* answers a step-up. `verifiedAt` is
 * the moment it was registered — a credential is proved by the ceremony that
 * created it, so there is no pending state to represent. Not `restricted`:
 * WebAuthn is the opposite of a restricted channel.
 *
 * @category combinators
 * @since 0.2.0
 */
export const summaryOf = (passkey: Passkey): AuthenticatorSummary => ({
  type: authenticatorType,
  id: passkey.id,
  name: passkey.name,
  verifiedAt: passkey.createdAt,
  lastUsedAt: passkey.lastUsedAt,
  signIn: true,
  secondFactor: true,
  restricted: false
})

/**
 * This plugin's contribution to the `Authenticators` seam, over a store already
 * in hand.
 *
 * @category combinators
 * @since 0.2.0
 */
export const authenticatorsOf = (store: PasskeyStoreService): AuthenticatorsService => ({
  list: (userId) => Effect.map(store.listByUserId(userId), (rows) => rows.map(summaryOf)),
  revokeAll: (userId) => store.removeByUserId(userId)
})

/**
 * Builds the {@link Passkeys} implementation.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (options: Options) => Effect.Effect<PasskeysService, never, Requirements> = Effect.fnUntraced(
  function* (options: Options) {
    const config = makeConfig(options)
    const store = yield* PasskeyStore
    const webauthn = yield* WebAuthn
    const verifications = yield* Verifications
    const users = yield* UserStore
    const accountRows = yield* AccountStore
    // Whatever the deployment installed underneath it, so a removal can see
    // the other factor plugins' authenticators as well as this one's.
    const authenticators = yield* Authenticators
    const signIn = yield* SignIn
    const sessions = yield* Sessions
    const events = yield* AuthEvents
    const hmac = yield* Hmac
    const tokens = yield* Token

    const timeoutMillis = Duration.toMillis(config.timeout)

    const publish = (event: string, userId: UserId | null, data: Record<string, unknown>) =>
      publishSafely(events, PluginEvent.make({ plugin: passkeysPlugin, event, userId, data }))

    /**
     * 32 bytes of `effect/Crypto` randomness, base64url. `Token.generateToken`
     * is this library's one source of it; the value is unwrapped because a
     * challenge is handed to the browser and a handle is stored, and neither is
     * a secret the way a session token is — what makes the ceremony single-use
     * is the verification row's own secret half.
     */
    const randomValue = Effect.map(tokens.generateToken, Redacted.value)

    /**
     * The user's WebAuthn handle, issued on first use.
     *
     * Two concurrent registrations for one person race here; the unique key on
     * `user_id` settles it and the loser reads the winner's handle. A handle
     * that changed would orphan every credential registered under the old one,
     * so it is never rewritten.
     */
    const ensureHandle = Effect.fnUntraced(function* (userId: UserId) {
      const existing = yield* store.findHandle(userId)
      if (Option.isSome(existing)) return existing.value
      const handle = yield* randomValue
      const created = yield* Effect.result(store.createHandle(userId, handle))
      if (Result.isSuccess(created)) return created.success
      if (!isUniqueViolation(created.failure)) return yield* created.failure
      const settled = yield* store.findHandle(userId)
      // The winner's row is there by construction: the only way to lose this
      // race is for somebody else to have written one.
      return Option.getOrElse(settled, () => handle)
    })

    const descriptorsOf = (passkeys: ReadonlyArray<Passkey>): ReadonlyArray<CredentialDescriptor> =>
      passkeys.map((passkey) => ({
        id: passkey.credentialId,
        type: "public-key" as const,
        ...(passkey.transports.length === 0 ? {} : { transports: passkey.transports })
      }))

    /**
     * Plausible credential ids for an address that has no account.
     *
     * Derived rather than random so that the same address is always answered
     * the same way, and keyed under the deployment's own secret so they cannot
     * be computed by anybody else. See WebAuthn L3 §14.6.2.
     */
    const decoysFor = Effect.fnUntraced(function* (email: string) {
      const normalized = normalizeEmail(email)
      const seed = yield* hmac.sign(encodeUtf8(`${decoyContext}${normalized}`))
      const count = decoyCount(seed)
      const ids: Array<string> = []
      for (let index = 0; index < count; index = index + 1) {
        const mac = yield* hmac.sign(encodeUtf8(`${decoyContext}${normalized}\n${index}`))
        ids.push(Encoding.encodeBase64Url(mac))
      }
      return ids.map((id): CredentialDescriptor => ({ id, type: "public-key" as const }))
    })

    const issue = Effect.fnUntraced(function* (payload: PasskeyChallengePayload) {
      const challenge = yield* randomValue
      const issued = yield* verifications.issue({
        purpose: passkeyChallengePurpose,
        subject: challenge,
        ttl: config.challengeTtl,
        payload
      })
      return { challenge, handle: issued.token, expiresAt: issued.expiresAt }
    })

    /**
     * Claims the ceremony row and refuses one minted for a different ceremony.
     *
     * The claim is atomic and happens *before* anything the response says is
     * looked at, so a challenge is spent whichever way the ceremony goes and no
     * response can be replayed.
     */
    const claim = Effect.fnUntraced(function* (
      handle: Redacted.Redacted,
      ceremony: PasskeyChallengePayload["ceremony"]
    ) {
      const claimed = yield* Effect.catchTag(verifications.claim(passkeyChallengePurpose, handle), "InvalidToken", () =>
        ChallengeExpired.make()
      )
      // The tag better-auth did not check (`baeaa00bc`): a registration
      // challenge must not complete an authentication, or the other way round.
      if (claimed.payload.ceremony !== ceremony) {
        return yield* PasskeyVerificationFailed.make()
      }
      return claimed
    })

    const registrationOptions = Effect.fnUntraced(
      function* (request: RegistrationOptionsRequest) {
        const handle = yield* ensureHandle(request.user.id)
        const existing = yield* store.listByUserId(request.user.id)
        const issued = yield* issue({
          ceremony: "registration",
          userId: request.user.id,
          userVerification: config.userVerification
        })
        const document = yield* webauthn.generateRegistrationOptions({
          rpId: config.rpId,
          rpName: config.rpName,
          userHandle: handle,
          userName: request.user.email,
          userDisplayName: request.user.name,
          challenge: issued.challenge,
          timeout: timeoutMillis,
          excludeCredentials: descriptorsOf(existing),
          userVerification: config.userVerification,
          residentKey: config.residentKey,
          algorithms: config.algorithms,
          ...(request.authenticatorAttachment === undefined
            ? {}
            : { authenticatorAttachment: request.authenticatorAttachment })
        })
        return {
          options: document,
          handle: issued.handle,
          expiresAt: issued.expiresAt
        } satisfies IssuedCeremony<RegistrationOptions>
      },
      (effect) => Effect.withSpan(effect, "Passkeys.registrationOptions")
    )

    const verifyRegistration = Effect.fnUntraced(
      function* (options: VerifyRegistrationOptions) {
        const claimed = yield* claim(options.handle, "registration")
        // A registration challenge is always minted for a known person, and the
        // person completing it must be that person: a session that changed
        // between the two halves of the ceremony does not get to finish it.
        if (claimed.payload.userId !== options.user.id) {
          return yield* PasskeyVerificationFailed.make()
        }
        const verified = yield* webauthn.verifyRegistration({
          response: options.response,
          challenge: claimed.subject,
          rpId: config.rpId,
          origins: config.origins,
          requireUserVerification: claimed.payload.userVerification === "required",
          algorithms: config.algorithms
        })
        const now = yield* DateTime.now
        const row = yield* insertRow(Passkey.insert, {
          userId: options.user.id,
          credentialId: verified.credentialId,
          publicKey: verified.publicKey,
          signCount: verified.signCount,
          // Deduplicated, which is also what bounds the column: the element
          // schema is a closed set of seven.
          transports: Array.from(new Set(verified.transports)),
          aaguid: verified.aaguid,
          backupEligible: verified.backupEligible,
          backedUp: verified.backedUp,
          uvInitialised: verified.userVerified,
          name: options.name ?? null,
          lastUsedAt: null
        })
        const created = yield* Effect.result(store.create(row))
        if (Result.isFailure(created)) {
          // The unique index refused it: this credential is already registered,
          // here or to somebody else. One answer for both — see the header.
          if (isUniqueViolation(created.failure)) return yield* PasskeyVerificationFailed.make()
          return yield* created.failure
        }
        yield* publish(registeredEvent, options.user.id, {
          passkeyId: created.success.id,
          aaguid: created.success.aaguid,
          backupEligible: created.success.backupEligible,
          backedUp: created.success.backedUp,
          userVerified: verified.userVerified,
          registeredAt: DateTime.formatIso(now)
        })
        return created.success
      },
      (effect) => Effect.withSpan(effect, "Passkeys.verifyRegistration")
    )

    const authenticationOptions = Effect.fnUntraced(
      function* (request: AuthenticationOptionsRequest) {
        const bound = Option.map(request.session, (session) => session.userId)
        const scoped = yield* Option.match(bound, {
          onSome: (userId) => store.listByUserId(userId),
          onNone: () =>
            request.email === undefined
              ? Effect.succeed<ReadonlyArray<Passkey>>([])
              : Effect.flatMap(users.findByEmail(normalizeEmail(request.email)), (found) =>
                  Option.match(found, {
                    onNone: () => Effect.succeed<ReadonlyArray<Passkey>>([]),
                    onSome: (user) => store.listByUserId(user.id)
                  })
                )
        })
        // Computed whichever branch ran, so that an address with an account and
        // one without cost the same two HMACs. The result is used only when
        // there was nothing real to list for an address that was actually named.
        const decoys = request.email === undefined ? [] : yield* decoysFor(request.email)
        const allowCredentials =
          scoped.length > 0 ? descriptorsOf(scoped) : request.email === undefined || Option.isSome(bound) ? [] : decoys

        const issued = yield* issue({
          ceremony: "authentication",
          userId: Option.getOrNull(bound),
          userVerification: config.userVerification
        })
        const document = yield* webauthn.generateAuthenticationOptions({
          rpId: config.rpId,
          challenge: issued.challenge,
          timeout: timeoutMillis,
          allowCredentials,
          userVerification: config.userVerification
        })
        return {
          options: document,
          handle: issued.handle,
          expiresAt: issued.expiresAt
        } satisfies IssuedCeremony<AuthenticationOptions>
      },
      (effect) => Effect.withSpan(effect, "Passkeys.authenticationOptions")
    )

    const verifyAuthentication = Effect.fnUntraced(
      function* (options: VerifyAuthenticationOptions) {
        const claimed = yield* claim(options.handle, "authentication")
        const found = yield* store.findByCredentialId(options.response.id)
        if (Option.isNone(found)) {
          return yield* PasskeyVerificationFailed.make()
        }
        const stored = found.value

        // The check better-auth does not make. A ceremony minted for one person
        // may only be finished with that person's own credential, or
        // "re-authenticate as *this* user" enforces nothing.
        if (claimed.payload.userId !== null && claimed.payload.userId !== stored.userId) {
          return yield* PasskeyVerificationFailed.make()
        }

        const handle = yield* store.findHandle(stored.userId)
        const presented = options.response.response.userHandle
        // A discoverable sign-in is *identified* by the handle, so a handle this
        // deployment did not issue for this credential's owner is not a
        // credential this deployment registered.
        if (presented !== undefined && (Option.isNone(handle) || handle.value !== presented)) {
          return yield* PasskeyVerificationFailed.make()
        }

        const verified = yield* webauthn.verifyAuthentication({
          response: options.response,
          challenge: claimed.subject,
          rpId: config.rpId,
          origins: config.origins,
          requireUserVerification: claimed.payload.userVerification === "required",
          credential: {
            credentialId: stored.credentialId,
            publicKey: stored.publicKey,
            signCount: stored.signCount,
            transports: stored.transports
          }
        })

        // Synced passkeys never keep a counter, and two zeroes are what that
        // looks like — WebAuthn L3 §6.1.1 says to skip the check there rather
        // than to read it as a clone.
        const counted = !(stored.signCount === 0 && verified.signCount === 0)
        const regressed = counted && verified.signCount <= stored.signCount
        if (regressed) {
          yield* publish(counterRegressionEvent, stored.userId, {
            passkeyId: stored.id,
            storedSignCount: stored.signCount,
            presentedSignCount: verified.signCount,
            rejected: config.rejectCounterRegression
          })
          if (config.rejectCounterRegression) {
            return yield* PasskeyVerificationFailed.make()
          }
        }

        const now = yield* DateTime.now
        const recorded = yield* store.recordUse(stored.id, {
          // The high-water mark, not the last value seen. A tolerated
          // regression that overwrote the counter downwards would erase the
          // clone signal after a single event: with the row rewritten to the
          // clone's low counter, the real device's next ceremony presents a
          // *higher* number and looks clean, the clone's next one does too,
          // and a deployment watching this event for exactly that alternation
          // would see one blip and then silence. Keeping the maximum means
          // every subsequent use of the lagging authenticator keeps
          // publishing, and turning `rejectCounterRegression` on later still
          // catches it.
          signCount: Math.max(stored.signCount, verified.signCount),
          backedUp: verified.backedUp,
          // Once an authenticator has verified the person to itself it has a
          // PIN or a biometric; a later ceremony that did not use it does not
          // unlearn that.
          uvInitialised: stored.uvInitialised || verified.userVerified,
          lastUsedAt: now
        })
        const user = yield* users.findById(stored.userId)
        if (Option.isNone(user)) {
          // The account went between the credential read and here.
          return yield* PasskeyVerificationFailed.make()
        }
        return {
          user: user.value,
          passkey: Option.getOrElse(recorded, () => stored),
          evidence: passkeyEvidence(verified.userVerified),
          userVerified: verified.userVerified
        } satisfies VerifiedPasskey
      },
      (effect) => Effect.withSpan(effect, "Passkeys.verifyAuthentication")
    )

    const authenticate = Effect.fnUntraced(
      function* (options: VerifyAuthenticationOptions & { readonly request: SignInRequest }) {
        const verified = yield* verifyAuthentication(options)
        const current = Option.filter(options.session, (session) => session.userId === verified.user.id)
        if (Option.isSome(current)) {
          // The caller's own live session: raise it in place rather than mint a
          // second one. The id survives, the token rotates.
          const elevated = yield* sessions.elevate(current.value, verified.evidence)
          return PasskeyAuthentication.Elevated({ ...elevated, verified })
        }
        const result = yield* signIn.complete({
          user: verified.user,
          source: passkeySource,
          evidence: [verified.evidence],
          // A passkey sign-in is not a merge seam: the request either carried
          // this person's own session, in which case it was an elevation above,
          // or it carried somebody else's, which is not something to adopt.
          current: Option.none(),
          request: options.request
        })
        return PasskeyAuthentication.SignedIn({ result, verified })
      },
      (effect) => Effect.withSpan(effect, "Passkeys.authenticate")
    )

    /**
     * Whether the account would still hold a way in after `excluded` goes.
     *
     * **Details**
     *
     * Three sources, counted so that none is double-counted and none depends
     * on the deployment having wired the seam: the `accounts` rows that can
     * actually authenticate, this plugin's *own* remaining credentials read
     * straight from its table, and every other contributor's sign-in-capable
     * authenticators from the `Authenticators` seam.
     *
     * Reading this plugin's own credentials from the store rather than from
     * the seam is deliberate: a deployment that forgot `layerAuthenticators`
     * would otherwise be told it has no passkeys and be refused every removal.
     *
     * **Gotchas**
     *
     * The `accounts` half restates the rule `Accounts.unlink` applies — a
     * provider row is always a way in, a `local:credential` row only when it
     * carries a hash. The two spellings must not drift; there should be one
     * exported helper and there is not yet one.
     */
    const hasAnotherWayIn = Effect.fnUntraced(function* (userId: UserId, excluded: PasskeyId) {
      const held = yield* accountRows.listByUserId(userId)
      const fromAccounts = held.filter(
        (account) => account.issuer !== CredentialIssuer || account.passwordHash !== null
      ).length
      if (fromAccounts > 0) return true

      const mine = yield* store.listByUserId(userId)
      if (mine.some((passkey) => passkey.id !== excluded)) return true

      const others = yield* listAuthenticators(authenticators, userId)
      return others.some((summary) => summary.signIn && summary.type !== authenticatorType)
    })

    return Passkeys.of({
      config,
      registrationOptions,
      verifyRegistration,
      authenticationOptions,
      verifyAuthentication,
      authenticate,
      list: (userId) => store.listByUserId(userId),
      rename: (userId, id, name) => store.rename(id, userId, name),
      remove: Effect.fnUntraced(function* (userId, id) {
        // Removing a credential is the mirror of `Accounts.unlink`, and it owes
        // the same guarantee: a passwordless account whose only credential is
        // one passkey must not be able to delete itself out of existence.
        if (!(yield* hasAnotherWayIn(userId, id))) {
          return yield* CannotRemoveLastAuthenticator.make()
        }
        const removed = yield* store.remove(id, userId)
        if (removed) yield* publish(removedEvent, userId, { passkeyId: id })
        return removed
      })
    })
  }
)

/**
 * Provides {@link Passkeys}.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Passkeys, PasskeyStore, WebAuthn } from "effect-auth/passkeys"
 *
 * const PasskeysLive = Passkeys.layer({ rpId: "example.com", origin: "https://example.com" }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(WebAuthn.layerSimple),
 *   Layer.provide(PasskeyStore.layer)
 * )
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (options: Options): Layer.Layer<Passkeys, never, Requirements> =>
  Layer.effect(Passkeys, make(options))

/**
 * This plugin's contribution to the `Authenticators` seam, appended to whatever
 * the deployment already installed.
 *
 * **When to use**
 *
 * Always, and *underneath* `Auth.layer`: it is what makes `Accounts.unlink`
 * count a passkey as a way in, and what makes the takeover defence revoke one.
 *
 * ```ts skip-type-checking
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Passkeys.layerAuthenticators.pipe(Layer.provide(PasskeyStore.layer)))
 * )
 * ```
 *
 * **Gotchas**
 *
 * It appends rather than replaces, so a deployment serving passkeys *and* TOTP
 * gets both without either plugin knowing about the other. Reading the
 * reference here resolves its default when nothing installed one.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerAuthenticators: Layer.Layer<never, never, PasskeyStore> = Layer.effect(
  Authenticators,
  Effect.gen(function* () {
    const store = yield* PasskeyStore
    const installed = yield* Authenticators
    return combine(installed, authenticatorsOf(store))
  })
)
