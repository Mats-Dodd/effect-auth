/**
 * Authenticator assurance: what a session actually proved, and what an
 * operation demands before it will run.
 *
 * **Details**
 *
 * A session records an append-only log of the {@link AuthenticationMethod}s that
 * established it. That log is the stored truth; everything else here is derived
 * from it by a pure function, so there is exactly one place each derivation is
 * written:
 *
 * - {@link deriveAal} collapses the log to an {@link Aal}, the level a policy
 *   compares against. It is materialised onto the session row so the cookie
 *   cache carries it and the compiler can exhaust it.
 * - {@link amrOf} projects the log onto the RFC 8176 registered `amr` values,
 *   for the day a token plugin needs the claim.
 *
 * `method` is an **open set** — a plain string, never a closed union — because a
 * plugin outside this package names its own factors. Only `factor`,
 * which is what the derivation counts, is closed.
 *
 * **Gotchas**
 *
 * `aal3` is not derived. This library does not verify authenticator attestation
 * against a trust root, so "hardware-bound" would be an unverified claim; the
 * type does not admit it, and {@link amrOf} never emits `hwk` for the same
 * reason.
 *
 * @since 0.2.0
 */
import { Duration, Schema } from "effect"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * The authenticator assurance level a session reached.
 *
 * **Details**
 *
 * Three frozen wire strings, in Ory's spelling, so a future token plugin can
 * emit them as an `acr` claim unchanged:
 *
 * - `aal0` — nothing was proven. An anonymous session.
 * - `aal1` — one factor.
 * - `aal2` — two distinct factors, or one multi-factor ceremony.
 *
 * `aal0` exists so that `requireAssurance({ aal: "aal1" })` is the single guard
 * that excludes anonymous sessions, rather than an `isAnonymous` check
 * scattered over the endpoints that care.
 *
 * @category models
 * @since 0.2.0
 */
export const Aal: Schema.Literals<["aal0", "aal1", "aal2"]> = Schema.Literals(["aal0", "aal1", "aal2"])

/**
 * The type of an {@link Aal}.
 *
 * @category models
 * @since 0.2.0
 */
export type Aal = typeof Aal.Type

/**
 * What kind of thing an authentication method proved.
 *
 * **Details**
 *
 * The NIST 800-63B factor taxonomy, plus `none` for a method that is a true
 * statement about how a session was established but proves nothing on its own —
 * a trusted-device skip is the example, and it is recorded rather than dropped
 * precisely so the log stays honest while {@link deriveAal} gives it no weight.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticationFactor: Schema.Literals<["knowledge", "possession", "inherence", "none"]> = Schema.Literals([
  "knowledge",
  "possession",
  "inherence",
  "none"
])

/**
 * The type of an {@link AuthenticationFactor}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticationFactor = typeof AuthenticationFactor.Type

/**
 * One thing a person proved, once.
 *
 * **Details**
 *
 * `method` is the open set: `"password"`, `"totp"`, `"passkey"`, `"emailOtp"`,
 * `"recoveryCode"`, `"trustedDevice"`, `"oauth:google"`, or whatever a plugin
 * outside this package calls its own factor. Nothing branches on an unknown
 * value; the derivations read `factor`, `restricted` and `userVerified`.
 *
 * `restricted` marks a factor NIST 800-63B §3.2.9 restricts — SMS and PSTN
 * delivery — so a policy can refuse it without knowing which methods a
 * deployment installed. `userVerified` is present only for a ceremony that
 * reports one: it is the WebAuthn UV bit, read off the authenticator's own
 * response and never off the `userVerification` the request asked for.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticationMethod = Schema.Struct({
  /** How the person authenticated. An open set — see the details above. */
  method: Schema.String,
  /** When the ceremony completed. */
  completedAt: Schema.DateTimeUtcFromString,
  /** What kind of thing it proved. */
  factor: AuthenticationFactor,
  /** Whether the ceremony is bound to an origin, as WebAuthn is. */
  phishingResistant: Schema.Boolean,
  /** Whether NIST 800-63B restricts the channel it used (SMS, PSTN). */
  restricted: Schema.Boolean,
  /** The WebAuthn user-verification bit, where the ceremony reports one. */
  userVerified: Schema.optionalKey(Schema.Boolean)
})

/**
 * The type of an {@link AuthenticationMethod}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticationMethod = typeof AuthenticationMethod.Type

/**
 * A session's authentication log, in the order the methods completed.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticationMethods: Schema.$Array<typeof AuthenticationMethod> = Schema.Array(AuthenticationMethod)

/**
 * The type of {@link AuthenticationMethods}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticationMethods = typeof AuthenticationMethods.Type

/**
 * {@link AuthenticationMethods} as it is stored: a JSON array in a `text`
 * column.
 *
 * **Details**
 *
 * One codec, used by every variant of the session model, which is what makes
 * the cookie cache work: a snapshot is written through `Session.json` and read
 * back through the *stored* variant, so the two must agree on the encoded form.
 * The precedent for a text column that stays text on the wire is
 * `accounts.scope`.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticationMethodsJson: Schema.fromJsonString<typeof AuthenticationMethods> =
  Schema.fromJsonString(AuthenticationMethods)

// -----------------------------------------------------------------------------
// Derivations
// -----------------------------------------------------------------------------

/**
 * The methods that count: everything the log records except the entries that
 * prove nothing.
 */
const live = (methods: ReadonlyArray<AuthenticationMethod>): ReadonlyArray<AuthenticationMethod> =>
  methods.filter((entry) => entry.factor !== "none")

/**
 * Whether one ceremony proved two factors by itself.
 *
 * A WebAuthn authenticator that reports `UV=1` verified the person to the
 * authenticator — a PIN or a biometric — *and* demonstrated possession of the
 * key, in one ceremony and with no second prompt. That is the definition of a
 * multi-factor authenticator, so the bit rather than the method name is what is
 * read: a plugin that calls its factor something other than `"passkey"` is
 * judged on the same evidence.
 */
const isMultiFactorCeremony = (entry: AuthenticationMethod): boolean => entry.userVerified === true

/**
 * The assurance level a set of authentication methods reaches.
 *
 * **Details**
 *
 * Entries whose `factor` is `"none"` are ignored — a trusted-device skip is
 * recorded, and weighs nothing. Of what is left: nothing at all is `aal0`; a
 * single ceremony that verified the user to the authenticator is `aal2` on its
 * own; two or more *distinct* factors are `aal2`; anything else is `aal1`.
 *
 * Distinctness is what stops two possession factors — a TOTP code and a mailed
 * code — adding up to `aal2`.
 *
 * @category combinators
 * @since 0.2.0
 */
export const deriveAal = (methods: ReadonlyArray<AuthenticationMethod>): Aal => {
  const counted = live(methods)
  if (counted.length === 0) return "aal0"
  if (counted.some(isMultiFactorCeremony)) return "aal2"
  const factors = new Set(counted.map((entry) => entry.factor))
  return factors.size >= 2 ? "aal2" : "aal1"
}

/**
 * The RFC 8176 values one method contributes, before deduplication.
 *
 * **Details**
 *
 * A closed table over an open set: a method with no entry contributes nothing,
 * which is the honest answer for federated sign-in (`"oauth:google"`) and for
 * anonymous sessions, neither of which has a registered value. Inventing a
 * private vocabulary — as Supabase and Ory both did — is what the stored
 * `methods` log exists to avoid.
 *
 * `swk` rather than `hwk` for a WebAuthn credential: this library does not
 * verify attestation, so "hardware-secured" is not something it can claim.
 */
const amrEntriesOf = (entry: AuthenticationMethod): ReadonlyArray<string> => {
  switch (entry.method) {
    case "password":
      return ["pwd"]
    case "totp":
      return ["otp"]
    case "recoveryCode":
      return ["otp"]
    // A code or a link delivered to a channel that is not the one being
    // authenticated: `mca` is multiple-channel authentication.
    case "emailOtp":
    case "magic-link":
      return ["otp", "mca"]
    case "sms":
      return ["otp", "sms", "mca"]
    case "passkey":
      return entry.userVerified === true ? ["swk", "pop", "user"] : ["swk", "pop"]
    default:
      return []
  }
}

/**
 * The RFC 8176 `amr` values a set of authentication methods justifies.
 *
 * **Details**
 *
 * Registered values only, deduplicated, in the order the methods completed,
 * with `mfa` appended when {@link deriveAal} reaches `aal2`. A method this
 * library has no registered value for contributes nothing rather than a made-up
 * string, so the claim stays interoperable and an `amr` this produces never
 * over-states what happened.
 *
 * **When to use**
 *
 * When something outside this library needs the standards-registered form — a
 * JWT `amr` claim, an audit record a compliance tool reads. Inside the library,
 * `methods` is the value to branch on.
 *
 * @category combinators
 * @since 0.2.0
 */
export const amrOf = (methods: ReadonlyArray<AuthenticationMethod>): ReadonlyArray<string> => {
  const values = new Set<string>()
  for (const entry of live(methods)) {
    for (const value of amrEntriesOf(entry)) values.add(value)
  }
  if (deriveAal(methods) === "aal2") values.add("mfa")
  return Array.from(values)
}

// -----------------------------------------------------------------------------
// Policy
// -----------------------------------------------------------------------------

/**
 * What an operation demands of the session that reaches it.
 *
 * **Details**
 *
 * Every member is optional and they are conjunctive: a policy that states
 * nothing admits every authenticated session, and each member it does state
 * must hold.
 *
 * - `aal` — the minimum level, compared on the frozen ordering `aal0 < aal1 <
 *   aal2`.
 * - `maxAge` — how long ago the session may have been *interactively*
 *   authenticated. Measured from `Session.authenticatedAt`, which the rolling
 *   refresh never moves.
 * - `methods` — the method names that satisfy the requirement, when an endpoint
 *   is stricter than a level (a re-authentication that only a passkey may
 *   perform).
 * - `allowRecovery` — whether a recovery code counts. Defaults to allowing it:
 *   refusing it silently is what locks a legitimate person out of the page
 *   where they would repair their second factor.
 *
 * @category models
 * @since 0.2.0
 */
export interface AssurancePolicy {
  readonly aal?: Aal
  readonly maxAge?: Duration.Duration
  readonly methods?: ReadonlyArray<string>
  readonly allowRecovery?: boolean
}

/**
 * An {@link AssurancePolicy} as it goes over the wire.
 *
 * **Details**
 *
 * The one difference is `maxAge`, which is seconds rather than a
 * `Duration` — the shape RFC 9470's `max_age` challenge parameter uses, so a
 * bearer transport can render the same requirement as a `WWW-Authenticate`
 * header without a second translation.
 *
 * @category models
 * @since 0.2.0
 */
export const AssurancePolicyJson = Schema.Struct({
  aal: Schema.optionalKey(Aal),
  /** Seconds. */
  maxAge: Schema.optionalKey(Schema.Finite),
  methods: Schema.optionalKey(Schema.Array(Schema.String)),
  allowRecovery: Schema.optionalKey(Schema.Boolean)
})

/**
 * The type of an {@link AssurancePolicyJson}.
 *
 * @category models
 * @since 0.2.0
 */
export type AssurancePolicyJson = typeof AssurancePolicyJson.Type

/**
 * An {@link AssurancePolicy} in its wire form.
 *
 * **Details**
 *
 * A member the policy did not state stays absent rather than becoming `null`,
 * so a client can tell "any level will do" from "level `aal0`".
 *
 * **Gotchas**
 *
 * An infinite `maxAge` — the documented way for an endpoint to say "any age
 * will do" beside a level it does insist on — is *also* absent, because there
 * is no number that means it and `AssurancePolicyJson.maxAge` is finite by
 * schema. Emitting `Infinity` there does not make a body a client could read:
 * it makes `StepUpRequired.make` throw, which turns a 403 into a 500 and tells
 * the caller nothing at all. Absent is the honest encoding and it is what
 * "unstated" already means.
 *
 * @category combinators
 * @since 0.2.0
 */
export const policyToJson = (policy: AssurancePolicy): AssurancePolicyJson => ({
  ...(policy.aal === undefined ? {} : { aal: policy.aal }),
  ...(policy.maxAge === undefined || !Duration.isFinite(policy.maxAge)
    ? {}
    : { maxAge: Duration.toSeconds(policy.maxAge) }),
  ...(policy.methods === undefined ? {} : { methods: policy.methods }),
  ...(policy.allowRecovery === undefined ? {} : { allowRecovery: policy.allowRecovery })
})

/**
 * What the session that was refused actually had.
 *
 * **Details**
 *
 * `available` is the method names this person *could* step up with, which is
 * what lets a client offer the right prompt instead of guessing — and lets it
 * degrade gracefully when the answer is "none of them". It carries no
 * identifier, no address and no secret: the names of factor kinds only.
 *
 * @category models
 * @since 0.2.0
 */
export const CurrentAssurance = Schema.Struct({
  aal: Aal,
  authenticatedAt: Schema.DateTimeUtcFromString,
  available: Schema.Array(Schema.String)
})

/**
 * The type of a {@link CurrentAssurance}.
 *
 * @category models
 * @since 0.2.0
 */
export type CurrentAssurance = typeof CurrentAssurance.Type
