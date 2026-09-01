/**
 * The two failures a WebAuthn ceremony has, as the caller sees them.
 *
 * **Details**
 *
 * Browser-safe and free of the optional dependency: {@link WebAuthn} raises
 * these, `Passkeys` raises them, the endpoints declare them and the client
 * decodes them, so they live in a module all four can import.
 *
 * There are two, and there are deliberately only two.
 * {@link PasskeyVerificationFailed} is every way a presented assertion can be
 * wrong — a bad signature, an unknown credential, the wrong origin, the wrong
 * RP id, a credential belonging to somebody else, a `userHandle` that does not
 * match the one this deployment issued. Telling them apart would tell an
 * unauthenticated caller which of their guesses was closest, and none of the
 * distinctions is one the caller can act on: the answer to all of them is
 * "try again with a credential you actually hold".
 *
 * {@link ChallengeExpired} is separate because it *is* actionable and it says
 * nothing about anybody: the ceremony this request belongs to is over, and the
 * client should ask for fresh options. It is raised before any credential is
 * looked at, so it cannot be used to probe for one.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"

/**
 * The assertion or attestation this deployment was handed is not one it will
 * accept.
 *
 * **Gotchas**
 *
 * One error for every reason. See the module header for why, and do not add a
 * `reason` field to it: the moment it carries one, an attacker enumerating
 * credential ids can tell "no such credential" from "not your credential".
 *
 * @category errors
 * @since 0.2.0
 */
export class PasskeyVerificationFailed extends Schema.TaggedError<PasskeyVerificationFailed>(
  "effect-auth/passkeys/PasskeyVerificationFailed"
)(
  "PasskeyVerificationFailed",
  {},
  {
    description: "The passkey could not be verified",
    httpApiStatus: 401
  }
) {}

/**
 * The ceremony this request belongs to has expired, was already completed, or
 * was never started by this browser.
 *
 * **Details**
 *
 * A challenge is a single-use `Verifications` row addressed by a `__Host-`
 * cookie, so "expired", "already spent" and "never issued" are one state —
 * exactly as they are for every other single-use token in this library. Nothing
 * about a user is implied by it: it is raised before the presented credential
 * is read.
 *
 * @category errors
 * @since 0.2.0
 */
export class ChallengeExpired extends Schema.TaggedError<ChallengeExpired>("effect-auth/passkeys/ChallengeExpired")(
  "ChallengeExpired",
  {},
  {
    description: "The passkey challenge has expired or was already used",
    httpApiStatus: 400
  }
) {}

/**
 * Removing this credential would leave the account with no way into it.
 *
 * **Details**
 *
 * The mirror of core's `CannotUnlinkLastAccount`, and it exists for the same
 * reason: a passwordless account whose only credential is one passkey would
 * otherwise be able to delete it and be locked out with nothing left to
 * present. `Accounts.unlink` counts a passkey as a way in — this is the other
 * half of that sum.
 *
 * Unlike {@link PasskeyVerificationFailed} this one *is* specific, and safely
 * so: it is raised only for a caller who already holds a session for the
 * account, and it discloses nothing that caller could not read from
 * `GET /auth/passkeys` and their own account list.
 *
 * @category errors
 * @since 0.2.0
 */
export class CannotRemoveLastAuthenticator extends Schema.TaggedError<CannotRemoveLastAuthenticator>(
  "effect-auth/passkeys/CannotRemoveLastAuthenticator"
)(
  "CannotRemoveLastAuthenticator",
  {},
  {
    description: "Removing this passkey would leave the account with no way to sign in",
    httpApiStatus: 409
  }
) {}
