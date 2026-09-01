/**
 * The HTTP contract of the username plugin.
 *
 * Three endpoints under `/auth/username`: sign in with a username and a
 * password, choose or change a username, and — only where a deployment switched
 * it on — ask whether one is free.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` is: it
 * pulls in schemas, the group declaration and the `Authenticated` middleware
 * *declaration*, never a store or a hasher. It is what `UsernameClient` and the
 * server implementation share.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { InvalidCredentials, EmailNotVerified, RateLimited } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { SessionWithUser } from "../domain/Schema.js"
import { MfaRequired, Secret } from "../http/AuthApi.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../http/Middleware.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * Why a username was refused.
 *
 * **Details**
 *
 * A closed set, so a client can say what is wrong without parsing prose. It
 * describes the *shape* of the name and never who holds it — that is
 * {@link UsernameTaken}, and the two are deliberately different answers: a
 * username is public by design, so telling somebody that one is taken reveals
 * nothing they could not learn by visiting a profile.
 *
 * @category models
 * @since 0.2.0
 */
export const UsernameRefusal = Schema.Literals(["too_short", "too_long", "charset", "reserved"])

/**
 * The type of a {@link UsernameRefusal}.
 *
 * @category models
 * @since 0.2.0
 */
export type UsernameRefusal = typeof UsernameRefusal.Type

/**
 * The username does not satisfy this deployment's rules.
 *
 * **Gotchas**
 *
 * Raised on the *write* path — the service's `set` — and never per route, so
 * every way a username can be chosen enforces the same rules. Sign-in does not
 * raise it: a name stored under an earlier policy must still be able to sign
 * in, and a shape check in front of the password verification would be a
 * timing signal.
 *
 * @category errors
 * @since 0.2.0
 */
export class UsernameInvalid extends Schema.TaggedError<UsernameInvalid>("effect-auth/username/UsernameInvalid")(
  "UsernameInvalid",
  { reason: UsernameRefusal },
  {
    description: "The username does not satisfy this deployment's rules",
    httpApiStatus: 400
  }
) {}

/**
 * Somebody else already holds that username, in its normalized form.
 *
 * **Details**
 *
 * The unique index is what decides this, not a read beforehand: two people
 * claiming one name in the same instant both reach the insert and exactly one
 * of them wins. See `Username.set`.
 *
 * @category errors
 * @since 0.2.0
 */
export class UsernameTaken extends Schema.TaggedError<UsernameTaken>("effect-auth/username/UsernameTaken")(
  "UsernameTaken",
  {},
  {
    description: "That username is already held by somebody else",
    httpApiStatus: 409
  }
) {}

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/**
 * A username as it arrives on the wire: bounded by the column that stores it,
 * and otherwise unjudged — the rules live on the write path.
 *
 * @category models
 * @since 0.2.0
 */
export const InputUsername = Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(64)))

/**
 * The body of `POST /auth/username/sign-in`.
 *
 * @category models
 * @since 0.2.0
 */
export const UsernameSignInPayload = Schema.Struct({
  username: InputUsername,
  password: Secret,
  /** When `false` the session expires in a day rather than at `session.expiresIn`. */
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The type of a {@link UsernameSignInPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type UsernameSignInPayload = typeof UsernameSignInPayload.Type

/**
 * The body of `POST /auth/username/set` and `POST /auth/username/available`.
 *
 * @category models
 * @since 0.2.0
 */
export const UsernamePayload = Schema.Struct({ username: InputUsername })

/**
 * The type of a {@link UsernamePayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type UsernamePayload = typeof UsernamePayload.Type

/**
 * What `POST /auth/username/set` answers with: the display form as it was
 * stored.
 *
 * **Gotchas**
 *
 * The display form, not the key. `Ada_Lovelace` and `ada_lovelace` are one
 * account and the second is what uniqueness is decided on, but the first is
 * what the person typed and what a profile should show.
 *
 * @category models
 * @since 0.2.0
 */
export const UsernameResponse = Schema.Struct({
  username: Schema.String,
  /** The normalized form uniqueness is decided on. */
  usernameKey: Schema.String
})

/**
 * The type of a {@link UsernameResponse}.
 *
 * @category models
 * @since 0.2.0
 */
export type UsernameResponse = typeof UsernameResponse.Type

/**
 * What `POST /auth/username/available` answers with.
 *
 * @category models
 * @since 0.2.0
 */
export const AvailabilityResponse = Schema.Struct({
  available: Schema.Boolean
})

/**
 * The type of an {@link AvailabilityResponse}.
 *
 * @category models
 * @since 0.2.0
 */
export type AvailabilityResponse = typeof AvailabilityResponse.Type

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const usernamePrefix = "/auth/username"

/**
 * The three endpoints the username plugin serves.
 *
 * **Details**
 *
 * A class, for the reasons `AuthApiGroup` is one, and non-generic: a plugin
 * group answers the base user projection, so it costs nothing against the user
 * model's `F` parameter.
 *
 * Only `set` carries the `Authenticated` middleware — signing in cannot require
 * a session, and the availability oracle is reachable by somebody who has no
 * account at all, which is the point of it.
 *
 * @category models
 * @since 0.2.0
 */
export class UsernameApiGroup extends HttpApiGroup.make("username")
  .add(
    HttpApiEndpoint.post("signIn", "/sign-in", {
      payload: UsernameSignInPayload,
      success: [SessionWithUser, MfaRequired],
      error: [InvalidCredentials, EmailNotVerified, PolicyRefused, OriginNotAllowed, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Sign in with a username and password",
        description:
          "The username resolves to a user id, or to an id that cannot exist, and exactly one password verification runs either way — so an unknown username, a user with no password credential and a wrong password are one answer, InvalidCredentials, at one cost. Success is the same two-status union as /auth/sign-in/email: 200 with the session and its user, or 202 with MfaRequired when a factor plugin owes a second factor, in which case the pending-authentication token is set in the __Host-effect_auth.pending cookie and no session cookie is written."
      })
    ),
    HttpApiEndpoint.post("set", "/set", {
      payload: UsernamePayload,
      success: UsernameResponse,
      error: [UsernameInvalid, UsernameTaken]
    })
      .middleware(Authenticated)
      // The username is a way into the account, so the decision is made against
      // the row rather than against a cookie-cache snapshot.
      .annotate(AuthoritativeSession, true)
      // And a stolen but stale cookie must not be enough to take somebody's
      // name — or to move one's own out of reach of a recovery flow.
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Choose or change the caller's username",
          description:
            "Replaces whatever username the caller held. The rules — length, character set, the reserved list — are enforced here, on the write path, so every way a username can be chosen enforces the same ones. UsernameTaken is the unique index answering, not a read beforehand, so two people claiming one name in the same instant produce exactly one winner. Requires a session that authenticated within session.freshAge."
        })
      ),
    HttpApiEndpoint.post("available", "/available", {
      payload: UsernamePayload,
      success: AvailabilityResponse,
      error: [UsernameInvalid, OriginNotAllowed, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Ask whether a username is free",
        description:
          "Served only where the deployment switched it on; answers 404 otherwise. A username is public by design, so an availability oracle is acceptable — but it is a deliberate choice rather than a default, and it is rate limited on its own bucket. A name that is not free and one that this deployment refuses are different answers: the first is available: false, the second is UsernameInvalid."
      })
    )
  )
  .prefix(usernamePrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Username",
      description: "Signing in with a username and password instead of an e-mail address."
    })
  ) {}

/**
 * The username endpoints as a standalone `HttpApi` — what `UsernameClient`
 * builds against.
 *
 * @category models
 * @since 0.2.0
 */
export const UsernameApi = HttpApi.make("effect-auth-username").add(UsernameApiGroup)
