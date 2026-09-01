/**
 * The observability seam of `effect-auth`.
 *
 * Every flow that changes an identity — a user is created, a session is
 * established or revoked, a password changes, an account is linked — publishes
 * a tagged {@link AuthEvent}. An application subscribes to
 * {@link AuthEvents.stream} to drive welcome mails, audit logs, analytics or a
 * security-alert pipeline without the library taking a dependency on any of
 * them.
 *
 * **Details**
 *
 * Emission is **after commit** and **best effort**. A domain service runs its
 * writes (inside `WithAuthTransaction.run` when more than one store is
 * involved) and only publishes once that effect has succeeded, so a subscriber
 * never observes an event for a transaction that later rolled back. Publishing
 * itself can neither fail nor block: the default layer is backed by a dropping
 * `PubSub`, so a slow or absent subscriber costs a dropped event rather than a
 * stalled sign-in.
 *
 * **Gotchas**
 *
 * Because delivery is best effort, these events are not an audit *ledger*. If
 * you need one, write it inside the transaction through your own store.
 *
 * **Example**
 *
 * ```ts
 * import { Effect, Stream } from "effect"
 * import { AuthEvents } from "effect-auth"
 *
 * const audit = Effect.gen(function*() {
 *   const events = yield* AuthEvents
 *   yield* Stream.runForEach(events.stream, (event) => Effect.log(event._tag))
 * })
 * ```
 *
 * @since 1.0.0
 */
import type { Scope } from "effect"
import { Context, Effect, Layer, PubSub, Schema, Stream } from "effect"
import { dual } from "effect/Function"
import { annotateAuthLogs } from "../internal/effects.js"
import { AccountId, SessionId, UserId } from "./Schema.js"

// -----------------------------------------------------------------------------
// Sign-in methods
// -----------------------------------------------------------------------------

/**
 * The `method` recorded on a sign-in that used an e-mail address and password.
 *
 * @category constructors
 * @since 1.0.0
 */
export const passwordMethod = "password"

/**
 * The `method` recorded on a sign-in that came back from an OAuth provider.
 *
 * @category constructors
 * @since 1.0.0
 */
export const oauthMethod = (providerId: string): string => `oauth:${providerId}`

// -----------------------------------------------------------------------------
// Events
// -----------------------------------------------------------------------------

/**
 * A user row was provisioned — by e-mail sign-up, or by an OAuth flow that
 * found no existing account to link to.
 *
 * @category models
 * @since 1.0.0
 */
export const UserCreated = Schema.TaggedStruct("UserCreated", {
  userId: UserId,
  email: Schema.String,
  emailVerified: Schema.Boolean,
  /** {@link passwordMethod}, or {@link oauthMethod} of the provider that provisioned the user. */
  method: Schema.String
})

/**
 * The type of a {@link UserCreated} event.
 *
 * @category models
 * @since 1.0.0
 */
export type UserCreated = typeof UserCreated.Type

/**
 * A session was established.
 *
 * @category models
 * @since 1.0.0
 */
export const SignedIn = Schema.TaggedStruct("SignedIn", {
  userId: UserId,
  sessionId: SessionId,
  /** {@link passwordMethod}, or {@link oauthMethod} of the provider used. */
  method: Schema.String
})

/**
 * The type of a {@link SignedIn} event.
 *
 * @category models
 * @since 1.0.0
 */
export type SignedIn = typeof SignedIn.Type

/**
 * A session was ended by its own owner presenting it.
 *
 * @category models
 * @since 1.0.0
 */
export const SignedOut = Schema.TaggedStruct("SignedOut", {
  userId: UserId,
  sessionId: SessionId
})

/**
 * The type of a {@link SignedOut} event.
 *
 * @category models
 * @since 1.0.0
 */
export type SignedOut = typeof SignedOut.Type

/**
 * How broadly a revocation applied.
 *
 * @category models
 * @since 1.0.0
 */
export const RevocationScope = Schema.Literals(["single", "all", "others"])

/**
 * The type of a {@link RevocationScope}.
 *
 * @category models
 * @since 1.0.0
 */
export type RevocationScope = typeof RevocationScope.Type

/**
 * One or more sessions were revoked.
 *
 * **Details**
 *
 * `sessionId` is present only for a `"single"` revocation. `count` is how many
 * rows were actually removed, which is the useful figure for the `"all"` and
 * `"others"` scopes — a password reset that signs eleven devices out is worth
 * an alert.
 *
 * @category models
 * @since 1.0.0
 */
export const SessionRevoked = Schema.TaggedStruct("SessionRevoked", {
  userId: UserId,
  sessionId: Schema.NullOr(SessionId),
  scope: RevocationScope,
  count: Schema.Finite
})

/**
 * The type of a {@link SessionRevoked} event.
 *
 * @category models
 * @since 1.0.0
 */
export type SessionRevoked = typeof SessionRevoked.Type

/**
 * A user's password hash was replaced — through `changePassword` or through a
 * completed reset.
 *
 * @category models
 * @since 1.0.0
 */
export const PasswordChanged = Schema.TaggedStruct("PasswordChanged", {
  userId: UserId,
  /** `true` when the change came from a consumed reset token rather than the current password. */
  viaReset: Schema.Boolean
})

/**
 * The type of a {@link PasswordChanged} event.
 *
 * @category models
 * @since 1.0.0
 */
export type PasswordChanged = typeof PasswordChanged.Type

/**
 * A password reset link was minted and handed to the e-mail seam.
 *
 * **Gotchas**
 *
 * This is emitted only when the address actually belongs to a user. The
 * endpoint answers `200` either way, so the absence of this event is the only
 * place the distinction exists — keep it out of anything a caller can observe.
 *
 * @category models
 * @since 1.0.0
 */
export const PasswordResetRequested = Schema.TaggedStruct("PasswordResetRequested", {
  userId: UserId
})

/**
 * The type of a {@link PasswordResetRequested} event.
 *
 * @category models
 * @since 1.0.0
 */
export type PasswordResetRequested = typeof PasswordResetRequested.Type

/**
 * A user's e-mail address was confirmed by a consumed verification token.
 *
 * @category models
 * @since 1.0.0
 */
export const EmailVerified = Schema.TaggedStruct("EmailVerified", {
  userId: UserId,
  email: Schema.String
})

/**
 * The type of an {@link EmailVerified} event.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailVerified = typeof EmailVerified.Type

/**
 * Which of a user's own profile fields a {@link UserUpdated} touched.
 *
 * **Gotchas**
 *
 * The base user's two mutable fields, and only those. A deployment's own custom
 * columns are deliberately not named here: an event is forwarded to log sinks
 * and webhooks, and this library cannot know whether a field a deployment added
 * is safe to name there. An update that touched nothing but custom fields
 * publishes an empty `fields`.
 *
 * @category models
 * @since 1.0.0
 */
export const UpdatedUserField = Schema.Literals(["name", "image"])

/**
 * The type of an {@link UpdatedUserField}.
 *
 * @category models
 * @since 1.0.0
 */
export type UpdatedUserField = typeof UpdatedUserField.Type

/**
 * A user edited their own profile.
 *
 * @category models
 * @since 1.0.0
 */
export const UserUpdated = Schema.TaggedStruct("UserUpdated", {
  userId: UserId,
  /** The base fields the update actually changed. See {@link UpdatedUserField}. */
  fields: Schema.Array(UpdatedUserField)
})

/**
 * The type of a {@link UserUpdated} event.
 *
 * @category models
 * @since 1.0.0
 */
export type UserUpdated = typeof UserUpdated.Type

/**
 * A user's e-mail address was replaced, both halves of the two-hop change
 * having been proven.
 *
 * **Details**
 *
 * The address ends up verified: the token that completed the change was
 * delivered to it. `previousEmail` is carried because a security pipeline that
 * alerts on address changes needs to be able to reach the *old* mailbox.
 *
 * @category models
 * @since 1.0.0
 */
export const EmailChanged = Schema.TaggedStruct("EmailChanged", {
  userId: UserId,
  previousEmail: Schema.String,
  email: Schema.String
})

/**
 * The type of an {@link EmailChanged} event.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailChanged = typeof EmailChanged.Type

/**
 * A user row was deleted, taking its sessions and its sign-in methods with it.
 *
 * **Gotchas**
 *
 * Published *after* the row has gone, so a subscriber that wants anything else
 * about the person has to have recorded it beforehand. `email` is carried for
 * exactly that reason: it is the one field an off-boarding pipeline invariably
 * needs and can no longer read.
 *
 * @category models
 * @since 1.0.0
 */
export const UserDeleted = Schema.TaggedStruct("UserDeleted", {
  userId: UserId,
  email: Schema.String
})

/**
 * The type of a {@link UserDeleted} event.
 *
 * @category models
 * @since 1.0.0
 */
export type UserDeleted = typeof UserDeleted.Type

/**
 * A linked provider's tokens were exchanged for fresh ones.
 *
 * @category models
 * @since 1.0.0
 */
export const TokensRefreshed = Schema.TaggedStruct("TokensRefreshed", {
  userId: UserId,
  accountId: AccountId,
  providerId: Schema.String
})

/**
 * The type of a {@link TokensRefreshed} event.
 *
 * @category models
 * @since 1.0.0
 */
export type TokensRefreshed = typeof TokensRefreshed.Type

/**
 * A sign-in method was added to a user.
 *
 * @category models
 * @since 1.0.0
 */
export const AccountLinked = Schema.TaggedStruct("AccountLinked", {
  userId: UserId,
  accountId: AccountId,
  providerId: Schema.String,
  issuer: Schema.String
})

/**
 * The type of an {@link AccountLinked} event.
 *
 * @category models
 * @since 1.0.0
 */
export type AccountLinked = typeof AccountLinked.Type

/**
 * A sign-in method was removed from a user.
 *
 * @category models
 * @since 1.0.0
 */
export const AccountUnlinked = Schema.TaggedStruct("AccountUnlinked", {
  userId: UserId,
  accountId: AccountId,
  providerId: Schema.String,
  issuer: Schema.String
})

/**
 * The type of an {@link AccountUnlinked} event.
 *
 * @category models
 * @since 1.0.0
 */
export type AccountUnlinked = typeof AccountUnlinked.Type

/**
 * Something a plugin did that a subscriber should be able to see.
 *
 * **Details**
 *
 * The event union is closed — a subscriber matches on `_tag` exhaustively — so a
 * plugin cannot add a member of its own. This is the door instead: `plugin` names
 * the module (`"magic-link"`, `"two-factor"`), `event` names what happened
 * (`"requested"`, `"verified"`), `userId` is present when the flow knows one, and
 * `data` carries whatever else is worth recording.
 *
 * **Gotchas**
 *
 * `data` is forwarded to log sinks and webhooks exactly as the rest of the union
 * is, so the same rule applies to it and more sharply: no token, no hash, no
 * credential, no e-mail body. An identifier and a classification are enough for a
 * subscriber to go and read whatever else it needs.
 *
 * @category models
 * @since 1.0.0
 */
export const PluginEvent = Schema.TaggedStruct("PluginEvent", {
  /** The plugin that published it, in kebab-case. */
  plugin: Schema.String,
  /** What happened, named by the plugin. */
  event: Schema.String,
  /** The user it concerns, or `null` where the flow has not identified one. */
  userId: Schema.NullOr(UserId),
  /** Anything else worth recording. Never a secret — see the gotcha above. */
  data: Schema.Record(Schema.String, Schema.Unknown)
})

/**
 * The type of a {@link PluginEvent}.
 *
 * @category models
 * @since 1.0.0
 */
export type PluginEvent = typeof PluginEvent.Type

/**
 * Everything `effect-auth` publishes.
 *
 * **Gotchas**
 *
 * No member carries a token, a password, a hash or a provider credential.
 * Events are routinely forwarded to log sinks and webhooks, so keep it that
 * way: an identifier and a classification are enough for a subscriber to go and
 * read whatever else it needs.
 *
 * @category models
 * @since 1.0.0
 */
export const AuthEvent = Schema.Union([
  UserCreated,
  SignedIn,
  SignedOut,
  SessionRevoked,
  PasswordChanged,
  PasswordResetRequested,
  EmailVerified,
  UserUpdated,
  EmailChanged,
  UserDeleted,
  TokensRefreshed,
  AccountLinked,
  AccountUnlinked,
  PluginEvent
])

/**
 * The type of an {@link AuthEvent}.
 *
 * @category models
 * @since 1.0.0
 */
export type AuthEvent = typeof AuthEvent.Type

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link AuthEvents} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface AuthEventsService {
  /**
   * Publishes one event.
   *
   * **Details**
   *
   * Never fails and never suspends: a full buffer drops the event. Call it
   * *after* the writes it describes have committed.
   */
  readonly publish: (event: AuthEvent) => Effect.Effect<void>

  /**
   * Every event published from the moment the stream is run. There is no
   * replay of history.
   */
  readonly stream: Stream.Stream<AuthEvent>

  /**
   * A scoped subscription, for consumers that want to pull rather than run a
   * `Stream`. The subscription is closed when the scope closes.
   */
  readonly subscribe: Effect.Effect<PubSub.Subscription<AuthEvent>, never, Scope.Scope>

  /**
   * The underlying hub, exposed so an application can build its own `Stream`
   * combinators or share the hub with adjacent features.
   */
  readonly pubsub: PubSub.PubSub<AuthEvent>
}

/**
 * The publish/subscribe hub the domain services emit through.
 *
 * @category services
 * @since 1.0.0
 */
export class AuthEvents extends Context.Service<AuthEvents, AuthEventsService>()(
  "effect-auth/domain/Events/AuthEvents"
) {}

/**
 * How many events the default hub buffers before it starts dropping.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultCapacity = 256

/**
 * Builds an {@link AuthEvents} implementation over a dropping `PubSub`.
 *
 * **Details**
 *
 * Dropping — rather than back-pressuring or sliding — is the deliberate
 * choice: a subscriber that stops consuming must not be able to wedge every
 * sign-in in the process, and the newest events are the ones a security
 * pipeline cares about least once it has already fallen behind.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: (options?: { readonly capacity?: number | undefined }) => Effect.Effect<AuthEventsService> =
  Effect.fnUntraced(function* (options?: { readonly capacity?: number | undefined }) {
    const pubsub = yield* PubSub.dropping<AuthEvent>(options?.capacity ?? defaultCapacity)
    return AuthEvents.of({
      pubsub,
      publish: (event) => Effect.asVoid(PubSub.publish(pubsub, event)),
      stream: Stream.fromPubSub(pubsub),
      subscribe: PubSub.subscribe(pubsub)
    })
  })

/**
 * Provides {@link AuthEvents} over a dropping hub.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = (options?: { readonly capacity?: number | undefined }): Layer.Layer<AuthEvents> =>
  Layer.effect(AuthEvents, make(options))

/**
 * Publishes an event through the ambient {@link AuthEvents}, swallowing any
 * defect the hub might raise.
 *
 * **When to use**
 *
 * In consumer code that has {@link AuthEvents} in its requirements and no
 * resolved service to hand — a plugin, an application effect that publishes an
 * event of this library's own. It is {@link publishSafely} with the lookup
 * folded in, so a single `yield* emit(...)` after a commit can never turn a
 * successful request into a failed one, whatever a future hub implementation
 * does.
 *
 * **Gotchas**
 *
 * The domain services do not use this: each of them resolves `AuthEvents` when
 * its layer is built and calls {@link publishSafely} directly, which is what
 * keeps `AuthEvents` out of the requirements of every method.
 *
 * @category combinators
 * @since 1.0.0
 */
export const emit = (event: AuthEvent): Effect.Effect<void, never, AuthEvents> =>
  AuthEvents.use((events) => publishSafely(events, event))

/**
 * Publishes an event through an already-resolved {@link AuthEvents}, swallowing
 * any defect the hub might raise.
 *
 * **When to use**
 *
 * This is what the domain services call: each of them resolves `AuthEvents`
 * once, when its own layer is built, so emitting costs nothing at request time
 * and does not leak `AuthEvents` into the requirement of every method.
 *
 * @category combinators
 * @since 1.0.0
 */
export const publishSafely: {
  (event: AuthEvent): (events: AuthEventsService) => Effect.Effect<void>
  (events: AuthEventsService, event: AuthEvent): Effect.Effect<void>
} = dual(2, (events: AuthEventsService, event: AuthEvent): Effect.Effect<void> =>
  Effect.catchCause(events.publish(event), (cause) =>
    annotateAuthLogs(Effect.logDebug("an auth event was not published", cause))
  )
)
