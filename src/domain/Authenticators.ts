/**
 * Every way a person can prove who they are, gathered from the plugins that own
 * them.
 *
 * **Details**
 *
 * Core knows about exactly one credential class — the `accounts` rows a
 * password or an OAuth identity writes — and two of its decisions are about
 * *all* of them: `Accounts.unlink` refuses to remove the last way in, and the
 * email-otp reclaim path revokes every way in before it hands an unproven
 * address to whoever proved it. A passkey, a TOTP secret or a recovery-code set
 * is a way in that `accounts` has never heard of, so both decisions are wrong
 * the moment a factor plugin ships: `unlink` refuses a user who still holds a
 * passkey, and reclaim deletes the `accounts` rows while leaving the
 * pre-registrant's passkey working — the defence reporting success while
 * failing open.
 *
 * The alternative — a core `authenticators` table plugins write rows into — is
 * a shared table wearing a hat, and it is the one shape this library forbids: a
 * plugin never adds a column to a core table and never writes another module's
 * rows. So the aggregate is a *seam*, not a table. Each plugin keeps its own
 * table and its own management endpoints, and contributes a read and a revoke;
 * core asks the seam the two questions it has to ask about all of them.
 *
 * **Gotchas — this is a monoid over a `Context.Reference`, exactly like
 * `AuthHooks`**
 *
 * Both members are optional and the default is the empty set, so a deployment
 * with no factor plugins provides nothing and every answer is "no
 * authenticators beyond the ones core can see for itself". {@link layer}
 * installs a set; {@link append} adds to whatever is already there, which is
 * what a plugin uses, because a plugin cannot know what else is installed.
 *
 * `revokeAll` is called from inside the caller's transaction, under whatever
 * row lock it already holds, so an implementation must not make a network call
 * or sleep — the same rule `AuthHooks` documents, for the same reason.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Effect, Layer } from "effect"
 * import { Auth, Authenticators } from "effect-auth"
 *
 * const PasskeyAuthenticators = Authenticators.append({
 *   list: (userId) =>
 *     Effect.map(store.listByUserId(userId), (rows) =>
 *       rows.map((row) => ({
 *         type: "passkey",
 *         id: row.id,
 *         name: row.name,
 *         verifiedAt: row.createdAt,
 *         lastUsedAt: row.lastUsedAt,
 *         signIn: true,
 *         secondFactor: true,
 *         restricted: false
 *       }))),
 *   revokeAll: (userId) => store.deleteByUserId(userId)
 * })
 *
 * const AuthLive = Auth.layer(options).pipe(Layer.provide(PasskeyAuthenticators))
 * ```
 *
 * @since 0.1.0
 */
import { Context, type DateTime, Effect, Layer } from "effect"
import { omitUndefined } from "../internal/records.js"
import type { UserId } from "./Schema.js"
import type { PersistenceError } from "./Stores.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * One way a person can prove who they are, as the plugin that owns it describes
 * it.
 *
 * **Details**
 *
 * A projection, never the credential: nothing here is a secret, and a summary
 * is safe to serve to the person it belongs to. The three booleans are what
 * core actually branches on — the strings are for whoever is reading.
 *
 * @category models
 * @since 0.1.0
 */
export interface AuthenticatorSummary {
  /**
   * What kind of authenticator this is — `"passkey"`, `"totp"`,
   * `"recovery-code"`, `"account"`.
   *
   * A plain string, and namespaced by whoever owns it: a closed union here
   * would mean every new plugin widened a type belonging to this library.
   */
  readonly type: string
  /** Its identifier in its own plugin's table. Unique within a `type`. */
  readonly id: string
  /** Whatever the person called it, or `null` when they never named it. */
  readonly name: string | null
  /** When possession of it was proved, or `null` while it is still pending. */
  readonly verifiedAt: DateTime.Utc | null
  /** When it was last used to authenticate, or `null` if it never has been. */
  readonly lastUsedAt: DateTime.Utc | null
  /**
   * Whether it can start a session on its own.
   *
   * This is the flag `Accounts.unlink` counts: removing the last authenticator
   * that can sign in locks the person out of their own account.
   */
  readonly signIn: boolean
  /** Whether it can answer a second-factor challenge. */
  readonly secondFactor: boolean
  /**
   * Whether it is too weak to be relied on alone.
   *
   * SMS is the case this exists for: it is a real factor, and it is
   * SIM-swappable, so it may never be a person's *only* second factor and it
   * never contributes a phishing-resistant assurance level.
   */
  readonly restricted: boolean
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The authenticators the plugins installed in this deployment contribute.
 *
 * **Details**
 *
 * Every member is optional, and an absent one contributes nothing — the empty
 * set answers "no rows" and "revoked none", which is exactly what a deployment
 * with no factor plugins should answer.
 *
 * @category models
 * @since 0.1.0
 */
export interface AuthenticatorsService {
  /**
   * Every authenticator this contributor holds for a user.
   *
   * **When to use**
   *
   * Read by `Accounts.unlink` (would this leave zero ways in?), by the
   * assurance machinery (which factors could this person step up with?), and by
   * whatever aggregate view a deployment chooses to serve.
   */
  readonly list?: (userId: UserId) => Effect.Effect<ReadonlyArray<AuthenticatorSummary>, PersistenceError>

  /**
   * Removes every authenticator this contributor holds for a user, and answers
   * how many rows went.
   *
   * **Gotchas**
   *
   * Called inside the caller's transaction and under whatever row lock it
   * holds — the reclaim path takes the user row for update first, precisely so
   * that a factor cannot be enrolled between the count and the sweep. An
   * implementation that talked to the network here would be holding a database
   * transaction open across it.
   */
  readonly revokeAll?: (userId: UserId) => Effect.Effect<number, PersistenceError>
}

/**
 * The authenticators this deployment's plugins contribute, or none.
 *
 * **Details**
 *
 * A `Context.Reference` rather than a service: its default is the empty set, so
 * `Auth.layer` needs nothing provided to it and a deployment with no factor
 * plugins works unchanged. {@link layer} sets it; {@link append} adds to
 * whatever is already there.
 *
 * **Gotchas**
 *
 * It is read when the layer that consults it is *built*, not per request. A
 * deployment therefore provides its contributors underneath `Auth.layer`
 * (`Layer.provide`), and cannot swap them for one request.
 *
 * @category services
 * @since 0.1.0
 */
export const Authenticators: Context.Reference<AuthenticatorsService> = Context.Reference<AuthenticatorsService>(
  "effect-auth/domain/Authenticators/Authenticators",
  { defaultValue: () => ({}) }
)

// -----------------------------------------------------------------------------
// Composition
// -----------------------------------------------------------------------------

/**
 * Two contributors as one: `list` concatenates left to right, `revokeAll` runs
 * both and sums what they removed.
 *
 * **Details**
 *
 * This is the monoid {@link append} is written in terms of, with `{}` — the
 * {@link Authenticators} default — as its identity. Both members run
 * sequentially and in order, because `revokeAll` is called inside a
 * transaction: two sweeps racing inside one transaction is not something a
 * contributor should have to think about.
 *
 * Only the members at least one side declared survive. A combined set that
 * named both would turn "this contributor has no revoke" into "a revoke that
 * removes nothing", which is observably different to a caller that branches on
 * absence.
 *
 * @category combinators
 * @since 0.1.0
 */
export const combine = (first: AuthenticatorsService, second: AuthenticatorsService): AuthenticatorsService => {
  const firstList = first.list
  const secondList = second.list
  const list =
    firstList === undefined
      ? secondList
      : secondList === undefined
        ? firstList
        : (userId: UserId) =>
            Effect.flatMap(firstList(userId), (left) => Effect.map(secondList(userId), (right) => [...left, ...right]))

  const firstRevoke = first.revokeAll
  const secondRevoke = second.revokeAll
  const revokeAll =
    firstRevoke === undefined
      ? secondRevoke
      : secondRevoke === undefined
        ? firstRevoke
        : (userId: UserId) =>
            Effect.flatMap(firstRevoke(userId), (left) => Effect.map(secondRevoke(userId), (right) => left + right))

  return { ...omitUndefined({ list, revokeAll }) }
}

// -----------------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------------

/**
 * Every authenticator the installed contributors hold for a user, or none at
 * all when nothing is installed.
 *
 * **When to use**
 *
 * From core, which must not care whether anything was installed: the empty set
 * has no `list`, and the answer is then the empty array rather than a branch at
 * every call site.
 *
 * @category combinators
 * @since 0.1.0
 */
export const list = (
  service: AuthenticatorsService,
  userId: UserId
): Effect.Effect<ReadonlyArray<AuthenticatorSummary>, PersistenceError> =>
  service.list === undefined ? Effect.succeed([]) : service.list(userId)

/**
 * Revokes every authenticator the installed contributors hold for a user, and
 * answers how many rows went — `0` when nothing is installed.
 *
 * @category combinators
 * @since 0.1.0
 */
export const revokeAll = (service: AuthenticatorsService, userId: UserId): Effect.Effect<number, PersistenceError> =>
  service.revokeAll === undefined ? Effect.succeed(0) : service.revokeAll(userId)

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * Installs `service`, replacing whatever was there.
 *
 * **When to use**
 *
 * In an application, which knows what it installed. Provide it underneath
 * `Auth.layer` — the reference is read when the services that consult it are
 * built.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer = (service: AuthenticatorsService): Layer.Layer<never> => Layer.succeed(Authenticators)(service)

/**
 * Adds `service` after whatever is already installed, rather than replacing it.
 *
 * **When to use**
 *
 * In a plugin, which cannot know what else the deployment installed. Every
 * factor plugin appends, so a deployment that serves passkeys *and* TOTP gets
 * both in one answer without either plugin knowing about the other.
 *
 * **Details**
 *
 * This is exactly what `Layer.updateService` does, written as the layer it
 * builds from: reading {@link Authenticators} here resolves the reference's
 * default when nothing provided one, so appending to an empty deployment works
 * without the deployment having to install an empty set first.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Authenticators.append(passkeyAuthenticators)),
 *   Layer.provide(Authenticators.append(totpAuthenticators))
 * )
 * ```
 *
 * @category layers
 * @since 0.1.0
 */
export const append = (service: AuthenticatorsService): Layer.Layer<never> =>
  Layer.effect(
    Authenticators,
    Effect.map(Authenticators, (installed) => combine(installed, service))
  )
