/**
 * Signing in with a username instead of an e-mail address.
 *
 * **Details**
 *
 * The username is a *lookup key*, not a credential: the thing being proved is
 * still the `local:credential` password this library already owns, so this
 * module resolves a name to a user id and then calls
 * `Passwords.verifyPassword` and `SignIn.complete`. It never reimplements
 * `Passwords.signIn`'s lookup, which is what makes the timing defence hold on
 * every branch — including the one better-auth gets wrong, a username that
 * exists whose account has no password.
 *
 * It contributes nothing to `Authenticators`, for the same reason: a username
 * is not a way into an account, it is another spelling of one that already
 * exists. Removing it takes nothing away.
 *
 * **Gotchas — the two rules that shape this module**
 *
 * *One constant cost.* {@link UsernameService.signIn} looks the name up, reads
 * the user row for whatever id that produced — `Passwords.absentUserId` when
 * the name is unknown — and runs exactly one password verification, before any
 * branch on whether the name, the user or the credential existed. The shape of
 * the name is not checked here either: a username stored under an earlier
 * policy must still be able to sign in, and a refusal in front of the
 * verification would be a timing signal.
 *
 * *Validity on the write path.* Length, character set and the reserved list are
 * enforced in {@link UsernameService.set} — the one place a username is written
 * — rather than at the route. better-auth validated its sign-up and neither its
 * admin-create nor its update; a rule that lives on the write path cannot have
 * that shape of hole.
 *
 * @since 0.2.0
 */
import type { Redacted } from "effect"
import { Context, Effect, Layer, Option } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import type { EmailNotVerified, InvalidCredentials, PasswordHashError } from "../domain/Errors.js"
import {
  EmailNotVerified as EmailNotVerifiedError,
  InvalidCredentials as InvalidCredentialsError
} from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import { ProvisionSource } from "../domain/Hooks.js"
import { absentUserId, passwordEvidence, Passwords } from "../domain/Passwords.js"
import type { UserId } from "../domain/Schema.js"
import type { SignInResult } from "../domain/SignIn.js"
import { SignIn } from "../domain/SignIn.js"
import type { PersistenceError, SessionWithUser } from "../domain/Stores.js"
import { UserStore } from "../domain/Stores.js"
import { withDefaults } from "../internal/records.js"
import type { UsernameRefusal, UsernameTaken } from "./Api.js"
import { UsernameInvalid } from "./Api.js"
import type { UsernameRecord } from "./Store.js"
import { UsernameStore } from "./Store.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The name this plugin provisions and publishes under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const usernamePlugin = "username"

/**
 * What every sign-in this plugin completes came from.
 *
 * **Gotchas**
 *
 * `SignedIn.method` is therefore `"username"` while the evidence the session
 * records is `{ method: "password" }`. The two are different facts — which
 * *flow* ran, and which *factor* was proved — and conflating them would make a
 * username sign-in look like a second knowledge factor.
 *
 * @category constructors
 * @since 0.2.0
 */
export const usernameSource: ProvisionSource = ProvisionSource.Plugin({ plugin: usernamePlugin })

/**
 * The names this library refuses out of the box: the words an application
 * routinely mounts a page on, and every segment of this library's own API.
 *
 * **Details**
 *
 * A username that collides with a route is not a security boundary being
 * crossed — nothing here resolves a person by path — but it is a support
 * problem and a phishing surface, and an application that serves `/<username>`
 * profile pages has a real collision. The list is deliberately short and
 * deliberately *replaceable*: spread it into your own rather than hoping this
 * one grows.
 *
 * **Gotchas**
 *
 * Every entry is already normalized, and so is anything a deployment adds — see
 * {@link makeConfig}, which normalizes the list it is given so that `Admin`
 * cannot slip past a list containing `admin`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const reservedUsernames: ReadonlySet<string> = new Set([
  // The words an application mounts something on.
  "admin",
  "administrator",
  "root",
  "support",
  "help",
  "api",
  "auth",
  "login",
  "logout",
  "register",
  "settings",
  "account",
  "profile",
  "me",
  "system",
  "security",
  "billing",
  "static",
  "assets",
  "public",
  "www",
  ".well-known",
  // Every segment of this library's own API, so a profile page mounted beside
  // it cannot shadow one.
  "accounts",
  "callback",
  "change-email",
  "change-password",
  "delete-user",
  "get-access-token",
  "link-social",
  "reauthenticate",
  "refresh-token",
  "request-password-reset",
  "reset-password",
  "revoke-other-sessions",
  "revoke-session",
  "revoke-sessions",
  "send-verification-email",
  "session",
  "sessions",
  "set-password",
  "sign-in",
  "sign-out",
  "sign-up",
  "unlink-account",
  "update-user",
  "verify-email",
  // And the plugins' own prefixes.
  "anonymous",
  "email-otp",
  "magic-link",
  "one-tap",
  "passkeys",
  "phone",
  "two-factor",
  "username"
])

/**
 * The character set a username may be spelled in when `unicode` is off:
 * lowercase ASCII letters, digits, `_` and `-`.
 *
 * **Gotchas**
 *
 * Applied to the *normalized* form, which is already case-folded, so `Ada` is
 * accepted and stored with the key `ada`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const asciiUsername = /^[a-z0-9_-]+$/

/**
 * The characters a username may never contain, whatever `unicode` says.
 *
 * **Details**
 *
 * Whitespace and control characters, and the punctuation a URL, a mention or a
 * shell reads as structure. A Unicode deployment gets scripts and marks; it
 * does not get a name that changes what a path means.
 *
 * **Gotchas**
 *
 * The control range is spelled with escapes rather than with the bytes
 * themselves. Literal NUL, US and DEL in the source make `grep` call this file
 * binary, and — worse — they render as an innocent-looking space-to-at-sign
 * range, which a reviewer or a tool that normalises control characters turns
 * into a class that forbids every digit and the hyphen. The escapes say the
 * same thing and cannot be misread into a different class.
 *
 * @category constructors
 * @since 0.2.0
 */
// oxlint-disable-next-line no-control-regex -- refusing control characters in a username is the point; see the note above
export const forbiddenInUsername = /[\s\x00-\x1f\x7f@:/\\?#[\]%<>"'`&,;+=*|^$(){}!~]/

// -----------------------------------------------------------------------------
// Normalization
// -----------------------------------------------------------------------------

/**
 * The form uniqueness is decided on: PRECIS `UsernameCaseMapped`, as far as
 * this runtime can express it.
 *
 * **Details**
 *
 * RFC 8265's `UsernameCaseMapped` profile is width-map, then case-fold, then
 * normalize to **NFC**, then check. This is `trim()` (the profile forbids
 * leading, trailing and internal spaces outright, and {@link
 * forbiddenInUsername} refuses the internal ones), `normalize("NFC")` and
 * `toLowerCase()`.
 *
 * **Gotchas**
 *
 * `toLowerCase` is lowercasing, not case-folding: the two differ for a handful
 * of characters, most visibly the German sharp s, which folds to `ss` and
 * lowercases to itself. That makes this profile *narrower* than PRECIS — two
 * names PRECIS considers equal can both exist here — and narrower is the safe
 * direction: it never merges two people, it only fails to merge two spellings.
 * `String.prototype` offers no case-folding, and the ICU dependency that would
 * is not worth it for a difference only a Unicode deployment ever meets.
 *
 * NFC, not NFKC: compatibility mapping folds superscripts and ligatures onto
 * their ASCII lookalikes, which is confusable-collapsing dressed up as
 * normalization. Confusables are UTS #39's job and belong in a deployment's own
 * soft signal, never in a unique index.
 *
 * @category combinators
 * @since 0.2.0
 */
export const normalizeUsername = (username: string): string => username.trim().normalize("NFC").toLowerCase()

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a deployment may vary about usernames.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /** Shortest accepted normalized username. Defaults to `3`. */
  readonly minLength: number
  /**
   * Longest accepted normalized username. Defaults to `30`, and is bounded by
   * the column at `64` whatever this says.
   */
  readonly maxLength: number
  /**
   * Accept characters outside `[a-z0-9_-]`. Defaults to `false`.
   *
   * **Gotchas**
   *
   * Switching it on accepts any normalized name containing none of
   * {@link forbiddenInUsername} — so scripts, marks and emoji, and therefore
   * confusables: a Cyrillic lookalike of an ASCII name is a different name and
   * both can exist. UTS #39 skeletons are the answer to that, and they are
   * deliberately not a unique constraint here; a deployment that switches this
   * on should carry its own soft check.
   */
  readonly unicode: boolean
  /**
   * The names nobody may take, already normalized. Defaults to
   * {@link reservedUsernames}, which a deployment *replaces* rather than adds
   * to — spread it to keep it.
   */
  readonly reserved: ReadonlySet<string>
  /**
   * Serve `POST /auth/username/available`. Defaults to `false`.
   *
   * **Gotchas**
   *
   * A username is public by design, so the oracle is acceptable — but it is an
   * oracle, and one an unauthenticated caller can drive, so switching it on is
   * a decision rather than a default. It has a rate-limit bucket of its own;
   * the endpoint answers `404` while this is off.
   */
  readonly availability: boolean
}

/**
 * {@link Config}, with every field optional and the reserved list accepted as
 * anything iterable.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly minLength?: number | undefined
  readonly maxLength?: number | undefined
  readonly unicode?: boolean | undefined
  readonly reserved?: Iterable<string> | undefined
  readonly availability?: boolean | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Config = {
  minLength: 3,
  maxLength: 30,
  unicode: false,
  reserved: reservedUsernames,
  availability: false
}

/**
 * Resolves {@link Options} against {@link defaults}, normalizing the reserved
 * list on the way.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options?: Options): Config =>
  withDefaults(defaults, {
    minLength: options?.minLength,
    maxLength: options?.maxLength,
    unicode: options?.unicode,
    availability: options?.availability,
    // Normalized here rather than at every check: a deployment that wrote
    // `Admin` means `admin`, and a list compared against a normalized name has
    // to be normalized itself or the entry silently does nothing.
    reserved: options?.reserved === undefined ? undefined : new Set(Array.from(options.reserved, normalizeUsername))
  })

// -----------------------------------------------------------------------------
// Validity
// -----------------------------------------------------------------------------

/**
 * How many *characters* a string is, counted in code points.
 *
 * `String.prototype.length` counts UTF-16 units, so an astral character would
 * cost two against a length bound and a Unicode deployment's rules would be
 * silently stricter than they read.
 */
const codePoints = (value: string): number => Array.from(value).length

/**
 * Why this deployment refuses a username, or `None` when it does not.
 *
 * **Details**
 *
 * Checked against the *normalized* form: length is counted in code points
 * rather than UTF-16 units, so a name of two astral characters is two
 * characters and not four; the character set is applied to the case-folded
 * name; and the reserved list is compared against the key.
 *
 * @category combinators
 * @since 0.2.0
 */
export const refusalFor = (username: string, config: Config): Option.Option<UsernameRefusal> => {
  const key = normalizeUsername(username)
  const length = codePoints(key)
  if (length < config.minLength) return Option.some("too_short")
  if (length > config.maxLength) return Option.some("too_long")
  if (forbiddenInUsername.test(key)) return Option.some("charset")
  if (!config.unicode && !asciiUsername.test(key)) return Option.some("charset")
  if (config.reserved.has(key)) return Option.some("reserved")
  return Option.none()
}

/**
 * {@link refusalFor} as a guard.
 *
 * @category combinators
 * @since 0.2.0
 */
export const checkUsername = (username: string, config: Config): Effect.Effect<void, UsernameInvalid> =>
  Option.match(refusalFor(username, config), {
    onNone: () => Effect.void,
    onSome: (reason) => UsernameInvalid.make({ reason })
  })

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What {@link UsernameService.signIn} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInOptions {
  readonly username: string
  readonly password: Redacted.Redacted
  readonly rememberMe?: boolean | undefined
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  /**
   * The session the request already carried, handed to `beforeSessionCreate` —
   * the seam an "adopt this anonymous visitor" policy hangs on.
   */
  readonly current?: SessionWithUser | undefined
}

/**
 * What {@link UsernameService.set} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface SetOptions {
  readonly userId: UserId
  readonly username: string
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Username} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface UsernameService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Verifies a password against the account a username names, and establishes a
   * session through the one choke point every sign-in in this library goes
   * through.
   *
   * **Details**
   *
   * Exactly one hash verification runs on every path — an unknown username, a
   * known one whose account has no password credential, and a wrong password
   * are one answer at one cost. The e-mail gate and the deployment's own
   * `beforeSessionCreate` are consulted after it, exactly as `Passwords.signIn`
   * consults them, so a refusal is only ever seen by somebody who presented the
   * right password.
   */
  readonly signIn: (
    options: SignInOptions
  ) => Effect.Effect<
    SignInResult,
    InvalidCredentials | EmailNotVerified | PasswordHashError | PolicyRefused | PersistenceError
  >

  /**
   * Gives a user this username, releasing whatever they held.
   *
   * The rules are enforced here — this is the write path — and uniqueness is
   * the index's, so two callers racing for one name produce exactly one winner
   * and one `UsernameTaken`.
   */
  readonly set: (
    options: SetOptions
  ) => Effect.Effect<UsernameRecord, UsernameInvalid | UsernameTaken | PersistenceError>

  /** The row a username names, if any. */
  readonly find: (username: string) => Effect.Effect<Option.Option<UsernameRecord>, PersistenceError>

  /** The username a person holds, if any. */
  readonly forUser: (userId: UserId) => Effect.Effect<Option.Option<UsernameRecord>, PersistenceError>

  /**
   * Whether a username is free *and* acceptable.
   *
   * Fails `UsernameInvalid` for a name this deployment would refuse, so
   * "nobody has it and you still cannot have it" is never reported as
   * available.
   */
  readonly available: (username: string) => Effect.Effect<boolean, UsernameInvalid | PersistenceError>

  /** Releases whatever username a person holds. Answers whether one was released. */
  readonly clear: (userId: UserId) => Effect.Effect<boolean, PersistenceError>
}

/**
 * Signing in with a username. See {@link UsernameService}.
 *
 * @category services
 * @since 0.2.0
 */
export class Username extends Context.Service<Username, UsernameService>()("effect-auth/username/Username") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * **Gotchas**
 *
 * Everything but {@link UsernameStore} is published by `Auth.layer`, and the
 * store is provided by `Store.layer` over the deployment's own `SqlClient`.
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements = UsernameStore | AuthConfig | Passwords | SignIn | UserStore

/**
 * Builds the {@link Username} implementation.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (options?: Options) => Effect.Effect<UsernameService, never, Requirements> = Effect.fnUntraced(
  function* (options?: Options) {
    const settings = makeConfig(options)
    const store = yield* UsernameStore
    const config = yield* AuthConfig
    const passwords = yield* Passwords
    const { complete: completeSignIn } = yield* SignIn
    const users = yield* UserStore

    const signIn = Effect.fnUntraced(
      function* (request: SignInOptions) {
        const key = normalizeUsername(request.username)
        const held = yield* store.findByKey(key)
        // An id that cannot exist when the name is unknown, so the two reads
        // below run on both paths. A branch here would make a known username
        // cost two round trips more than an unknown one — the same enumeration
        // channel an unbalanced hash verify opens, and it costs two indexed
        // misses to close.
        const userId = Option.isSome(held) ? held.value.userId : absentUserId
        const found = yield* users.findById(userId)
        // The one constant-cost verification, run before anything branches on
        // whether the name, the user or the credential existed. `verifyPassword`
        // checks against the dummy hash when there is no credential, so all
        // three paths cost the same.
        const matches = yield* passwords.verifyPassword(userId, request.password)

        if (Option.isNone(found) || !matches) {
          return yield* InvalidCredentialsError.make()
        }
        const user = found.value

        if (config.emailPassword.requireEmailVerification && !user.emailVerified) {
          return yield* EmailNotVerifiedError.make()
        }

        // The choke point. The evidence is the password's, not the username's:
        // what was proved is knowledge of a secret, and the name it was looked
        // up by is not a factor.
        return yield* completeSignIn({
          user,
          source: usernameSource,
          evidence: [passwordEvidence],
          current: Option.fromNullishOr(request.current),
          request: {
            ipAddress: request.ipAddress ?? null,
            userAgent: request.userAgent ?? null,
            rememberMe: request.rememberMe
          }
        })
      },
      (effect) => Effect.withSpan(effect, "Username.signIn")
    )

    const set = Effect.fnUntraced(function* (request: SetOptions) {
      // The write path, and the only place these rules are applied.
      yield* checkUsername(request.username, settings)
      // The display form keeps the caller's case and loses nothing else; the
      // key is what uniqueness is decided on.
      const username = request.username.trim().normalize("NFC")
      return yield* store.claim({
        usernameKey: normalizeUsername(username),
        username,
        userId: request.userId
      })
    })

    const available = Effect.fnUntraced(function* (username: string) {
      yield* checkUsername(username, settings)
      const held = yield* store.findByKey(normalizeUsername(username))
      return Option.isNone(held)
    })

    return Username.of({
      config: settings,
      signIn,
      set,
      find: (username) => store.findByKey(normalizeUsername(username)),
      forUser: (userId) => store.findByUserId(userId),
      available,
      clear: (userId) => store.release(userId)
    })
  }
)

/**
 * Provides {@link Username}.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Migrations, Username, UsernameMigrations, UsernameStore } from "effect-auth"
 *
 * const UsernameLive = Username.layer({ minLength: 2 }).pipe(
 *   Layer.provide(layerUsernameStore),
 *   Layer.provide(UsernameMigrations.layer.pipe(Layer.provide(Migrations.layer))),
 *   Layer.provideMerge(AuthLive)
 * )
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (options?: Options): Layer.Layer<Username, never, Requirements> =>
  Layer.effect(Username, make(options))
