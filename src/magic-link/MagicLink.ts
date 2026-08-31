/**
 * Passwordless sign-in by a single-use link sent to an e-mail address.
 *
 * `MagicLink` owns three operations: minting a link and handing it to a mailer
 * ({@link MagicLinkService.request}), spending one ({@link MagicLinkService.verify}),
 * and spending one on behalf of a browser that must be redirected whatever
 * happens ({@link MagicLinkService.complete}).
 *
 * **Details**
 *
 * The plugin owns no table. A link is an ordinary `Verifications` token under the
 * purpose {@link magicLinkPurpose}, whose subject is the normalized address and
 * whose payload carries what the request asked for — the display name for an
 * account that does not exist yet, the three redirect targets, and whether the
 * session it establishes should be remembered. Only the token's SHA-256 digest is
 * stored, and claiming one is the same atomic `DELETE ... RETURNING` every other
 * e-mail flow in this library uses.
 *
 * **Gotchas — the two rules that shape this module**
 *
 * *No user enumeration.* {@link MagicLinkService.request} answers the same for an
 * address with an account and one without: the lookup runs either way (the mailer
 * is told which it was, so a message to a stranger can read differently), the
 * same token is minted, and a delivery failure is logged and swallowed. The one
 * asymmetry is a deployment with `disableSignUp` on, where an unknown address
 * gets no token and no message — there is nothing a link to it could ever do —
 * and still the same `200`.
 *
 * *An unproven account is not a credential.* Somebody can register an address
 * they do not own, wait, and hope its real owner signs in with a magic link
 * later; they would then share the account. So when a link proves control of an
 * address whose account is *unverified*, that account's sign-in methods and
 * sessions are destroyed in one transaction and the address is marked verified —
 * see {@link Options.revokeUnprovenAccounts}, which is on by default.
 *
 * @since 1.0.0
 */
import { Context, Duration, Effect, Layer, Option, Redacted, Schema } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import { tokenUrl } from "../config/AuthEmails.js"
import type { EmailDeliveryError } from "../domain/Errors.js"
import { InvalidToken } from "../domain/Errors.js"
import { AuthEvents, publishSafely } from "../domain/Events.js"
import type { Session, User } from "../domain/Schema.js"
import { normalizeEmail, User as UserModel } from "../domain/Schema.js"
import { Sessions } from "../domain/Sessions.js"
import type { PersistenceError } from "../domain/Stores.js"
import { AccountStore, isUniqueViolation, SessionStore, UserStore, WithAuthTransaction } from "../domain/Stores.js"
import type { TokenPurpose } from "../domain/Verifications.js"
import { purpose, Verifications } from "../domain/Verifications.js"
import { resolveUrl, validateUrl, withErrorCode } from "../http/OriginCheck.js"
import { annotateAuthLogs, insertRow } from "../internal/effects.js"
import { withDefaults } from "../internal/records.js"
import { magicLinkPrefix, SignUpDisabled } from "./Api.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The `method` every event this plugin publishes carries — the counterpart of
 * `passwordMethod` and `oauthMethod`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const magicLinkMethod = "magic-link"

/**
 * The name this plugin publishes `PluginEvent`s under.
 *
 * **Details**
 *
 * One event: `"UnprovenAccountRevoked"`, carrying how many sign-in methods and
 * sessions the takeover defence destroyed. The three things that happened to the
 * *user* — `AccountUnlinked`, `SessionRevoked`, `EmailVerified` — are published
 * as themselves, because a subscriber that acts on those should not have to know
 * this plugin exists.
 *
 * @category constructors
 * @since 1.0.0
 */
export const magicLinkPlugin = "magic-link"

// -----------------------------------------------------------------------------
// Tokens
// -----------------------------------------------------------------------------

/**
 * What travels with a magic link.
 *
 * **Details**
 *
 * Server-side state in the `verifications` table, never a claim in the URL. The
 * link carries the token and nothing else, so a recipient cannot edit their own
 * landing page — or their own display name — into it.
 *
 * @category models
 * @since 1.0.0
 */
export const MagicLinkPayload = Schema.Struct({
  /** The display name to give the account this link may create. */
  name: Schema.NullOr(Schema.String),
  /** Where to land after a successful sign-in. Already validated when it was stored. */
  callbackURL: Schema.NullOr(Schema.String),
  /** Where to land instead when this link created the account. */
  newUserCallbackURL: Schema.NullOr(Schema.String),
  /** Where to land when following the link fails. */
  errorCallbackURL: Schema.NullOr(Schema.String),
  /** Whether the session this link establishes is a remembered one. */
  rememberMe: Schema.Boolean
})

/**
 * The type of a {@link MagicLinkPayload}.
 *
 * @category models
 * @since 1.0.0
 */
export type MagicLinkPayload = typeof MagicLinkPayload.Type

/**
 * The purpose magic link tokens are minted under. Its subject is the normalized
 * e-mail address the link was sent to.
 *
 * @category constructors
 * @since 1.0.0
 */
export const magicLinkPurpose: TokenPurpose<MagicLinkPayload> = purpose("magic-link", MagicLinkPayload)

// -----------------------------------------------------------------------------
// The mailer seam
// -----------------------------------------------------------------------------

/**
 * One magic link message, as the application is asked to deliver it.
 *
 * **Gotchas**
 *
 * `user` is `null` when the address has no account — a plugin's mail is not
 * always about somebody the library knows. Both messages must go out, and should
 * look alike enough that a recipient cannot use them to decide whether an address
 * is registered; the difference worth making is what the *link* leads to, which
 * the flow already handles.
 *
 * @category models
 * @since 1.0.0
 */
export interface MagicLinkEmail {
  /** The address the message goes to, normalized. */
  readonly email: string
  /** The account it belongs to, or `null` when the address has none. */
  readonly user: User | null
  /** The raw single-use token, for a client that would rather build its own link. */
  readonly token: Redacted.Redacted<string>
  /** The link itself: `{baseUrl}{path}?token=…`. */
  readonly url: Redacted.Redacted<string>
}

/**
 * The {@link MagicLinkEmails} service definition — what an application implements
 * to deliver magic links.
 *
 * **Gotchas**
 *
 * A service of the plugin's own rather than a method on `AuthEmails`: a plugin
 * cannot widen a library interface every other deployment implements, and this
 * message's shape genuinely differs (there may be no user). A deployment that
 * forgets it gets a compile error from {@link layer}'s requirements, which is the
 * point.
 *
 * @category models
 * @since 1.0.0
 */
export interface MagicLinkEmailsService {
  readonly sendMagicLink: (email: MagicLinkEmail) => Effect.Effect<void, EmailDeliveryError>
}

/**
 * Delivers magic links. See {@link MagicLinkEmailsService}.
 *
 * @category services
 * @since 1.0.0
 */
export class MagicLinkEmails extends Context.Service<MagicLinkEmails, MagicLinkEmailsService>()(
  "effect-auth/magic-link/MagicLinkEmails"
) {}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a deployment may vary about the magic link flow.
 *
 * @category models
 * @since 1.0.0
 */
export interface Config {
  /**
   * How long a link may be followed for. Defaults to five minutes.
   *
   * **Gotchas**
   *
   * Short on purpose: the link is a bearer credential sitting in a mailbox, and
   * the person who asked for it is usually looking at their inbox already.
   */
  readonly ttl: Duration.Duration
  /**
   * Refuse to create an account for an address that has none. Defaults to
   * `false` — a magic link is the classic sign-up-and-sign-in-in-one.
   */
  readonly disableSignUp: boolean
  /**
   * The path the e-mailed link points at, resolved against `baseUrl`. Defaults
   * to `/auth/magic-link/verify`, which is where {@link MagicLinkApiGroup} serves
   * the endpoint.
   *
   * **Gotchas**
   *
   * Change it only to point at a page of your own that forwards the `token` to
   * the endpoint — a deployment serving the API somewhere else changes
   * `AuthConfig.basePath` and this together.
   */
  readonly path: string
  /**
   * Destroy the sign-in methods and sessions of an *unverified* account when a
   * magic link proves control of its address. Defaults to `true`.
   *
   * **Gotchas**
   *
   * This is the pre-registration takeover defence, and switching it off is a
   * real decision: an address whose account was created by somebody who never
   * proved they owned it keeps whatever they set up — a password they know, an
   * OAuth identity they control — and they keep it *alongside* the real owner,
   * who has just signed in. Leave it on unless something else in the deployment
   * guarantees no account is ever created unverified.
   */
  readonly revokeUnprovenAccounts: boolean
}

/**
 * {@link Config}, with every field optional.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options {
  readonly ttl?: Duration.Duration | undefined
  readonly disableSignUp?: boolean | undefined
  readonly path?: string | undefined
  readonly revokeUnprovenAccounts?: boolean | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaults: Config = {
  ttl: Duration.minutes(5),
  disableSignUp: false,
  path: `${magicLinkPrefix}/verify`,
  revokeUnprovenAccounts: true
}

/**
 * Resolves {@link Options} against {@link defaults}.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeConfig = (options?: Options): Config => withDefaults(defaults, options)

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What {@link MagicLinkService.request} takes.
 *
 * @category models
 * @since 1.0.0
 */
export interface RequestOptions {
  /** The address to send the link to. Normalized here, not by the caller. */
  readonly email: string
  /** The display name to give an account this link ends up creating. */
  readonly name?: string | undefined
  /** Where to land after a successful sign-in. Validated here as well as by the caller. */
  readonly callbackURL?: string | undefined
  /** Where to land instead when the link created the account. */
  readonly newUserCallbackURL?: string | undefined
  /** Where to land when following the link fails. */
  readonly errorCallbackURL?: string | undefined
  /** When explicitly `false`, the session the link establishes expires in a day. */
  readonly rememberMe?: boolean | undefined
}

/**
 * What {@link MagicLinkService.verify} and {@link MagicLinkService.complete} take.
 *
 * @category models
 * @since 1.0.0
 */
export interface VerifyOptions {
  /** The token out of the link. */
  readonly token: Redacted.Redacted<string>
  /** Recorded on the session row, so a person can recognise their own devices. */
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
}

/**
 * A spent magic link: who it signed in, and where to send them.
 *
 * @category models
 * @since 1.0.0
 */
export interface VerifyResult {
  readonly user: User
  readonly session: Session
  /**
   * The session's raw token — the only copy that will ever exist. Put it in a
   * `Set-Cookie` and drop it.
   */
  readonly token: Redacted.Redacted<string>
  /** What the request asked for, carried through the token's payload. */
  readonly rememberMe: boolean
  /** `true` when spending this link is what created the account. */
  readonly userCreated: boolean
  /** The validated URL the browser is to be sent to. */
  readonly redirectTo: string
}

/**
 * Everything spending a link can fail with, apart from persistence.
 *
 * @category models
 * @since 1.0.0
 */
export type VerifyError = InvalidToken | SignUpDisabled

/**
 * The outcome of {@link MagicLinkService.complete}: always somewhere to send the
 * browser.
 *
 * @category models
 * @since 1.0.0
 */
export type VerifyOutcome =
  | ({ readonly _tag: "Success" } & VerifyResult)
  | {
    readonly _tag: "Failure"
    readonly error: VerifyError
    /** The validated error URL, carrying `?error=<code>`. */
    readonly redirectTo: string
    /** The safe, closed-set error code that was appended. */
    readonly code: string
  }

/**
 * The safe error code a failed link reports in the redirect's query string.
 *
 * **Details**
 *
 * A closed set of two, chosen by this library. Nothing a caller supplied is ever
 * echoed, and neither code says whether the address has an account:
 * `invalid_token` covers a link that was never minted, one already spent and one
 * that expired alike.
 *
 * @category combinators
 * @since 1.0.0
 */
export const errorCode = (error: VerifyError): string =>
  error._tag === "SignUpDisabled" ? "sign_up_disabled" : "invalid_token"

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link MagicLink} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface MagicLinkService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Mints a link and hands it to the {@link MagicLinkEmails} seam.
   *
   * **Gotchas**
   *
   * Succeeds whether or not the address belongs to a user, and swallows delivery
   * failures after logging them — see the module header. What is *not* identical
   * is the latency, exactly as in `Passwords.requestReset`: a mailer that
   * enqueues and returns is what closes the residual signal.
   */
  readonly request: (options: RequestOptions) => Effect.Effect<void, PersistenceError>

  /**
   * Spends a link: claims the token, retires its siblings, resolves or creates
   * the account, and establishes a session.
   *
   * **Details**
   *
   * Every failure is one of two answers. `InvalidToken` covers a token that was
   * never minted, one already spent, and one that expired — the claim is a single
   * conditional delete, so there is nothing left to tell them apart with.
   * `SignUpDisabled` is the deployment refusing to create an account.
   */
  readonly verify: (
    options: VerifyOptions
  ) => Effect.Effect<VerifyResult, VerifyError | PersistenceError>

  /**
   * {@link MagicLinkService.verify}, resolved into somewhere to send a browser.
   *
   * **When to use**
   *
   * From the `GET` endpoint. The person arrived by a top-level navigation out of
   * their mailbox and has to land on a page, so a failure becomes a redirect to
   * the link's own `errorCallbackURL` carrying `?error=<code>` — see
   * {@link errorCode} — rather than an error body.
   */
  readonly complete: (options: VerifyOptions) => Effect.Effect<VerifyOutcome, PersistenceError>
}

/**
 * Passwordless sign-in by e-mailed link. See {@link MagicLinkService}.
 *
 * @category services
 * @since 1.0.0
 */
export class MagicLink extends Context.Service<MagicLink, MagicLinkService>()("effect-auth/MagicLink") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * **Gotchas**
 *
 * Every one of these but {@link MagicLinkEmails} is published by `Auth.layer`, so
 * a consumer composes this plugin over their deployment and supplies one mailer:
 *
 * ```ts skip-type-checking
 * const MagicLinkLive = MagicLink.layer({ ttl }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyMagicLinkMailer)
 * )
 * ```
 *
 * @category models
 * @since 1.0.0
 */
export type Requirements =
  | MagicLinkEmails
  | AuthConfig
  | AuthEvents
  | Verifications
  | Sessions
  | UserStore
  | AccountStore
  | SessionStore
  | WithAuthTransaction

/**
 * Builds the {@link MagicLink} implementation.
 *
 * **Gotchas**
 *
 * Every service is resolved here, when the layer is built, so that no method
 * carries a request-time requirement — the same shape `Passwords.make` has, and
 * for the same reason.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: (options?: Options) => Effect.Effect<MagicLinkService, never, Requirements> = Effect.fnUntraced(
  function*(options?: Options) {
    const settings = makeConfig(options)
    const config = yield* AuthConfig
    const emails = yield* MagicLinkEmails
    const events = yield* AuthEvents
    const verifications = yield* Verifications
    const sessions = yield* Sessions
    const users = yield* UserStore
    const accounts = yield* AccountStore
    const sessionStore = yield* SessionStore
    const transaction = yield* WithAuthTransaction

    /**
     * A caller-supplied redirect target, or `null` when it did not survive
     * `trustedOrigins`.
     *
     * Dropped rather than refused, and validated *here* as well as at the HTTP
     * layer: what goes in ends up in a link sent to somebody's mailbox, and an
     * open redirect there is a phishing page with this deployment's name on it.
     */
    const target = (candidate: string | undefined): string | null =>
      Option.getOrNull(validateUrl(config, candidate))

    const request = Effect.fnUntraced(function*(options: RequestOptions) {
      const email = normalizeEmail(options.email)
      // The lookup runs on both paths. Its result decides what the mailer is
      // told, never what the caller observes.
      const found = yield* users.findByEmail(email)

      if (settings.disableSignUp && Option.isNone(found)) {
        // There is nothing a link to this address could do: spending it would
        // answer `SignUpDisabled`. No row is written and no message is sent — and
        // the endpoint above still answers exactly as it does for a known
        // address.
        return
      }

      const issued = yield* verifications.issue({
        purpose: magicLinkPurpose,
        subject: email,
        ttl: settings.ttl,
        payload: {
          name: options.name ?? null,
          callbackURL: target(options.callbackURL),
          newUserCallbackURL: target(options.newUserCallbackURL),
          errorCallbackURL: target(options.errorCallbackURL),
          rememberMe: options.rememberMe !== false
        }
      })

      const url = tokenUrl(config, settings.path, issued.token)
      // Delivery is the application's responsibility and its failure must not
      // change what the caller observes; it is logged and dropped.
      yield* annotateAuthLogs(Effect.ignore(
        emails.sendMagicLink({ email, user: Option.getOrNull(found), token: issued.token, url }),
        { log: "Warn", message: "magic link e-mail delivery failed" }
      ))
    })

    /**
     * Provisions the account a link is about.
     *
     * **Gotchas**
     *
     * The row is built from the base user fields alone and stored through the
     * base-typed `UserStore`, exactly as the OAuth flow provisions one. A
     * deployment's own columns are filled in by the store from the model's
     * declared defaults — which the provisionability rule on `makeUserModel`
     * guarantees is always possible — so this plugin never has to know what they
     * are.
     */
    const create = Effect.fnUntraced(function*(email: string, name: string | null) {
      const row = yield* insertRow(UserModel.insert, {
        name: name ?? email,
        email,
        // The token was delivered to this address and came back: that is the
        // whole of what verification ever proves.
        emailVerified: true,
        image: null
      })
      const user = yield* users.create(row)
      yield* publishSafely(events, {
        _tag: "UserCreated",
        userId: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
        method: magicLinkMethod
      })
      return user
    })

    /**
     * Destroys an unverified account's sign-in methods and sessions, and marks
     * the address verified. See the module header for why.
     */
    const reclaim = Effect.fnUntraced(function*(user: User) {
      const outcome = yield* transaction.run(Effect.gen(function*() {
        // Locked for the length of the transaction: the set of a user's sign-in
        // methods is being destroyed, and a concurrent link must not add one
        // between the read and the delete.
        const linked = yield* accounts.listByUserIdForUpdate(user.id)
        yield* accounts.deleteByUserId(user.id)
        const revoked = yield* sessionStore.deleteByUserId(user.id)
        const updated = yield* users.update(user.id, { emailVerified: true })
        return { linked, revoked, updated }
      }))

      for (const account of outcome.linked) {
        yield* publishSafely(events, {
          _tag: "AccountUnlinked",
          userId: user.id,
          accountId: account.id,
          providerId: account.providerId,
          issuer: account.issuer
        })
      }
      yield* publishSafely(events, {
        _tag: "SessionRevoked",
        userId: user.id,
        sessionId: null,
        scope: "all",
        count: outcome.revoked
      })
      yield* publishSafely(events, {
        _tag: "PluginEvent",
        plugin: magicLinkPlugin,
        event: "UnprovenAccountRevoked",
        userId: user.id,
        data: { accounts: outcome.linked.length, sessions: outcome.revoked }
      })
      return outcome.updated
    })

    /**
     * The account a link proved control of, as it stands once that proof has been
     * applied — `None` when the row went between the claim and the write.
     *
     * **Details**
     *
     * A verified account is left exactly as it was: the link signed its owner in
     * and said nothing new about them. An unverified one ends up verified either
     * way, because the token *was* delivered to the address and came back; what
     * {@link Options.revokeUnprovenAccounts} decides is whether whoever set that
     * account up keeps their way into it.
     */
    const settle = Effect.fnUntraced(function*(user: User) {
      if (user.emailVerified) return Option.some(user)
      const updated = settings.revokeUnprovenAccounts
        ? yield* reclaim(user)
        : yield* users.update(user.id, { emailVerified: true })
      if (Option.isNone(updated)) return Option.none<User>()
      yield* publishSafely(events, {
        _tag: "EmailVerified",
        userId: updated.value.id,
        email: updated.value.email
      })
      return Option.some(updated.value)
    })

    /**
     * Claims the token and retires whatever else was outstanding for the same
     * address.
     *
     * Asking for two links and following the older one must not leave the newer
     * one live: somebody with a few minutes of mailbox access would otherwise keep
     * a working key.
     */
    const claim = Effect.fnUntraced(function*(token: Redacted.Redacted<string>) {
      const claimed = yield* verifications.claim(magicLinkPurpose, token)
      yield* verifications.retire(magicLinkPurpose, claimed.subject)
      return claimed
    })

    const resolve = Effect.fnUntraced(function*(email: string, payload: MagicLinkPayload) {
      const found = yield* users.findByEmail(email)
      if (Option.isNone(found)) {
        if (settings.disableSignUp) {
          return yield* Effect.fail(new SignUpDisabled())
        }
        return { user: yield* create(email, payload.name), userCreated: true }
      }
      const settled = yield* settle(found.value)
      if (Option.isNone(settled)) {
        // The row went between the two reads — a concurrent deletion. The token
        // is spent and there is nobody to sign in.
        return yield* Effect.fail(new InvalidToken())
      }
      return { user: settled.value, userCreated: false }
    })

    const finish = Effect.fnUntraced(function*(
      email: string,
      payload: MagicLinkPayload,
      options: VerifyOptions
    ) {
      const { user, userCreated } = yield* resolve(email, payload)

      const created = yield* sessions.create({
        userId: user.id,
        ipAddress: options.ipAddress ?? null,
        userAgent: options.userAgent ?? null,
        rememberMe: payload.rememberMe
      })
      yield* publishSafely(events, {
        _tag: "SignedIn",
        userId: user.id,
        sessionId: created.session.id,
        method: magicLinkMethod
      })

      return {
        user,
        session: created.session,
        token: created.token,
        rememberMe: payload.rememberMe,
        userCreated,
        redirectTo: resolveUrl(
          config,
          userCreated ? payload.newUserCallbackURL ?? payload.callbackURL : payload.callbackURL
        )
      } satisfies VerifyResult
    })

    const verify = Effect.fnUntraced(
      function*(options: VerifyOptions) {
        const claimed = yield* claim(options.token)
        // A user provisioned here loses a race only to a concurrent sign-up for
        // the same address, which the unique index settles. Running the
        // resolution again finds the row the winner wrote and signs in as it;
        // nothing is published before the write that failed, so no event can be
        // duplicated.
        return yield* Effect.retry(
          finish(normalizeEmail(claimed.subject), claimed.payload, options),
          { while: (error) => error._tag === "PersistenceError" && isUniqueViolation(error), times: 1 }
        )
      },
      (effect) => Effect.withSpan(effect, "MagicLink.verify")
    )

    const failure = (error: VerifyError, errorURL: string | null): VerifyOutcome => {
      const code = errorCode(error)
      return {
        _tag: "Failure",
        error,
        redirectTo: withErrorCode(resolveUrl(config, errorURL), code),
        code
      }
    }

    const complete = Effect.fnUntraced(
      function*(options: VerifyOptions) {
        const claimed = yield* Effect.result(claim(options.token))
        if (claimed._tag === "Failure") {
          if (claimed.failure._tag === "PersistenceError") return yield* Effect.fail(claimed.failure)
          // No payload was ever read, so there is no error URL to honour: the
          // token is not one this deployment minted.
          return failure(claimed.failure, null)
        }
        const { payload, subject } = claimed.success
        const finished = yield* Effect.result(
          Effect.retry(finish(normalizeEmail(subject), payload, options), {
            while: (error) => error._tag === "PersistenceError" && isUniqueViolation(error),
            times: 1
          })
        )
        if (finished._tag === "Failure") {
          if (finished.failure._tag === "PersistenceError") return yield* Effect.fail(finished.failure)
          return failure(finished.failure, payload.errorCallbackURL)
        }
        return { _tag: "Success", ...finished.success } satisfies VerifyOutcome
      },
      (effect) => Effect.withSpan(effect, "MagicLink.complete")
    )

    return MagicLink.of({ config: settings, request, verify, complete })
  }
)

/**
 * Provides {@link MagicLink}.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { MagicLink } from "effect-auth"
 *
 * const MagicLinkLive = MagicLink.layer({ disableSignUp: true }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyMagicLinkMailer)
 * )
 * ```
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = (options?: Options): Layer.Layer<MagicLink, never, Requirements> =>
  Layer.effect(MagicLink, make(options))
