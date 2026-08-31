/**
 * The session cookie cache: a signed snapshot of the session and its user,
 * carried in a second cookie, that lets an authenticated request be served
 * without reading the session store.
 *
 * **Details**
 *
 * The cookie's value is `base64url(json) + "." + base64url(HMAC-SHA-256(secret,
 * json))`. The JSON half carries the snapshot's own expiry, the digest of the
 * session token it was minted for, a version string, and the same two objects
 * `GET /session` already answers with — `Session.json` and the model's public
 * user projection. `SessionCache.read` verifies the tag, checks that digest
 * against the credential actually presented, checks the expiry and the version,
 * and only then hands the snapshot back.
 *
 * The snapshot expires at `min(now + cookieCache.maxAge, refreshDueAt(session),
 * session.expiresAt)`. Clamping to the refresh instant is what keeps the rolling
 * refresh honest: the first request after a session becomes refresh-due misses
 * the cache, reaches `Sessions.verify`, rolls the expiry forward and writes a
 * fresh snapshot. Nothing here ever re-signs a session or extends one.
 *
 * **Gotchas — the threat model, in full**
 *
 * *Integrity, not confidentiality.* The payload is signed, not encrypted:
 * anybody holding the cookie can read it. It contains exactly what the endpoint
 * would have answered with, so that is not a leak — but it is why a field
 * declared `UserField.hidden` is absent from the snapshot, and why nothing
 * secret may ever be added to it.
 *
 * *Revocation lag.* This is the real cost. A session revoked in one browser
 * keeps working in another for up to `cookieCache.maxAge`, because a valid
 * snapshot means no database read at all. The same holds for a user row that
 * changed. Endpoints whose decision depends on the *current* state annotate
 * `AuthoritativeSession`, which bypasses the cache in both directions; a
 * deployment that cannot accept the lag anywhere leaves the cache off, which is
 * the default.
 *
 * *A hidden field is not carried.* The snapshot is the model's `json`
 * projection, so a `UserField.hidden` column is not in it; a cached read fills
 * it with the field's declared default rather than its stored value. An endpoint
 * that reads one must be annotated `AuthoritativeSession`.
 *
 * *Binding.* A snapshot is useless without the session token it was minted for:
 * `tokenHash` is inside the signed payload and is compared with the digest of
 * the presented credential, so a stolen cache cookie cannot be replayed beside
 * somebody else's session, and swapping the two cookies is a miss rather than a
 * confusion.
 *
 * *Bearer clients gain nothing.* The cache is written and read on the cookie
 * transports only — a bearer client has no cookie jar, and reading a cookie
 * alongside a bearer credential would let a cookie decide what a header-only
 * request sees. `write` enforces that itself, by refusing to write where the
 * request presented no session cookie: the middleware knows which transport
 * authenticated a request, but a handler rewriting the snapshot after an update
 * does not, and a browser SPA holding a bearer token would otherwise be left
 * with a signed profile snapshot in its jar that nothing ever clears.
 *
 * *It is not a defence.* Rotating `AuthConfig.secret` invalidates every
 * outstanding snapshot — an undecodable cookie is a miss, never a `401` — but
 * that is mass *cache* invalidation, not sign-out: the session tokens themselves
 * are untouched.
 *
 * @since 1.0.0
 */
import { Context, DateTime, Duration, Effect, Encoding, Layer, Option, Redacted, Result, Schema } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Hmac } from "../crypto/Hmac.js"
import { Token } from "../crypto/Token.js"
import type { Session, User, UserFields, UserModel, UserOf, UserRow } from "../domain/Schema.js"
import { baseUserModel, Session as SessionModel } from "../domain/Schema.js"
import { refreshDueAt } from "../domain/Sessions.js"
import type { SessionWithUser } from "../domain/Stores.js"
import { encodeUtf8 } from "../internal/crypto.js"
import { annotateAuthLogs } from "../internal/effects.js"
import {
  expiredSessionCookieOptions,
  sessionCacheCookieName,
  sessionCacheCookieSecurity,
  sessionCookieName,
  sessionCookieOptions
} from "./Cookies.js"

// -----------------------------------------------------------------------------
// Format
// -----------------------------------------------------------------------------

/**
 * The separator between the payload and its tag. Neither half can contain it:
 * both are base64url.
 *
 * @category constructors
 * @since 1.0.0
 */
export const cacheCookieSeparator = "."

/**
 * The largest cookie value this module will write.
 *
 * **Details**
 *
 * Browsers guarantee only about 4KB per cookie, and a snapshot that exceeds it
 * is silently dropped by the browser — which would look like a cache that never
 * hits rather than like a configuration mistake. A deployment whose user model
 * is too large for the budget is better off with no cache, so a snapshot over
 * this size is skipped with a `Debug` log and the request is served from the
 * database as it would have been anyway.
 *
 * @category constructors
 * @since 1.0.0
 */
export const maxCookieBytes = 3072

/**
 * The version of the payload format itself, so that a future change to the
 * *shape* of a snapshot is a miss rather than a mis-decode.
 *
 * @category constructors
 * @since 1.0.0
 */
export const payloadVersion = 1

/**
 * What every cache MAC covers before the payload itself.
 *
 * **Details**
 *
 * Domain separation. `Hmac` is a published service — a plugin may sign values
 * of its own with the same key — and a tag is only ever a tag *for* something.
 * Prefixing the signed bytes with a context nothing else uses is what makes a
 * tag produced elsewhere useless here: a forged envelope would have to be
 * signed under this exact prefix, which only this module writes.
 *
 * It is part of the format, so changing it invalidates every outstanding
 * snapshot — a miss, never a `401`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const macContext = "effect-auth/session-cache/v1\n"

/**
 * The wire envelope, as it is written into the cookie.
 *
 * **Details**
 *
 * The two halves are carried *already encoded*: what goes on the wire is
 * exactly `Session.json` and the model's `json` projection. They are decoded
 * back through the *stored* variants (`Session`, `UserModel.decodeRow`), because
 * a cache hit has to answer with the same `Session` and `UserOf<F>` a database
 * read would — which is also why the model, not this envelope, is what decodes
 * the user half.
 *
 * @category models
 * @since 1.0.0
 */
export const CacheEnvelope = Schema.Struct({
  v: Schema.Literal(payloadVersion),
  version: Schema.String,
  /** The base64url SHA-256 digest of the session token this snapshot belongs to. */
  tokenHash: Schema.String,
  /** When the snapshot stops being trusted — never later than the session itself. */
  expiresAt: Schema.DateTimeUtcFromString,
  session: Schema.Record(Schema.String, Schema.Unknown),
  user: Schema.Record(Schema.String, Schema.Unknown)
})

/**
 * The type of a {@link CacheEnvelope}.
 *
 * @category models
 * @since 1.0.0
 */
export type CacheEnvelope = typeof CacheEnvelope.Type

const CacheEnvelopeJson = Schema.fromJsonString(CacheEnvelope)

/**
 * A decoded snapshot: what the cookie said, with both halves decoded into the
 * values a store would have answered with.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionCachePayload<F extends UserFields = {}> {
  /** The invalidation token this snapshot was written under. */
  readonly version: string
  /** The base64url SHA-256 digest of the session token it belongs to. */
  readonly tokenHash: string
  /** When it stops being trusted. */
  readonly expiresAt: DateTime.Utc
  readonly session: Session
  readonly user: UserOf<F>
}

// -----------------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------------

/**
 * When a snapshot taken at `now` stops being trusted:
 * `min(now + maxAge, refreshDueAt(session), session.expiresAt)`.
 *
 * **Details**
 *
 * The three bounds are three different things that must not be papered over.
 * `maxAge` is the revocation lag a deployment accepted; `refreshDueAt` is the
 * instant the session's own expiry has to be rolled forward, which only a
 * database write can do; `expiresAt` is the end of the session. Whichever comes
 * first ends the snapshot.
 *
 * @category combinators
 * @since 1.0.0
 */
export const cacheExpiry = (
  config: AuthConfigService,
  session: Session,
  now: DateTime.Utc
): DateTime.Utc => {
  const candidates = [
    DateTime.addDuration(now, config.cookieCache.maxAge),
    refreshDueAt(session, config),
    session.expiresAt
  ]
  return candidates.reduce((earliest, candidate) => DateTime.isLessThan(candidate, earliest) ? candidate : earliest)
}

/**
 * The version string a snapshot of this session and user is written — and read —
 * under.
 *
 * @category combinators
 * @since 1.0.0
 */
export const cacheVersion = (config: AuthConfigService, session: Session, user: User): string => {
  const { version } = config.cookieCache
  return typeof version === "string" ? version : version(session, user)
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link SessionCache} service definition.
 *
 * **Gotchas**
 *
 * Every method is a no-op — and every read a miss — when `cookieCache.enabled`
 * is `false`. A disabled deployment still gets the service, so nothing that
 * depends on it has to branch on the configuration.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionCacheService<F extends UserFields = {}> {
  /** Whether this deployment writes and reads snapshots at all. */
  readonly enabled: boolean

  /** Signs a snapshot into the value the cookie carries. */
  readonly encode: (payload: SessionCachePayload<F>) => Effect.Effect<string>

  /**
   * Verifies and decodes a cookie value, or answers `None`.
   *
   * **Gotchas**
   *
   * Every failure is `None`: a value that is not two base64url halves, a tag
   * that does not verify (a tampered payload, or a payload signed with another
   * secret), a payload that is not this format's version, and a session or user
   * half the current models no longer decode. None of them is an error a caller
   * can act on — the answer in every case is "read the database".
   */
  readonly decode: (value: string) => Effect.Effect<Option.Option<SessionCachePayload<F>>>

  /**
   * The snapshot this request presented, if it presented a valid one for the
   * credential it authenticated with.
   */
  readonly read: (
    credential: Redacted.Redacted<string>
  ) => Effect.Effect<Option.Option<SessionWithUser<F>>, never, HttpServerRequest.HttpServerRequest>

  /**
   * Writes a snapshot of this session and user onto the response being built.
   *
   * **Gotchas**
   *
   * A no-op unless the request presented the session cookie: the cache is a
   * cookie-transport optimisation, and a caller that authenticated with a
   * bearer token must not be handed one.
   */
  readonly write: (
    session: Session,
    user: UserOf<F>
  ) => Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>

  /**
   * Expires the cache cookie on the response being built.
   */
  readonly clear: Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>
}

/**
 * The session cookie cache. See {@link SessionCacheService}.
 *
 * @category services
 * @since 1.0.0
 */
export class SessionCache extends Context.Service<SessionCache, SessionCacheService>()(
  "effect-auth/SessionCache"
) {}

/**
 * {@link SessionCache}, seen through a model's custom fields.
 *
 * The same key with a narrower shape — see `userStoreOf` in `domain/Stores.ts`
 * for what a typed view is and why it is sound.
 *
 * @category services
 * @since 1.0.0
 */
export const sessionCacheOf = <F extends UserFields>(
  _model: UserModel<F>
): Context.Service<SessionCache, SessionCacheService<F>> =>
  Context.Service<SessionCache, SessionCacheService<F>>("effect-auth/SessionCache")

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

const encodeSessionJson = Schema.encodeUnknownEffect(SessionModel.json)
const decodeSession = Schema.decodeUnknownEffect(SessionModel)
const encodeEnvelope = Schema.encodeEffect(CacheEnvelopeJson)
const decodeEnvelope = Schema.decodeUnknownEffect(CacheEnvelopeJson)

/**
 * The half of a snapshot that describes the session: `Session.json`, encoded —
 * which is to say, without the token hash.
 *
 * **Gotchas**
 *
 * The digest is not omitted because it is unsafe to carry (it rides in the
 * envelope's own `tokenHash`, where it is the binding), but because the session
 * half is the same projection every session endpoint answers with, and it must
 * stay that.
 *
 * @category combinators
 * @since 1.0.0
 */
export const sessionSnapshot = (session: Session): Effect.Effect<UserRow> => Effect.orDie(encodeSessionJson(session))

/**
 * Builds the {@link SessionCache} implementation for a user model.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: <F extends UserFields>(model: UserModel<F>) => Effect.Effect<
  SessionCacheService<F>,
  never,
  AuthConfig | Hmac | Token
> = Effect.fnUntraced(function*<F extends UserFields>(model: UserModel<F>) {
  const config = yield* AuthConfig
  const hmac = yield* Hmac
  const tokens = yield* Token

  const enabled = config.cookieCache.enabled
  const cookieName = sessionCacheCookieName(config)
  const security = sessionCacheCookieSecurity(config)
  // The columns a stored user has that its public projection does not — a
  // `UserField.hidden` field, and nothing else. Resolved once, here.
  const hiddenDefaults = yield* model.extraDefaults
  const encodeUser = Schema.encodeUnknownEffect(model.json)

  const hidden = Object.keys(hiddenDefaults)
  if (enabled && hidden.length > 0) {
    // Said once, when the stack is built, rather than left to whoever reads the
    // module header: on a cache hit these columns carry their declared
    // defaults, because a snapshot is the public projection and a hidden field
    // is not in it. An endpoint that reads one has to be annotated
    // `AuthoritativeSession`, and nothing but this line will tell a deployment
    // so.
    yield* annotateAuthLogs(Effect.logWarning(
      `the session cookie cache is enabled and the user model hides ${
        hidden.join(", ")
      }: a cached read sees the declared default of a hidden field, not the stored value. Annotate any endpoint that reads one AuthoritativeSession.`
    ))
  }

  const encode = Effect.fnUntraced(function*(payload: SessionCachePayload<F>) {
    const json = yield* Effect.orDie(encodeEnvelope({
      v: payloadVersion,
      version: payload.version,
      tokenHash: payload.tokenHash,
      expiresAt: payload.expiresAt,
      session: yield* sessionSnapshot(payload.session),
      // `toPublic` as well as the schema: the projection drops a hidden field
      // from the *value*, so it cannot reach the encoder in the first place.
      user: yield* Effect.orDie(encodeUser(model.toPublic(payload.user)))
    }))
    const mac = yield* hmac.sign(encodeUtf8(`${macContext}${json}`))
    return `${Encoding.encodeBase64Url(json)}${cacheCookieSeparator}${Encoding.encodeBase64Url(mac)}`
  })

  const decode = Effect.fnUntraced(function*(value: string) {
    const at = value.indexOf(cacheCookieSeparator)
    if (at <= 0 || at === value.length - 1) return Option.none<SessionCachePayload<F>>()

    const json = Encoding.decodeBase64UrlString(value.slice(0, at))
    const mac = Encoding.decodeBase64Url(value.slice(at + 1))
    if (Result.isFailure(json) || Result.isFailure(mac)) return Option.none<SessionCachePayload<F>>()

    // The tag is checked before anything is parsed: everything below trusts the
    // payload to be one this deployment wrote *as a cache snapshot* — hence the
    // context prefix, which is what "as a cache snapshot" is made of.
    const authentic = yield* hmac.verify(encodeUtf8(`${macContext}${json.success}`), mac.success)
    if (!authentic) return Option.none<SessionCachePayload<F>>()

    const envelope = yield* Effect.option(decodeEnvelope(json.success))
    if (Option.isNone(envelope)) return Option.none<SessionCachePayload<F>>()

    const session = yield* Effect.option(
      decodeSession({ ...envelope.value.session, tokenHash: envelope.value.tokenHash })
    )
    if (Option.isNone(session)) return Option.none<SessionCachePayload<F>>()

    // A hidden field is not in the snapshot, so its declared default is what a
    // cached read sees. See the module header.
    const user = yield* Effect.option(model.decodeRow({ ...hiddenDefaults, ...envelope.value.user }))
    if (Option.isNone(user)) return Option.none<SessionCachePayload<F>>()

    return Option.some<SessionCachePayload<F>>({
      version: envelope.value.version,
      tokenHash: envelope.value.tokenHash,
      expiresAt: envelope.value.expiresAt,
      session: session.value,
      user: user.value
    })
  })

  const read = Effect.fnUntraced(function*(credential: Redacted.Redacted<string>) {
    if (!enabled) return Option.none<SessionWithUser<F>>()

    const request = yield* HttpServerRequest.HttpServerRequest
    const cookie = request.cookies[cookieName]
    if (cookie === undefined || cookie.length === 0) return Option.none<SessionWithUser<F>>()

    const payload = yield* decode(cookie)
    if (Option.isNone(payload)) return Option.none<SessionWithUser<F>>()

    // The binding: this snapshot belongs to the token that was actually
    // presented, not merely to some session of this browser's.
    const tokenHash = yield* tokens.hashToken(credential)
    if (payload.value.tokenHash !== tokenHash) return Option.none<SessionWithUser<F>>()

    const now = yield* DateTime.now
    if (DateTime.isLessThanOrEqualTo(payload.value.expiresAt, now)) return Option.none<SessionWithUser<F>>()

    if (payload.value.version !== cacheVersion(config, payload.value.session, payload.value.user)) {
      return Option.none<SessionWithUser<F>>()
    }

    return Option.some<SessionWithUser<F>>({ session: payload.value.session, user: payload.value.user })
  })

  const write = Effect.fnUntraced(function*(session: Session, user: UserOf<F>) {
    if (!enabled) return

    // Cookie transports only, whoever is asking. The middleware decides that
    // for the request it authenticates, but a handler rewriting the snapshot
    // after a change to the user — `updateUser` — has no idea which transport
    // reached it, and a bearer client would otherwise be handed a `Set-Cookie`
    // it never asked for and nothing ever clears. The presented session cookie
    // is exactly the condition the read side applies.
    const request = yield* HttpServerRequest.HttpServerRequest
    const presented = request.cookies[sessionCookieName(config)]
    if (presented === undefined || presented.length === 0) return

    const now = yield* DateTime.now
    const expiresAt = cacheExpiry(config, session, now)
    const maxAge = Duration.millis(DateTime.toEpochMillis(expiresAt) - DateTime.toEpochMillis(now))
    // A session that is already due for a refresh, or already over, has nothing
    // worth snapshotting: the next request has to reach the database anyway.
    if (Duration.toMillis(maxAge) <= 0) return

    const value = yield* encode({
      version: cacheVersion(config, session, user),
      // The session row already holds the digest of its own token, so writing a
      // snapshot costs no hashing.
      tokenHash: session.tokenHash,
      expiresAt,
      session,
      user
    })

    if (encodeUtf8(value).length > maxCookieBytes) {
      yield* annotateAuthLogs(Effect.logDebug("session cache snapshot too large for a cookie; not written"))
      return
    }

    yield* HttpApiBuilder.securitySetCookie(security, value, sessionCookieOptions(config, { maxAge }))
  })

  const clear = Effect.suspend(() =>
    enabled
      ? HttpApiBuilder.securitySetCookie(security, "", expiredSessionCookieOptions(config))
      : Effect.void
  )

  return sessionCacheOf(model).of({ enabled, encode, decode, read, write, clear })
})

/**
 * Provides {@link SessionCache} for one user model.
 *
 * **Details**
 *
 * The layer's type does not mention the model, as no layer in this library's
 * surface does: what the model decides is the shape of the user a snapshot
 * carries, which a reader asks for through {@link sessionCacheOf}.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<SessionCache, never, AuthConfig | Hmac | Token> => Layer.effect(sessionCacheOf(model), make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<SessionCache, never, AuthConfig | Hmac | Token> = layerFor(baseUserModel)
