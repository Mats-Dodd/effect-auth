import { PgliteClient } from "@effect/sql-pglite"
import { assert } from "@effect/vitest"
import { Context, Effect, FileSystem, Layer, Option, Path, Redacted, Ref } from "effect"
import {
  Cookies,
  Etag,
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
  HttpEffect,
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse
} from "effect/unstable/http"
import { HttpApi, HttpApiBuilder, HttpApiClient, HttpApiMiddleware } from "effect/unstable/httpapi"
import type {
  AuthConfigOptions,
  CookieConfig,
  EmailPasswordConfig,
  PartialOptions,
  RateLimitConfig,
  SessionConfig,
  TokenConfig
} from "../../src/config/AuthConfig.js"
import { layer as authConfigLayer } from "../../src/config/AuthConfig.js"
import type { AuthEmail } from "../../src/config/AuthEmails.js"
import { AuthEmails } from "../../src/config/AuthEmails.js"
import { layerScrypt } from "../../src/crypto/PasswordHasher.js"
import { layer as tokenLayer } from "../../src/crypto/Token.js"
import { layer as accountsLayer } from "../../src/domain/Accounts.js"
import { layer as authEventsLayer } from "../../src/domain/Events.js"
import { layer as passwordsLayer } from "../../src/domain/Passwords.js"
import { layer as sessionsLayer } from "../../src/domain/Sessions.js"
import { AuthApi } from "../../src/http/AuthApi.js"
import { insecureSessionCookieName } from "../../src/http/Cookies.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import { Authenticated } from "../../src/http/Middleware.js"
import { layer as middlewareLayer } from "../../src/http/MiddlewareLive.js"
import { layer as rateLimiterLayer } from "../../src/http/RateLimits.js"
import * as Migrations from "../../src/sql/Migrations.js"
import * as SqlStores from "../../src/sql/SqlStores.js"

/**
 * The base URL every test serves from. Plain HTTP on purpose: the cookie is
 * then written under the un-prefixed name, which is the second of the three
 * declared security schemes and therefore also exercises the fall-through.
 */
export const baseUrl = "http://localhost:3000"

/**
 * An application API that embeds `effect-auth`'s group, exactly as a consumer
 * composes it — and therefore what `AuthHandlers.layer` has to infer against.
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi)

/**
 * One delivered authentication e-mail.
 */
export interface SentEmail extends AuthEmail {
  readonly kind: "verification" | "reset"
}

/**
 * Captures what the application was asked to deliver, so a test can read the
 * token out of a link the way a person reads it out of their inbox.
 */
export class TestEmails extends Context.Service<TestEmails, {
  readonly all: Effect.Effect<ReadonlyArray<SentEmail>>
  readonly last: (kind: SentEmail["kind"]) => Effect.Effect<SentEmail>
}>()("test/http/TestEmails") {}

const emailsLayer = Layer.effectContext(Effect.gen(function*() {
  const sent = yield* Ref.make<ReadonlyArray<SentEmail>>([])
  const record = (kind: SentEmail["kind"]) => (email: AuthEmail) =>
    Ref.update(sent, (all) => [...all, { ...email, kind }])

  return Context.make(TestEmails, {
    all: Ref.get(sent),
    last: (kind) =>
      Effect.flatMap(Ref.get(sent), (all) => {
        const matching = all.filter((email) => email.kind === kind)
        const latest = matching[matching.length - 1]
        return latest === undefined
          ? Effect.sync(() => assert.fail(`no ${kind} e-mail was sent`))
          : Effect.succeed(latest)
      })
  }).pipe(
    Context.add(AuthEmails, {
      sendVerification: record("verification"),
      sendPasswordReset: record("reset")
    })
  )
}))

/**
 * What a test may vary about the deployment under test.
 */
export interface Overrides {
  readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
  readonly session?: PartialOptions<SessionConfig> | undefined
  readonly tokens?: PartialOptions<TokenConfig> | undefined
  readonly cookie?: PartialOptions<CookieConfig> | undefined
  readonly rateLimit?: PartialOptions<RateLimitConfig> | undefined
  readonly trustedOrigins?: ReadonlyArray<string> | undefined
}

export const testConfig = (overrides?: Overrides): AuthConfigOptions => ({
  baseUrl,
  secret: Redacted.make("test-secret-not-for-production"),
  trustedOrigins: overrides?.trustedOrigins ?? ["https://trusted.example.com"],
  emailPassword: { enabled: true, ...overrides?.emailPassword },
  session: overrides?.session,
  tokens: overrides?.tokens,
  cookie: overrides?.cookie,
  // Off by default: every test that is not *about* the limits would otherwise
  // spend its three attempts on its second or third request.
  rateLimit: { enabled: false, ...overrides?.rateLimit }
})

/** Cost parameters small enough for a test suite; the format is unchanged. */
export const testScryptOptions = { N: 1024, r: 8, p: 1 } as const

/**
 * Everything below the HTTP layer, on a fresh in-memory PGlite database: the
 * stores, the crypto, the mail capture, the rate limiter and the three domain
 * services.
 */
export const servicesLayer = (overrides?: Overrides) => {
  const database = PgliteClient.layer()
  const storage = SqlStores.layer.pipe(
    Layer.provide(Migrations.layer.pipe(Layer.provideMerge(database)))
  )
  const infrastructure = Layer.mergeAll(
    storage,
    authConfigLayer(testConfig(overrides)),
    tokenLayer,
    layerScrypt(testScryptOptions),
    authEventsLayer(),
    emailsLayer,
    rateLimiterLayer
  )
  const domain = Layer.mergeAll(sessionsLayer, accountsLayer).pipe(
    Layer.provideMerge(infrastructure)
  )
  return passwordsLayer.pipe(Layer.provideMerge(domain))
}

/**
 * The platform services an `HttpApi` needs in order to encode a response.
 */
export const platformLayer = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

/**
 * The whole server stack: {@link servicesLayer}, the `Authenticated`
 * implementation, the handlers, and the platform.
 */
export const testLayer = (overrides?: Overrides) => {
  // The handlers need the `Authenticated` implementation, and it needs the
  // session service: `Layer.provide` rather than `mergeAll`, or the middleware
  // would come back out as an unsatisfied requirement.
  const server = AuthHandlers.layer(TestApi).pipe(
    Layer.provide(middlewareLayer),
    Layer.provideMerge(servicesLayer(overrides))
  )
  return Layer.mergeAll(server, platformLayer)
}

/**
 * How a client presents itself.
 */
export interface ClientOptions {
  /** A jar to share with another client, so both act as the same browser. */
  readonly cookies?: Ref.Ref<Cookies.Cookies> | undefined
  /** Presented as `Authorization: Bearer`. A bearer client sends no cookies. */
  readonly bearerToken?: (() => string | undefined) | undefined
  /** Extra request headers — an `Origin`, for the CSRF tests. */
  readonly headers?: Record<string, string> | undefined
}

/**
 * A generated client wired straight to the router, with a cookie jar.
 *
 * **Details**
 *
 * This is `HttpApiTest.groups` with two additions the auth tests need: a cookie
 * jar the test can inspect (asserting what `Set-Cookie` did, not merely that the
 * next request worked) and per-client request headers. Everything else — the
 * routing, the codecs, the middleware — is the real pipeline.
 */
export const makeClient = Effect.fnUntraced(function*(options?: ClientOptions) {
  const cookies = options?.cookies ?? (yield* Ref.make(Cookies.empty))
  const handler = yield* HttpRouter.toHttpEffect(HttpApiBuilder.layer(TestApi))

  // `HttpEffect.toHandled` rather than running the router effect directly: it is
  // what a real server adapter calls, and it is the only thing that runs the
  // *pre-response* handlers — which is how `securitySetCookie` attaches the
  // session cookie. Running `handler` on its own would silently drop every
  // `Set-Cookie` this library writes.
  const router = HttpClient.make(Effect.fnUntraced(function*(request: HttpClientRequest.HttpClientRequest) {
    const sent = yield* Ref.make(Option.none<HttpServerResponse.HttpServerResponse>())
    yield* HttpEffect.toHandled(handler, (_request, response) => Ref.set(sent, Option.some(response))).pipe(
      Effect.provideService(HttpServerRequest.HttpServerRequest, HttpServerRequest.fromClientRequest(request))
    )
    const response = yield* Ref.get(sent)
    return HttpServerResponse.toClientResponse(
      Option.getOrElse(response, () => HttpServerResponse.empty({ status: 500 }))
    )
  }))

  const withHeaders = options?.headers === undefined
    ? router
    : HttpClient.mapRequest(router, HttpClientRequest.setHeaders(options.headers))

  const httpClient = options?.bearerToken === undefined
    ? HttpClient.withCookiesRef(withHeaders, cookies)
    : withHeaders

  const client = yield* HttpApiClient.makeWith(TestApi, { httpClient, baseUrl }).pipe(
    Effect.provide(
      HttpApiMiddleware.layerClient(Authenticated, ({ next, request }) => {
        const token = options?.bearerToken?.()
        return next(token === undefined ? request : HttpClientRequest.bearerToken(request, token))
      })
    )
  )

  return { client, cookies } as const
})

/**
 * The session cookie a single response wrote, if it wrote one.
 *
 * **When to use**
 *
 * To tell "the cookie was re-sent on this request" from "the jar still holds
 * one from an earlier request" — the difference the rolling refresh turns on.
 */
export const responseCookie = (
  response: HttpClientResponse.HttpClientResponse,
  name: string = insecureSessionCookieName
): Option.Option<Cookies.Cookie> => Cookies.get(response.cookies, name)

/**
 * The session cookie currently in a jar, if there is one.
 */
export const sessionCookie = (
  cookies: Ref.Ref<Cookies.Cookies>
): Effect.Effect<Option.Option<Cookies.Cookie>> =>
  Effect.map(Ref.get(cookies), (jar) => Cookies.get(jar, insecureSessionCookieName))

/**
 * The value of the session cookie, or `""` when it was expired away.
 */
export const sessionCookieValue = (
  cookies: Ref.Ref<Cookies.Cookies>
): Effect.Effect<string> =>
  Effect.map(
    sessionCookie(cookies),
    Option.match({ onNone: () => "<absent>", onSome: (cookie) => cookie.value })
  )

/**
 * Reads the `token` query parameter out of a link that was e-mailed.
 */
export const tokenOf = (email: SentEmail): string => {
  const url = new URL(Redacted.value(email.url))
  const token = url.searchParams.get("token")
  return token ?? assert.fail("the e-mailed link carried no token")
}

/**
 * Per-test timeout: every test boots its own PGlite and runs the migrations.
 */
export const testTimeout = 30_000

/**
 * Registers an account and returns the client that is signed in as it.
 */
export const signedUp = Effect.fnUntraced(function*(options?: {
  readonly email?: string | undefined
  readonly password?: string | undefined
  readonly name?: string | undefined
}) {
  const created = yield* makeClient()
  const email = options?.email ?? "ada@example.com"
  const password = options?.password ?? "correct horse battery staple"
  const result = yield* created.client.auth.signUpEmail({
    payload: {
      name: options?.name ?? "Ada Lovelace",
      email,
      password: Redacted.make(password)
    }
  })
  return { ...created, email, password, user: result.user, session: result.session }
})
