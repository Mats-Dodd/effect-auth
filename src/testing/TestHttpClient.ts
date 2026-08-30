/**
 * A generated `HttpApiClient` wired straight to the router, with a cookie jar
 * the test can read.
 *
 * **Details**
 *
 * This is `HttpApiTest.groups` with two additions the auth tests need: a cookie
 * jar a test can inspect (asserting what `Set-Cookie` did, not merely that the
 * next request worked) and per-client request headers. Everything else — the
 * routing, the codecs, the middleware — is the real pipeline.
 *
 * @since 1.0.0
 */
import { Effect, Option, Redacted, Ref } from "effect"
import type { HttpClientResponse } from "effect/unstable/http"
import {
  Cookies,
  HttpClient,
  HttpClientRequest,
  HttpEffect,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse
} from "effect/unstable/http"
import type { HttpApi, HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApiBuilder, HttpApiClient, HttpApiMiddleware } from "effect/unstable/httpapi"
import { insecureSessionCookieName } from "../http/Cookies.js"
import { Authenticated } from "../http/Middleware.js"
import type { SentEmail } from "./TestEmails.js"
import { testBaseUrl, TestApi } from "./TestLayer.js"

/**
 * How a client presents itself.
 *
 * @category models
 * @since 1.0.0
 */
export interface ClientOptions {
  /**
   * A jar to share with another client, so both act as the same browser.
   */
  readonly cookies?: Ref.Ref<Cookies.Cookies> | undefined
  /**
   * Presented as `Authorization: Bearer`. A bearer client sends no cookies.
   */
  readonly bearerToken?: (() => string | undefined) | undefined
  /**
   * Extra request headers — an `Origin`, for the CSRF tests.
   */
  readonly headers?: Record<string, string> | undefined
  /**
   * The origin the client addresses. Defaults to `AuthTest.testBaseUrl`.
   */
  readonly baseUrl?: string | undefined
}

/**
 * A generated client for `api`, wired straight to the router, with a cookie jar.
 *
 * **Gotchas**
 *
 * `HttpEffect.toHandled` rather than running the router effect directly: it is
 * what a real server adapter calls, and it is the only thing that runs the
 * *pre-response* handlers — which is how `securitySetCookie` attaches the
 * session cookie. Running the handler on its own would silently drop every
 * `Set-Cookie` this library writes.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeClient = Effect.fnUntraced(
  function*<ApiId extends string, Groups extends HttpApiGroup.Constraint>(
    api: HttpApi.HttpApi<ApiId, Groups>,
    options?: ClientOptions
  ) {
    const cookies = options?.cookies ?? (yield* Ref.make(Cookies.empty))
    const handler = yield* HttpRouter.toHttpEffect(HttpApiBuilder.layer(api))

    const respond = (request: HttpClientRequest.HttpClientRequest) =>
      Effect.gen(function*() {
        const sent = yield* Ref.make(Option.none<HttpServerResponse.HttpServerResponse>())
        yield* HttpEffect.toHandled(handler, (_request, response) => Ref.set(sent, Option.some(response))).pipe(
          Effect.provideService(HttpServerRequest.HttpServerRequest, HttpServerRequest.fromClientRequest(request))
        )
        const response = yield* Ref.get(sent)
        return HttpServerResponse.toClientResponse(
          Option.getOrElse(response, () => HttpServerResponse.empty({ status: 500 }))
        )
      })

    // `HttpClient.make` takes a callback that may need nothing, and the router
    // built above still needs whatever the consumer's own groups and the
    // platform need. For a concrete API the compiler discharges that itself; for
    // one whose groups are still a type parameter it cannot, so the requirement
    // is discharged explicitly, from the context this effect already runs on.
    const context = yield* Effect.context<Effect.Services<ReturnType<typeof respond>>>()
    const router = HttpClient.make((request) => Effect.provideContext(respond(request), context))

    const withHeaders = options?.headers === undefined
      ? router
      : HttpClient.mapRequest(router, HttpClientRequest.setHeaders(options.headers))

    const httpClient = options?.bearerToken === undefined
      ? HttpClient.withCookiesRef(withHeaders, cookies)
      : withHeaders

    const client = yield* HttpApiClient.makeWith(api, {
      httpClient,
      baseUrl: options?.baseUrl ?? testBaseUrl
    }).pipe(
      Effect.provide(
        HttpApiMiddleware.layerClient(Authenticated, ({ next, request }) => {
          const token = options?.bearerToken?.()
          return next(token === undefined ? request : HttpClientRequest.bearerToken(request, token))
        })
      )
    )

    return { client, cookies } as const
  }
)

/**
 * Registers an account and returns the client that is signed in as it.
 *
 * **Gotchas**
 *
 * Bound to `AuthTest.TestApi`, because it has to *name* the `auth` group's
 * `signUpEmail` endpoint. A test of an application's own API composes
 * {@link makeClient} with its own sign-up call instead.
 *
 * @category constructors
 * @since 1.0.0
 */
export const signedUp = Effect.fnUntraced(function*(options?: ClientOptions & {
  readonly email?: string | undefined
  readonly password?: string | undefined
  readonly name?: string | undefined
}) {
  const created = yield* makeClient(TestApi, options)
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

/**
 * The session cookie a single response wrote, if it wrote one.
 *
 * **When to use**
 *
 * To tell "the cookie was re-sent on this request" from "the jar still holds
 * one from an earlier request" — the difference the rolling refresh turns on.
 *
 * @category combinators
 * @since 1.0.0
 */
export const responseCookie = (
  response: HttpClientResponse.HttpClientResponse,
  name: string = insecureSessionCookieName
): Option.Option<Cookies.Cookie> => Cookies.get(response.cookies, name)

/**
 * The session cookie currently in a jar, if there is one.
 *
 * @category combinators
 * @since 1.0.0
 */
export const sessionCookie = (
  cookies: Ref.Ref<Cookies.Cookies>
): Effect.Effect<Option.Option<Cookies.Cookie>> =>
  Effect.map(Ref.get(cookies), (jar) => Cookies.get(jar, insecureSessionCookieName))

/**
 * The value of the session cookie, `""` when it was expired away, and
 * `"<absent>"` when the jar never held one.
 *
 * @category combinators
 * @since 1.0.0
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
 *
 * **Gotchas**
 *
 * Throws when the link carries none. A test that got here without a token has a
 * broken assumption, not a condition to recover from.
 *
 * @category combinators
 * @since 1.0.0
 */
export const tokenOf = (email: SentEmail): string => {
  const url = new URL(Redacted.value(email.url))
  const token = url.searchParams.get("token")
  if (token === null) {
    throw new Error("effect-auth/testing: the e-mailed link carried no token")
  }
  return token
}
