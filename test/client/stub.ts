/**
 * A stub `HttpClient` that answers the `effect-auth` endpoints from memory.
 *
 * It is deliberately not a server: it exists so the client tests exercise the
 * real generated `HttpApiClient` — real encoding of the request, real decoding
 * of the response into the declared success and error schemas — without a
 * socket, a database or a clock.
 *
 * **Gotchas**
 *
 * The transport is built with `HttpClient.makeWith`, not `Layer.mock`: the
 * client the tests drive is *wrapped* — by the bearer-token middleware and by
 * `filterStatusOk` — and every one of those combinators reads the underlying
 * client's `preprocess`/`postprocess` fields. A partial mock has neither, so it
 * fails at wiring time rather than at the unimplemented member.
 */
import { Effect, Layer } from "effect"
import type { HttpClientError } from "effect/unstable/http"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import * as ClientError from "effect/unstable/http/HttpClientError"

/** A fixed instant, so the encoded fixtures never move. */
const now = "2024-01-01T00:00:00.000Z"

/** The encoded form of a `UserPublic`. */
export const userJson = {
  id: "0192e5a0-0000-7000-8000-000000000001",
  name: "Ada Lovelace",
  email: "ada@example.com",
  emailVerified: true,
  image: null,
  createdAt: now,
  updatedAt: now
}

/** The encoded form of a `SessionPublic`. Note the absence of `tokenHash`. */
export const sessionJson = {
  id: "0192e5a0-0000-7000-8000-000000000002",
  userId: userJson.id,
  expiresAt: "2024-01-08T00:00:00.000Z",
  ipAddress: null,
  userAgent: null,
  rememberMe: true,
  createdAt: now,
  updatedAt: now
}

/** The encoded form of a `SessionWithUser`. */
export const sessionWithUserJson = {
  user: userJson,
  session: sessionJson
}

/**
 * The encoded form of an `AccessTokenResponse`.
 *
 * **Gotchas**
 *
 * The two credentials are plain strings on the wire and `Redacted` once the
 * generated client has decoded them — which is the point of declaring them as
 * `Secret`, and what the client test asserts.
 */
export const accessTokenJson = {
  accessToken: "provider-access-token",
  accessTokenExpiresAt: "2024-01-01T01:00:00.000Z",
  idToken: null,
  scopes: ["read:user", "user:email"],
  providerId: "github",
  accountId: "0192e5a0-0000-7000-8000-000000000003"
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  })

const unauthorized = (): Response => json(401, { _tag: "Unauthorized" })

/**
 * Nothing to do before the request goes out. Annotated rather than inferred:
 * `makeWith` cannot infer the transport's error channel from the postprocess
 * side alone.
 */
const preprocess: HttpClient.HttpClient.Preprocess<HttpClientError.HttpClientError, never> = Effect.succeed

/**
 * The controls a test has over the stub.
 */
export interface Stub {
  /** The layer to hand to `AuthClient.make({ httpClient })`. */
  readonly layer: Layer.Layer<HttpClient.HttpClient>
  /** `"GET /auth/session"`, in order, one entry per request. */
  readonly calls: ReadonlyArray<string>
  /** The `authorization` header of the most recent request, if any. */
  readonly lastAuthorization: () => string | undefined
  /** How many times a route was called. */
  readonly countOf: (call: string) => number
  /** Whether the stub considers the caller signed in. */
  readonly signedIn: () => boolean
  /** Makes `signInEmail` answer `401 InvalidCredentials`. */
  readonly rejectCredentials: () => void
  /** Makes the magic link `exchange` answer `400 InvalidToken`, as a spent link does. */
  readonly rejectMagicLink: () => void
  /** Makes every request fail at the transport, the way a dead network does. */
  readonly breakTransport: () => void
}

/**
 * Builds a stub whose starting state is "signed out" unless told otherwise.
 *
 * `user` replaces the encoded user every route answers with — a deployment that
 * declared custom fields has more of one, and the generated client decodes the
 * response through its own model, so the stub has to answer with what that model
 * declares.
 */
export const make = (options?: {
  readonly signedIn?: boolean | undefined
  readonly user?: { readonly [key: string]: unknown } | undefined
}): Stub => {
  const calls: Array<string> = []
  const user = options?.user ?? userJson
  const sessionWithUser = { user, session: sessionJson }
  let signedIn = options?.signedIn ?? false
  let credentialsValid = true
  let magicLinkValid = true
  let transportBroken = false
  let authorization: string | undefined

  /** One entry per route the client tests reach; anything else is a 404. */
  const routes: Record<string, () => Response> = {
    "GET /auth/session": () => (signedIn ? json(200, sessionWithUser) : unauthorized()),
    "GET /auth/sessions": () => (signedIn ? json(200, [sessionJson]) : unauthorized()),
    "POST /auth/sign-in/email": () => {
      if (!credentialsValid) return json(401, { _tag: "InvalidCredentials" })
      signedIn = true
      return json(200, sessionWithUser)
    },
    "POST /auth/sign-up/email": () => {
      signedIn = true
      return json(200, sessionWithUser)
    },
    "POST /auth/sign-out": () => {
      if (!signedIn) return unauthorized()
      signedIn = false
      return json(200, { success: true })
    },
    "POST /auth/sign-in/social": () =>
      json(200, { url: "https://github.test/login/oauth/authorize?state=abc", redirect: true }),
    "POST /auth/update-user": () => (signedIn ? json(200, { user }) : unauthorized()),
    "POST /auth/change-email": () => (signedIn ? json(200, { success: true }) : unauthorized()),
    "GET /auth/change-email/confirm": () => json(200, { success: true }),
    "GET /auth/change-email/verify": () => json(200, { success: true }),
    "POST /auth/delete-user": () => {
      if (!signedIn) return unauthorized()
      signedIn = false
      return json(200, { success: true, status: "Deleted" })
    },
    "POST /auth/set-password": () => (signedIn ? json(200, { success: true }) : unauthorized()),
    "POST /auth/magic-link/sign-in": () => json(200, { success: true }),
    "POST /auth/magic-link/exchange": () => {
      if (!magicLinkValid) return json(400, { _tag: "InvalidToken" })
      signedIn = true
      return json(200, sessionWithUser)
    },
    "POST /auth/get-access-token": () => (signedIn ? json(200, accessTokenJson) : unauthorized()),
    "POST /auth/refresh-token": () =>
      signedIn
        ? json(200, {
            ...accessTokenJson,
            refreshToken: "provider-refresh-token",
            refreshTokenExpiresAt: null
          })
        : unauthorized()
  }

  const client = HttpClient.makeWith(
    Effect.fnUntraced(function* (requestEffect) {
      const request = yield* requestEffect
      const path = new URL(request.url, "http://auth.test").pathname
      const call = `${request.method} ${path}`
      calls.push(call)
      authorization = request.headers["authorization"]

      if (transportBroken) {
        return yield* Effect.fail(
          new ClientError.HttpClientError({
            reason: new ClientError.TransportError({
              request,
              cause: new Error("network is down")
            })
          })
        )
      }

      const route = Object.hasOwn(routes, call) ? routes[call] : undefined
      return HttpClientResponse.fromWeb(request, route?.() ?? json(404, { _tag: "NotFound" }))
    }),
    preprocess
  )

  return {
    layer: Layer.succeed(HttpClient.HttpClient, client),
    calls,
    lastAuthorization: () => authorization,
    countOf: (call) => calls.filter((_) => _ === call).length,
    signedIn: () => signedIn,
    rejectCredentials: () => {
      credentialsValid = false
    },
    rejectMagicLink: () => {
      magicLinkValid = false
    },
    breakTransport: () => {
      transportBroken = true
    }
  }
}
