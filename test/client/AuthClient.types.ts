/**
 * Type-level tests for the error unions `AuthClient` publishes.
 *
 * `AsyncResult` is covariant in its error, so an atom whose real error union is
 * narrower than the one `AuthClient` declares would still typecheck — the
 * declaration would simply be a lie, and a consumer's `switch` on `_tag` would
 * carry dead branches. These assertions pin each union to exactly what
 * `AtomHttpApi` derives from `AuthApi`, middleware error included.
 *
 * There is nothing to run: `tsc` is the test. It lives outside `*.test.ts` on
 * purpose so vitest does not collect an empty suite.
 */
import { Effect, Layer, Schema } from "effect"
import { HttpClient } from "effect/unstable/http"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import type { Atom } from "effect/unstable/reactivity"
import { AtomHttpApi } from "effect/unstable/reactivity"
import { AuthClient } from "../../src/client/index.js"
import type * as E from "../../src/domain/Errors.js"
import { AuthApi } from "../../src/http/AuthApi.js"

const S = AtomHttpApi.Service()("x", {
  api: AuthApi,
  httpClient: Layer.succeed(HttpClient.HttpClient, HttpClient.make(() => Effect.die("no"))) as any
})

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
const eq = <T extends true>(_: T): void => {}

eq<Exact<Atom.Failure<ReturnType<typeof S.mutation<"auth", "signOut">>>, E.Unauthorized>>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "signUpEmail">>>,
    E.UserAlreadyExists | E.PasswordPolicyViolation | E.RateLimited
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "unlinkAccount">>>,
    E.CannotUnlinkLastAccount | E.NotFound | E.SessionNotFresh | E.Unauthorized
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "changePassword">>>,
    E.InvalidCredentials | E.SessionNotFresh | E.PasswordPolicyViolation | E.Unauthorized
  >
>(true)
eq<Exact<Atom.Failure<ReturnType<typeof S.query<"auth", "getSession">>>, E.Unauthorized>>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "signInSocial">>>,
    E.OAuthProviderError | E.RateLimited
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "linkSocial">>>,
    E.OAuthProviderError | E.Unauthorized
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "verifyEmail">>>,
    E.InvalidToken
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "revokeSession">>>,
    E.NotFound | E.Unauthorized
  >
>(true)

// ---------------------------------------------------------------------------
// A composed API — the auth group plus the application's own — must be
// accepted by `AuthClient.make`. `HttpApi` is invariant in its groups, so this
// only compiles because `Options.api` is generic; a parameter fixed at
// `AuthApi`'s own group set would reject it.
// ---------------------------------------------------------------------------

const Todos = HttpApiGroup.make("todos").add(
  HttpApiEndpoint.get("listTodos", "/todos", { success: Schema.Array(Schema.String) })
)

const ComposedApi = HttpApi.make("app").addHttpApi(AuthApi).add(Todos)

const built = <T extends AuthClient.AuthClient>(_: T): void => {}

built(AuthClient.make({ api: ComposedApi, baseUrl: "http://localhost:3000" }))
// And the default — no API at all — still infers.
built(AuthClient.make())
