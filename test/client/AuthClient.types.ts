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
import type * as Hooks from "../../src/domain/Hooks.js"
import { AuthApi, type AuthApiGroup } from "../../src/http/AuthApi.js"

const S = AtomHttpApi.Service()("x", {
  api: AuthApi,
  httpClient: Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make(() => Effect.die("no"))
  )
})

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false

/**
 * Compiles only when the type argument it is given is `true`. Nothing reads the
 * result; it is the identity so that `T` is load-bearing in the signature
 * rather than a constraint that appears once.
 */
const eq = <T extends true>(_: T): T => _

eq<Exact<Atom.Failure<ReturnType<typeof S.mutation<"auth", "signOut">>>, E.Unauthorized>>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "signUpEmail">>>,
    E.UserAlreadyExists | E.PasswordPolicyViolation | Hooks.PolicyRefused | E.RateLimited
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
    E.OAuthProviderError | Hooks.PolicyRefused | E.RateLimited
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "linkSocial">>>,
    E.OAuthProviderError | Hooks.PolicyRefused | E.Unauthorized
  >
>(true)
eq<Exact<Atom.Failure<ReturnType<typeof S.mutation<"auth", "verifyEmail">>>, E.InvalidToken>>(true)
eq<Exact<Atom.Failure<ReturnType<typeof S.mutation<"auth", "revokeSession">>>, E.NotFound | E.Unauthorized>>(true)
eq<Exact<Atom.Failure<ReturnType<typeof S.mutation<"auth", "updateUser">>>, E.UserNotFound | E.Unauthorized>>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "changeEmail">>>,
    E.EmailUnchanged | Hooks.PolicyRefused | E.SessionNotFresh | E.RateLimited | E.Unauthorized
  >
>(true)
eq<
  Exact<Atom.Failure<ReturnType<typeof S.mutation<"auth", "verifyEmailChange">>>, E.InvalidToken | E.UserAlreadyExists>
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "deleteUser">>>,
    E.InvalidCredentials | Hooks.PolicyRefused | E.SessionNotFresh | E.RateLimited | E.Unauthorized
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "setPassword">>>,
    E.PasswordAlreadySet | E.PasswordPolicyViolation | E.SessionNotFresh | E.RateLimited | E.Unauthorized
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "getAccessToken">>>,
    E.NotFound | E.TokenRefreshFailed | E.Unauthorized
  >
>(true)
eq<
  Exact<
    Atom.Failure<ReturnType<typeof S.mutation<"auth", "refreshToken">>>,
    E.NotFound | E.TokenRefreshFailed | E.Unauthorized
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

/** Compiles only when what it is handed is an `AuthClient`; see `eq`. */
const built = <T extends AuthClient.AuthClient>(_: T): T => _

built(AuthClient.make({ api: ComposedApi, baseUrl: "http://localhost:3000" }))
// And the default — no API at all — still infers.
built(AuthClient.make())
// As does the standalone auth API.
built(AuthClient.make({ api: AuthApi }))

// ---------------------------------------------------------------------------
// Rejected: "generic" is not "anything". `Options.api` pins `groups.auth` to
// `effect-auth`'s own group, so the loose shapes the old
// `HttpApiGroup.Constraint` bound admitted no longer reach the one boundary
// cast in `src/client/AuthClient.ts`. Each `@ts-expect-error` is the test:
// undo the tightening and these lines stop erroring, which fails `tsc`.
// ---------------------------------------------------------------------------

/** Somebody else's group, sharing only the name. */
const Impostor = HttpApiGroup.make("auth").add(HttpApiEndpoint.get("ping", "/ping", { success: Schema.String }))
const ImpostorApi = HttpApi.make("app").add(Impostor)

AuthClient.make({
  // @ts-expect-error — `groups.auth` is not `typeof AuthApiGroup`; every atom
  // this client publishes would call an endpoint this API does not declare.
  api: ImpostorApi
})

/** No auth group at all. */
const TodosApi = HttpApi.make("app").add(Todos)

AuthClient.make({
  // @ts-expect-error — there is no `auth` group to build atoms from.
  api: TodosApi
})

// ---------------------------------------------------------------------------
// The argument each published mutation accepts, checked against the endpoint it
// is meant to call rather than against the interface that declares it. The
// wrappers in `AuthClient.make` used to take the underlying atom as
// `AtomResultFn<any, …>`, which let any atom be paired with any declaration —
// `verifyEmail` reading a `payload` from an endpoint that has only a `query`
// would have compiled, and failed on the wire. These pin the pairing.
// ---------------------------------------------------------------------------

type WriteArg<T> = T extends Atom.Writable<infer _R, infer W> ? Exclude<W, Atom.Reset | Atom.Interrupt> : never
type AuthEndpoint = HttpApiEndpoint.Identifier<HttpApiGroup.Endpoints<typeof AuthApiGroup>>
type MutationArg<Endpoint extends AuthEndpoint> = WriteArg<ReturnType<typeof S.mutation<"auth", Endpoint>>>

eq<Exact<WriteArg<AuthClient.AuthClient["signUp"]>, MutationArg<"signUpEmail">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["signIn"]>, MutationArg<"signInEmail">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["changePassword"]>, MutationArg<"changePassword">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["unlinkAccount"]>, MutationArg<"unlinkAccount">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["updateUser"]>, MutationArg<"updateUser">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["changeEmail"]>, MutationArg<"changeEmail">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["deleteUser"]>, MutationArg<"deleteUser">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["setPassword"]>, MutationArg<"setPassword">["payload"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["getAccessToken"]>, MutationArg<"getAccessToken">["payload"]>>(true)
// The query-parameter endpoints: their argument is the query, not a payload.
eq<Exact<WriteArg<AuthClient.AuthClient["verifyEmail"]>, MutationArg<"verifyEmail">["query"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["confirmEmailChange"]>, MutationArg<"confirmEmailChange">["query"]>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["verifyEmailChange"]>, MutationArg<"verifyEmailChange">["query"]>>(true)
// And the endpoints that take nothing accept nothing.
eq<Exact<WriteArg<AuthClient.AuthClient["signOut"]>, void>>(true)
eq<Exact<WriteArg<AuthClient.AuthClient["revokeSessions"]>, void>>(true)
