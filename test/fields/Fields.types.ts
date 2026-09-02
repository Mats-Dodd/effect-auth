/**
 * Type-level tests for the parameterization kernel.
 *
 * **Details**
 *
 * Two claims are being made, and neither of them can be checked at run time.
 *
 * *The custom fields are real types.* `UserOf<F>` carries them, `UserPublicOf<F>`
 * carries the ones that are allowed on the wire and not the ones that are not,
 * and `SignUpOptions<F>` accepts exactly the ones a client may state.
 *
 * *Nothing else moved.* A typed view is the same key with a narrower shape, so
 * `userStoreOf(model)` still puts `UserStore` in the requirement channel, and
 * every `layerFor` has byte-identical types to the base `layer` it generalises.
 * That is the whole reason the design is typed views rather than a factory: if
 * these assertions ever needed a `<F>` in them, `F` would have infected
 * `Auth.Services` and every plugin.
 *
 * There is nothing to run: `tsc` is the test. It lives outside `*.test.ts` on
 * purpose so vitest does not collect an empty suite.
 */
import type { Effect, Layer, Redacted } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import type { Atom } from "effect/unstable/reactivity"
import type { SqlClient } from "effect/unstable/sql"
import { AuthClient } from "../../src/client/index.js"
import * as Auth from "../../src/config/Auth.js"
import type * as AuthConfig from "../../src/config/AuthConfig.js"
import type { EmailNotVerified, InvalidCredentials, RateLimited } from "../../src/domain/Errors.js"
import type { AuthHooksOf, AuthHooksService, hooksOf, PolicyRefused, ProvisionSource } from "../../src/domain/Hooks.js"
import type { PasswordsService, SignUpOptions } from "../../src/domain/Passwords.js"
import type { OriginNotAllowed } from "../../src/http/OriginCheck.js"
import type * as Passwords from "../../src/domain/Passwords.js"
import type {
  baseUserModel,
  SessionWithUserOf,
  SignUpResponseOf,
  User,
  UserInsertOf,
  UserOf,
  UserPublicOf
} from "../../src/domain/Schema.js"
import type { SessionsService } from "../../src/domain/Sessions.js"
import type * as Sessions from "../../src/domain/Sessions.js"
import type {
  AuthStores,
  SessionWithUser,
  UserPatch,
  UserStore,
  userStoreOf,
  UserStoreService
} from "../../src/domain/Stores.js"
import type { SignUpEmailOf } from "../../src/http/AuthApi.js"
import { AuthApi } from "../../src/http/AuthApi.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import type { CurrentUser, currentUserOf } from "../../src/http/Middleware.js"
import type * as MiddlewareLive from "../../src/http/MiddlewareLive.js"
import type * as SqlStores from "../../src/sql/SqlStores.js"
import { AuthTest } from "../../src/testing/index.js"
import type { Fields } from "./model.js"
import { FieldsApi, model } from "./model.js"

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
const eq = <T extends true>(_: T): T => _

// ---------------------------------------------------------------------------
// The custom fields are real types.
// ---------------------------------------------------------------------------

eq<
  Exact<
    UserOf<Fields>,
    User & {
      readonly plan: "free" | "pro"
      readonly apiSecret: string | null
      readonly role: "user" | "admin"
      readonly order: "asc" | "desc"
    }
  >
>(true)

/** A `hidden` field is in the stored user and in no JSON projection of it. */
eq<Exact<"apiSecret" extends keyof UserOf<Fields> ? true : false, true>>(true)
eq<Exact<"apiSecret" extends keyof UserPublicOf<Fields> ? true : false, false>>(true)
eq<Exact<"plan" extends keyof UserPublicOf<Fields> ? true : false, true>>(true)
eq<Exact<"role" extends keyof UserPublicOf<Fields> ? true : false, true>>(true)

/** The empty model's user is the base one, in both directions. */
eq<Exact<UserOf<{}>, User>>(true)

declare const password: Redacted.Redacted

/** A `withDefault` field may be stated at sign-up, and may equally be left out. */
const stated: SignUpOptions<Fields> = { name: "Ada", email: "ada@example.com", password, plan: "pro" }
const omitted: SignUpOptions<Fields> = { name: "Ada", email: "ada@example.com", password }

/** A `readOnly` field may not: it is not part of `jsonCreate`. */
// @ts-expect-error `role` is the application's to set, never a client's
const readOnly: SignUpOptions<Fields> = { name: "Ada", email: "ada@example.com", password, role: "admin" }

/** Neither may a `hidden` one. */
// @ts-expect-error `apiSecret` never leaves the server, so it never enters it either
const hidden: SignUpOptions<Fields> = { name: "Ada", email: "ada@example.com", password, apiSecret: "x" }

/** A patch may name a custom column. */
const patch: UserPatch<Fields> = { name: "Ada", plan: "pro" }

// @ts-expect-error the primary key is not a mutable field
const patchesId: UserPatch<Fields> = { id: "nope" }

/** The joined read carries the model's user. */
eq<Exact<SessionWithUser<Fields>["user"], UserOf<Fields>>>(true)
eq<Exact<SessionWithUser["user"], User>>(true)

// ---------------------------------------------------------------------------
// Nothing else moved: a typed view is the same key with a narrower shape.
// ---------------------------------------------------------------------------

/**
 * A service key is itself an `Effect`, so both halves of a typed view can be
 * read straight off it: what it asks the context for, and what it hands back.
 *
 * Comparing whole service interfaces would be a weaker test than it looks —
 * their methods are functions, and two of these interfaces can be mutually
 * assignable while their *user* types differ. So each assertion below reaches
 * through to the type that actually carries the fields.
 */
type RequirementsOf<T> = T extends Effect.Effect<infer _A, infer _E, infer R> ? R : never
type SuccessOf<T> = T extends Effect.Effect<infer A, infer _E, infer _R> ? A : never
type ErrorOf<T> = T extends Effect.Effect<infer _A, infer E, infer _R> ? E : never

type UserStoreView = ReturnType<typeof userStoreOf<Fields>>
type CurrentUserView = ReturnType<typeof currentUserOf<Fields>>
type SessionsView = ReturnType<typeof Sessions.sessionsOf<Fields>>
type PasswordsView = ReturnType<typeof Passwords.passwordsOf<Fields>>
type HooksView = ReturnType<typeof hooksOf<Fields>>

/** Each view asks the context for the plain key, never one of its own. */
eq<Exact<RequirementsOf<UserStoreView>, UserStore>>(true)
eq<Exact<RequirementsOf<CurrentUserView>, CurrentUser>>(true)
eq<Exact<RequirementsOf<SessionsView>, Sessions.Sessions>>(true)
eq<Exact<RequirementsOf<PasswordsView>, Passwords.Passwords>>(true)

/** And answers with a service whose users carry the deployment's own fields. */
eq<Exact<SuccessOf<UserStoreView>, UserStoreService<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<UserStoreView>["create"]>>, UserOf<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<(typeof UserStore)["Service"]["create"]>>, User>>(true)

eq<Exact<SuccessOf<CurrentUserView>, UserOf<Fields>>>(true)

eq<Exact<SuccessOf<SessionsView>, SessionsService<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<SessionsView>["verify"]>>["user"], UserOf<Fields>>>(true)

eq<Exact<SuccessOf<PasswordsView>, PasswordsService<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<PasswordsView>["signUp"]>>["user"], UserOf<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<PasswordsView>["verifyEmail"]>>, UserOf<Fields>>>(true)

// ---------------------------------------------------------------------------
// The policy hooks, seen through the model.
// ---------------------------------------------------------------------------

/**
 * `hooksOf` is a typed view like the four above, with one difference that
 * matters: `AuthHooks` is a `Context.Reference` and therefore asks the context
 * for nothing. That is what keeps the whole feature free at the layer level —
 * a deployment that installs no policy provides nothing, and the assertions
 * further down (`Auth.layer`'s type, character for character) still hold.
 */
eq<Exact<RequirementsOf<HooksView>, never>>(true)
eq<Exact<SuccessOf<HooksView>, AuthHooksOf<Fields>>>(true)

type BeforeUserCreate = NonNullable<AuthHooksOf<Fields>["beforeUserCreate"]>

/**
 * The candidate a hook is handed, and the one it answers with, are the model's
 * own insert row — so a policy reads and writes the deployment's columns with
 * no cast, and `PolicyRefused` is the only failure it may raise.
 */
eq<Exact<Parameters<BeforeUserCreate>[0]["candidate"], UserInsertOf<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<BeforeUserCreate>>, UserInsertOf<Fields>>>(true)
eq<Exact<ErrorOf<ReturnType<BeforeUserCreate>>, PolicyRefused>>(true)

/** And every hook that inspects a stored person sees the model's user. */
eq<Exact<Parameters<NonNullable<AuthHooksOf<Fields>["afterUserCreate"]>>[0]["user"], UserOf<Fields>>>(true)
eq<Exact<Parameters<NonNullable<AuthHooksOf<Fields>["beforeSessionCreate"]>>[0]["user"], UserOf<Fields>>>(true)

/**
 * The soundness condition of the view: the base-typed set core actually reads
 * and the typed one a deployment writes are interchangeable, so the same slot
 * holds either. Every member is optional and the extra columns are optional on
 * the insert variant, which is what makes both directions true — and the
 * `@ts-expect-error` below is what says the check still has teeth.
 */
declare const baseTyped: AuthHooksService
const typedSlot: AuthHooksOf<Fields> = baseTyped
declare const modelTyped: AuthHooksOf<Fields>
const baseSlot: AuthHooksService = modelTyped

declare const wrongAnswer: {
  readonly beforeUserCreate?: (options: {
    readonly candidate: UserInsertOf<{}>
    readonly source: ProvisionSource
  }) => Effect.Effect<string, PolicyRefused>
}
// @ts-expect-error a hook must answer with a candidate, not with something else
const notAHookSet: AuthHooksOf<Fields> = wrongAnswer

/**
 * The refusal reaches the client, in the union the endpoint derives — including
 * `signIn`, whose sign-in path consults `beforeSessionCreate`. Carrying custom
 * fields changes the *success* type of these atoms and nothing about their
 * errors, which is the second assertion.
 */
eq<
  Exact<
    Atom.Failure<AuthClient.AuthClient<Fields>["signIn"]>,
    InvalidCredentials | EmailNotVerified | PolicyRefused | RateLimited | OriginNotAllowed
  >
>(true)
eq<Exact<Atom.Failure<AuthClient.AuthClient<Fields>["signIn"]>, Atom.Failure<AuthClient.AuthClient["signIn"]>>>(true)
eq<Exact<Atom.Success<AuthClient.AuthClient<Fields>["signIn"]>, AuthClient.SignInResult<Fields>>>(true)

/**
 * The four `layerFor`s. Each of these is the assertion that carrying custom
 * fields costs a deployment nothing in its layer graph: the types below are the
 * ones the base `layer` constants already have, character for character.
 */
eq<
  Exact<
    ReturnType<typeof SqlStores.layerFor<Fields>>,
    Layer.Layer<AuthStores, never, SqlClient.SqlClient | AuthConfig.AuthConfig>
  >
>(true)
eq<Exact<ReturnType<typeof SqlStores.layerFor<Fields>>, typeof SqlStores.layer>>(true)
eq<Exact<ReturnType<typeof Sessions.layerFor<Fields>>, typeof Sessions.layer>>(true)
eq<Exact<ReturnType<typeof Passwords.layerFor<Fields>>, typeof Passwords.layer>>(true)
eq<Exact<ReturnType<typeof MiddlewareLive.layerFor<Fields>>, typeof MiddlewareLive.layer>>(true)

/** And the base model still builds the base instances. */
eq<Exact<typeof baseUserModel.extraKeys, ReadonlyArray<never>>>(true)

// ---------------------------------------------------------------------------
// The HTTP surface carries `F`, and nothing around it does.
// ---------------------------------------------------------------------------

declare const settings: Auth.Settings

const fieldsHandlers = AuthHandlers.layer(FieldsApi, model)
const baseHandlers = AuthHandlers.layer(AuthApi)
const fieldsStack = Auth.layer({ ...settings, user: { model } })
const baseStack = Auth.layer(settings)

/** The sign-up payload takes exactly what the `jsonCreate` variant does. */
const httpStated: SignUpEmailOf<Fields> = { name: "Ada", email: "ada@example.com", password, plan: "pro" }
const httpOmitted: SignUpEmailOf<Fields> = { name: "Ada", email: "ada@example.com", password }

// @ts-expect-error `role` is `readOnly`: readable everywhere, settable nowhere
const httpReadOnly: SignUpEmailOf<Fields> = { name: "Ada", email: "ada@example.com", password, role: "admin" }

// @ts-expect-error `apiSecret` is `hidden`: it is in no JSON variant at all
const httpHidden: SignUpEmailOf<Fields> = { name: "Ada", email: "ada@example.com", password, apiSecret: "x" }

/** The three user-bearing endpoints answer with the model's public user. */
eq<Exact<SessionWithUserOf<Fields>["user"], UserPublicOf<Fields>>>(true)
eq<Exact<SignUpResponseOf<Fields>["user"], UserPublicOf<Fields>>>(true)

/**
 * The handlers of a parameterized API. This is the assertion the whole design
 * exists for: the layer that serves a deployment's own fields has the type the
 * base one has, character for character — no `F`, in any channel.
 */
eq<
  Exact<
    typeof fieldsHandlers,
    Layer.Layer<HttpApiGroup.Service<"fields-app", "auth">, never, AuthHandlers.HandlerServices>
  >
>(true)
/** The base API's own handlers differ only in the API id they are keyed by. */
eq<
  Exact<
    typeof baseHandlers,
    Layer.Layer<HttpApiGroup.Service<"effect-auth", "auth">, never, AuthHandlers.HandlerServices>
  >
>(true)

/**
 * And so does the stack, which is what "the parameterization does not infect"
 * means — and, since the hooks went in, what says installing policy points cost
 * a deployment nothing in its layer graph: `AuthHooks` is a `Context.Reference`
 * with a default, so it is in neither channel of these two types.
 */
eq<Exact<typeof fieldsStack, Layer.Layer<Auth.Services, never, Auth.Requirements>>>(true)
eq<Exact<typeof fieldsStack, typeof baseStack>>(true)

/** The `define` bundle's four entry points have those same types. */
declare const defined: Auth.Definition<Fields>
eq<Exact<ReturnType<typeof defined.layer>, Layer.Layer<Auth.Services, never, Auth.Requirements>>>(true)
eq<Exact<ReturnType<typeof defined.layerWithOAuth>, Layer.Layer<Auth.OAuthServices, never, Auth.OAuthRequirements>>>(
  true
)
eq<Exact<RequirementsOf<typeof defined.CurrentUser>, CurrentUser>>(true)
eq<Exact<SuccessOf<typeof defined.CurrentUser>, UserOf<Fields>>>(true)

// @ts-expect-error a parameterized API served by handlers built without its
// model would drop every custom field: `F` falls back to `{}`, and the API's
// `auth` group is not that group.
AuthHandlers.layer(FieldsApi)

// @ts-expect-error and the base API cannot be served by handlers built *with* a
// model — its endpoints do not carry the fields those handlers would answer with.
AuthHandlers.layer(AuthTest.TestApi, model)

// @ts-expect-error the same rule, one level up.
AuthTest.layerHttpApi(FieldsApi)

/** The client is typed by the model it was given. */
const fieldsClient = AuthClient.make({ api: FieldsApi, model })
eq<Exact<typeof fieldsClient, AuthClient.AuthClient<Fields>>>(true)
eq<Exact<typeof AuthClient.make extends () => AuthClient.AuthClient ? true : false, true>>(true)

declare const plan: "free" | "pro"
declare const fieldsSession: SessionWithUserOf<Fields>
const clientPlan: typeof plan = fieldsSession.user.plan

// @ts-expect-error a hidden field is not a key of what the client decodes
const clientSecret = fieldsSession.user.apiSecret

// @ts-expect-error a fields API without its model: the model cannot be inferred
// from the API's type, so the compiler reads the API as the base one.
AuthClient.make({ api: FieldsApi })

// The bindings above exist for their annotations; naming them here is what keeps
// `noUnusedLocals` quiet without weakening the assertions.
export type Assertions = [
  typeof stated,
  typeof omitted,
  typeof readOnly,
  typeof hidden,
  typeof patch,
  typeof patchesId,
  typeof httpStated,
  typeof httpOmitted,
  typeof httpReadOnly,
  typeof httpHidden,
  typeof clientPlan,
  typeof clientSecret,
  typeof typedSlot,
  typeof baseSlot,
  typeof notAHookSet
]
