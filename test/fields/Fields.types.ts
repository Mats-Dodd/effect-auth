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
import type { SqlClient } from "effect/unstable/sql"
import type { PasswordsService, SignUpOptions } from "../../src/domain/Passwords.js"
import * as Passwords from "../../src/domain/Passwords.js"
import type { User, UserOf, UserPublicOf } from "../../src/domain/Schema.js"
import { baseUserModel } from "../../src/domain/Schema.js"
import type { AuthStores, SessionWithUser, UserPatch, UserStoreService } from "../../src/domain/Stores.js"
import { UserStore, userStoreOf } from "../../src/domain/Stores.js"
import type { SessionsService } from "../../src/domain/Sessions.js"
import * as Sessions from "../../src/domain/Sessions.js"
import type { CurrentUser } from "../../src/http/Middleware.js"
import { currentUserOf } from "../../src/http/Middleware.js"
import * as MiddlewareLive from "../../src/http/MiddlewareLive.js"
import * as SqlStores from "../../src/sql/SqlStores.js"
import type { Fields } from "./model.js"

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
const eq = <T extends true>(_: T): void => {}

// ---------------------------------------------------------------------------
// The custom fields are real types.
// ---------------------------------------------------------------------------

eq<
  Exact<
    UserOf<Fields>,
    & User
    & {
      readonly plan: "free" | "pro"
      readonly apiSecret: string | null
      readonly role: "user" | "admin"
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

declare const password: Redacted.Redacted<string>

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

type UserStoreView = ReturnType<typeof userStoreOf<Fields>>
type CurrentUserView = ReturnType<typeof currentUserOf<Fields>>
type SessionsView = ReturnType<typeof Sessions.sessionsOf<Fields>>
type PasswordsView = ReturnType<typeof Passwords.passwordsOf<Fields>>

/** Each view asks the context for the plain key, never one of its own. */
eq<Exact<RequirementsOf<UserStoreView>, UserStore>>(true)
eq<Exact<RequirementsOf<CurrentUserView>, CurrentUser>>(true)
eq<Exact<RequirementsOf<SessionsView>, Sessions.Sessions>>(true)
eq<Exact<RequirementsOf<PasswordsView>, Passwords.Passwords>>(true)

/** And answers with a service whose users carry the deployment's own fields. */
eq<Exact<SuccessOf<UserStoreView>, UserStoreService<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<UserStoreView>["create"]>>, UserOf<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<typeof UserStore["Service"]["create"]>>, User>>(true)

eq<Exact<SuccessOf<CurrentUserView>, UserOf<Fields>>>(true)

eq<Exact<SuccessOf<SessionsView>, SessionsService<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<SessionsView>["verify"]>>["user"], UserOf<Fields>>>(true)

eq<Exact<SuccessOf<PasswordsView>, PasswordsService<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<PasswordsView>["signUp"]>>["user"], UserOf<Fields>>>(true)
eq<Exact<SuccessOf<ReturnType<SuccessOf<PasswordsView>["verifyEmail"]>>, UserOf<Fields>>>(true)

/**
 * The four `layerFor`s. Each of these is the assertion that carrying custom
 * fields costs a deployment nothing in its layer graph: the types below are the
 * ones the base `layer` constants already have, character for character.
 */
eq<Exact<ReturnType<typeof SqlStores.layerFor<Fields>>, Layer.Layer<AuthStores, never, SqlClient.SqlClient>>>(true)
eq<Exact<ReturnType<typeof SqlStores.layerFor<Fields>>, typeof SqlStores.layer>>(true)
eq<Exact<ReturnType<typeof Sessions.layerFor<Fields>>, typeof Sessions.layer>>(true)
eq<Exact<ReturnType<typeof Passwords.layerFor<Fields>>, typeof Passwords.layer>>(true)
eq<Exact<ReturnType<typeof MiddlewareLive.layerFor<Fields>>, typeof MiddlewareLive.layer>>(true)

/** And the base model still builds the base instances. */
eq<Exact<typeof baseUserModel.extraKeys, ReadonlyArray<never>>>(true)

// The bindings above exist for their annotations; naming them here is what keeps
// `noUnusedLocals` quiet without weakening the assertions.
export type Assertions = [
  typeof stated,
  typeof omitted,
  typeof readOnly,
  typeof hidden,
  typeof patch,
  typeof patchesId
]
