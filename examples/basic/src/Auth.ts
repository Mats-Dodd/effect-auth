/**
 * The one declaration everything else in the example is derived from.
 *
 * **Details**
 *
 * `Auth.define` takes a field map and hands back the whole parameterized
 * surface: the schemas, the endpoint group, the handlers, all four entry points,
 * the migrations, and the typed views of the services. Declaring `plan` here is
 * what puts a `plan` column on `users`, a `plan` key in the sign-up payload and
 * in `updateUser`, a `plan` on every user a response carries, and a
 * `"free" | "pro"` on {@link auth}`.CurrentUser` inside `Todos.ts`.
 *
 * **Gotchas**
 *
 * Call it once, at module scope, and import the result. Two calls with the same
 * fields build two models of the same shape and *different types*, which the
 * compiler points out at the first call site that mixes them — which is exactly
 * the mistake this module exists to make impossible.
 *
 * Every custom field has to be constructible without a value, because OAuth
 * sign-in and the magic link plugin provision accounts from the base fields
 * alone. `UserField.withDefault` is how `plan` satisfies that; a field that does
 * not throws when this module is first imported.
 */
import { Schema } from "effect"
import { Auth, UserField } from "effect-auth"

/**
 * The deployment's own user fields, and everything derived from them.
 */
export const auth = Auth.define({
  user: {
    fields: {
      plan: UserField.withDefault(Schema.Literals(["free", "pro"]), () => "free" as const)
    }
  }
})

/**
 * How many todos an account on the free plan may keep.
 *
 * The example's one piece of product logic, and the reason a custom user field
 * is worth the paragraph above: `Todos.ts` reads it off `CurrentUser` without
 * a second query and without knowing anything about `effect-auth`.
 */
export const freeTodoLimit = 3
