/**
 * The application's HTTP contract: `effect-auth`'s group, a plugin's group, and
 * one protected group of its own.
 *
 * The point of this file is the last line — an application composes the auth API
 * into its own `HttpApi` and gets the twenty-eight authentication endpoints,
 * their OpenAPI documentation and a generated client for free. Adding a plugin
 * is one more `.add`, and it is the same `.add` an application's own group uses:
 * there is no plugin registry.
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { Authenticated, EmailOtp, UserId } from "effect-auth"
import { auth } from "./Auth.js"

/**
 * One item on somebody's list.
 */
export const Todo = Schema.Struct({
  id: Schema.Finite,
  ownerId: UserId,
  title: Schema.String,
  done: Schema.Boolean
})

export type Todo = typeof Todo.Type

export const CreateTodoPayload = Schema.Struct({
  title: Schema.String
})

/**
 * What a free-plan account gets when it has filled its list.
 *
 * The example's own error, declared the way this library declares its own: a
 * `Schema.TaggedError` with an HTTP status, so it is a `402` on the wire and a
 * discriminated tag in the generated client.
 */
export class TodoLimitReached extends Schema.TaggedError<TodoLimitReached>("example/TodoLimitReached")(
  "TodoLimitReached",
  { limit: Schema.Finite },
  { description: "A free-plan account may keep only so many todos", httpApiStatus: 402 }
) {}

/**
 * The application's own endpoints. Every one of them carries `Authenticated`,
 * so `CurrentUser` is available to the handler and an anonymous request is
 * answered `401` before the handler runs.
 */
export class TodosGroup extends HttpApiGroup.make("todos").add(
  HttpApiEndpoint.get("list", "/todos", {
    success: Schema.Array(Todo)
  }).middleware(Authenticated),
  HttpApiEndpoint.post("create", "/todos", {
    payload: CreateTodoPayload,
    success: Todo,
    error: TodoLimitReached
  }).middleware(Authenticated)
) {}

/**
 * The whole application API: this library's group (carrying the deployment's own
 * user fields), the e-mail one-time-code plugin's, and the application's own.
 */
export const AppApi = HttpApi.make("app").addHttpApi(auth.Api).add(EmailOtp.EmailOtpApiGroup).add(TodosGroup)
