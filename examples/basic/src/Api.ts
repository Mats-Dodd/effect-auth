/**
 * The application's HTTP contract: `effect-auth`'s group, plus one protected
 * group of its own.
 *
 * The point of this file is the last line — an application composes
 * `AuthApi` into its own `HttpApi` and gets the eighteen authentication
 * endpoints, their OpenAPI documentation and a generated client for free.
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { Authenticated, AuthApi, UserId } from "effect-auth"

/**
 * One item on somebody's list.
 */
export const Todo = Schema.Struct({
  id: Schema.Number,
  ownerId: UserId,
  title: Schema.String,
  done: Schema.Boolean
})

export type Todo = typeof Todo.Type

export const CreateTodoPayload = Schema.Struct({
  title: Schema.String
})

/**
 * The application's own endpoints. Every one of them carries `Authenticated`,
 * so `CurrentUser` is available to the handler and an anonymous request is
 * answered `401` before the handler runs.
 */
export class TodosGroup extends HttpApiGroup.make("todos")
  .add(
    HttpApiEndpoint.get("list", "/todos", {
      success: Schema.Array(Todo)
    }).middleware(Authenticated),
    HttpApiEndpoint.post("create", "/todos", {
      payload: CreateTodoPayload,
      success: Todo
    }).middleware(Authenticated)
  ) {}

/**
 * The whole application API.
 */
export const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(TodosGroup)
