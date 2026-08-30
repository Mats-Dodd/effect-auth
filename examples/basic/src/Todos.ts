/**
 * The application's own handlers.
 *
 * They show the only thing an application has to know about `effect-auth` at
 * request time: `CurrentUser` is in the context, already verified, and the
 * request never reaches the handler without it.
 */
import { Effect, Ref } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { CurrentUser } from "effect-auth"
import type { Todo } from "./Api.js"
import { AppApi } from "./Api.js"

/**
 * An in-memory list, so the example has exactly one moving part: the auth.
 */
export const layer = HttpApiBuilder.group(
  AppApi,
  "todos",
  (handlers) =>
    Effect.gen(function*() {
      const items = yield* Ref.make<ReadonlyArray<Todo>>([])
      const nextId = yield* Ref.make(1)

      return handlers
        .handle("list", () =>
          Effect.gen(function*() {
            const user = yield* CurrentUser
            const all = yield* Ref.get(items)
            return all.filter((todo) => todo.ownerId === user.id)
          }))
        .handle("create", ({ payload }) =>
          Effect.gen(function*() {
            const user = yield* CurrentUser
            const id = yield* Ref.getAndUpdate(nextId, (n) => n + 1)
            const todo: Todo = { id, ownerId: user.id, title: payload.title, done: false }
            yield* Ref.update(items, (all) => [...all, todo])
            return todo
          }))
    })
)
