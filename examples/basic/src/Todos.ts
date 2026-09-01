/**
 * The application's own handlers.
 *
 * They show the two things an application has to know about `effect-auth` at
 * request time. `CurrentUser` is in the context, already verified, and the
 * request never reaches the handler without it — and because this deployment
 * declared a `plan` field, `auth.CurrentUser` is the *same* context key seen
 * through its own model, so `user.plan` is a `"free" | "pro"` here with no
 * second query and nothing generic anywhere in the middleware's signature.
 */
import { Effect, Ref } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { Todo } from "./Api.js"
import { AppApi, TodoLimitReached } from "./Api.js"
import { auth, freeTodoLimit } from "./Auth.js"

/**
 * An in-memory list, so the example has exactly one moving part: the auth.
 */
export const layer = HttpApiBuilder.group(AppApi, "todos", (handlers) =>
  Effect.gen(function* () {
    const items = yield* Ref.make<ReadonlyArray<Todo>>([])
    const nextId = yield* Ref.make(1)

    return handlers
      .handle("list", () =>
        Effect.gen(function* () {
          const user = yield* auth.CurrentUser
          const all = yield* Ref.get(items)
          return all.filter((todo) => todo.ownerId === user.id)
        })
      )
      .handle("create", ({ payload }) =>
        Effect.gen(function* () {
          const user = yield* auth.CurrentUser
          const all = yield* Ref.get(items)
          const mine = all.filter((todo) => todo.ownerId === user.id)

          // The deployment's own user field, decided in the application's own
          // handler. Upgrading is `POST /auth/update-user`.
          if (user.plan === "free" && mine.length >= freeTodoLimit) {
            return yield* TodoLimitReached.make({ limit: freeTodoLimit })
          }

          const id = yield* Ref.getAndUpdate(nextId, (n) => n + 1)
          const todo: Todo = { id, ownerId: user.id, title: payload.title, done: false }
          yield* Ref.update(items, (rest) => [...rest, todo])
          return todo
        })
      )
  })
)
