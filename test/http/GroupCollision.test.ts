/**
 * Two `HttpApiGroup`s that collide on an identifier, and what the plugin seam
 * makes of them.
 *
 * **Details**
 *
 * `HttpApi.add` is a last-one-wins merge keyed by the group's identifier, and a
 * group's context key is `effect/httpapi/HttpApiGroup/<identifier>` — derived
 * from the identifier and nothing else. So two groups called the same thing are
 * one group to everything downstream: one entry in `api.groups`, one key for
 * both handler layers to publish under, and no diagnostic anywhere. The
 * collision has to be caught before a route is ever registered.
 *
 * `forGroup` is where it is caught, and it catches it in the type checker: the
 * API it accepts is pinned to `{ groups: { [Id]: Group } }`, while a colliding
 * API's `groups[Id]` is the *union* of the two groups — which is not the group
 * whose handlers were built. Each `@ts-expect-error` below is therefore half of
 * a test: `tsc` fails if the pin ever stops rejecting a collision, and the body
 * underneath it records what a consumer with no types — JavaScript, or a cast —
 * would get instead.
 *
 * **Gotchas**
 *
 * Only one of the two shapes fails loudly at build. A handler set *wider* than
 * the surviving group dies naming the endpoint that is not there; a handler set
 * *narrower* than it builds perfectly happily and simply never serves the rest,
 * which is why the pin, and not the layer build, is the check that matters.
 */
import { assert, describe, it } from "@effect/vitest"
import { Cause, Context, Effect, Layer, Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import * as AuthHandlers from "../../src/http/Handlers.js"

/** One plugin's group. */
const Ping = HttpApiGroup.make("collide").add(
  HttpApiEndpoint.get("ping", "/collide/ping", { success: Schema.String })
)

/** Somebody else's group, which happens to be called the same thing. */
const PingAndPong = HttpApiGroup.make("collide")
  .add(HttpApiEndpoint.get("ping", "/collide/ping", { success: Schema.String }))
  .add(HttpApiEndpoint.get("pong", "/collide/pong", { success: Schema.String }))

/** Added last, so `Ping` is the group the API actually carries. */
const pingSurvives = HttpApi.make("collide-app").add(PingAndPong).add(Ping)

/** The other order: `PingAndPong` survives, `Ping` is the clobbered one. */
const pongSurvives = HttpApi.make("collide-app").add(Ping).add(PingAndPong)

const pingAndPongHandlers = AuthHandlers.forGroup(PingAndPong, (handlers) =>
  Effect.succeed(
    handlers
      .handle("ping", () => Effect.succeed("ping"))
      .handle("pong", () => Effect.succeed("pong"))
  ))

const pingHandlers = AuthHandlers.forGroup(Ping, (handlers) =>
  Effect.succeed(handlers.handle("ping", () => Effect.succeed("ping"))))

/** What one group's handler layer published, read back off its context key. */
const routesOf = (context: Context.Context<never>, group: { readonly key: string }): ReadonlyArray<string> => {
  const registered: { readonly routes: ReadonlyArray<{ readonly path: string }> } = context.mapUnsafe.get(group.key)
  return registered.routes.map((route) => route.path)
}

describe("http/group collisions", () => {
  it("collapse into one group, under one key, with nothing said", () => {
    // The API carries one `collide`, and it is the one added last. The other is
    // simply gone — no error, no second entry.
    assert.deepStrictEqual(Object.keys(pingSurvives.groups), ["collide"])
    assert.strictEqual(pingSurvives.groups.collide, Ping)
    assert.strictEqual(pongSurvives.groups.collide, PingAndPong)

    // And both groups address the same context key, so two handler layers built
    // for them would overwrite one another rather than sit side by side.
    assert.strictEqual(Ping.key, PingAndPong.key)
  })

  it.effect("are refused by the pin, and die at build when forced past it", () =>
    Effect.gen(function*() {
      // @ts-expect-error — `groups.collide` is `Ping | PingAndPong`, not the
      // group these handlers implement. This line is the pin.
      const forced = pingAndPongHandlers(pingSurvives)

      // What a consumer without that refusal gets: the handlers are built
      // against the *surviving* group, so `pong` — an endpoint only the
      // clobbered group declares — has nothing to register against, and the
      // layer dies naming it rather than serving a route it cannot describe.
      const exit = yield* Effect.exit(Effect.scoped(Layer.build(forced)))
      assert.strictEqual(exit._tag, "Failure")
      if (exit._tag !== "Failure") return
      assert.isTrue(Cause.hasDies(exit.cause))
      assert.include(String(Cause.squash(exit.cause)), "pong")
    }))

  it.effect("serve only the surviving group, in the shape that does not die", () =>
    Effect.gen(function*() {
      // @ts-expect-error — the same pin, the other way round: a narrower group
      // is not the `Ping | PingAndPong` this API carries either.
      const forced = pingHandlers(pongSurvives)

      // Nothing diagnoses this one. Every handler it holds does name an endpoint
      // of the surviving group, so the build succeeds — and `pong`, which that
      // group declares and these handlers never implement, is quietly served by
      // no route at all. A deployment would meet it as a 404, at runtime, with
      // no start-up failure to point at.
      const context = yield* Effect.scoped(Layer.build(forced))
      assert.deepStrictEqual([...routesOf(context, Ping)], ["/collide/ping"])
    }))
})
