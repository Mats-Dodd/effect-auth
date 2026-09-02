/**
 * The two things a database provider needs that outlive one `layer()` block:
 * a resource memoised for the life of the vitest worker, and a name no other
 * build in any worker will pick.
 *
 * Not part of the public API.
 *
 * @internal
 */
import { Effect, Scope } from "effect"
import { webCrypto } from "../../internal/crypto.js"

/**
 * The scope every per-worker resource is acquired in. It is never closed: a
 * vitest worker is a process, and the engine it booted — a Testcontainers
 * container, an admin connection pool — is meant to outlive every `layer()`
 * block that borrows it. A reusable container outlives the process too, which
 * is the point of `withReuse()`; a non-reusable one is reaped by Ryuk when the
 * run ends.
 */
const workerScope = Scope.makeUnsafe()

/**
 * Acquires `resource` at most once per worker and hands the same value to every
 * later caller.
 *
 * **Details**
 *
 * With vitest module isolation off, a module-level memo is per worker rather
 * than per test file, so a run pays for one server per worker instead of one
 * per `layer()` block — and, with Testcontainers reuse on, usually one per
 * machine. It is why `pnpm test:pg` costs a `CREATE DATABASE` per block rather
 * than a container start.
 *
 * @internal
 */
export const perWorker = <A, E>(resource: Effect.Effect<A, E, Scope.Scope>): Effect.Effect<A, E> =>
  Effect.runSync(Effect.cached(Scope.provide(resource, workerScope)))

/**
 * A free-list of resources, each booted at most once per worker, handed out
 * exclusively and put back — recycled — when the scope that borrowed one
 * closes.
 *
 * **Details**
 *
 * This is what a single-connection engine needs to be shared: it cannot keep
 * two builds apart on one connection, so instead each concurrent build borrows
 * an engine of its own and a sequential build inherits a wiped one. The list
 * grows to the number of builds that ever overlap in one worker — a handful —
 * and the engines it holds live in the never-closed worker scope. `recycle`
 * must leave the resource exactly as a fresh boot would; a recycle that fails
 * is a defect, because the next borrower would read a stale one.
 *
 * @internal
 */
export const pooled = <A, E, E2>(
  boot: Effect.Effect<A, E, Scope.Scope>,
  recycle: (resource: A) => Effect.Effect<void, E2>
): Effect.Effect<A, E, Scope.Scope> => {
  const idle: Array<A> = []
  return Effect.acquireRelease(
    Effect.suspend(() => {
      const next = idle.pop()
      return next === undefined ? Scope.provide(boot, workerScope) : Effect.succeed(next)
    }),
    (resource) =>
      Effect.orDie(
        Effect.andThen(
          recycle(resource),
          Effect.sync(() => {
            idle.push(resource)
          })
        )
      )
  )
}

/** Reads better than a bare digest in a `\\dn` listing while a suite is stuck. */
let builds = 0

const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")

/**
 * A database name unique across every worker of every run: a per-worker build
 * counter for legibility, and six bytes from `effect/Crypto` — never
 * `Math.random` — for the uniqueness itself.
 *
 * Thirty-three characters at most, which fits MySQL's 64-character limit on a
 * database name.
 *
 * @internal
 */
export const uniqueName = (prefix: string): Effect.Effect<string> =>
  Effect.map(
    Effect.all([Effect.sync(() => builds++), Effect.orDie(webCrypto.randomBytes(6))]),
    ([build, bytes]) => `${prefix}_${build}_${hex(bytes)}`
  )
