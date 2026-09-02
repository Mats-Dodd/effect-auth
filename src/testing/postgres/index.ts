/**
 * `effect-auth/testing/postgres` — a real PostgreSQL server for a test suite.
 *
 * **When to use**
 *
 * Through `EFFECT_AUTH_TEST_DATABASE=pg`, or by passing {@link container} or
 * {@link fromUrl} as `AuthTest.Settings.database`. PGlite proves PostgreSQL
 * *semantics*; this proves the driver, the pool and the wire protocol, which is
 * what the support claim in `db-expansion.md` asks for.
 *
 * **Gotchas**
 *
 * This subpath needs `@effect/sql-pg` and, for {@link container},
 * `@testcontainers/postgresql` and a Docker daemon — all optional peer
 * dependencies. Nothing under `effect-auth`, `effect-auth/client` or
 * `effect-auth/testing` imports them.
 *
 * @since 0.1.0
 */
import { PgClient } from "@effect/sql-pg"
import { PostgreSqlContainer } from "@testcontainers/postgresql"
import { Effect, Layer, Redacted } from "effect"
import { Reactivity } from "effect/unstable/reactivity"
import { SqlClient, type SqlError } from "effect/unstable/sql"
import type { Provider } from "../Database.js"
import { TestDatabase } from "../Database.js"
import * as Catalog from "../internal/catalog.js"
import { withDatabase } from "../internal/url.js"
import { perWorker, uniqueName } from "../internal/worker.js"

/**
 * `postgres:alpine`, pinned to the digest it resolved to on 2026-09-02. The
 * same digest is in `.github/workflows/ci.yml`, so a green local run and a green
 * CI run are runs against the same bytes.
 */
const image = "postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"

/**
 * One container per worker, reused between runs: `withReuse()` labels the
 * container with a hash of its own configuration, so the second `pnpm test:pg`
 * on a machine finds the first one still running.
 */
const started = perWorker(
  Effect.promise(() => new PostgreSqlContainer(image).withReuse().start()).pipe(
    Effect.catchCause((cause) =>
      Effect.die(
        new Error(
          "effect-auth/testing: could not start a PostgreSQL container. Start Docker, or point EFFECT_AUTH_TEST_POSTGRES_URL at a server that is already running.",
          { cause }
        )
      )
    )
  )
)

/** One admin pool per server per worker: the connection that owns `CREATE DATABASE`. */
const admins = new Map<string, Effect.Effect<SqlClient.SqlClient, SqlError.SqlError>>()

const adminFor = (url: string): Effect.Effect<SqlClient.SqlClient, SqlError.SqlError> => {
  const existing = admins.get(url)
  if (existing !== undefined) return existing
  // `provideServiceEffect` rather than a layer: this pool is acquired in the
  // never-closed worker scope, which is the one lifetime a `Layer` in the build
  // graph cannot express. Every client that *is* in the graph takes
  // `Reactivity` through `Layer.provide` below.
  const created = perWorker(
    Effect.provideServiceEffect(
      PgClient.make({ url: Redacted.make(url), maxConnections: 2 }),
      Reactivity.Reactivity,
      Reactivity.make
    )
  )
  admins.set(url, created)
  return created
}

/**
 * A database of this build's own on the server `serverUrl` names, and a pool
 * pointed at it.
 *
 * The two `acquireRelease`s unwind in reverse, so the build's own pool is
 * already closed when the drop runs; `pg_terminate_backend` covers a connection
 * something else opened.
 */
const database = (serverUrl: Effect.Effect<string>) =>
  Effect.gen(function* () {
    const url = yield* serverUrl
    const admin = yield* adminFor(url)
    const name = yield* uniqueName("effect_auth_test")
    yield* Effect.acquireRelease(admin`CREATE DATABASE ${admin(name)}`, () =>
      Effect.orDie(
        Effect.andThen(
          admin`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
          WHERE datname = ${name} AND pid <> pg_backend_pid()`,
          admin`DROP DATABASE ${admin(name)}`
        )
      )
    )
    return yield* PgClient.make({ url: Redacted.make(withDatabase(url, name)), maxConnections: 4 })
  })

const provider = (serverUrl: Effect.Effect<string>): Provider => {
  // `Reactivity` is provided once, here, for the whole provider — the client
  // effect above states the requirement rather than satisfying it.
  const client = Layer.effect(SqlClient.SqlClient, database(serverUrl)).pipe(Layer.provide(Reactivity.layer))
  return Layer.effect(TestDatabase, Effect.map(SqlClient.SqlClient, Catalog.postgres)).pipe(Layer.provideMerge(client))
}

/**
 * A Testcontainers PostgreSQL at the pinned `postgres:alpine` digest: one container per worker, one
 * database per build, dropped when the build's scope closes.
 *
 * **Gotchas**
 *
 * Needs a Docker daemon. Export `TESTCONTAINERS_REUSE_ENABLE=false` to opt out
 * of reuse and have the container reaped at the end of the run.
 *
 * @category layers
 * @since 0.1.0
 */
export const container: Provider = provider(Effect.map(started, (server) => server.getConnectionUri()))

/** Memoised so that two calls with one URL are one layer, and therefore one database. */
const providers = new Map<string, Provider>()

/**
 * A PostgreSQL already running at `url`: one database per build on that server,
 * dropped when the build's scope closes.
 *
 * **When to use**
 *
 * In CI, where a service container is already up — `EFFECT_AUTH_TEST_POSTGRES_URL`
 * selects this over {@link container} — and locally against a server you keep.
 *
 * **Gotchas**
 *
 * The role in `url` must be allowed to `CREATE DATABASE`.
 *
 * @category layers
 * @since 0.1.0
 */
export const fromUrl = (url: string): Provider => {
  const existing = providers.get(url)
  if (existing !== undefined) return existing
  const created = provider(Effect.succeed(url))
  providers.set(url, created)
  return created
}
