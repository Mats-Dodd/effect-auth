/**
 * `effect-auth/testing/mysql` — a real MySQL server for a test suite.
 *
 * **When to use**
 *
 * Through `EFFECT_AUTH_TEST_DATABASE=mysql`, or by passing {@link container} or
 * {@link fromUrl} as `AuthTest.Settings.database`.
 *
 * **Gotchas**
 *
 * This subpath needs `@effect/sql-mysql2` and, for {@link container},
 * `@testcontainers/mysql` and a Docker daemon — all optional peer dependencies.
 * Nothing under `effect-auth`, `effect-auth/client` or `effect-auth/testing`
 * imports them.
 *
 * @since 0.1.0
 */
import { MysqlClient } from "@effect/sql-mysql2"
import { MySqlContainer } from "@testcontainers/mysql"
import { Effect, Layer, Redacted } from "effect"
import { Reactivity } from "effect/unstable/reactivity"
import { SqlClient, type SqlError } from "effect/unstable/sql"
import type { Provider } from "../Database.js"
import { TestDatabase } from "../Database.js"
import * as Catalog from "../internal/catalog.js"
import { withDatabase } from "../internal/url.js"
import { perWorker, uniqueName } from "../internal/worker.js"

/**
 * `mysql:lts`, pinned to the digest it resolved to on 2026-09-02. The same
 * digest is in `.github/workflows/ci.yml`.
 */
const image = "mysql@sha256:257388edf9c84dbc04c763625446d5f3fa6ed60d1b0873bc552c614ba0a7ab4e"

/**
 * One container per worker, reused between runs. The health check is the
 * container's own `mysqladmin ping` over TCP rather than the log line: MySQL
 * writes its "ready for connections" twice, once before it closes the
 * initialisation port, and a client that believes the first one is refused.
 */
const started = perWorker(
  Effect.promise(() =>
    new MySqlContainer(image)
      .withReuse()
      .withHealthCheck({
        test: [
          "CMD-SHELL",
          'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqladmin ping --protocol TCP --host 127.0.0.1 --user root --silent'
        ],
        interval: 250,
        timeout: 1000,
        retries: 1000
      })
      .start()
  ).pipe(
    Effect.catchCause((cause) =>
      Effect.die(
        new Error(
          "effect-auth/testing: could not start a MySQL container. Start Docker, or point EFFECT_AUTH_TEST_MYSQL_URL at a server that is already running.",
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
  const created = perWorker(
    Effect.provide(MysqlClient.make({ url: Redacted.make(url), maxConnections: 2 }), Reactivity.layer)
  )
  admins.set(url, created)
  return created
}

/**
 * A database of this build's own on the server `serverUrl` names, and a pool
 * pointed at it. The pool is closed by its own finalizer before the drop runs.
 */
const database = (serverUrl: Effect.Effect<string>) =>
  Effect.gen(function* () {
    const url = yield* serverUrl
    const admin = yield* adminFor(url)
    const name = yield* uniqueName("effect_auth_test")
    yield* Effect.acquireRelease(admin`CREATE DATABASE ${admin(name)}`, () =>
      Effect.orDie(admin`DROP DATABASE ${admin(name)}`)
    )
    return yield* Effect.provide(
      MysqlClient.make({ url: Redacted.make(withDatabase(url, name)), maxConnections: 4 }),
      Reactivity.layer
    )
  })

const provider = (serverUrl: Effect.Effect<string>): Provider => {
  const client = Layer.effect(SqlClient.SqlClient, database(serverUrl))
  return Layer.effect(TestDatabase, Effect.map(SqlClient.SqlClient, Catalog.mysql)).pipe(Layer.provideMerge(client))
}

/**
 * A Testcontainers MySQL at the pinned `mysql:lts` digest: one container per worker, one
 * database per build, dropped when the build's scope closes.
 *
 * **Gotchas**
 *
 * Needs a Docker daemon, and MySQL's first boot on a machine costs about half a
 * minute — which is what reuse is for. Export
 * `TESTCONTAINERS_REUSE_ENABLE=false` to opt out and have the container reaped
 * at the end of the run.
 *
 * The connection is the container's `root`: `CREATE DATABASE` is not a
 * privilege the container's ordinary user has.
 *
 * @category layers
 * @since 0.1.0
 */
export const container: Provider = provider(Effect.map(started, (server) => server.getConnectionUri(true)))

/** Memoised so that two calls with one URL are one layer, and therefore one database. */
const providers = new Map<string, Provider>()

/**
 * A MySQL already running at `url`: one database per build on that server,
 * dropped when the build's scope closes.
 *
 * **When to use**
 *
 * In CI, where a service container is already up — `EFFECT_AUTH_TEST_MYSQL_URL`
 * selects this over {@link container} — and locally against a server you keep.
 *
 * **Gotchas**
 *
 * The account in `url` must be allowed to `CREATE DATABASE`.
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
