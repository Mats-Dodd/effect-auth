/**
 * The database a test suite runs against.
 *
 * **Details**
 *
 * `effect-auth`'s own suite, and any suite built on `effect-auth/testing`, runs
 * unchanged on PGlite, SQLite, PostgreSQL or MySQL. A {@link Provider} is the
 * seam: a layer that hands each `layer()` block a private, empty database and
 * takes it away when the block's scope closes. {@link fromConfig} picks one from
 * `EFFECT_AUTH_TEST_DATABASE`, so the choice is a variable rather than a code
 * change, and {@link pglite} is what it picks when the variable is unset.
 *
 * {@link TestDatabase} is what a test may ask the database beyond SQL: which
 * dialect it is, an empty-the-tables reset, and schema inspection. Keeping
 * `information_schema`, `pg_catalog` and `PRAGMA` behind it is what lets one
 * assertion be true on all four backends.
 *
 * **Gotchas**
 *
 * Only PGlite is always available. `sqlite`, `pg` and `mysql` live on the
 * `effect-auth/testing/{sqlite,postgres,mysql}` subpaths behind optional peer
 * dependencies, and {@link fromConfig} loads the one it was asked for on demand.
 *
 * @since 0.1.0
 */
import { PgliteClient } from "@effect/sql-pglite"
import { Config, Context, Effect, Layer, Option } from "effect"
import { Reactivity } from "effect/unstable/reactivity"
import { SqlClient, type SqlError } from "effect/unstable/sql"
import * as Catalog from "./internal/catalog.js"

/**
 * The three dialects this library supports. Never `"mssql"`, never
 * `"clickhouse"`: PGlite reports itself as `"pg"`, which is what it is.
 *
 * @category models
 * @since 0.1.0
 */
export type Dialect = "pg" | "sqlite" | "mysql"

/**
 * What a test may ask a database beyond SQL.
 *
 * @category models
 * @since 0.1.0
 */
export interface TestDatabaseService {
  /**
   * Which dialect answered — for the handful of assertions that are
   * deliberately different, and for nothing else.
   */
  readonly dialect: Dialect
  /**
   * Empties every table this database holds *except* migration bookkeeping
   * tables (any table whose name ends in `_migrations`), in foreign-key-safe
   * order. PostgreSQL truncates with `CASCADE`; SQLite and MySQL delete per
   * table with foreign-key checks suspended for the duration. Migration state
   * is preserved, so a migration test cannot be falsified by a reset.
   */
  readonly reset: Effect.Effect<void, SqlError.SqlError>
  /** Every table in this build's schema (or database), sorted, bookkeeping included. */
  readonly tableNames: Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
  /** Column names of one table, in definition order. */
  readonly columnNames: (table: string) => Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
  /** Index names of one table, sorted, primary key excluded. */
  readonly indexNames: (table: string) => Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
}

/**
 * The ambient {@link TestDatabaseService}. Every {@link Provider} publishes one
 * beside its `SqlClient`.
 *
 * @category services
 * @since 0.1.0
 */
export class TestDatabase extends Context.Service<TestDatabase, TestDatabaseService>()(
  "effect-auth/testing/Database/TestDatabase"
) {}

/**
 * A database provider: a layer that, every time it is built, hands the build a
 * fresh, empty database (or schema) with nothing in it — the caller runs the
 * migrations — and tears it down when the build's scope closes.
 *
 * **Gotchas**
 *
 * The error channel is `SqlError` only. Infrastructure that cannot start — a
 * container, a URL that does not answer — *dies* with a message naming the
 * variable or option to fix. It is never a typed failure a test could branch on.
 *
 * @category models
 * @since 0.1.0
 */
export type Provider = Layer.Layer<SqlClient.SqlClient | TestDatabase, SqlError.SqlError>

/**
 * PGlite: one embedded instance per build, always available — it is what
 * `effect-auth`'s own suite runs on when nothing says otherwise.
 *
 * **Gotchas**
 *
 * One instance *per build*, not per worker, and that is deliberate. PGlite has
 * a single connection, so a shared instance would have to keep its builds apart
 * with a schema each and a `search_path` on that one connection — and
 * `sequence.concurrent` means two top-level `layer()` blocks in one file
 * overlap in time, so the second build's `search_path` would land under the
 * first block's running tests. `test/testing/Isolation.test.ts` is the standing
 * proof that a block never sees another block's rows; it is what would go red
 * if this were ever made to share.
 *
 * The engines that *can* be shared are shared: `effect-auth/testing/postgres`
 * and `effect-auth/testing/mysql` keep one server per worker and give each
 * build a database of its own on it, which concurrent connections make safe.
 *
 * @category layers
 * @since 0.1.0
 */
export const pglite: Provider = Layer.effect(TestDatabase, Effect.map(SqlClient.SqlClient, Catalog.postgres)).pipe(
  Layer.provideMerge(Layer.effect(SqlClient.SqlClient, PgliteClient.make({})).pipe(Layer.provide(Reactivity.layer)))
)

/**
 * Which backend to run against. Absent is `"pglite"`, so the fast default needs
 * no environment at all.
 */
const chosen = Config.string("EFFECT_AUTH_TEST_DATABASE").pipe(Config.withDefault("pglite"))

const urlFor = (variable: string) => Config.option(Config.string(variable))

/**
 * Reads `EFFECT_AUTH_TEST_DATABASE` — one of `"pglite"` (the default),
 * `"sqlite"`, `"pg"`, `"mysql"` — and resolves the named provider, loading the
 * subpath module for it on demand.
 *
 * **Details**
 *
 * For `"pg"` and `"mysql"`, a URL in `EFFECT_AUTH_TEST_POSTGRES_URL` /
 * `EFFECT_AUTH_TEST_MYSQL_URL` selects URL mode — which is what CI's service
 * containers use; otherwise a Testcontainers container is started, and reused
 * across runs when `TESTCONTAINERS_REUSE_ENABLE=true`.
 *
 * **Gotchas**
 *
 * The `import()`s below are the *only* way `effect-auth/testing` reaches its
 * optional peers — the arrangement `effect-auth/passkeys` has for
 * `@simplewebauthn/server` — and they are the reason this module has no static
 * dependency on `@effect/sql-pg`, `@effect/sql-sqlite-node` or
 * `@effect/sql-mysql2`. An unknown name dies naming the variable and the four
 * values it takes.
 *
 * @category layers
 * @since 0.1.0
 */
export const fromConfig: Provider = Layer.unwrap(
  Effect.gen(function* () {
    const name = yield* Effect.orDie(chosen)
    switch (name) {
      case "pglite":
        return pglite
      case "sqlite": {
        const module = yield* Effect.promise(() => import("./sqlite/index.js"))
        return module.memory
      }
      case "pg": {
        const module = yield* Effect.promise(() => import("./postgres/index.js"))
        const url = yield* Effect.orDie(urlFor("EFFECT_AUTH_TEST_POSTGRES_URL"))
        return Option.match(url, { onNone: () => module.container, onSome: module.fromUrl })
      }
      case "mysql": {
        const module = yield* Effect.promise(() => import("./mysql/index.js"))
        const url = yield* Effect.orDie(urlFor("EFFECT_AUTH_TEST_MYSQL_URL"))
        return Option.match(url, { onNone: () => module.container, onSome: module.fromUrl })
      }
      default:
        return yield* Effect.die(
          new Error(
            `effect-auth/testing: EFFECT_AUTH_TEST_DATABASE is "${name}"; it must be pglite, sqlite, pg or mysql`
          )
        )
    }
  })
)

/**
 * The dialect of the ambient {@link TestDatabase} — for a test that branches on
 * it.
 *
 * @category combinators
 * @since 0.1.0
 */
export const dialect: Effect.Effect<Dialect, never, TestDatabase> = Effect.map(
  TestDatabase,
  (database) => database.dialect
)
