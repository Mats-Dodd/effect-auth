# Database expansion — execution plan

## Status

Execution plan, 2026-09-02, for the design in `db-expansion.md`. Branch `db-expansion`, cut from
`main` at `0575c61`. This file is the contract every builder, reviewer and fixer in the wave reads
first; `db-expansion.md` is the reasoning behind it, `CLAUDE.md` is how we work, `REFACTOR.md` §6 is
the definition of done for any change.

Nothing here is built. Where this file and `db-expansion.md` disagree, this file wins — it is the
later decision and it was taken with measurements the design doc did not have.

## Decisions (locked 2026-09-02)

1. **Supported: PostgreSQL, SQLite, MySQL.** PGlite stays the built-in fast test backend. MS SQL is
   out of scope.
2. **The public testing module carries the database choice.** `effect-auth/testing` gains a
   `Database` seam; `effect-auth/testing/{sqlite,postgres,mysql}` are subpaths behind optional peer
   dependencies, exactly as `effect-auth/passkeys` is behind `@simplewebauthn/server`. The
   `PgliteClient.PgliteClient` leak in every exported testing layer type is removed. Breaking to
   the testing types; `CHANGELOG.md` records it.
3. **One suite, every dialect.** The whole 1440-test suite runs on whichever dialect
   `EFFECT_AUTH_TEST_DATABASE` names. There is no separate contract-only runner: the store,
   migration, concurrency and error contracts are ordinary test files that read the dialect from
   the `TestDatabase` service and are therefore run four times by CI. Dialect-specific facts branch
   on `TestDatabase.dialect` inside the test.
4. **CI is five parallel jobs, no shards**: `check`, and one full-suite job per dialect. Speed is a
   standing consideration (see "Speed rules"), not a cap.
5. **Node 22 and later only.** `node:sqlite` needs it. `engines.node` becomes `>=22`, CI drops the
   Node 20 job.
6. **Vitest module isolation is off.** Measured on the current tree: 143 s → 61 s at two workers,
   41 s at four, all 1440 passing, no timeout tripwire. `isolate: false` goes into
   `vitest.config.ts` with the measurement in the comment; `pnpm test` runs `--maxWorkers=4`.
7. **One database instance per worker, one schema or database per build.** See "The database
   providers". Today every `layer()` block boots a PGlite (~1 s each, ~120 boots, half the suite);
   after this wave a block costs a `CREATE SCHEMA`.
8. **Images pinned by digest**: `postgres:alpine` and `mysql:lts`, resolved to a digest at build
   time by A2 and written into the CI workflow and the container providers.
9. **Column lengths on MySQL** are the table under "Column roles". Custom string user fields are
   `varchar(255)`; per-field storage metadata is roadmap work, not this wave.
10. **PostgreSQL and SQLite behaviour is unchanged.** The SQL they run may be restructured through
    helpers but must be semantically identical; the existing suite on PGlite is the proof and must
    stay green throughout.

## Pinned interfaces

Wave A builders work in parallel and cannot see each other's code. These are the names and shapes
they code against. Wave B builders read the real code Wave A produced.

### `src/testing/Database.ts` — exported from `effect-auth/testing` as `Database`

```ts
import type { SqlClient, SqlError } from "effect/unstable/sql"

/** The three dialects this library supports. Never "mssql", never "clickhouse". */
export type Dialect = "pg" | "sqlite" | "mysql"

/**
 * What a test may ask a database beyond SQL: which dialect it is, a reset, and
 * schema inspection — so `information_schema`, `pg_catalog`, `PRAGMA` and the
 * reset syntax live in the providers, never in a test.
 */
export interface TestDatabaseService {
  readonly dialect: Dialect
  /**
   * Empties every table this database holds *except* migration bookkeeping
   * tables (any table whose name ends in `_migrations`), in foreign-key-safe
   * order. PostgreSQL: TRUNCATE … CASCADE. SQLite and MySQL: DELETE per table
   * with foreign-key checks suspended for the duration. Migration state is
   * preserved so a migration test cannot be falsified by a reset.
   */
  readonly reset: Effect.Effect<void, SqlError.SqlError>
  /** Every table in this build's schema (or database), sorted, bookkeeping tables included. */
  readonly tableNames: Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
  /** Column names of one table, in definition order. */
  readonly columnNames: (table: string) => Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
  /** Index names of one table, sorted, primary key excluded. */
  readonly indexNames: (table: string) => Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
}

export class TestDatabase extends Context.Service<TestDatabase, TestDatabaseService>()(
  "effect-auth/testing/Database/TestDatabase"
) {}

/**
 * A database provider: a layer that, every time it is built, hands the build a
 * fresh, empty database (or schema) with nothing in it — the caller runs the
 * migrations — and tears it down when the build's scope closes.
 *
 * The error channel is `SqlError` only. Infrastructure that cannot start (a
 * container, a URL that does not answer) dies with a message naming the
 * variable or option to fix; it is never a typed failure a test could branch on.
 */
export type Provider = Layer.Layer<SqlClient.SqlClient | TestDatabase, SqlError.SqlError>

/** PGlite: one instance per worker, one schema per build. Always available. */
export const pglite: Provider

/**
 * Reads `EFFECT_AUTH_TEST_DATABASE` through `Config` — one of "pglite" (the
 * default), "sqlite", "pg", "mysql" — and resolves the named provider, loading
 * the subpath module for it on demand. For "pg" and "mysql", a URL in
 * `EFFECT_AUTH_TEST_POSTGRES_URL` / `EFFECT_AUTH_TEST_MYSQL_URL` selects URL mode;
 * otherwise a Testcontainers container is started (and reused across runs).
 * An unknown name dies naming the variable and the four values.
 */
export const fromConfig: Provider

/** The dialect of the ambient `TestDatabase` — for a test that branches on it. */
export const dialect: Effect.Effect<Dialect, never, TestDatabase>
```

### The subpath modules

| subpath | file | exports | optional peer |
|---|---|---|---|
| `effect-auth/testing/sqlite` | `src/testing/sqlite/index.ts` | `memory: Provider` | `@effect/sql-sqlite-node` |
| `effect-auth/testing/postgres` | `src/testing/postgres/index.ts` | `container: Provider`, `fromUrl: (url: string) => Provider` | `@effect/sql-pg`, `@testcontainers/postgresql` |
| `effect-auth/testing/mysql` | `src/testing/mysql/index.ts` | `container: Provider`, `fromUrl: (url: string) => Provider` | `@effect/sql-mysql2`, `@testcontainers/mysql` |

`effect-auth/testing` itself must not statically import any of those packages; `Database.fromConfig`
reaches them with a dynamic `import()` of the subpath, and that is the only dynamic import in the
tree. `@effect/sql-pglite` stays a static import of the testing module, as today.

### `AuthTest` and the plugin test modules

- `AuthTest.Settings` gains `readonly database?: Database.Provider | undefined`. Absent means
  `Database.fromConfig`.
- `layerDatabaseFor(model)` becomes `layerDatabaseFor(model, provider)`, memoised on the *pair*
  (a `WeakMap<UserModel, WeakMap<Provider, Layer>>`); `layerDatabase` remains the base-model,
  `fromConfig` constant. Every `*Test.ts` module that composed `AuthTest.layerDatabase` composes
  the provider from its own options the same way.
- Every exported layer type that reads `SqlClient.SqlClient | PgliteClient.PgliteClient` reads
  `SqlClient.SqlClient | Database.TestDatabase`. `DeploymentServices` likewise. The error channel
  stays `Migrator.MigrationError | SqlError.SqlError`.
- `PasskeysTest`'s `export type { PgliteClient }` goes.

### The database providers

Every provider follows one shape, and a provider that boots an engine per build is not done:

| dialect | per worker (module-level memo, legitimate now that `isolate: false`) | per build | teardown |
|---|---|---|---|
| pglite | one `PGlite` instance | `CREATE SCHEMA effect_auth_test_<n>`, and a `SqlClient` whose connection has `search_path` set to it | `DROP SCHEMA … CASCADE` |
| sqlite | nothing | `SqliteClient.layer({ filename: ":memory:" })` then `PRAGMA foreign_keys = ON` | scope close |
| pg | one container (Testcontainers, reuse enabled) or the URL | `CREATE DATABASE effect_auth_test_<id>`, `PgClient.layer` pointed at it | terminate its connections, `DROP DATABASE` |
| mysql | one container or the URL | `CREATE DATABASE effect_auth_test_<id>`, `MysqlClient.layer` pointed at it | `DROP DATABASE` |

`<n>` is a per-worker counter; `<id>` is unique across workers (a counter plus something
worker-specific, or `effect/Crypto` — never `Math.random`). The isolation claim for the shared
PGlite instance rests on `@effect/vitest`'s `layer()` blocks being sequential within a file; A2
adds a test in `test/testing/` that two top-level blocks in one file never observe each other's
rows and never overlap in time, and falls back to one PGlite per build (today's behaviour, behind
the same `Provider`) if that test cannot be made to pass.

### `src/sql/Dialect.ts` and `src/sql/Mutations.ts` (A1) — names and semantics

Wave B reads the real code; these are the names and the guarantees.

- `dialectOf(sql): Effect<Dialect>` — the three supported dialects; anything else *dies* at layer
  build with a message naming the dialect Effect SQL reported.
- `booleanCodec(dialect)` — `encode(boolean) → boolean | number`, `decode(unknown) → boolean`,
  `decodeNullable(unknown) → boolean | null | undefined`. pg passes through; sqlite and mysql store
  `0`/`1` and accept a number or a boolean back. The single boolean codec in the tree: the copies in
  `SqlStores.ts` and `src/passkeys/Store.ts` are deleted by their Wave B owners.
- `lockClause(sql, dialect)` — ` FOR UPDATE` on pg and mysql, empty on sqlite. Replaces the three
  copies in `SqlStores.ts`.
- `columnType(dialect, role, options?)` — the DDL type for a column role (table below), with the
  collation on MySQL where the role is an identity; `options.length` overrides the MySQL length.
- `booleanLiteral(dialect, value)` — `true`/`false`, `1`/`0`, `1`/`0`.
- `identifier(sql, name)` — an escaped identifier fragment; the replacement for every
  `sql.literal(<table or column name>)` and every `sql.unsafe` that interpolated a name.
- Mutation helpers, each taking the `sql` client and a dialect, each returning the same thing on
  every dialect:
  - `insertAndRead(table, record, columns, key)` — pg/sqlite: `INSERT … RETURNING`; mysql: the
    insert then `SELECT … WHERE <key> = ?` on the transaction connection. IDs are always
    application-generated, so the key is always known.
  - `updateAndRead(table, set, where, columns, key)` — pg/sqlite: `UPDATE … RETURNING`; mysql:
    update then select, inside `withTransaction`. Returns `Option`.
  - `deleteAndCount(statement)` — pg/sqlite: rows of `DELETE … RETURNING id`; mysql: the delete
    then `SELECT ROW_COUNT() AS count`, inside `withTransaction`. Returns `number`.
  - `deleteAndRead(…)` — as `updateAndRead`, for the two stores that need the deleted row.
  - `consumeOne(table, where, columns)` — the exactly-once claim. pg/sqlite: the single guarded
    `DELETE … RETURNING`. mysql: `SELECT … WHERE <where> FOR UPDATE`, then `DELETE … WHERE id = ?`
    by the selected primary key, inside `withTransaction`; no row → `None`, nothing deleted.
  - `upsertAndRead(spec)` — a conditional upsert: insert, or update the conflicting row only while
    a condition holds, then hand back the caller's row or `None`. pg/sqlite: `INSERT … ON CONFLICT
    (…) DO UPDATE SET … WHERE <condition> RETURNING …`. mysql: `INSERT … ON DUPLICATE KEY UPDATE
    col = IF(<condition>, <new>, col)` then a read-back the caller specifies. The two call sites it
    must express exactly: `src/username/Store.ts` `claim` and `src/two-factor/Store.ts` the TOTP
    enrolment upsert (`WHERE verified_at IS NULL`).
- All helpers are `@internal`, unexported from the package, and `sql.withTransaction` is the only
  transaction primitive they use — a caller already inside `WithAuthTransaction` gets a savepoint.
- Every statement the helpers produce on pg and sqlite is byte-identical to what the store wrote
  before, apart from whitespace. That is what keeps decision 10 true.

### `src/sql/stores/` (A4) — file names Wave B owns

`src/sql/SqlStores.ts` becomes a facade re-exporting `layer`, `layerFor` and the types from:
`src/sql/stores/Users.ts`, `Sessions.ts`, `Accounts.ts`, `Verifications.ts`, `Transaction.ts`, with
shared row types and projections in `src/sql/stores/internal.ts`. No behaviour change, no export
change: the `.d.ts` of `effect-auth` is diffed against a build of `main` and must be identical.

### Column roles and MySQL lengths (B1, B4, B5)

| role | used for | pg | sqlite | mysql |
|---|---|---|---|---|
| `id` | primary keys and foreign keys | `text` | `text` | `varchar(64) CHARACTER SET ascii COLLATE ascii_bin` |
| `hash` | `token_hash`, `value_hash`, `code_hash`, `username_key`'s digest if any | `text` | `text` | `varchar(64) … ascii_bin` |
| `credential` | WebAuthn `credential_id`, passkey user handles | `text` | `text` | `varchar(1024) … ascii_bin` |
| `email` | `users.email` | `text` | `text` | `varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin` |
| `identity` | `issuer`, `account_id`, `provider_id`, `username`, `username_key`, `phone_e164`, `aaguid`, `aal` | `text` | `text` | `varchar(255) … utf8mb4_bin` |
| `identifier` | `verifications.identifier` (`<purpose>:<subject>`, subject may be an address) | `text` | `text` | `varchar(400) … utf8mb4_bin` |
| `timestamp` | every `*_at` column, ISO-8601 UTC | `text` | `text` | `varchar(32) … ascii_bin` |
| `boolean` | every flag | `boolean` | `integer` | `boolean` |
| `number` | custom number fields | `double precision` | `real` | `double` |
| `bigint` | `last_used_step` | `bigint` | `integer` | `bigint` |
| `text` | names, image URLs, user agents, IPs, JSON (`methods`, `payload`, `transports`), ciphertexts, password hashes, public keys, custom string fields' *values* — and custom string *columns* | `text` | `text` | `text`, except custom string fields: `varchar(255) … utf8mb4_bin` |

Rules: an indexed MySQL column is never `text`; every unique index's byte width stays under
InnoDB's 3072 (`issuer` + `account_id` = 2040; `credential_id` = 1024); opaque identity never
inherits the server collation; e-mail is stored normalised (lower-cased) by the domain already, so
`utf8mb4_bin` matches pg and sqlite semantics exactly. MySQL has no `ADD COLUMN IF NOT EXISTS`:
migrations run once, so mysql branches use plain `ADD COLUMN`; `forUserFields` — which runs on
every boot — checks `information_schema.columns WHERE table_schema = DATABASE()` first. Every
bounded column has its bound stated in the README beside the domain constraint that guarantees it.

### Vitest and scripts (A2)

- `vitest.config.ts`: `isolate: false`; `hookTimeout` 15 s on pglite and sqlite, 120 s when
  `EFFECT_AUTH_TEST_DATABASE` is `pg` or `mysql` (container start lands in a `layer()` beforeAll);
  `testTimeout` unchanged at 10 s — it is a tripwire and stays one.
- `package.json` scripts: `test` = `vitest run --maxWorkers=4`; `test:sqlite`, `test:pg`,
  `test:mysql` = the same with the variable set. No `test:sql`.
- `lefthook.yml` unchanged (pre-commit still runs the pglite suite).

### CI (A2)

`.github/workflows/ci.yml`: Node 22 only. Jobs: `check` (install, `pnpm check`, `pnpm format:check`),
`test-pglite`, `test-sqlite`, `test-pg` (a `postgres` service container at the pinned digest, URL in
`EFFECT_AUTH_TEST_POSTGRES_URL`), `test-mysql` (a `mysql` service container at the pinned digest,
URL in `EFFECT_AUTH_TEST_MYSQL_URL`). All five parallel; each test job records its wall time in the
job summary. Expected: check 20 s, pglite 60–90 s, sqlite 45–60 s, pg 60–75 s, mysql 90–120 s.

## Speed rules

Written into every builder's definition of done.

1. `isolate: false` stays. A change that needs isolation back has to say what state it leaks.
2. One engine per worker, one schema or database per build. A provider that boots per build is
   unfinished.
3. No new top-level `layer()` block where a nested `it.layer` would inherit the database. A test
   that needs an empty database uses `TestDatabase.reset`, not a new block.
4. Service containers in CI, reusable containers locally (`withReuse()` and
   `TESTCONTAINERS_REUSE_ENABLE=true` documented) — MySQL's init is paid once per machine.
5. Every wave gate records wall time per dialect in its report, and the final reviewer reports the
   CI run's per-job wall time on the branch.

## Contract test groups (A3, B6)

All in ordinary `test/**/*.test.ts` files, dialect-neutral, inspecting schema only through
`TestDatabase`, isolating with `reset` between cases where a case needs an empty table:

- **Store behaviour** (`test/sql/SqlStores.test.ts`, `test/fields/Store.test.ts`, the plugin
  `Store.test.ts` files): everything they assert today, unchanged in meaning.
- **Error behaviour** (`test/sql/Errors.test.ts`): duplicate e-mail, duplicate session hash,
  duplicate OAuth identity are `UniqueViolation`; a foreign-key violation is a `PersistenceError`
  of kind `Unknown`; a failing transaction rolls every write back.
- **Concurrency** (`test/sql/Concurrency.test.ts`), real forked fibers: two registrations of one
  address → one user; two provisions of one OAuth identity → one account; two consumers of one
  verification → exactly one `Some`; reclaim and link hold their lock invariant; rollback exposes no
  partial state.
- **Migrations** (`test/sql/Migrations.test.ts` and the plugin `Migrations.test.ts` files): apply
  to empty, rerun applies none, ids and names stable, the `remember_me` and `authenticated_at`
  backfills, every required index present (by name, through `indexNames`), cascades work, custom
  columns get the right nullability and default, `forUserFields` is idempotent.
- **Dialect facts** (`test/sql/Dialect.test.ts`): sqlite stores `0`/`1` and has foreign keys on;
  mysql identity columns carry `utf8mb4_bin` or `ascii_bin`; mysql write-then-read returns the
  row just written; mysql `ROW_COUNT()` counts correctly; pg and mysql `FOR UPDATE` blocks a second
  reader; sqlite serialises writers.

## Waves

### Wave A — foundations (four Opus builders, disjoint)

| builder | owns | delivers |
|---|---|---|
| A1 Dialect kernel | `src/sql/Dialect.ts`, `src/sql/Mutations.ts`, `test/sql/Dialect.unit.test.ts` (new) | everything under "`src/sql/Dialect.ts` and `src/sql/Mutations.ts`". Unit-tested on PGlite for the pg branches; the mysql branches are tested by their Wave B consumers on MySQL. Nothing else in the tree imports it yet |
| A2 Testing module and CI | `src/testing/**`, `package.json`, `pnpm-lock.yaml`, `vitest.config.ts`, `.github/workflows/ci.yml`, `test/testing/**` | everything under "Pinned interfaces" for the testing module, the providers, vitest, scripts, CI; a before/after wall time per dialect in its report |
| A3 Contracts | `test/sql/**` (except `Dialect.unit.test.ts`), `test/fields/**` | the existing cases made dialect-neutral against the pinned `TestDatabase`, plus `Errors`, `Concurrency`, `Dialect` files. Until A2 lands these compile against the pinned interface only; the gate proves them |
| A4 Store split | `src/sql/SqlStores.ts`, `src/sql/stores/**` (new) | the pure move, with the `.d.ts` diff and the snapshot compare in its report |

Gate A: `pnpm check`, `pnpm test`, `pnpm test:sqlite`, `pnpm test:pg`, `pnpm test:mysql` — the
last three are expected to *fail* on the MySQL-only paths (no store or migration has a mysql branch
yet) and the gate records exactly which files fail on which dialect; pglite and sqlite must be green
and the failures on pg must be only those that the `FOR UPDATE`-free sqlite path does not share.
Commit.

### Wave B — the port (six Opus builders, disjoint)

| builder | owns | delivers |
|---|---|---|
| B1 Core migrations | `src/sql/Migrations.ts`, a draft of SPEC Amendment 20's column table in `db-expansion-plan.md` § "Column roles" (append, do not rewrite) | six migrations through `columnType`, mysql DDL, `forUserFields` over `information_schema`, `identifier()` for every dynamic name, no `sql.unsafe` left in the file |
| B2 Users and Sessions | `src/sql/stores/Users.ts`, `Sessions.ts` | every mutation through the helpers; the joined read; `elevate`'s single locked write |
| B3 Accounts, Verifications, Transaction | `src/sql/stores/Accounts.ts`, `Verifications.ts`, `Transaction.ts`, `internal.ts` | same, plus `consumeOne` for `VerificationStore.consume`. Runs `test/sql/Concurrency.test.ts` on mysql before reporting |
| B4 Plugins, simple | `src/username/{Store,Migrations}.ts`, `src/anonymous/{Store,Migrations}.ts`, `src/phone/{Store,Migrations}.ts` | ports; `upsertAndRead` for the username claim; `identifier()` for the phone table name |
| B5 Plugins, hard | `src/passkeys/{Store,Migrations}.ts`, `src/two-factor/{Store,Migrations}.ts` | ports; deletes the passkey boolean codec copy; `upsertAndRead` for the TOTP enrolment with a test proving an abandoned-then-restarted enrolment behaves identically on all dialects; the `credential` and `bigint` roles |
| B6 Plugin contracts and docs | `test/{username,anonymous,phone,passkeys,two-factor}/{Store,Migrations}.test.ts`, `README.md`, `CHANGELOG.md`, `SPEC.md` (Amendment 20), `AGENTS.md`, `db-expansion.md` (status line only) | dialect-neutral plugin contracts; README "Databases" (drivers, versions, the SQLite pragma, MySQL lengths and collations, the migrator's MySQL caveats: DDL auto-commits, no cross-process lock) and "Testing" (the `database` option, the variable, the four scripts, Docker and reuse); AGENTS.md: why isolation is off, why a module-level memo in `src/testing` is legitimate, the speed rules |

Gate B: all five commands green on all four dialects, wall time per dialect recorded. Commit.

### Review, fix, gate

- **Reviewer 1 (Fable), adversarial on correctness.** Can any dialect break exactly-once
  consumption, the reclaim lock, uniqueness under `utf8mb4_bin`/`ascii_bin`, or rollback? Can a
  MySQL write-then-read return a row another connection changed between the two statements? Do
  InnoDB gap locks deadlock the concurrent-consume test? Does any dialect's timing differ in a way
  that touches the no-enumeration guarantee? Is decision 10 actually true — read the pg SQL before
  and after? Reads the better-auth history in `phase1.md` § Part C for the bug classes.
- **Reviewer 2 (Fable), conventions and support definition.** No sixth cast, no new `sql.unsafe`,
  no `Math.random`/`Date` outside `Clock`/`Crypto`, service keys unchanged, `@since`/`@category` on
  every export, suppression list unchanged or justified, the A4 `.d.ts` diff, the speed rules,
  `db-expansion.md` § "Support definition" met for each dialect, docs match code.
- **Fixers (Opus ×2), findings routed by path.** Fixer 1: `src/sql/**`, `test/sql/**`,
  `test/fields/**`. Fixer 2: plugins, `src/testing/**`, `test/testing/**`, docs, CI.
- **Gate C**, then the **final reviewer (Fable)**: refutes the support claim per dialect, runs all
  four suites itself, and reports the branch's CI per-job wall time.

## Definition of done for the wave

`REFACTOR.md` §6 for every change, plus: all four suites green locally and in CI; the `.d.ts` of
`effect-auth` unchanged by A4 and changed only by the testing types afterwards; `CHANGELOG.md` and
SPEC Amendment 20 written; the support definition in `db-expansion.md` met for PostgreSQL, SQLite
and MySQL; the pglite CI job under two minutes.
