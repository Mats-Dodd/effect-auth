# Database Expansion: PostgreSQL, SQLite, and MySQL

## Status

Design plan. This document describes the work required to make `effect-auth` fully and continuously tested against PostgreSQL, SQLite, and MySQL.

MS SQL and non-relational databases are explicitly out of scope.

## Goals

- Support PostgreSQL, SQLite, and MySQL through Effect SQL's native clients.
- Run one behavioral persistence contract against all three databases.
- Preserve the domain Store interfaces and keep database differences internal to the SQL implementation.
- Preserve the atomicity and concurrency guarantees on which authentication depends.
- Keep PostgreSQL and SQLite on their direct `RETURNING` path while giving MySQL a deliberate fallback.
- Make migrations, custom user fields, indexes, booleans, transactions, and error classification part of the support claim.
- Let developers run one dialect locally while CI runs the complete matrix.

## Non-goals

- A public ORM-style database adapter API.
- Prisma, Drizzle, or Kysely integration in core.
- MS SQL support.
- Hiding every SQL difference behind one universal query language.
- Replacing the domain persistence seam.

Applications that need a non-SQL backend or a substantially different persistence implementation can already provide `UserStore`, `SessionStore`, `AccountStore`, `VerificationStore`, and `WithAuthTransaction` themselves.

## Why the current architecture is already a good fit

The library has two useful boundaries:

1. Domain services depend on Store interfaces rather than SQL.
2. `SqlStores` depends on the generic `SqlClient.SqlClient` service rather than a concrete driver.

Effect SQL already defines the driver abstraction. The supported deployment supplies one of:

- `@effect/sql-pg`
- `@effect/sql-sqlite-node`
- `@effect/sql-mysql2`

Each driver layer provides the generic `SqlClient`, so `effect-auth` should not know about pools, sockets, connection acquisition, or driver configuration. Database expansion is therefore a portability and testing project, not a persistence redesign.

## Effect primitives to use

### `SqlClient.SqlClient`

The ambient generic client remains the only SQL requirement of `SqlStores` and `Migrations`.

### `sql.onDialect` and `sql.onDialectOrElse`

Dialect decisions should use Effect SQL's own dialect discriminator. Unsupported dialects should fail explicitly rather than silently inheriting PostgreSQL behavior.

```ts
const implementation = sql.onDialectOrElse({
  pg: () => postgres,
  sqlite: () => sqlite,
  mysql: () => mysql,
  orElse: () => unsupported
})
```

Dialect selection should happen in a few internal constructors, not be scattered through every Store method.

### Dialect-aware statement construction

Continue using tagged SQL templates and their bound parameters. Prefer Effect SQL's structural helpers:

- `sql(identifier)` for escaped identifiers
- `sql.insert(record)`
- `sql.update(record)`
- `sql.and(fragments)`
- `sql.or(fragments)`

Avoid constructing identifiers with `sql.literal` or interpolating them into `sql.unsafe`. This is especially important for custom user fields and reserved words.

### `SqlSchema`

Continue using `SqlSchema.findOne`, `findOneOption`, and `findAll` for request encoding and result decoding. MySQL fallback reads and `ROW_COUNT()` results should be decoded at this boundary too; raw driver-shaped values should not enter the domain.

### `SqlClient.withTransaction`

This is the key MySQL primitive. It:

- reserves one connection;
- propagates it through the Effect context;
- commits on success;
- rolls back on failure or interruption; and
- uses savepoints for nested transactions.

No connection needs to be passed manually between an update and its fallback select. A Store operation can safely call `withTransaction` even when a domain workflow already runs inside `WithAuthTransaction`; Effect SQL turns the inner transaction into a savepoint.

### `Migrator`

`Migrator` continues to own migration ordering, bookkeeping, and transaction execution. The migration statements still need portable DDL, but the library should not build another migration runner.

### `SqlModel`

`SqlModel.makeRepository` demonstrates Effect SQL's own MySQL write-then-read pattern. It is useful reference material, but it is not a replacement for `SqlStores`: Effect Auth has application-generated IDs, custom projections, encrypted provider tokens, joined session reads, and atomic verification consumption.

## Current portability gaps

### Real database coverage

The current SQL suites use PGlite. That exercises PostgreSQL semantics but does not prove support for:

- the real PostgreSQL driver;
- an actual SQLite client and its transaction behavior; or
- MySQL.

SQLite boolean conversion has unit coverage, but the Store and migration contracts do not currently run on SQLite.

### Mutation results

`SqlStores` uses raw `RETURNING` clauses for inserts, updates, and deletes. PostgreSQL and modern SQLite support these. MySQL does not support general `RETURNING`.

### Locks

PostgreSQL and MySQL support `SELECT ... FOR UPDATE`. SQLite does not, but `@effect/sql-sqlite-node` starts writable transactions with `BEGIN IMMEDIATE`, serializing writers and avoiding read-to-write lock upgrades.

### DDL types

The current schema uses `text` for IDs and indexed values. That is valid in PostgreSQL and SQLite but not a suitable MySQL definition for primary keys and indexes. MySQL needs bounded string columns for these values.

### Conditional DDL and introspection

`CREATE INDEX IF NOT EXISTS`, `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, and column introspection vary across the three databases. `forUserFields` currently contains PostgreSQL and SQLite implementations only.

### SQLite foreign keys

`@effect/sql-sqlite-node` provides serialized access, WAL, busy handling, and `BEGIN IMMEDIATE`, but foreign-key enforcement must still be enabled with:

```sql
PRAGMA foreign_keys = ON
```

The deployment recipe and test layer must do this explicitly.

## Internal implementation shape

Do not begin with a large public `DatabaseAdapter`. Add a small set of private operation helpers around the places where SQL semantics genuinely differ:

```ts
insertAndRead(...)
updateAndRead(...)
deleteAndCount(...)
deleteAndRead(...)
consumeVerification(...)
```

The helpers may share a small internal strategy value if that makes their construction clearer. The Store APIs and domain models remain unchanged.

PostgreSQL and SQLite should continue sharing direct `RETURNING` implementations. MySQL should be selected explicitly and use transactions where a mutation must be followed by another statement.

## Mutation semantics

### Inserts

All Effect Auth IDs are generated by the application before insertion. MySQL therefore does not need `LAST_INSERT_ID()` or driver-generated-key behavior.

PostgreSQL and SQLite:

```sql
INSERT INTO users (...) VALUES (...) RETURNING ...;
```

MySQL, on one transaction connection:

```sql
INSERT INTO users (...) VALUES (...);
SELECT ... FROM users WHERE id = ?;
```

The select by a known unique ID gives deterministic behavior and avoids Better Auth's generic inserted-row discovery problem.

### Updates

PostgreSQL and SQLite:

```sql
UPDATE users SET ... WHERE id = ? RETURNING ...;
```

MySQL, transactionally:

```sql
UPDATE users SET ... WHERE id = ?;
SELECT ... FROM users WHERE id = ?;
```

The select returns `None` when no row remains. Running both statements in `withTransaction` prevents another connection from interleaving with the operation where a consistent returned snapshot matters.

### Deletes returning a count

PostgreSQL and SQLite can continue counting returned IDs.

For MySQL, execute the mutation and read the connection-local count inside one transaction:

```sql
DELETE FROM sessions WHERE user_id = ?;
SELECT ROW_COUNT() AS count;
```

Although Effect statements expose `.raw` and mysql2 returns `affectedRows`, `ROW_COUNT()` is preferable here: driver result headers and casts stay out of the generic Store implementation, and the behavior can be schema-decoded and integration-tested.

### Deletes returning a boolean

Use the same count primitive and map `count > 0`.

### Atomic verification consumption

`VerificationStore.consume` is security-sensitive. Its contract is not merely "find and delete"; exactly one concurrent caller may receive a valid row.

PostgreSQL and SQLite retain the atomic statement:

```sql
DELETE FROM verifications
WHERE identifier = ?
  AND value_hash = ?
  AND expires_at > ?
RETURNING ...;
```

MySQL uses a transaction and row lock:

```sql
BEGIN;

SELECT ...
FROM verifications
WHERE identifier = ?
  AND value_hash = ?
  AND expires_at > ?
FOR UPDATE;

DELETE FROM verifications WHERE id = ?;

COMMIT;
```

If the select returns no row, the transaction returns `None` without deleting. A competing consumer waits for the lock, then observes that the row is gone. The implementation should delete by the selected primary key, not repeat a broad predicate.

This operation deserves its own dialect helper rather than being forced through a generic CRUD abstraction.

## Booleans

The model always sees JavaScript booleans.

| Database | Stored form |
|---|---|
| PostgreSQL | native `boolean` |
| SQLite | integer `0` / `1` |
| MySQL | `boolean`, represented by MySQL as `tinyint(1)` |

The existing boolean codec should become explicit for all three supported dialects. PostgreSQL passes booleans through; SQLite and MySQL encode to `0`/`1` and accept driver-returned numbers or booleans on decode. Nullable booleans must continue preserving `null` and `undefined`.

The codec applies both to built-in flags and custom user fields whose encoded schema is boolean.

## Migration design

### Logical column types

Define built-in columns in terms of logical storage roles, then map those roles per dialect. A starting point is:

| Logical role | PostgreSQL | SQLite | MySQL |
|---|---|---|---|
| ID | `text` | `text` | `varchar(64)` |
| email | `text` | `text` | `varchar(320)` |
| token hash | `text` | `text` | `varchar(64)` |
| short identity string | `text` | `text` | bounded `varchar(...)` |
| ISO timestamp | `text` | `text` | `varchar(24)` |
| boolean | `boolean` | `integer` | `boolean` / `tinyint(1)` |
| number | `double precision` | `real` | `double` |
| large unindexed text | `text` | `text` | `text` |

The exact limits for `issuer`, `account_id`, `provider_id`, names, hashes, and password fields must be decided from their schemas and expected providers before implementing MySQL DDL. Every bounded database column should have a corresponding documented application constraint where practical; otherwise an input accepted by the domain can fail only when persisted.

### Indexes

The migration implementation must create equivalent indexes on all three databases:

- unique user email;
- unique session token hash;
- session user ID;
- unique account issuer/account ID pair;
- account user ID; and
- verification identifier.

Do not assume `CREATE INDEX IF NOT EXISTS` is uniformly available. Migration records already run once, so normal migration execution need not make every statement independently idempotent. Where `forUserFields` intentionally runs on every boot, inspect metadata before altering.

### Collation and identity semantics

MySQL installations commonly default to case-insensitive collations, while PostgreSQL and SQLite text comparisons are normally case-sensitive. The schema must deliberately define semantics for:

- IDs;
- token hashes;
- OAuth issuer;
- OAuth account ID;
- provider ID; and
- email.

Opaque IDs, hashes, and OAuth identity components should not silently inherit a case-insensitive server default. Use an explicit case-sensitive/binary MySQL collation where exact identity is required. Email normalization and uniqueness must be documented and tested independently.

### Custom user fields

`forUserFields` currently infers `text`, `boolean`, or `number` from the field's encoded schema. MySQL adds two questions:

1. What maximum length should an arbitrary stored string have?
2. Can that field safely receive a default while adding it to a populated table?

The initial implementation can map custom strings to a documented bounded `varchar`, but the longer-term API should allow optional SQL storage metadata or per-field migration overrides. Type inference alone cannot express length, collation, indexing, or large-text intent.

MySQL column discovery should use `information_schema.columns`. Dynamic table and column names must use Effect SQL identifier fragments rather than raw string interpolation.

## Testing architecture

### Principle: one contract, three layers

The strongest support claim is that the exact same behavioral suite runs against each database. Do not copy a PostgreSQL test file and edit its SQL for MySQL.

Create a contract registration function:

```ts
export const sqlStoreContract = (
  name: string,
  database: Layer.Layer<SqlClient.SqlClient | TestDatabase>
) => {
  layer(makeContractLayer(database), { timeout: "90 seconds" })(name, (it) => {
    it.effect("creates and finds a user", () => withCleanDatabase(/* ... */))
    it.effect("consumes a verification exactly once", () => withCleanDatabase(/* ... */))
  })
}
```

Register it three times:

```ts
sqlStoreContract("PostgreSQL", PostgresTest.layer)
sqlStoreContract("SQLite", SqliteTest.layer)
sqlStoreContract("MySQL", MysqlTest.layer)
```

`@effect/vitest`'s `layer(...)` builds a scoped layer once, shares it across the suite through a memo map, and closes its scope after the suite. That is the right lifecycle for a database container and connection pool.

### `TestDatabase` service

The test harness needs portable operations beyond `SqlClient`. Introduce a test-only service along these lines:

```ts
interface TestDatabaseService {
  readonly dialect: "pg" | "sqlite" | "mysql"
  readonly reset: Effect.Effect<void, SqlError.SqlError>
  readonly tableNames: Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
  readonly columnNames: (table: string) => Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
  readonly indexNames: (table: string) => Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
}
```

Each harness provides `SqlClient | TestDatabase`. This keeps `information_schema`, PostgreSQL catalogs, SQLite pragmas, and reset syntax out of the common assertions.

### Scoped database layers

#### SQLite

Use the in-process Effect client:

```ts
SqliteClient.layer({ filename: ":memory:" })
```

Sequence an initialization layer that runs `PRAGMA foreign_keys = ON`, then run migrations and construct the Stores. The same client must be retained throughout the suite because an in-memory SQLite database belongs to its connection.

#### PostgreSQL

Use `@testcontainers/postgresql` and `@effect/sql-pg` for the real integration suite. PGlite can remain the fast default test deployment, but it is not a substitute for validating the real driver.

#### MySQL

Use `@testcontainers/mysql` and `@effect/sql-mysql2` with a pinned supported MySQL image.

Model container ownership with Effect:

- `Effect.acquireRelease` starts and stops the container;
- `Layer.scoped` exposes the started container;
- `Layer.unwrap` constructs the driver layer from the container's dynamic URL; and
- the client layer provides the generic `SqlClient`.

This is the same general pattern used by Effect SQL's own integration tests.

### Isolation

Do not wrap every contract test in a transaction that is rolled back afterward. The concurrency tests must use separate real transaction connections. If the entire test is already inside one transaction, child fibers inherit its connection and Effect SQL serializes their statements, turning a race test into a single-connection test.

Instead, prepend each contract case with `TestDatabase.reset` and run cases sequentially within a dialect suite.

Suggested reset behavior:

- PostgreSQL: `TRUNCATE ... CASCADE`.
- SQLite: delete in foreign-key order.
- MySQL: delete in foreign-key order.

Migration-history tests should use a fresh database or a separately scoped harness because resetting auth rows must not erase or falsify migration state.

Test data should still use unique values where a test intentionally creates concurrent work, but correctness should not depend on leftovers from sibling tests.

### Contract groups

#### Store behavior

Run identically on all three databases:

- create, read, update, and delete users;
- create, resolve, touch, list, and revoke sessions;
- create, read, update, list, and delete accounts;
- encrypted provider-token round trips;
- create, consume, and clean up verifications;
- custom user fields, including nullable booleans and defaults;
- accurate boolean and bulk-delete results;
- timestamp expiry and ordering behavior; and
- session-plus-user joined reads.

#### Error behavior

- Duplicate email is classified as `UniqueViolation`.
- Duplicate session hash is classified as `UniqueViolation`.
- Duplicate OAuth identity is classified as `UniqueViolation`.
- Foreign-key violations remain persistence failures.
- Transaction failures roll back all writes.

Effect's PostgreSQL, SQLite, and MySQL clients normalize duplicate-key errors into `SqlError` with a `UniqueViolation` reason; the contract must prove that `kindOf` observes this consistently.

#### Concurrency behavior

These tests must fork real concurrent effects rather than merely call operations in sequence:

- two registrations for one email produce one user;
- two OAuth provisioning attempts produce one identity/account;
- two valid verification consumers yield exactly one `Some`;
- account reclamation and linking preserve their lock invariants; and
- transaction rollback does not expose partial state.

The verification race is a release-blocking contract for MySQL support.

#### Migration behavior

Run against a database dedicated to each case where necessary:

- all migrations apply to an empty database;
- rerunning applies none;
- migration IDs and names remain stable;
- migration 5 adds and backfills `sessions.remember_me`;
- all required indexes exist;
- foreign-key cascades work;
- custom columns are added with the right nullability, type, and default; and
- re-running custom-field synchronization is idempotent.

Schema inspection should go through `TestDatabase`, leaving the expected schema assertions common.

#### Dialect-specific checks

Keep a small suite for facts that are intentionally different:

- SQLite stores booleans as `0`/`1` and has foreign keys enabled.
- SQLite transactions use the expected serialized-writer behavior.
- MySQL uses the intended case-sensitive collations for identity columns.
- MySQL write-then-read fallbacks return the correct row.
- MySQL `ROW_COUNT()` produces accurate delete counts.

### Fast suite versus integration suite

Keep the ordinary feedback loop fast:

- `pnpm test`: current unit, domain, HTTP, and PGlite-backed tests.
- `pnpm test:sql`: full real-database contract.
- `pnpm test:sql:pg`: PostgreSQL only.
- `pnpm test:sql:sqlite`: SQLite only.
- `pnpm test:sql:mysql`: MySQL only.

The full SQL contract should run on every pull request if CI resources allow. Authentication race semantics are important enough not to defer to a nightly build.

Use a CI matrix over `pg`, `sqlite`, and `mysql`. Separate jobs make failures obvious, run the containers in parallel, and let SQLite finish without waiting for Docker-backed siblings.

## Proposed test layout

One possible organization:

```text
test/sql-contract/
  TestDatabase.ts
  contract.ts
  stores.contract.ts
  concurrency.contract.ts
  migrations.contract.ts
  harness/
    Postgres.ts
    Sqlite.ts
    Mysql.ts
  pg.test.ts
  sqlite.test.ts
  mysql.test.ts
```

The three entry files should do little more than instantiate the same contracts with different layers.

## Delivery sequence

### Phase 1: establish the contract

1. Extract the current `SqlStores` assertions into reusable contract functions.
2. Add the `TestDatabase` service and deterministic reset behavior.
3. Preserve PGlite as the fast default while proving that the contract remains equivalent.

### Phase 2: make existing support real

1. Add `@effect/sql-sqlite-node` integration coverage.
2. Enable and test SQLite foreign keys.
3. Run Store, migration, transaction, and concurrency contracts against SQLite.
4. Add a real `@effect/sql-pg` Testcontainers layer and run the same contracts.

### Phase 3: centralize genuine dialect differences

1. Replace unsafe dynamic identifiers in migration/custom-field code.
2. Centralize boolean encoding.
3. Extract insert/update/delete-result helpers.
4. Keep PostgreSQL and SQLite behavior unchanged behind those helpers.
5. Make unsupported Effect SQL dialects fail explicitly.

### Phase 4: add MySQL migrations

1. Decide and document bounded built-in column lengths.
2. Decide and test collations.
3. Add MySQL table, index, boolean, number, and custom-field DDL.
4. Add MySQL metadata inspection for custom columns.
5. Run the migration contract against a pinned MySQL version.

### Phase 5: add MySQL Stores

1. Implement insert-then-read by application-generated ID.
2. Implement update-then-read transactions.
3. Implement delete counts with `ROW_COUNT()`.
4. Implement transactional `SELECT ... FOR UPDATE` verification consumption.
5. Run all behavioral and concurrency contracts.

### Phase 6: documentation and release contract

1. Document supported driver packages and versions.
2. Document SQLite's foreign-key initialization requirement.
3. Document MySQL collation and length choices.
4. Document the minimum SQLite and MySQL versions.
5. Add the three-dialect CI matrix as a required check.

## Support definition

A database is supported only when all of the following are true:

- its real Effect SQL driver has a documented setup;
- core migrations run from empty state and through the supported upgrade path;
- custom user fields work;
- every Store contract passes;
- unique violations are classified correctly;
- transaction rollback passes;
- the concurrent verification-consumption contract passes; and
- the database runs in required CI.

By that definition, PGlite is a valuable fast test backend but not the complete PostgreSQL support proof, and a boolean codec unit test is not the complete SQLite support proof.

## Decisions

- Supported databases: PostgreSQL, SQLite, and MySQL.
- MS SQL is out of scope.
- The public Store seam remains unchanged.
- Effect SQL remains the driver and transaction abstraction.
- PostgreSQL and SQLite retain direct `RETURNING` operations.
- MySQL receives explicit transactional mutation fallbacks.
- Verification consumption must remain exactly-once under concurrency.
- One behavioral contract runs against all three real clients.
- Testcontainers owns PostgreSQL and MySQL integration lifecycles.
- SQLite runs in process with foreign keys explicitly enabled.
- Test isolation uses reset operations, not a transaction around every test.
- The complete three-dialect matrix is part of the release contract.
