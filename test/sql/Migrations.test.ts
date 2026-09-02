/**
 * The migrator, on whichever database `EFFECT_AUTH_TEST_DATABASE` names.
 *
 * **Details**
 *
 * Two kinds of case live here. The first is about migration *history* — what
 * applying, re-applying or arriving late at a table does — and each of those
 * needs a database whose whole history is its own, so it gets a `layer()` block
 * and therefore a build of the provider of its own. `TestDatabase.reset` cannot
 * serve them: it preserves the bookkeeping tables by design, which is exactly
 * what those cases are asserting about.
 *
 * The second is about the schema the migrations leave behind, and shares one
 * already-migrated database. Nothing in either kind reads a catalog directly:
 * table, column and index names come from {@link Database.TestDatabase}, which
 * is where `information_schema`, `pg_catalog` and `PRAGMA` are allowed to live.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { AccountStore, SessionStore, UserStore } from "../../src/domain/Stores.js"
import { booleanCodec } from "../../src/sql/Dialect.js"
import * as Migrations from "../../src/sql/Migrations.js"
import * as Database from "../../src/testing/Database.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, uniqueEmail } from "../fixtures.js"
import { createOauthAccount, createSession, createUser, unique } from "./helpers.js"

const migrationIds = [1, 2, 3, 4, 5, 6]

const migrationNames = [
  "create_users",
  "create_sessions",
  "create_accounts",
  "create_verifications",
  "session_remember_me",
  "session_assurance"
]

/**
 * A database per case, as each of the history cases needs.
 *
 * "applies every migration to an empty database" and "is idempotent on a second
 * run" are both statements about a database whose whole history is the case's
 * own, so they cannot share one: a sibling that had already migrated would make
 * either of them pass for the wrong reason. `@effect/vitest` gives each
 * top-level `layer()` block a memo map of its own, so one block per case is
 * what keeps them isolated — and under the new providers that costs a schema,
 * not an engine.
 */
const empty = Database.fromConfig

layer(empty)("sql/Migrations", (it) => {
  it.effect("applies every migration to an empty database", () =>
    Effect.gen(function* () {
      const applied = yield* Migrations.run

      assert.deepStrictEqual(
        applied.map(([id]) => id),
        migrationIds
      )
      assert.deepStrictEqual(
        applied.map(([, name]) => name),
        migrationNames
      )

      const database = yield* Database.TestDatabase
      assert.deepStrictEqual(yield* database.tableNames, [
        "accounts",
        "effect_auth_migrations",
        "sessions",
        "users",
        "verifications"
      ])
    })
  )
})

layer(empty)("sql/Migrations", (it) => {
  it.effect("is idempotent on a second run", () =>
    Effect.gen(function* () {
      yield* Migrations.run
      const second = yield* Migrations.run

      assert.deepStrictEqual(second, [])
    })
  )
})

/**
 * The `sessions` table as an existing deployment has it — every column through
 * `0004`, and none that `0005` or `0006` add.
 *
 * This is the one place in the suite that writes DDL of its own, and it is
 * dialect-shaped on purpose: it stands in for a schema an older release of this
 * library created, which is a different statement on each database. The
 * migrator's own `CREATE TABLE IF NOT EXISTS` then finds these tables and leaves
 * them alone, while `0005` and `0006` add their columns to a table that already
 * has a row in it — which is the whole point.
 *
 * It stops at `0004` rather than at `0005` because a table that already had
 * `remember_me` would only survive `0005` on a dialect with
 * `ADD COLUMN IF NOT EXISTS`, and that is an accident of PostgreSQL rather than
 * anything this test means to assert.
 */
const legacySchema = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* Database.dialect

  if (dialect === "sqlite") {
    yield* sql`CREATE TABLE users (
      id text PRIMARY KEY,
      name text NOT NULL,
      email text NOT NULL,
      email_verified integer NOT NULL DEFAULT 0,
      image text,
      created_at text NOT NULL,
      updated_at text NOT NULL
    )`
    yield* sql`CREATE TABLE sessions (
      id text PRIMARY KEY,
      token_hash text NOT NULL,
      user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
      expires_at text NOT NULL,
      ip_address text,
      user_agent text,
      created_at text NOT NULL,
      updated_at text NOT NULL
    )`
  } else if (dialect === "mysql") {
    yield* sql`CREATE TABLE users (
      id varchar(64) PRIMARY KEY,
      name text NOT NULL,
      email varchar(320) NOT NULL,
      email_verified boolean NOT NULL DEFAULT false,
      image text,
      created_at varchar(32) NOT NULL,
      updated_at varchar(32) NOT NULL
    )`
    yield* sql`CREATE TABLE sessions (
      id varchar(64) PRIMARY KEY,
      token_hash varchar(64) NOT NULL,
      user_id varchar(64) NOT NULL,
      expires_at varchar(32) NOT NULL,
      ip_address text,
      user_agent text,
      created_at varchar(32) NOT NULL,
      updated_at varchar(32) NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`
  } else {
    yield* sql`CREATE TABLE users (
      id text PRIMARY KEY,
      name text NOT NULL,
      email text NOT NULL,
      email_verified boolean NOT NULL DEFAULT false,
      image text,
      created_at text NOT NULL,
      updated_at text NOT NULL
    )`
    yield* sql`CREATE TABLE sessions (
      id text PRIMARY KEY,
      token_hash text NOT NULL,
      user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
      expires_at text NOT NULL,
      ip_address text,
      user_agent text,
      created_at text NOT NULL,
      updated_at text NOT NULL
    )`
  }
})

layer(empty)("sql/Migrations", (it) => {
  it.effect("backfills sessions.authenticated_at from created_at, and defaults the derived columns", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient

      // The row is written *before* the migration runs: what the migration does
      // to an existing row is the whole point, and it is unobservable if the row
      // is written afterwards.
      yield* legacySchema
      yield* sql`INSERT INTO users ${sql.insert({
        id: "u-assurance",
        name: "Ada",
        email: "assurance@example.com",
        image: null,
        created_at: "2024-01-01T00:00:00.000Z",
        updated_at: "2024-01-01T00:00:00.000Z"
      })}`
      yield* sql`INSERT INTO sessions ${sql.insert({
        id: "s-assurance",
        token_hash: "hash-assurance",
        user_id: "u-assurance",
        expires_at: "2999-01-01T00:00:00.000Z",
        ip_address: null,
        user_agent: null,
        created_at: "2024-03-04T05:06:07.000Z",
        updated_at: "2024-03-04T05:06:07.000Z"
      })}`

      const applied = yield* Migrations.run
      assert.include(
        applied.map(([, name]) => name),
        "session_assurance"
      )

      const dialect = yield* Database.dialect
      const rows = yield* sql<{
        readonly authenticated_at: unknown
        readonly aal: unknown
        readonly methods: unknown
        readonly remember_me: unknown
      }>`SELECT authenticated_at, aal, methods, remember_me FROM sessions WHERE id = 's-assurance'`

      // `0005` reaches the same row: a session written before the flag existed
      // reads back as remembered, which is the length it actually had.
      assert.strictEqual(booleanCodec(dialect).decode(rows[0]?.remember_me), true)

      // Before step-up existed, a session's creation *was* the moment its owner
      // authenticated, so that is what an existing row is worth — not "now",
      // which would silently re-freshen every session in the table.
      assert.strictEqual(rows[0]?.authenticated_at, "2024-03-04T05:06:07.000Z")
      assert.strictEqual(rows[0]?.aal, "aal1")
      assert.strictEqual(rows[0]?.methods, "[]")

      // The backfill left no NULL behind, which is what lets the model treat
      // the column as required on every dialect — including SQLite, where an
      // added column cannot be tightened afterwards.
      const nulls = yield* sql<{ readonly id: string }>`SELECT id FROM sessions WHERE authenticated_at IS NULL`
      assert.deepStrictEqual([...nulls], [])
    })
  )
})

const createLinks = Effect.flatMap(
  SqlClient.SqlClient,
  (sql) => sql`CREATE TABLE IF NOT EXISTS plugin_links (id text PRIMARY KEY)`
)

const plugin = Migrations.make({
  table: "effect_auth_plugin_migrations",
  migrations: { "0001_create_links": createLinks }
})

layer(empty)("sql/Migrations.make", (it) => {
  it.effect("records a plugin's migrations in a bookkeeping table of its own", () =>
    Effect.gen(function* () {
      // Sequenced, as a plugin whose tables reference this library's must be.
      yield* Migrations.run
      const applied = yield* plugin.run

      // Its numbering starts at 1 and is entirely its own business: this is
      // exactly what merging the two records would have made impossible.
      assert.deepStrictEqual(applied, [[1, "create_links"]])
      assert.deepStrictEqual(yield* plugin.run, [])

      const database = yield* Database.TestDatabase
      const bookkeeping = (yield* database.tableNames).filter((name) => name.endsWith("_migrations"))
      assert.deepStrictEqual(bookkeeping, ["effect_auth_migrations", "effect_auth_plugin_migrations"])
    })
  )
})

// -----------------------------------------------------------------------------
// The schema the migrations leave behind
// -----------------------------------------------------------------------------

layer(AuthTest.layerStores)("sql/Migrations (schema)", (it) => {
  describe("schema", () => {
    it.effect("adds the sessions.remember_me flag, defaulted so existing rows are remembered", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const sessions = yield* SessionStore
        const database = yield* Database.TestDatabase
        assert.include(yield* database.columnNames("sessions"), "remember_me")

        const user = yield* createUser(uniqueEmail("remember-default"))
        const hash = unique("hash-remember-default")

        // A row inserted without stating the flag inherits the DEFAULT, so a
        // deployment's pre-existing sessions read back as remembered rather than
        // as a NULL the model cannot decode. `authenticated_at` has no DEFAULT
        // on purpose — only the writer knows when the person actually
        // authenticated — so it is stated here, while `remember_me`, `aal` and
        // `methods` are the ones being left to theirs.
        yield* sql`INSERT INTO sessions ${sql.insert({
          id: unique("s-remember"),
          token_hash: hash,
          user_id: user.id,
          expires_at: "2999-01-01T00:00:00.000Z",
          ip_address: null,
          user_agent: null,
          authenticated_at: "2024-01-01T00:00:00.000Z",
          created_at: "2024-01-01T00:00:00.000Z",
          updated_at: "2024-01-01T00:00:00.000Z"
        })}`

        // Read through the store, so whichever way the dialect spells the flag
        // it is a boolean by the time the assertion sees it.
        const found = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the session")
        assert.strictEqual(found.session.rememberMe, true)
        assert.strictEqual(found.session.aal, "aal1")
        assert.deepStrictEqual(found.session.methods, [])
      })
    )

    it.effect("creates the indexes the stores rely on", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase

        // By name, per table: an index the stores rely on that a dialect quietly
        // failed to create is a full table scan on the request hot path.
        const expected = {
          users: ["users_email_unique"],
          sessions: ["sessions_token_hash_unique", "sessions_user_id_idx"],
          accounts: ["accounts_issuer_account_id_unique", "accounts_user_id_idx"],
          verifications: ["verifications_identifier_idx"]
        }

        for (const [table, names] of Object.entries(expected)) {
          const present = yield* database.indexNames(table)
          for (const name of names) {
            assert.include(present, name, `${table} is missing ${name}`)
          }
        }
      })
    )

    it.effect("cascades a deleted user's sessions and accounts away", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const sessions = yield* SessionStore
        const accounts = yield* AccountStore
        const user = yield* createUser(uniqueEmail("cascade"))
        const hash = unique("hash-cascade")
        yield* createSession(user.id, hash, Duration.days(1))
        yield* createOauthAccount(user.id, "github", unique("gh-cascade"))

        assert.strictEqual(yield* users.delete(user.id), true)

        // The foreign keys are `ON DELETE CASCADE`, and on SQLite that only
        // means anything with the pragma on — so this is where a provider that
        // forgot it would be caught.
        assert.isTrue(Option.isNone(yield* sessions.findByTokenHash(hash)))
        assert.strictEqual(yield* accounts.countByUserId(user.id), 0)
      })
    )

    it.effect("records every migration it applied, in order", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const rows = yield* sql<{
          readonly name: string
        }>`SELECT name FROM effect_auth_migrations ORDER BY migration_id`
        assert.deepStrictEqual(
          rows.map((row) => row.name),
          migrationNames
        )
      })
    )
  })
})
