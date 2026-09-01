import { assert, describe, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import * as UsernameTest from "../../src/testing/UsernameTest.js"
import { migrations, table } from "../../src/username/Migrations.js"
import { uniqueEmail } from "../fixtures.js"

interface ColumnRow {
  readonly column_name: string
  readonly data_type: string
  readonly is_nullable: string
  readonly character_maximum_length: number | null
}

const columnsOf = Effect.fnUntraced(function* (name: string) {
  const sql = yield* SqlClient.SqlClient
  const rows = yield* sql<ColumnRow>`
    SELECT column_name, data_type, is_nullable, character_maximum_length
    FROM information_schema.columns
    WHERE table_name = ${name}
    ORDER BY column_name`
  return rows
})

describe.sequential("username/Migrations", () => {
  layer(UsernameTest.layer())("the plugin's own table", (it) => {
    it("numbers its migrations from 0001 in a bookkeeping table of its own", () => {
      // A plugin that merged into this library's record would be one
      // renumbering away from a migration that silently never runs.
      assert.strictEqual(table, "effect_auth_username_migrations")
      assert.deepStrictEqual(Object.keys(migrations), ["0001_create_usernames"])
    })

    it.effect("creates effect_auth_usernames with both PRECIS forms, and nothing nullable", () =>
      Effect.gen(function* () {
        const columns = yield* columnsOf("effect_auth_usernames")
        assert.deepStrictEqual(
          columns.map((column) => column.column_name),
          ["created_at", "user_id", "username", "username_key"]
        )
        // A username is never absent from its own row: the key is the primary
        // key, and the display form is what the key was folded from.
        assert.deepStrictEqual(
          columns.map((column) => column.is_nullable),
          ["NO", "NO", "NO", "NO"]
        )
      })
    )

    it.effect("bounds every id and name, so the MySQL port stays mechanical", () =>
      Effect.gen(function* () {
        const columns = yield* columnsOf("effect_auth_usernames")
        const width = (name: string) => columns.find((column) => column.column_name === name)?.character_maximum_length
        // MySQL cannot index an unbounded text column, and all three of these
        // are indexed.
        assert.strictEqual(width("username_key"), 64)
        assert.strictEqual(width("username"), 64)
        assert.strictEqual(width("user_id"), 36)
      })
    )

    it.effect("makes the key the identity and the holder unique", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const indexes = yield* sql<{ readonly indexname: string }>`
          SELECT indexname FROM pg_indexes WHERE tablename = 'effect_auth_usernames' ORDER BY indexname`
        assert.deepStrictEqual(
          indexes.map((index) => index.indexname),
          ["effect_auth_usernames_pkey", "effect_auth_usernames_user_id_unique"]
        )
      })
    )

    it.effect("takes the row with the person, so a deleted user leaves no name behind", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const email = uniqueEmail()
        const rows = yield* sql<{ readonly id: string }>`
          INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
          VALUES ('cascade-user', 'Ada', ${email}, false, NULL, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')
          RETURNING id`
        const userId = rows[0]!.id
        yield* sql`INSERT INTO effect_auth_usernames (username_key, username, user_id, created_at)
          VALUES ('ada', 'Ada', ${userId}, '2026-01-01T00:00:00.000Z')`

        yield* sql`DELETE FROM users WHERE id = ${userId}`
        // ON DELETE CASCADE, not a dangling row a later claim would collide
        // with: the name is free again the moment the person is gone.
        const left = yield* sql<{ readonly username_key: string }>`
          SELECT username_key FROM effect_auth_usernames WHERE username_key = 'ada'`
        assert.strictEqual(left.length, 0)
      })
    )

    it.effect("adds no column to any core table", () =>
      Effect.gen(function* () {
        // The one rule a plugin may not break.
        for (const core of ["users", "sessions", "accounts", "verifications"]) {
          const names = (yield* columnsOf(core)).map((column) => column.column_name)
          assert.isFalse(
            names.some((name) => name.includes("username")),
            `${core} has no username column`
          )
        }
      })
    )
  })
})
