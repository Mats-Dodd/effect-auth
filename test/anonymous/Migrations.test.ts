import { assert, describe, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { migrations, table } from "../../src/anonymous/Migrations.js"
import * as AnonymousTest from "../../src/testing/AnonymousTest.js"
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

describe.sequential("anonymous/Migrations", () => {
  layer(AnonymousTest.layer())("the plugin's own table", (it) => {
    it("numbers its migrations from 0001 in a bookkeeping table of its own", () => {
      assert.strictEqual(table, "effect_auth_anonymous_migrations")
      assert.deepStrictEqual(Object.keys(migrations), ["0001_create_anonymous"])
    })

    it.effect("creates effect_auth_anonymous as a marker keyed by the person", () =>
      Effect.gen(function* () {
        const columns = yield* columnsOf("effect_auth_anonymous")
        assert.deepStrictEqual(
          columns.map((column) => column.column_name),
          ["created_at", "last_seen_at", "user_id"]
        )
        // Nothing here may be absent: the row's *existence* is the whole of the
        // fact it records, and the sweep reads both timestamps.
        assert.deepStrictEqual(
          columns.map((column) => column.is_nullable),
          ["NO", "NO", "NO"]
        )
        assert.strictEqual(columns.find((column) => column.column_name === "user_id")?.character_maximum_length, 36)
      })
    )

    it.effect("indexes what the sweep scans by", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const indexes = yield* sql<{ readonly indexname: string }>`
          SELECT indexname FROM pg_indexes WHERE tablename = 'effect_auth_anonymous' ORDER BY indexname`
        assert.deepStrictEqual(
          indexes.map((index) => index.indexname),
          ["effect_auth_anonymous_last_seen_at_idx", "effect_auth_anonymous_pkey"]
        )
      })
    )

    it.effect("takes the marker with the person, so a deleted visitor is not still anonymous", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const email = uniqueEmail()
        yield* sql`
          INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
          VALUES ('cascade-anon', 'Anonymous', ${email}, false, NULL, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`
        yield* sql`INSERT INTO effect_auth_anonymous (user_id, created_at, last_seen_at)
          VALUES ('cascade-anon', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`

        yield* sql`DELETE FROM users WHERE id = 'cascade-anon'`
        const left = yield* sql<{
          readonly user_id: string
        }>`SELECT user_id FROM effect_auth_anonymous WHERE user_id = 'cascade-anon'`
        assert.strictEqual(left.length, 0)
      })
    )

    it.effect("adds no is_anonymous column to any core table", () =>
      Effect.gen(function* () {
        // The decision phase 1 locked: a marker table, never a column on
        // `users`. Adoption is a DELETE, which no UPDATE on a shared row can be
        // rolled back around.
        for (const core of ["users", "sessions", "accounts", "verifications"]) {
          const names = (yield* columnsOf(core)).map((column) => column.column_name)
          assert.isFalse(
            names.some((name) => name.includes("anonymous")),
            `${core} has no anonymous column`
          )
          assert.isFalse(names.includes("is_anonymous"), `${core} has no is_anonymous column`)
        }
      })
    )
  })
})
