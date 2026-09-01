import { assert, describe, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { migrations, table } from "../../src/passkeys/Migrations.js"
import * as PasskeysTest from "../../src/testing/PasskeysTest.js"

interface ColumnRow {
  readonly column_name: string
  readonly data_type: string
  readonly is_nullable: string
}

const columnsOf = Effect.fnUntraced(function* (name: string) {
  const sql = yield* SqlClient.SqlClient
  const rows = yield* sql<ColumnRow>`
    SELECT column_name, data_type, is_nullable
    FROM information_schema.columns
    WHERE table_name = ${name}
    ORDER BY column_name`
  return rows
})

describe.sequential("passkeys/Migrations", () => {
  layer(PasskeysTest.layer())("the plugin's own tables", (it) => {
    it("numbers its migrations from 0001 in a bookkeeping table of its own", () => {
      // A plugin that merged into this library's record would be one
      // renumbering away from a migration that silently never runs.
      assert.strictEqual(table, "effect_auth_passkey_migrations")
      assert.deepStrictEqual(Object.keys(migrations), ["0001_create_passkeys", "0002_create_passkey_users"])
    })

    it.effect("creates effect_auth_passkeys with every column the model reads", () =>
      Effect.gen(function* () {
        const columns = yield* columnsOf("effect_auth_passkeys")
        assert.deepStrictEqual(
          columns.map((column) => column.column_name),
          [
            "aaguid",
            "backed_up",
            "backup_eligible",
            "created_at",
            "credential_id",
            "id",
            "last_used_at",
            "name",
            "public_key",
            "sign_count",
            "transports",
            "user_id",
            "uv_initialised"
          ]
        )
        const nullable = columns.filter((column) => column.is_nullable === "YES").map((column) => column.column_name)
        // Exactly two things a credential may not have: a name, and a last use.
        assert.deepStrictEqual(nullable, ["last_used_at", "name"])
      })
    )

    it.effect("creates effect_auth_passkey_users, whose whole purpose is the handle", () =>
      Effect.gen(function* () {
        const columns = yield* columnsOf("effect_auth_passkey_users")
        assert.deepStrictEqual(
          columns.map((column) => column.column_name),
          ["handle", "user_id"]
        )
        assert.deepStrictEqual(
          columns.map((column) => column.is_nullable),
          ["NO", "NO"]
        )
      })
    )

    it.effect("makes a credential id unique across the whole table, not per user", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const indexes = yield* sql<{ readonly indexname: string }>`
          SELECT indexname FROM pg_indexes WHERE tablename = 'effect_auth_passkeys' ORDER BY indexname`
        assert.deepStrictEqual(
          indexes.map((index) => index.indexname),
          ["effect_auth_passkeys_credential_id_unique", "effect_auth_passkeys_pkey", "effect_auth_passkeys_user_id_idx"]
        )
      })
    )

    it.effect("adds no column to any core table", () =>
      Effect.gen(function* () {
        // The one rule a plugin may not break. `users`, `sessions`, `accounts`
        // and `verifications` are this library's, and a passkey lives in
        // neither of them.
        for (const core of ["users", "sessions", "accounts", "verifications"]) {
          const columns = yield* columnsOf(core)
          const names = columns.map((column) => column.column_name)
          assert.isFalse(
            names.some((name) => name.includes("passkey")),
            `${core} has no passkey column`
          )
          assert.isFalse(
            names.some((name) => name.includes("credential_id")),
            `${core} has no credential column`
          )
        }
      })
    )
  })
})
