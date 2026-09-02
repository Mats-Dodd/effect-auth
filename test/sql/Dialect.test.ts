/**
 * The facts that are deliberately different on each database.
 *
 * **Details**
 *
 * Every other file under `test/sql/` is written so that it cannot tell which
 * dialect it is running on. This one is the exception, and it is the only one:
 * a divergence that is not asserted here is a divergence nobody decided on.
 *
 * Each case reads {@link Database.dialect} and asserts only where the fact
 * applies — the cases that do not apply are a no-op rather than a skip, so the
 * file's shape is the same on every dialect and the reason a fact is absent is
 * written down beside it.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Fiber, Latch } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { oauthIssuer } from "../../src/domain/Schema.js"
import { AccountStore, SessionStore, UserStore, WithAuthTransaction } from "../../src/domain/Stores.js"
import { columnType } from "../../src/sql/Dialect.js"
import * as Database from "../../src/testing/Database.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, uniqueEmail } from "../fixtures.js"
import { createOauthAccount, createSession, createUser, unique } from "./helpers.js"

/**
 * Runs `effect` only on the dialects the fact is about.
 *
 * A no-op rather than `it.skip`: which dialects a fact holds on is a property of
 * the fact, and belongs beside it rather than in a runner's configuration.
 */
const on = <A, E, R>(
  dialects: ReadonlyArray<Database.Dialect>,
  effect: Effect.Effect<A, E, R>
): Effect.Effect<void, E, R | Database.TestDatabase> =>
  Effect.flatMap(Database.dialect, (dialect) => (dialects.includes(dialect) ? Effect.asVoid(effect) : Effect.void))

layer(AuthTest.layerStores)("sql/Dialect", (it) => {
  describe("boolean storage", () => {
    it.effect("stores a flag as the dialect's own boolean, and reads it back as one", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const users = yield* UserStore
        const dialect = yield* Database.dialect

        const verified = yield* createUser(uniqueEmail("flag-true"), true)
        const unverified = yield* createUser(uniqueEmail("flag-false"), false)

        const raw = yield* sql<{ readonly id: string; readonly email_verified: unknown }>`SELECT id, email_verified
          FROM users WHERE id IN (${verified.id}, ${unverified.id})`
        const stored = new Map(raw.map((row) => [row.id, row.email_verified]))

        // PostgreSQL has a real boolean; SQLite has no boolean type at all and
        // MySQL's is an alias for `tinyint(1)` — both hand back a number. This
        // is the divergence the boolean codec exists for.
        if (dialect === "pg") {
          assert.strictEqual(stored.get(verified.id), true)
          assert.strictEqual(stored.get(unverified.id), false)
        } else {
          assert.strictEqual(stored.get(verified.id), 1)
          assert.strictEqual(stored.get(unverified.id), 0)
        }

        // Whatever is in the column, the store answers with a boolean.
        const read = yield* expectSome(yield* users.findById(verified.id), "expected the verified user")
        assert.strictEqual(read.emailVerified, true)
      })
    )
  })

  describe("sqlite", () => {
    it.effect("has foreign keys switched on", () =>
      on(
        ["sqlite"],
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          // SQLite enforces no foreign key unless the connection asks it to, and
          // a connection that forgot would silently keep orphaned sessions.
          const rows = yield* sql<{ readonly foreign_keys: number }>`PRAGMA foreign_keys`
          assert.strictEqual(rows[0]?.foreign_keys, 1)
        })
      )
    )

    it.effect("serialises two writers rather than losing one's update", () =>
      on(
        ["sqlite"],
        Effect.gen(function* () {
          const users = yield* UserStore
          const transaction = yield* WithAuthTransaction
          const user = yield* createUser(uniqueEmail("sqlite-writers"))
          yield* users.update(user.id, { name: "0" })

          // SQLite has no `FOR UPDATE`; `BEGIN IMMEDIATE` is what stands in for
          // it, and this is the guarantee that buys: a read-modify-write in a
          // transaction cannot interleave with another one.
          const increment = transaction.run(
            Effect.gen(function* () {
              const current = yield* expectSome(yield* users.findById(user.id), "expected the user")
              yield* users.update(user.id, { name: String(Number(current.name) + 1) })
            })
          )

          const left = yield* Effect.forkChild(increment)
          const right = yield* Effect.forkChild(increment)
          yield* Fiber.join(left)
          yield* Fiber.join(right)

          const final = yield* expectSome(yield* users.findById(user.id), "expected the user")
          assert.strictEqual(final.name, "2")
        })
      )
    )
  })

  describe("mysql", () => {
    it.effect("gives every indexed identity column a binary collation", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          // An identity that inherited the server's default collation would
          // compare case-insensitively, and `ada@example.com` and
          // `Ada@Example.com` would be one row on MySQL and two everywhere else.
          const rows = yield* sql<{
            readonly TABLE_NAME: string
            readonly COLUMN_NAME: string
            readonly COLLATION_NAME: string | null
          }>`SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND (
                (TABLE_NAME = 'users' AND COLUMN_NAME IN ('id', 'email'))
                OR (TABLE_NAME = 'sessions' AND COLUMN_NAME IN ('id', 'token_hash', 'user_id'))
                OR (TABLE_NAME = 'accounts' AND COLUMN_NAME IN ('id', 'issuer', 'account_id', 'user_id'))
                OR (TABLE_NAME = 'verifications' AND COLUMN_NAME IN ('id', 'identifier', 'value_hash'))
              )`

          assert.strictEqual(rows.length, 12)
          for (const row of rows) {
            assert.isTrue(
              row.COLLATION_NAME === "ascii_bin" || row.COLLATION_NAME === "utf8mb4_0900_bin",
              `${row.TABLE_NAME}.${row.COLUMN_NAME} is ${String(row.COLLATION_NAME)}`
            )
          }
        })
      )
    )

    it.effect("declares a character set on its unbounded text columns too", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          // A bare `text` inherits the *database's* default character set, not
          // the server's and not the column's role. A database created
          // `CHARACTER SET latin1` — which a legacy configuration still does —
          // then refuses `INSERT … 'Zoë 😀'` with error 1366 on MySQL and on no
          // other dialect. Stating the character set on every string column is
          // what makes this schema independent of how the database was made.
          const rows = yield* sql<{
            readonly TABLE_NAME: string
            readonly COLUMN_NAME: string
            readonly CHARACTER_SET_NAME: string | null
          }>`SELECT TABLE_NAME, COLUMN_NAME, CHARACTER_SET_NAME
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND DATA_TYPE = 'text'`

          assert.isAbove(rows.length, 0)
          for (const row of rows) {
            assert.strictEqual(
              row.CHARACTER_SET_NAME,
              "utf8mb4",
              `${row.TABLE_NAME}.${row.COLUMN_NAME} is ${String(row.CHARACTER_SET_NAME)}`
            )
          }
        })
      )
    )

    it.effect("stores an emoji in a text column whatever the surrounding default charset is", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          const users = yield* UserStore
          // From the outside, on the real schema: `users.name` is the `text`
          // role and a four-byte character has to survive it.
          const user = yield* createUser(uniqueEmail("mysql-utf8mb4"))
          const updated = yield* expectSome(
            yield* users.update(user.id, { name: "Zoë 😀" }),
            "expected the updated user"
          )
          assert.strictEqual(updated.name, "Zoë 😀")

          // And where it would actually bite. The test database is `utf8mb4`,
          // so a bare `text` inherits the right character set here by luck; a
          // `latin1` table is the standing proof that the *column* states it,
          // and it is the case a bare `text` fails with error 1366.
          yield* sql`CREATE TABLE effect_auth_charset_probe (
            value ${sql.literal(columnType("mysql", "text"))}
          ) DEFAULT CHARSET=latin1`
          const written = yield* Effect.result(
            sql`INSERT INTO effect_auth_charset_probe ${sql.insert({ value: "Zoë 😀" })}`
          )
          const rows = yield* sql<{ readonly value: string }>`SELECT value FROM effect_auth_charset_probe`
          yield* sql`DROP TABLE effect_auth_charset_probe`

          assert.strictEqual(written._tag, "Success")
          assert.deepStrictEqual([...rows], [{ value: "Zoë 😀" }])
        })
      )
    )

    it.effect("bounds the credential role at the longest credential id WebAuthn allows", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient
          // WebAuthn allows a raw credential id of up to 1023 bytes, and what
          // this library stores is simplewebauthn's base64url spelling of it —
          // 1364 characters at that size. A bound below that registers an
          // authenticator on PostgreSQL and SQLite and refuses it on MySQL with
          // "Data too long for column credential_id", which is a
          // `PersistenceError` at the end of a passkey registration.
          const longest = "A".repeat(1364)
          yield* sql`CREATE TABLE effect_auth_credential_probe (
            value ${sql.literal(columnType("mysql", "credential"))} NOT NULL,
            UNIQUE (value)
          )`
          const written = yield* Effect.result(
            sql`INSERT INTO effect_auth_credential_probe ${sql.insert({ value: longest })}`
          )
          const rows = yield* sql<{ readonly value: string }>`SELECT value FROM effect_auth_credential_probe`
          yield* sql`DROP TABLE effect_auth_credential_probe`

          // The unique index over it has to stay inside InnoDB's 3072-byte key
          // limit, which the `ascii` character set is what buys.
          assert.strictEqual(written._tag, "Success")
          assert.strictEqual(rows[0]?.value, longest)
        })
      )
    )

    it.effect("reads back the row it has just written", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const users = yield* UserStore
          // MySQL has no `RETURNING`, so an insert is followed by a select on
          // the same transaction connection. What comes back must be the row
          // that was written, not the row as it was before.
          const email = uniqueEmail("mysql-write-read")
          const created = yield* createUser(email, true)
          assert.strictEqual(created.email, email)
          assert.strictEqual(created.emailVerified, true)

          const reread = yield* expectSome(yield* users.findById(created.id), "expected the user")
          assert.strictEqual(reread.id, created.id)
          assert.strictEqual(reread.emailVerified, created.emailVerified)

          const updated = yield* expectSome(
            yield* users.update(created.id, { name: "Ada L." }),
            "expected the updated user"
          )
          assert.strictEqual(updated.name, "Ada L.")
        })
      )
    )

    it.effect("never lets a transaction commit after InnoDB has rolled it back", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const users = yield* UserStore
          const transaction = yield* WithAuthTransaction
          const one = yield* createUser(uniqueEmail("mysql-deadlock-one"))
          const two = yield* createUser(uniqueEmail("mysql-deadlock-two"))

          const oneReady = yield* Latch.make(false)
          const twoReady = yield* Latch.make(false)

          /**
           * Two transactions that take each other's row in the opposite order,
           * each recovering whatever its second write failed with and carrying
           * on — a hook that logs and continues, a store call wrapped in
           * `Effect.result`.
           *
           * MySQL answers the loser of that race with `ER_LOCK_DEADLOCK`, and
           * InnoDB's answer to a deadlock is to roll back the *whole*
           * transaction rather than the statement. From that instant the
           * connection is out of the transaction and in autocommit: everything
           * the body did before the deadlock is gone and everything it does
           * after lands permanently, so the `COMMIT` at the end would report
           * success over half a body. PostgreSQL poisons the transaction
           * instead — the next statement fails — and SQLite serialises writers
           * rather than deadlocking them, which is why this is a MySQL case.
           *
           * The latches are safe here because MySQL is a real server with a
           * connection each; on a one-connection backend two bodies cannot be
           * open at once and this shape would wait for ever, which is the other
           * reason it lives under `on(["mysql"])`.
           */
          const cross = (
            first: typeof one,
            second: typeof one,
            label: string,
            ready: Latch.Latch,
            other: Latch.Latch
          ) =>
            Effect.gen(function* () {
              const swallowed: Array<unknown> = []
              const run = yield* Effect.result(
                transaction.run(
                  Effect.gen(function* () {
                    yield* users.update(first.id, { name: label })
                    yield* ready.open
                    yield* other.await
                    const inner = yield* Effect.result(users.update(second.id, { name: label }))
                    if (inner._tag === "Failure") swallowed.push(inner.failure)
                    yield* users.update(first.id, { image: label })
                  })
                )
              )
              return { run, swallowed } as const
            })

          const left = yield* Effect.forkChild(cross(one, two, "one", oneReady, twoReady))
          const right = yield* Effect.forkChild(cross(two, one, "two", twoReady, oneReady))
          const outcomes = [yield* Fiber.join(left), yield* Fiber.join(right)] as const

          // One of them has to have lost, or the case proves nothing.
          assert.strictEqual(
            outcomes.filter((outcome) => outcome.swallowed.length > 0).length,
            1,
            "expected exactly one of the two transactions to deadlock"
          )

          for (const [index, outcome] of outcomes.entries()) {
            if (outcome.swallowed.length > 0) {
              // The guarantee: a transaction that saw a storage failure does not
              // get to say it committed. `WithAuthTransaction` proves the
              // transaction is still there before it commits, with a savepoint
              // of its own that an implicit rollback takes with it.
              assert.strictEqual(
                outcome.run._tag,
                "Failure",
                `fiber ${index} swallowed ${String(outcome.swallowed[0])} and still reported success`
              )
            }
          }

          // And the other direction, so the case cannot pass by failing
          // everything: the one that committed has its last write in the row.
          const winner = outcomes.findIndex((outcome) => outcome.run._tag === "Success")
          assert.notStrictEqual(winner, -1, "expected one of the two transactions to commit")
          const row = yield* expectSome(yield* users.findById(winner === 0 ? one.id : two.id), "expected the user")
          assert.strictEqual(row.image, winner === 0 ? "one" : "two")
        })
      )
    )

    it.effect("counts the rows a delete removed", () =>
      on(
        ["mysql"],
        Effect.gen(function* () {
          const sessions = yield* SessionStore
          // `DELETE … RETURNING id` becomes `ROW_COUNT()` on MySQL, and a count
          // read on the wrong connection would answer for another statement.
          const user = yield* createUser(uniqueEmail("mysql-row-count"))
          yield* createSession(user.id, unique("hash-count"), Duration.days(1))
          yield* createSession(user.id, unique("hash-count"), Duration.days(1))
          yield* createSession(user.id, unique("hash-count"), Duration.days(1))

          assert.strictEqual(yield* sessions.deleteByUserId(user.id), 3)
          assert.strictEqual(yield* sessions.deleteByUserId(user.id), 0)
        })
      )
    )
  })

  describe("string comparison", () => {
    it.effect("tells two identities apart when only a trailing space separates them", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        // MySQL's `utf8mb4_bin` is a *PAD SPACE* collation: trailing spaces are
        // insignificant in an equality test and in a unique index, so
        // `"pad-sub"` and `"pad-sub "` would be one row there and two on
        // PostgreSQL and SQLite. `accounts.account_id` holds an identity
        // provider's `sub` verbatim, so that divergence would resolve a second
        // subject to the first one's account on MySQL alone. The column is
        // declared `utf8mb4_0900_bin`, which is NO PAD, and this is the
        // assertion that says so from the outside — on every dialect, because
        // the point of the collation is that the three agree.
        const user = yield* createUser(uniqueEmail("pad-space"))
        const providerId = unique("pad-provider")
        const bare = unique("pad-sub")
        const padded = `${bare} `

        yield* createOauthAccount(user.id, providerId, bare)
        yield* createOauthAccount(user.id, providerId, padded)

        const issuer = oauthIssuer(providerId)
        const foundBare = yield* expectSome(
          yield* accounts.findByIssuerAccountId(issuer, bare),
          "expected the unpadded account"
        )
        const foundPadded = yield* expectSome(
          yield* accounts.findByIssuerAccountId(issuer, padded),
          "expected the padded account"
        )

        assert.strictEqual(foundBare.accountId, bare)
        assert.strictEqual(foundPadded.accountId, padded)
        assert.notStrictEqual(foundBare.id, foundPadded.id)
      })
    )
  })

  describe("not-null constraints", () => {
    it.effect("tightens sessions.authenticated_at wherever the dialect can", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const dialect = yield* Database.dialect
        const user = yield* createUser(uniqueEmail("not-null"))
        const hash = unique("hash-not-null")

        const result = yield* Effect.result(
          sql`INSERT INTO sessions ${sql.insert({
            id: unique("s-not-null"),
            token_hash: hash,
            user_id: user.id,
            expires_at: "2999-01-01T00:00:00.000Z",
            ip_address: null,
            user_agent: null,
            authenticated_at: null,
            created_at: "2024-01-01T00:00:00.000Z",
            updated_at: "2024-01-01T00:00:00.000Z"
          })}`
        )

        if (dialect === "sqlite") {
          // `0006` adds the column to a table that may already have rows, and
          // SQLite cannot tighten a column afterwards — so there the `NOT NULL`
          // is the model's to enforce. The backfill still leaves none behind,
          // which `Migrations.test.ts` asserts.
          assert.strictEqual(result._tag, "Success")
          yield* sql`DELETE FROM sessions WHERE token_hash = ${hash}`
        } else {
          assert.strictEqual(result._tag, "Failure")
        }
      })
    )
  })

  describe("row locking", () => {
    it.effect("blocks a second reader until the holder commits", () =>
      on(
        ["pg", "mysql"],
        Effect.gen(function* () {
          const users = yield* UserStore
          const transaction = yield* WithAuthTransaction
          const user = yield* createUser(uniqueEmail("for-update"))
          const marker = unique("locked-by")

          const locked = yield* Latch.make(false)
          const proceed = yield* Latch.make(false)

          const holder = yield* Effect.forkChild(
            transaction.run(
              Effect.gen(function* () {
                yield* users.lockUserRow(user.id)
                yield* locked.open
                yield* proceed.await
                yield* users.update(user.id, { name: marker })
              })
            )
          )

          yield* locked.await
          yield* proceed.open

          // The second reader asks for the same lock. Under READ COMMITTED it
          // would otherwise see the row as it was before the holder's update;
          // `FOR UPDATE` makes it wait for the commit instead.
          const seen = yield* transaction.run(
            Effect.gen(function* () {
              yield* users.lockUserRow(user.id)
              return yield* users.findById(user.id)
            })
          )
          yield* Fiber.join(holder)

          const row = yield* expectSome(seen, "expected the user")
          assert.strictEqual(row.name, marker)
        })
      )
    )
  })
})
