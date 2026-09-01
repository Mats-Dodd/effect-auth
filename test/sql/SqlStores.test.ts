import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option } from "effect"
import { SqlClient, SqlError } from "effect/unstable/sql"
import { Account, CredentialIssuer, oauthIssuer, Session, User, Verification } from "../../src/domain/Schema.js"
import type { UserId } from "../../src/domain/Schema.js"
import {
  AccountStore,
  isUniqueViolation,
  PersistenceError,
  SessionStore,
  UserStore,
  VerificationStore,
  WithAuthTransaction
} from "../../src/domain/Stores.js"
import { decodeSqliteBoolean } from "../../src/sql/SqlStores.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, testName, uniqueEmail } from "../fixtures.js"

/**
 * A value no other test in the block will write.
 *
 * The block shares one database, so a fixed `"hash-1"` in two tests is one row
 * that both of them find.
 */
const unique = (label: string): string => `${label}-${globalThis.crypto.randomUUID()}`

const createUser = Effect.fnUntraced(function*(email: string, emailVerified = false) {
  const users = yield* UserStore
  const row = yield* User.insert.makeEffect({
    name: testName,
    email,
    emailVerified,
    image: null
  })
  return yield* users.create(row)
})

const createSession = Effect.fnUntraced(function*(
  userId: UserId,
  tokenHash: string,
  ttl: Duration.Duration,
  rememberMe = true
) {
  const sessions = yield* SessionStore
  const now = yield* DateTime.now
  const row = yield* Session.insert.makeEffect({
    tokenHash,
    userId,
    expiresAt: DateTime.addDuration(now, ttl),
    ipAddress: "203.0.113.7",
    userAgent: "vitest",
    rememberMe
  })
  return yield* sessions.create(row)
})

const createVerification = Effect.fnUntraced(function*(
  identifier: string,
  valueHash: string,
  ttl: Duration.Duration
) {
  const verifications = yield* VerificationStore
  const now = yield* DateTime.now
  const row = yield* Verification.insert.makeEffect({
    identifier,
    valueHash,
    payload: null,
    expiresAt: DateTime.addDuration(now, ttl)
  })
  return yield* verifications.create(row)
})

layer(AuthTest.layerStores)("sql/SqlStores", (it) => {
  // ---------------------------------------------------------------------------
  // UserStore
  // ---------------------------------------------------------------------------

  describe("UserStore", () => {
    it.effect("creates, reads, updates and deletes a user", () =>
      Effect.gen(function*() {
        const users = yield* UserStore
        const email = uniqueEmail("crud")
        const created = yield* createUser(email)

        assert.strictEqual(created.email, email)
        assert.strictEqual(created.emailVerified, false)
        assert.strictEqual(created.image, null)
        assert.strictEqual(DateTime.isUtc(created.createdAt), true)

        const byId = yield* expectSome(yield* users.findById(created.id), "expected the user by id")
        assert.strictEqual(byId.id, created.id)

        const byEmail = yield* expectSome(yield* users.findByEmail(email), "expected the user by e-mail")
        assert.strictEqual(byEmail.id, created.id)

        const updated = yield* expectSome(
          yield* users.update(created.id, { name: "Ada L.", emailVerified: true, image: null }),
          "expected the updated user"
        )
        assert.strictEqual(updated.name, "Ada L.")
        assert.strictEqual(updated.emailVerified, true)

        assert.strictEqual(yield* users.delete(created.id), true)
        assert.strictEqual(yield* users.delete(created.id), false)
        assert.strictEqual(Option.isNone(yield* users.findById(created.id)), true)
      }))

    it.effect("returns None for an unknown user", () =>
      Effect.gen(function*() {
        const users = yield* UserStore

        assert.strictEqual(Option.isNone(yield* users.findByEmail(uniqueEmail("nobody"))), true)
        assert.strictEqual(Option.isNone(yield* users.update("missing" as UserId, { name: "x" })), true)
      }))

    it.effect("locks a user row inside a transaction, and tolerates an unknown id", () =>
      Effect.gen(function*() {
        const users = yield* UserStore
        const transaction = yield* WithAuthTransaction
        const created = yield* createUser(uniqueEmail("lock"))

        // It answers nothing — it is taken for the lock, not the row — and must
        // not throw when the id matches no row (`FOR UPDATE` of an empty result
        // is a no-op, and the SQLite degrade is a plain read).
        yield* transaction.run(Effect.gen(function*() {
          yield* users.lockUserRow(created.id)
          yield* users.lockUserRow("missing" as UserId)
        }))
      }))

    it.effect("reports a duplicate e-mail as a PersistenceError", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("duplicate")
        yield* createUser(email)
        const failure = yield* Effect.flip(createUser(email))

        if (!(failure instanceof PersistenceError)) {
          return assert.fail(`expected a PersistenceError, got ${String(failure)}`)
        }
        assert.strictEqual(failure.operation, "UserStore.create")
        // the driver failure survives in `cause` for logs, and is classified into
        // `kind` so the domain can tell a lost race from any other storage failure
        // without importing the SQL driver's error type
        assert.strictEqual(SqlError.isSqlError(failure.cause), true)
        assert.strictEqual(
          SqlError.isSqlError(failure.cause) ? failure.cause.reason._tag : "",
          "UniqueViolation"
        )
        assert.strictEqual(failure.kind, "UniqueViolation")
        assert.isTrue(isUniqueViolation(failure))
      }))
  })

  // ---------------------------------------------------------------------------
  // SessionStore
  // ---------------------------------------------------------------------------

  describe("SessionStore", () => {
    it.effect("resolves a token hash to the session and its user in one read", () =>
      Effect.gen(function*() {
        const sessions = yield* SessionStore
        const email = uniqueEmail("session")
        const hash = unique("hash-join")
        const user = yield* createUser(email, true)
        const session = yield* createSession(user.id, hash, Duration.days(7))

        const found = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the joined row")

        assert.strictEqual(found.session.id, session.id)
        assert.strictEqual(found.session.tokenHash, hash)
        assert.strictEqual(found.session.ipAddress, "203.0.113.7")
        assert.strictEqual(found.user.id, user.id)
        assert.strictEqual(found.user.email, email)
        assert.strictEqual(found.user.emailVerified, true)
        assert.strictEqual(
          DateTime.toEpochMillis(found.session.expiresAt),
          DateTime.toEpochMillis(session.expiresAt)
        )

        assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(unique("nope"))), true)
      }))

    it.effect("extends a session with touch", () =>
      Effect.gen(function*() {
        const sessions = yield* SessionStore
        const hash = unique("hash-touch")
        const user = yield* createUser(uniqueEmail("touch"))
        const session = yield* createSession(user.id, hash, Duration.days(1))
        const now = yield* DateTime.now
        const later = DateTime.addDuration(now, Duration.days(30))

        const touched = yield* expectSome(yield* sessions.touch(session.id, later), "expected the touched session")
        assert.strictEqual(DateTime.toEpochMillis(touched.expiresAt), DateTime.toEpochMillis(later))

        const reread = yield* expectSome(yield* sessions.findByTokenHash(hash), "expected the session")
        assert.strictEqual(DateTime.toEpochMillis(reread.session.expiresAt), DateTime.toEpochMillis(later))
      }))

    it.effect("persists remember_me and reads it back on the joined row", () =>
      Effect.gen(function*() {
        const sessions = yield* SessionStore
        const rememberedHash = unique("hash-remembered")
        const forgottenHash = unique("hash-forgotten")
        const user = yield* createUser(uniqueEmail("remember"))

        const remembered = yield* createSession(user.id, rememberedHash, Duration.days(7), true)
        const forgotten = yield* createSession(user.id, forgottenHash, Duration.days(1), false)

        // The flag survives the insert round-trip on the returned row …
        assert.strictEqual(remembered.rememberMe, true)
        assert.strictEqual(forgotten.rememberMe, false)

        // … and the joined read the hot path uses.
        const foundRemembered = yield* expectSome(
          yield* sessions.findByTokenHash(rememberedHash),
          "expected the remembered session"
        )
        const foundForgotten = yield* expectSome(
          yield* sessions.findByTokenHash(forgottenHash),
          "expected the forgotten session"
        )
        assert.strictEqual(foundRemembered.session.rememberMe, true)
        assert.strictEqual(foundForgotten.session.rememberMe, false)
      }))

    it.effect("leaves remember_me untouched across a rolling refresh", () =>
      Effect.gen(function*() {
        const sessions = yield* SessionStore
        const hash = unique("hash-remember-touch")
        const user = yield* createUser(uniqueEmail("remember-touch"))
        const session = yield* createSession(user.id, hash, Duration.days(1), false)
        const now = yield* DateTime.now

        const touched = yield* expectSome(
          yield* sessions.touch(session.id, DateTime.addDuration(now, Duration.hours(1))),
          "expected the touched session"
        )
        // Touch moves only the expiry; a short session must not be promoted.
        assert.strictEqual(touched.rememberMe, false)

        const listed = yield* sessions.listByUserId(user.id)
        const reread = listed.find((row) => row.tokenHash === hash)
        assert.strictEqual(reread?.rememberMe, false)
      }))

    it.effect("scopes deleteById to the owning user", () =>
      Effect.gen(function*() {
        const sessions = yield* SessionStore
        const hash = unique("hash-owned")
        const owner = yield* createUser(uniqueEmail("owner"))
        const other = yield* createUser(uniqueEmail("other"))
        const session = yield* createSession(owner.id, hash, Duration.days(1))

        assert.strictEqual(yield* sessions.deleteById(session.id, other.id), false)
        assert.strictEqual(Option.isSome(yield* sessions.findByTokenHash(hash)), true)

        assert.strictEqual(yield* sessions.deleteById(session.id, owner.id), true)
        assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(hash)), true)
      }))

  })

  // ---------------------------------------------------------------------------
  // AccountStore
  // ---------------------------------------------------------------------------

  describe("AccountStore", () => {
    it.effect("creates and reads accounts by both identities", () =>
      Effect.gen(function*() {
        const accounts = yield* AccountStore
        const user = yield* createUser(uniqueEmail("accounts"))
        const accountId = unique("gh")

        const credential = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: CredentialIssuer,
            accountId: user.id,
            providerId: "credential",
            userId: user.id,
            accessToken: null,
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: "scrypt$n=16384,r=16,p=1$c2FsdA$a2V5"
          })
        )

        assert.strictEqual(credential.passwordHash, "scrypt$n=16384,r=16,p=1$c2FsdA$a2V5")

        const oauth = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: oauthIssuer("github"),
            accountId,
            providerId: "github",
            userId: user.id,
            accessToken: "gho_secret",
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: "read:user",
            passwordHash: null
          })
        )

        const sql = yield* SqlClient.SqlClient
        const raw = yield* sql<{ readonly access_token: string }>`SELECT access_token FROM accounts WHERE id = ${oauth.id}`
        assert.strictEqual(raw.length, 1)
        assert.notStrictEqual(raw[0]!.access_token, "gho_secret")
        assert.isTrue(raw[0]!.access_token.startsWith("v1."))

        const byIssuer = yield* expectSome(
          yield* accounts.findByIssuerAccountId(oauthIssuer("github"), accountId),
          "expected the github account"
        )
        assert.strictEqual(byIssuer.providerId, "github")
        assert.strictEqual(byIssuer.accessToken, "gho_secret")

        const byProvider = yield* expectSome(
          yield* accounts.findByUserIdAndProviderId(user.id, "credential"),
          "expected the credential account"
        )
        assert.strictEqual(byProvider.id, credential.id)

        const byId = yield* expectSome(
          yield* accounts.findByIdAndUserId(byIssuer.id, user.id),
          "expected the github account by its own id"
        )
        assert.strictEqual(byId.id, byIssuer.id)

        // Ownership is a predicate of the statement, not a check afterwards: a
        // real account belonging to somebody else answers exactly as a
        // non-existent one does.
        const stranger = yield* createUser(uniqueEmail("accounts-stranger"))
        assert.isTrue(Option.isNone(yield* accounts.findByIdAndUserId(byIssuer.id, stranger.id)))

        assert.strictEqual(yield* accounts.countByUserId(user.id), 2)
        assert.strictEqual((yield* accounts.listByUserId(user.id)).length, 2)

        // The locking read answers the same rows; the lock it takes is what
        // makes `Accounts.unlink`'s last-method guard race-safe.
        const locked = yield* accounts.listByUserIdForUpdate(user.id)
        assert.deepStrictEqual(
          locked.map((account) => account.id),
          (yield* accounts.listByUserId(user.id)).map((account) => account.id)
        )
      }))

    it.effect("updates tokens and the credential password hash", () =>
      Effect.gen(function*() {
        const accounts = yield* AccountStore
        const user = yield* createUser(uniqueEmail("tokens"))
        const now = yield* DateTime.now
        const expiry = DateTime.addDuration(now, Duration.hours(1))

        const account = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: oauthIssuer("github"),
            accountId: unique("gh"),
            providerId: "github",
            userId: user.id,
            accessToken: "old",
            refreshToken: "refresh",
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: null
          })
        )

        const updated = yield* expectSome(
          yield* accounts.updateTokens(account.id, {
            accessToken: "new",
            accessTokenExpiresAt: expiry,
            scope: "read:user"
          }),
          "expected the updated account"
        )

        assert.strictEqual(updated.accessToken, "new")
        // absent keys are left untouched
        assert.strictEqual(updated.refreshToken, "refresh")
        assert.strictEqual(updated.scope, "read:user")
        assert.strictEqual(
          updated.accessTokenExpiresAt === null ? null : DateTime.toEpochMillis(updated.accessTokenExpiresAt),
          DateTime.toEpochMillis(expiry)
        )

        // no local:credential account yet
        assert.strictEqual(Option.isNone(yield* accounts.updatePasswordHash(user.id, "pbkdf2$i=600000$s$k")), true)

        yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: CredentialIssuer,
            accountId: user.id,
            providerId: "credential",
            userId: user.id,
            accessToken: null,
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: "old-hash"
          })
        )

        const rehashed = yield* expectSome(
          yield* accounts.updatePasswordHash(user.id, "pbkdf2$i=600000$s$k"),
          "expected the credential account"
        )
        assert.strictEqual(rehashed.passwordHash, "pbkdf2$i=600000$s$k")
      }))

    it.effect("scopes deleteById to the owning user", () =>
      Effect.gen(function*() {
        const accounts = yield* AccountStore
        const owner = yield* createUser(uniqueEmail("acc-owner"))
        const other = yield* createUser(uniqueEmail("acc-other"))

        const account = yield* accounts.create(
          yield* Account.insert.makeEffect({
            issuer: oauthIssuer("github"),
            accountId: unique("gh"),
            providerId: "github",
            userId: owner.id,
            accessToken: null,
            refreshToken: null,
            idToken: null,
            accessTokenExpiresAt: null,
            refreshTokenExpiresAt: null,
            scope: null,
            passwordHash: null
          })
        )

        assert.strictEqual(yield* accounts.deleteById(account.id, other.id), false)
        assert.strictEqual(yield* accounts.countByUserId(owner.id), 1)

        assert.strictEqual(yield* accounts.deleteById(account.id, owner.id), true)
        assert.strictEqual(yield* accounts.countByUserId(owner.id), 0)
      }))

    it.effect("deletes every method of one user, and only that user's", () =>
      Effect.gen(function*() {
        const accounts = yield* AccountStore
        const owner = yield* createUser(uniqueEmail("acc-purge-owner"))
        const other = yield* createUser(uniqueEmail("acc-purge-other"))

        const link = (userId: typeof owner.id, providerId: string) =>
          Effect.flatMap(
            Account.insert.makeEffect({
              issuer: oauthIssuer(providerId),
              accountId: unique(providerId),
              providerId,
              userId,
              accessToken: null,
              refreshToken: null,
              idToken: null,
              accessTokenExpiresAt: null,
              refreshTokenExpiresAt: null,
              scope: null,
              passwordHash: null
            }),
            (row) => accounts.create(row)
          )

        yield* link(owner.id, "github")
        yield* link(owner.id, "google")
        yield* link(other.id, "github")

        assert.strictEqual(yield* accounts.deleteByUserId(owner.id), 2)
        assert.strictEqual(yield* accounts.countByUserId(owner.id), 0)
        // The neighbour's row is untouched: the statement is scoped by user.
        assert.strictEqual(yield* accounts.countByUserId(other.id), 1)

        // And a user with nothing linked is not an error.
        assert.strictEqual(yield* accounts.deleteByUserId(owner.id), 0)
      }))
  })

  // ---------------------------------------------------------------------------
  // VerificationStore
  // ---------------------------------------------------------------------------

  describe("VerificationStore", () => {
    it.effect("consumes a value exactly once", () =>
      Effect.gen(function*() {
        const verifications = yield* VerificationStore
        const identifier = unique("email-verify")
        yield* createVerification(identifier, "value-hash", Duration.hours(1))

        const first = yield* verifications.consume(identifier, "value-hash")
        assert.strictEqual(Option.isSome(first), true)

        const second = yield* verifications.consume(identifier, "value-hash")
        assert.strictEqual(Option.isNone(second), true)
      }))

    it.effect("hands the row to exactly one of two concurrent consumers", () =>
      Effect.gen(function*() {
        const verifications = yield* VerificationStore
        const identifier = unique("password-reset")
        yield* createVerification(identifier, "race-hash", Duration.hours(1))

        const results = yield* Effect.all(
          [
            verifications.consume(identifier, "race-hash"),
            verifications.consume(identifier, "race-hash")
          ],
          { concurrency: 2 }
        )

        assert.strictEqual(results.filter(Option.isSome).length, 1)
        assert.strictEqual(results.filter(Option.isNone).length, 1)
      }))

    it.effect("deletes every row under one identifier, expired or not", () =>
      Effect.gen(function*() {
        const verifications = yield* VerificationStore
        // Two reset links for the same user, plus somebody else's row, which
        // must survive.
        const ada = unique("password-reset-ada")
        const bob = unique("password-reset-bob")
        yield* createVerification(ada, "first-hash", Duration.hours(1))
        yield* createVerification(ada, "second-hash", Duration.hours(1))
        yield* createVerification(bob, "bobs-hash", Duration.hours(1))

        assert.strictEqual(yield* verifications.deleteByIdentifier(ada), 2)
        assert.strictEqual(Option.isNone(yield* verifications.consume(ada, "first-hash")), true)
        assert.strictEqual(Option.isSome(yield* verifications.consume(bob, "bobs-hash")), true)
        // An identifier with nothing under it is not an error.
        assert.strictEqual(yield* verifications.deleteByIdentifier(ada), 0)
      }))

  })

  // ---------------------------------------------------------------------------
  // WithAuthTransaction
  // ---------------------------------------------------------------------------

  describe("WithAuthTransaction", () => {
    it.effect("commits every write of a successful effect", () =>
      Effect.gen(function*() {
        const transaction = yield* WithAuthTransaction
        const users = yield* UserStore

        const user = yield* transaction.run(Effect.gen(function*() {
          const user = yield* createUser(uniqueEmail("tx-ok"))
          yield* createSession(user.id, unique("hash-tx"), Duration.days(1))
          return user
        }))

        assert.strictEqual(Option.isSome(yield* users.findById(user.id)), true)
      }))
  })
})

// -----------------------------------------------------------------------------
// The one dialect divergence
// -----------------------------------------------------------------------------

describe("sql/SqlStores (sqlite booleans)", () => {
  it("reads the integer flag back, and leaves an absent value absent", () => {
    // The suite runs on PGlite, so this adapter is never exercised by a store
    // test — and it is applied to every boolean-flagged column, including the
    // nullable one a deployment declares with `NullOr(Schema.Boolean)`.
    assert.strictEqual(decodeSqliteBoolean(1), true)
    assert.strictEqual(decodeSqliteBoolean(0), false)
    assert.strictEqual(decodeSqliteBoolean(true), true)
    assert.strictEqual(decodeSqliteBoolean(false), false)

    // "Not asked yet" is not "declined": a null that decoded as `false` would
    // pass `NullOr(Schema.Boolean)` and be a silent rewrite on every read.
    assert.strictEqual(decodeSqliteBoolean(null), null)
    assert.strictEqual(decodeSqliteBoolean(undefined), undefined)
  })
})

// -----------------------------------------------------------------------------
// The table-wide operations, each on a database of its own
// -----------------------------------------------------------------------------

/**
 * These three cannot share a deployment.
 *
 * `deleteExpired` sweeps a whole table, so its count is an assertion about
 * every row any sibling happens to have written; and a rollback discards a
 * sibling's uncommitted writes too, because PGlite serves the block from one
 * connection.
 */
describe("sql/SqlStores (whole-table)", () => {
  it.effect("lists, revokes and expires sessions", () =>
    Effect.gen(function*() {
      const sessions = yield* SessionStore
      const user = yield* createUser(uniqueEmail("many"))
      const first = yield* createSession(user.id, "hash-1", Duration.days(7))
      yield* createSession(user.id, "hash-2", Duration.days(7))
      yield* createSession(user.id, "hash-3", Duration.minutes(-1))

      const live = yield* sessions.listByUserId(user.id)
      assert.deepStrictEqual(live.map((session) => session.tokenHash).sort(), ["hash-1", "hash-2"])

      assert.strictEqual(yield* sessions.deleteExpired, 1)

      assert.strictEqual(yield* sessions.deleteByUserIdExcept(user.id, first.id), 1)
      assert.deepStrictEqual((yield* sessions.listByUserId(user.id)).map((session) => session.tokenHash), [
        "hash-1"
      ])

      assert.strictEqual(yield* sessions.deleteByUserId(user.id), 1)
      assert.deepStrictEqual(yield* sessions.listByUserId(user.id), [])
    }).pipe(Effect.provide(AuthTest.layerStores)))

  it.effect("refuses an expired row and a wrong value hash", () =>
    Effect.gen(function*() {
      const verifications = yield* VerificationStore
      yield* createVerification("oauth-state:expired", "expired-hash", Duration.minutes(-1))
      yield* createVerification("oauth-state:live", "live-hash", Duration.minutes(10))

      assert.strictEqual(
        Option.isNone(yield* verifications.consume("oauth-state:expired", "expired-hash")),
        true
      )
      assert.strictEqual(Option.isNone(yield* verifications.consume("oauth-state:live", "wrong-hash")), true)
      assert.strictEqual(Option.isSome(yield* verifications.consume("oauth-state:live", "live-hash")), true)

      // the expired row is still there until it is swept
      assert.strictEqual(yield* verifications.deleteExpired, 1)
      assert.strictEqual(yield* verifications.deleteExpired, 0)
    }).pipe(Effect.provide(AuthTest.layerStores)))

  it.effect("rolls every write back when the effect fails", () =>
    Effect.gen(function*() {
      const transaction = yield* WithAuthTransaction
      const users = yield* UserStore
      const sessions = yield* SessionStore
      const email = uniqueEmail("tx-bad")
      const hash = unique("hash-rollback")

      const failure = yield* Effect.flip(transaction.run(Effect.gen(function*() {
        const user = yield* createUser(email)
        yield* createSession(user.id, hash, Duration.days(1))
        return yield* Effect.fail("boom" as const)
      })))

      assert.strictEqual(failure, "boom")
      assert.strictEqual(Option.isNone(yield* users.findByEmail(email)), true)
      assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(hash)), true)
    }).pipe(Effect.provide(AuthTest.layerStores)))
})
