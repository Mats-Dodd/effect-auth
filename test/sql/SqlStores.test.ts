import { PgliteClient } from "@effect/sql-pglite"
import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Layer, Option } from "effect"
import { SqlError } from "effect/unstable/sql"
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
import * as Migrations from "../../src/sql/Migrations.js"
import * as SqlStores from "../../src/sql/SqlStores.js"

/**
 * A fresh in-memory PGlite database, migrated, with the stores on top. Built
 * per test so that no two tests share rows.
 */
const testLayer = () => {
  const database = PgliteClient.layer()
  return Layer.provide(SqlStores.layer, Migrations.layer.pipe(Layer.provideMerge(database)))
}

const unwrap = <A>(option: Option.Option<A>, message: string): Effect.Effect<A> =>
  Option.isSome(option) ? Effect.succeed(option.value) : Effect.sync(() => assert.fail(message))

const createUser = Effect.fnUntraced(function*(email: string, emailVerified = false) {
  const users = yield* UserStore
  const row = yield* User.insert.makeEffect({
    name: "Ada Lovelace",
    email,
    emailVerified,
    image: null
  })
  return yield* users.create(row)
})

const createSession = Effect.fnUntraced(function*(userId: UserId, tokenHash: string, ttl: Duration.Duration) {
  const sessions = yield* SessionStore
  const now = yield* DateTime.now
  const row = yield* Session.insert.makeEffect({
    tokenHash,
    userId,
    expiresAt: DateTime.addDuration(now, ttl),
    ipAddress: "203.0.113.7",
    userAgent: "vitest"
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

// -----------------------------------------------------------------------------
// UserStore
// -----------------------------------------------------------------------------

describe("sql/SqlStores/UserStore", () => {
  it.effect("creates, reads, updates and deletes a user", () =>
    Effect.gen(function*() {
      const users = yield* UserStore
      const created = yield* createUser("ada@example.com")

      assert.strictEqual(created.email, "ada@example.com")
      assert.strictEqual(created.emailVerified, false)
      assert.strictEqual(created.image, null)
      assert.strictEqual(DateTime.isUtc(created.createdAt), true)

      const byId = yield* unwrap(yield* users.findById(created.id), "expected the user by id")
      assert.strictEqual(byId.id, created.id)

      const byEmail = yield* unwrap(yield* users.findByEmail("ada@example.com"), "expected the user by e-mail")
      assert.strictEqual(byEmail.id, created.id)

      const updated = yield* unwrap(
        yield* users.update(created.id, { name: "Ada L.", emailVerified: true, image: null }),
        "expected the updated user"
      )
      assert.strictEqual(updated.name, "Ada L.")
      assert.strictEqual(updated.emailVerified, true)

      assert.strictEqual(yield* users.delete(created.id), true)
      assert.strictEqual(yield* users.delete(created.id), false)
      assert.strictEqual(Option.isNone(yield* users.findById(created.id)), true)
    }).pipe(Effect.provide(testLayer())))

  it.effect("returns None for an unknown user", () =>
    Effect.gen(function*() {
      const users = yield* UserStore

      assert.strictEqual(Option.isNone(yield* users.findByEmail("nobody@example.com")), true)
      assert.strictEqual(Option.isNone(yield* users.update("missing" as UserId, { name: "x" })), true)
    }).pipe(Effect.provide(testLayer())))

  it.effect("reports a duplicate e-mail as a PersistenceError", () =>
    Effect.gen(function*() {
      yield* createUser("dup@example.com")
      const failure = yield* Effect.flip(createUser("dup@example.com"))

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
    }).pipe(Effect.provide(testLayer())))
})

// -----------------------------------------------------------------------------
// SessionStore
// -----------------------------------------------------------------------------

describe("sql/SqlStores/SessionStore", () => {
  it.effect("resolves a token hash to the session and its user in one read", () =>
    Effect.gen(function*() {
      const sessions = yield* SessionStore
      const user = yield* createUser("session@example.com", true)
      const session = yield* createSession(user.id, "hash-join", Duration.days(7))

      const found = yield* unwrap(yield* sessions.findByTokenHash("hash-join"), "expected the joined row")

      assert.strictEqual(found.session.id, session.id)
      assert.strictEqual(found.session.tokenHash, "hash-join")
      assert.strictEqual(found.session.ipAddress, "203.0.113.7")
      assert.strictEqual(found.user.id, user.id)
      assert.strictEqual(found.user.email, "session@example.com")
      assert.strictEqual(found.user.emailVerified, true)
      assert.strictEqual(
        DateTime.toEpochMillis(found.session.expiresAt),
        DateTime.toEpochMillis(session.expiresAt)
      )

      assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash("nope")), true)
    }).pipe(Effect.provide(testLayer())))

  it.effect("extends a session with touch", () =>
    Effect.gen(function*() {
      const sessions = yield* SessionStore
      const user = yield* createUser("touch@example.com")
      const session = yield* createSession(user.id, "hash-touch", Duration.days(1))
      const now = yield* DateTime.now
      const later = DateTime.addDuration(now, Duration.days(30))

      const touched = yield* unwrap(yield* sessions.touch(session.id, later), "expected the touched session")
      assert.strictEqual(DateTime.toEpochMillis(touched.expiresAt), DateTime.toEpochMillis(later))

      const reread = yield* unwrap(yield* sessions.findByTokenHash("hash-touch"), "expected the session")
      assert.strictEqual(DateTime.toEpochMillis(reread.session.expiresAt), DateTime.toEpochMillis(later))
    }).pipe(Effect.provide(testLayer())))

  it.effect("scopes deleteById to the owning user", () =>
    Effect.gen(function*() {
      const sessions = yield* SessionStore
      const owner = yield* createUser("owner@example.com")
      const other = yield* createUser("other@example.com")
      const session = yield* createSession(owner.id, "hash-owned", Duration.days(1))

      assert.strictEqual(yield* sessions.deleteById(session.id, other.id), false)
      assert.strictEqual(Option.isSome(yield* sessions.findByTokenHash("hash-owned")), true)

      assert.strictEqual(yield* sessions.deleteById(session.id, owner.id), true)
      assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash("hash-owned")), true)
    }).pipe(Effect.provide(testLayer())))

  it.effect("lists, revokes and expires sessions", () =>
    Effect.gen(function*() {
      const sessions = yield* SessionStore
      const user = yield* createUser("many@example.com")
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
    }).pipe(Effect.provide(testLayer())))
})

// -----------------------------------------------------------------------------
// AccountStore
// -----------------------------------------------------------------------------

describe("sql/SqlStores/AccountStore", () => {
  it.effect("creates and reads accounts by both identities", () =>
    Effect.gen(function*() {
      const accounts = yield* AccountStore
      const user = yield* createUser("accounts@example.com")

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

      yield* accounts.create(
        yield* Account.insert.makeEffect({
          issuer: oauthIssuer("github"),
          accountId: "gh-42",
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

      const byIssuer = yield* unwrap(
        yield* accounts.findByIssuerAccountId(oauthIssuer("github"), "gh-42"),
        "expected the github account"
      )
      assert.strictEqual(byIssuer.providerId, "github")
      assert.strictEqual(byIssuer.accessToken, "gho_secret")

      const byProvider = yield* unwrap(
        yield* accounts.findByUserIdAndProviderId(user.id, "credential"),
        "expected the credential account"
      )
      assert.strictEqual(byProvider.id, credential.id)

      assert.strictEqual(yield* accounts.countByUserId(user.id), 2)
      assert.strictEqual((yield* accounts.listByUserId(user.id)).length, 2)

      // The locking read answers the same rows; the lock it takes is what
      // makes `Accounts.unlink`'s last-method guard race-safe.
      const locked = yield* accounts.listByUserIdForUpdate(user.id)
      assert.deepStrictEqual(
        locked.map((account) => account.id),
        (yield* accounts.listByUserId(user.id)).map((account) => account.id)
      )
    }).pipe(Effect.provide(testLayer())))

  it.effect("updates tokens and the credential password hash", () =>
    Effect.gen(function*() {
      const accounts = yield* AccountStore
      const user = yield* createUser("tokens@example.com")
      const now = yield* DateTime.now
      const expiry = DateTime.addDuration(now, Duration.hours(1))

      const account = yield* accounts.create(
        yield* Account.insert.makeEffect({
          issuer: oauthIssuer("github"),
          accountId: "gh-7",
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

      const updated = yield* unwrap(
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

      const rehashed = yield* unwrap(
        yield* accounts.updatePasswordHash(user.id, "pbkdf2$i=600000$s$k"),
        "expected the credential account"
      )
      assert.strictEqual(rehashed.passwordHash, "pbkdf2$i=600000$s$k")
    }).pipe(Effect.provide(testLayer())))

  it.effect("scopes deleteById to the owning user", () =>
    Effect.gen(function*() {
      const accounts = yield* AccountStore
      const owner = yield* createUser("acc-owner@example.com")
      const other = yield* createUser("acc-other@example.com")

      const account = yield* accounts.create(
        yield* Account.insert.makeEffect({
          issuer: oauthIssuer("github"),
          accountId: "gh-99",
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
    }).pipe(Effect.provide(testLayer())))
})

// -----------------------------------------------------------------------------
// VerificationStore
// -----------------------------------------------------------------------------

describe("sql/SqlStores/VerificationStore", () => {
  it.effect("consumes a value exactly once", () =>
    Effect.gen(function*() {
      const verifications = yield* VerificationStore
      yield* createVerification("email-verify:ada@example.com", "value-hash", Duration.hours(1))

      const first = yield* verifications.consume("email-verify:ada@example.com", "value-hash")
      assert.strictEqual(Option.isSome(first), true)

      const second = yield* verifications.consume("email-verify:ada@example.com", "value-hash")
      assert.strictEqual(Option.isNone(second), true)
    }).pipe(Effect.provide(testLayer())))

  it.effect("hands the row to exactly one of two concurrent consumers", () =>
    Effect.gen(function*() {
      const verifications = yield* VerificationStore
      yield* createVerification("password-reset:ada", "race-hash", Duration.hours(1))

      const results = yield* Effect.all(
        [
          verifications.consume("password-reset:ada", "race-hash"),
          verifications.consume("password-reset:ada", "race-hash")
        ],
        { concurrency: 2 }
      )

      assert.strictEqual(results.filter(Option.isSome).length, 1)
      assert.strictEqual(results.filter(Option.isNone).length, 1)
    }).pipe(Effect.provide(testLayer())))

  it.effect("deletes every row under one identifier, expired or not", () =>
    Effect.gen(function*() {
      const verifications = yield* VerificationStore
      // Two reset links for the same user, plus somebody else's row, which
      // must survive.
      yield* createVerification("password-reset:ada", "first-hash", Duration.hours(1))
      yield* createVerification("password-reset:ada", "second-hash", Duration.hours(1))
      yield* createVerification("password-reset:bob", "bobs-hash", Duration.hours(1))

      assert.strictEqual(yield* verifications.deleteByIdentifier("password-reset:ada"), 2)
      assert.strictEqual(
        Option.isNone(yield* verifications.consume("password-reset:ada", "first-hash")),
        true
      )
      assert.strictEqual(
        Option.isSome(yield* verifications.consume("password-reset:bob", "bobs-hash")),
        true
      )
      // An identifier with nothing under it is not an error.
      assert.strictEqual(yield* verifications.deleteByIdentifier("password-reset:ada"), 0)
    }).pipe(Effect.provide(testLayer())))

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
    }).pipe(Effect.provide(testLayer())))
})

// -----------------------------------------------------------------------------
// WithAuthTransaction
// -----------------------------------------------------------------------------

describe("sql/SqlStores/WithAuthTransaction", () => {
  it.effect("commits every write of a successful effect", () =>
    Effect.gen(function*() {
      const transaction = yield* WithAuthTransaction
      const users = yield* UserStore

      const user = yield* transaction.run(Effect.gen(function*() {
        const user = yield* createUser("tx-ok@example.com")
        yield* createSession(user.id, "hash-tx", Duration.days(1))
        return user
      }))

      assert.strictEqual(Option.isSome(yield* users.findById(user.id)), true)
    }).pipe(Effect.provide(testLayer())))

  it.effect("rolls every write back when the effect fails", () =>
    Effect.gen(function*() {
      const transaction = yield* WithAuthTransaction
      const users = yield* UserStore
      const sessions = yield* SessionStore

      const failure = yield* Effect.flip(transaction.run(Effect.gen(function*() {
        const user = yield* createUser("tx-bad@example.com")
        yield* createSession(user.id, "hash-rollback", Duration.days(1))
        return yield* Effect.fail("boom" as const)
      })))

      assert.strictEqual(failure, "boom")
      assert.strictEqual(Option.isNone(yield* users.findByEmail("tx-bad@example.com")), true)
      assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash("hash-rollback")), true)
    }).pipe(Effect.provide(testLayer())))
})
