import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Effect, Fiber, Schema, Stream } from "effect"
import type { AuthEvent } from "../../src/domain/Events.js"
import {
  AccountLinked,
  AccountUnlinked,
  AuthEvent as AuthEventSchema,
  AuthEvents,
  EmailChanged,
  EmailVerified,
  emit,
  layer as authEventsLayer,
  oauthMethod,
  PasswordChanged,
  PasswordResetRequested,
  passwordMethod,
  PluginEvent,
  SessionElevated,
  SessionRevoked,
  SignedIn,
  SignedOut,
  TokensRefreshed,
  UserCreated,
  UserDeleted,
  UserUpdated
} from "../../src/domain/Events.js"
import { AccountId, SessionId, UserId } from "../../src/domain/Schema.js"

const userId = UserId.make("01890000-0000-7000-8000-00000000000a")
const sessionId = SessionId.make("01890000-0000-7000-8000-00000000000b")
const accountId = AccountId.make("01890000-0000-7000-8000-00000000000c")

const everyEvent: ReadonlyArray<AuthEvent> = [
  UserCreated.make({ userId, email: "ada@example.com", emailVerified: false, method: passwordMethod }),
  SignedIn.make({
    userId,
    sessionId,
    method: oauthMethod("github"),
    methods: [
      {
        method: "oauth:github",
        factor: "possession",
        phishingResistant: false,
        restricted: false,
        completedAt: DateTime.makeUnsafe(0)
      }
    ]
  }),
  // The log a mint that recorded no evidence carries: `aal0`, and a subscriber
  // that reads `methods` has to accept it as readily as a full one.
  SignedIn.make({ userId, sessionId, method: passwordMethod, methods: [] }),
  SessionElevated.make({ userId, sessionId, method: "totp" }),
  SignedOut.make({ userId, sessionId }),
  SessionRevoked.make({ userId, sessionId, scope: "single", count: 1 }),
  SessionRevoked.make({ userId, sessionId: null, scope: "all", count: 3 }),
  SessionRevoked.make({ userId, sessionId: null, scope: "others", count: 2 }),
  PasswordChanged.make({ userId, viaReset: true }),
  PasswordResetRequested.make({ userId }),
  EmailVerified.make({ userId, email: "ada@example.com" }),
  UserUpdated.make({ userId, fields: ["name", "image"] }),
  // The empty `fields` an update that touched nothing but a deployment's own
  // columns publishes — a shape the array's schema has to accept as readily as
  // the full one.
  UserUpdated.make({ userId, fields: [] }),
  EmailChanged.make({ userId, previousEmail: "ada@example.com", email: "ada@lovelace.example" }),
  UserDeleted.make({ userId, email: "ada@example.com" }),
  TokensRefreshed.make({ userId, accountId, providerId: "github" }),
  AccountLinked.make({ userId, accountId, providerId: "github", issuer: "local:oauth:github" }),
  AccountUnlinked.make({ userId, accountId, providerId: "github", issuer: "local:oauth:github" }),
  PluginEvent.make({ plugin: "email-otp", event: "requested", userId: null, data: { newUser: true } }),
  PluginEvent.make({ plugin: "email-otp", event: "verified", userId, data: {} })
]

describe("domain/Events/schema", () => {
  it.effect("round-trips every member of the union", () =>
    Effect.gen(function* () {
      // Events are routinely forwarded to a webhook or a log sink, so the union
      // has to survive the trip through JSON in both directions.
      const encode = Schema.encodeEffect(AuthEventSchema)
      const decode = Schema.decodeEffect(AuthEventSchema)

      for (const event of everyEvent) {
        const encoded = yield* encode(event)
        assert.deepStrictEqual(yield* decode(encoded), event)
      }
    })
  )

  it("samples every member of the closed union", () => {
    // The two tests below are only as good as this list, so the list is pinned
    // to the union itself: a member added without a sample here fails this
    // assertion rather than quietly going unasserted in both of them.
    // `discriminants` is the tagged union's own ordered tuple of tags, so this
    // names the missing member rather than reporting a count that is one short.
    const sampled = new Set<string>(everyEvent.map((event) => event._tag))
    assert.deepStrictEqual([...sampled].sort(), [...AuthEventSchema.discriminants].sort())
  })

  it("carries no credential-shaped field", () => {
    // Events are handed to log sinks and webhooks, so a field that ever came to
    // hold a token, a password or a hash would leak it everywhere at once. This
    // is the guard against that field being added.
    const fields = new Set<string>()
    for (const event of everyEvent) {
      for (const field of Object.keys(event)) fields.add(field)
    }
    assert.ok(fields.size > 0)
    for (const field of fields) {
      assert.strictEqual(/token|password|secret|hash|credential/i.test(field), false, `field \`${field}\``)
    }
  })

  it("names the sign-in methods it documents", () => {
    assert.strictEqual(passwordMethod, "password")
    assert.strictEqual(oauthMethod("github"), "oauth:github")
  })
})

layer(authEventsLayer())("domain/Events/hub", (it) => {
  it.effect(
    "delivers published events to a running subscriber",
    () =>
      Effect.gen(function* () {
        const events = yield* AuthEvents
        const fiber = yield* Effect.forkChild(Stream.runCollect(Stream.take(events.stream, 2)))
        // Let the subscriber attach before anything is published: the hub drops,
        // it does not replay.
        yield* Effect.yieldNow

        yield* events.publish(PasswordResetRequested.make({ userId }))
        yield* events.publish(PasswordChanged.make({ userId, viaReset: true }))

        const collected = yield* Fiber.join(fiber)
        assert.deepStrictEqual(
          Array.from(collected, (event) => event._tag),
          ["PasswordResetRequested", "PasswordChanged"]
        )
      }),
    10_000
  )
})

/**
 * The back-pressure tests need a hub small enough to overflow, so they get a
 * block of their own. They share one hub: neither subscribes for longer than
 * its own test, and the hub drops rather than replays, so nothing one publishes
 * is visible to the other.
 */
layer(authEventsLayer({ capacity: 2 }))("domain/Events/hub (capacity 2)", (it) => {
  it.effect(
    "publishing with no subscriber succeeds rather than blocking",
    () =>
      Effect.gen(function* () {
        // A hub of two, nobody listening, and far more than two events: a
        // back-pressuring hub would wedge the sign-in that published them.
        const events = yield* AuthEvents
        for (let i = 0; i < 32; i++) {
          yield* events.publish(PasswordResetRequested.make({ userId }))
        }
        yield* emit(SignedOut.make({ userId, sessionId }))
        assert.ok(true)
      }),
    10_000
  )

  it.effect(
    "a subscriber that stops reading cannot wedge a publisher",
    () =>
      Effect.gen(function* () {
        const events = yield* AuthEvents
        // Subscribed, and deliberately never drained.
        yield* events.subscribe

        for (let i = 0; i < 32; i++) {
          yield* events.publish(PasswordChanged.make({ userId, viaReset: false }))
        }
        assert.ok(true)
      }),
    10_000
  )
})
