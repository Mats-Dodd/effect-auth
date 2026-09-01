import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Effect, Layer, Option, Redacted } from "effect"
import { PolicyRefused } from "../../src/domain/Hooks.js"
import { Passwords } from "../../src/domain/Passwords.js"
import type { CompleteOptions, SignInDecision, SignInPipelineService } from "../../src/domain/SignIn.js"
import {
  appendPipeline,
  combine,
  layerPipeline,
  methodOf,
  proceed,
  SignIn,
  SignInPipeline
} from "../../src/domain/SignIn.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { EmailOtp } from "../../src/email-otp/index.js"
import { AuthTest, EmailOtpTest } from "../../src/testing/index.js"
import { forUser, signUpUser, testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * The pending state a factor plugin's decider would have written. What is under
 * test is that a challenge stops the mint, not what answering one does, so the
 * token here addresses nothing.
 */
const challengeOf = (kind: string, available: ReadonlyArray<string>): SignInDecision => ({
  _tag: "Challenge",
  kind,
  available,
  token: Redacted.make(`pending-${kind}`),
  expiresAt: DateTime.makeUnsafe(0)
})

/**
 * The deployment installs exactly one decider and one `beforeSessionCreate`,
 * and each test says what they do.
 *
 * A `layer()` block is one PGlite and both seams are read when the services are
 * built, so a layer per case would mean a database per case. What varies here is
 * behaviour, not wiring — so the wiring is fixed and the behaviour is the
 * variable. `plain` puts both back, and every test opens with it.
 */
let decide: (options: CompleteOptions) => Effect.Effect<SignInDecision, PolicyRefused> = () => Effect.succeed(proceed)
let refuse: Effect.Effect<void, PolicyRefused> = Effect.void
let seen: Array<CompleteOptions> = []

const plain = Effect.sync(() => {
  decide = () => Effect.succeed(proceed)
  refuse = Effect.void
  seen = []
})

/** A decider that answers `answer` and remembers how often it was asked. */
const counted = (
  answer: (options: CompleteOptions) => Effect.Effect<SignInDecision, PolicyRefused>
): { readonly service: SignInPipelineService; readonly calls: () => number } => {
  let calls = 0
  return {
    service: {
      decide: (options) =>
        Effect.suspend(() => {
          calls = calls + 1
          return answer(options)
        })
    },
    calls: () => calls
  }
}

/** A real set of options to hand a decider under test. */
const completeOptions = Effect.fnUntraced(function* (label: string) {
  const { user } = yield* signUpUser(uniqueEmail(label))
  return {
    user,
    source: { _tag: "EmailPassword" },
    evidence: [{ method: "password", factor: "knowledge", phishingResistant: false, restricted: false }],
    current: Option.none(),
    request: { ipAddress: null, userAgent: null }
  } satisfies CompleteOptions
})

const deployment = EmailOtpTest.layer({
  signInPipeline: {
    decide: (options) =>
      Effect.suspend(() => {
        seen.push(options)
        return decide(options)
      })
  },
  hooks: { beforeSessionCreate: () => refuse }
})

describe.sequential("domain/SignIn", () => {
  layer(deployment)("a deployment with one decider installed", (it) => {
    it.effect("Proceed mints the session, records the evidence and publishes the log", () =>
      Effect.gen(function* () {
        yield* plain
        const passwords = yield* Passwords
        const email = uniqueEmail("proceed")
        const { user } = yield* signUpUser(email)

        const { events, result } = yield* AuthTest.recordingEvents(passwords.signIn({ email, password: testPassword }))

        assert.strictEqual(result._tag, "Complete")
        if (result._tag !== "Complete") return
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["password"]
        )
        assert.strictEqual(result.session.aal, "aal1")

        const signedIn = forUser(events, user.id).find((event) => event._tag === "SignedIn")
        if (signedIn === undefined || signedIn._tag !== "SignedIn") return assert.fail("expected a SignedIn event")
        // `method` still names the entry point, unchanged …
        assert.strictEqual(signedIn.method, "password")
        // … and `methods` is the evidence, exactly as the row records it.
        assert.deepStrictEqual(signedIn.methods, result.session.methods)
      })
    )

    it.effect("a Challenge mints no session row and publishes no SignedIn", () =>
      Effect.gen(function* () {
        yield* plain
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const email = uniqueEmail("challenged")
        const { user } = yield* signUpUser(email)
        const before = (yield* sessions.list(user.id)).length
        decide = () => Effect.succeed(challengeOf("mfa", ["totp"]))

        const { events, result } = yield* AuthTest.recordingEvents(passwords.signIn({ email, password: testPassword }))

        assert.strictEqual(result._tag, "Challenge")
        if (result._tag !== "Challenge") return
        assert.strictEqual(result.kind, "mfa")
        assert.deepStrictEqual(result.available, ["totp"])
        // Nothing was minted …
        assert.strictEqual((yield* sessions.list(user.id)).length, before)
        // … and nothing was announced.
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, user.id)), [])
      })
    )

    it.effect("the decider is handed the evidence, the source and the request", () =>
      Effect.gen(function* () {
        yield* plain
        const passwords = yield* Passwords
        const email = uniqueEmail("decider-sees")
        const { user } = yield* signUpUser(email)
        seen = []

        yield* passwords.signIn({ email, password: testPassword, ipAddress: "203.0.113.9", rememberMe: false })

        const options = seen.at(-1)
        if (options === undefined) return assert.fail("the decider should have been consulted")
        assert.strictEqual(options.user.id, user.id)
        assert.strictEqual(options.source._tag, "EmailPassword")
        assert.deepStrictEqual(
          options.evidence.map((entry) => entry.method),
          ["password"]
        )
        assert.strictEqual(options.request.ipAddress, "203.0.113.9")
        assert.strictEqual(options.request.rememberMe, false)
        // Nothing was carried in, so nothing is claimed.
        assert.isTrue(Option.isNone(options.current))
      })
    )

    it.effect("a PolicyRefused from beforeSessionCreate short-circuits the pipeline", () =>
      Effect.gen(function* () {
        yield* plain
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const email = uniqueEmail("refused")
        const { user } = yield* signUpUser(email)
        const before = (yield* sessions.list(user.id)).length
        refuse = Effect.flatMap(PolicyRefused.make({ code: "suspended" }), Effect.fail)
        seen = []

        const failure = yield* Effect.flip(passwords.signIn({ email, password: testPassword }))

        assert.strictEqual(failure._tag, "PolicyRefused")
        assert.strictEqual(failure._tag === "PolicyRefused" ? failure.code : "", "suspended")
        // The hook runs first, so the decider never issued a pending row for a
        // sign-in that was never going to be allowed.
        assert.deepStrictEqual(seen, [])
        assert.strictEqual((yield* sessions.list(user.id)).length, before)
      })
    )

    it.effect("a challenged sign-up answers with no session rather than a broken account", () =>
      Effect.gen(function* () {
        yield* plain
        const passwords = yield* Passwords
        decide = () => Effect.succeed(challengeOf("mfa", []))

        const result = yield* passwords.signUp({
          name: "Ada",
          email: uniqueEmail("challenged-signup"),
          password: testPassword
        })

        // The row committed before the pipeline was asked, exactly as it does
        // when `autoSignIn` is off.
        assert.isTrue(Option.isNone(result.session))
      })
    )

    it.effect("a challenged sign-up answers an account and no session, and says so", () =>
      Effect.gen(function* () {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        decide = () => Effect.succeed(challengeOf("mfa", ["totp"]))

        const result = yield* passwords.signUp({
          name: testName,
          email: uniqueEmail("challenged-signup"),
          password: testPassword
        })

        // The contract `SignInPipelineOf` states: a decider must Proceed on an
        // EmailPassword sign-up, because a brand-new account holds no second
        // factor and there is nothing for the person to answer with. When one
        // does not, this is what happens — an account, no session, and the
        // shape `autoSignIn: false` already produces. It fails closed, which is
        // why it is a warning and not a failure.
        assert.isTrue(Option.isNone(result.session))
        assert.strictEqual((yield* sessions.list(result.user.id)).length, 0)
      })
    )

    it.effect("a plugin's own sign-in mints through the same choke point", () =>
      Effect.gen(function* () {
        yield* plain
        const otp = yield* EmailOtp
        const email = uniqueEmail("code-evidence")
        const issued = yield* otp.send({ email, purpose: "signIn" })
        const code = yield* EmailOtpTest.awaitCode(email)

        const { events, result } = yield* AuthTest.recordingEvents(otp.verify({ handle: issued.handle, code }))

        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn") return
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["emailOtp"]
        )
        // Mailbox control is a possession factor, and one factor is aal1.
        assert.strictEqual(result.session.methods[0]?.factor, "possession")
        assert.strictEqual(result.session.aal, "aal1")
        const signedIn = forUser(events, result.user.id).find((event) => event._tag === "SignedIn")
        if (signedIn === undefined || signedIn._tag !== "SignedIn") return assert.fail("expected a SignedIn event")
        assert.strictEqual(signedIn.method, "email-otp")
        assert.deepStrictEqual(signedIn.methods, result.session.methods)
      })
    )

    it.effect("a challenged plugin sign-in mints nothing and spends the credential", () =>
      Effect.gen(function* () {
        yield* plain
        const otp = yield* EmailOtp
        const sessions = yield* Sessions
        const email = uniqueEmail("code-challenged")
        const { user } = yield* signUpUser(email)
        const before = new Set((yield* sessions.list(user.id)).map((session) => session.id))
        const issued = yield* otp.send({ email, purpose: "signIn" })
        const code = yield* EmailOtpTest.awaitCode(email)
        decide = () => Effect.succeed(challengeOf("mfa", ["totp"]))

        const challenged = yield* otp.verify({ handle: issued.handle, code })

        // The challenge is handed back rather than refused — this door is
        // request/response and can carry one — and no session came with it.
        assert.strictEqual(challenged._tag, "Challenge")
        // Not a count: this plugin's takeover defence revokes the unproven
        // account's sessions on the way through, so what matters is that no
        // *new* one was minted.
        const after = yield* sessions.list(user.id)
        assert.deepStrictEqual(
          after.filter((session) => !before.has(session.id)),
          []
        )

        // The code is spent whichever way it went, so it cannot be replayed
        // once the pipeline changes its mind.
        decide = () => Effect.succeed(proceed)
        const replayed = yield* Effect.flip(otp.verify({ handle: issued.handle, code }))
        assert.strictEqual(replayed._tag, "InvalidCode")
      })
    )

    it.effect("SignIn.complete is reachable as a service, and mints nothing on a challenge", () =>
      Effect.gen(function* () {
        yield* plain
        const signIn = yield* SignIn
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("service"))
        const before = (yield* sessions.list(user.id)).length
        decide = () => Effect.succeed(challengeOf("mfa", ["passkey"]))

        const result = yield* signIn.complete({
          user,
          source: { _tag: "Plugin", plugin: "test" },
          evidence: [{ method: "test", factor: "possession", phishingResistant: false, restricted: false }],
          current: Option.none(),
          request: { ipAddress: null, userAgent: null }
        })

        assert.strictEqual(result._tag, "Challenge")
        assert.strictEqual((yield* sessions.list(user.id)).length, before)
      })
    )

    it.effect("the pipeline is consulted after the credential, never before it", () =>
      Effect.gen(function* () {
        yield* plain
        const passwords = yield* Passwords
        const email = uniqueEmail("wrong-password")
        yield* signUpUser(email)
        seen = []

        const failure = yield* Effect.flip(passwords.signIn({ email, password: Redacted.make("not the passphrase") }))

        assert.strictEqual(failure._tag, "InvalidCredentials")
        // A wrong password must not cost a pending row, an SMS or a decision.
        assert.deepStrictEqual(seen, [])
      })
    )
    it.effect("methodOf names the entry point for every provisioning source", () =>
      Effect.sync(() => {
        assert.strictEqual(methodOf({ _tag: "EmailPassword" }), "password")
        assert.strictEqual(
          methodOf({
            _tag: "OAuth",
            providerId: "github",
            info: { id: "1", email: "ada@example.com", emailVerified: true, image: null }
          }),
          "oauth:github"
        )
        assert.strictEqual(methodOf({ _tag: "MagicLink" }), "magic-link")
        assert.strictEqual(methodOf({ _tag: "Plugin", plugin: "passkeys" }), "passkeys")
      })
    )

    it.effect("combine: the first challenge wins and the decider behind it is never entered", () =>
      Effect.gen(function* () {
        yield* plain
        const options = yield* completeOptions("combine-first")
        const first = counted(() => Effect.succeed(challengeOf("mfa", ["totp"])))
        const second = counted(() => Effect.succeed(proceed))
        const both = combine(first.service, second.service).decide
        if (both === undefined) return assert.fail("combining two deciders should produce one")

        const decision = yield* both(options)

        assert.strictEqual(decision._tag === "Challenge" ? decision.kind : "", "mfa")
        assert.strictEqual(first.calls(), 1)
        assert.strictEqual(second.calls(), 0)
      })
    )

    it.effect("combine: a Proceed hands the question on, and the second decider may challenge", () =>
      Effect.gen(function* () {
        yield* plain
        const options = yield* completeOptions("combine-second")
        const first = counted(() => Effect.succeed(proceed))
        const second = counted(() => Effect.succeed(challengeOf("device", [])))
        const both = combine(first.service, second.service).decide
        if (both === undefined) return assert.fail("combining two deciders should produce one")

        const decision = yield* both(options)

        assert.strictEqual(decision._tag === "Challenge" ? decision.kind : "", "device")
        assert.strictEqual(first.calls(), 1)
        assert.strictEqual(second.calls(), 1)
      })
    )

    it.effect("append stacks a plugin's decider after the deployment's, first challenge winning", () =>
      Effect.gen(function* () {
        yield* plain
        const options = yield* completeOptions("append")
        const application = counted(() => Effect.succeed(challengeOf("mfa", ["totp"])))
        const plugin = counted(() => Effect.succeed(challengeOf("device", [])))
        // What a plugin does: add to whatever the deployment installed, rather
        // than replacing it.
        const stacked = appendPipeline(plugin.service).pipe(Layer.provide(layerPipeline(application.service)))

        const installed = yield* Effect.provide(SignInPipeline, stacked)
        const decision = yield* (installed.decide ?? (() => Effect.succeed(proceed)))(options)

        assert.strictEqual(decision._tag === "Challenge" ? decision.kind : "", "mfa")
        assert.strictEqual(plugin.calls(), 0)
      })
    )

    it.effect("combine: a refusal short-circuits, and the empty pipeline is the identity", () =>
      Effect.gen(function* () {
        yield* plain
        const options = yield* completeOptions("combine-refuse")
        const refusing = counted(() => Effect.flatMap(PolicyRefused.make({ code: "banned" }), Effect.fail))
        const after = counted(() => Effect.succeed(proceed))
        const both = combine(refusing.service, after.service).decide
        if (both === undefined) return assert.fail("combining two deciders should produce one")

        const failure = yield* Effect.flip(both(options))
        assert.strictEqual(failure._tag, "PolicyRefused")
        assert.strictEqual(after.calls(), 0)

        // `{}` contributes nothing on either side, and two empty sets declare no
        // member at all — "no decider" stays distinguishable from "a decider
        // that always proceeds".
        const only = counted(() => Effect.succeed(proceed))
        assert.strictEqual(combine({}, only.service).decide, only.service.decide)
        assert.strictEqual(combine(only.service, {}).decide, only.service.decide)
        assert.deepStrictEqual(combine({}, {}), {})
      })
    )
  })
})
