/**
 * Internal `Effect` helpers shared across the domain services. Not exported
 * from the package: nothing here is part of the public API.
 *
 * @internal
 */
import type { SchemaIssue } from "effect"
import { Effect } from "effect"

/**
 * The subset of a model's `insert` variant this package constructs rows with.
 *
 * @internal
 */
export interface Insertable<in I, out A> {
  readonly makeEffect: (input: I) => Effect.Effect<A, SchemaIssue.Issue>
}

/**
 * Builds an insert row from a model's `insert` variant, turning a construction
 * failure into a defect.
 *
 * **Details**
 *
 * The fields handed in have already been validated — by the API schema, by the
 * domain service, or by both — and the generated columns (`id`, `createdAt`,
 * `updatedAt`) come from the model itself. So an issue here means the *code* is
 * wrong, not the request, and belongs in the defect channel rather than in
 * every caller's error union.
 *
 * @internal
 */
export const insertRow = <I, A>(model: Insertable<I, A>, input: I): Effect.Effect<A> =>
  Effect.orDie(model.makeEffect(input))

/**
 * Puts what a `beforeUserCreate` hook answered with back through the model's
 * `makeInsert` — its `insert` variant, `orDie` — and re-normalizes the address
 * it answered with.
 *
 * **Details**
 *
 * What a hook hands back is an ordinary object, and nothing else would stop it
 * storing a row the schema rejects — so a rewrite is validated even though the
 * candidate it was handed already was.
 *
 * The address is re-normalized on the way out. Every read of a user by e-mail in
 * this library looks the address up as `normalizeEmail(…)` — the stored column
 * is normalized by the discipline of every caller that writes it, not by the
 * schema — so a hook that rewrote `email` to `User@Example.com` would store a
 * row that no sign-in, no reset and no link could ever find again, and that the
 * duplicate pre-check would not see either.
 *
 * **Gotchas**
 *
 * The normalizer is handed in rather than imported: `normalizeEmail` lives in
 * `domain/Schema`, which reads this module, and `src/internal` stays a leaf of
 * the import graph.
 *
 * @internal
 */
export const revalidateRewrite = <I, A extends { readonly email: string }>(
  makeInsert: (input: I) => Effect.Effect<A>,
  answer: I,
  normalizeEmail: (email: string) => string
): Effect.Effect<A> =>
  Effect.map(makeInsert(answer), (validated) => Object.assign(validated, { email: normalizeEmail(validated.email) }))

/**
 * The annotations every log this library writes carries.
 *
 * **Details**
 *
 * Replaces the hand-written `"effect-auth: …"` message prefix: a structured
 * annotation is filterable by a log aggregator, a prefix is only greppable.
 *
 * @internal
 */
export const authLogAnnotations: { readonly module: string } = { module: "effect-auth" }

/**
 * Tags every log written while `effect` runs as one of this library's.
 *
 * @internal
 */
export const annotateAuthLogs = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
  Effect.annotateLogs(effect, authLogAnnotations)

/**
 * Hands a message to the mail seam and forgets whatever it says, logging a
 * failure at `Warn` under `message`.
 *
 * **Details**
 *
 * Delivery is the application's responsibility and its failure must never
 * change what the caller observes — least of all on the change-email and
 * password-reset paths, where a distinguishable answer would be the enumeration
 * oracle those flows are shaped to avoid. The failure is therefore logged and
 * dropped, and the caller's response is the one it would have given anyway.
 *
 * @internal
 */
export const deliverEmail = <E>(email: Effect.Effect<void, E>, message: string): Effect.Effect<void> =>
  annotateAuthLogs(Effect.ignore(email, { log: "Warn", message }))
