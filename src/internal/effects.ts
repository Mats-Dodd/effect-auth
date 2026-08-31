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
