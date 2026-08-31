/**
 * Internal record helpers. Not exported from the package: nothing here is part
 * of the public API.
 *
 * @internal
 */

/**
 * `record` with every key it holds `undefined` at dropped — in the type as well
 * as in the value.
 *
 * @internal
 */
export type Defined<A> = { readonly [K in keyof A]?: Exclude<A[K], undefined> }

/**
 * A copy of `record` with every `undefined`-valued key dropped.
 *
 * **Details**
 *
 * Written onto a null-prototype object, so a key called `__proto__` or
 * `constructor` is data rather than a prototype write — these records are built
 * from patch objects and option sections whose keys are ours but whose *values*
 * came off the wire or out of a caller's hands.
 *
 * "Absent" and "explicitly null" stay distinct: only `undefined` is dropped, so
 * a patch that clears a column by passing `null` still reaches the statement.
 *
 * The keys survive into the result type, each of them optional — which is what
 * "droppable" means. That is what makes the result safe to spread over a record
 * of defaults: `{ ...defaults, ...omitUndefined(section) }` is exactly
 * `typeof defaults`, because no key can overwrite a default with `undefined`.
 *
 * @internal
 */
export const omitUndefined = <A extends object>(record: A): Defined<A> =>
  Object.assign(
    Object.create(null),
    Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined))
  )

/**
 * `defaults`, with whatever `overrides` actually states applied over it.
 *
 * **Details**
 *
 * The one shape every settings section in this library resolves through: a
 * caller may leave the section out entirely, or pass it with an explicit
 * `undefined` for any field, and neither may cost a default.
 *
 * @internal
 */
export const withDefaults = <A extends object>(
  defaults: A,
  overrides: { readonly [K in keyof A]?: A[K] | undefined } | undefined
): A => ({ ...defaults, ...omitUndefined(overrides ?? {}) })
