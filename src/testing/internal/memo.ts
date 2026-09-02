/**
 * One job: hand back the same value for the same key.
 *
 * `@effect/vitest`'s `layer()` memoises by object identity, so a harness that
 * builds an equivalent layer twice gets two databases. Every "one database per
 * model, per provider" claim in this package rests on a memo, and this is the
 * one memo they all use.
 *
 * Not part of the public API.
 *
 * @internal
 */

/**
 * `make`, called at most once per key. The keys are models and providers —
 * long-lived objects a suite holds anyway — so the cache is weak and a fixture
 * that goes out of scope takes its layer with it.
 *
 * @internal
 */
export const memoise = <K extends object, A>(make: (key: K) => A): ((key: K) => A) => {
  const cache = new WeakMap<K, A>()
  return (key) => {
    const existing = cache.get(key)
    if (existing !== undefined) return existing
    const created = make(key)
    cache.set(key, created)
    return created
  }
}
