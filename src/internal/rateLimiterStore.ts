/**
 * A process-local `RateLimiterStore` that deletes what it no longer needs.
 *
 * Mirrors `RateLimiter.layerStoreMemory` from `effect/unstable/persistence`
 * (rc.112) — the same fixed-window counters, the same token buckets, the same
 * adaptive state machine — with one difference: every entry carries the instant
 * it stops meaning anything, and a swept map is what bounds the store's size.
 * Upstream *resets* an expired fixed window the next time its key is used and
 * never deletes it, so a key used once and never again is held for the life of
 * the process.
 *
 * Not part of the public API: `http/RateLimits.ts` publishes the layer.
 *
 * @internal
 */
import type { Scope } from "effect"
import { Duration, Effect, Schedule } from "effect"
import { RateLimiter } from "effect/unstable/persistence"

/**
 * The shape of `effect`'s `RateLimiterStore`, named so the store below can
 * state what it builds.
 *
 * @internal
 */
export type RateLimiterStoreService = RateLimiter.RateLimiterStore["Service"]

/**
 * How often the sweep runs when a caller does not say.
 *
 * **Details**
 *
 * A minute is no shorter than either bucket this library configures (ten
 * seconds and sixty), so a window is dead by the time it is collected, and it is
 * short enough that a burst of spoofed client addresses costs a minute of map
 * entries rather than a process lifetime of them.
 *
 * @internal
 */
export const defaultSweepInterval: Duration.Duration = Duration.minutes(1)

/** Upstream's grace period: how long an adaptive state outlives its window. */
const adaptiveStateTtlGraceMillis = 60_000

/** Upstream's ceiling on a learned or fed-back adaptive window. */
const adaptiveStateMaxWindowMillis = 60 * 60 * 1_000

const clampAdaptiveDurationMillis = (millis: number): number => {
  if (Number.isNaN(millis) || millis <= 0) return 1
  return Math.min(millis, adaptiveStateMaxWindowMillis)
}

interface FixedCounter {
  count: number
  expiresAt: number
}

interface TokenBucket {
  tokens: number
  lastRefill: number
  expiresAt: number
}

interface AdaptiveState {
  phase: RateLimiter.AdaptivePhase
  epoch: number
  cooldownUntil: number
  learningStartedAt: number
  observedTokens: number
  learnedLimit: number
  learnedWindowMillis: number
  expiresAt: number
}

/**
 * What {@link makeStore} builds: the store itself, and the two handles that
 * make its eviction observable.
 *
 * @internal
 */
export interface EvictingStore {
  /** The store, as `RateLimiter.RateLimiterStore` expects it. */
  readonly store: RateLimiterStoreService
  /** Deletes every entry whose expiry has passed, and answers how many went. */
  readonly sweep: Effect.Effect<number>
  /** How many entries are held right now, swept or not. */
  readonly size: Effect.Effect<number>
}

/**
 * The store and its sweep, with nothing running yet.
 *
 * @internal
 */
const make = (): EvictingStore => {
  const fixedCounters = new Map<string, FixedCounter>()
  const tokenBuckets = new Map<string, TokenBucket>()
  const adaptiveStates = new Map<string, AdaptiveState>()

  const getAdaptiveState = (key: string, now: number): AdaptiveState | undefined => {
    const state = adaptiveStates.get(key)
    if (!state) return undefined
    if (state.expiresAt <= now) {
      adaptiveStates.delete(key)
      return undefined
    }
    return state
  }

  const cooldownExpiresAt = (cooldownUntil: number): number => cooldownUntil + adaptiveStateTtlGraceMillis

  const learningExpiresAt = (now: number, fallbackWindow: Duration.Duration): number =>
    now + Duration.toMillis(fallbackWindow) + adaptiveStateTtlGraceMillis

  const learnedExpiresAt = (now: number, learnedWindowMillis: number): number =>
    now + learnedWindowMillis + adaptiveStateTtlGraceMillis

  /**
   * Deleting from a `Map` while iterating it is defined behaviour: an entry
   * removed before the cursor reaches it is simply not visited.
   */
  const sweepAt = (now: number): number => {
    let evicted = 0
    for (const [key, counter] of fixedCounters) {
      if (counter.expiresAt <= now) {
        fixedCounters.delete(key)
        evicted++
      }
    }
    for (const [key, bucket] of tokenBuckets) {
      if (bucket.expiresAt <= now) {
        tokenBuckets.delete(key)
        evicted++
      }
    }
    for (const [key, state] of adaptiveStates) {
      if (state.expiresAt <= now) {
        adaptiveStates.delete(key)
        evicted++
      }
    }
    return evicted
  }

  const store = RateLimiter.RateLimiterStore.of({
    fixedWindow: (options) =>
      Effect.clockWith((clock) =>
        Effect.sync(() => {
          const refillRateMillis = Duration.toMillis(options.refillRate)
          const now = clock.currentTimeMillisUnsafe()
          let counter = fixedCounters.get(options.key)
          if (!counter || counter.expiresAt <= now) {
            counter = { count: 0, expiresAt: now }
            fixedCounters.set(options.key, counter)
          }
          if (options.limit && counter.count + options.tokens > options.limit) {
            return [counter.count + options.tokens, counter.expiresAt - now] as const
          }
          counter.count += options.tokens
          counter.expiresAt += refillRateMillis * options.tokens
          return [counter.count, counter.expiresAt - now] as const
        })
      ),
    tokenBucket: (options) =>
      Effect.clockWith((clock) =>
        Effect.sync(() => {
          const refillRateMillis = Duration.toMillis(options.refillRate)
          const now = clock.currentTimeMillisUnsafe()
          let bucket = tokenBuckets.get(options.key)
          if (!bucket) {
            bucket = { tokens: options.limit, lastRefill: now, expiresAt: now }
            tokenBuckets.set(options.key, bucket)
          } else {
            const elapsed = now - bucket.lastRefill
            const tokensToAdd = Math.floor(elapsed / refillRateMillis)
            if (tokensToAdd > 0) {
              bucket.tokens = Math.min(options.limit, bucket.tokens + tokensToAdd)
              bucket.lastRefill += tokensToAdd * refillRateMillis
            }
          }

          const newTokenCount = bucket.tokens - options.tokens
          if (options.allowOverflow || newTokenCount >= 0) {
            bucket.tokens = newTokenCount
          }
          // A bucket is worth keeping only until it has refilled: full and idle
          // is exactly the state an absent key is rebuilt in, so a bucket that
          // has reached it may go. A bucket in debt refills later, and the
          // arithmetic says so.
          bucket.expiresAt = bucket.lastRefill + ((options.limit - bucket.tokens) * refillRateMillis)
          return newTokenCount
        })
      ),
    adaptiveConsume: (options) =>
      Effect.clockWith((clock) =>
        Effect.sync(() => {
          const now = clock.currentTimeMillisUnsafe()
          const state = getAdaptiveState(options.key, now)
          if (!state) {
            return {
              delay: Duration.zero,
              epoch: 0,
              phase: "inactive"
            }
          }

          if (state.phase === "cooldown") {
            if (state.cooldownUntil > now) {
              return {
                delay: Duration.millis(state.cooldownUntil - now),
                epoch: state.epoch,
                phase: "cooldown"
              }
            }

            state.phase = "learning"
            state.epoch += 1
            state.learningStartedAt = now
            state.observedTokens = options.tokens
            state.expiresAt = learningExpiresAt(now, options.fallbackWindow)
            return {
              delay: Duration.zero,
              epoch: state.epoch,
              phase: "learning"
            }
          }

          if (state.phase === "learning") {
            state.observedTokens += options.tokens
            return {
              delay: Duration.zero,
              epoch: state.epoch,
              phase: state.phase
            }
          }

          if (state.phase === "learned") {
            const refillRateMillis = state.learnedWindowMillis / state.learnedLimit
            if (state.cooldownUntil <= now) {
              state.observedTokens = 0
              state.cooldownUntil = now
            }
            state.observedTokens += options.tokens
            state.cooldownUntil += refillRateMillis * options.tokens

            const ttl = state.cooldownUntil - now
            const ttlTotal = state.observedTokens * refillRateMillis
            const elapsed = ttlTotal - ttl
            const windowNumber = Math.floor((state.observedTokens - 1) / state.learnedLimit)
            const remaining = (windowNumber * state.learnedWindowMillis) - elapsed

            return {
              delay: remaining <= 0 ? Duration.zero : Duration.millis(remaining),
              epoch: state.epoch,
              phase: state.phase
            }
          }

          return {
            delay: Duration.zero,
            epoch: state.epoch,
            phase: state.phase
          }
        })
      ),
    adaptiveFeedback: (options) =>
      Effect.clockWith((clock) =>
        Effect.sync(() => {
          if (options.status !== 429 || options.retryAfter === undefined) return

          const retryAfterMillis = clampAdaptiveDurationMillis(Duration.toMillis(options.retryAfter))

          const now = clock.currentTimeMillisUnsafe()
          const cooldownUntil = now + retryAfterMillis
          const state = getAdaptiveState(options.key, now)
          if (!state) {
            if (options.epoch !== 0) return
            adaptiveStates.set(options.key, {
              phase: "cooldown",
              epoch: 0,
              cooldownUntil,
              learningStartedAt: 0,
              observedTokens: 0,
              learnedLimit: 0,
              learnedWindowMillis: 0,
              expiresAt: cooldownExpiresAt(cooldownUntil)
            })
            return
          }

          if (state.epoch !== options.epoch) return

          if (state.phase === "cooldown") {
            state.cooldownUntil = Math.max(state.cooldownUntil, cooldownUntil)
            state.expiresAt = cooldownExpiresAt(state.cooldownUntil)
            return
          }

          if (state.phase === "learning") {
            const acceptedTokens = state.observedTokens - options.tokens
            if (acceptedTokens <= 0) {
              state.phase = "cooldown"
              state.cooldownUntil = cooldownUntil
              state.learningStartedAt = 0
              state.observedTokens = 0
              state.learnedLimit = 0
              state.learnedWindowMillis = 0
              state.expiresAt = cooldownExpiresAt(cooldownUntil)
              return
            }

            const learnedWindowMillis = clampAdaptiveDurationMillis((now - state.learningStartedAt) + retryAfterMillis)
            state.phase = "learned"
            state.epoch += 1
            state.cooldownUntil = state.learningStartedAt + learnedWindowMillis
            state.observedTokens = acceptedTokens
            state.learnedLimit = acceptedTokens
            state.learnedWindowMillis = learnedWindowMillis
            state.expiresAt = learnedExpiresAt(now, learnedWindowMillis)
            return
          }

          if (state.phase === "learned") {
            state.phase = "cooldown"
            state.cooldownUntil = cooldownUntil
            state.learningStartedAt = 0
            state.observedTokens = 0
            state.learnedLimit = 0
            state.learnedWindowMillis = 0
            state.expiresAt = cooldownExpiresAt(cooldownUntil)
          }
        })
      )
  })

  return {
    store,
    sweep: Effect.clockWith((clock) => Effect.sync(() => sweepAt(clock.currentTimeMillisUnsafe()))),
    size: Effect.sync(() => fixedCounters.size + tokenBuckets.size + adaptiveStates.size)
  }
}

/**
 * Builds the store and forks its sweep, which runs for as long as the scope
 * the store was built in.
 *
 * **Details**
 *
 * The sweep is a fiber rather than a lazy check on the way in, because the
 * entries that need collecting are exactly the ones nobody asks about again:
 * a spoofed client address is used once. A failed sweep is impossible — the
 * maps are local and the work is synchronous — so unlike `Auth.layerCleanup`
 * there is nothing to log and nothing to retry.
 *
 * @internal
 */
export const makeStore = (
  options?: { readonly sweepInterval?: Duration.Duration | undefined } | undefined
): Effect.Effect<EvictingStore, never, Scope.Scope> =>
  Effect.suspend(() => {
    const evicting = make()
    return Effect.as(
      Effect.forkScoped(
        Effect.repeat(evicting.sweep, Schedule.spaced(options?.sweepInterval ?? defaultSweepInterval))
      ),
      evicting
    )
  })
