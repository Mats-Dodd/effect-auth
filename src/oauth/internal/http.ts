/**
 * Internal helpers for reading a provider's HTTP responses. Not exported from
 * the package: nothing here is part of the public API.
 *
 * @internal
 */
import type { Cause, Duration, Schema } from "effect"
import { Effect } from "effect"
import type { HttpClientError, HttpClientResponse } from "effect/unstable/http"

/**
 * Reads a response body as JSON under a deadline of its own.
 *
 * **Details**
 *
 * The body gets its own deadline because headers arriving is no promise that
 * the bytes will: a provider that answers and then trickles bytes forever would
 * otherwise hold the fiber that read it — a discovery build, a callback, a key
 * set fetch — open indefinitely.
 *
 * The deadline is left in the error channel rather than mapped here. Every
 * caller reports an unreadable body as its own error, and the two failures it
 * reports it for — a body that never arrived and a body that could not be read
 * — are the same failure to that caller.
 *
 * @internal
 */
export const jsonWithin = (
  response: HttpClientResponse.HttpClientResponse,
  timeout: Duration.Input
): Effect.Effect<Schema.Json, HttpClientError.HttpClientError | Cause.TimeoutError> =>
  Effect.timeout(response.json, timeout)
