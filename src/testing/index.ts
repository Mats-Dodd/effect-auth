/**
 * `effect-auth/testing` — a complete deployment for a test suite.
 *
 * **Details**
 *
 * `AuthTest` is the deployment: the layers, the options, and the seams
 * (`freshClock`, `countingHasher`, `recordingEvents`). `TestEmails` is the
 * captured outbox, `TestHttpClient` drives the real request pipeline through a
 * generated client, and `MockProvider` stands in for an OAuth provider.
 *
 * **Gotchas**
 *
 * This entry point imports `@effect/sql-pglite`. Install it as a dev
 * dependency; nothing under `effect-auth` or `effect-auth/client` depends on
 * it, so a production bundle never sees it.
 *
 * @since 1.0.0
 */
export * as MockProvider from "./MockProvider.js"
export * as TestEmails from "./TestEmails.js"
export * as TestHttpClient from "./TestHttpClient.js"
export * as AuthTest from "./TestLayer.js"
