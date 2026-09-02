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
 * `Database` is which database it all runs on: PGlite by default, and SQLite,
 * PostgreSQL or MySQL through `EFFECT_AUTH_TEST_DATABASE` or
 * `AuthTest.Settings.database`.
 *
 * **Gotchas**
 *
 * This entry point imports `@effect/sql-pglite`. Install it as a dev
 * dependency; nothing under `effect-auth` or `effect-auth/client` depends on
 * it, so a production bundle never sees it. The other three drivers live behind
 * `effect-auth/testing/{sqlite,postgres,mysql}` and are loaded only when asked
 * for.
 *
 * @since 0.1.0
 */
export * as Database from "./Database.js"
export * as AnonymousTest from "./AnonymousTest.js"
export * as EmailOtpTest from "./EmailOtpTest.js"
export * as OneTapTest from "./OneTapTest.js"
export * as PasskeysTest from "./PasskeysTest.js"
export * as PhoneTest from "./PhoneTest.js"
export * as TwoFactorTest from "./TwoFactorTest.js"
export * as UsernameTest from "./UsernameTest.js"
export * as MockProvider from "./MockProvider.js"
export * as TestEmails from "./TestEmails.js"
export * as TestHttpClient from "./TestHttpClient.js"
export * as AuthTest from "./TestLayer.js"
