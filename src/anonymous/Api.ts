/**
 * The HTTP contract of the anonymous plugin.
 *
 * Two endpoints under `/auth/anonymous`: become an anonymous visitor, and throw
 * that visitor away.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` is.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { RateLimited } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { SessionWithUser } from "../domain/Schema.js"
import { Ok } from "../http/AuthApi.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../http/Middleware.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * The caller holds a real account, and this endpoint only ever destroys an
 * anonymous one.
 *
 * **Details**
 *
 * Refusing rather than succeeding silently is the whole point: a client that
 * calls `delete` on a person who has since adopted their account is asking to
 * delete a real account, and that is `DELETE /auth/delete-user`'s job, with the
 * confirmation that endpoint requires.
 *
 * @category errors
 * @since 0.2.0
 */
export class NotAnonymous extends Schema.TaggedError<NotAnonymous>("effect-auth/anonymous/NotAnonymous")(
  "NotAnonymous",
  {},
  {
    description: "The caller does not hold an anonymous account",
    httpApiStatus: 403
  }
) {}

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const anonymousPrefix = "/auth/anonymous"

/**
 * The two endpoints the anonymous plugin serves.
 *
 * @category models
 * @since 0.2.0
 */
export class AnonymousApiGroup extends HttpApiGroup.make("anonymous")
  .add(
    HttpApiEndpoint.post("signIn", "/sign-in", {
      success: SessionWithUser,
      error: [PolicyRefused, OriginNotAllowed, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Become an anonymous visitor",
        description:
          "Takes no body. Creates a real user row with a synthetic address in the RFC 2606 reserved domain anonymous.invalid, marks it anonymous, and establishes a session whose methods are empty and whose level is therefore aal0 — so requireAssurance({ aal: 'aal1' }) is the one guard that excludes every anonymous visitor, and no endpoint needs an isAnonymous check of its own. Rate limited per client address, because each call writes two rows."
      })
    ),
    HttpApiEndpoint.post("delete", "/delete", {
      success: Ok,
      error: NotAnonymous
    })
      .middleware(Authenticated)
      // The decision is "is this account still anonymous", which a cookie-cache
      // snapshot cannot answer: it was written before whatever adopted it.
      .annotate(AuthoritativeSession, true)
      // The empty policy, which resolves to session.freshAge and admits aal0 —
      // an anonymous visitor must be able to discard themselves.
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Discard the caller's anonymous account",
          description:
            "Deletes the user row, and its sessions and accounts with it. Refuses with NotAnonymous for a caller whose account has since been adopted — deleting a real account is DELETE /auth/delete-user's job, with the confirmation that endpoint requires."
        })
      )
  )
  .prefix(anonymousPrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Anonymous",
      description: "Signing in as nobody, and turning that visitor into somebody later."
    })
  ) {}

/**
 * The anonymous endpoints as a standalone `HttpApi` — what `AnonymousClient`
 * builds against.
 *
 * @category models
 * @since 0.2.0
 */
export const AnonymousApi = HttpApi.make("effect-auth-anonymous").add(AnonymousApiGroup)
