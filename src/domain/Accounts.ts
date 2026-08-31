/**
 * Sign-in methods: linking OAuth identities to users, and removing them again.
 *
 * An {@link Account} row is one way to sign in. A user may have several — a
 * password (the synthetic `local:credential` issuer) and any number of OAuth
 * providers — and `Accounts` is what decides, when a provider hands back an
 * identity, whether that identity *is* an existing user, may be attached to
 * one, or calls for a new one.
 *
 * **Details**
 *
 * The decision is deliberately conservative, because getting it wrong is an
 * account-takeover bug: anyone who can obtain an e-mail address at a provider
 * that does not verify addresses could otherwise claim somebody else's account
 * by presenting it. So identity is matched on `(issuer, accountId)` — the
 * provider's own stable subject — and an e-mail address alone is never enough
 * on its own.
 *
 * @since 1.0.0
 */
import { Context, Effect, Layer, Option } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import { insertRow } from "../internal/effects.js"
import { pickKeys } from "../internal/records.js"
import type { OAuthUserInfo } from "../oauth/Provider.js"
import { AccountAlreadyLinked, CannotUnlinkLastAccount, NotFound, UserNotFound } from "./Errors.js"
import { AuthEvents, oauthMethod, publishSafely } from "./Events.js"
import type { PolicyRefused, ProvisionSource } from "./Hooks.js"
import { AuthHooks } from "./Hooks.js"
import type { AccountId, User, UserId, UserInsertOf } from "./Schema.js"
import { Account, normalizeEmail, User as UserModel, UserModelRef } from "./Schema.js"
import type { AccountTokens, PersistenceError } from "./Stores.js"
import { AccountStore, isUniqueViolation, UserStore, WithAuthTransaction } from "./Stores.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What a provider told us about the person who just authorized.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthIdentity {
  /**
   * The configured provider id — `"github"`, `"google"`. Names the row and the
   * entry in `trustedProviders`.
   */
  readonly providerId: string
  /**
   * The provider's OIDC issuer URL, or `local:oauth:<providerId>` for a plain
   * OAuth2 provider that publishes none. Half of the account's identity.
   */
  readonly issuer: string
  /**
   * The provider's stable subject for this person — `sub`, or the numeric user
   * id. The other half of the identity.
   *
   * **Gotchas**
   *
   * Never an e-mail address. Addresses change hands; subjects do not.
   */
  readonly accountId: string
  /**
   * The address the provider reports, used only to look for a local account to
   * link to, and stored on a user this flow creates.
   */
  readonly email: string
  /**
   * Whether the provider claims to have verified that address. This is the
   * single most important field on this object: it gates implicit linking.
   */
  readonly emailVerified: boolean
  /**
   * Display name for a user provisioned by this flow. Defaults to the address.
   */
  readonly name?: string | undefined
  /**
   * Avatar URL for a user provisioned by this flow.
   */
  readonly image?: string | null | undefined
  /**
   * The provider credentials to store, refreshed on every sign-in.
   */
  readonly tokens?: AccountTokens | undefined
}

/**
 * The outcome of a link.
 *
 * @category models
 * @since 1.0.0
 */
export interface LinkResult {
  readonly user: User
  readonly account: Account
  /**
   * `true` when this flow provisioned the user — the caller's cue to treat the
   * callback as a registration rather than a sign-in.
   */
  readonly userCreated: boolean
  /**
   * `true` when this flow created the account row. `false` means the provider
   * identity was already known and this was an ordinary sign-in.
   */
  readonly accountCreated: boolean
}

/**
 * The provider profile a hook is shown, recovered from the identity the flow
 * built out of it.
 *
 * **Details**
 *
 * `Accounts` is handed an {@link OAuthIdentity} rather than the raw
 * `OAuthUserInfo`, because by this point the flow has already resolved the two
 * questions only it can answer — which issuer this identity belongs under, and
 * which claim is the provider's stable subject. This puts those answers back
 * into the shape hooks are written against, so one `beforeUserCreate` covers
 * every provider a deployment serves.
 */
const userInfoOf = (identity: OAuthIdentity): OAuthUserInfo => ({
  id: identity.accountId,
  email: identity.email,
  emailVerified: identity.emailVerified,
  name: identity.name,
  image: identity.image,
  issuer: identity.issuer
})

// -----------------------------------------------------------------------------
// The linking gate
// -----------------------------------------------------------------------------

/**
 * Whether a provider identity may be attached to an existing local account on
 * the strength of a matching e-mail address alone.
 *
 * **Details**
 *
 * Two conditions, both required:
 *
 * 1. the provider says it verified the address — otherwise the "match" is just
 *    a string somebody typed into a profile form;
 * 2. the provider is listed in `trustedProviders`, **or** the local account has
 *    itself verified that address — so at least one side of the match has been
 *    proven.
 *
 * When it returns `false` the flow fails `AccountAlreadyLinked`, and the person
 * must sign in with the method they already have and link deliberately.
 *
 * @category guards
 * @since 1.0.0
 */
export const canLinkImplicitly = (options: {
  readonly providerId: string
  readonly providerEmailVerified: boolean
  readonly localEmailVerified: boolean
  readonly trustedProviders: ReadonlyArray<string>
}): boolean =>
  options.providerEmailVerified &&
  (options.trustedProviders.includes(options.providerId) || options.localEmailVerified)

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Accounts} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface AccountsService {
  /**
   * Resolves a provider identity to a user, in three steps.
   *
   * **Details**
   *
   * 1. An account already exists for `(issuer, accountId)`: this is a sign-in.
   *    The stored provider tokens are refreshed and nothing else changes.
   * 2. No such account, but a user holds the address the provider reported: the
   *    account is attached to that user *only* if `canLinkImplicitly` allows
   *    it, otherwise the call fails `AccountAlreadyLinked`.
   * 3. Neither: a user and an account are created together in one transaction,
   *    with `emailVerified` taken from the provider's claim.
   *
   * **Gotchas**
   *
   * Step 2 consults `beforeAccountLink` — an identity is about to be attached
   * to somebody who already exists — and step 3 consults `beforeUserCreate` and
   * `afterUserCreate` instead, because a first provisioning is not a link.
   * Either refusal is a `PolicyRefused`, and in step 3 it aborts the
   * transaction the user and the account would have committed in.
   */
  readonly linkOAuth: (
    identity: OAuthIdentity
  ) => Effect.Effect<LinkResult, AccountAlreadyLinked | PolicyRefused | UserNotFound | PersistenceError>

  /**
   * Attaches a provider identity to a user who is already signed in — the
   * `link-social` flow.
   *
   * **Gotchas**
   *
   * No e-mail matching and no trust rules apply here: the person proved they
   * control both sides. The one refusal is an identity that already belongs to
   * somebody else, which fails `AccountAlreadyLinked`. Re-linking an identity
   * the user already holds is a no-op that refreshes the tokens.
   *
   * `beforeAccountLink` is consulted before a *new* row is written, and not on
   * that no-op: nothing is being attached that was not attached already.
   */
  readonly linkToUser: (
    userId: UserId,
    identity: OAuthIdentity
  ) => Effect.Effect<LinkResult, AccountAlreadyLinked | PolicyRefused | UserNotFound | PersistenceError>

  /**
   * Removes one sign-in method.
   *
   * **Gotchas**
   *
   * Refuses with `CannotUnlinkLastAccount` when it would leave the user unable
   * to sign in at all.
   *
   * The count and the delete run in one transaction, and the count is taken
   * with `AccountStore.listByUserIdForUpdate`, which holds a write lock on the
   * user's rows for the rest of it. The lock is the part that matters: a plain
   * `BEGIN` is READ COMMITTED on PostgreSQL, under which two concurrent
   * unlinks would each see two methods, each delete a different one, and both
   * commit — leaving a user with no way to sign in.
   */
  readonly unlink: (
    accountId: AccountId,
    userId: UserId
  ) => Effect.Effect<void, CannotUnlinkLastAccount | NotFound | PersistenceError>

  /**
   * Every sign-in method a user holds, oldest first.
   */
  readonly listForUser: (userId: UserId) => Effect.Effect<ReadonlyArray<Account>, PersistenceError>
}

/**
 * The account-linking service.
 *
 * @category services
 * @since 1.0.0
 */
export class Accounts extends Context.Service<Accounts, AccountsService>()("effect-auth/Accounts") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Accounts} implementation.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: () => Effect.Effect<
  AccountsService,
  never,
  AuthConfig | AuthEvents | UserStore | AccountStore | WithAuthTransaction
> = Effect.fnUntraced(function*() {
  const config = yield* AuthConfig
  const users = yield* UserStore
  const accounts = yield* AccountStore
  const transaction = yield* WithAuthTransaction
  const events = yield* AuthEvents
  // A `Context.Reference` with a no-op default, so a deployment that installs
  // nothing provides nothing — and, being read here, the set is fixed when the
  // layer is built rather than looked up on every request.
  const hooks = yield* AuthHooks
  // The deployment's own model, behind a reference whose default is the base
  // one. This module is base-typed on purpose — an identity carries base fields
  // and nothing else — but a hook may not be, so the model is what says which
  // of the columns on a rewritten row are the deployment's.
  const model = yield* UserModelRef

  const insertAccount = Effect.fnUntraced(function*(userId: UserId, identity: OAuthIdentity) {
    const tokens = identity.tokens
    const row = yield* insertRow(Account.insert, {
      issuer: identity.issuer,
      accountId: identity.accountId,
      providerId: identity.providerId,
      userId,
      accessToken: tokens?.accessToken ?? null,
      refreshToken: tokens?.refreshToken ?? null,
      idToken: tokens?.idToken ?? null,
      accessTokenExpiresAt: tokens?.accessTokenExpiresAt ?? null,
      refreshTokenExpiresAt: tokens?.refreshTokenExpiresAt ?? null,
      scope: tokens?.scope ?? null,
      passwordHash: null
    })
    return yield* accounts.create(row)
  })

  const refreshTokens = Effect.fnUntraced(function*(account: Account, identity: OAuthIdentity) {
    if (identity.tokens === undefined) return account
    const updated = yield* accounts.updateTokens(account.id, identity.tokens)
    return Option.getOrElse(updated, () => account)
  })

  /**
   * Puts what a `beforeUserCreate` answered with back through the schema.
   *
   * The base half is checked by the base user model, which is the only one this
   * module can name — so a hook cannot store a row the base schema would have
   * rejected. The deployment's own columns ride across by name, because
   * `User.insert` does not know them and would drop the very rewrite a hook
   * installed through `hooksOf` was written to make; `completeInsert` then fills
   * in whichever of them the hook left out.
   */
  const revalidate = Effect.fnUntraced(function*(rewritten: UserInsertOf<{}>) {
    const validated = yield* insertRow(UserModel.insert, rewritten)
    return yield* model.completeInsert(Object.assign(validated, pickKeys(rewritten, model.extraKeys)))
  })

  /**
   * Writes the user row a first sign-in through a provider creates, asking the
   * deployment's policy on the way in and on the way out.
   *
   * **Gotchas**
   *
   * This is `Users.provision`'s sequence rather than a call to it, and the two
   * have to stay in step. `Users` reads `Passwords`, which is layered above
   * this module, so a dependency the other way round would be a cycle in the
   * layer graph and `Auth.layer` would not build.
   *
   * A rewrite goes back through {@link revalidate} rather than straight to the
   * store, for the reasons given there.
   *
   * It opens no transaction: the caller's is what makes a refusal, or a failing
   * `afterUserCreate`, take the account row down with the user.
   */
  const provision = Effect.fnUntraced(function*(identity: OAuthIdentity, email: string) {
    const source: ProvisionSource = {
      _tag: "OAuth",
      providerId: identity.providerId,
      info: userInfoOf(identity)
    }
    const candidate = yield* insertRow(UserModel.insert, {
      name: identity.name ?? email,
      email,
      emailVerified: identity.emailVerified,
      image: identity.image ?? null
    })

    const before = hooks.beforeUserCreate
    const row = before === undefined
      ? candidate
      : yield* revalidate(yield* before({ candidate, source }))
    const user = yield* users.create(row)

    const after = hooks.afterUserCreate
    if (after !== undefined) {
      yield* after({ user, source })
    }
    return user
  })

  const linked = (userId: UserId, account: Account) =>
    publishSafely(events, {
      _tag: "AccountLinked",
      userId,
      accountId: account.id,
      providerId: account.providerId,
      issuer: account.issuer
    })

  const attemptLinkOAuth = Effect.fnUntraced(function*(identity: OAuthIdentity) {
    // 1. The provider identity is already known: an ordinary sign-in.
    const existing = yield* accounts.findByIssuerAccountId(identity.issuer, identity.accountId)
    if (Option.isSome(existing)) {
      // The foreign key cascades, so a missing owner only happens on a store
      // that does not enforce it. Refuse rather than provision a replacement.
      const found = yield* users.findById(existing.value.userId)
      const owner = yield* Effect.fromOption(found, () => new UserNotFound())
      const account = yield* refreshTokens(existing.value, identity)
      return { user: owner, account, userCreated: false, accountCreated: false } satisfies LinkResult
    }

    // 2. Somebody already holds the address the provider reported.
    const email = normalizeEmail(identity.email)
    const byEmail = yield* users.findByEmail(email)
    if (Option.isSome(byEmail)) {
      const user = byEmail.value
      const allowed = canLinkImplicitly({
        providerId: identity.providerId,
        providerEmailVerified: identity.emailVerified,
        localEmailVerified: user.emailVerified,
        trustedProviders: config.trustedProviders
      })
      if (!allowed) {
        return yield* Effect.fail(new AccountAlreadyLinked({ providerId: identity.providerId }))
      }
      // A row is about to be attached to somebody who already exists, which is
      // the one thing `beforeAccountLink` is for. It is asked after the gate
      // above rather than before it, so a policy cannot stand in for the
      // account-takeover rule that decides whether this link is permissible at
      // all.
      const beforeLink = hooks.beforeAccountLink
      if (beforeLink !== undefined) {
        yield* beforeLink({ user, providerId: identity.providerId, info: userInfoOf(identity) })
      }
      const account = yield* insertAccount(user.id, identity)
      yield* linked(user.id, account)
      return { user, account, userCreated: false, accountCreated: true } satisfies LinkResult
    }

    // 3. A new person. The user and their first sign-in method commit together.
    const result = yield* transaction.run(Effect.gen(function*() {
      const user = yield* provision(identity, email)
      const account = yield* insertAccount(user.id, identity)
      return { user, account }
    }))

    yield* publishSafely(events, {
      _tag: "UserCreated",
      userId: result.user.id,
      email: result.user.email,
      emailVerified: result.user.emailVerified,
      method: oauthMethod(identity.providerId)
    })
    yield* linked(result.user.id, result.account)
    return { ...result, userCreated: true, accountCreated: true } satisfies LinkResult
  })

  /**
   * Two callbacks for one brand-new identity — or a callback racing a password
   * sign-up for one address — have one loser, whose insert the unique index
   * rejects. That is a race, not a fault: run the resolution once more, and it
   * now finds the row the winner wrote and completes as a sign-in or a link.
   * Nothing is published before the write that failed, so the retry cannot
   * duplicate an event.
   */
  const linkOAuth = (identity: OAuthIdentity) =>
    Effect.retry(attemptLinkOAuth(identity), {
      while: (error) => error._tag === "PersistenceError" && isUniqueViolation(error),
      times: 1
    })

  const linkToUser = Effect.fnUntraced(function*(userId: UserId, identity: OAuthIdentity) {
    const found = yield* users.findById(userId)
    const owner = yield* Effect.fromOption(found, () => new UserNotFound())

    const existing = yield* accounts.findByIssuerAccountId(identity.issuer, identity.accountId)
    if (Option.isSome(existing)) {
      if (existing.value.userId !== userId) {
        return yield* Effect.fail(new AccountAlreadyLinked({ providerId: identity.providerId }))
      }
      const account = yield* refreshTokens(existing.value, identity)
      return { user: owner, account, userCreated: false, accountCreated: false } satisfies LinkResult
    }

    // The `linkSocial` half of `beforeAccountLink`: a deliberate link onto an
    // account that already exists. The branch above is not one — it refreshes
    // the tokens of an identity this user already holds, and attaches nothing.
    const beforeLink = hooks.beforeAccountLink
    if (beforeLink !== undefined) {
      yield* beforeLink({ user: owner, providerId: identity.providerId, info: userInfoOf(identity) })
    }

    const account = yield* insertAccount(userId, identity)
    yield* linked(userId, account)
    return { user: owner, account, userCreated: false, accountCreated: true } satisfies LinkResult
  })

  const unlink = Effect.fnUntraced(function*(accountId: AccountId, userId: UserId) {
    const removed = yield* transaction.run(Effect.gen(function*() {
      // Locking read: a concurrent unlink of a *different* method now waits
      // here rather than counting the same two rows we are counting.
      const held = yield* accounts.listByUserIdForUpdate(userId)
      const target = held.find((account) => account.id === accountId)
      if (target === undefined) {
        return yield* Effect.fail(new NotFound())
      }
      if (held.length <= 1) {
        return yield* Effect.fail(new CannotUnlinkLastAccount())
      }
      const deleted = yield* accounts.deleteById(accountId, userId)
      if (!deleted) {
        return yield* Effect.fail(new NotFound())
      }
      return target
    }))

    yield* publishSafely(events, {
      _tag: "AccountUnlinked",
      userId,
      accountId: removed.id,
      providerId: removed.providerId,
      issuer: removed.issuer
    })
  })

  return Accounts.of({
    linkOAuth,
    linkToUser,
    unlink,
    listForUser: (userId) => accounts.listByUserId(userId)
  })
})

/**
 * Provides {@link Accounts}.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<
  Accounts,
  never,
  AuthConfig | AuthEvents | UserStore | AccountStore | WithAuthTransaction
> = Layer.effect(Accounts, make())
