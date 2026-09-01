# effect-auth roadmap

This roadmap grows `effect-auth` from a focused authentication library into a broader identity platform without sacrificing the qualities that make it compelling today: explicit Effect services, typed failures, composable layers, feature-local persistence, and no hidden state.

The sequence follows the dependency graph:

```text
Human authentication
  └─ factors, challenges, assurance, recovery

Organizations and administration
  └─ ownership, membership, policy, lifecycle, auditing

API and machine authentication
  └─ non-human principals, scopes, keys, token issuance

Enterprise identity
  └─ organization-bound providers, SAML, JIT, SCIM
```

Each phase should leave the library in a coherent, independently useful state. Feature parity with other authentication libraries is not the goal by itself; equivalent breadth should be expressed naturally in Effect.

## Design rules

New capabilities should be vertical modules rather than options added to a growing `Auth.layer` configuration object. A feature should ordinarily own:

- its `HttpApiGroup` and typed errors;
- domain services and layers;
- handlers applied to the consumer's composed API;
- migrations and bookkeeping table, when needed;
- browser client support, when applicable;
- test layers, fixtures, and captured external seams;
- security invariants and operational documentation.

Composition should continue to look like ordinary Effect composition:

```ts
const IdentityLive = Layer.mergeAll(
  AuthLive,
  PasskeysLive,
  OrganizationsLive,
  ApiKeysLive
)
```

Avoid a central plugin registry, privileged plugin internals, global state, and value-dependent layer types. Plugins should build on the same public services available to applications.

## Phase 1 — Human authentication

Complete the common interactive authentication methods before expanding into product and enterprise concerns.

### Shared foundations

Establish shared concepts before implementing passkeys and multi-factor authentication:

- authenticators and factors;
- enrollment and challenge lifecycles;
- single-use challenge consumption;
- recovery methods and recovery-code rotation;
- session assurance levels;
- step-up authentication;
- recently authenticated requirements;
- authentication method references (for example password, passkey, TOTP);
- trusted-device lifecycle and revocation.

These concepts should extend the existing freshness model rather than allowing every authentication method to invent incompatible semantics.

### Features

Suggested order:

1. Email OTP
2. Username sign-in
3. Anonymous accounts and conversion into permanent accounts
4. Passkeys/WebAuthn
5. TOTP two-factor authentication
6. Recovery codes and trusted devices
7. Phone/SMS OTP behind a provider service
8. One Tap and additional social providers

Every new method must preserve account-linking rules, user provision hooks, no-enumeration behavior, rate limiting, redaction, and transactional token consumption.

## Phase 2 — Organizations and administration

Add product-level identity management after human authentication has stable assurance and recovery concepts.

### Administration

- active, suspended, and banned account states;
- administrative user creation and updates;
- session inspection and revocation;
- account recovery controls;
- user impersonation with explicit provenance and expiry;
- auditable administrative actions.

A ban or suspension must affect existing authority, not only prevent the next sign-in. Its design must account for active sessions, secondary session stores, and cookie-cache invalidation.

### Organizations

- organizations;
- memberships;
- invitations;
- teams;
- roles and permissions;
- ownership transfer;
- organization-aware hooks and events;
- organization-aware audit records.

Authorization should remain outside authentication core. `CurrentUser` and related context services are inputs to an organization or policy module, not reasons to add roles directly to core auth.

```ts
const AppApi = HttpApi.make("app")
  .addHttpApi(auth.Api)
  .add(Organizations.Api)
  .add(Admin.Api)
```

## Phase 3 — API and machine authentication

Introduce non-browser credentials only after lifecycle, ownership, and administrative controls are established.

Suggested order:

1. Managed API keys
2. Scoped bearer credentials
3. JWT/JWKS issuance and signing-key rotation
4. Service principals
5. OAuth 2.1 authorization server
6. Device authorization
7. MCP and agent authentication

### Principal model

Machine credentials must not pretend to be users. Establish an explicit principal model before building multiple machine-auth features:

```ts
type Principal =
  | { readonly _tag: "User"; readonly userId: UserId }
  | { readonly _tag: "Service"; readonly serviceId: ServiceId }
  | { readonly _tag: "ApiKey"; readonly keyId: ApiKeyId }
```

The final model should define:

- credential ownership by users, services, or organizations;
- scopes, audiences, and permissions;
- expiry and rotation;
- revocation and cache behavior;
- secret display exactly once;
- token introspection where appropriate;
- audit attribution;
- rate limits and quotas;
- distinction between delegation and impersonation.

This is the largest architectural decision after the current user model and should be designed before individual machine-auth plugins establish incompatible principal assumptions.

## Phase 4 — Enterprise identity

Build enterprise identity on organizations, administrative lifecycle controls, auditing, and machine credentials.

Suggested order:

1. Dynamic OIDC provider registration
2. Domain ownership verification
3. Organization-specific SSO discovery and enforcement
4. SAML service-provider support
5. Just-in-time provisioning and attribute mapping
6. SCIM users
7. SCIM groups and role projection
8. IdP-initiated flows

The dependency model should remain clear:

- organizations own identity-provider configurations;
- verified domains route users to organizations;
- SSO provisions users and memberships through the existing provisioning choke point;
- SCIM manages users, groups, and lifecycle state;
- machine credentials authenticate SCIM clients;
- audit events record provider and directory changes.

Enterprise flows must retain the existing fail-closed approach to redirects, issuer and audience validation, token verification, linking, and error disclosure.

## Later ecosystem work

These can proceed independently where they do not distort the core roadmap:

- additional SQL dialect validation and documentation;
- Prisma, Drizzle, MongoDB, and other persistence adapters;
- framework adapters for common non-Effect runtimes;
- React and other client bindings over the existing reactive client;
- CLI-assisted migration and schema workflows;
- CAPTCHA and compromised-password integrations;
- internationalized user-facing error mapping;
- additional OAuth providers;
- community plugin authoring guides and templates.

Billing belongs in integrations built on identity events and organizations, not in authentication core.

## Definition of done for every feature

A feature is complete when it has:

- a stable typed contract and documented error union;
- explicit service requirements and provided layers;
- redaction at every secret-bearing boundary;
- deterministic time-based tests using `Clock`;
- concurrency tests for single-use and uniqueness behavior;
- no-enumeration and redirect tests where applicable;
- migration and rollback/operational guidance;
- HTTP, domain, client, and type-level tests as applicable;
- OpenAPI coverage;
- examples showing composition with the existing stack;
- documented interactions with hooks, events, session revocation, rate limits, custom user fields, and cookie caching.

## Guiding constraint

Do not pursue breadth by weakening the architecture. The roadmap succeeds only if the larger library retains the current property that security constraints improve the developer experience rather than bypassing it.
