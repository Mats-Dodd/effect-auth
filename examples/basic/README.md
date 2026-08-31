# examples/basic

A complete `effect-auth` deployment in six short files.

| File | What it shows |
|---|---|
| `src/Auth.ts` | `Auth.define` — one declaration of the deployment's own user field (`plan`), and everything derived from it |
| `src/Api.ts` | Composing the auth API into your own `HttpApi`, adding a plugin's group, and one protected group of your own |
| `src/Todos.ts` | Reading `CurrentUser` — and a custom field off it — in a handler; the whole of what an application knows about auth at request time |
| `src/Mailer.ts` | The `AuthEmails` seam, and the magic link plugin's own mailer beside it (a development mailer that prints the link) |
| `src/App.ts` | `auth.layer` wired to PGlite and the mailers, the plugin layered over it, then the router — plus `auth.layerWithOAuth` alongside, which is the whole of what adding GitHub sign-in costs |
| `src/main.ts` | Serving it on `node:http` |

Run the server (`tsx` is not a dependency of this repo, so fetch it on the fly):

```sh
pnpm dlx tsx examples/basic/src/main.ts
```

Run the end-to-end flow instead:

```sh
pnpm vitest run examples/basic
```

Six tests, each one driving the real pipeline through the generated `HttpApiClient`:

1. sign-up → verify → sign-in → protected endpoint → change password → sign-out, and the new
   password being the one that works afterwards.
2. an anonymous request never reaching the application's own handlers.
3. a password reset revoking every session, being single-use, and saying nothing about an unknown
   address.
4. the deployment's own `plan` field: stated at sign-up, read off `CurrentUser` by the application's
   own handler (a free account is capped at three todos), then changed with
   `POST /auth/update-user`.
5. `POST /auth/set-password` giving a first password to an account that has none — the shape an
   OAuth-provisioned account is in, simulated here by dropping the credential row through the store,
   since the example configures no provider. Asking twice is `PasswordAlreadySet`.
6. a magic link signing a stranger in: the plugin's endpoint on the application's own API, the
   message that goes out with no user behind the address, the single-use exchange, and the account
   it provisions arriving with `plan` defaulted.

The test substitutes `AuthTest.layerHttpApi` for the example's database and its two console mailers,
because reading the token out of the message is the only way to follow a link — the raw token exists
exactly once, in the mail that carries it. Everything else is the example's own code, including
`Todos.layer` and the API it is built against.
