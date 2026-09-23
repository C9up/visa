# @c9up/visa

An OAuth 2.1 authorization server for the Ream ecosystem. It issues tokens to
**other** applications on a user's behalf.

It does not authenticate anyone — that stays warden's job. Visa asks your
application who is signed in, and everything else is its business.

No dependencies: `node:crypto` only. A package in the path that mints and
compares credentials is a package that can replace them.

```bash
ream configure @c9up/visa
```

## What it implements

| | |
|---|---|
| Grants | `authorization_code` (PKCE required), `refresh_token`, `client_credentials` |
| Endpoints | `/oauth/token`, `/oauth/revoke`, `/oauth/introspect`, `/.well-known/oauth-authorization-server` |
| Removed | `implicit` and `password` — gone from OAuth 2.1, and not available under any option |

`/authorize` is **not** mounted, deliberately: it needs a signed-in user and a
consent screen, and both belong to your application. See below.

## Security decisions, and why

- **PKCE on every client**, confidential ones included — a code on the front
  channel is interceptable whoever asked for it.
- **`S256` only.** `plain` puts the verifier in the authorization request, so
  anything that can read that request can complete the exchange, which is what
  PKCE exists to stop. `allowPlainChallenge: true` brings it back; don't.
- **Exact redirect URI matching**, with the one exception the spec names (a
  loopback port). A prefix match is how an open redirect on the client's own
  domain becomes a stolen code.
- **An error is never redirected to an unverified URI.** A bad `redirect_uri`
  is shown to the user, not bounced.
- **Everything is hashed at rest** — codes, access tokens, refresh tokens,
  client secrets. A database dump is not a set of working credentials.
- **Refresh rotation with replay detection.** Every use mints a new token; a
  spent one coming back proves a leak, and since there is no telling the thief
  from the victim, the whole family goes.
- **One sentence per failure.** "No such code", "expired", "already used" and
  "wrong client" are `invalid_grant: The code is not valid.` — telling them
  apart is how a code space gets probed.

## Wiring `/authorize`

The decision is visa's; the page is yours.

```ts
// start/routes.ts
import visa from '@c9up/visa/services/main'

router.get('/oauth/authorize', async (ctx) => {
  const outcome = await visa.authorize(ctx.request.qs(), ctx.auth.user?.id)

  if (outcome.type === 'redirect') return ctx.response.redirect(outcome.url)
  if (outcome.type === 'error') {
    // NOT a redirect: the redirect URI is what failed validation.
    return ctx.view.render('oauth/error', { error: outcome.error.toResponse() })
  }
  if (!ctx.auth.user) return ctx.response.redirect('/login?next=' + encodeURIComponent(ctx.request.url(true)))

  return ctx.view.render('oauth/consent', {
    client: outcome.request.client,
    scopes: outcome.request.scopes,
  })
})

router.post('/oauth/consent', async (ctx) => {
  const outcome = await visa.authorize(ctx.request.all(), ctx.auth.user.id)
  if (outcome.type !== 'consent') return ctx.response.redirect('/')
  const url = ctx.request.input('approve')
    ? await visa.grant(outcome.request, ctx.auth.user.id)
    : visa.deny(outcome.request)
  return ctx.response.redirect(url)
})
```

## Registering a client

```ts
const { client, secret } = await visa.registerClient({
  id: 'invoices',
  name: 'Invoices',
  redirectUris: ['https://invoices.example.com/callback'],
  scopes: ['profile', 'invoices:read'],
})
// `secret` is shown once and never stored in plaintext. A client that loses
// it gets a new one.
```

A public client — a SPA, a native app — registers with
`tokenEndpointAuthMethod: 'none'` and gets no secret. It may not use
`client_credentials`: "the client itself" means nothing when anyone can read
its id out of a browser.

## Protecting a resource

```ts
const grant = await visa.verify(bearerToken)
if (!grant) return ctx.response.unauthorized({ error: 'invalid_token' })
if (!grant.scopes.includes('invoices:read')) {
  return ctx.response.forbidden({ error: 'insufficient_scope' })
}
```

## The store

`MemoryStore` is for tests and a single development process. Everything else
implements `VisaStore` — twelve methods. Two of them, `consumeAuthorizationCode`
and `consumeRefreshToken`, **must be atomic**: two requests racing with the same
code must not both succeed, and that single-use guarantee is what replay
detection is built on.

## What is not here yet

OpenID Connect — `id_token`, discovery, JWKS, `/userinfo`. The `nonce` is
already carried through the authorization code for it.

## License

MIT
