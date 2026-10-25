<p align="center">
  <img src="docs/brand/rill-dark.svg#gh-dark-mode-only" alt="Rill" width="280">
  <img src="docs/brand/rill.svg#gh-light-mode-only" alt="Rill" width="280">
</p>

<p align="center">
  <strong>Your Stremio add-ons as a private Jellyfin server, on your own free Cloudflare account.</strong><br>
  A fork of <a href="https://github.com/mrtxiv/Rill">mrtxiv/Rill</a> with stricter defaults.
</p>

<p align="center">
  <a href="https://github.com/cyberbanksy/rill-hardened/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cyberbanksy/rill-hardened/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

---

Rill turns the Stremio add-ons you choose into a Jellyfin server, so any Jellyfin app (Infuse, Swiftfin, Jellyfin and others) can sign in to it. It runs as a single Cloudflare Worker with a D1 database. There's no server to maintain, and the free plans are enough.

Based on upstream `5b9dd54`. Rill ships with no add-ons or content.

## Differences from upstream

- Settings and `/api/*` routes require the owner's session.
- First sign-in needs `RILL_SETUP_TOKEN`.
- Saved add-on and provider keys are encrypted with `RILL_DATA_KEY` and never sent back to the browser.
- Logins are throttled; artwork must be PNG, JPEG, GIF or WebP; outbound requests are HTTPS-only and can't reach private addresses.
- No auto-update. You merge upstream changes yourself.

Details and known gaps are in [HARDENING.md](HARDENING.md).

## Quick start

You need a [GitHub account](https://github.com/signup) and a [Cloudflare account](https://dash.cloudflare.com/sign-up).

### 1. Make two secrets

Run these in a terminal and keep both results in your password manager.

```sh
openssl rand -base64 32   # RILL_DATA_KEY
openssl rand -hex 16      # RILL_SETUP_TOKEN
```

- `RILL_DATA_KEY` encrypts your saved add-on keys. If you lose it, you have to enter them again.
- `RILL_SETUP_TOKEN` is a one-time code for the first sign-in, so nobody else can claim your install before you do.

### 2. Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cyberbanksy/rill-hardened)

- Choose your Cloudflare account and connect GitHub when asked. Cloudflare copies this repository into your GitHub account.
- Keep the suggested Worker, database and queue names, or pick unused ones. The database binding must stay `DB`.
- Paste the two secrets from step 1 into `RILL_DATA_KEY` and `RILL_SETUP_TOKEN`, then select **Deploy**.

The build runs the type check and tests before it deploys. Tables are created on first use, so there's no SQL to import.

<details>
<summary>If you're asked for build settings</summary>

| Setting | Value |
| --- | --- |
| Root directory | `/` |
| Build command | `npm run build` |
| Deploy command | `npm run deploy` |
| D1 database binding | `DB` |
| Secrets | `RILL_DATA_KEY`, `RILL_SETUP_TOKEN` |

</details>

### 3. Claim it

- In the [Cloudflare dashboard](https://dash.cloudflare.com/), open **Workers & Pages**, select your Worker, and open its `workers.dev` address.
- Enter your setup token, then choose a username and a password of at least 12 characters. This account is separate from GitHub and Cloudflare.
- Add your add-ons on the settings page.

### 4. Sign in from a Jellyfin app

Add a server in your Jellyfin app with your `workers.dev` address, then sign in with the username and password from step 3.

<details>
<summary>Deploying with Wrangler instead</summary>

```sh
npm ci --ignore-scripts
npx wrangler secret put RILL_DATA_KEY
npx wrangler secret put RILL_SETUP_TOKEN
npm run build
npm run deploy
```

</details>

## Updating

Your copy never updates itself. To take a newer version, review the change, merge it into your GitHub copy, and Cloudflare rebuilds and deploys it. Before merging anything from upstream, go through the checklist at the end of [HARDENING.md](HARDENING.md#upstream-merge-checklist).


## Development

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
```

Requires Node 22.13+.

## Security

See [SECURITY.md](SECURITY.md).

## Credits and license

Rill is by [mrtxiv](https://github.com/mrtxiv/Rill). MIT, see [LICENSE](LICENSE).
