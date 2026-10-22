<p align="center">
  <img src="docs/brand/rill-dark.svg#gh-dark-mode-only" alt="Rill" width="280">
  <img src="docs/brand/rill.svg#gh-light-mode-only" alt="Rill" width="280">
</p>

A hardened copy of [Rill](https://github.com/mrtxiv/Rill) by mrtxiv (MIT). Rill runs on your own free Cloudflare account and turns the Stremio add-ons you choose into a Jellyfin server, so any Jellyfin app (Infuse, Swiftfin, Jellyfin, and others) can sign in to it.

This copy is Rill at upstream commit `5b9dd54` plus the security changes listed in [HARDENING.md](HARDENING.md). The main ones:

- Add-on artwork must be a real PNG, JPEG, GIF or WebP, so a malicious SVG can't take over the settings page.
- Saved add-on keys are encrypted with a key only your Worker has, and settings never send them back to the browser.
- Logins are throttled, sessions can be revoked, and every helper route needs you signed in.
- Builds use only the code in your copy. Nothing pulls new code from upstream during a deploy, and the auto-update path is gone.

One gap remains and is documented: Cloudflare Workers can't pin a checked DNS answer, so the outbound address checks don't fully close DNS rebinding.

Rill doesn't come with any add-ons or content. You add the ones you're allowed to use.

## Set it up

You need a [GitHub account](https://github.com/signup) and a [Cloudflare account](https://dash.cloudflare.com/sign-up). Both free plans are enough.

### 1. Make two secrets

Open Terminal (Mac or Linux) and run these two lines. Keep both results in your password manager.

```sh
openssl rand -base64 32   # RILL_DATA_KEY
openssl rand -hex 16      # RILL_SETUP_TOKEN
```

`RILL_DATA_KEY` encrypts your saved add-on keys. If you lose it, you re-enter them. `RILL_SETUP_TOKEN` is a one-time code you type on the first sign-in, so nobody else can claim your install before you do.

### 2. Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cyberbanksy/rill-hardened)

- Choose your Cloudflare account and connect GitHub when asked. Cloudflare makes a copy of this repository in your GitHub account.
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
- Enter your setup token, then make a username and a password of at least 12 characters. This account is separate from GitHub and Cloudflare.
- Add your add-ons on the settings page.

### 4. Sign in from a Jellyfin app

In your Jellyfin app, add a server with your `workers.dev` address and the username and password from step 3.

## Updating

Your copy never updates itself. To take a newer version, review the change, merge it into your GitHub copy, and Cloudflare rebuilds and deploys it. Read the checklist at the end of [HARDENING.md](HARDENING.md) before merging anything from upstream.

## Running it yourself

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
npx wrangler secret put RILL_DATA_KEY
npx wrangler secret put RILL_SETUP_TOKEN
npm run deploy
```

Tests need Node 22.13 or newer.

## License

MIT, as upstream. See [LICENSE](LICENSE).
