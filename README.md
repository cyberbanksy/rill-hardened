<p align="center">
  <img src="docs/brand/rill-dark.svg#gh-dark-mode-only" alt="Rill" width="280">
  <img src="docs/brand/rill.svg#gh-light-mode-only" alt="Rill" width="280">
</p>

<p align="center">
  <strong>Your Stremio add-ons as a private Jellyfin server, on your own free Cloudflare account.</strong><br>
  A security-hardened fork of <a href="https://github.com/mrtxiv/Rill">mrtxiv/Rill</a>.
</p>

<p align="center">
  <a href="https://github.com/cyberbanksy/rill-hardened/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cyberbanksy/rill-hardened/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="HARDENING.md"><img alt="Hardening notes" src="https://img.shields.io/badge/security-hardened-2ea44f.svg"></a>
  <img alt="Runs on Cloudflare Workers" src="https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-f38020.svg">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-the-hardening-changes">What's hardened</a> ·
  <a href="#updating">Updating</a> ·
  <a href="HARDENING.md">Full security notes</a> ·
  <a href="SECURITY.md">Report a vulnerability</a>
</p>

---

Rill turns the Stremio add-ons you choose into a Jellyfin server, so any Jellyfin app (Infuse, Swiftfin, Jellyfin and others) can sign in to it. It runs as a single Cloudflare Worker with a D1 database. There's no server to maintain, and the free plans are enough.

This copy is Rill at upstream commit `5b9dd54` plus the security changes in [HARDENING.md](HARDENING.md). Rill ships with no add-ons or content. You add the ones you're allowed to use.

## What the hardening changes

| Area | Upstream Rill | This fork |
| --- | --- | --- |
| Settings and helper routes | Several helpers callable without signing in | Every `/api/*` helper needs the owner session, an exact same-origin request and JSON |
| First sign-in | Whoever reaches a new install first claims it | Needs a one-time `RILL_SETUP_TOKEN`; the claim is atomic |
| Saved add-on and provider keys | Stored and returned in readable form | AES-GCM encrypted with `RILL_DATA_KEY`; settings never send them back to the browser |
| Login | Unlimited attempts | Progressive throttling, revocable sessions and tokens, current password needed to change sign-in |
| Without a login | Artwork resolved for any item ID, user list visible | Only server-issued, unguessable image tags; no user list |
| Artwork | Any content type, including SVG | PNG, JPEG, GIF or WebP checked by signature, served sandboxed |
| Outbound requests | Followed redirects, any address | HTTPS only, private addresses denied, redirects checked hop by hop, byte limits |
| Settings page | No browser protections | Hash-pinned Content-Security-Policy, no framing, `__Host-` cookies |
| Updates | Pulled and deployed upstream code automatically | Never updates itself; you review and merge changes |

One gap remains and is documented: Cloudflare Workers can't pin a checked DNS answer, so the outbound address checks don't fully close DNS rebinding. See [HARDENING.md](HARDENING.md#changes-in-requested-order).

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

## Updating

Your copy never updates itself. To take a newer version, review the change, merge it into your GitHub copy, and Cloudflare rebuilds and deploys it. Before merging anything from upstream, go through the checklist at the end of [HARDENING.md](HARDENING.md#every-upstream-merge-must-re-check).

## Development

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
npx wrangler secret put RILL_DATA_KEY
npx wrangler secret put RILL_SETUP_TOKEN
npm run deploy
```

Tests need Node 22.13 or newer. They run against in-memory SQLite and mocked HTTP; nothing touches the network. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please don't open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md) for how to report one privately.

## Credits and license

Rill is by [mrtxiv](https://github.com/mrtxiv/Rill). This fork adds the security changes only. MIT, as upstream; see [LICENSE](LICENSE).
