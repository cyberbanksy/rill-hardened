# Rill hardening

## Changes

1. **Build this fork.** `scripts/build.mjs` runs the local compiler and tests, then hashes source, migrations, scripts, tests, package files and Wrangler configuration. `deploy.mjs` deploys this working tree and refuses a stale/missing build receipt. Neither script clones or installs fetched code. The old npm typecheck lifecycle hook is removed. Update routes, Cloudflare monitor/deploy-hook code, the UI and cron call are removed; old hook/monitor credentials are removed during migration. Cron still performs owner tracking/metadata maintenance.
2. **Owner authorization and bounded work.** Every `/api/*` helper requires a current owner session, except the account endpoints that implement status/login/provisioning. Helpers merge write-only credential markers with server settings and force the installation scope from the owner row. D1 atomic quotas allow 60 helper requests/minute and two expensive recommendation/catalog-generation/MovieLens requests/hour. Quick Connect issuance is capped at ten/minute. First setup requires `RILL_SETUP_TOKEN` and an atomic singleton `INSERT OR IGNORE` before configuration writes; concurrent losers cannot overwrite the owner. Existing owners retain their installation scope, password hash and unchanged usernames. Orphan accounts/recommendation jobs formerly admitted by public helpers are removed.
3. **Media and byte limits.** Proxied artwork accepts PNG, JPEG, GIF and WebP only when MIME and signature agree; SVG and other media are rejected. Response bodies are read through limits before raster responses are cached. The image cache namespace changes to bypass legacy SVG entries. Media responses set `Content-Security-Policy: sandbox`, `X-Content-Type-Options: nosniff` and `Content-Disposition: inline`. Limits: encoded configs 64 KiB, decoded configs/settings requests 256 KiB, upstream JSON 4 MiB, images 8 MiB, subtitles 2 MiB. Streaming counters apply even without Content-Length or when it lies. Subtitle conversion also uses bounded reads. Artwork returned to Stremio uses opaque proxy URLs rather than provider-key URLs.
4. **Central outbound policy — partial.** All runtime HTTP callers use `security/outbound.ts`, apart from its fixed HTTPS DNS resolver bootstrap. HTTPS is mandatory; `ALLOW_HTTP_ADDONS=true` permits HTTP only on Stremio add-on calls, including background jobs. Private/reserved IPv4/IPv6, local hostnames, credentials in URL authorities and nonstandard ports are denied. Both A and AAAA answers are checked. Redirects are manual, capped at five hops, checked at every hop, and credential-bearing requests cannot redirect across origins. **Remaining gap:** Worker `fetch` independently resolves the original hostname after the DoH check. This code cannot bind its connection to the checked IP, so DNS rebinding is not conclusively closed. Fully closing this needs a vetted outbound gateway that pins validated addresses or a verified platform guarantee; These checks are not complete SSRF protection.
5. **CSRF and CORS.** Settings/account requests require an exact Origin matching the request URL and JSON content type. Missing, null and sibling Origins are rejected before processing. Arbitrary Origin reflection and credentialed CORS are removed. Jellyfin and capability-authenticated Stremio endpoints use wildcard CORS without credentials for native/browser bearer-token clients. Native Jellyfin requests need no browser Origin.
6. **Login throttling and revocation.** D1 counters share a single owner account bucket across owner/profile/Jellyfin logins plus a trusted `CF-Connecting-IP` bucket. Atomic admission reserves attempts before hashing, with progressive 1–256 second delays after the first five attempts (15 minute window); retries are admitted after their deadline. Expired limiter rows are cleaned by maintenance. Owner cookies have durable nonce records; logout removes that record. Both token families include `auth_generation`; password/username changes and `/api/account/logout-all` bump it. Pending Quick Connect records from an older generation cannot mint fresh tokens. The UI delivery status/retry flow uses the owner cookie, not a recovered password.
7. **Secret storage and responses.** Owner passwords are verified with the existing salted PBKDF2-SHA256 hash and removed from both encoded and decoded configs. Jellyfin checks that owner hash, preserving profile login names. `RILL_DATA_KEY` is a separate 32-byte base64 Worker secret used for AES-GCM with fresh 96-bit nonces and purpose/scope authenticated data. Account and recommendation-job configs, tracker refresh credentials, MovieLens session cookies, generated signing keys, image-tag URL mappings, presentation data and durable/edge metadata caches are encrypted. First-run migration encrypts existing authoritative rows with compare-and-swap writes; disposable legacy caches/image/presentation mappings are purged. A durable completion marker makes migration idempotent across cold starts. Settings return nonsecret saved markers and opaque add-on references; blank/marked secret inputs preserve existing values. OAuth tokens are stored server-side and returned only as saved markers. Public config-bearing legacy URLs/imports are rejected; replacement Stremio install URLs are random, generation-bound, 30-day capabilities. Nameless manifests use “Add-on”. HTTP errors/logs omit raw exceptions/URLs; Worker observability is disabled to avoid request-path/query token capture.
8. **Third-party opt-in.** AI generation/search requires explicit recommendation enablement, not merely a saved key/model. Letterboxd→StremThru requires the new `thirdParty.letterboxd` checkbox and defaults off, including legacy configurations without that toggle. Existing explicitly enabled recommendations remain enabled.

9. **Artwork, re-authentication and lockout.**
   - Anonymous image requests (items and profile avatars) resolve only by `tag`. Tags are HMAC-SHA256, keyed from `RILL_DATA_KEY`, and only issued in signed-in responses. Item IDs are forgeable, so resolving them anonymously would spend the owner's add-on, TMDB and D1 quota. Old unkeyed tags are purged once (`hardening:image-tags-v2`).
   - `/Users/Public` returns `[]`.
   - Changing the username or password, and `/api/account/logout-all`, need `currentPassword`. Failures count against the login throttle.
   - New passwords need 12+ characters; existing shorter ones keep working.
   - A browser sign-in sets a `__Host-rill_device` [device cookie](https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies) (180 days, bound to `auth_generation`). Logins with a valid one are throttled per device; others share the per-IP and account buckets. Jellyfin apps don't send cookies, so a new app sign-in can be delayed during a guessing attack.
   - Known limitation: a stolen session without a device cookie can keep the account bucket throttled through failed `currentPassword` checks. Changing the password from a browser that has a device cookie ends that session.
   - The owner cookie is `__Host-rill_owner` on HTTPS; sign in again once after upgrading.
   - Settings page: CSP (`default-src 'none'`, its one inline script allowed by hash, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`. All responses: `nosniff`, `Referrer-Policy: no-referrer`, HSTS on HTTPS.
   - Artwork URLs in settings and Trakt/Simkl verification links must be `https:`.
   - Public without login, because Jellyfin apps need them before sign-in: `/System/Info/Public`, `/System/Ping`, Quick Connect, the login endpoints, `/Branding/*`, the settings page and logo, `/api/account/status`.
   - hono 4.13.13 (GHSA-5r4p-p66f-jhc7; affects `serveStatic`, unused here).
   - PBKDF2 stays at 100,000 iterations. Raising it needs a versioned hash format.

## Upgrade and compatibility

- Existing D1 owners do not need `RILL_SETUP_TOKEN`; that secret is only for an unclaimed instance. Empty password fields retain the current hash. Existing sessions lack a generation and will require sign-in after this upgrade. Password changes/log-out-all also revoke Stremio capabilities; re-create the install URL as needed.
- Existing reversible config/install tokens may already have disclosed credentials offline. Rejecting them now cannot retract that disclosure. Rotate the owner password and affected provider/tracker keys that were shared. Old backups/exported tokens remain sensitive and are not erased by this migration.
- Blank/saved secret fields retain credentials; replace them to rotate. Disconnecting a tracker removes its config entry. Provider credentials are never recovered to the settings browser. Media playback URLs issued by an add-on remain necessary downstream playback capabilities; Rill still redirects video playback rather than operating a video relay.
- Provider HTTP endpoints, unusual ports and unsupported image encodings now fail closed. JSON over 4 MiB and large CSV uploads require smaller imports. HTTP compatibility is limited to add-on APIs, not artwork/subtitle/collection URLs.
- Preserve `RILL_DATA_KEY` in your secret manager. Changing/removing it without decrypting and re-encrypting rows with the old key will make stored credentials unreadable. This patch does not implement online data-key rotation. Legacy database backups are still plaintext.
- Encryption/SQLite route tests are local substitutes for D1; they do not establish deployed Worker DNS behavior, cache performance or real provider compatibility. DNS checks add subrequests, and background metadata caches without a request context stay in memory rather than persisting unencrypted payloads.

## Upstream merge checklist

- No clone/download/lifecycle execution or unreviewed auto-update/deploy-hook/Cloudflare monitor path is restored.
- New UI/helper/durable-work endpoints inherit owner auth, origin/content-type guards, server scope and quotas; no caller-chosen account gets registered.
- New auth/Quick Connect/token families include durable revocation and generation checks. Password hashing/cookie flags, trusted-IP admission and first-owner singleton semantics remain intact.
- Every outbound fetch enters the central policy; no automatic redirect, HTTP exception outside add-ons, URL credential authority or unchecked DNS answer is introduced. Re-evaluate the documented DNS pinning gap on the target runtime.
- Every read/buffer/decompress path retains byte bounds; raster MIME/signature validation and security headers precede caching. Legacy cache namespaces must remain retired.
- New provider fields and credential copies (including derived image URLs, jobs, caches and OAuth responses) are encrypted or purged and stay write-only. Re-check marker round trips, profile names and existing-owner migration with tests.
- Logging, telemetry/observability, CORS reflection, raw provider errors and implicit AI/Letterboxd activation do not return. Review lockfile/dependency changes and run the checks below.

## Deploying

Back up your D1 database before upgrading.

```sh
npm ci --ignore-scripts

# openssl rand -base64 32
./node_modules/.bin/wrangler secret put RILL_DATA_KEY

# New installs only
./node_modules/.bin/wrangler secret put RILL_SETUP_TOKEN

npm run typecheck
npm test
npm audit --omit=dev
npm run build
npm run deploy
```

`npm run build` runs the type check and tests and records a source hash; `npm run deploy` refuses to deploy a tree that changed since. Migrations run on the first request after deploy. Sign in and check settings, a Jellyfin login, artwork and tracking. Re-enable Letterboxd if you used it.
