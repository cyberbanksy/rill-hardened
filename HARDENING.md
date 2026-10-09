# Rill hardening

The production dependency audit reports zero known vulnerabilities. Local verification uses Node's test runner, the installed TypeScript compiler, and in-memory SQLite implementing the D1 statement/batch contract; it does not exercise the deployed Worker or live D1. Tests require Node 22.13 or newer (verified with the existing Node 26 installation); no test dependencies were installed.

## Changes, in requested order

1. **Build this fork.** `scripts/build.mjs` runs the local compiler and tests, then hashes source, migrations, scripts, tests, package files and Wrangler configuration. `deploy.mjs` deploys this working tree and refuses a stale/missing build receipt. Neither script clones or installs fetched code. The old npm typecheck lifecycle hook is removed. Update routes, Cloudflare monitor/deploy-hook code, the UI and cron call are removed; old hook/monitor credentials are removed during migration. Cron still performs owner tracking/metadata maintenance.
2. **Owner authorization and bounded work.** Every `/api/*` helper requires a current owner session, except the account endpoints that implement status/login/provisioning. Helpers merge write-only credential markers with server settings and force the installation scope from the owner row. D1 atomic quotas allow 60 helper requests/minute and two expensive recommendation/catalog-generation/MovieLens requests/hour. Quick Connect issuance is capped at ten/minute. First setup requires `RILL_SETUP_TOKEN` and an atomic singleton `INSERT OR IGNORE` before configuration writes; concurrent losers cannot overwrite the owner. Existing owners retain their installation scope, password hash and unchanged usernames. Orphan accounts/recommendation jobs formerly admitted by public helpers are removed.
3. **Media and byte limits.** Proxied artwork accepts PNG, JPEG, GIF and WebP only when MIME and signature agree; SVG and other media are rejected. Response bodies are read through limits before raster responses are cached. The image cache namespace changes to bypass legacy SVG entries. Media responses set `Content-Security-Policy: sandbox`, `X-Content-Type-Options: nosniff` and `Content-Disposition: inline`. Limits: encoded configs 64 KiB, decoded configs/settings requests 256 KiB, upstream JSON 4 MiB, images 8 MiB, subtitles 2 MiB. Streaming counters apply even without Content-Length or when it lies. Subtitle conversion also uses bounded reads. Artwork returned to Stremio uses opaque proxy URLs rather than provider-key URLs.
4. **Central outbound policy — partial.** All runtime HTTP callers use `security/outbound.ts`, apart from its fixed HTTPS DNS resolver bootstrap. HTTPS is mandatory; `ALLOW_HTTP_ADDONS=true` permits HTTP only on Stremio add-on calls, including background jobs. Private/reserved IPv4/IPv6, local hostnames, credentials in URL authorities and nonstandard ports are denied. Both A and AAAA answers are checked. Redirects are manual, capped at five hops, checked at every hop, and credential-bearing requests cannot redirect across origins. **Remaining gap:** Worker `fetch` independently resolves the original hostname after the DoH check. This code cannot bind its connection to the checked IP, so DNS rebinding is not conclusively closed. No live runtime test was authorized/performed. Fully closing this needs a vetted outbound gateway that pins validated addresses or a verified platform guarantee; do not describe these checks as complete SSRF protection.
5. **CSRF and CORS.** Settings/account requests require an exact Origin matching the request URL and JSON content type. Missing, null and sibling Origins are rejected before processing. Arbitrary Origin reflection and credentialed CORS are removed. Jellyfin and capability-authenticated Stremio endpoints use wildcard CORS without credentials for native/browser bearer-token clients. Native Jellyfin requests need no browser Origin.
6. **Login throttling and revocation.** D1 counters share a single owner account bucket across owner/profile/Jellyfin logins plus a trusted `CF-Connecting-IP` bucket. Atomic admission reserves attempts before hashing, with progressive 1–256 second delays after the first five attempts (15 minute window); retries are admitted after their deadline. Expired limiter rows are cleaned by maintenance. Owner cookies have durable nonce records; logout removes that record. Both token families include `auth_generation`; password/username changes and `/api/account/logout-all` bump it. Pending Quick Connect records from an older generation cannot mint fresh tokens. The UI delivery status/retry flow uses the owner cookie, not a recovered password.
7. **Secret storage and responses.** Owner passwords are verified with the existing salted PBKDF2-SHA256 hash and removed from both encoded and decoded configs. Jellyfin checks that owner hash, preserving profile login names. `RILL_DATA_KEY` is a separate 32-byte base64 Worker secret used for AES-GCM with fresh 96-bit nonces and purpose/scope authenticated data. Account and recommendation-job configs, tracker refresh credentials, MovieLens session cookies, generated signing keys, image-tag URL mappings, presentation data and durable/edge metadata caches are encrypted. First-run migration encrypts existing authoritative rows with compare-and-swap writes; disposable legacy caches/image/presentation mappings are purged. A durable completion marker makes migration idempotent across cold starts. Settings return nonsecret saved markers and opaque add-on references; blank/marked secret inputs preserve existing values. OAuth tokens are stored server-side and returned only as saved markers. Public config-bearing legacy URLs/imports are rejected; replacement Stremio install URLs are random, generation-bound, 30-day capabilities. Nameless manifests use “Add-on”. HTTP errors/logs omit raw exceptions/URLs; Worker observability is disabled to avoid request-path/query token capture.
8. **Third-party opt-in.** AI generation/search requires explicit recommendation enablement, not merely a saved key/model. Letterboxd→StremThru requires the new `thirdParty.letterboxd` checkbox and defaults off, including legacy configurations without that toggle. Existing explicitly enabled recommendations remain enabled.

## Upgrade and compatibility

- Existing D1 owners do not need `RILL_SETUP_TOKEN`; that secret is only for an unclaimed instance. Empty password fields retain the current hash. Existing sessions lack a generation and will require sign-in after this upgrade. Password changes/log-out-all also revoke Stremio capabilities; re-create the install URL as needed.
- Existing reversible config/install tokens may already have disclosed credentials offline. Rejecting them now cannot retract that disclosure. Rotate the owner password and affected provider/tracker keys that were shared. Old backups/exported tokens remain sensitive and are not erased by this migration.
- Blank/saved secret fields retain credentials; replace them to rotate. Disconnecting a tracker removes its config entry. Provider credentials are never recovered to the settings browser. Media playback URLs issued by an add-on remain necessary downstream playback capabilities; Rill still redirects video playback rather than operating a video relay.
- Provider HTTP endpoints, unusual ports and unsupported image encodings now fail closed. JSON over 4 MiB and large CSV uploads require smaller imports. HTTP compatibility is limited to add-on APIs, not artwork/subtitle/collection URLs.
- Preserve `RILL_DATA_KEY` in your secret manager. Changing/removing it without decrypting and re-encrypting rows with the old key will make stored credentials unreadable. This patch does not implement online data-key rotation. Legacy database backups are still plaintext.
- Encryption/SQLite route tests are local substitutes for D1; they do not establish deployed Worker DNS behavior, cache performance or real provider compatibility. DNS checks add subrequests, and background metadata caches without a request context stay in memory rather than persisting unencrypted payloads.

## Every upstream merge must re-check

- No clone/download/lifecycle execution or unreviewed auto-update/deploy-hook/Cloudflare monitor path is restored.
- New UI/helper/durable-work endpoints inherit owner auth, origin/content-type guards, server scope and quotas; no caller-chosen account gets registered.
- New auth/Quick Connect/token families include durable revocation and generation checks. Password hashing/cookie flags, trusted-IP admission and first-owner singleton semantics remain intact.
- Every outbound fetch enters the central policy; no automatic redirect, HTTP exception outside add-ons, URL credential authority or unchecked DNS answer is introduced. Re-evaluate the documented DNS pinning gap on the target runtime.
- Every read/buffer/decompress path retains byte bounds; raster MIME/signature validation and security headers precede caching. Legacy cache namespaces must remain retired.
- New provider fields and credential copies (including derived image URLs, jobs, caches and OAuth responses) are encrypted or purged and stay write-only. Re-check marker round trips, profile names and existing-owner migration with tests.
- Logging, telemetry/observability, CORS reflection, raw provider errors and implicit AI/Letterboxd activation do not return. Review lockfile/dependency changes and run the checks below.

## Deployment steps for the owner (not executed here)

Use the existing fork and Cloudflare deployment identity with only the Rill resources it needs. Review and back up the owning D1 database through your existing operational process before deploying; keep that backup private. Do not reuse an upstream clone/build hook.

```sh
# If dependencies are missing: install only the reviewed lockfile, without lifecycle scripts.
npm ci --ignore-scripts

# Enter a securely generated base64 encoding of 32 random bytes; do not log/share it.
./node_modules/.bin/wrangler secret put RILL_DATA_KEY

# Only for a NEW, unclaimed instance: set a random provisioning token,
# then enter it into the first-run UI. Existing D1 owners skip this.
./node_modules/.bin/wrangler secret put RILL_SETUP_TOKEN

npm run typecheck
npm test
npm audit --omit=dev
npm run build
npm run deploy
```

`npm run build` is local validation plus a source receipt. Wrangler bundles the same reviewed local source during `npm run deploy`. Any source/config/test change after building invalidates the receipt. Migration `0016_hardening.sql` and encryption conversion execute on the first request/maintenance/queue event with the data secret present. Sign in with the existing owner password; verify settings, Jellyfin login, artwork and tracking on the upgraded instance. Re-enable Letterboxd only if desired. Do not enable external build hooks to automate upstream updates.

## Verification recorded for this patch

- `npm run typecheck`: pass.
- `npm test`: 24 passing tests; all HTTP/DNS/provider fixtures mocked, all D1 tests use in-memory SQLite.
- `npm audit --omit=dev`: zero known vulnerabilities.
- `npm run build`: pass; verifies local compiler/tests and writes a source receipt.
- Local esbuild Worker bundle with SQL/binary loaders: pass (`output/hardening/worker.mjs`, ignored generated output).
- `git diff --check`: pass. No deployment, remote D1 migration, Cloudflare secret write, push, or live bridge test was run.
