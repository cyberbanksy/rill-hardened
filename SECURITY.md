# Security policy

## Reporting a vulnerability

Please don't open a public issue. Report privately through GitHub instead: open the **Security** tab of this repository and select **Report a vulnerability**. If that button isn't there, open an issue that asks for a private contact and leaves out the details.

Include:

- the affected route, file or setting,
- steps to reproduce, ideally against your own deployment or the local test setup,
- what an attacker gains.

You should get a reply within a week. Fixes land on `main` with a note in [HARDENING.md](HARDENING.md). Your copy never updates itself, so watch this repository's releases or security advisories and merge fixes yourself.

## Scope

In scope: this repository's Worker code, the settings page, the build and deploy scripts, and the defaults they ship with.

Out of scope:

- third-party add-ons and providers, and the playback URLs they return,
- Cloudflare platform behaviour, including the documented DNS-pinning gap in [HARDENING.md](HARDENING.md),
- denial of service that only uses up your own free-plan quotas through ordinary traffic volume.

Upstream Rill issues that also affect upstream belong with [mrtxiv/Rill](https://github.com/mrtxiv/Rill) too.

## Testing your own deployment

You may test a deployment you own. Don't test other people's installs. Load tests count against your own Cloudflare quotas.
