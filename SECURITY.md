# Security policy

## Reporting a vulnerability

Please don't open a public issue. Use **Report a vulnerability** on this repository's Security tab. If that button isn't there, open an issue asking for a private contact, without details.

Include the affected route or file, steps to reproduce, and impact. Expect a reply within a week. Deployments don't update themselves; watch this repository (Custom → Security alerts) to hear about fixes.

## Scope

In scope: this repository's Worker code, the settings page, the build and deploy scripts, and their defaults.

Out of scope: third-party add-ons and providers and the playback URLs they return, Cloudflare platform behaviour (including the DNS-pinning gap in [HARDENING.md](HARDENING.md)), and denial of service by ordinary traffic volume.

If the issue also affects upstream, please tell [mrtxiv/Rill](https://github.com/mrtxiv/Rill) as well.
