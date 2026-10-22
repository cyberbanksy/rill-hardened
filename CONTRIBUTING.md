# Contributing

Thanks for helping. This fork's purpose is security, so changes are held to the checklist in [HARDENING.md](HARDENING.md#every-upstream-merge-must-re-check).

## Set up

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
```

Node 22.13 or newer. Tests use in-memory SQLite and mocked HTTP; they never touch the network.

## Before you open a pull request

- Every new `/api/*` route needs the owner session, the same-origin and JSON checks, and a quota.
- Every outbound request goes through `src/security/outbound.ts`.
- New secrets are encrypted at rest and never sent back to the browser.
- Anything reachable without a login needs a reason, written down in [HARDENING.md](HARDENING.md).
- Add a test that fails without your change.
- Don't add dependencies, lifecycle scripts, telemetry or auto-update paths without discussing them first.

Security problems go through [SECURITY.md](SECURITY.md), not pull requests or issues.
