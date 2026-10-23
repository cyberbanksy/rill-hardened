# Contributing

Changes must keep the guarantees listed in [HARDENING.md](HARDENING.md#upstream-merge-checklist).

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
```

Requires Node 22.13+.

- New `/api/*` routes go through the owner-session, origin and quota checks.
- Outbound requests go through `src/security/outbound.ts`.
- Add a test that fails without your change.

Discuss new dependencies first. Security problems go through [SECURITY.md](SECURITY.md).
