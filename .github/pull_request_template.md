## What changed

## Why

## Security checklist

- [ ] New routes need the owner session (or the reason they don't is in HARDENING.md)
- [ ] Outbound requests go through `security/outbound.ts`
- [ ] Secrets stay encrypted and write-only
- [ ] A test fails without this change
- [ ] `npm run typecheck`, `npm test` and `npm audit --omit=dev` pass
