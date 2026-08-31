# Loop Contract - EFC Proxy

Safety guardrails for reverse proxy (C++) automation loops.

## Stop Conditions (Non-Negotiable)

- **Never deploy without explicit user approval** — ask first, wait for "yes"
- **Stop on compilation errors** — don't ignore C++23 build failures
- **Stop on permission denial** — never retry or work around
- **Stop on network errors** — verify connectivity before proceeding
- **Stop on config syntax errors** — validate before reloading
- **Max 5 retries per task** — no infinite loops

## Tone & Scope

- **Terse output** — no trailing summaries
- **Commit-first** — no uncommitted work
- **Test locally first** — run on localhost before deploying
- **Verify upstream routes** — don't assume docapi/cproxy connectivity
- **No force-push** — clean merge only

## Secrets & Safety

- **Never commit credentials** — use `.env.local` or `/secret/` (gitignored)
- **No automated prod deploys** — user approval required for every deploy
- **No direct prod config changes** — stage and test locally first
- **Logs: no credential leaks** — sanitize before viewing

## Scope for This Project

- **C++23 code** — proxy logic, request handling, routing
- **Config files** — YAML/TOML for upstream routes, timeouts, etc.
- **Build (CMake)** — local compilation only
- **Network/DNS** — verify upstreams reachable (reads only)

## Deployment

- **Current topology:** Droplet 159.89.113.225:80 front > docapi via DO VPC (10.118.0.3:8080)
- **Logs location:** /mnt/volume_cnode/cproxy/logs (volumes, never mkfs)
- **Config validation:** must pass `--check` before reload
- **Zero-downtime reload:** use systemd or container restart

## When to Loop

**Loop for:** iterating route changes, testing upstream failover, log analysis
**Single-shot for:** major rewrites, feature additions
