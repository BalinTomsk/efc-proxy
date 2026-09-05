# Agent Rules

## Git Safety

- DO NOT COMMIT without explicit user permission.
- DO NOT PUSH without explicit user permission.
- DO NOT CREATE, MERGE, OR CLOSE PULL REQUESTS without explicit user permission.
- When code changes are requested, make the file edits and stop with a status summary unless the user explicitly asks for Git actions.
- DO NOT USE real ip4/ip6/fqdn in code or in tests or any document going to git

## Documentation

- **README files must NEVER contain external (public) real IP addresses.** Redact any to a placeholder (a documentation IP or a `<host>` token) and remove any that already exist. Real deploy addresses belong in the gitignored operational docs (`CLAUDE.md`, `docs/do-update.md`), not in a tracked README.
