# cproxy Changelog

Split out of `CLAUDE.md` for readability. `CLAUDE.md` stays local-only (gitignored); this file is
tracked. Newest entries first.

> **Addresses here are placeholders.** This repo is public, so every real host is written as
> `<cproxy-droplet>`, `<docapi-droplet>`, `<second-droplet>`, `<docapi-vpc>`, `<vpc-cidr>`,
> `<admin-ip>` (`EXTERNAL_ADMIN`), `<frontend-ip>` / `<frontend-egress-ip>` (`EXTERNAL_FRONTEND`).
> The real values live in the gitignored `CLAUDE.md` → Deployment/Reachability and in `secret/`.
> Never paste a real address into this file. `127.0.0.1` and `0.0.0.0` are literal.

- 2026-09-03: **0.9.1 — `/news/featured` and `/news/more` join `/news/default` behind the day-key.
  BUILT AND TESTED, NOT DEPLOYED.** Closes an unauthenticated bypass that this stack opened itself.

  docapi 1.8.1 split `GET /api/v1/news/default` into `/news/featured` (the 2 lead articles, ~1.09 MB)
  and `/news/more` (the sidebar, ~1.6 KB), so a caller can take whichever half it renders. But
  `daykey_paths` still named only `/news/default`, and `/api/*` is forwarded wholesale — so the two
  new paths went live **completely open**. Confirmed against the deployed gateway with no
  `X-Day-Guid` header:

  ```
  /api/v1/news/default    500          62 bytes   (gated, as intended)
  /api/v1/news/featured   200   1,085,243 bytes   (the bypass)
  /api/v1/news/more       200       1,636 bytes   (the bypass)
  ```

  The whole point of gating `/news/default` is that assembling it is expensive and there is no reason
  to serve it to anonymous scrapers. `/news/featured` handed over the expensive half — the same
  content, larger per request — for free.

  - **Fix:** `Config::daykey_paths` now defaults to
    `{"/news/default", "/news/featured", "/news/more"}`. No routing change was needed; `/api/*` was
    already forwarded. The comment on the field now says in capitals that these three must be listed
    together and that a future split must add its paths in the same commit.
  - **Tests.** `daykey_paths_gate_reads_by_default` gains the two endpoints at the real route prefix,
    bare, with a trailing slash and in mixed case, plus near-miss negatives (`/news/moreish` and
    `/oldnews/more` must stay open). **Verified failing first**: reverting the default to
    `{"/news/default"}` — with the size assertions relaxed so only the gate itself could fail —
    produces `CHECK failed: c.daykey_required("GET", "/api/v1/news/featured")` at
    `config_test.cpp:177`. 6/6 test binaries pass on a `--no-cache` build with the fix.
  - **No env change needed at deploy:** production sets no `CPROXY_DAYKEY_PATHS`, so it runs on this
    default. That is also why the bypass existed — the gate list lives in the binary, and shipping a
    docapi change alone could not update it.

- 2026-09-02: **0.9.0 — the day-key store is keyed by DATE, not day-of-year. DEPLOYED.**
  The store held exactly 365 rows indexed `1..365` and reused them every year. The generated key set
  — `secret/daykeys.csv` and `secret/daykeys_mssql.sql` (`dbo.day_keys`) — is **date-keyed and spans
  ten years, 3,652 rows**, so a 365-row projection of it agreed for about twelve months and then
  drifted: cproxy and every other consumer would have disagreed from 2027-09-02. cproxy now holds
  the same record count as the CSV, and they agree by construction.
  - **How this surfaced.** A key that was valid in the date-keyed set was rejected by the gate. The
    deployed SQLite and the local `secret/daykeys.sqlite` were byte-identical (so "just re-upload the
    file" would have been a no-op), and the GUID was in `daykeys.csv` but in *none* of the 365 rows —
    two different generations of key material, only one of which cproxy could represent.
  - **The rewrite deleted logic rather than adding it.** `day_keys(stamp TEXT PRIMARY KEY, guid TEXT
    NOT NULL)`, an `unordered_map<date, guid>`, and yesterday/today/tomorrow by plain chrono
    arithmetic. Gone: the **year-boundary wrap** (365 → 1) and the **leap-day clamp**, under which
    day 366 reused day 365's key — 29 February and 31 December shared a credential. The live store
    now carries 3 genuine leap-day keys (2028/2032/2036). Side effect: `day_key_store_test` went from
    **16.6s to 0.63s** and `proxy_test` from 3.6s to 0.45s, because the fixtures no longer write 365
    rows per case.
  - **Startup now logs the covered range** (`days`, `from`, `to`). The store is finite; past the last
    date every gated request fails closed with the usual opaque 500 and nothing else says why, so
    that line is the only warning it is expiring.
  - **Fails loud on the old schema.** A 0.9.0 binary against a pre-0.9.0 database throws with an
    explicit "regenerate from secret/daykeys.csv" message instead of loading an empty store and
    silently 500ing everything. `legacy_day_of_year_schema_throws` pins it.
  - **Deploy is a coordinated two-part change** — 0.9.0 rejects the 365-row schema and 0.8.0 rejects
    a 3,652-row one, so either mismatch fails closed across the whole gated surface. Sequence used:
    push the image, upload the new SQLite next to the *running* container (which holds its keys in
    memory and is unaffected), then recreate once so binary and store land together.
  - **A near-miss worth remembering:** the first rebuild used `secret/daykeys_new.csv` because it
    already had a `day_of_year` column — but that file (16:16) is an **earlier, superseded
    generation** with different GUIDs; the authoritative set is `daykeys.csv` (16:25), matching
    `daykeys_mssql.sql` (16:26). Only an assertion against the known-good key caught it. A store
    built from the wrong file looks perfectly valid — right row count, no empties — and rejects every
    live key.
  - **Verified live:** `/health` → `0.9.0`; `day-key store loaded, days:3652, from:2026-09-02,
    to:2036-08-31`; the real key → `200` (1.06 MB); no key / wrong key → `500`; **tomorrow's** key →
    `200` (±1 day window) and a key **5 days out** → `500`; POST write gate still `500`;
    `fish/search` and the cloud-range store (3,758 ranges, GCP override intact) unaffected.
  - Also this session: `daykeys.sqlite` tightened to `0400` (was `0444`), matching `.env` /
    `master.key`. Verified by restarting rather than assuming — the store is read at startup, so a
    permission mistake would have sat latent until an unrelated deploy.

- 2026-09-02: **DEPLOYED 0.8.0 to prod** (digest `sha256:38a734f2…cc93`), which also carried the
  undeployed `0.7.0` day-key read gate. Verified live from an allowlisted machine: `/health` →
  `0.8.0`, breaker `closed`, traversal `400`, unknown route `404`, `POST` and `GET /news/default` →
  `500` (day-key), `news/list` not gated, `cloud-range store loaded … merged_ranges: 3914`, and all
  **12 feeds** refreshed in prod writing an 8.6 MB database to the volume.
  - **I caused a short outage during this deploy, and the cause is worth remembering.** The
    2026-09-02 redaction pass replaced the docapi VPC address in `deploy/compose.yml` with the
    literal `<docapi-vpc>` — but that file is `scp`'d to `/opt/cproxy/compose.yml` **verbatim**, so
    cproxy tried to resolve the placeholder and answered every `/api/*` with
    `502 Could not establish connection`. **A `<placeholder>` in a deployed file is an outage, not
    documentation.** It was hard to spot because `/health` is local-only and stayed `200`, and
    `/health/ready` only reports breaker state — only a real proxied call revealed it.
  - **Fixed properly, not just hot-patched:** `CPROXY_DOCAPI_UPSTREAM` is now **absent** from the
    tracked `compose.yml` and supplied by `/mnt/volume_cnode/cproxy/.env` next to
    `EXTERNAL_ADMIN`/`EXTERNAL_FRONTEND`. A real process env var wins over the dotenv, so the key
    must stay absent rather than empty. Re-deployed from the corrected git file to prove the
    git→droplet path is clean. `do-update.md` gained the rule, a pre-ship
    `grep -n '<[a-z-]*>' deploy/*` check, and "always finish by calling a real proxied endpoint".
  - **Pre-existing, NOT caused by this deploy:** docapi returns `500` on `/api/v1/fish/search` and
    `/api/v1/news/list`. Confirmed by querying docapi directly, bypassing cproxy — identical
    statuses; cproxy logs them with upstream latency (`-> 500 (784ms)`), i.e. it is relaying
    faithfully. Needs looking at on the docapi side.
  - **Pre-deploy safety check** (every critical address tested against the range set before enabling
    anything): admin, frontend A record, frontend egress and the docapi VPC address are all clear.
    **The cproxy droplet's own public address IS in the DigitalOcean feed** — moot today because the
    `DOCKER-USER` allowlist means it can never be a client, but exempt it before widening that list.
  - Also learned: 91,633 fetched rows collapse to 63,818 unique `(provider, cidr)` — Azure repeats
    prefixes across service tags — and then to 3,914 coalesced intervals.
  - **Follow-up:** `CPROXY_CLOUDRANGE_REFRESH_ON_START=true` is still set from the first populate and
    should come out, or every redeploy re-pulls twelve third-party feeds.

- 2026-09-02: **0.8.0 — datacenter / cloud-provider IP blocking, with an in-process fortnightly
  feed refresher.**
  Ports the frontend's `dbo.CloudProviderIpRange` control (`aspnet/Account/CLAUDE.md`) to the
  gateway: a REST call whose peer address falls in published datacenter space is refused with the
  same opaque `500` as a failed day-key, **before every other guard**. Real anglers come from
  residential/mobile ISPs; sustained traffic from AWS/GCP/Azure/Oracle/DO/Alibaba is bots.
  - **Store** (`cloud_range_store.*`): SQLite `cloud_provider_ip_range(provider, cidr, ip_start,
    ip_end, disabled, source, updated_utc)`, PK `(provider, cidr)`, partial index on `ip_start
    WHERE disabled = 0` — same shape and same filtered index as the frontend's table.
  - **Lookup is in-memory**, not one indexed SQL seek per request as on the frontend: cproxy sees
    every call, so enabled rows load once into a sorted vector and binary-search. Refreshes publish
    a new snapshot via `std::atomic<std::shared_ptr<const vector>>` — readers never lock, never see
    a half-updated set, and a refresh takes effect with no restart.
  - **Ranges are COALESCED at load, and this is a real correctness fix, not an optimisation.** The
    frontend's single-seek query is only correct while ranges are disjoint. Across twelve feeds they
    are not: an interval nested inside another makes `TOP 1 … ORDER BY ipStart DESC` return the
    wrong row and answer "not blocked" for an address that *is* covered. Merging overlapping and
    adjacent windows makes the binary search correct unconditionally — and collapsed **91,633 raw
    rows to 3,914 intervals** in the first live run, so the small count is expected, not a bug.
    *(The frontend has the same latent hazard; not touched here.)*
  - **Peer address is `req.remote_addr`, never `X-Forwarded-For`** — cproxy is the edge, so an
    inbound XFF is attacker-controlled; honouring it would make the block both bypassable and a way
    to get a third party refused.
  - **Fail-SAFE, deliberately the opposite of the day-key store's fail-closed stance.** A missing or
    unreadable range DB blocks nothing. A *missing* file logs INFO (the normal state before the
    first refresh); a corrupt one logs ERROR. Refusing all traffic because a data file vanished is
    exactly the outage this asymmetry avoids — don't "make them consistent".
  - **`EXTERNAL_FRONTEND` / `EXTERNAL_ADMIN` are exempt automatically**, plus
    `CPROXY_CLOUDRANGE_EXEMPT_IPS`. The portal's own host sits at a hosting provider whose space a
    feed can legitimately cover, so without this the first refresh could take the site offline.
    Third hatch: `CPROXY_BLOCK_CLOUD_IPS=false` (no redeploy), mirroring the frontend's
    `BlockCloudProviderIps`.
  - **Refresher** (`cloud_range_refresh.*`): in-process thread, **fortnightly** (336h, configurable),
    mirroring `envfish-db/mssql/tools/Update-CloudProviderRanges.ps1` feed for feed — AWS, GCP,
    Oracle, DigitalOcean, the weekly Azure ServiceTags file (link scraped from the download page),
    and RIPEstat announced-prefixes for Alibaba/Linode/Vultr/Hetzner/OVH/Scaleway/Tencent. Both
    quirks that script documents are carried across (GCP entries with no `ipv4Prefix`; DO's CSV with
    no text content-type). Providers that succeeded are replaced in one transaction with `disabled`
    overrides preserved per `(provider, cidr)`; a failed feed keeps its own rows; if every feed
    fails the DB is untouched. Waits on a condition variable so shutdown never blocks on the timer.
    Does **not** refresh on boot by default — a redeploy loop would hammer the feeds for data that
    moves on the order of weeks.
  - **TLS turned ON, reversing a deliberate decision.** `HTTPLIB_USE_OPENSSL_IF_AVAILABLE` was off
    ("lean binary; cproxy speaks plain HTTP to internal upstreams") and that reasoning still holds
    for the proxy path, which is unchanged. But every provider feed is HTTPS-only. Accepted
    knowingly: libssl joins libcrypto, the image grows, **`ca-certificates` becomes load-bearing**
    (without the trust store every fetch fails cert verification), and the proxy now makes outbound
    internet calls it never made. nlohmann/json v3.11.3 (header-only) added to parse the feeds.
  - Tests: new `cloud_range_store_test` (IPv4 parsing incl. rejecting leading-zero/port/CIDR forms,
    CIDR expansion incl. `/0` and `/32` and host-bit masking, coalescing of nested/overlapping/
    adjacent ranges and the top-of-space wrap guard, boundary-exact lookups, `disabled` rows
    ignored, and a failed reload keeping the previous set); `proxy_test` gains
    `datacenter_ip_is_refused_with_500` (incl. proof it runs before the method allow-list, so the
    block can't be probed by method) and `datacenter_block_has_escape_hatches`. **6 suites, all
    passing** in the Docker build. Every address in the tests is RFC 5737/1918.
  - **Verified live (2026-09-02, Docker):** real container, real feeds, all **12 providers fetched
    successfully** — AWS 10,520 · GCP 1,003 · Azure 69,064 · Oracle 1,107 · DigitalOcean 1,080 ·
    Alibaba 2,193 · Linode 349 · Vultr 1,723 · Hetzner 481 · OVH 715 · Scaleway 20 · Tencent 3,378.
    91,633 rows written (8.6 MB SQLite), read back and coalesced to 3,914 intervals; `/health` →
    `0.8.0`. The Azure download-page scrape — the fragile one — worked.
  - **Deploy note (NOT deployed):** needs `CPROXY_CLOUDRANGE_DB` pointed at a **writable** path on
    the volume; the container runs `read_only: true`, so the range DB must live on a bind mount
    (alongside the day-key DB), not in the image. Until the first refresh completes nothing is
    blocked. Consider setting `CPROXY_CLOUDRANGE_REFRESH_ON_START=true` for the first deploy only,
    and confirm `EXTERNAL_FRONTEND` is set before enabling — that exemption is what keeps the portal
    reachable.

- 2026-09-01: **0.7.0 — the day-key now also gates a READ: `GET /api/v1/news/default`; plus the
  `CPROXY_LOG_DIR=""` console-only switch is fixed (it never worked) → `CPROXY_LOG_DIR=NONE`. BUILT
  AND VERIFIED LOCALLY, NOT DEPLOYED.**
  Until now the rotating credential was purely verb-based (every POST/PATCH, any path). It grows a
  second, independent arm: `CPROXY_DAYKEY_PATHS` (default `/news/default`) gates the listed paths on
  **every** method, GET included. `Config::daykey_required(method, path)` is the one place both arms
  are decided; `proxy.cpp` calls it instead of the old inline `POST||PATCH` test. Rationale:
  `/news/default` assembles the entire news home page upstream (lead articles + right column, each a
  full per-article document) and being a `GET` is not a reason to serve that to anonymous scrapers.
  - **Matching** is on the path *tail*, so an entry works at any route prefix (`/news/default` covers
    `/api/v1/news/default`); it is case-folded and trailing-slash-insensitive, and anything nested
    under a gated path is gated too. The entry's leading `/` keeps it on a segment boundary, so
    `/oldnews/default` does not match.
  - **The dot-dot rejection was moved ABOVE the gate** and must stay there. A tail match cannot be
    stripped by traversal, but it can be appended past:
    `/api/v1/news/default/../default` ends in `/default`, would clear a naive tail match, and still
    normalizes back to the gated endpoint at a Spring upstream. Now it is a `400` before the gate is
    ever consulted. (Worth knowing when testing: plain `curl` normalizes `..` client-side and shows a
    `500`; `curl --path-as-is` is what actually exercises this and shows the `400`.)
  - **Off switch is `CPROXY_DAYKEY_PATHS=NONE`, not `""`.** Caught in end-to-end testing, not by the
    unit tests: `system_env()` maps an empty variable to `nullopt`, so `-e CPROXY_DAYKEY_PATHS=`
    is indistinguishable from unset and silently left the default gate standing — while the unit
    test's fake `EnvLookup` hands back a real empty string and passed happily. Switched to a `NONE`
    sentinel (the same idiom `CPROXY_ALLOWED_METHODS` already uses for `ALL`) and added a test that
    asserts the empty case through `system_env` itself so the discrepancy cannot come back.
  - **`CPROXY_LOG_DIR` had the identical trap, and is fixed in this same 0.7.0 (undeployed, so no
    released behaviour changes).** CLAUDE.md and the spec both documented `CPROXY_LOG_DIR=""` as the
    console-only switch; through a real process environment it never was one — `system_env` collapses
    an empty variable to `nullopt`, the `if (auto ld = env(...))` never fired, and the service went on
    writing rolling files. Confirmed in a container: `-e CPROXY_LOG_DIR=` logs `"log_dir":"logs"`,
    i.e. it does not even keep the image's `/var/log/cproxy` — it drops to the compiled-in default and
    writes to a relative `./logs`.
    - **Fix (option a, the sentinel):** `CPROXY_LOG_DIR=NONE` (trimmed, case-insensitive) is
      console-only; everything else is a directory; empty falls back to the default via the ordinary
      `get_str`. Chosen over making `system_env` distinguish empty from unset because that collapse is
      now **load-bearing for security**: `CPROXY_DAYKEY_PATHS=""` must keep the default `/news/default`
      gate standing, and teaching `system_env` about empty would have turned that read gate **off**
      unless separately re-guarded — a fail-open regression, and two env vars with opposite empty
      semantics. The sentinel keeps one rule for the whole config surface. (Checked the other call
      sites either way: `get_str` already collapses empty→fallback, so `CPROXY_API_KEY`,
      `CPROXY_ROUTE_PREFIX` and `CPROXY_DOCAPI_UPSTREAM` would have been unaffected by option b; only
      `CPROXY_DAYKEY_PATHS` and `CPROXY_LOG_DIR` read `env()` directly.)
    - **Test:** `console_only_sentinel_works_through_the_real_environment` in `config_test` drives the
      **real process environment** through a portable `put_real_env` helper (`setenv`/`_putenv_s`) and
      the real `system_env` — not `make_env`. It asserts the blind spot itself (the fake returns a
      value for `""`, `system_env` does not), then `""` → default, `NONE`/`none`/`" None "` →
      console-only, an explicit path → that path, and unset → default. **Verified it actually catches
      the bug:** rebuilt the old `config.cpp` against the new test with the `make_env` sentinel
      assertions removed, and the real-environment test alone fails
      (`CHECK failed: load_config().log_dir.empty()`).
    - **Docs corrected** (all four had documented the broken behaviour as working): `CLAUDE.md`,
      `docs/specification.md`, `README.md`, `.env.example` — plus a general rule in each: *empty always
      means "use the default", every off switch is a word* (`ALL` / `NONE`), and a new switch must be
      asserted through `system_env` and the real environment. Noted the one asymmetry: the dotenv layer
      (`make_env_lookup`) *can* return a real empty string, so a dotenv line and `-e` were not
      equivalent under the old rule — now they are.
    - **Verified (2026-09-01, Docker):** `ctest` 5/5 in the build stage; container runs confirm image
      default → `/var/log/cproxy` + `cproxy.log` written; `-e CPROXY_LOG_DIR=` → `"logs"`;
      `NONE` and `none` → `"(stdout only)"`, nothing under `/var/log/cproxy`; explicit path → that
      path. **Not deployed.**
  - **Blast radius change:** a missing/corrupt day-key SQLite file previously degraded only the
    writes to "always 500"; it now also takes `/news/default` offline. The rest of the GET surface is
    unaffected, as before.
  - Tests: `config_test` gains the two-arm matching cases (prefix, casing, trailing slash, nesting,
    the `/oldnews/default` boundary, `PUT`/`DELETE` deliberately *not* in the method arm) and the
    sentinel/empty-value cases; `proxy_test` gains real-HTTP `gated_read_path_requires_day_key`
    (500 bare, 500 wrong key, 502 through with a valid key against a deliberately dead upstream,
    siblings still open, `--path-as-is` traversal → 400) and `gated_read_path_can_be_disabled`.
    All 5 suites pass in the Docker build (`ctest` runs inside it).
  - **Verified locally (2026-09-01, Docker):** `cproxy:0.7.0-test`, real container, real 365-row
    day-key SQLite, upstream deliberately pointed at `127.0.0.1:1` so `502` proves a request cleared
    the gate and `500` proves it was stopped by it. `/health` → `0.7.0`; `news/default` no key →
    `500`, wrong key → `500`, correct key → `502`; trailing slash / `News/Default` / `?country=CA` /
    `news/default/extra` → `500`; `news/list`, `news/search`, `fish` → `502` (untouched);
    `--path-as-is .../default/../default` → `400`; `CPROXY_DAYKEY_PATHS=NONE` → `502` while `PATCH`
    still `500`; `CPROXY_DAYKEY_PATHS=""` → `500` (correctly reads as unset);
    `CPROXY_DAYKEY_PATHS=/news/default,/news/export` → both `500`, `news/list` still `502`.
  - **Deploy note:** prod runs `CPROXY_ALLOWED_METHODS: GET,PATCH,POST` and already mounts the
    day-key DB, so this needs **no compose/env change** — the default gates `/news/default` on
    deploy. Any client that reads that endpoint must start sending `X-Day-Guid`; the ASP.NET frontend
    does not call it (grepped), so nothing in the portal breaks.

- 2026-08-26: **docapi `GET`/`PATCH /api/v1/river/source/{guid}` and
  `GET`/`PATCH /api/v1/river/mouth/{guid}` will front automatically once deployed (no cproxy change
  needed).** docapi 1.7.0 (built/tested, **not yet deployed**) adds the Source/Mouth-tab counterparts
  of the existing description/fish endpoints on `RiverController` — reads reuse the already-live
  `dbo.fn_lake_source_json`/`fn_lake_mouth_json`; writes are a JSON merge patch of that tab's editable
  fields via two new procs, `dbo.sp_lake_source_update`/`sp_lake_mouth_update` (`envfish-db`,
  2026-08-26), protecting the same class of identity/linkage fields the description PATCH already
  does. This gateway forwards any `GET`/`PATCH` under `/api/v1` with no per-path allowlist (see
  `install_routes` in `proxy.cpp`), so these four routes need **zero cproxy code or config change** —
  the PATCH pair picks up the existing verb-based day-key gate automatically, same as every other
  docapi write route so far. `docs/api-guide.html` updated: two new GET rows + two new PATCH rows in
  the River table, each tagged "docapi 1.7.0, not yet deployed" — no quick-reference rows added yet
  (those get added once live-verified, same as the regulation entry below).
- 2026-08-26: **Regulation endpoints verified live end-to-end through the public gateway.** docapi
  1.6.0 deployed to the droplet 2026-08-26. Confirmed through `http://<cproxy-droplet>`: `GET
  /api/v1/river/regulation/{guid}`, `GET /api/v1/region/regulation/ca/on`, `GET
  /api/v1/region/regulation/us` all `200` with real rows; `PATCH /api/v1/region/regulation/ca/on`
  with the correct `X-Day-Guid` reaches `sp_regulation_upsert` (`{"error":"year is required"}` on a
  body missing `year` — validation, not a write), and the same PATCH with no day-key is `500` as
  expected. No cproxy code/config change was needed, confirming the verb-based day-key gate covers
  the new routes exactly as predicted. `docs/api-guide.html` updated: "pending deploy" tags removed,
  version banner bumped to docapi 1.6.0 / cproxy 0.6.1, quick-reference rows added for the new
  live-verified requests.
- 2026-08-25: **docapi `GET`/`PATCH /api/v1/river/regulation/{guid}` and
  `GET`/`PATCH /api/v1/region/regulation/{country}[/{state}]` will front automatically once deployed
  (no cproxy change needed).** docapi 1.6.0 (built/tested, **not yet deployed**) adds
  `RegulationController` — two of the three scopes `Editor/LakeRegulation.aspx`'s "regulation dialog"
  edits (water-body + region/country-state; zone-scoped has no endpoint yet), via the new
  `dbo.sp_regulation_upsert`. Deliberately **no `POST`/insert verb** — every write is a PATCH that
  upserts by identity, specifically so this stays inside the existing `GET`/`PATCH`-only method
  allow-list and the day-key gate (which applies to every PATCH, not a specific path) covers it with
  zero cproxy code or config change. Will need the same live-verification pass the other write
  endpoints got (correct day-key → 200, no/wrong day-key → 500) once docapi 1.6.0 is actually deployed
  — not done yet, don't treat this feature as live until that happens. `docs/api-guide.html` updated
  (new Regulation section + quick-ref); version banner deliberately **left at 1.5.4** pending that
  verification.

- 2026-08-25: **docapi `PATCH /api/v1/river/description/{guid}` now fronted (no cproxy change).**
  docapi 1.5.4 added a second, independent write — a JSON merge patch of the
  `Editor/LakeEditor.aspx` "General" tab's editable fields (`dbo.sp_lake_description_update`),
  protecting `lakeName`/`source`/`sourceId`/`mouth`/`mouthId`. Reachable through the gateway
  automatically: the 0.6.1 day-key gate applies to **every** PATCH request, not a specific path, so
  this needed zero cproxy code or config change. Verified live end-to-end through the public gateway
  — correct day-key → 200 with a real field update and `lakeName` correctly reported protected;
  no/wrong day-key → 500; all other guards unchanged. `docs/api-guide.html` updated (River section +
  quick-ref + version banner → docapi 1.5.4).

- 2026-08-25: **0.6.1 — DEPLOYED to prod, fixing a live bug found during the 0.6.0 rollout:
  Content-Type was never forwarded on any proxied request body.** `is_unforwardable()` strips
  `Content-Type` deliberately for the RESPONSE side (`proxy_to_docapi` reads it straight off the
  upstream's own reply instead), but the OUTBOUND request built in the same function
  (`httplib::Request out`) is constructed by hand — not via `Client::Post`/`Patch`, which is what
  would normally set a default — so nothing set it at all. Every JSON body crossing the proxy arrived
  upstream as **`text/plain`**. This had never surfaced before because every endpoint fronted through
  cproxy until today was a bodyless GET; the first real body — the very first live PATCH test against
  `river/fish/{guid}` through the public gateway, day-key header correct — 500'd with
  `HttpMediaTypeNotSupportedException: Content-Type 'text/plain' is not supported` on docapi's side
  (confirmed via `docker logs docapi`, then reproduced and root-caused from the code, not guessed).
  Direct calls to docapi (bypassing cproxy) had worked fine throughout — the bug was entirely in the
  proxy's forwarding, never in docapi's endpoint. **Fix:** `proxy_to_docapi` now explicitly copies
  `req.get_header_value("Content-Type")` onto `out` when non-empty, right after the header-copy loop.
  New regression test `content_type_is_forwarded` (`tests/proxy_test.cpp`) — POST (not PATCH, to stay
  independent of the day-key gate) with `application/json`, fake upstream echoes back what it
  actually received; **would have caught this before it ever shipped**. Full local `ctest`: 5/5 pass.
  **Deploy timeline:** built 0.6.0 → pushed → deployed → live day-key smoke tests (no-header/wrong-key
  → 500, other verbs still 405) all passed **but the one real end-to-end PATCH (correct key, real
  body) 500'd** → root-caused in ~10 minutes from docapi's own logs → fixed → rebuilt as 0.6.1 →
  pushed → redeployed within the same session, no rollback needed. **Verified live**: PATCH with the
  correct day-key through `http://<cproxy-droplet>/api/v1/river/fish/{guid}` → `200`, real
  insert/GET-confirmed/cleaned-up round trip; GET endpoints, traversal guard (400), unknown-route
  (404), and the day-key 500s all re-confirmed unchanged. See "Day-key store" above for the design
  this ships (unchanged from 0.6.0 below other than this fix).

- 2026-08-25: **0.6.0 — day-key store (SQLite) gates the write surface; `CPROXY_ALLOWED_METHODS`
  updated to admit `PATCH`. Built and tested locally; NOT yet deployed.** Supersedes the entry
  directly below — the "leave PATCH un-fronted" decision was revisited: docapi's new
  `PATCH /api/v1/river/fish/{guid}` (1.5.3, batch upsert of assigned species) is now meant to be
  fronted, but gated by a **per-day rotating credential** instead of the static `CPROXY_API_KEY`.
  New `DayKeyStore` (`src/day_key_store.hpp/.cpp`) loads a 365-row read-only SQLite database
  (`day_keys(day_of_year, guid)`, path `CPROXY_DAYKEY_DB`) at startup and requires every PATCH
  request to carry the current UTC day's guid (± 1 day window) in `X-Day-Guid`; a wrong/missing key
  answers a generic `500`, not `401`, on purpose. New system dependency: `libsqlite3` via CMake's
  `find_package(SQLite3)` (`libsqlite3-dev` build-time, `libsqlite3-0` runtime — both added to the
  Dockerfile). New `day_key_store_test` (7 cases: today/yesterday/tomorrow window, both directions of
  the year boundary, leap-day-366 clamp to day 365's key, empty/unknown guid rejected, missing DB
  file throws, wrong row count throws) — full local `ctest` run: **5/5 suites pass**
  (config/secret_codec/proxy/breaker/day_key_store). Generated the actual 365 GUIDs with a throwaway
  script into `secret/daykeys.sqlite` (deploy target) + `secret/daykeys.csv` (human reference) — both
  gitignored, handed to the user directly, never committed. `deploy/compose.yml` updated
  (`CPROXY_ALLOWED_METHODS: GET,PATCH`, `CPROXY_DAYKEY_DB` + a new read-only bind mount at
  `/mnt/volume_cnode/cproxy/daykeys/daykeys.sqlite`, its own folder alongside the logs/`.env`/
  `master.key` mounts) — **but the image digest there is still 0.5.1**; deploying this needs its own
  build→push→pin→restart pass (`docs/do-update.md`) plus uploading the SQLite file to the droplet,
  same as any other prod change here. See "Day-key store" above for the full design.
  **Superseded same-day by the 0.6.1 entry above** — 0.6.0 itself was never actually deployed; a bug
  found during that deploy attempt was fixed and shipped as 0.6.1 instead.

- 2026-08-25: **docapi `PATCH /api/v1/river/fish/{guid}` added — initially left NOT fronted, now
  superseded by the day-key entry above.** docapi
  1.5.3 adds a batch upsert of assigned species (duplicate of the admin Save-JSON Fishing-tab "Add"
  form, `Editor/EditLakeFish.aspx` → `AddFishToLake`), backed by the new `dbo.sp_lake_fish_upsert_batch`
  — its **first write path outside document CRUD**. Unlike every prior river GET, this one is **not**
  reachable through the gateway: `CPROXY_ALLOWED_METHODS: GET` in `deploy/compose.yml` ("write surface
  stays 405") already blocks it, and no change was made here to lift that. docapi itself is never
  publicly bound either way, so right now `PATCH /river/fish/{guid}` is reachable only from inside the
  DigitalOcean VPC (i.e. from the cproxy droplet's own outbound calls, not from the internet).
  **Fronting it is a follow-up decision, not bundled into this entry** — doing so means both allowing
  `PATCH` in `CPROXY_ALLOWED_METHODS` *and* setting `CPROXY_API_KEY` (currently unset/no-auth), since
  this would be the platform's first publicly-reachable write endpoint. `docs/api-guide.html` documents
  the endpoint's existence and its VPC-only reachability, with no quick-reference "verified live" row
  (nothing to verify through the gateway yet).
- 2026-08-25: **docapi `GET /api/v1/river/fish/{guid}` now fronted (no cproxy change).** docapi 1.5.2
  added a fish endpoint (duplicate of the admin Save-JSON Fishing-tab export,
  `Editor/EditLakeFish.aspx` → `HandlerImage.ashx?lakejson=&tab=fishing`); cproxy forwarded it
  automatically, no redeploy — verified public through the gateway:
  `http://<cproxy-droplet>/api/v1/river/fish/a55caadf-2892-e811-9104-00155d007b12` → 200, real data
  ("Little Somme River") — the exact URL a user had hit pre-deploy and gotten docapi's own
  "No handler for the requested path" 404 from (prod was still 1.5.1). Unknown guid → 404 through the
  gateway too. `docs/api-guide.html` updated (River section + quick-ref + version banner → docapi
  1.5.2, verified 2026-08-25).
- 2026-08-24: **docapi `GET /api/v1/river/description/{guid}` now fronted (no cproxy change).** docapi
  1.5.1 added a description endpoint (duplicate of the admin Save-JSON View-tab export,
  `Editor/HandlerImage.ashx?lakejson=&tab=view`); cproxy forwards it automatically — verified public
  through the gateway (200 with real data for a known guid, 404 for an unknown one, 405 on POST). No
  redeploy. Updated `docs/api-guide.html` (River section + quick-ref + version banner → docapi 1.5.1).
- 2026-08-24: **0.5.1 — ship the `mcrypter`/`_HIDD` env-name obfuscation layer. DEPLOYED to prod** as
  `ghcr.io/balintomsk/cproxy@sha256:304428…4fb0` (compose digest bumped). No behavioural change vs
  0.5.0: the commit `1e089d9` ("Additional abstraction layer to obscure the data") obfuscates the
  `FF_MASTER_KEY_FILE`/`FF_MASTER_KEY` env-var name lookups in `secret_codec.cpp` via `mcrypter.hpp`
  `_HIDD(...)`. That commit landed **after** the 0.5.0 image build, so prod was one commit stale until
  now. Followed `docs/do-update.md`: bumped `CMakeLists` 0.5.0→0.5.1 (don't reuse the 0.5.0 rollback
  tag), built (4/4 tests: config/secret_codec/proxy/breaker), pushed, pinned the new digest in
  `service/cproxy/deploy/compose.yml`, `docker compose up -d --pull always`. **Verified:** `/health`
  0.5.1, `/health/ready` 200 (breaker closed), `/api/*` 200, POST→405/404 guards, and startup log
  `external_admin`/`external_frontend` = `set` (proves the obfuscated key lookup still decrypts the
  real `.env`). `restarts=0`. `CMakeLists`+`compose.yml` committed (`fdd97f3`) to reconcile git↔prod.
- 2026-08-24: **docapi `GET /api/v1/river/unfished` now fronted (no cproxy change).** docapi 1.5.0 added
  a river endpoint (duplicate of the frontend `wbUnFish.aspx`); cproxy forwards it automatically because
  it already proxies every `GET /api/*` to docapi over the VPC. Verified public:
  `http://<cproxy-host>/api/v1/river/unfished?country=CA&state=NL&river=2` → real data. No redeploy.
- 2026-08-04: **0.5.0 — Phase 3 reliability. DEPLOYED to prod** as
  `ghcr.io/balintomsk/cproxy@sha256:f6bc38…038f` (compose digest bumped). (1) **Pooled upstream
  connections** — `pooled_client()` keeps a `thread_local` keep-alive `httplib::Client` per worker
  thread instead of constructing one per request (was a full TCP connect+teardown every call).
  Thread-local, not shared: one Client serializes concurrent requests on its own mutex. (2)
  **Circuit breaker** (`breaker.{hpp,cpp}`) — after `CPROXY_BREAKER_THRESHOLD` (5) consecutive
  **transport** failures it opens and requests get an immediate `502 upstream_unavailable` instead
  of each paying the connect timeout and pinning a worker thread; after
  `CPROXY_BREAKER_COOLDOWN_MS` (5000) exactly ONE probe is admitted (half-open), success closes it,
  failure re-opens with a fresh cooldown. **HTTP error statuses from a reachable upstream do NOT
  trip it** — only transport errors. Clock is injected, so the cooldown is unit-tested without
  sleeping. (3) **`CPROXY_UPSTREAM_RETRY`** (1) — one retry for **GET/HEAD/OPTIONS only** on a
  transport failure, hiding a pooled connection the upstream closed while idle (httplib drops the
  dead socket on failure, so the retry reconnects); never for POST/PATCH. (4) **`GET /health/ready`**
  — 503 while the breaker is open; `/health` stays pure liveness (200 during an outage, so an
  orchestrator never kills a healthy proxy over a sick upstream). Readiness reads breaker state
  rather than probing on demand, which would hammer a struggling upstream. (5) **`GET /metrics`** —
  Prometheus text: requests by status, upstream latency sum/count, failures, retries,
  short-circuits, breaker state. Counted in **`set_post_routing_handler`**, which httplib runs for
  every response *after* the error handler, so it is the one place that sees every status exactly
  once. **Key design point: breaker + counters are per-`install_routes` (`shared_ptr<ProxyState>`
  captured by the handlers), NOT global** — the tests stand several proxies up in one process and
  global state would leak between them. New `breaker_test` (6 state-machine cases) + 3 proxy
  integration cases (readiness/fail-fast timing, metrics counters, **connection reuse** — asserts
  5 requests share ONE upstream socket via `remote_port`; it was 5 before). All 4 suites green;
  red confirmed first (stub breaker + missing endpoints). **Verified in a container** through a
  full outage cycle: 2 failures → open, short-circuit in **0.02s**, `/health/ready` 503
  (`"upstream":"open"`) while `/health` stayed 200, upstream restarted → probe after cooldown →
  closed, counters correct. **Verified in prod:** `/health` 0.5.0, `/health/ready` 200
  `"upstream":"closed"`, 3× `/api/v1/fish/search` 200 (first 0.30s then 0.21/0.20s — the pooled
  connection showing), `/metrics` counting, traversal 400 + POST 405 still intact. **Gotcha found:**
  a `*/` inside a doc comment (`X-Forwarded-*/X-Request-Id`) silently terminates the comment block —
  broke the build until reworded.
- 2026-08-04: **0.4.0 — Phase 2 security hardening. DEPLOYED to prod** as
  `ghcr.io/balintomsk/cproxy@sha256:b7f197…d750` (compose digest bumped, droplet now GHCR-authed —
  earlier deploys used save/scp/load). Changes: (1) **dot-dot path rejection (400)** — plain and
  percent-encoded `..` segments die at the proxy (an upstream could normalize `/api/../actuator`
  out of the route prefix); checked on both the decoded path and the raw target. (2) **Raw-target
  forwarding** — forwards `req.target` verbatim (no decode/re-encode round trip). (3)
  **`X-Request-Id`** — well-formed caller id preserved, junk re-minted (`[A-Za-z0-9_-]{1,64}`);
  propagated upstream, echoed in the response, logged. (4) **Client IP + reqid in every log line**
  (`log_request`), including **404s** (scanner visibility; `/health` stays unlogged). (5)
  **Constant-time API-key compare** (`CRYPTO_memcmp`). (6) **`CPROXY_MAX_PAYLOAD_BYTES`** (default
  1 MiB) → 413. (7) **Startup config validation** (`validate_config`) — port/timeout/prefix/upstream
  nonsense is FATAL. (8) **Inbound `X-Forwarded-*`/`X-Request-Id` stripped** before forwarding —
  httplib's `set_header` APPENDS to the multimap, so a spoofed inbound value would otherwise ride
  along next to ours. **Two big pre-existing defects found by the new tests:** (a) the whole ctest
  suite was **passing vacuously** — Release builds define `NDEBUG`, turning `assert()` into a no-op;
  all tests now use `tests/check.hpp` `CHECK` (fails properly in Release). (b) **`pre_routing_handler`
  runs BEFORE httplib reads the request body** — the old catch-all forwarded POST/PUT bodies EMPTY
  and the payload limit never fired; routing is now real per-method regex routes
  (`regex_escape(prefix) + ".*"`), body read+capped before dispatch; unmatched paths fall to the
  error handler (JSON by status + logged). New `tests/proxy_test.cpp` — 8 integration scenarios
  driving real HTTP through `install_routes` against an in-process fake upstream (health, raw-target
  forward, reqid mint/preserve/replace, traversal ×3 + dots-in-segment pass, key/method guards,
  413 + body-never-reaches-upstream, body forwarding, 502/404); test-first: confirmed failing
  against 0.3.0 before the fix. **Verified live:** `/health` 0.4.0; `/api/v1/fish/search` 200 with
  `X-Request-Id` echoed; `/api/../secret` + `/api/%2e%2e/secret` → 400; POST → 405; `/nope` → 404;
  volume log lines carry `ip` + `reqid`. Old container kept running through the GHCR auth hiccup —
  zero downtime swap.
- 2026-08-04: **Phase 1 artifacts folded into git (`deploy/`) + firewall parameterized.** The droplet
  script was reworked to read its allowlist from `/usr/local/etc/cproxy-firewall.allow` (one IP/CIDR
  per line; missing file = fail-closed drop-all) so the tracked copy carries no real IPs (AGENTS.md
  rule). Tracked now: `deploy/cproxy-firewall.sh`, `deploy/cproxy-firewall.service`,
  `deploy/cproxy-firewall.allow.example` (placeholders), `deploy/compose.yml` (private VPC addresses
  only). Droplet updated to the parameterized script + real allow file (admin `<admin-ip>`,
  fishfind `<frontend-ip>` + egress `<frontend-egress-ip>`), reapplied, unit restart clean, `/health` 200
  from admin IP. **The droplet's `/usr/local/sbin/cproxy-firewall.sh` and `/opt/cproxy/compose.yml`
  must stay in sync with `deploy/`** — edit in git, then scp + rerun.
- 2026-08-04: **Phase 1 hardening DEPLOYED — public access closed to two allowed sources.** (1)
  **IP allowlist** on the droplet: `/usr/local/sbin/cproxy-firewall.sh` populates the `DOCKER-USER`
  iptables chain (the chain Docker-published ports actually honor — ufw/INPUT is bypassed by Docker
  NAT): on `eth0` only `<admin-ip>` (EXTERNAL_ADMIN) and `<frontend-ip>` (EXTERNAL_FRONTEND =
  fishfind.info's WinHost server, resolved 2026-08-04) may reach published containers; everyone else
  DROPs; established/related returns for container-initiated outbound (GHCR pulls) stay open; `eth1`
  (VPC) and SSH (host INPUT) untouched, so no lock-out risk. ip6tables mirrored (drop-all — no global
  IPv6 on eth0 but Docker publishes `[::]:80`). Persisted via systemd oneshot
  `cproxy-firewall.service` (`After=docker.service`, enabled) since iptables rules don't survive
  reboot. (2) **Run config captured in `/opt/cproxy/compose.yml`** (replaces the hand-typed `docker
  run`; redeploy = `docker compose -f /opt/cproxy/compose.yml up -d`) with the image **pinned by
  digest** (`ghcr.io/balintomsk/cproxy@sha256:883f0c…913f` = 0.3.0) and container hardening:
  `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`. Container recreated under it, healthy,
  secrets still decrypt (`external_admin:set`). **Verified:** admin IP → `/health` 200 +
  `/api/v1/fish/search` 200 + POST 405; check-host.net nodes (DE/IR/RU) → connection timeout; DROP
  counter accruing; volume logs still written. **Egress verified (2026-08-04):** a temporary
  server-side test page on fishfind.info proved WinHost's *outbound* egress IP is **<frontend-egress-ip>**
  — NOT the A record `.29` — so `cproxy-firewall.sh` allows **both** `.28` (egress, the one that
  matters for calling cproxy) and `.29` (the site's inbound IP); with only `.29` the site's call
  timed out, with `.28` added it gets `/health` 200. Test page deleted after use. If a future
  frontend→cproxy call ever times out, re-check WinHost's egress IP first (same test-page trick:
  server-side fetch of `api.ipify.org` + cproxy `/health`).
  `CPROXY_API_KEY` deliberately NOT enabled yet — no frontend caller exists to carry the header;
  enable together with the frontend integration. **No code/image change — droplet config only.**
- 2026-08-04: **0.3.0 — encrypted config values (SecretCodec-compatible) read from `volume-cnode`.**
  New `secret_codec.{hpp,cpp}` (OpenSSL AES-256-GCM decrypt of `enc:v1:` values, AAD = var name, key
  from `FF_MASTER_KEY_FILE`) + `dotenv.{hpp,cpp}` (read `CPROXY_DOTENV_PATH`, decrypt, real-env-wins
  lookup). `EXTERNAL_ADMIN` / `EXTERNAL_FRONTEND` are carried encrypted in `secret/.env` (produced by
  the new tracked `secret/Protect-Env.ps1`, `-Encrypt` = those two) and decrypted at startup; masked in
  logs. Missing/wrong key ⇒ fatal exit 1 (verified). `config_test` +1, new `secret_codec_test`
  (decrypts a fixture the .NET AesGcm produced — cross-impl proof); Dockerfile adds `libssl-dev`
  (build) / `openssl` (runtime). **Deployed to `<cproxy-droplet>` as
  `ghcr.io/balintomsk/cproxy:0.3.0`**: `.env` + `master.key` copied to `/mnt/volume_cnode/cproxy/`
  (uid 10001, `0400`), bind-mounted read-only; startup log shows `external_admin:set`,
  `external_frontend:set`; `/health` 0.3.0, `/api/*` 200. `secret/{.env,master.key,plaintext.env}`
  gitignored.
- 2026-08-04: **Committed + pushed to version control.** The cproxy service (0.2.0) is committed on
  `efc-proxy` `main` and pushed to `github.com/BalinTomsk/efc-proxy` (real IPs scrubbed from the tracked
  `README.md`; `AGENTS.md` gained the "no external real IPs in README" rule). Upstream docapi's
  fish-search endpoint — which cproxy fronts under `/api/v1/fish/search` — was merged to `efj-backend`
  main (PR #85) and is live as docapi 1.4.0. Prod (`http://<cproxy-host>/`) and git are in sync.
- 2026-08-04: **0.2.0 — rolling-file logging (waterservice parity) on `volume-cnode`.** Added
  `log.hpp/.cpp`: JSON to console **and** a daily-rolling file (`cproxy.log` → `cproxy.<date>.log`,
  keep `CPROXY_LOG_MAX_HISTORY`=7 days), matching waterservice's logback console+file setup.
  Config gained `CPROXY_LOG_DIR` (image default `/var/log/cproxy`; `""`=console-only) +
  `CPROXY_LOG_MAX_HISTORY`. `main` inits logging and routes startup + request lines through it; `proxy`
  no longer has its own logger. `config_test` +1 case (7 asserts total incl. logging + empty-dir).
  **Deployed to `<cproxy-droplet>` as `ghcr.io/balintomsk/cproxy:0.2.0`**, logs bind-mounted from the DO
  volume `volume-cnode` at `/mnt/volume_cnode/cproxy/logs` → `/var/log/cproxy` (volume was already
  ext4-formatted+mounted — NOT reformatted; added an fstab `nofail` entry for reboot persistence).
  Verified: public `/health` 0.2.0, `/api/v1/fish/search` 200, and the startup+request JSON lines
  landing in `/mnt/volume_cnode/cproxy/logs/cproxy.log`. **Note:** the placeholder default upstream
  `http://127.0.0.1:8080` self-loops if hit under `/api/` (proxy forwards to its own port) — harmless
  in prod (upstream is docapi) but don't run the default against `/api/` locally.
- 2026-08-04: **Initial service — built and DEPLOYED.** C++23 reverse proxy fronting docapi for
  `fishfind.info`. cpp-httplib server+client; env-driven config; `/health` + `/api/`-forward + 404;
  hop-by-hop stripping; `X-Forwarded-*`; optional API-key + method allow-list; 502 on upstream failure.
  Multi-stage Debian 13 Docker image (non-root, ctest-in-build). **Deployed to `<cproxy-droplet>`** as
  `ghcr.io/balintomsk/cproxy:0.1.0`, public on port 80, GET-only, upstream docapi over the DO VPC
  (`http://<docapi-vpc>:8080`). docapi rebound to dual-publish `127.0.0.1` + `<docapi-vpc>` (VPC), change
  persisted in the `update-docapi` skill. End-to-end verified public → cproxy → VPC → docapi → SQL.
