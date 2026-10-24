---
name: triage-results
description: Validate and narrow down 404Plyh recon results for a target into a short list of genuinely important findings. Starts from the server's ranked finding model, verifies promising signals live against the target (read-only + light param probing, scope- and rate-gated), chains related signals into attack-surface stories, writes verdicts back via the state API, and emits a ranked triage_report.md. Use when the user asks to triage, validate, review, or "find the interesting stuff" in a recon target directory.
---

# Triage 404Plyh results

You are triaging the output of an **authorized** bug-bounty recon run. The pipeline has
already collected and *scored* signals. Your job is the judgment layer on top: confirm what
is real, kill false positives, chain related signals, and hand back a short ranked list of
what actually deserves a human's attention.

You do **not** re-score from scratch and you do **not** invent a new signal model. The
ranking already lives in `db.py` (`findings` table, `score`, `score_detail`, tiers). You add
live verification and correlation that the passive pipeline cannot do.

## Hard rules (read first, never break)

These mirror the project's working agreement. A fresh run of you must honor them even if it
seems "helpful" to skip them.

1. **Scope gate.** Before any network request to a target host, confirm the host is in scope
   by applying `ScopeEngine.is_in_scope` from `dashboard.py` exactly — it is the single source
   of truth, and the same gate that governs the recon scans themselves. Scope lives in
   `<projects_dir>/.scope_config.json` (global `in_scope`/`out_of_scope` plus
   `target_overrides[<target>]`). Match hostnames with fnmatch patterns and CIDRs just as that
   method does. Its semantics (do not second-guess them):
   - **Empty `in_scope` ⇒ every host is allowed** *except* those matching `out_of_scope`.
     This is the intended default here: operators treat everything as in scope and carve out
     exclusions via `out_of_scope`. Do **not** refuse or downgrade to passive-only just because
     `in_scope` is empty.
   - Non-empty `in_scope` ⇒ a host must match a pattern to be allowed.
   - **A host matching `out_of_scope` is never touched**, regardless of the above.
   Only the host matching the engine's result is fair game; a host the engine rejects ⇒ do not
   touch it, handle it as "Needs a human".
2. **Read-only + light probing only.** Allowed: `GET`/`HEAD`, fetching a response body you
   already have a URL for, re-checking status/size/content-type, and **single-shot** param/ID
   manipulation on an *already-discovered* endpoint to test for access-control / IDOR-shaped
   behavior. **Forbidden:** fuzzing, wordlist/dir brute force, cred stuffing, any
   state-changing request (POST/PUT/DELETE/PATCH to real data), exploitation beyond a
   minimal proof, DoS-shaped request volume, or anything destructive.
3. **Rate-aware.** Respect the pipeline's conservative posture. Default to **≤ 1 request/sec**
   per host, serial not parallel, with a short timeout (e.g. `curl -s -m 15`). Honor
   `RATE_LIMIT`/`THREADS` from `.env`/`config.sh` if present (treat them as ceilings, go
   lower). Never hammer. If a host returns errors/ratelimit signals, back off and note it.
4. **Never write `severity`, never fabricate `confirmed`.** `severity` is human-only and must
   stay NULL unless the user explicitly sets it. The tier firewall holds: a heuristic/regex/
   keyword match is at most `suspicious`; `confirmed` requires an active-verification artifact.
   When *you* verify something live, record it with `starred: true` + a clear `notes` trail and
   a `verdict` — do **not** rewrite the DB tier to `confirmed` yourself. Let the human confirm.
5. **Faithful reporting.** If a check failed, timed out, or you skipped it, say so. Do not
   claim a finding is confirmed when you only re-read a file.
6. **Blend in — real browser User-Agent.** Every request to a *target* host must send a
   normal, current browser User-Agent, never a bot/AI/tooling UA (no `curl/x.y`, no "claude",
   no "python-requests"). An AI/tooling UA gets you blocked, rate-limited, or served different
   content, and skews the triage. Define it once and pass it on **every** target request:
   ```bash
   UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
   curl -s -m 15 -A "$UA" "https://<target-host>/<path>"
   ```
   (Calls to the local dashboard API at `127.0.0.1` don't need it — this is about target
   traffic only.) If a tool other than curl is used for a target request, set the same UA on it.

## Inputs you need

- **target** — the target folder name (e.g. `example.com`), i.e. the subdirectory under the
  projects dir that holds `recon.db`, `httpx/`, `js/`, etc.
- **projects_dir** — the parent dir passed to `dashboard.py -p`. If you were launched inside a
  single target dir, `projects_dir` is its parent and `target` is its basename.
- **dashboard base URL** — if the dashboard is running, default `http://127.0.0.1:9090`
  (override if the user gives another port). Probe it once; if it's down, use the DB/file path.

Confirm these up front. If the user just says "triage this" from inside a target dir, infer
`target`/`projects_dir` from the working directory and state your assumption.

## Progress markers (emit these — the dashboard tracker depends on them)

When launched from the dashboard, your stdout is the run log and the UI progress bar is driven
by it. The recon engine prints `Module N:` banners; you must print a **phase marker** instead.
**As the very first action when you enter each phase, echo its marker line verbatim** so the
tracker advances and the timing is accurate:

```bash
echo "TRIAGE PHASE: Preflight"            # entering Phase 0
echo "TRIAGE PHASE: Load & orient"        # entering Phase 1
echo "TRIAGE PHASE: Prune & budget"       # entering Phase 1b
echo "TRIAGE PHASE: Live validation"      # entering Phase 2
echo "TRIAGE PHASE: Chain signals"        # entering Phase 3
echo "TRIAGE PHASE: Write-back & report"  # entering Phase 4
```

The header text must match exactly (the server maps it to `TRIAGE_STAGES` in `dashboard.py`).
Emit each once, in order; don't skip a phase's marker even if that phase is quick. This is the
only source of live progress for a triage run, so treat it as required, not cosmetic.

## Phase 0 — Preflight (run first, always report it)

Before any triage, confirm your environment can actually do the job, so a degraded run is
obvious instead of silently thin. Run these quick checks and keep the results — they go at the
**top** of both your chat summary and `triage_report.md` as a short "Preflight" block.

1. **Shell + core tools.** Verify the command-line tools the later phases use are present and
   runnable (not just installed — actually invoke them once):
   ```bash
   for t in curl sqlite3 grep sed; do
     command -v "$t" >/dev/null 2>&1 && echo "ok   $t" || echo "MISS $t"
   done
   curl --version >/dev/null 2>&1 && echo "ok   curl runs" || echo "FAIL curl cannot run"
   ```
   - `curl` **missing/blocked ⇒ no live validation is possible** — say so loudly and fall back
     to passive triage only (Phases 1 + 3), clearly labelling every finding "unverified".
   - `sqlite3` missing only matters for the DB fallback; note it and prefer the API/file paths.
2. **Tool-permission sanity (scoped-allowlist runs).** When launched from the dashboard the
   agent runs with a *scoped* `--allowedTools`; a tool outside that list is **auto-denied**, not
   prompted. So if a check above fails because the tool itself is fine but the *agent* can't use
   it, treat that as an environment failure, not a missing binary — report it as
   "tool denied by permission policy" and tell the user to widen `TRIAGE_AGENT_ARGS`.
3. **Data source.** Determine which path you're on and confirm it's live:
   ```bash
   curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/findings?target=<target>"   # 200 ⇒ API path
   ls -1 <projects_dir>/<target>/recon.db 2>/dev/null                                  # ⇒ DB fallback
   ```
   Record which one you'll use. If none works (no server, no DB, no files), stop and tell the
   user — there is nothing to triage.
4. **Write test.** Confirm you can write the report where it belongs:
   ```bash
   touch <projects_dir>/<target>/reports/triage_report.md 2>&1 && echo "ok   report writable"
   ```
   If writes are denied (e.g. `Write` not in the allowlist), still do the triage but deliver the
   report in chat and say the file couldn't be written.

**Preflight block format** (put it first in the report and summarise it in chat):
```
Preflight: curl ok · sqlite3 ok · data source=API(200) · report writable=yes · WARNINGS: none
```
If anything is MISS/FAIL/denied, list each one and state plainly how it degrades this run
(e.g. "curl denied ⇒ passive-only, all findings unverified"). **Never proceed silently past a
failed preflight** — the whole point is that the user learns something went off at a glance.

## Phase 1 — Load & orient (no network)

Prefer the dashboard API (it reuses the exact server scoring); fall back to the DB; fall back
to files. In all three, the **latest scan** is the one to triage.

**A. API path (preferred). Summary-first — do NOT slurp all findings.** On a large scope the
full `/api/findings?target=` payload (every finding, with `evidence`/`score_detail` on each
row, across every asset) is huge and will burn context for no reason. Start from the compact
per-asset summary and only drill into assets worth it:
```bash
BASE=http://127.0.0.1:9090
curl -s "$BASE/api/findings/assets?target=<target>" > assets.json      # one small row per asset
```
Each summary row has `host`, per-tier `tiers` counts, a correlated priority `score`, `live`,
`web`/`tech`/`status`, and a short `preview`. Rank assets by this. **Then**, only for the
assets that survive pruning + budget (below), pull their full findings one host at a time,
filtered to actionable tiers:
```bash
curl -s "$BASE/api/findings?target=<target>&asset=<host>&tier=suspicious"
curl -s "$BASE/api/findings?target=<target>&asset=<host>&tier=confirmed"
```
Each finding then carries `fingerprint`, `url`, `source`, `type`, `tier`, `score`,
`score_detail`, `evidence`, plus merged human state (`verdict`, `severity`, `starred`,
`notes`). This keeps context proportional to the *top-N assets you actually investigate*, not
to total scope size.

**B. DB fallback (server down).** Read the per-target SQLite directly, latest scan only:
```bash
DB=<projects_dir>/<target>/recon.db
sqlite3 -json "$DB" "
  SELECT f.* FROM findings f
  WHERE f.scan_id = (SELECT id FROM scans ORDER BY id DESC LIMIT 1)
  ORDER BY f.score DESC, f.id ASC;"
sqlite3 -json "$DB" "SELECT * FROM finding_state;"   -- merge by fingerprint
```
Mirror `ReconDB.get_findings`: join `finding_state` on `fingerprint`, default verdict `new`,
severity NULL, starred false.

**C. File fallback (no DB yet, fresh scan).** Read the on-disk contract directly — these are
the highest-signal files to start from:
- `reports/summary.json`, `reports/summary.txt` — scope of the run
- `dorks/active_confirmed.txt`, `dorks/active_hits.txt` — already active-verified dork hits
- `historical/validated_interesting.json`, `historical/probed_interesting.txt`
- `js/secrets.txt`, `js/leakage.txt`, `js/api_endpoints.txt`, `js/new_hostnames.txt`
- `js/extracted_maps/` — reconstructed sourcemap source
- `endpoints/api_paths.txt`, `endpoints/sensitive_files.txt`, `endpoints/interesting_paths.txt`
- `httpx/results.json`, `httpx/alive.txt` — what's live, titles, tech, status
- `ports/hosts_with_ports.txt`, `infra/infra_map.json`

Build a working set: group findings by `asset` (host), highest-scoring first, and load the
scope rules so every later live check can be gated.

### Phase 1b — Prune useless assets, then budget (do this before any live check)

The cheapest token is the one you never spend. Drop low-value assets up front so Phase 2 never
investigates them. Prune an asset when **any** of these holds:

1. **Already ignored.** It's in the persistent ignore list — `GET $BASE/api/triage?target=<target>`
   returns `{starred, ignored}`. Skip every host in `ignored` outright.
2. **Already dismissed.** All its findings carry a dismissed verdict (`false_positive`/`wont_fix`).
   The summary already discounts these — an asset with nothing left is noise.
3. **Out of scope.** Fails the scope gate (handle it exactly as Phase 0/scope rules require).
4. **No actionable signal.** Its `tiers` are **only `observation`** — zero `suspicious` and
   zero `confirmed`. Pure-observation hosts (plain alive host, generic tech fingerprint, a
   wildcard/CDN catch-all with nothing behind it) are not worth live-checking. Keep them only
   if the user explicitly asks for an exhaustive pass.
5. **Below the value floor.** Its correlated asset `score` is under a threshold **and** it has
   no `confirmed`/`suspicious` findings.

**Known noise — kill on sight (no live check, no tokens spent).** Use your own judgment plus
the scan data to dismiss these *before* Phase 2. Mark them `false_positive` with a one-line
reason and move on — do not fetch them, do not pull their full findings:

- **Blanket-WAF patterns.** A host where sensitive paths (`/.git`, `/actuator/env`, `/admin`,
  `/backup.sql`, …) all return the **same** status with an identical/zero length (classic
  `[403] len:0`, or a uniform 404/200 soft-wall). That's a WAF/edge default, not exposure —
  one spot-check at most, then dismiss the whole set.
- **SPA catch-all 200s.** A host that returns `200` for *any* `*.json`/`*.js` path, including
  obviously impossible ones (`.../node_modules/.../guide.json`, random paths). The framework
  serves `index.html` for everything — every "sensitive-file" hit on it is a false positive.
- **Benign standard files.** `robots.txt`, `crossdomain.xml`, `manifest.json`, `sitemap.xml`,
  `security.txt`, favicon, SAML/OAuth `/login` pages. "200" ≠ sensitive. Don't re-verify these.
- **Auth-walled source hosts.** GHE/GitLab/Bitbucket repo *blob* paths (e.g.
  `…/blob/master/.../.env`) require auth and are not filesystem exposure — the only check worth
  one request is the **bare** `https://<host>/.env` / `/.git/config` at web root, not every blob.
- **Front-end-safe keys.** Domain-locked/public keys meant to ship in client JS (e.g. a
  referrer-restricted Maps key, a public analytics id). Note and dismiss; don't probe.
- **Pure-observation / CDN / wildcard hosts** with no `suspicious`/`confirmed` signal (already
  covered by prune rule 4) — never promote these into Phase 2.

Spend live checks only where a 200 would plausibly be *sensitive and real*. When in doubt, one
cheap `HEAD`/`GET` to decide, then commit to a verdict — don't re-chase the same noise.

Then **budget** what's left: take the **top `MAX_ASSETS` assets by score** (default **20**),
and within each, the **top `MAX_FINDINGS` findings by score** (default **50** total across the
run). These are overridable — if the user names a number ("triage the top 10 hosts") use that;
otherwise use the defaults and state them in the Preflight/Coverage. Everything pruned or
beyond budget is listed in the report's Coverage note (counts, not detail) so nothing vanishes
silently — the user can always ask you to go deeper on the tail.

**Optional persistent pruning (compounding savings).** For assets *you* judge genuinely
useless after looking (not merely low-scored — actually noise), you may add them to the ignore
list so future runs skip them for free:
```bash
# merge, don't overwrite: read current ignored, add hosts, POST the union
curl -s -X POST "$BASE/api/triage" -H 'Content-Type: application/json' \
  -d '{"target":"<target>","starred":[...existing...],"ignored":[...existing + new...]}'
```
Only do this for clear noise, mention which hosts you ignored in the report, and never ignore a
host that had any `suspicious`/`confirmed` signal.

## Phase 2 — Live validation (the part a human would do by hand)

Go down the ranked list. For each high-value finding, pick the matching check. **Scope-gate
every host first.** Keep it read-only + rate-limited, and send the **browser User-Agent**
(hard rule 6: `curl -s -m 15 -A "$UA" …`) on every target request.

- **Exposed/sensitive file (dorks, `sensitive_files.txt`):** re-fetch with `GET`. Confirm it's
  still live, check status, content-type, size, and *look at the body* — is it a real
  `.env`/backup/config/`.git` or a soft-404/login redirect/placeholder? A 200 that returns a
  generic HTML page is a false positive.
- **Secret/key in JS (`js/secrets.txt`, `js/leakage.txt`):** read the evidence, classify the
  key type. Decide live-ness with the **minimal** read-only check for that key type (e.g. a
  single metadata/validate call), never a privileged or state-changing one. A restricted,
  public, or clearly front-end-safe key (e.g. a domain-locked maps key) is low value — say so.
- **API endpoint (`js/api_endpoints.txt`, `endpoints/api_paths.txt`):** `GET` it
  unauthenticated. `401`/`403` with a sane auth wall is expected; **`200` returning real data
  unauthenticated** is the finding. Note what data shape comes back.
- **Historical param URL (`historical/validated_interesting.json`):** if it exposes an
  object-id/user-id-shaped param, do **one** controlled swap to a neighbouring/sentinel value
  and compare responses (read-only). Different record returned ⇒ IDOR-shaped, worth flagging.
  Identical/denied ⇒ not. Do not iterate or enumerate.
- **Live host / title / tech (`httpx/results.json`):** confirm admin panels, dev/stage hosts,
  default pages, and interesting tech are still reachable and look as recorded.
- **New hostname from JS (`js/new_hostnames.txt`):** does it resolve and respond, and is it
  *absent* from the main alive list? Unlinked internal surface is high value.

Record each check's outcome (confirmed / false-positive / inconclusive / skipped-why) as you
go — you'll both write it back and report it.

## Phase 3 — Chain signals

Isolated hits are noise; chains are findings. Actively look for these combinations across the
working set (and any others that emerge):

- **Sourcemap → source → internal API → unlinked host:** exposed `.js.map`
  (`js/extracted_maps/`) → reconstructed source reveals an API base or hostname
  (`js/new_hostnames.txt`) → that host resolves + responds but isn't in `httpx/alive.txt` ⇒
  undocumented internal surface. Verify the host is live (one request, in scope).
- **Leaked key → which service → live:** key in JS → identify the API → one read-only
  validity check ⇒ a live, usable credential is far more important than a string match.
- **Exposed file + privileged host:** `dorks/active_confirmed.txt` hit on a host that
  `ports/`/`httpx` shows running an admin/management surface ⇒ access-control story.
- **Historical param + reflected/id behavior:** validated interesting URL with an id-shaped
  param + Phase-2 swap test ⇒ IDOR-shaped candidate.
- **Dev/stage host + weak auth/default page:** stage subdomain live with a default or
  unauthenticated panel ⇒ likely softer target into the same app.

For each chain, write one plain-English sentence: *signal → signal → why it matters*, plus the
concrete live evidence you gathered.

## Phase 4 — Narrow & write back

**Write-back (state API, server up):** for each finding you judged, persist your verdict so it
survives re-ingest (keyed by `fingerprint`):
```bash
curl -s -X POST "$BASE/api/finding/state" -H 'Content-Type: application/json' -d '{
  "target":"<target>",
  "fingerprint":"<fp>",
  "verdict":"confirmed",                  // see vocab below
  "starred": true,                        // star the genuinely important ones
  "notes":"Live GET 200 returns real user records unauthenticated; chained from js/api_endpoints.txt. Checked 2026-10-19."
}'
```
**Verdict vocab** — use only these values (they match the dashboard dropdown exactly):
`new`, `reviewing`, `interesting`, `confirmed`, `reported`, `false_positive`, `wont_fix`.
Map your outcomes to them: live-verified ⇒ `confirmed`; promising but unverified ⇒
`interesting`; couldn't safely verify / needs a human ⇒ `reviewing`; killed noise ⇒
`false_positive` (or `wont_fix`). Do **not** invent other verdict strings — the UI shows a
fixed set and would silently drop an unknown one. `confirmed` here is the human/skill
live-verification verdict in `finding_state`; it does **not** change the finding's `tier`
(the `confirmed` tier firewall in `db.py` still requires an active-verification artifact).

Your verdicts **re-rank the Hunt Queue** (server-side, `db.score_assets`): a `confirmed`
finding boosts its asset and pins it to HIGH priority, and `false_positive`/`wont_fix` findings
are excluded from the asset score so noise sinks. So verdicts are not just labels — use them
deliberately: `confirmed` floats verified work to the top for the human; dismissals declutter
the queue. (This does not change the finding's `tier` or any `severity` — only display rank.)

Rules for write-back: **star** the short list of real findings; mark obvious noise
`false_positive` with a one-line reason; leave `severity` untouched (NULL). Never set a
field you didn't actually determine. If the server is down, write the same verdict/notes via
`db.set_finding_state(fingerprint, verdict=, starred=, notes=)` through `db.py`, or skip
write-back and say so in the report.

**Standalone report:** write `<projects_dir>/<target>/reports/triage_report.md` (and optionally
a `.json` alongside). Structure:
- **Preflight** — the one-line block from Phase 0 (tools, data source, write test, warnings),
  so anyone reading the report can see at a glance whether the run was degraded.
- **Top findings** — ranked, each with: asset, the chain/story in one line, the live evidence
  you gathered (status, body snippet, what you tested), your confidence, and the `fingerprint`
  so it's traceable back to the DB/dashboard.
- **Dismissed** — what you killed and why (so the human doesn't re-chase it).
- **Needs a human** — things you couldn't safely verify (out of scope, needs auth, risky to
  probe) with the exact next step.
- **Coverage note** — what you checked, what you skipped, and any rate-limit/back-off you hit.

Keep the report short and scannable — the whole point is *narrowing down*. A handful of
high-confidence items beats an exhaustive dump.

## Finishing

Report to the user in chat: the count triaged, how many you starred as important, the top 3–5
one-liners, and the report path. Note anything that needs their decision (scope gaps, auth,
risky probes you declined to run).
