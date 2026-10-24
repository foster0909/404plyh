# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

404Plyh is a modular reconnaissance / monitoring / triage framework for **authorized** bug-bounty and attack-surface research. It chains external recon tools into a pipeline, stores results as predictable files on disk, ingests them into per-target SQLite, and exposes everything through a browser triage dashboard. See `README.md` for the full feature-by-feature narrative.

The codebase has three largely independent halves that meet at the on-disk output layout:
1. **Bash recon pipeline** (`recon_engine.sh` + `modules/`) — produces the files.
2. **Python dashboard + DB** (`dashboard.py`, `db.py`, `dashboard.html`, `dashboard.js`) — reads/serves those files and ingests them into SQLite.
3. **Bash monitors** (`monitor.sh`, `monitor_all.sh`) — lightweight recurring diffing against baselines.

## Commands

```bash
# Run a full scan (output defaults to recon_<domain>/)
./recon_engine.sh -d example.com
./recon_engine.sh -d example.com -o ~/recon/example.com -t 25 --rate 100
./recon_engine.sh -d example.com --skip-screenshots --skip-ports --skip-dorks
./recon_engine.sh --check-deps        # verify external tools are installed

# Dashboard (point -p at a directory containing one subdir per target)
python3 dashboard.py -p ~/recon-projects
python3 dashboard.py -p ~/recon-projects -P 8888 --bind 127.0.0.1

# Monitoring (designed for cron)
./monitor.sh -d example.com --init    # create baseline first
./monitor.sh -d example.com           # subsequent runs: diff vs baseline
./monitor_all.sh ~/recon-projects     # run monitor for every enabled target
```

### Testing after changes

There is no build step and no package manager. Run these checks after any significant change:

```bash
# Bash integration test (synthetic data, no network needed) — the main test suite
bash tests/test_monitor.sh

# Pipeline resource controls (stub tools: screenshot batching, port stage)
bash tests/test_pipeline.sh

# Dashboard server: paged data APIs, Hunt Queue summaries, gzip/ETag, traversal
python3 tests/test_dashboard.py

# Python syntax / import sanity (no third-party deps required)
python3 -m py_compile dashboard.py db.py
python3 -c "import db, dashboard"     # catches import-time errors

# Shell syntax for every pipeline file
bash -n recon_engine.sh monitor.sh monitor_all.sh modules/*.sh

# Frontend syntax (Node is available in this environment)
node --check dashboard.js
```

Run the checks relevant to the files you touched; run **all** of them before declaring a multi-file change done. If you add Python or JS logic worth testing, add a test next to `tests/test_monitor.sh` rather than leaving it uncovered.

## Architecture

### Recon pipeline
- `recon_engine.sh` is the orchestrator: it sources every file in `modules/` once, parses CLI flags into globals, then `main()` calls each stage function in fixed order (`module_subdomain_discovery` → `module_dns_resolution` → `module_http_probing` → … → `module_report`).
- **Each module is a sourced file exposing one `module_*` function**, not a standalone script. Modules communicate only through files under `$OUTPUT_DIR/<section>/` — there is no in-memory data passing. Adding a stage means: add `modules/foo.sh`, `source` it in `recon_engine.sh`, add a `SKIP_FOO` flag in `config.sh`, wire the flag in `parse_args()`, and call it from `main()`.
- `modules/config.sh` owns all defaults, colors, logging (`log`, `success`, etc.), and every `SKIP_*` flag. All tunables use `${VAR:-default}` so they can be overridden by env var **or** by `.env` (loaded at startup from the repo root) **or** by CLI flag.
- `modules/utils.sh` provides `run_safe`, `require_tool`, `require_py_tool`, `normalize_hosts`, `merge_dedup`, `create_directories`.
- **Optional-tool resilience is a core design rule**: a missing external tool logs a warning and skips its stage; the pipeline continues. Documented fallbacks (README "Implementation Notes"): no `puredns` → raw subs copied to `dns/resolved.txt`; no Naabu host list → Nmap scans only first 50 hosts; WHOIS enrichment caps at 20 IPs.
- JS analysis is **recursive**: `module_js_deep` can discover new hostnames, and `handle_recursion()` re-runs DNS/HTTP/JS up to `RECURSIVE_ROUNDS` times.
- Python helpers invoked *by* shell modules: `modules/js_scanner.py` (static JS analysis) and `modules/sourcemap_extractor.py` (source-map reconstruction). `PATH` is extended at the top of `recon_engine.sh` to find Go/cargo/local tool binaries.
- `modules/monitor.sh` holds `monitor_diff` (used by `monitor.sh` and by the test), which writes `monitor/changes/*.json` and sets `MONITOR_CHANGE_FILE` / `MONITOR_TOTAL_CHANGES`.

### Dashboard + DB
- `dashboard.py` is a single-file stdlib `http.server` with a hand-rolled router in `do_GET`/`do_POST` (see README "Dashboard API" for the endpoint list). It serves `dashboard.html` / `dashboard.js` and exposes JSON/text APIs over the on-disk output of each target.
  - `ScanManager` runs recon/monitor subprocesses for multiple targets concurrently (one run per target, bounded by `max_concurrent` / `MAX_CONCURRENT_SCANS`, default 3), each in its own process group. It keys runs by target, tracks each run's `kind` ('scan' | 'monitor'), retains finished runs in-session for the Explorer tracker, and ingests full scans into SQLite from each run's process-watcher thread on exit. `PIPELINE_STAGES` is the canonical ordered stage list (keys match recon_engine's `stage()`/`timing.jsonl`), used by `list_runs()` and `progress()` to drive the UI tracker.
  - `StatsCache` memoizes `build_stats` per target, keyed on a cheap shallow mtime signature, so `/api/targets` does not walk the whole tree on every request.
  - `HistoricalIndex` categorizes `historical/all_urls.txt` in memory (bounded LRU cache). It is the single serving path for historical URLs — it needs no DB ingest, so the view works immediately after a scan.
  - `ScopeEngine` persists per-target scope rules and does in/out-of-scope hostname checks (fnmatch + CIDR).
- **One SQLite DB per target** (`<target>/recon.db`), not a global DB. `db.py` (`ReconDB`) defines the schema and `ingest_scan(target_dir)` parses the on-disk recon files into tables. Ingest is **idempotent**: re-ingesting the same scan (same stable timestamp key) replaces that scan's rows rather than creating duplicates. `categorize_url()` in `db.py` is the single source of truth for URL categorization, shared with the dashboard's `HistoricalIndex`.
- SQLite is read for Diff (`/api/diff`) and the scan list (`/api/scans`). Diffing uses SQL `EXCEPT` across `scan_id`s.
- **Unified finding model** (`findings` + `finding_state` tables). `normalize_findings(target_dir, scan_id)` runs inside `ingest_scan` and translates the on-disk output of all sources (http/ports/js/dorks/historical/crawl/monitor) into one normalized signal per row. Each finding carries three independent axes that must stay separate:
  - `tier` = `observation | suspicious | confirmed` — confidence the signal is **real & live**, *not* a severity or vulnerability claim. **Firewall:** a heuristic/regex/keyword match may produce at most `suspicious`; `confirmed` comes only from active-verification artifacts (`dorks/active_confirmed.txt`, live-validated `historical/validated_interesting.json`).
  - `score` = attention-priority for ranking (**not** severity), with an explainable `score_detail` breakdown.
  - human state (`verdict`/`severity`/`notes`/`starred`) lives in `finding_state`, keyed by `fingerprint` so it **survives re-ingest and rescans**. `severity` is NULL unless a human sets it — the pipeline never labels a recon signal a vulnerability. Do not change this.
  - Served via `GET /api/findings` (tiered, score-ranked, filterable by tier/type/asset/source) and `POST /api/finding/state`. Constants (`ADMIN_TECH`, tier weights, type scores, regexes) live in `db.py` as the single source of truth — mirror there, not in the client.
- **Security-critical code to preserve**: `resolve_target_path` enforces path-traversal containment (keep requests inside the selected target dir); `ScopeEngine.is_in_scope` gates scan starts. Do not loosen either.
- The **Hunt Queue + Asset Dossier are driven by the server finding model** (`loadFindings()` → `/api/findings/assets` per-asset summaries via `db.get_asset_summaries`; the dossier fetches `/api/findings?asset=` on open, grouped by tier with per-finding verdict/severity controls). The legacy client-side scorer `compileHuntQueue()` remains **only as a fallback** when the server returns no findings; new signal/scoring logic belongs in `db.py`'s normalizer, not the client.

### Frontend
- `dashboard.html` is one page: a large inline `<style>` block (theme via CSS custom properties) plus the markup; `dashboard.js` is a single IIFE that owns all behavior. No framework, no bundler — keep it that way unless there is a clear, stated reason.
- Section loaders are **server-paged**: `makeServerTable` (table over `/api/data/table` etc.) and `renderServerList` (one-column list over `/api/data/list`). The browser never downloads whole result files — large scopes crashed mobile browsers. Reuse these rather than fetching `/api/file/...` and parsing client-side; raw views use `fetchTextHead` (`?max=` / `?tail=`).
- The Hunt Queue loads one summary row per asset from `/api/findings/assets` (cached server-side, invalidated on verdict change / ingest) and fetches an asset's full findings only when its dossier opens; the list renders in chunks (`TRIAGE_RENDER_STEP`).
- Triage star/ignore state is persisted **server-side** per target via `/api/triage`; `localStorage` is only a fallback cache.
- User-facing failures surface through `toast()` — do not swallow errors silently.

## On-disk contract (the real API between components)

The per-target directory layout is the shared contract: shell modules *write* specific filenames, and `db.py` / `dashboard.py` *read* those exact paths. Changing an output filename or directory in a module will silently break ingestion and the dashboard unless the Python readers are updated to match. The full tree is documented in README "Output Structure" (`subs/`, `dns/`, `httpx/`, `ports/`, `js/`, `historical/`, `endpoints/`, `dorks/`, `infra/`, `monitor/`, `reports/`, `recon.db`).

## Coding conventions

- **Bash**: `set -uo pipefail`; functions are `lower_snake_case`; modules expose `module_*`; always gate external tools with `require_tool`/`require_py_tool` and skip (warn) rather than abort when missing; emit user output through the logging helpers in `config.sh`, not raw `echo` with colors.
- **Python**: standard library only (see dependency rule below); 4-space indent; per-request DB connections closed in a `finally`/after use; keep handler methods small and route in `do_GET`/`do_POST`. Thread-safety matters — the server is threaded, so guard shared mutable state with locks.
- **JavaScript**: one IIFE, no globals except the intentional `window.*` handlers wired from inline `on*` attributes; escape **all** interpolated data with `esc()` before putting it in HTML; prefer the existing table/list helpers.
- **Filenames and output paths are API.** Treat any change to the on-disk layout as a breaking change that must be updated on both the writer (module) and reader (Python) sides in the same change.

## Working agreement (follow these when changing this repo)

- **Preserve existing functionality.** Every feature that works today must still work after your change. If a change would alter observable behavior, call it out explicitly.
- **Make small, incremental changes.** Prefer a sequence of focused, verifiable edits over a large rewrite. Keep each change reviewable.
- **Run the relevant tests/checks after any significant change** (see "Testing after changes"). Do not report work as done without having run them.
- **Never silently remove a feature.** If something must be removed or replaced, say so clearly and explain why; do not drop capabilities as a side effect of a refactor.
- **Never weaken scope controls or rate limiting.** `ScopeEngine`, the `--rate`/`THREADS` defaults, `rate_guard.sh`, and the conservative tool settings are safety features. Do not remove, bypass, or raise them without an explicit request, and never as a convenience.
- **Prefer the Python standard library.** Do not add a third-party Python/JS dependency or a build step unless the need is clearly justified and stated; the zero-dependency, run-from-clone property is a design goal.
- **Keep the frontend lightweight and responsive.** No SPA framework or bundler by default; keep the single-file HTML + IIFE structure, avoid blocking the UI, and preserve mobile behavior.
- **Explain architectural changes before implementing them.** For anything that changes data flow, the on-disk contract, the schema, the request model, or a module's public shape, describe the approach first, then implement.

## Gotchas

- Conservative defaults (`THREADS=15`, `RATE_LIMIT=150`) are intentional to avoid WAF/rate-limit bans — keep new tooling rate-aware; `modules/rate_guard.sh` provides CPU-aware throttling.
- `.env` holds API keys for external tools and is treated as secret — never commit it.
- This is authorized-use security tooling. Keep scope controls, rate limiting, and traversal checks intact when editing; they are safety features, not incidental.
