# Verification record — October 5, 2026

This records actual local results on Windows x64/CPython 3.13.7. No submitted fixture/sample was executed. No live malware, public release, repository push, GitHub-hosted job or independent security audit was performed.

## Material checks

Commands below ran from the project root using private nonsynchronized fixture/test directories (represented as `$fixtures`, `$variants`, `$tests`). Exact runtime paths remain private; the CLI prints the resolved paths for local use.

| Phase / command | Result | Evidence |
|---|---|---|
| `scripts/build_fixtures.py $fixtures` | PASS / exit 0 | Four Zig 0.14.1 cross-target fixture hashes/build commands; never executed |
| `scripts/build_variants.py $variants` | PASS / exit 0 | PE imports/resources, ELF dynamic dependency/PIE/stripped, optimized PE |
| `scripts/verify_integration.py $fixtures` | PASS / exit 0 | All four targets, real Ghidra 12.1.4, schema-valid reports, unchanged input, independently decoded headers/entry values, hashes/marker offsets/rule offsets, instruction byte comparisons, CFGs, string-reference joins and pseudocode |
| Representative branch semantics checked in recorded output | PASS | All four pseudocode bodies contain the fixture's +7 and −3 paths; instruction bytes/CFGs independently checked |
| `scripts/verify_failure_paths.py $fixtures $variants` | PASS / exit 0 | Real missing/failed/one-second Ghidra deadline, stripped inferred-name recovery, optimized pseudocode, import-reference join, name/address inspection |
| `scripts/verify_signature_limits.py` | PASS / exit 0 | Synthetic harmless bytes: outer worker timeout and actual native scan deadline both enforced |
| `scripts/verify_reproducibility.py $fixtures` | PASS / exit 0 | Same-version report semantic equality excluding only `metadata.generated_at` |
| `WB_VARIANTS=$variants; python -m pytest -q --basetemp $tests` | PASS / exit 0 | 31 passed, 1 skipped; symlink creation privilege unavailable; native junction rejection separately passed |
| `python -m bandit -r src -f json -o .tools/bandit-final.json` (installed 1.9.4) | PASS / exit 0 | No findings after reviewed narrow subprocess-import annotation |
| Source-tree `doctor`, `functions`, `inspect` by name/address | PASS | Actual CLI returned dependency inventory, three functions and real selected details; absent detail gives code 5 |
| Playwright CLI isolated Edge `run-code --filename=scripts/browser_check.js` | PASS | Search 150→2 visible items, negative search zero, function/string links, inert HTML payload, zero external requests/page errors/dialogs; interaction while browser context offline |
| `python -m compileall -q src scripts tests` | PASS / exit 0 | All current Python source/helpers/tests compile |
| `.venv/Scripts/python.exe scripts/verify_project.py` | PASS / exit 0 | JSON/schema/workflow syntax and immutable pins; 78 prospective files, zero matches in focused credential/private-path patterns; no exhaustive secret-scan claim |
| Dedicated lint/type checker | NOT RUN | No project-configured installed checker found; runtime/property/schema tests and manual review used. No checker installed just for a completion label |
| GitHub CodeQL/Bandit/protections/alerts | NOT RUN | Local immutable-action workflows prepared; repository publication/control changes not authorized; live eligibility cannot be assessed before repository exists |
| Cross-host/version compatibility; comprehensive fuzzing | NOT RUN | No Linux/macOS/ARM/non-BMP-wide or cross-Ghidra-version compatibility claim |

## Fixture RE results

| Fixture | Functions / selected | Retained instructions | String/import evidence joins | Local demo matches |
|---|---:|---:|---:|---:|
| PE64 | 3 / 3 | 44 | 3 | 1 |
| PE32 | 3 / 3 | 42 | 6 | 1 |
| ELF64 | 3 / 3 | 40 | 2 | 1 |
| ELF32 | 3 / 3 | 42 | 6 | 1 |

The public [aggregate verification](../examples/benign-pe64/verification.json) preserves the fixture hashes, counts and never-executed assertion. Private runs retain raw Ghidra output and diagnostics. These are small source-built fixtures, not a malware-detection accuracy evaluation. Independent expectations use the original fixture bytes/source and fixed documented header layouts; no claim of a broad external-tool corpus comparison is made.

Evidence selection: the ignored `.tools/integration-summary.json` is an earlier development run with zero reference joins, preserved as historical evidence. Use the public aggregate above for final fixture hashes/counts (joins 3/6/2/6); `.tools/final-evidence.json` points local reviewers to the matching final private integration, failure and repeat receipts. No analyses or samples were rerun to create that pointer.

## Behavioral coverage

Tests cover locked original/snapshot denial of writes, Unicode paths, canonical AppData resolution, exclusive reports, ADS/synced-root rejection; supervisor normal/nonzero exits, deadline and descendant cleanup, diagnostic/watched-output/disk caps, committed-memory/process limits, and mandatory job-setup failure before execution. The symlink/reparse test is present but skipped on this account because symlink creation lacks permission. A separate harmless native directory-junction check passed. Path rejection logic was reviewed; the skipped symlink-specific OS test is not a pass.

Static tests cover known entropy, ASCII/BMP-wide offsets at both alignments, IPv4/IPv6/URL candidates, string caps, ambiguous/zero-fill mappings, two property campaigns (100 arbitrary inputs ≤4 KiB and 60 deterministic malformed PE/ELF-prefix inputs ≤4 KiB), and source-built format variants. Certificate file-offset handling, trailing data, managed/unsupported PE markers, truncated headers, oversized COFF tables, dynamic ELF dependencies, stripped/sectionless/PIE behavior are exercised. This is a bounded regression/property campaign, not exhaustive fuzzing.

Triage tests cover positive/negative high-entropy/RWX/import combinations, stable explained findings, local positive/negative rule offsets, disabled includes and explicit per-pattern truncation. Rendering tests cover inert HTML/control-character payloads, bundled assets/CSP, schema/version handling and cap/no-overwrite behavior. Browser tests loaded only the reviewed benign example through a loopback server because the installed CLI blocks file URLs. The test browser and server were stopped afterward. Direct file-protocol launch remains unverified by automation.

## ECC self-review

The implementing agent used the installed ECC code-review entry point and pinned reviewer reference, read actual task source/callers/tests (including untracked files) and reviewed collection, Job Objects, parser normalization, Ghidra scripts, controller joins, rule matching, HTML/CLI, setup helpers, schema and workflows. No independence is claimed.

Concrete fixes made during review/testing:

- `safeio.local_path/locked_file`: packaged AppData redirection caused a legitimate input to fail the handle-path check. Canonicalization occurs after reparse rejection, and physical paths are rechecked. Runtime DACL installation now occurs atomically at directory creation.
- `supervisor.run_worker`: explicit inherited-handle list replaces broad inheritance; unexpected wait results fail; descendants are killed and zero active job processes verified; watched-output caps are checked after exit too.
- `static.parse_pe`: a 256-byte truncated fixture could be reported complete because the upstream parser tolerated it. Declared header/table sizes and available section counts now produce partial status; oversized COFF tables are bounded.
- `WorkbenchPolicy`: singular `Reference` and required pointer/string analyzer options were missing, so string joins failed. Actual analyzer names were inspected and tested on all four targets; PDB/external analyzers remain disabled.
- `backend.join_evidence`: per-reference scans of all strings/imports/regions could make the unsupervised controller expensive. Precomputed unique mapping spans, binary search and import indexing bound that work. Backend object/address/byte/provenance shapes are validated before joining.
- `worker.signatures`: reaching native per-pattern caps was previously silent. Possible truncation is now explicit; rule-only matches preserve null locations.
- `cli.inspect`: min/max function endpoints could include gaps. Address inspection now matches actual retained instruction ranges.

Current result: ready for Jake's review within the documented learning/lab scope. Remaining risks are the external VM/network/disk boundaries, same-user compromise, parser/native engine vulnerabilities, limited corpus/host coverage, missing symlink privilege test and unrun GitHub controls. No merge/deployment/publication is implied.

## CI preparation

Checkout/setup-python/CodeQL action SHAs were resolved through connected GitHub and publisher source; exact commits are pinned with release comments, checkout credentials are not persisted, and permissions are minimal. Python Bandit and Windows tests run on main pushes/PRs/manual dispatch. CodeQL covers Python and Java with no-build analysis on pushes/PRs, weekly schedule and manual dispatch. Java's external Ghidra APIs can limit no-build precision. Dependency update scaffolding is prepared. Before a future authorized publication, inspect actual visibility/default branch, licensing eligibility, protections, secret scanning/push protection and passing checks. Do not weaken or assume existing protections.



