# Acceptance tasks

Status: all six stages/defaults approved by Jake on October 5, 2026 ("okay, begin"). Publication and merges remain separate.
Each task should remain a focused change; split any slice that exceeds roughly five implementation files. Tests and documentation accompany the relevant slice.

## Stage 1 — research and authorization

- [x] T01: Inspect relevant context and public candidates; record sources, licenses, source/CI/test evidence, caveats and worker outcome. Verified by research.md and private evidence record. Dependency: none.
- [x] T02: Present architecture, threat model, matrix, limits and stage acceptance criteria. Verification: plan completeness review; product behavior unverified. Dependency: T01.
- [x] T03: Record Jake's exact approved stages/defaults. Verification: "okay, begin" approved the presented six-stage plan/defaults. Dependency: T02.

## Stage 2 — secure PE slice

- [x] T04: Review and lock tools/artifacts; create project environment and benign fixture toolchain. Acceptance: canonical identities/hashes/notices recorded; no sample download or execution; tool inventory documented. Verification: version/artifact checks. Dependency: T03.
- [x] T05: Prove Windows supervisor and direct trusted JVM launch using benign children and one included fixture. Acceptance: suspended-start job assignment, memory/process caps, deadline/tree cleanup; real selected-function pseudocode returned. Verification: kill/hang/grandchild tests plus recorded Ghidra output. Dependency: T04. This is an early feasibility gate, not completed RE integration.
- [x] T06: Implement controlled collection and output ownership. Acceptance: same hashed immutable snapshot across workers; changing/nonregular/reparse input rejected; exclusive output commit. Verification: file-race, path/Unicode and no-overwrite tests. Dependency: T05.
- [x] T07: Define model/CLI/status conventions and common extraction. Acceptance: typed locations/provenance; capped strings/entropy/indicators; escaped CLI and explicit truncation. Verification: handcrafted byte/hash/encoding and injection expectations. Dependency: T06.
- [x] T08: Implement full PE adapter. Acceptance: planned directories/sections/symbol availability/resources/certificates/trailing data; validated address/entry mappings; malformed evidence preserved. Verification: native x86/x64 fixture expectations and truncated/overlapping/managed cases. Dependency: T07.

Checkpoint: PE CLI useful; mandatory collection/process limits verified; no speculative safety or RE completion claim.

## Stage 3 — ELF and exports

- [x] T09: Implement ELF adapter. Acceptance: segments/sections/dependencies/symbols/entry; PIE/zero-fill/stripped/sectionless handling; bounded failures. Verification: ELF32/64 independent header/symbol/mapping comparisons. Dependency: T08.
- [x] T10: Export versioned JSON/schema and reproducibility metadata. Acceptance: diagnostic/partial reports validate; stable content separated from timestamps; cap/exit semantics documented. Verification: schema compatibility and repeated normalized runs. Dependency: T09.
- [x] T11: Export searchable offline HTML. Acceptance: all evidence text inert; bundled assets and limits; private paths excluded by default. Verification: real-browser offline search/navigation, HTML/terminal payloads and no network requests. Dependency: T10.

Checkpoint: four static fixture targets and usable safe reports; failures/skips represented faithfully.

## Stage 4 — complete reverse engineering

- [x] T12: Expand adapter to functions, instructions, cross-references and CFG. Acceptance: typed address joins; recovered/inferred names and boundaries distinguished; selection by function/address. Verification: known bytes/calls/branches/string/import references. Dependency: T11 and T05.
- [x] T13: Integrate bounded selected-function pseudocode and investigation/export flow. Acceptance: real backend on all four fixture targets; stripped/optimized partial states; backend/settings/hash provenance. Verification: semantic representative output expectations, CLI inspect and report links, never identical-text requirement. Dependency: T12.
- [x] T14: Exercise missing/failing/timeout backends and process cleanup. Acceptance: static core available; requested RE partial/unavailable explicit; no worker descendants or blocking pipes after cleanup. Verification: benign mock/failing child process scenarios and actual Ghidra deadline test. Dependency: T13.

Checkpoint: working tested disassembly AND decompilation; no release if either requirement remains a stub.

## Stage 5 — triage

- [x] T15: Add transparent heuristics. Acceptance: stable IDs, evidence/location, priority and uncertainty per finding; observed versus interpreted separated; no verdict/probability. Verification: positive and benign negative fixtures, compressed resource/certificate/import cases. Dependency: T14.
- [x] T16: Add optional local signature worker and original harmless demo rules. Acceptance: explicit rules only, bounded trusted include root, rule/pattern provenance; absent engine unavailable. Verification: match offsets, negative/header regression and compile/scan timeout tests. Dependency: T15.

Checkpoint: full three-capability benign walkthrough available with explained uncertainty.

## Stage 6 — hardening and demonstration

- [x] T17: Run targeted property/fuzz and limits/path/render review. Acceptance: bounded campaigns recorded; meaningful failures fixed; enforcement gaps disclosed. Verification: documented seeds/budgets, process/memory/output overflow cases and affected regressions. Dependency: T16.
- [x] T18: Complete README/setup/security/architecture/schema/matrix/troubleshooting/notices/AI disclosure and reviewed demo exports. Acceptance: from-source benign rebuild plus all-three analysis recorded; example JSON/HTML useful; no private material in prospective tracked files. Verification: reproduce documented commands and inspect exports/secret-scan results. Dependency: T17.
- [x] T19: Prepare security baseline configuration locally; apply owned-repository controls when creation/completion is authorized. Acceptance: immutable actions, least permissions, eligible SAST, no weakened protections; report unavailable controls. Verification: local CI review plus real checks when GitHub authorization exists. Dependency: T18; external publication requires explicit authorization.

Final checkpoint: all authorized acceptance criteria pass; exact failures/unsupported cases documented; Jake reviews consequential untrusted-input boundaries before any separately authorized merge/deployment.

## Verified closure and limits

T04-T18 are complete within the documented tested Windows learning/lab scope. T06/T17 include a skipped symlink-permission test; a separate native directory-junction rejection check passed. Bounded campaigns and residual isolation/coverage limits are recorded in docs/verification.md. T19 is complete only for local prepared scaffolding: actual GitHub eligibility/protections/hosted checks require a separately authorized repository/publication step. No remote control is claimed enabled.

