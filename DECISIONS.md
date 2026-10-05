# Decisions

Jake approved all six stages/defaults on October 5, 2026. These decisions describe the implemented learning workbench; verification and remaining limits are recorded separately.

| ID | Decision | Reason / tradeoff |
|---|---|---|
| D01 | Thin Python orchestration; adopt parsers/backend | Makes evidence, usability and security the portfolio contribution; avoids expensive custom decompiler/parser work. |
| D02 | pefile + pyelftools initially | Inspectable specialized adapters; two models to normalize. LIEF stays an alternative if fixture gaps justify change. |
| D03 | Ghidra official 12.1.4 + release-supported JDK 21 | Real RE integration verified on all four targets; publisher archive hashes locked. Larger footprint and native child-process supervision required. |
| D04 | Optional explicit local YARA-X rules, no score | Transparent findings and reproducible matches; engine/rules absent remain unavailable checks. |
| D05 | Windows 11 x64 first host | Verified environment family; focus on enforceable Windows controls. Upstream portability does not confer tested product support. |
| D06 | Nonsynchronized local private storage | Parent workspace is OneDrive-backed; sample/evidence confidentiality requires separate runtime storage. |
| D07 | No dynamic analysis, sample execution or automatic network activity | Honors requested scope and keeps evidence reproducible; packing and behavior remain uncertain. |
| D08 | Real decompiler feasibility check early | Prevents a metadata-only build from being mistaken for completed scope; full RE still stage 4. |
| D09 | MIT original code with component notices | Approved default; original fixtures/rules/code and third-party integration notices included. |
| D10 | Direct JVM launch and mandatory Windows Job Objects | Avoids batch interpolation; suspended assignment, memory/process limits and descendant cleanup tested. Resource containment is not malware isolation. |
| D11 | Disable rule includes rather than establish an include tree | Smaller file-read boundary; users supply one reviewed local rule file. Rule hash and engine provenance retained. |
| D12 | Preserve unknown mappings; precompute unique spans | Overlap/zero-fill and non-RAM spaces remain unknown. Indexed controller joins avoid worker caps being undermined by expensive normalization. |
| D13 | Self-contained escaped HTML with fixed script/style CSP hashes | Offline search and evidence navigation without dependencies or sample-generated executable markup. Browser automation file URLs unavailable; tested on loopback then disconnected network. |
| D14 | Keep original proposed caps | 16 MiB JSON, 24 MiB HTML, 256 MiB sampled worker disk, 15-second signatures and maximum 180-second RE. Overshoot/OS isolation gaps remain explicit. |
| D15 | Keep publication separate | Local immutable-action CI/security scaffolding prepared; GitHub eligibility/protections/checks await an explicitly authorized repository/publication step. |
