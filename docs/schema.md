# JSON contract and reproducibility

Reports use `schema_version: "1.0.0"`. The authoritative JSON Schema (Draft 2020-12) is [report-1.0.0.json](../schema/report-1.0.0.json). Runtime uses standard-library identity/shape checks; development/integration tests validate complete reports against the schema. A different schema version is rejected by CLI import/export.

Top-level objects:

| Field | Meaning |
|---|---|
| `tool` | Workbench name/version |
| `status` | Aggregate requested-analysis state |
| `metadata` | Variable generation time plus actual host/Python information |
| `sample` | SHA-256 of copied immutable bytes and size; no original path/name |
| `static` | Format/parser version, headers, architecture, entropy, sections/segments/regions, symbols/imports/exports/dependencies/resources/certificates/overlay, strings and candidate indicators |
| `reverse_engineering` | Explicit state; Ghidra version/language/hash, analyzer booleans, script/tool hashes, limits, function index and selected detail |
| `signatures` | Explicit state, engine/version, local rule-set SHA-256, disabled includes, pattern evidence and cap flags |
| `findings` | Heuristic interpretation, stable ID, priority, explanation, supporting IDs/locations and uncertainty |
| `limits` / `warnings` | Actual configured bounds, enforcement gaps, incomplete/truncated evidence |

File offsets/sizes are nonnegative integers; malformed declared sizes may exceed input length and carry invalid-range state. VAs/RVAs are hex strings, preserving integers beyond JavaScript's exact-number range. Computed malformed addresses can exceed the declared width, carry warnings/invalid mappings, and are not passed to RE. Ghidra locations are `{ "space": "ram", "value": "0x140001030" }`; `stack`, `EXTERNAL` and other spaces are retained and never silently interpreted as file offsets. Null mappings are unknown, including overlap or zero-fill. Section `offset` means raw file offset; `va` is the linked image VA and `rva`, when present, is relative to the PE image base. PIE values are static linked coordinates, not a known runtime base.

Strings carry ID, text, encoding, file offset, retained byte length and per-run truncation. UTF-16LE additional BMP Unicode extraction tracks both alignments and byte offsets independently of decoded character indices. `strings_truncated`/`indicators_truncated` and warnings disclose caps. Candidate indicators link to source strings and their exact retained byte ranges.

Functions carry entry/end addresses, possible file offset, `name_source` and `boundary_source: "ghidra_analysis"`. `IMPORTED` names are recovered from symbols/exports; `DEFAULT` names are inferred. Endpoints do not guarantee a contiguous body. CLI address inspection matches actual retained instruction ranges. Selected detail contains instruction bytes/text, outgoing references, incoming references (`callers` can include non-call references; check type), block ranges/edges, pseudocode and decompilation state/error. A reference's `evidence_ids` joins known string/import evidence; unknown targets remain present without a fabricated join.

Signature matches include rule/pattern identifier and byte offset/length. Rule-only conditions can have null pattern/location. `rules_sha256` identifies exact local rule bytes; include directives are disabled and there is one explicit input namespace. `pattern_cap_reached` means 100 matches/pattern were returned, so further matches may have been suppressed; aggregate analysis is partial in that case. Rules are evidence sources, not authoritative malware labels.

Finding identifiers hash the rule kind and stable supporting evidence IDs. `classification: "heuristic_interpretation"` distinguishes them from observed static data. Locations can be unknown. Findings have no score/probability/verdict; no findings remains inconclusive. A cap of 10,000 findings is explicit in warnings.

For reproducibility, compare reports after removing `metadata.generated_at`; compare semantic objects rather than JSON key order. Fixed sample/rule hashes, backend/parser versions, actual analyzer settings and script/launcher hashes identify analysis inputs. Tool versions, PE build timestamps, inferred names, decompiler output, truncation/timeouts and upstream behavior can change results. No cross-version pseudocode identity or byte-identical fixture rebuild claim is made. JSON and HTML contain private sample evidence even though source paths are omitted; do not publish normal reports automatically.

