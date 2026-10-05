# Security policy

This learning workbench statically parses PE/ELF data and invokes trusted analysis tools. It never intentionally executes, emulates, debugs, or dynamically loads submitted binaries. Treat every sample, rule file, extracted value and backend output as untrusted data.

Use a disposable, offline Windows VM for genuinely hostile inputs. Job Objects constrain worker resources and lifetime; they do not restrict worker filesystem access, network access, token privileges or exploitation of parser vulnerabilities. A virtual environment is dependency separation, not malware isolation.

Only version 0.1.x is currently maintained. Report a suspected vulnerability through a repository's private vulnerability-reporting feature when one is available; otherwise arrange a private reporting channel with the maintainer before sending sample contents. No public GitHub repository or reporting endpoint has been created by this task. Never post credentials, live samples or private analysis reports in public issues.

Mandatory controls: explicit trusted executables, no shell launcher, suspended-start job assignment, deny-write/delete input snapshots, local regular-file paths, reparse-point rejection, private DACL at directory creation, exclusive report creation and output bounds. Required setup failures stop analysis; no uncontained fallback is attempted.

The runtime has no telemetry, upload, automatic signature download or indicator lookup feature. Ghidra analyzers are allowlisted; PDB/external-symbol import is disabled. Java external XML DTD/schema access is disabled. OS network isolation remains an external VM/firewall requirement. Host/user-controlled tools and same-user compromise are outside the application boundary.

Do not place normal runtime samples/reports in this repository or OneDrive. Use the default private LocalAppData run directory, protect backups, and review any export before sharing. Other sync products cannot be discovered reliably; explicitly select nonsynchronized local storage. Compiler fixture outputs also stay outside the development workspace.

See [docs/security-model.md](docs/security-model.md) for limits, enforcement gaps and manual review requirements. Merges, deployment, live malware acquisition and publication require separate authorization.
