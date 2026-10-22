# Synthetic tokenizer studies

The JSON corpora, expected reports and archive contract are frozen synthetic
fixtures used by the benchmark regression tests. They include historical command
help and output envelopes. Archived reports do not describe current CLI parity.
Integrity hashes bind those synthetic fixture bytes, not household configuration.

Measurements compare selected task transcript token counts for a named tokenizer.
They do not prove browser savings, API billing savings, task success, network
quality or equivalent clinical/operational outcomes. Retain the same workload,
fields, failures and provenance when interpreting a comparison.

Benchmark modules are development helpers run from a checkout with the `dev`
dependency group. Their repository-relative corpora are not wheel runtime assets.

## Public metadata adaptation

`corpus-validation-v2.json` and `results-validation-v2.json` were regenerated
with the existing `benchmark_validation.build_corpus()` and `run()` functions
against this export's sanitized capability metadata. They represent this public
CLI replay; the private-era v2 bytes are not claimed unchanged. Historical v1
and registered archive fixtures remain unchanged. No runtime code, operation
catalog, tests, required-answer checks or scoring rules were changed.

The public v2 corpus SHA-256 is
`2e9606b402ffe90966cc98bf403965237143e7aed169f41f7583922dde3d295e`.
With tiktoken 0.14.0 and `o200k_base`, small versus bounded-large capability
pages total 18,996 versus 16,692 training tokens (12.13% reduction), and 12,449
versus 12,337 held-out tokens (0.90% reduction). The held-out gate passes.
These counts apply only to the stated synthetic transcripts and tokenizer proxy.

The 2026-10-22 successor corpora retain current selected-read fields and discovery
help costs. Superseded public corpus/report bytes remain immutable and are
registered by exact public hashes in `history-2026-10-22.json`; historical replay
makes no current CLI parity claim. Current public validation artifacts were
regenerated against the sanitized public audit metadata. Metrics
are tokenizer proxies from small synthetic fixtures, not billing, native-model
or equivalent-browser savings.
