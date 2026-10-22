# Offline WebUI operation inventory

`router-agent capabilities --webui` lists operation candidates with bounded pagination. Use `--family`, `--status` or `--blocker` to filter; an exact operation ID returns its full record. This inventory cannot execute operations and adds no write authority.

The initial inventory contains 589 candidates across 69 catalog pages and 20 hidden-branch registers. All 89 branch enumerations remain unresolved. Three operations are implemented and 43 are partially implemented with offline evidence; zero operations have live verification in this inventory. The applicable denominator remains unknown. These counts do not establish complete WebUI coverage or compatibility with another router.

Planning references in the packaged public manifest point to this public summary. They describe candidate work rather than independently verified form controls. Detailed household planning, source captures, topology, pilot observations and operational records are excluded. Source references are summarized separately in [SOURCE-CONTRACT.md](SOURCE-CONTRACT.md); code and synthetic-test references point to included files.

Open contracts include complete LAN DHCP globals/reservations/leases, effective routing tables, VPN Fusion profile import/edit/delete and device/default/DNS policy, correlated diagnostic jobs, native settings export/restore and whole-state revision. Existing source enums or transport primitives are insufficient proof of these semantic operations. Protected file custody is an internal exact-byte helper; it neither exports a router configuration nor supplies native restore/recovery authority.

Complete forms, unknown-field preservation, coupled Apply effects, authorization, inverse recovery and target applicability require separate verification before an operation becomes executable. No upstream request or maintainer commitment is implied by a planning record.
