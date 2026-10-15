# Security and privacy

Router administration can disconnect users. This CLI bounds selected request
paths and normal output, preserves TLS verification and rejects uncertain
identity or recovery conditions. These controls do not make a compromised local
account safe or establish compatibility with every router.

Router passwords are entered interactively and stored in Linux desktop Secret
Service. Configuration and local state are owner-only. Alias keys, recovery
material, snapshots, plans, certificates, SSH keys, known-hosts files and HA
credentials remain private. A process controlling the same account can access
account-owned state; HMAC plan bindings are not independent authorization.

Normal CLI diagnostics suppress credential-bearing upstream logs and avoid
persisting vendor error text. This does not guarantee that external debuggers,
OS tools, shell history or other applications cannot disclose credentials.
Never enable or publish raw dependency DEBUG logs against real router profiles.

HA observation requires the user to supply an existing full bearer token through
the documented owner-only file; this tool neither creates nor scopes that token.
Treat it as a credential even though this collector only performs bounded GETs.
For SSH, trust the host key independently and select existing protected files.
No keys, tokens, SSH configuration or HA entity state are changed.

The phone helper serves temporary LAN HTTP with an unpredictable private URL.
LAN HTTP is not encrypted. Its URL grants access to that bounded observation
session; do not forward or screenshot it. The helper checks peer/origin/host,
request and lifetime budgets, then writes only a sanitized summary. It is not
an Internet-facing service. Phone observations require a human and remain
separate from router actions and approval grants.

Do not include passwords, tokens, key material, exports, MAC/IP inventories,
personal names, SSIDs or raw logs in public issues. For a suspected disclosure,
use GitHub private vulnerability reporting if enabled. If it is unavailable,
open only a minimal public request for a private contact route, without the
sensitive reproduction, and wait for the maintainer's response. Do not assume
a private reporting channel has already been configured for this repository.
