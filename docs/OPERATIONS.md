# Operation boundaries

Read commands authenticate against an explicitly configured router and collect
only allowlisted contracts. Native `get` is not universal endpoint discovery.
Source timestamps and freshness gaps must remain explicit when interpreting data.

`plan` fetches current state and stores a bounded preview; it does not apply a
configuration write. `approval-request HASH` displays scope without credential
or router access. Applying requires verified HTTPS, exact identity and before-state,
a separate administrator-issued matching grant under
`/etc/asus-router-agent/approvals/HASH.json`, and a human typing the exact terminal
confirmation. Grants must be issued separately by an administrator after reviewing
the actual plan. Agent harnesses must never create grants or enter confirmation.

The package does not supply a general grant issuer or unattended broker. Missing,
expired or mismatched grants fail closed. An inverse preview requires a fresh
review and authorization; the CLI does not silently roll back an uncertain write.
Same-user/root access limits the independence of this boundary.

Parental, VPN, forwarding and radio operations have additional source, preservation,
whole-policy drift and recovery prerequisites. Unsupported native round trips
remain blocked. Production backup admission remains disabled until independently
trusted evidence origin, full coverage and whole-configuration invalidation exist.
A user-held backup or a limited manual restore does not by itself open that gate.
The shipped source and synthetic tests document these checks. No write cookbook
or ready-made operational grants are included in this public MVP.
