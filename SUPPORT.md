# Support and contribution scope

This is an experimental community tool without a support SLA. Supported behavior
is defined by the pinned source contracts and fail-closed runtime gates, not by
an inventory entry or a successful offline test. Describe the command, sanitized
error code, model and firmware when asking for help; do not attach raw logs or
private state. The repository's issue tracker can be used once it is published.

Bug fixes should include a minimal synthetic regression and run the affected
offline tests. Do not weaken HTTPS, identity, exact-plan, human-confirmation,
drift or recovery gates to broaden compatibility. Device-specific support needs
independent source and recovery evidence. Runtime library upgrades are separate
compatibility changes; do not patch installed vendor packages.

No public endpoint or scheduled service is required. The CLI does not supply a
browser adapter, MCP server or home-automation integration. Existing supported
native tools remain preferable when their contracts cover the requested work.
