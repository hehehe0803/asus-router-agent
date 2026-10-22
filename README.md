# ASUS Router Agent

A local Python CLI for bounded ASUSWRT reads, compact JSON evidence and explicit
human-authorized operations. It uses the maintained `asusrouter` library,
pinned to 1.21.3. It does not install router firmware, enable remote access or
run an unattended control service.

This is an experimental Linux tool. Selected contracts target RT-AX86U firmware;
source support is not proof that a command works on your model or firmware.
Guarded writes remain limited by exact identity, authorization and recovery
contracts. Production backup admission is disabled; it requires independently
trusted evidence origin, complete coverage and whole-configuration invalidation
(the B2 boundary). No general autonomous write readiness is claimed.

## Install and inspect offline

Python 3.11+ and a Linux desktop with an unlocked Secret Service keyring are
required for router authentication. From a reviewed checkout:

```sh
python -m pip install .
router-agent --version
router-agent --help
router-agent capabilities
router-agent capabilities --native --limit 5
router-agent capabilities --expansion --limit 20
```

These inventory commands require no router credentials or LAN access. Data and
error responses use JSON by default; `--help` and `--version` use plain text.
There is an optional `--json` compatibility flag. Local snapshot diffs also offer `--format table`.

For development, install dependencies and prime the tokenizer data while network
access is available. Keep the same cache directory for the offline test run:

```sh
uv sync --locked
export TIKTOKEN_CACHE_DIR="$(mktemp -d)"
uv run python -c 'import tiktoken; tiktoken.get_encoding("o200k_base")'
uv run python -m pytest -q
```

The first setup needs network access for packages and tokenizer data. CI primes
the cache before isolating tests from LAN and Internet access.
The repository includes synthetic fixtures and historical tokenizer studies;
they do not measure real task success, current API billing or network benefit.
See [benchmark scope](benchmarks/README.md).

## Configure a router yourself

In an interactive local terminal, replace the reserved example host and CA path
with your exact router HTTPS origin and a certificate obtained through a trusted
channel. The certificate must match the selected hostname or address:

```sh
router-agent auth init --host https://router.example.invalid --username admin --ca-file /path/to/trusted-router-ca.pem
router-agent auth status
router-agent auth probe
router-agent status
router-agent get wan ports wlan guest
router-agent clients --online --limit 10
```

The password is entered with hidden terminal input and stored in desktop Secret
Service. Local configuration, aliases and snapshots use owner-only files under
`~/.local/state/asus-router-agent`. Public client results use local aliases.
`auth status` describes local setup; it does not establish a successful login.
Responses may come from router caches; fetched time does not prove source age.

Use verified HTTPS. Apply refuses HTTP, including no-op apply. There is no
certificate-verification bypass or automatic protocol fallback. Treat router
release notes as untrusted text. See [privacy and security](SECURITY.md),
[compatibility](docs/COMPATIBILITY.md) and [operation boundaries](docs/OPERATIONS.md).

## Optional observations from a checkout

The `scripts/` helpers are checkout tools, not installed entry points. They
observe selected aggregates and never change router, resolver or HA settings.
Read their `--help` before an explicitly chosen collection:

```sh
python scripts/observe_dns.py --help
python scripts/measure_dns.py --help
python scripts/observe_home.py --help
python scripts/observe_home_ssh.py --help
python scripts/phone_observer.py --help
```

HA HTTPS and SSH examples are under `examples/`; they contain reserved targets
and placeholder paths. Preflight does not create credentials. HTTPS needs an
existing owner-only credential JSON; SSH needs explicitly selected existing key,
known-hosts and HA token files. Never commit those files. SSH enforces strict host
verification and reads only bounded loopback API state on the selected host.

The phone helper opens a temporary listener on an explicitly selected RFC1918
IPv4 address. Use `--mode baseline` for a single observation without a router
change. Keep the tokenized phone URL private. A human must open it on the target
Wi-Fi with mobile data off and press the observation button. Its results describe
reachability, not verified filtering, DNS policy or physical device isolation.

## Contribute

Run the credential-free offline tests before sending a change. Include synthetic
regressions and describe the exact source contract and remaining hardware limits.
Do not submit household captures, personal device information or credentials.
See [support](SUPPORT.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
Project-authored code is MIT licensed; upstream components retain their licenses.

The offline [WebUI operation inventory](docs/WEBUI-COVERAGE.md) is available through
`router-agent capabilities --webui`. Its 589 candidates and 89 unresolved branches
are planning evidence. Three operations are implemented and 43 are partially
implemented with offline evidence; zero have live verification. These counts
do not establish WebUI parity. Selected WAN timing, guest capacity and radio
settings retain explicit null, freshness and applicability limits; see the
[source contract](docs/SOURCE-CONTRACT.md). Internal protected file custody does
not supply a native configuration export or recovery provider.
