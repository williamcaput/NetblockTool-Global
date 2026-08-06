# NetblockTool 4

NetblockTool discovers and ranks IP netblocks associated with an organization across all five Regional Internet Registries (RIRs). Version 4 replaces fragile search-engine and legacy HTML scraping with structured registry APIs where available and bounded public Whois queries where organization search remains Whois-oriented.

> Use NetblockTool only for organizations and systems you are authorized to assess. A registry association is evidence, not proof that every returned prefix is currently operated by the named organization or authorized for testing.

## Highlights

- All five RIRs: **ARIN, RIPE NCC, APNIC, LACNIC, and AFRINIC**
- IPv4 and IPv6 support
- Organization, network, and ASN discovery
- ASN announced-prefix enrichment through RIPEstat
- Confidence scoring with visible evidence
- CIDR-safe deduplication
- Table, CSV, and JSON output
- Per-provider failure isolation, retries, timeouts, and bounded Whois responses
- Python 3.10–3.13 support
- Automated linting, tests, coverage, and package builds with GitHub Actions

## Registry coverage

| Registry | Discovery method | Expansion |
|---|---|---|
| ARIN | Whois-RWS JSON | Organization → networks and ASNs |
| RIPE NCC | RIPE Database REST JSON | Organization inverse lookup and ASN prefixes |
| APNIC | Bounded public Whois | Network and ASN objects |
| LACNIC | Bounded public Whois | Owner and assigned IPv4/IPv6 resources |
| AFRINIC | Bounded public Whois | Organization inverse lookup and ASN prefixes |

RIPEstat is used only to enrich ASNs already matched through a registry. It does not establish registry ownership by itself.

## Installation

### From source

```bash
git clone https://github.com/williamcaput/NetblockTool.git
cd NetblockTool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

### Editable development install

```bash
python -m pip install -e '.[dev]'
```

## Quick start

Search all registries:

```bash
netblocktool -v "company"
```

Search selected registries:

```bash
netblocktool "company" --registry apnic --registry lacnic
netblocktool "company" --registry afrinic
```

Export results:

```bash
netblocktool "MUFG" --format csv --output company.csv --threshold 50
netblocktool "MUFG" --format json --output company.json
```

Filter by address family:

```bash
netblocktool "Example Corp" -4
netblocktool "Example Corp" -6
```

Run without installing:

```bash
PYTHONPATH=src python -m netblocktool -v "company"
```

## Command reference

```text
usage: netblocktool [-h] [-o OUTPUT] [-f {table,csv,json}] [-t 0-99]
                    [--registry {arin,ripe,apnic,lacnic,afrinic}]
                    [-4 | -6] [--timeout TIMEOUT] [--retries RETRIES]
                    [--user-agent USER_AGENT] [-v] [--version]
                    company
```

`--registry` is repeatable. When omitted, all five registries are queried. Provider failures are isolated so the tool can still return partial results.

## Output fields

- **Network**: normalized CIDR prefix
- **Organization**: registry-returned organization or network name
- **Handle**: registry organization, network, or maintainer handle
- **Source**: registry and optional enrichment source
- **Confidence**: 0–99 evidence score
- **Rationale**: scoring evidence
- **Resource URL**: link to the corresponding registry search or record

## Search guidance

Registry records frequently use legal entities, subsidiaries, abbreviations, or historic network names. When a search returns few or no results, try:

- the full legal company name;
- the parent company;
- regional subsidiaries;
- a known ASN, network name, or registry handle;
- registry-specific searches with `--registry`.

## Responsible use and data caveats

- Do not use registry contact data for marketing or unsolicited outreach.
- ASN announcements may include customer, partner, or delegated prefixes.
- Registry addresses may describe the registrant rather than the physical location of the infrastructure.
- Whois services may rate-limit or restrict bulk usage. Keep queries reasonable and comply with each registry's terms.
- Set a real operational contact in the HTTP User-Agent for sustained API use:

```bash
export NETBLOCKTOOL_USER_AGENT='NetblockTool/4.0 company=Example contact=security@example.com'
```

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest --cov=netblocktool --cov-report=term-missing
python -m build
```

The test suite uses deterministic fixtures and does not require live registry access.

## Project layout

```text
src/netblocktool/
├── cli.py
├── dedupe.py
├── http.py
├── models.py
├── names.py
├── output.py
├── rpsl.py
├── scoring.py
├── whois.py
└── providers/
    ├── afrinic.py
    ├── apnic.py
    ├── arin.py
    ├── lacnic.py
    └── ripe.py
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance and [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).

## Acknowledgments

NetblockTool 4 is a clean rewrite inspired by the original NetSPI NetblockTool concept. It is not an official product of any Regional Internet Registry.
