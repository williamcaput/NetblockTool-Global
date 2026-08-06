# Changelog

## 4.0.0

- Added LACNIC public Whois discovery with support for `owner`, `ownerid`, IPv4, and IPv6 records.
- Added AFRINIC Whois discovery with organization-object search, inverse organization expansion, IPv4/IPv6 parsing, and optional ASN prefix enrichment through RIPEstat.
- Expanded `--registry` to support `arin`, `ripe`, `apnic`, `lacnic`, and `afrinic`; all five are queried by default.
- Added provider parser tests for LACNIC and AFRINIC.
- Added GitHub Actions CI for Python 3.10–3.13, linting, tests, coverage, and package builds.
- Added contribution and security guidance and polished release documentation.

## 3.1.0

- Added RIPE Database REST provider with organization search and inverse organization expansion.
- Added APNIC Whois provider with bounded responses and object filtering.
- Added repeatable registry selection and provider failure isolation.

## 3.0.0

- Initial clean rewrite with ARIN Whois-RWS and RIPEstat support.

## 4.0.1 - 2026-08-06

### Fixed
- APNIC company-name searches now include `organisation` objects and expand their
  `org` handles into related IPv4, IPv6, and ASN records.
- APNIC result naming now prefers human-readable `org-name` and `descr` values
  over abbreviated `netname` identifiers when available.
- Queries such as `Bank of Ayudhya` can now resolve resources registered under
  identifiers such as `BAY-TH` and `ORG-BOAP1-AP`.
