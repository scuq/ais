# vuln-watch

Hourly check of security feeds (The Hacker News, CERT.at, heise Security,
CISA KEV, CERT-EU, Infosecurity Magazine, r/cybersecurity and r/netsec RSS,
GitHub Security Advisories) for vulnerabilities that affect the products and
versions in your inventory, verified against the vendor advisories of Cisco,
Citrix/NetScaler, Palo Alto Networks, F5 and Keycloak, and against NVD. The
allowlist also admits the research blogs of watchTowr, Rapid7, Unit 42,
Horizon3, Assetnote, Talos, Tenable, Qualys, Mandiant, GreyNoise, VulnCheck,
Bishop Fox, ProjectDiscovery, Arctic Wolf, and Sophos, so that the model can
follow a feed item to its analysis. The model sees distinct
vendor/product/version tuples with install counts and the operators' scrubbed
comments; it never sees a hostname or an address. Findings are validated
against a JSON schema, joined back to the devices on the host, and delivered
to the sinks listed under `sinks:`.

Inputs: an inventory with at least `vendor`, `product`, and `version`.
ais uses `hostname`, `ip`, `site`, and `comment` when present. The free-text
inventory `inventory.txt` adds products without device records, one per line,
with an optional version. A line without a version is watched for every
supported version, and its findings carry `installed_version: unknown`.
Set `sinks:` after `ais templates use vuln-watch`.

Output: only findings of severity `critical` or `high`. A vulnerability that
is exploited in the wild is rated `critical`. Each finding has `title`,
`cve_ids`, `cvss` (null when none is published), `exploited`, `affected`
(what is and is not affected), `action` (what an operator must check or do),
`published`, `source_urls`, `summary`, and `confidence`. The field
`previously_reported` is true when the finding was in an earlier result and
is repeated because of new information. Indicator-of-compromise addresses and
URLs from an advisory go into `summary`.
