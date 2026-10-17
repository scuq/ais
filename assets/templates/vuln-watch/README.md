# vuln-watch

Check of security feeds (The Hacker News, CERT.at, heise Security,
CISA KEV, CERT-EU, Infosecurity Magazine, r/cybersecurity and r/netsec RSS,
GitHub Security Advisories) for vulnerabilities that affect the products and
versions in your inventory, verified against the vendor advisories of Cisco,
Citrix/NetScaler, Palo Alto Networks, F5 and Keycloak, and against NVD. The
allowlist also admits the research blogs of watchTowr, Rapid7, Unit 42,
Horizon3, Assetnote, Talos, Tenable, Qualys, Mandiant, GreyNoise, VulnCheck,
Bishop Fox, ProjectDiscovery, Arctic Wolf, and Sophos, so that the model can
follow a feed item to its analysis. The model sees distinct
vendor/product/version tuples with entry counts and the operators' scrubbed
usage, interest, and comments; it never sees a hostname or an address. Findings are validated
against a JSON schema, joined back to the devices on the host, and delivered
to the sinks listed under `sinks:`.

Memory: each result has a list `checked` with the advisories and news items
that the run evaluated, with the URL, the product, and a short verdict. The
next run reads the last 20 results through `results_recent` and skips an item
that an earlier run checked, unless the source was updated after that run.
This saves the turns that a new check of the same item costs. The sinks show
only `findings`.

Digest: the task key `digest` sends a summary at 22:30 (`scheduler.timezone`)
when the results of the last 24 hours have no finding. The last run of the day
is at 22:07. The digest shows the runs, the turns, and the items checked, so a
day without findings is not silence. It goes to the `sinks`.

Schedule: `7 7,10-18,20,22 * * *`. The task runs at minute 7: once at 07, at
each hour from 10 to 18, and at 20 and 22. It does not run in the night. Most
advisories are published between 09 and 18. The prompt looks back 24 hours, so
a gap between runs delays a finding but does not lose it. The times are in `scheduler.timezone`. To change the schedule, use
`ais tasks set vuln-watch schedule="..."`.

Inputs: an inventory with at least `vendor` and `product`. The default file
is `~/.config/ais/inventory.mdj`, and the format follows the file extension.
ais uses `version`, `hostname`, `ip`, `site`, `usage`, `interest`, and
`comment` when present. A product without device records is an entry without
`hostname` and `ip`. An entry without `version` is watched for every
supported version, and its findings carry `installed_version: unknown`.
The model uses `usage` to drop findings that need a feature the usage rules
out. Where an `interest` is given, it reports only matching findings.
Set `sinks:` after `ais templates use vuln-watch`.

Output: only findings of severity `critical` or `high`. A vulnerability that
is exploited in the wild is rated `critical`. Each finding has `title`,
`cve_ids`, `cvss` (null when none is published), `exploited`, `affected`
(what is and is not affected), `action` (what an operator must check or do),
`published`, `source_urls`, `summary`, and `confidence`. The field
`previously_reported` is true when the finding was in an earlier result and
is repeated because of new information. Indicator-of-compromise addresses and
URLs from an advisory go into `summary`.
