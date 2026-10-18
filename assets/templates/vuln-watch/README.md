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

Feed checks: the host reads the feeds and gives the model only the items that
no earlier run evaluated. The task runs on the schedule below. A tick of the
schedule is a feed run. If it has no new item, ais starts no container and
records a `skipped` run with the reason `quiet`. Once a day, at 20:07
(`feeds.fullSchedule`), the full check with web search runs. In a feed run, the
model skips by title the items that cannot concern the inventory. It fetches
and checks the other items. To force the full check, run
`ais run --full vuln-watch`. To see what the feeds return, run
`ais feeds test vuln-watch`.

Feeds: The Hacker News, CERT.at (warnings and all), heise Security (alerts and
news), CISA KEV (JSON), CISA advisories, CERT-EU advisories, Infosecurity
Magazine, r/netsec, Palo Alto Networks, Cisco PSIRT, Fortinet PSIRT, MSRC,
Keycloak releases, watchTowr, Rapid7, Unit 42, Horizon3, Talos, Tenable, and
GreyNoise. These are 22 URLs.

No feed: Citrix bulletins, F5, GitHub Security Advisories, Qualys, OpenBSD,
Red Hat, FTAPI, Kemp, Sophos, Arctic Wolf, and VulnCheck. Only the daily full run
covers these sources.

The host fetches the feeds, so `egress.allow` does not apply to them. The
model still needs the host of an item link in `egress.allow` to fetch it.

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

Schedule: `7,27,47 6-22 * * *`. Each tick is a feed check, except the tick at 20:07, which is the full run (`feeds.fullSchedule`). A feed check without a new item starts no container and costs nothing, so the task runs every 20 minutes from 06 to 22 and not in the night; the first check of the day picks the night up. `feeds.maxRunsPerDay` (12) caps the feed checks that start the model in 24 hours, so that a feed with unstable item ids cannot start a run at every tick. Times are in `scheduler.timezone`. To change the schedule, use `ais tasks set vuln-watch schedule="..."`.

Inputs: an inventory with at least `vendor` and `product`. The default file
is `~/.config/ais/inventory.mdj`, and the format follows the file extension.
ais uses `version`, `count`, `hostname`, `ip`, `site`, `usage`, `interest`,
and `comment` when present. An entry can be a role, for example "Internet edge
firewalls", with `count` for the number of installs it stands for. An entry
without `count` counts once. `hostname` and `ip` are optional: give them when
the alert must name the device. The alert names an entry by `hostname`, else
`ip`, else the heading of the entry. A product without device records is an
entry without `hostname` and `ip`. An entry without `version` is watched for every
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
is repeated because of new information. Each finding also has `update` and,
when the advisory lists them, `iocs`. Indicator-of-compromise addresses,
domains, and URLs go into `iocs` (30 entries at most), not into `summary`.

Update rule: the model reports an earlier finding again only when something
material changed. The cases are exploitation in the wild, new indicators of
compromise, a new or changed fixed version, a higher severity or CVSS score,
and more affected products. Then `previously_reported` is true and `update`
holds only what is new, in one or two sentences (400 characters at most). For
a first-time finding, `update` is null.

Closed finding: a finding is closed when the inventory version of the product
is the fixed version or newer. The model does not report a closed finding. It
does not report an update for an earlier finding whose product the inventory
shows as fixed. An upgrade that you record in `inventory.mdj` ends the updates.

The `webex` sink shows a finding with `previously_reported` and an `update`
as a short update block. To get this in an existing task, install the template
again with `ais templates use vuln-watch --force`. This also gives the task the
`feeds` block and the two-mode prompt.
