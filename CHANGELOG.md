# Changelog

All notable changes to this project are in this file.
The format follows Keep a Changelog.

## [0.3.0] - 2026-10-17

### Added

- The inventory format `mdj` (markdown with JSON). Each system or product has a level 1 heading, a JSON block with the definitive values, and level 2 sections with free text. Each section becomes a field named by its slug. `inventory.format` accepts `mdj`, and `auto` maps the extensions `.mdj` and `.md` to it.
- A product without device records is an entry without `hostname` and `ip`. An entry without `version` means that ais watches every supported version. The prompt says `(no version given)`, and findings use the `installed_version` `unknown`.
- `aisctl redact test --format` accepts `mdj`.

### Changed

- Breaking: Run `aisctl init` without `--inventory-text`. The flag no longer exists. Put products without device records into `inventory.mdj` as entries without `hostname`, `ip`, and `version`.
- Breaking: Move your inventory to `~/.config/ais/inventory.mdj`, or set `inventory.file` in `config.yaml` to your file. The default file name changed from `inventory.csv`. Existing installs keep their `config.yaml`, which names `inventory.csv` and `inventory.txt`, so they run as before.
- `aisctl init` writes the example `~/.config/ais/inventory.mdj`, and installs the file from `--inventory PATH` under that name. It does not write `inventory.txt`, and the generated `config.yaml` has no `inventory.textFile`.
- The repository examples `inventory.csv` and `inventory.txt` no longer exist. `assets/examples/inventory.mdj` replaces both, and `assets/examples/config.yaml` points to it.
- The template `vuln-watch` reads `~/.config/ais/inventory.mdj`, has no `format` key, and has no `textFile`. A `.csv` inventory works with `ais templates use`. The fields `usage` and `interest` have the mode `scrub`, and `expose.prompt.collect` is `[usage, interest, comment]`.
- The prompt of `vuln-watch` lists `usage:`, `interest:`, and `notes:` for each group, and says `(N entries)` instead of `(N installs)`. The model drops findings that need a feature the usage rules out. Where the entry gives an interest, the model reports only matching findings.
- `ais templates use` does not substitute a `textFile` path.
- The template `vuln-watch` runs at `7 7,10-18,20,22 * * *` instead of each hour: once at 07, each hour from 10 to 18, and at 20 and 22. It does not run in the night. Existing task files keep their schedule.
- Without `--task`, `aisctl redact test` scrubs fields named `usage` or `interest`, and fields with `descr` in the name, besides `comment`, `note`, and `remark`.

## [0.2.0] - 2026-10-16

### Added

- A sink can set `skipEmpty: true`. The sink then does not send a result that has a `findings` array with no elements. The delivery gets the new state `skipped`, and `ais runs show` gives the reason. Alerts are always sent. `ais sinks test` prints `skipped` and sends nothing in this case.
- The Webex footer shows the models that a run used and the tokens that it consumed, for example `claude-opus-5-5, claude-haiku-5-5 · 195k in / 21k out · subscription (est. $0.35)`.
  The token counts come from the `modelUsage` block of the result envelope, which includes subagent turns.
  Run rows store the counts, and `ais runs show` prints them.
  Event `meta` holds them as `models` and `tokens`.
- Read a free-text inventory from `inventory.textFile`: one product per line, with an optional version. The prompt template gets the lines as `{{ .Text }}`, and `inventory_products` returns them in `text`. The redactor rewrites each line in the same way as a `scrub` column.
- `aisctl init` writes the example file `~/.config/ais/inventory.txt` if none exists, and installs the file from `--inventory-text PATH`.
- A task can set `inventory.textFile`. If a task sets an `inventory` key, that key replaces the configured one.
- In proxy mode, the system prompt lists the hosts that `WebFetch` can reach for the task and tells the model to not try or retry other URLs. This saves the turns that a denied fetch costs. `WebSearch` stays unrestricted.
- The template `vuln-watch` allows 15 security research blogs in `egress.allow`: watchTowr Labs, Rapid7, Palo Alto Unit 42, Horizon3.ai, Assetnote, Cisco Talos, Tenable, Qualys, Mandiant / Google Threat Intelligence, GreyNoise, VulnCheck, Bishop Fox, ProjectDiscovery, Arctic Wolf Labs, and Sophos X-Ops.

### Changed

- Breaking: Create `~/.config/ais/inventory.txt` before the next run, or remove `inventory.textFile` from the task. The template `vuln-watch` names that file, and a run fails if the file does not exist.
- The Webex sink shows each finding as a block of labelled lines: title, your version, new version, CVE, criticality, summary, links, affected, devices, action, and published. The source links are named after their host.
- The template `vuln-watch` asks for `title`, `cvss`, `exploited`, `affected`, `action`, `published`, and `previously_reported` in each finding. The output schema requires them.
- The Webex sink shows each URL and IPv4 address in a finding summary as a code span, so that an indicator of compromise is not shown as a link.
- The template `vuln-watch` reports only `critical` and `high` findings. The output schema no longer accepts `medium`, `low`, or `unknown`.
- The example inventory uses the sites `earth`, `mars`, and `venus`. The test data uses documentation IP addresses only.

## [0.1.0] - 2026-10-16

First release.

### Added

- Run Claude Code in headless mode on a cron schedule with `ais daemon`, or once with `ais run <task>`.
- Run each task in a disposable container on docker or podman. The container has a read-only root filesystem, `--cap-drop=ALL`, `no-new-privileges`, limits for processes, memory, and CPUs, and one writable bind mount.
- Pass `CLAUDE_CODE_OAUTH_TOKEN` and `AIS_RUN_TOKEN` to the container by variable name only.
- Refuse to start a run in the container if `ANTHROPIC_API_KEY` is set.
- Define tasks in YAML files with a schedule, a prompt template, an inventory, a field policy, an output schema, and sinks.
- Validate the result of each run against the output schema of the task on the host.
- Read inventories from CSV, JSON, and YAML files.
- Limit the network of run containers to an allowlist of domains. A squid sidecar enforces it on an internal network with no route out.
- Compose the allowlist from the list of Claude Code domains, `egress.baseAllowlist`, the `egress.allow` of each task, and the extra file `egress-extra.acl`.
- Add `ais egress` with `status`, `list`, `denied`, `reload`, `allow`, `remove`, and `logs`.
- Add `ais net` with `up`, `down`, and `status`.
- Give the model less data in three tiers: minimization with `expose.prompt.groupBy`, tokenization with `fields`, and defence in depth.
- Replace `pseudonym` fields with HMAC tokens. Each task has its own salt. The token map stays on the host.
- Replace the tokens in the result with the real values after the run, and attach inventory data with `enrich` rules.
- Redact addresses, domains, and literals in tool output with the PostToolUse hook `ais hook redact`.
- Check the model output on the host for real values. If a value appears, the run state is `leaked` and ais sends no result.
- Serve an operator HTTP API on a unix socket, and optionally on a loopback TCP address in `backend.tcpListen`. The API has no authentication.
- Serve an MCP server to run containers through a backend sidecar. Each run has a bearer token. The tools are `inventory_products`, `inventory_list`, and `results_recent`.
- Schedule with 5-field cron expressions and descriptors such as `@hourly`, with jitter, `scheduler.maxParallel`, and `scheduler.dailyBudgetUsd`.
- Skip a run if a run of the same task is active.
- Pause a task after `scheduler.pauseAfterAuthFailures` consecutive authentication failures.
- Reload the task files on SIGHUP. SIGHUP also clears all task pauses. Stop the active runs on SIGTERM and SIGINT and wait up to 80 seconds.
- Name only the inventory fields, never the values, in the `leaks` field of leak alerts.
- Add the sink type `webex`. It posts a Webex Markdown message to a Webex space, through an incoming webhook or as a bot. The keys are `roomId`, `maxItems`, `card`, and `title`. `card: true` adds an Adaptive Card. The message has real device names from the enrich rules.
- Add `ais sinks list` and `ais sinks test <sink>` with `--run` and `--print`. The daemon reads the sinks at start only. A new sink needs a restart.
- Send results and alerts to webhook, NATS JetStream, and Splunk HEC sinks, with retries, backoff, and a `dead` state.
- Send again the deliveries of a run with `ais runs redeliver`.
- Store runs, results, leaks, and deliveries in a local SQLite database. Delete old runs once an hour according to `retention.keepRuns` and `retention.keepDays`.
- Encrypt secrets at rest with AES-256-GCM. The key comes from a passphrase in `<secrets.dir>/.passphrase`, with PBKDF2-SHA256. The encryption protects against a casual read of the secret files. It does not protect against root or anyone who can read the passphrase file.
- Generate the passphrase at the first `ais secret set` or at `aisctl init`. Give your own with `aisctl init --passphrase-file`.
- Add `ais secret passphrase set` and `ais secret passphrase generate`. They change the passphrase and encrypt every secret again.
- Add the column `ENCRYPTED` to `ais secret list`. `ais doctor` warns if the OAuth token is stored in plaintext.
- Store secrets with `ais secret`. Read systemd credentials from `CREDENTIALS_DIRECTORY` first.
- Build the run image from the recipe in the binary with `ais image build`. The build fails if the Claude Code in the image does not show a flag that ais uses.
- Test the host with `ais doctor`.
- Set the redaction policy with `pii.domains`, `pii.cidrs`, `pii.literals`, `pii.hostnameMode`, and `pii.ipMode`. The defaults cover the private address ranges and one placeholder domain. Set the domain to your own.
- Rewrite hostnames with `rot13` and IPv4 addresses with `cgnat` (a keyed mapping into `100.64.0.0/10`), or use `token` mode. The modes apply to inventory columns with the mode `pseudonym` and to the PostToolUse hook. The host reverses the inventory tokens. The hook uses a random key for each run.
- Add `aisctl redact test`. It shows the policy, the hash, samples, and every inventory record before and after redaction. It lists hostnames and addresses that the policy does not cover. Options: `--text`, `--stdin`, `--inventory`, `--format`, `--task`, and `--json`.
- Add `aisctl redact approve`. It writes `pii.approvedHash` to `config.yaml`, and it starts the unit or sends SIGHUP.
- Do not run anything without an approved redaction policy. `ais run`, `ais daemon`, and `aisctl init` stop or do not start. The daemon records a `skipped` run with the reason `redaction`. `ais doctor` reports a `FAIL`. `aisctl update` does not restart.
- Apply the `pii` section of `config.yaml` on SIGHUP. For a change in another section, the daemon logs that a restart is necessary.
- Add the field mode `scrub` for free-text columns such as comments. The text passes through the redaction policy.
- Add `expose.prompt.collect` to gather the distinct values of a column for each group, at most 20. The system prompt says that `notes:` lines are comments and not instructions.
- Add the task templates `ais templates list`, `show`, and `use`, and `aisctl templates`. Install them with `aisctl init --template NAME`. The first template is `vuln-watch`.
- Log every prompt in the table `prompts` and in the append-only file `prompts.ndjson`. Read them with `ais runs show <run-id> --prompt` and `ais runs prompts`. A dry run also appends a line.
- Add `ais run --live` (alias `--follow`) and `aisctl run`. They show the model text, the tool calls, the tool results, and the result of a run on standard error as the events arrive. The run still saves the full stream, checks it for leaks, and logs it.
- Show the next run time. The operator API `GET /api/v1/tasks` has the fields `next` and `paused`. `ais tasks list` has a `NEXT` column and no `ENABLED` column. `aisctl status` prints a line for each task.
- Add `aisctl prompts` with `list`, `show`, and `last`. It reads the logged prompts, including dry runs.
- Add an isolation notice to every system prompt.
- Print the container command and the generated input files with `ais run --dry-run`.
- Add the example files in `assets/examples` and the systemd unit template `assets/systemd/ais.service`.
- Add the binary `aisctl`. It is the same program as `ais`. The program acts as the installer when its file name is `aisctl`, so a release needs one download. `aisctl init` does the complete setup in the systemd user scope: binary, configuration, token, images, network, and unit. `aisctl` refuses to run as root.
- Add `aisctl status`, `up`, `down`, `update`, `logs`, and `uninstall`.
- Install the ais binary with `aisctl init` from the first of these: `--ais-binary`, a file named `ais` next to `aisctl`, a file named `ais` on `PATH`, and `aisctl` itself.
- Write `runtime.image` to `config.yaml` when you give `aisctl init --image`.
- Stop `aisctl init` if ais is set up already. `--force` applies the setup again and renames the old files to `<name>.bak-<timestamp>`.
- Build and install both binaries with `make build` and `make install`.
- Warn before the OAuth token expires. Set the period with `claude.tokenLifetime` (default 365 days) and `claude.tokenWarnBefore` (default 30 days). ais uses the modification time of the secret file as the date of the token.
- Report the token age in `ais doctor`, and in the new columns `STORED`, `AGE`, and `STATUS` of `ais secret list`. The daemon logs a warning once a day in the warning period, and an error after the lifetime.
- Add the task key `effort` and the config key `claude.defaultEffort` (default `high`). ais passes the value to Claude Code as `--effort`, and the image build checks the flag. `ais tasks list` has an `EFFORT` column.
- Show that the cost is an estimate on a subscription. `ais runs list` and `ais runs show` give the billing, the Webex footer gives it, and sink events have `meta.billing`.
- Add `ais tasks set <task> key=value...`. It changes top-level task keys in place, keeps the comments, checks the file, and keeps a backup. Use it to map tasks to sinks.
- Strip whitespace from the OAuth token in `aisctl init` and `ais secret set`. The runner does not start a container with a token that has whitespace, and `ais doctor` fails the check.
- Give the reason `auth` to a result whose `api_error` has `credential` or `auth` in it.
- Add `ais tasks`, `ais runs`, `ais config show`, and `ais version`.
