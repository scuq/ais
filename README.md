# ais - run Claude Code on a schedule inside disposable containers

## Usage

    ais <command> [options] [args...]

    ais daemon
    ais run [--dry-run] [--live|--follow] [--engine docker|podman] [--json] [--no-autobuild] <task>
    ais tasks list [--json] | validate | show <task>
    ais tasks set <task> key=value...
    ais sinks list | test <sink> [--run RUN-ID] [--print]
    ais templates list [--json] | show <name> | use <name> [--as NAME] [--force]
    ais runs list [--task T] [--state S] [-n N] [--json]
    ais runs show [--clear] [--prompt] [--json] <run-id>
    ais runs prompts [--task T] [-n N] [--json]
    ais runs redeliver [--sink S] <run-id>
    ais image build [--no-cache] | status
    ais net up | down | status [--json]
    ais egress status | list | denied [-n N] [--json] | reload | allow DOMAIN... | remove DOMAIN... | logs [-n N]
    ais secret set NAME [--stdin] | list | delete NAME
    ais secret passphrase set [--stdin] | generate
    ais config show [--json]
    ais doctor [--json]
    ais version

    aisctl init | status | up | down | update | logs | uninstall | version | help
    aisctl run <task> [--live] [--dry-run]
    aisctl redact test | approve
    aisctl prompts [list [--task T] [-n N]] | show <run-id> | last [--task T]
    aisctl templates list | show NAME | use NAME [--as NAME] [--force]

## Description

ais is a host program. It runs Claude Code in headless mode on cron schedules.
Each run happens inside a disposable, hardened container (docker or podman).
The container is removed when the run ends.

For each run, ais does these steps:

1. Read the inventory (for example products and versions) and apply the field policy of the task.
2. Build a prompt for the task and write the input files to a run directory.
3. Start the container and read the JSON result from its standard output.
4. Validate the result against the output schema of the task.
5. Check the model output for real values that must not appear.
6. Replace the pseudonyms in the result with the real values and attach device identity.
7. Store the result in a local SQLite database and send it to the sinks of the task.

A sink (delivery target) is a webhook, NATS JetStream, Splunk HTTP Event Collector (HEC), or a Webex space.

The container has no route to the network. It reaches only a proxy that allows a list of domains.
The inventory is not in the container. The model gets pseudonyms (stable replacement tokens) instead of sensitive values.
The map from pseudonym to real value stays on the host.

## Quickstart

You need a container engine (podman or docker), systemd with a user session, and a Claude account. A Go toolchain is necessary only to build from source (see Limitations).
Run all commands as an unprivileged user. `aisctl` refuses to run as root.

### Short version

    # 1. install (pick amd64 or arm64)
    tar xzf ais_v0.2.0_linux_arm64.tar.gz
    install -D -m 0755 -t ~/.local/bin ais_v0.2.0_linux_arm64/{ais,aisctl}

    # 2. token (Claude subscription, not an API key)
    claude setup-token

    # 3. setup: config, secret, image, proxy, user unit (not started)
    aisctl init --template vuln-watch

    # 4. edit: inventory, task, pii domains and cidrs
    $EDITOR ~/.config/ais/inventory.csv ~/.config/ais/tasks/vuln-watch.yaml ~/.config/ais/config.yaml

    # 5. redaction: test until no NOT COVERED, then approve (starts daemon)
    aisctl redact test
    aisctl redact approve

    # 6. verify
    aisctl status
    aisctl run vuln-watch --dry-run
    aisctl run vuln-watch --live

No approval, no runs. Details in the steps below.

### With aisctl

`aisctl` is the installer. It sets up ais in the systemd user scope in one command.
`ais` and `aisctl` are the same program. The program acts as the installer when its file name is `aisctl`. A release needs one download.

1. Copy the `aisctl` binary to a directory on `PATH`, for example `~/.local/bin`.

        install -D -m 0755 aisctl ~/.local/bin/aisctl

   To build from source instead, run `make build`. It writes `./ais` and `./aisctl`. Use `./aisctl` in the next steps.

2. Create a long-lived token.

        claude setup-token

3. Run the setup.

        aisctl init --template vuln-watch

   `aisctl init` does these steps:

   1. It checks the container engine and `systemctl --user`.
   2. It installs the ais binary to `~/.local/bin/ais`. If no other ais binary is available, it installs a copy of `aisctl`.
   3. It writes `~/.config/ais/config.yaml` with explicit paths. It writes an example inventory and an example free-text inventory if none exist.
   4. It installs each task template that you name with `--template`, for example `vuln-watch`. The option can repeat.
   5. It stores the OAuth token as the secret `claude-oauth-token`. The token comes from `--token-file`, from `CLAUDE_CODE_OAUTH_TOKEN`, or from a hidden prompt.
   6. It builds the run image, or pulls the image from `--image`. It also pulls the proxy image and the sidecar image.
   7. In `proxy` mode, it creates the networks and starts the proxy.
   8. It installs `~/.config/systemd/user/ais.service` and runs `systemctl --user daemon-reload`.
   9. It runs `loginctl enable-linger`, unless you give `--no-linger`.
   10. It enables the unit. It does not start the unit, because no redaction policy is approved yet. It prints the redaction test report instead.

   If `config.yaml` or the unit file exists, `aisctl init` stops with an error. Give `--force` to apply the setup again. `--force` renames the old files to `<name>.bak-<timestamp>`.

4. Edit the task and the inventory for your site. Review the `pii` section in `~/.config/ais/config.yaml`. It must name the domains and address ranges of your inventory.

5. Test the redaction policy.

        aisctl redact test

   The report lists inventory hostnames and addresses that the policy does not cover. Fix `pii.domains` and `pii.cidrs` until the report has no line `NOT COVERED`.

6. Approve the policy. This starts the daemon.

        aisctl redact approve

7. Show the state, and show what a run would do.

        aisctl status
        ais run vuln-watch --dry-run

Nothing runs until you approve the policy. See Redaction policy in the security model.

The options of `aisctl init` are in the Commands section.

### Manual steps

Use these steps if you do not want `aisctl`. You must still approve the redaction policy. `aisctl redact approve` writes `pii.approvedHash` to `config.yaml`. Without `aisctl`, set `pii.approvedHash` by hand to the hash that `aisctl redact test` prints.

1. Build and install the binaries.

        make build
        make install

   `make install` writes `ais` and `aisctl` to `~/.local/bin`. Set `PREFIX=/usr/local` for a system-wide install.

2. Create a long-lived token and store it as a secret.

        claude setup-token
        ais secret set claude-oauth-token

   The second command asks for the value without echo. Use `--stdin` to read the value from standard input.

3. Copy the example files.

        mkdir -p ~/.config/ais/tasks
        cp assets/examples/config.yaml ~/.config/ais/config.yaml
        ais templates use vuln-watch
        cp assets/examples/inventory.csv ~/.config/ais/inventory.csv

   Edit the files for your site. The example sinks in `config.yaml` point to placeholder hosts.
   Remove the sinks and the `alerts` key if you have no sink yet.

4. Check the host.

        ais doctor

5. Build the run image.

        ais image build

6. Start the network and the proxy.

        ais net up

7. Show what a run would do. This command starts no container.

        ais run vuln-watch --dry-run

8. Do one real run.

        ais run vuln-watch

9. Start the scheduler.

        ais daemon

For a permanent installation, use the systemd user unit. See Operations.

## Configuration

ais resolves the configuration in this order. A later source overrides an earlier source.

1. Compiled defaults.
2. The file `~/.config/ais/config.yaml`. The variable `AIS_CONFIG` selects another file. The variable `XDG_CONFIG_HOME` replaces `~/.config`.
3. The `AIS_*` environment variables in the Environment section.
4. Command-line flags.

A missing file is not an error. An unknown key is an error, because a mistyped key must not silently disable a policy.
Run `ais config show` to print the resolved configuration.

Every key is optional. A duration is a Go duration such as `30s`, `2m`, or `20m`.
A path can start with `~/` and can contain environment variables.

### Top level

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | Schema version. ais refuses any other value. |
| `alerts` | none | List of sink names. They receive an alert when a run ends as `leaked`, `failed`, or `timeout`. |

### runtime

| Key | Default | Meaning |
|---|---|---|
| `runtime.engine` | `auto` | `auto`, `docker`, or `podman`. `auto` selects podman if it is on `PATH`, and docker if not. |
| `runtime.image` | `localhost/ais:latest` | Name of the run image. |
| `runtime.user` | `auto` | The `uid:gid` of the container process on docker. `auto` uses the uid and gid of the ais process. Podman ignores this key. |
| `runtime.memory` | `2g` | Memory limit. ais sets the swap limit to the same value. |
| `runtime.cpus` | `1` | CPU limit. |
| `runtime.pidsLimit` | `256` | Maximum number of processes in the container. |
| `runtime.tmpfsSize` | `256m` | Size of the `/tmp` tmpfs. |
| `runtime.binary` | empty | Host path of the ais binary that ais mounts read-only into the containers. Empty means the running executable. |

### paths, secrets, and image

| Key | Default | Meaning |
|---|---|---|
| `paths.stateDir` | `~/.local/state/ais` | Database, run directories, and proxy files. |
| `paths.tasksDir` | `~/.config/ais/tasks` | Directory of task files. |
| `secrets.dir` | `~/.config/ais/secrets` | Secret store directory. |
| `image.claudeVersion` | `2.1.301` | Version of the Claude Code package in the image. |
| `image.autobuild` | `true` | If the image is missing or stale, `ais run` and `ais daemon` build it. |
| `image.caCertificates` | empty | Host path of a file or a directory. ais adds the `*.crt` and `*.pem` files to the trust store of the image at build time. |

### claude

| Key | Default | Meaning |
|---|---|---|
| `claude.oauthTokenSecret` | `claude-oauth-token` | Name of the secret that holds the token. |
| `claude.defaultModel` | `claude-opus-5-5` | Model for tasks that set no `model`. |
| `claude.defaultMaxTurns` | `30` | Turn limit for tasks that set no `maxTurns`. |
| `claude.defaultEffort` | `high` | Effort level for tasks that set no `effort`. The values are `low`, `medium`, `high`, `xhigh`, and `max`. |
| `claude.defaultMaxBudgetUsd` | `2.0` | Cost limit per run in US dollars for tasks that set no `maxBudgetUsd`. |
| `claude.defaultTimeout` | `20m` | Time limit per run for tasks that set no `timeout`. |
| `claude.tokenLifetime` | `8760h` (365 days) | Expected lifetime of the OAuth token. It must be more than 0. |
| `claude.tokenWarnBefore` | `720h` (30 days) | Warning period before the token reaches its lifetime. It must be shorter than `claude.tokenLifetime`. |

The token is opaque, so ais cannot read its expiry date. ais uses the modification time of the secret file instead. `ais secret set` renews that time.
For a systemd credential in `CREDENTIALS_DIRECTORY`, ais uses the modification time of that file.
Write a duration in hours, for example `8760h`.

### egress

| Key | Default | Meaning |
|---|---|---|
| `egress.mode` | `proxy` | `proxy` or `open`. `open` uses the default network of the engine. Use it only for the first start and for debugging. |
| `egress.subnet` | `10.199.0.0/24` | IPv4 subnet of the internal network. The proxy uses the address ending in `.2`. The backend sidecar uses the address ending in `.4`. |
| `egress.proxyImage` | `docker.io/ubuntu/squid:latest` | Image of the proxy sidecar. |
| `egress.proxyPort` | `3128` | Port of the proxy. |
| `egress.baseAllowlist` | none | Domains that every task can reach. |

### backend

| Key | Default | Meaning |
|---|---|---|
| `backend.socket` | `~/.local/state/ais/backend.sock` | Unix socket of the operator API. The path must be shorter than 108 bytes. The MCP socket `mcp.sock` is in the same directory. |
| `backend.tcpListen` | empty | Loopback address such as `127.0.0.1:9090`. If set, the daemon also serves the operator API on this TCP address. A non-loopback address is a configuration error. |
| `backend.sidecarImage` | `gcr.io/distroless/static-debian12:nonroot` | Image of the backend sidecar. |
| `backend.mcpPort` | `8080` | Port of the backend sidecar. |

### pii

| Key | Default | Meaning |
|---|---|---|
| `pii.domains` | `[".cyberdyne.systems"]` | Domain suffixes. A name under a suffix is a sensitive hostname. |
| `pii.cidrs` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7` | Address ranges. An address in a range is sensitive. |
| `pii.literals` | none | Exact strings. They are always sensitive. |
| `pii.hostnameMode` | `rot13` | `rot13` or `token`. How ais rewrites a hostname. |
| `pii.ipMode` | `cgnat` | `cgnat` or `token`. How ais rewrites an address. |
| `pii.approvedHash` | empty | Hash of the approved policy. `aisctl redact approve` writes it. Do not set it by hand. |

The keys `pii.redactDomains` and `pii.redactCidrs` do not exist. An unknown key is an error.
The default `pii.domains` is a placeholder. Set it to the domains of your inventory.
Any change to `pii.domains`, `pii.cidrs`, `pii.literals`, `pii.hostnameMode`, or `pii.ipMode` voids the approval.
The task keys `pii.redact.domains`, `pii.redact.cidrs`, and `pii.redact.literals` add to these lists for one task. They are not part of the approval hash.

### scheduler

| Key | Default | Meaning |
|---|---|---|
| `scheduler.timezone` | `Local` | Timezone for the cron schedules and for the daily budget. |
| `scheduler.defaultJitter` | `2m` | Maximum random delay added to each tick, for tasks that set no `jitter`. |
| `scheduler.maxParallel` | `2` | Maximum number of runs at the same time. The value must be 1 or more. |
| `scheduler.dailyBudgetUsd` | `0` | Cost limit per day for all tasks. `0` means no limit. |
| `scheduler.pauseAfterAuthFailures` | `3` | A task pauses after this number of consecutive authentication failures. `0` turns the pause off. |

### retention

| Key | Default | Meaning |
|---|---|---|
| `retention.keepRuns` | `500` | Number of finished runs to keep for each task. `0` means no limit. |
| `retention.keepDays` | `90` | Age in days after which a finished run is deleted. `0` means no limit. |

### inventory

| Key | Default | Meaning |
|---|---|---|
| `inventory.file` | empty | Default inventory file. A task can set its own. |
| `inventory.format` | `auto` | `auto`, `yaml`, `json`, or `csv`. `auto` uses the file extension. |
| `inventory.textFile` | empty | Free-text inventory. A task can set its own. |

An inventory is a flat list of records. A CSV file has a header row. A YAML or JSON file is a list of objects.
ais reads every value as a string.
The example inventory `assets/examples/inventory.csv` has a `comment` column. Use the mode `scrub` for such a column.

The free-text inventory is a text file with one product per line, for example `Palo Alto Networks GlobalProtect` or `Keycloak 26.1`.
A version is optional. ais ignores blank lines and lines that start with `#`.
A line has 300 characters at most, and the file has 500 lines at most.
The model gets each line through the prompt and through `inventory_products`.
The redactor rewrites a hostname or an address in a line in the same way as a `scrub` column.
The example file is `assets/examples/inventory.txt`.
If `inventory.textFile` names a file that does not exist, the run fails. Create the file or remove the key.

ais reads the inventory file and the free-text file at the start of each run. A change to these files applies to the next run. A reload or a restart of the daemon is not necessary.
If a change adds a hostname or an address outside `pii.domains` or `pii.cidrs`, run `aisctl redact test`. The daemon does not check the coverage of the inventory at the start of a run.

### delivery

| Key | Default | Meaning |
|---|---|---|
| `delivery.maxAttempts` | `10` | Attempts for one delivery before it becomes `dead`. The value must be 1 or more. |
| `delivery.backoff.initial` | `30s` | Delay after the first failed attempt. The delay doubles for each attempt. |
| `delivery.backoff.max` | `1h` | Upper limit of the delay. |

### sinks

The key `sinks` is a map. Each key is a sink name. The task key `sinks` lists these names.
Every sink needs `type` and `url`.

In `url` and in header values, ais replaces `${secret:NAME}` with the value of the secret `NAME`.

| Key | Types | Meaning |
|---|---|---|
| `type` | all | `webhook`, `nats`, `splunk_hec`, or `webex`. |
| `url` | all | Target URL. For NATS, a `nats://` URL. |
| `headers` | `webhook`, `splunk_hec` | Map of HTTP headers. |
| `body` | `webhook` | Go template for the request body. Default: `{{ json . }}`. |
| `timeout` | `webhook`, `splunk_hec`, `webex` | HTTP timeout. Default: `15s`. |
| `insecureSkipVerify` | `webhook`, `splunk_hec`, `webex` | If `true`, ais does not check the TLS certificate. |
| `skipEmpty` | all | If `true`, ais does not send a `result` event that has a `findings` array with no elements. The delivery gets the state `skipped`. Alerts are always sent. Default: `false`. |
| `credsSecret` | `nats` | Secret that holds NATS credentials. |
| `tokenSecret` | `nats`, `splunk_hec`, `webex` | Secret that holds the token. Splunk needs it, unless the `Authorization` header holds the token. For Webex it selects bot mode. |
| `subject` | `nats` | Go template for the subject. Default: `ais.results.{{ .Task }}`. |
| `stream.name` | `nats` | If set, ais creates or updates this JetStream stream before it publishes. |
| `stream.subjects` | `nats` | Subjects of that stream. |
| `sourcetype` | `splunk_hec` | Go template. Default: `ais:result`. |
| `source` | `splunk_hec` | Go template. Default: `ais:{{ .Task }}`. |
| `index` | `splunk_hec` | Splunk index. If empty, ais sends no index. |
| `host` | `splunk_hec` | Value of the HEC host field. If empty, ais uses the hostname of the machine. |
| `split` | `splunk_hec` | Name of a top-level array in the result. ais sends one event for each element. |
| `roomId` | `webex` | Webex space ID. It is necessary in bot mode. |
| `maxItems` | `webex` | Maximum number of findings in one message. Default: `10`. |
| `card` | `webex` | If `true`, ais adds an Adaptive Card to the message. |
| `title` | `webex` | Go template for the headline. Default: `ais {{ .Task }}`. |

A `webex` sink posts a formatted message to a Webex space. It has two modes:

- Incoming webhook: `url` is the URL from the Webex App Hub "Incoming Webhooks". No token is necessary.
- Bot: `url` is `https://webexapis.com/v1/messages`, with `tokenSecret` and `roomId`. Bot mode without `roomId` is a configuration error. A `url` that is not a webhook and has no token is also an error.

The message is in Webex Markdown:

1. A headline with a severity marker and counts.
2. One block for each finding, sorted `critical`, `high`, `medium`, then `low`. The blocks are separated by a blank line.
3. After `maxItems` findings, the line "… and N more; see `ais runs show <id> --clear`".
4. A footer with the time, the run ID, the number of turns, and the billing, for example `subscription (est. $0.42)`.

A finding block has one labelled line for each fact:

| Line | Content |
|---|---|
| Title | The severity marker, the vendor and product, and the `title` of the finding. Without a `title`, the CVE IDs. |
| Your version | The installed version and the affected version range. |
| New version | The fixed version, or `none yet`. |
| CVE | The CVE IDs, or `none assigned`. |
| Criticality | The severity, the CVSS score, and `Exploited in the wild` or `No known exploitation`. |
| Summary | The summary, 400 characters at most. A URL or an IPv4 address is a code span. |
| Links | Up to 3 source links, each named after its host. |
| Affected | Which products and configurations are affected, 300 characters at most. |
| Devices | Up to 5 device names with a count. |
| Action | What an operator must check or do, 300 characters at most. |
| Published | The publication date, and if the finding is new to this watch. |

A line whose fact is missing from the finding is not shown, except the first five lines.

ais truncates a message to 7000 characters. If a result has no findings, the message is a line with a green check mark. To send nothing in this case, set `skipEmpty: true` on the sink. An alert event gives a warning line with the reason, the error, and the names of the leaked fields. A result without a `findings` array is sent as a JSON code block.
With `card: true`, the message also has an Adaptive Card (version 1.3) with the same content and up to 3 `Action.OpenUrl` buttons.

CAUTION: The device names come from the enrich rules. A Webex message contains real hostnames by design. Send it only to a space that may see them.

## Task reference

A task is one YAML file in the tasks directory. The extension is `.yaml` or `.yml`. The name of each task must be unique.
The template `vuln-watch` (`assets/templates/vuln-watch/task.yaml`) is a complete example.
It checks these sources every hour:

- Primary: The Hacker News (RSS through `feeds.feedburner.com`), CERT.at, and heise Security.
- Catalogues: CISA Known Exploited Vulnerabilities, CERT-EU, Infosecurity Magazine, the RSS feeds of r/cybersecurity and r/netsec, and GitHub Security Advisories.
- Verification: the advisories of Cisco, Citrix and NetScaler, Palo Alto Networks, F5, Keycloak, Microsoft (`msrc.microsoft.com`), and Fortinet (`fortiguard.fortinet.com`), and NVD for CVE details.
- Research blogs: watchTowr Labs, Rapid7, Palo Alto Unit 42, Horizon3.ai, Assetnote, Cisco Talos, Tenable, Qualys, Mandiant / Google Threat Intelligence (`cloud.google.com`), GreyNoise, VulnCheck, Bishop Fox, ProjectDiscovery, Arctic Wolf Labs, and Sophos X-Ops (`news.sophos.com`).

The `egress.allow` list of the template names these domains. An entry with a leading dot, such as `.cert.at`, also covers the subdomains.
An unknown key is an error. Run `ais tasks validate` to check all tasks.
To change top-level keys without an editor, use `ais tasks set`.

| Key | Default | Meaning |
|---|---|---|
| `version` | `1` | Task schema version. |
| `name` | none | Required. Lowercase letters, digits, and hyphens. At most 63 characters. It starts with a letter or digit. |
| `description` | empty | Free text. |
| `enabled` | `true` | If `false`, the scheduler does not run the task. |
| `schedule` | none | Required. A cron expression with five fields, or a descriptor such as `@hourly`. |
| `jitter` | `scheduler.defaultJitter` | Maximum random delay added to each tick. `0` means no delay. |
| `overlap` | `skip` | `skip` is the only value. If a run of the task is active, the new run is recorded as `skipped`. |
| `timeout` | `claude.defaultTimeout` | Time limit of one run. |
| `model` | `claude.defaultModel` | Model name. |
| `effort` | `claude.defaultEffort` | `low`, `medium`, `high`, `xhigh`, or `max`. ais passes it to Claude Code as `--effort`. |
| `maxTurns` | `claude.defaultMaxTurns` | Turn limit. |
| `maxBudgetUsd` | `claude.defaultMaxBudgetUsd` | Cost limit of one run. |
| `inventory.file` | `inventory.file` | Inventory file for this task. |
| `inventory.format` | `auto` | Format of that file. |
| `inventory.textFile` | `inventory.textFile` | Free-text inventory for this task. The template `{{ .Text }}` gives its lines. |
| `fields` | none | Map from inventory column to `clear`, `pseudonym`, `scrub`, or `drop`. A column that is not listed is dropped. |
| `expose.prompt.groupBy` | none | List of columns. The prompt gets the distinct combinations of these columns and a count. Each column must be `clear`. |
| `expose.prompt.collect` | none | List of columns, for example `[comment]`. For each group, the prompt gets the distinct values of these columns, at most 20. Each column must be `clear` or `scrub`. |
| `expose.mcp.tools` | all three | Subset of `inventory_products`, `inventory_list`, and `results_recent`. |
| `tools` | `[WebFetch, WebSearch]` | Built-in tools of the run. No other tool is permitted. |
| `allowedTools` | `tools` plus `mcp__inventory__*` | Tools that run without a permission prompt. |
| `mcpServers` | none | Map of extra MCP servers. Each needs `type: http` and `url`. `headers` is optional. The name `inventory` is reserved. |
| `egress.allow` | none | Domains that this task needs. Each entry is a bare domain, without a scheme, path, or port. |
| `pii.redact.domains` | none | Domain suffixes for the redaction hook. |
| `pii.redact.cidrs` | none | Address ranges for the redaction hook. |
| `pii.redact.literals` | none | Exact strings. The hook and the leak check look for them. |
| `prompt` | none | Required. Go template. |
| `appendSystemPrompt` | empty | Text added to the system prompt. |
| `outputSchema` | none | JSON Schema as YAML. |
| `outputSchemaFile` | none | Path of a JSON Schema file. A relative path starts at the directory of the task file. |
| `enrich` | none | List of rules that attach inventory data to the result on the host. |
| `sinks` | none | Names of sinks from `config.yaml`. |

Exactly one of `outputSchema` and `outputSchemaFile` is necessary. ais compiles the schema when it loads the task.

The `stdio` type of MCP server is not supported, because the container has no toolchain.

### Prompt template

The `prompt` uses the Go `text/template` syntax. A reference to a missing key is an error.

| Name | Content |
|---|---|
| `.Now` | Time of the run. |
| `.Run.ID`, `.Run.Task`, `.Run.StartedAt` | Run metadata. |
| `.Groups` | List of groups. Each group has `.Fields`, `.Count`, and `.Collected`. `.Collected` maps a column from `expose.prompt.collect` to its list of values. The list is empty unless `expose.prompt.groupBy` is set. |
| `.Records` | The records after the field policy. Each record has `.Fields`. |
| `.Task` | The task. |

The functions are `join`, `lower`, `upper`, and `json`.

### Enrich rules

An enrich rule joins the result with the original inventory on the host, after the run. The model never sees the attached data.
Each rule has three keys:

- `path` selects result elements, for example `findings` or `a.b[]`.
- `match` maps a result field to an inventory column. The column must be `clear`.
- `attach` maps a new result field to a list of inventory columns. Each column must appear in `fields`.

The new field holds a list with one object for each inventory record that matches. The list can be empty.

## Commands

| Command | Meaning |
|---|---|
| `ais daemon` | Run the scheduler, the backend, and the sink dispatcher in the foreground. |
| `ais run <task>` | Run one task now. The trigger is `manual`. |
| `ais run --dry-run <task>` | Write the input files, print the container command and the file list, and start nothing. |
| `ais run --engine E <task>` | Use the engine `docker` or `podman` for this run. |
| `ais run --live <task>` | Show the progress of the run on standard error while it runs. `--follow` is an alias. See Live runs. |
| `ais run --json <task>` | Print the run, the clear result, and the leaks as JSON. |
| `ais run --no-autobuild <task>` | Fail if the image is missing or stale, instead of a build. |
| `ais tasks list [--json]` | List the tasks with the columns `NAME`, `SCHEDULE`, `NEXT`, `MODEL`, `EFFORT`, `SINKS`, and `HASH`. See Next run. |
| `ais tasks set <task> key=value...` | Change top-level keys of a task file. See Billing and task changes. |
| `ais tasks validate` | Load all tasks and report the first error. |
| `ais tasks show <task>` | Print one task as JSON, with defaults applied. |
| `ais sinks list` | List the configured sinks with type and URL. |
| `ais sinks test <sink>` | Send a built-in sample result to the sink. `--run RUN-ID` sends the clear result of that run. `--print` prints the Webex markdown and sends nothing. If the sink has `skipEmpty: true` and the event has no findings, the command prints `skipped` and sends nothing. With `--print`, it also prints a warning. It works without a configured sink. |
| `ais runs list` | List runs. Flags: `--task`, `--state`, `-n` (default 30), `--json`. The column `BILLING` shows `sub (est. $x)`. |
| `ais runs show <run-id>` | Show one run. `--clear` prints the result with the real values. `--json` prints everything as JSON. `--prompt` prints the system prompt and the prompt that ais sent. |
| `ais runs prompts` | List the logged prompts, newest first, with the run, the SHA-256 hash, and the size. Flags: `--task`, `-n`, `--json`. |
| `ais templates list` | List the task templates in the binary. `--json` prints JSON. |
| `ais templates show <name>` | Print the description and the task file of a template. |
| `ais templates use <name>` | Copy a template into the tasks directory. It sets the task name and the inventory path, and checks the task. `--as NAME` sets another task name. `--force` replaces an existing file. |
| `ais runs redeliver <run-id>` | Queue all deliveries of the run again. `--sink S` limits it to one sink. |
| `ais image build` | Build the run image from the recipe in the binary. `--no-cache` ignores the layer cache. |
| `ais image status` | Print whether the image exists and matches the recipe of this binary. |
| `ais net up` | Create the networks, start the proxy, and start the backend sidecar. |
| `ais net down` | Remove the sidecars and the networks. |
| `ais net status` | Show the networks, the sidecars, and the number of allowlist entries. |
| `ais egress list` | Print the composed allowlist. |
| `ais egress denied` | Count denied requests by host in the proxy log. `-n` sets the number of log lines (default 5000). |
| `ais egress allow DOMAIN...` | Add domains to the extra file and reload the proxy. |
| `ais egress remove DOMAIN...` | Remove domains from the extra file and reload the proxy. |
| `ais egress reload` | Compose the allowlist again and reload the proxy. |
| `ais egress logs` | Print the proxy log. `-n` sets the number of lines (default 200). |
| `ais egress status` | Same as `ais net status`. |
| `ais secret set NAME` | Store a secret. The value comes from a hidden prompt, or from standard input if it is not a terminal or you give `--stdin`. |
| `ais secret list` | List secret names with the columns `STORED`, `AGE`, `ENCRYPTED`, and `STATUS`. `ENCRYPTED` is `no` for a plaintext file. `STATUS` is set only for the OAuth token secret. Its values are `ok`, `expiring`, and `expired`. |
| `ais secret delete NAME` | Delete a secret. |
| `ais secret passphrase set` | Set the passphrase that encrypts the secrets, and encrypt every secret again. The value comes from a hidden prompt, or from standard input if it is not a terminal or you give `--stdin`. |
| `ais secret passphrase generate` | Generate a random passphrase, and encrypt every secret again. |
| `ais hook redact --rules FILE` | The PostToolUse hook. It runs inside the container. You do not run it by hand. |
| `ais config show` | Print the resolved configuration. |
| `ais doctor` | Check the engine and the host. For the OAuth token it reports `ok`, `warn` (expiring), or `fail` (expired), with the stored date and the days left. |
| `ais version` | Print the version. |
| `ais help` | Print the help text. |

### aisctl commands

| Command | Meaning |
|---|---|
| `aisctl init` | Do the complete setup. See Quickstart. It does not start the daemon until you approve the redaction policy. |
| `aisctl redact test` | Print the redaction policy and its hash. Run samples through the policy, and list inventory values that it does not cover. `--text T` adds your text. `--stdin` adds text from standard input. `--inventory FILE` uses another inventory, and `--format csv\|json\|yaml` sets its format. `--task NAME` applies the `fields` of that task. Without it, a policy based on the column names applies. `--json` prints the report as JSON. The report shows every record before and after redaction. |
| `aisctl redact approve` | Run the test, and write `pii.approvedHash` to `config.yaml`. It stops if inventory values are not covered, unless you give `--force`. Then it starts the unit if the unit is enabled and not running, or sends SIGHUP if the unit is running. The new policy applies to the next run. `--no-start` skips this last step. |
| `aisctl prompts list` | List the logged prompts from `prompts.ndjson`, newest first, with dry runs. `--task T` and `-n N` limit the list. `aisctl prompts` alone does the same. |
| `aisctl prompts last` | Show the newest prompt. `--task T` limits it to one task. |
| `aisctl prompts show <run-id>` | Show the system prompt and the prompt of a run, with the SHA-256 hash and the size in bytes. It reads the database first and then `prompts.ndjson`. |
| `aisctl run <task>` | The same as `ais run <task>`. It accepts `--live` and `--dry-run`. |
| `aisctl templates ...` | The same as `ais templates ...`. |
| `aisctl status` | Show the unit state, the network state, the checks of `ais doctor`, and the health of the daemon. |
| `aisctl up` | Start the unit. |
| `aisctl down` | Stop the unit. `--network` also removes the sidecars and the networks. |
| `aisctl update` | Install a changed ais binary, rebuild a stale image, restart the unit, and wait for health. |
| `aisctl logs` | Show the journal of the unit. `-f` follows it. `-n` sets the number of lines (default 200). |
| `aisctl uninstall` | Stop and disable the unit. Remove the sidecars, the networks, the unit file, and the ais binary. |
| `aisctl version`, `aisctl help` | Print the version, or the help text. |

Options of `aisctl init`:

| Option | Meaning |
|---|---|
| `--engine auto\|docker\|podman` | Container engine. Default: `auto`. |
| `--egress proxy\|open` | Egress mode. Default: `proxy`. |
| `--timezone ZONE` | Scheduler timezone. Default: `Local`. |
| `--claude-version V` | Claude Code version in the image. |
| `--image REF` | Pull a prebuilt run image, and do not build one. `aisctl init` writes `runtime.image` with this value to `config.yaml`. |
| `--ais-binary PATH` | The ais binary to install. Default: a file named `ais` next to `aisctl`, then a file named `ais` on `PATH`, then `aisctl` itself. |
| `--token-file PATH` | File with the OAuth token. Without it, ais uses `CLAUDE_CODE_OAUTH_TOKEN`, then a hidden prompt. If the secret exists already, `aisctl init` keeps it unless you give this option. |
| `--passphrase-file PATH` | File with the passphrase for the secret store. Without it, `aisctl init` generates a random passphrase if none exists. |
| `--inventory PATH` | Install this file as `~/.config/ais/inventory.csv`. |
| `--inventory-text PATH` | Install this file as `~/.config/ais/inventory.txt`, the free-text inventory. |
| `--template NAME` | Install the task template `NAME` into the tasks directory. The option can repeat. `ais templates list` shows the names. |
| `--force` | Apply the setup again over an existing setup. |
| `--no-start` | Write everything, and start nothing. |
| `--no-linger` | Do not run `loginctl enable-linger`. |
| `--wait DURATION` | Time to wait for health. Default: `60s`. |

Options of `aisctl update`: `--claude-version V`, `--image REF`, `--ais-binary PATH`, `--skip-health`, and `--wait DURATION` (default `60s`).
With `--claude-version` or `--image`, `aisctl update` also writes `image.claudeVersion` or `runtime.image` to `config.yaml`.
Options of `aisctl uninstall`: `--purge-state` also removes the state directory. `--purge-all` also removes the configuration, the tasks, and the secrets. It asks first, unless you give `--yes`.
`aisctl uninstall` keeps the run image and the `aisctl` binary.

Flags can appear before or after the positional arguments for `ais run`, `ais runs show`, `ais runs redeliver`, and `ais secret set`.

### Live runs

With `ais run <task> --live` (or `--follow`, or `aisctl run <task> --live`), you see the progress of the run on standard error. ais starts Claude Code with `--output-format stream-json --verbose` and shows each event when it arrives:

| Line | Meaning |
|---|---|
| Header | The run ID and the hash of the prompt. |
| `▶ session started` | The model, the tools, and the state of the MCP servers. |
| `💬` | Text from the model. |
| `🔧 <tool> <input>` | A tool call. |
| `↩` and `✖` | A tool result, or a tool error. ais shortens the text to 300 characters. |
| `■ result` | The result subtype, the number of turns, and the estimated cost. |

ais still saves the complete stream in `stdout.json`. The leak check, the validation, the prompt log, and the delivery work as in a normal run. The result envelope is the last line of the stream.

### Next run

The daemon knows the exact time of the next tick of each task, including the jitter. The operator API shows it in `GET /api/v1/tasks` with the fields `next` and `paused`, and the task `effort`.
The column `NEXT` of `ais tasks list` shows one of these values:

- The exact time from the running daemon.
- `paused (reason)`, if the task is paused.
- `disabled`, if the task is disabled.
- `daemon: not scheduled`, if the daemon does not have the task.
- If no daemon answers: the time that the cron expression gives, with a leading `~` and the text `(daemon not running)`.

`aisctl status` prints a line `next run <task> <time>` for each task, when the daemon is healthy.

### Billing and task changes

ais runs only on a subscription OAuth token. The cost figures are the list-price estimates of Claude Code. They are not invoices.
They still drive `maxBudgetUsd` and `scheduler.dailyBudgetUsd`.

- `ais runs list` shows `sub (est. $x)` in the column `BILLING`.
- `ais runs show` prints `billing: subscription (est. $x at API list prices)`.
- Every sink event has `meta.billing` with the value `subscription`.

`ais tasks set <task> key=value...` changes top-level keys of a task file in place. The keys are `model`, `effort`, `schedule`, `jitter`, `timeout`, `maxTurns`, `maxBudgetUsd`, `enabled`, `overlap`, and `sinks`. For `sinks`, write a comma-separated list, for example `sinks=webex,splunk`.
The command keeps the comments and the other keys. It checks the new file before it replaces the old one. It keeps the old file as `<name>.bak-<timestamp>`. Then it tells you to send SIGHUP to the daemon.
To map a task to sinks, use `ais tasks set <task> sinks=a,b` or edit `sinks:` in the task file.

### Token format

A token with a line break breaks the run (`invalid_credential_header`). For this reason:

- `aisctl init` (from `--token-file`, the environment, or the prompt) and `ais secret set` for the OAuth token remove all whitespace from the token.
- The runner does not start a container if the stored token still has whitespace. It records a `skipped` run with the reason `config`.
- `ais doctor` fails the `credentials` check for such a token.

## Security model

### Container posture

A run container has these properties:

- The root filesystem is read-only.
- The command line has `--cap-drop=ALL` and `--security-opt no-new-privileges`.
- The limits for processes, memory, swap, and CPUs come from the `runtime` keys.
- The directories `/tmp`, `/run/ais/cfg`, `/run/ais/home`, and `/run/ais/work` are tmpfs mounts. They are `nosuid`, `nodev`, and `noexec`.
- The container has exactly one writable bind mount: the `out/` directory of the run.
- The `in/` directory and the ais binary are mounted read-only.
- Secrets pass by environment variable name only: `CLAUDE_CODE_OAUTH_TOKEN` and `AIS_RUN_TOKEN`. The values do not appear in the command line.
- Docker runs the process with `--user <uid>:<gid>`. Podman uses `--userns=keep-id`.
- The image removes the setuid and setgid bits from all files.
- The entrypoint refuses to start if `ANTHROPIC_API_KEY` is set, because the key would override the OAuth token.
- Claude Code starts with `--restricted`, `--permission-mode dontAsk`, and `--permission-prompts none`. The generated settings deny `Bash`, `Edit`, `Write`, `Read`, `Glob`, `Grep`, `Agent`, `Task`, `NotebookEdit`, and `MultiEdit`.

On a host where SELinux is enforcing, ais adds the `z` option to bind mounts.

### Egress

In `proxy` mode, the container is on the internal network `ais-internal`. This network has no route out.
The only way out is a squid proxy at the address ending in `.2`. The proxy is on the internal network and on the network `ais-egress`.
The proxy allows a request only if the client is in the subnet and the destination domain is on the allowlist.
The decision uses the domain. The port is not part of it.

ais composes the allowlist from these sources, in this order:

1. The list of domains in the binary that Claude Code needs: `api.anthropic.com`, `platform.claude.com`, and `claude.ai`.
2. The key `egress.baseAllowlist`.
3. The key `egress.allow` of every task.
4. The extra file `egress-extra.acl`, in the parent directory of the tasks directory. `ais egress allow` and `ais egress remove` change it. You can also edit it by hand.

An entry is a domain such as `www.cyberdyne.example`. An entry with a leading dot, such as `.cyberdyne.example`, matches the domain and all subdomains.

WebFetch runs inside the container. The domain of every feed that a task reads must be on the allowlist.
WebSearch runs on the server side. It needs no entry.

To find missing entries, run the task, and then run `ais egress denied`. The output lists the denied hosts and the number of requests. A feed can redirect to a CDN host. Such a host shows up in the output. Add it to the allowlist.

### Pseudonymization

ais has three tiers. Each tier is independent.

1. Minimization. `expose.prompt.groupBy` gives the model only the distinct combinations of some columns and a count. The model sees no device.
2. Tokenization. The key `fields` sets a mode for each column:
   - `clear` passes the value to the model.
   - `pseudonym` replaces the value with a token. The same value gives the same token in every run of the task. Different tasks give different tokens. The token form depends on the column and on `pii.hostnameMode` and `pii.ipMode`. See Redaction policy.
   - `scrub` is for free text such as a comment. The text goes through the redaction policy. Hostnames, addresses, and literals in it change, and the rest stays. ais uses the salt of the task, so an address in a comment matches the token of the same address in an address column. The host can reverse it.
   - `drop` removes the column.

   The map from token to value stays on the host, in the database. After the run, ais replaces the tokens in the result with the real values. Enrich rules then attach device identity.
3. Defence in depth.
   - The PostToolUse hook `ais hook redact` runs in the container after `WebFetch`, `WebSearch`, and MCP tools. It rewrites hostnames, addresses, and literals in tool output according to the redaction policy. If the hook fails, it exits with code 0 and leaves the output unchanged.
   - A leak check runs on the host. It searches the complete standard output of the container for each real value of the token map and for each literal. It ignores case and skips values of fewer than three characters. If it finds a value, the run state is `leaked` and ais sends no result to the sinks. The database keeps the pseudonymized result only.

The leak check does not know values of `drop` columns, and it does not use the domain and address rules. Add such values as `pii.literals`.

NOTE: The file `redact.json` is in the `in/` directory, which is mounted in the container. It lists the domain suffixes, the address ranges, the literals, the two modes, and the random key of the run for `cgnat` in clear text.

### Redaction policy

The redaction policy has five parts: `pii.domains`, `pii.cidrs`, `pii.literals`, `pii.hostnameMode`, and `pii.ipMode`. It applies in two places:

- To inventory columns with the mode `pseudonym`. A column named `hostname`, `host`, or `fqdn` is a hostname column. A column named `ip`, `ipv4`, `ipv6`, or `address` is an address column.
- To the output of tools, through the PostToolUse hook.

The modes work like this:

| Mode | Effect |
|---|---|
| `rot13` | Rotate the letters of a hostname by 13. Digits and dots stay. The rotation is its own inverse. `fw01.cyberdyne.systems` becomes `sj01.ploreqlar.flfgrzf`. |
| `cgnat` | Map an IPv4 address in the configured ranges to an address in `100.64.0.0/10`. The mapping is a keyed hash, so the same address gives the same result. |
| `token` | For an inventory column, use an opaque token such as `host-1a2b3c4d` or `ip-5e6f7a8b`. In tool output, use `[redacted]`. |

Details:

- For inventory columns, the key of `cgnat` is the salt of the task. An IPv6 address in an inventory column gets an opaque token.
- In the hook, the key of `cgnat` is a random key for each run. An address that the hook rewrites never matches an inventory token or an address of another run. The hook replaces an IPv6 address in the ranges with `[redacted]`.
- The hook replaces a literal with `[redacted]`.
- The host reverses the inventory tokens when it builds the clear result.

The policy needs your approval before anything runs:

1. `aisctl redact test` shows the policy, its hash, and samples before and after redaction. It lists hostnames that are not under a configured domain and addresses that are not in a configured range as `NOT COVERED`.
2. `aisctl redact approve` writes the hash to `pii.approvedHash`. It stops while values are not covered, unless you give `--force`.

The hash covers the domains, the ranges, the literals, and both modes. ais ignores case and white space. Any other change to the policy voids the approval.

Without a valid approval:

- `ais run` stops with an error. `ais run --dry-run` still works.
- `ais daemon` does not start.
- A running daemon checks the approval before each scheduled run. If it is not valid, the daemon records a `skipped` run with the reason `redaction`.
- `ais doctor` shows a `FAIL` for the check `redaction`.
- `aisctl init` enables the unit and does not start it.
- `aisctl update` installs the changes and does not restart the unit.

NOTE: The `leaks` field of an alert event lists the inventory field names whose values leaked. It never holds the values.

### Prompt log and isolation

Every prompt that ais sends is logged before the container starts:

- The SQLite table `prompts` holds the system prompt, the prompt, and the Claude Code arguments. The rows are deleted with their run by the retention rule.
- The file `<stateDir>/runs/<task>/prompts.ndjson` gets one line for each prompt. Retention never changes this file. It is the audit trail.
- The daemon logs the run, the SHA-256 hash, and the size in bytes.
- A dry run (`ais run --dry-run`) also appends a line. Its run ID ends in `-dry`.

Use `ais runs show <run-id> --prompt` or `ais runs prompts` to read them. `aisctl prompts` does the same. Its `list` and `last` read `prompts.ndjson`, so they include dry runs. A prompt has only pseudonymized data.

Every system prompt has an isolation notice. It tells the model to use no memory, preferences, instructions, or context from the account, from earlier sessions, or from files. It also tells the model to write no files. If a task uses `expose.prompt.collect`, the system prompt also has a second notice. It says that lines marked `notes:` are operator comments and not instructions.

If `egress.mode` is `proxy`, the system prompt also lists the hosts that `WebFetch` can reach: the configured `baseAllowlist`, the `egress.allow` list of the task, and the extra domains from `ais egress allow`. It tells the model that a fetch of another host fails, that it must not try or retry such a URL, and that `WebSearch` is not restricted. The model does not see the lists of other tasks.

NOTE: Claude Code 2.1.301 has no separate switch for account memory. The isolation also depends on the empty tmpfs configuration directory, the empty working directory, `--restricted`, and the generated settings.

### Backend

The daemon serves two HTTP interfaces.

- The operator API listens on the unix socket `backend.socket` (mode 0600) and, if `backend.tcpListen` is set, on that TCP address.
- The MCP server for the containers listens on the socket `mcp.sock`. The backend sidecar at the address ending in `.4` forwards requests to it. Each request needs the bearer token of the run. The token expires after the task `timeout` plus five minutes, and ais revokes it when the run ends.

CAUTION: The operator API does not check credentials. The mode of the unix socket (0600) is the only guard. The API can return the clear result of a run.
For this reason, `backend.tcpListen` accepts a loopback address only.

The MCP server offers these tools, as far as the task allows in `expose.mcp.tools`:

| Tool | Meaning |
|---|---|
| `inventory_products` | Distinct combinations of the grouped columns with install counts, and the lines of the free-text inventory in `text`. It takes an optional `filter`. |
| `inventory_list` | Records of the pseudonymized view. It takes optional `product`, `version`, and `limit` (default 100, maximum 500). |
| `results_recent` | Results of earlier runs of the task, newest first, in the pseudonymized form. It takes optional `since` and `limit` (default 10, maximum 50). |

In `open` mode, the run has no inventory MCP server.

### Secrets

ais encrypts each secret file with AES-256-GCM. The key comes from a passphrase with PBKDF2-SHA256 (600000 iterations) and a random salt for each file. The file format is `ais-enc-v1:` followed by base64 text.
The passphrase is in `<secrets.dir>/.passphrase` (mode 0600).

- The first `ais secret set` generates a random passphrase if none exists. `aisctl init` does the same, or reads the passphrase from `--passphrase-file`.
- `ais secret passphrase set` and `ais secret passphrase generate` change the passphrase and encrypt every secret again. They fail if a secret cannot be read with the old passphrase.
- A plaintext file that you write by hand is still readable. `ais secret list` shows `ENCRYPTED` as `no`, and `ais doctor` warns for every plaintext secret. Run `ais secret set NAME` to encrypt it.
- ais reads a systemd credential as it is. The credentials are `$CREDENTIALS_DIRECTORY/NAME` for a secret and `$CREDENTIALS_DIRECTORY/ais-passphrase` for the passphrase.

NOTE: The encryption protects against a casual read of the secret files, for example in a backup or a copied home directory.
It does not protect against root, or against anyone who can read the passphrase file on the same host. ais trusts the host.

## Operations

### Daemon

`ais daemon` runs in the foreground. At start it does these steps:

1. Load the configuration and the tasks.
2. Check the engine and the token secret.
3. Build the image if necessary.
4. Start the proxy (in `proxy` mode).
5. Open the sockets.
6. Start the backend sidecar (in `proxy` mode).
7. Start the dispatcher, the retention loop, and the scheduler.

Set `AIS_LOG_FORMAT=json` for JSON logs on standard error.

### Scheduler

- A schedule is a cron expression with five fields, or a descriptor such as `@hourly`. The timezone is `scheduler.timezone`.
- The scheduler adds a random delay between zero and the jitter to each tick.
- If a run of the same task is active, the new run is `skipped` with the reason `overlap`.
- `scheduler.maxParallel` limits the runs at the same time.
- If `scheduler.dailyBudgetUsd` is more than 0, the scheduler adds up the cost since midnight in the scheduler timezone. When the sum reaches the limit, the scheduler records a `skipped` run with the reason `budget`. This limit does not apply to `ais run`.
- The scheduler does not replay ticks that it missed while the daemon was off.
- After `scheduler.pauseAfterAuthFailures` consecutive failures with the reason `auth`, the daemon pauses the task. Create a new token with `claude setup-token`, run `ais secret set claude-oauth-token`, and send SIGHUP to the daemon or restart it. The pause is not saved.

### Reload and stop

- SIGHUP loads the task files again and clears all pauses. A task whose file did not change keeps its loop. In `proxy` mode, ais also composes the proxy allowlist again. If a task file has an error, ais keeps the old tasks.
- The daemon builds the sinks at start. After you add or change a sink, restart the daemon.
- SIGHUP also reads `config.yaml` and applies its `pii` section. For a change in any other section, the daemon logs that a restart is necessary. Restart the daemon to apply such a change.
- SIGTERM and SIGINT cancel the active runs and wait up to 80 seconds. Cancelled runs have the state `cancelled`.

### systemd

`aisctl init` installs the unit. The file `assets/systemd/ais.service` is a Go template. `aisctl` replaces `{{ .ExecStart }}` with the path of the installed ais binary and adds `Environment` lines if it has any.

To install the unit by hand, replace `{{ .ExecStart }}` with the path of the ais binary. Also delete the three template lines: the `range` line, the `Environment={{ . }}` line, and the `end` line. Then run:

    install -D -m 0644 ais.service ~/.config/systemd/user/ais.service
    systemctl --user daemon-reload
    systemctl --user enable --now ais
    loginctl enable-linger "$USER"

The unit runs `<ais binary> daemon`. It restarts on failure, waits 10 seconds, and sets `AIS_LOG_FORMAT=json`.
`ais` reads `$CREDENTIALS_DIRECTORY/NAME` before it reads the secret store. It reads such a file as it is, without decryption. For the passphrase, the credential name is `ais-passphrase`.
To use this, remove the comment mark from the `LoadCredential` line of the unit.

### Token rotation

The daemon checks the age of the token once a day. In the warning period, it logs a warning. After `claude.tokenLifetime`, it logs an error. `ais doctor` and `ais secret list` show the same state.
To rotate the token:

1. Run `claude setup-token`.
2. Run `ais secret set claude-oauth-token`.
3. Send SIGHUP to the daemon. This clears the pause of tasks that stopped after authentication failures.

The daemon reads the token at the start of each run. A restart is not necessary.

### Runs and states

Each run has a directory `<stateDir>/runs/<task>/<run-id>/`:

| Path | Content |
|---|---|
| `in/` | Input files, read-only in the container: `prompt.md`, `system.md`, `schema.json`, `mcp.json` (optional), `settings.json`, `redact.json`, `argv.json`, `inventory.pseudo.json`. The last file holds the groups, the records, and the free-text lines in `text`. |
| `out/` | The only writable directory of the container. ais reads the result from standard output, not from here. |
| `stdout.json` | Standard output of the container. |
| `stderr.log` | Standard error of the container. |
| `result.json` | Result in the pseudonymized form. |
| `result.clear.json` | Result with the real values. It exists only if the run succeeded. |

The file `<stateDir>/runs/<task>/runs.ndjson` has one line for each successful run. The file `prompts.ndjson` in the same directory has one line for each prompt. The file `ais.db` in the state directory stores runs, salts, token maps, results, leaks, prompts, and deliveries.

A run has one of these states:

| State | Meaning |
|---|---|
| `queued`, `running` | Not finished. |
| `succeeded` | The result is valid and the leak check found nothing. |
| `failed` | See the reason. |
| `leaked` | The leak check found real values. ais sends no result. |
| `timeout` | The run took longer than the task `timeout`. |
| `skipped` | ais did not start the run. See the reason. |
| `cancelled` | The daemon stopped during the run. |

The `Reason` column of `ais runs list` has one of these values:

| Reason | Meaning |
|---|---|
| `overlap` | A run of the task was active. |
| `auth` | The token was rejected. This includes an `api_error` in the result that has `credential` or `auth` in it. |
| `config` | The entrypoint exited with code 78: a missing token, a set `ANTHROPIC_API_KEY`, or a missing input file. Also, the stored token has whitespace (`skipped`). |
| `engine` | The container engine failed. |
| `exit` | The container ended without a result. |
| `budget` | The daily budget was reached (`skipped`), or the run reached `maxBudgetUsd` (`failed`). |
| `turns` | The run reached `maxTurns`. |
| `schema` | The output did not match the schema, or an enrich rule failed. |
| `timeout` | The time limit passed. |
| `leak` | The leak check found a value. |
| `redaction` | The redaction policy is not approved (`skipped`). |
| `model` | Claude Code reported an error. |

### Delivery and redelivery

When a run succeeds, ais queues one delivery for each sink of the task. When a run ends as `leaked`, `failed`, or `timeout`, ais queues an alert for each sink in `alerts`.
The dispatcher in the daemon checks the queue every five seconds.

- A response with status 2xx completes the delivery.
- A response with status 429 or 5xx, or a network error, causes a new attempt. The delay starts at `delivery.backoff.initial`, doubles for each attempt, and stops at `delivery.backoff.max`. ais adds up to 25 percent of random delay.
- Any other 4xx status, a template error, or an unknown sink makes the delivery `dead` at once.
- After `delivery.maxAttempts` attempts, the delivery is `dead`.
- If the sink has `skipEmpty: true` and the result has no findings, ais does not call the sink. The delivery is `skipped`, `ais runs show` gives the reason, and ais does not try again.

To send the results of a run again, run `ais runs redeliver <run-id>`. The command resets all deliveries of the run, or of one sink with `--sink`, including completed ones.
The daemon sends them. `ais runs show <run-id>` lists the state of each delivery.

The NATS sink sets a message ID of the form `<run-id>/<kind>/<sink>`. JetStream uses it to detect a duplicate.

### Retention

Once an hour, the daemon deletes finished runs of each task. It deletes the runs beyond `retention.keepRuns` and the runs older than `retention.keepDays`.
It removes the database rows and the run directories. Runs that are `queued` or `running` stay.

### Image

`ais image build` writes the recipe from the binary into a temporary directory and builds the image. The build tags the image with a hash of the recipe.
If the hash does not match the binary, the image is stale. `ais run` and `ais daemon` build it again if `image.autobuild` is `true`.
After the build, ais runs `claude --help` in the image. It fails if the help text does not show a flag that ais uses.

## Files

| Path | Content |
|---|---|
| `~/.config/ais/config.yaml` | Configuration. |
| `~/.config/ais/tasks/*.yaml` | Tasks. |
| `~/.config/ais/secrets/` | Secrets, one encrypted file for each secret. The directory has mode 0700 and the files have mode 0600. |
| `~/.config/ais/secrets/.passphrase` | Passphrase of the secret store (mode 0600). |
| `~/.config/ais/egress-extra.acl` | Hand-edited allowlist entries. |
| `~/.config/systemd/user/ais.service` | The systemd user unit, written by `aisctl init`. |
| `~/.local/state/ais/ais.db` | SQLite database (mode 0600). |
| `~/.local/state/ais/runs/` | Run directories. |
| `~/.local/state/ais/egress/` | `squid.conf` and `generated.acl`, written by ais. Do not edit them. |
| `~/.local/state/ais/backend.sock`, `mcp.sock` | Sockets of the daemon. |

## Environment

| Variable | Meaning |
|---|---|
| `AIS_CONFIG` | Path of the configuration file. |
| `XDG_CONFIG_HOME` | Base directory for `ais/config.yaml`. |
| `AIS_ENGINE` | `runtime.engine`. |
| `AIS_IMAGE` | `runtime.image`. |
| `AIS_STATE_DIR` | `paths.stateDir`. |
| `AIS_TASKS_DIR` | `paths.tasksDir`. |
| `AIS_EGRESS` | `egress.mode`. |
| `AIS_EGRESS_SUBNET` | `egress.subnet`. |
| `AIS_SECRETS_DIR` | `secrets.dir`. |
| `AIS_CA_CERTS` | `image.caCertificates`. |
| `AIS_AUTOBUILD` | `image.autobuild`. `1` or `true` turns it on. Any other value turns it off. |
| `AIS_LOG_FORMAT` | `json` selects JSON logs for the daemon and for `ais run`. |
| `CREDENTIALS_DIRECTORY` | systemd credential directory. ais reads secrets from it first, and reads the passphrase from the file `ais-passphrase` in it. |

## Exit status

| Code | Meaning |
|---|---|
| 0 | The command succeeded. For `ais run`, the run succeeded. |
| 1 | The command failed. For `ais run`, the run did not succeed. For `ais doctor`, a check failed. |
| 2 | A usage error in `ais run`. For `aisctl`, an unknown command, an unknown option, or no command. |

## Limitations

- Rootful docker: `ais doctor` warns. A container escape lands as root. The mitigations are the read-only root filesystem, `--cap-drop=ALL`, `no-new-privileges`, and the single writable mount. Rootless podman does not have this risk.
- Two flags of Claude Code are hidden: `--max-turns` and `--append-system-prompt-file`. The `--help` text does not show them, so the check in `ais image build` cannot detect a change. ais also sets `CLAUDE_CODE_MAX_TURNS` as a fallback for `--max-turns`.
- The Containerfile runs apt with `Acquire::Check-Date=false`. Without it, apt refuses a Release file with a date after the clock of the build host. A host with a slow clock then fails every build. apt still checks the signatures. Only the date comparison is off.
- The module needs Go 1.26.0 or later (`go.mod`).
- The scheduler does not replay missed ticks.
- A pause after authentication failures is in memory. SIGHUP or a restart of the daemon clears it.
- `ais run` does not apply the daily budget and the pause.
- `overlap: skip` is the only overlap mode.
- A task can use only the tools `WebFetch` and `WebSearch`, and MCP servers of type `http`.
- In `open` mode, the run has no inventory MCP server.

## Examples

List the last runs of a task, then show the clear result of one run:

    ais runs list --task vuln-watch -n 5
    ais runs show --clear 20260101T000000Z-0a1b

Call the operator API:

    curl --unix-socket ~/.local/state/ais/backend.sock 'http://localhost/api/v1/runs?limit=5'

The API has these paths:

- `GET /healthz`
- `GET /api/v1/tasks`
- `GET /api/v1/runs` with the optional parameters `task`, `state`, and `limit`
- `GET /api/v1/runs/{id}`
- `GET /api/v1/runs/{id}/result`, with `view=clear` for the real values
- `POST /api/v1/runs/{id}/redeliver`, with the optional parameter `sink`
- `GET /api/v1/inventory?task=NAME`

## See also

`docs/ARCHITECTURE.md`, `CHANGELOG.md`, `assets/examples/`
