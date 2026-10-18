# ais architecture

This document describes how ais works inside. For installation and configuration, read `README.md`.

## Data flow of one run

The package `internal/runner` does a run from start to end. A scheduled tick and `ais run` use the same code.

1. The runner takes an exclusive `flock` on `<runs>/<task>/.lock`. The runner records a run with the state `skipped` and the reason `overlap` in two cases. The first case is a busy lock. The second case is a `queued` or `running` run in the database that started less than twice the task `timeout` ago. The new run stops here.
2. The runner reads the token from the secret store. The secret name is `claude.oauthTokenSecret`.
3. `Prepare` creates the run directory with `in/` and `out/` (mode 0700). It loads the inventory and the free-text inventory, if `inventory.textFile` is set. For each key, the task value applies when the task sets it, and `inventory` in the configuration otherwise.
4. `Prepare` gets the salt of the task from the database and applies the field policy. The tokenizer uses `pii.hostnameMode` and `pii.ipMode`. Each `pseudonym` value becomes a token, and the token map is filled. Columns that are not in `fields` are dropped. Each free-text line goes through the same redactor as a `scrub` column.
5. If the task sets `expose.prompt.groupBy`, `Prepare` builds the minimized groups from the pseudonymized records.
6. `Prepare` merges the redaction rules: `pii.domains`, `pii.cidrs`, and `pii.literals` from the configuration, then the `pii.redact` lists of the task. It adds `pii.hostnameMode`, `pii.ipMode`, and a random 32-byte key for the `cgnat` mapping in the hook.
7. In `proxy` mode, `Prepare` sets the backend URL to `http://<subnet>.4:<mcpPort>/mcp` and sets the proxy variables. In `open` mode, there is no backend URL and the run has no inventory MCP server.
8. `internal/prompt` renders the files in `in/`: `prompt.md`, `system.md`, `schema.json`, `mcp.json` (optional), `settings.json`, `redact.json`, `argv.json`, and `inventory.pseudo.json`.
9. The runner builds the container specification, inserts the run as `running`, and saves the token map in the database before the container starts. A crash during the run does not lose the map. The runner also logs the prompt (see Prompt log).
10. The runner creates a bearer token for the run. The token lives for the task `timeout` plus five minutes. The database holds only its SHA-256 hash.
11. The runner starts the container with a timeout equal to the task `timeout`. It passes `CLAUDE_CODE_OAUTH_TOKEN` and `AIS_RUN_TOKEN` through the environment of the engine command. It copies standard output to `stdout.json` and standard error to `stderr.log`. Each stream is limited to 32 MiB in memory.
12. The runner classifies the result (see Outcome classification).
13. If the run is valid, the runner does the leak check on the complete standard output.
14. If the leak check finds nothing, the runner replaces the tokens with the real values and applies the enrich rules to the original inventory records.
15. The runner writes `result.json` (pseudonymized), `result.clear.json` (clear), and one line in `runs.ndjson`. It saves both result views in the database.
16. The runner revokes the run token, finishes the run in the database, and queues deliveries.

The entrypoint of the container (`assets/entrypoint.sh`) does these steps:

1. It exits with code 78 if `CLAUDE_CODE_OAUTH_TOKEN` is not set, if `ANTHROPIC_API_KEY` is set, or if `argv.json`, `prompt.md`, or `settings.json` is missing from `in/`.
2. It copies `settings.json` to the configuration directory in tmpfs and writes a `.claude.json` that marks the onboarding as done.
3. It reads `argv.json` with `jq`, one element for each line.
4. It runs `claude` with the argument list and gives `prompt.md` on standard input.

`tini` is the init process (PID 1) of the container. A stop signal reaches `claude`, and `tini` collects zombie processes.

### Claude Code arguments

`internal/claude` builds `argv.json`. The arguments are, in order:

- `-p` and `--output-format json`. For a live run (`ArgsInput.Stream`), `--output-format stream-json --verbose`.
- `--json-schema` with the schema of the task
- `--model`, `--effort`, `--max-turns`, and `--max-budget-usd`
- `--tools` and `--allowedTools`
- `--permission-mode dontAsk` and `--permission-prompts none`
- `--restricted`
- `--settings /run/ais/in/settings.json` and `--setting-sources user`
- `--no-session-persistence`
- `--mcp-config /run/ais/in/mcp.json` and `--strict-mcp-config`, if the run has MCP servers
- `--append-system-prompt-file /run/ais/in/system.md`

An argument must not contain a newline. If one does, `Prepare` fails.

The generated `settings.json` sets `permissions.defaultMode` to `dontAsk` and denies ten tools. If the ais binary is available, it also adds a PostToolUse hook. The hook matcher is `mcp__.*|WebFetch|WebSearch`, and the command is `/run/ais/bin/ais hook redact --rules /run/ais/in/redact.json` with a timeout of 10 seconds.

### Outcome classification

The function `execute` in `internal/runner/run.go` maps what happened to a state and a reason. It tests the cases in this order:

| Condition | State | Reason |
|---|---|---|
| The run context ended. If the daemon was stopping: | `cancelled` | `timeout` |
| The run context ended. If the task `timeout` passed: | `timeout` | `timeout` |
| The engine command failed to run | `failed` | `engine` |
| Standard output has no result envelope, and the exit code is 78 | `failed` | `config` |
| No envelope, and the text looks like an authentication error | `failed` | `auth` |
| No envelope, other cases | `failed` | `exit` |
| The envelope or standard error shows an authentication error. The `api_error` field with `credential` or `auth` counts as one | `failed` | `auth` |
| Subtype `error_max_budget_usd` | `failed` | `budget` |
| Subtype `error_max_turns` | `failed` | `turns` |
| Subtype `error_max_structured_output_retries` | `failed` | `schema` |
| Another error subtype, or `is_error` is true with the subtype `success` | `failed` | `model` |
| The output does not match the schema | `failed` | `schema` |
| The leak check finds a value | `leaked` | `leak` |
| The enrich rules fail | `failed` | `schema` |
| None of the above | `succeeded` | empty |

When the context ends, the runner stops and removes the container by name.

The runner checks the structured output twice. Claude Code checks it with `--json-schema`, and the host checks it again before the result can reach a sink.

## Live runs

`ais run --live` sets `Options.Live` to standard error. `Prepare` then asks `claude.Args` for `stream-json` output. The runner puts a `liveWriter` in front of the standard output capture. For each line, the writer calls `claude.RenderStreamLine`. It prints one line for each of these events: the session start, the model text, a tool call, a tool result, and the final result. A tool result has at most 300 characters.
The capture in `stdout.json` still gets every line. `ParseEnvelope` finds the result envelope in the last line. For this reason, the classification, the schema check, the leak check, and the prompt log are the same as for a normal run.

## Next run

`Scheduler.Next` returns the next time of each task, with jitter, and the pause reason. The operator handler `GET /api/v1/tasks` adds them to each task row as `next` and `paused`, with `effort`.
`ais tasks list` asks the daemon over the operator socket (`daemonTasks`). `nextColumn` formats the answer. If the socket does not answer, it computes the time with `scheduler.NextRun` and marks it as an estimate. `aisctl status` uses the same endpoint.

## Packages

| Package | Role |
|---|---|
| `cmd/ais` | The program entry point. It calls `app.Main`. |
| `assets` | Embedded files: Containerfile, entrypoint, squid template, allowlists, examples, systemd unit. |
| `cmd/aisctl`, `internal/aisctl` | The installer and lifecycle tool `aisctl`. `cmd/ais` and `cmd/aisctl` build the same program. Each entry point checks `filepath.Base(os.Args[0])` and starts `aisctl.Main` or `app.Main`. `inventory.go` holds the `aisctl inventory` subcommands. They pseudonymize with `pseudo.Redactor`, keep the map in `inventory.redact-map.json` in the state directory, and back up the file before each write. |
| `internal/app` | The command line. It parses arguments and calls the other packages. It also holds the daemon loop, the retention loop, and the digest loop (`digestLoop`). |
| `internal/config` | Defaults, YAML file, environment variables, and validation of the configuration. |
| `internal/task` | The task schema, defaults, validation, and loading from a directory. |
| `internal/inventory` | Reads CSV, JSON, YAML, and `mdj` inventories, and the free-text inventory. Builds the minimized groups and gathers the collected values. `Document` is the parsed `mdj` structure: entries with a title, ordered JSON values, and sections. `mdj.go` parses it and writes it again (round trip). `panorama.go` reads a Panorama CSV export and merges it into a `Document`. The grouping adds the reserved field `count` (`CountField`). The records view has the field `title`. |
| `internal/templates` | The task templates in the binary: list, show, and install. |
| `internal/pseudo` | Field policy, tokens, token map, depseudonymization, redactor, and leak check. |
| `internal/feed` | Fetches RSS 2.0, Atom, RDF, and CISA KEV JSON feeds on the host (`FetchAll`, at most four at a time). It reduces each entry to an `Item` with a `Key`: a hash of the GUID, else the link, else the title. A failed feed has `Err` set and no items. |
| `internal/prompt` | Renders the prompt and the other input files. |
| `internal/claude` | The Claude Code argument list, the result envelope, and output validation. |
| `internal/container` | The container specification and its translation to an engine command line. It has the docker and podman dialects. |
| `internal/runtime` | Runs the `docker` or `podman` command. It detects the engine. It also has a fake runtime for tests. |
| `internal/runner` | Does one run, from the run directory to the stored result. |
| `internal/egress` | Networks, the squid sidecar, and the allowlist. |
| `internal/backend` | The operator API, the MCP server, run tokens, and the reverse proxy for the sidecar. |
| `internal/scheduler` | Cron loops, jitter, parallel limit, reload, and pause. |
| `internal/store` | The SQLite database. |
| `internal/sink` | The webhook, NATS, Splunk, and Webex sinks, and the dispatcher. `digest.go` builds the digest event and queues the digest delivery (`QueueDigest`). |
| `internal/secret` | The encrypted secret store, the passphrase, and the `${secret:NAME}` expansion. |
| `internal/image` | The image recipe hash, the build, and the check of the Claude Code flags. |
| `internal/doctor` | The checks of `ais doctor`. |
| `internal/output` | Output to the terminal. Status goes to standard error. Data goes to standard output. |

## Container argv

`container.Spec` is plain data. `Spec.Argv` turns it into a command line. `ais run --dry-run` prints the same list that a real run executes. The order of the flags is fixed.

The two engines differ in only two places. `Dialect` holds them:

| Item | Docker | Podman |
|---|---|---|
| Process user | `--user <uid>:<gid>` | `--userns=keep-id:uid=<uid>,gid=<gid>` |
| Network with a fixed address | `--network name=<net>,ip=<ip>` | `--network <net>:ip=<ip>` |

For docker, the user is `runtime.user`. If it is `auto`, it is the uid and gid of the ais process. This lets the process write the `out/` directory, which the same user owns.
For podman, the uid and gid are 1000, the user of the image. The keep-id option maps the caller onto that user.
The user option is present only if the uid or the gid is more than 0.

The docker network syntax needs docker 25 or later.

### Example for docker

The command below is a run in `proxy` mode. The values `<run-dir>`, `<run-id>`, `<ais-binary>`, and `<proxy-url>` are placeholders. The environment flags are in the next list.

    docker run --rm --name ais-run-vuln-watch-<run-id> --hostname ais
      --user 1000:1000 --read-only --cap-drop=ALL
      --security-opt no-new-privileges
      --pids-limit 256 --memory 2g --memory-swap 2g --cpus 1
      --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m
      --tmpfs /run/ais/cfg:rw,nosuid,nodev,noexec,mode=1777,size=64m
      --tmpfs /run/ais/home:rw,nosuid,nodev,noexec,mode=1777,size=64m
      --tmpfs /run/ais/work:rw,nosuid,nodev,noexec,mode=1777,size=16m
      --volume <run-dir>/in:/run/ais/in:ro
      --volume <run-dir>/out:/run/ais/out
      --volume <ais-binary>:/run/ais/bin/ais:ro
      --workdir /run/ais/work
      <environment flags>
      --network ais-internal
      --label io.ais.managed=true --label io.ais.role=run
      --label io.ais.run=<run-id> --label io.ais.schema=1
      --label io.ais.task=vuln-watch
      localhost/ais:latest

The command is one line. The line breaks above are for reading.

For podman, replace `--user 1000:1000` with `--userns=keep-id:uid=1000,gid=1000`. The other flags are the same.
On a host with SELinux in enforcing mode, each `--volume` gets the option `z`, for example `<run-dir>/out:/run/ais/out:z`. A tmpfs never gets it.

The environment flags are:

- `--env HOME=/run/ais/home/ais`
- `--env CLAUDE_CONFIG_DIR=/run/ais/cfg/claude`
- `--env CLAUDE_CODE_OAUTH_TOKEN` and `--env AIS_RUN_TOKEN`, with no value
- `--env DISABLE_UPDATES=1`, `DISABLE_AUTOUPDATER`, `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `DISABLE_BUG_COMMAND`, and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, each set to `1`
- `--env AIS_TASK` and `--env AIS_RUN_ID`, with values
- `--env CLAUDE_CODE_MAX_TURNS`, with the value of `maxTurns`
- In `proxy` mode: `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, and `http_proxy`, set to the proxy URL
- In `proxy` mode: `NO_PROXY` and `no_proxy`, set to `localhost,127.0.0.1,::1` and the backend address

A flag without a value, such as `--env CLAUDE_CODE_OAUTH_TOKEN`, makes the engine copy the value from its own environment. The secret does not appear in the command line, in `ps`, or in `--dry-run` output.

The image sets the same `DISABLE_*` values as defaults. This protects a person who runs the image by hand.

### Ownership labels

ais puts these labels on every container, network, and image that it creates: `io.ais.managed`, `io.ais.schema`, and `io.ais.role`. The role is `run`, `proxy`, `backend`, or `network`. A run container also has `io.ais.task` and `io.ais.run`. The image has `io.ais.recipe` and `io.ais.version`.

## Network topology

`ais net up` and the daemon create this topology:

| Item | Detail |
|---|---|
| Network `ais-internal` | Created with `--internal` and the subnet `egress.subnet`. It has no route out. |
| Network `ais-egress` | An ordinary network. Only the proxy joins it. |
| Container `ais-proxy` | Squid. It is on both networks, at the address ending in `.2` on the internal network. |
| Container `ais-backend` | The backend sidecar, at the address ending in `.4` on the internal network. |
| Run containers | On `ais-internal` only. |

The sidecars use fixed addresses, so no container needs DNS on the internal network.

The proxy container has `no-new-privileges` and a limit of 256 processes. It mounts `squid.conf` and the composed allowlist read-only.
ais writes both files in place. It never renames them, because a rename leaves the sidecar with a dead file.

The template `assets/squid.conf.tmpl` allows a request if the source is in the subnet and the destination domain is on the list. It denies all other requests. It writes one access log line for each request. The cache is off.

`Manager.Reload` runs `squid -k parse` in the container. If squid rejects the new list, ais writes the previous list back and returns the error. If squid accepts it, ais runs `squid -k reconfigure`.
`ais egress denied` reads the log lines of the proxy and counts the lines that show a denial for each host.

## Backend and MCP

The package `internal/backend` has two HTTP handlers. They run in the daemon.

### Operator API

The operator handler listens on the unix socket `backend.socket` with mode 0600. If `backend.tcpListen` is set, the same handler also listens on that TCP address. Configuration validation accepts a loopback address only. The handler has no authentication, and the mode of the unix socket is the guard.
The paths are listed in `README.md`.

### MCP server

The run handler serves the path `/mcp` with the MCP streamable HTTP transport, in stateless mode with JSON responses. It listens on the socket `mcp.sock`, in the directory of `backend.socket`.

The sidecar gives run containers a fixed address for the MCP server. The daemon does not listen on a container network. The sidecar works like this:

1. The container `ais-backend` runs `ais backend-proxy --listen :<mcpPort> --upstream /run/ais/mcp.sock`.
2. The sidecar mounts the ais binary at `/ais` and the host `mcp.sock` at `/run/ais/mcp.sock`.
3. The sidecar is a reverse proxy. It forwards every request to the unix socket. It holds no data and no secrets.
4. The sidecar has a read-only root filesystem, `--cap-drop=ALL`, `no-new-privileges`, 64 processes, and 64 MiB of memory. It uses the user of the daemon.
5. The daemon starts the sidecar after the sockets exist. `ais net up` starts it only if the socket exists.

The run container reaches the sidecar directly. The address of the sidecar is in `NO_PROXY`, so the request does not go through squid.

The generated `mcp.json` names the server `inventory`, type `http`, and the header `Authorization: Bearer ${AIS_RUN_TOKEN}`. Claude Code expands the variable from the environment, so the token is not in the file.

Authentication has these properties:

- Every request except `GET /healthz` needs a bearer token. Without a valid token, the handler returns status 401.
- The token is 32 random bytes, encoded in base64. The database stores the SHA-256 hash.
- A token is valid for one run and one task. It expires after the task `timeout` plus five minutes. The runner revokes it when the run ends.
- The server for a request is the one for the task of the token. Server objects are cached by task name and task hash. A change of the task file gives a new server.

Each MCP tool reads the view of its own run. `viewForRun` reads `in/inventory.pseudo.json` of that run. The tool output and the prompt use the same pseudonymized data.

| Tool | Behavior |
|---|---|
| `inventory_products` | Groups the records by `expose.prompt.groupBy`. If that key is empty, it groups by all `clear` columns. The result field `text` holds the free-text lines. The optional `filter` matches a substring of any field or line, ignoring case. |
| `inventory_list` | Returns records of the view. The optional `product` match ignores case. The optional `version` match is exact. The default limit is 100 and the maximum is 500. The result has the field `total`. |
| `results_recent` | Returns the pseudonymized results of earlier runs of the same task, newest first. The default `since` is seven days ago. The default limit is 10 and the maximum is 50. |

The task key `expose.mcp.tools` selects the tools that the server of a task offers. If the key is empty, the server offers all three.

`inventory_list` reads the columns `product` and `version`. A task whose inventory has no such columns gets no match for these filters.

### Token stability across runs

The salt of a task is stored in the database. The same value in the same column gives the same token in every run. For this reason `results_recent` can show earlier findings with tokens that match the tokens of the current run.
The dry run uses a new random salt, so its tokens do not match any other run.

## Sinks and dispatcher

### Queue

When a run ends, the runner writes rows in the table `deliveries` with the state `pending`:

- For `succeeded`, one row of kind `result` for each sink in the task `sinks`.
- For `leaked`, `failed`, and `timeout`, one row of kind `alert` for each sink in `alerts`.

A `skipped` run and a `cancelled` run get no row.

The digest loop adds a row of kind `digest` for each sink in the task `sinks`. See Digest.

The dispatcher runs in the daemon. Every five seconds it takes up to 50 rows that are `pending` and due. For each row it builds the event, calls the sink, and writes the outcome.

### Event

The event is JSON with these fields: `kind`, `task`, `run_id`, `state`, `reason`, `error`, `finished_at`, `result`, `leaks`, and `meta`. The field `result` is the clear, enriched output of a `result` event. The field `leaks` lists the inventory field names whose values leaked, without duplicates. It never holds the values.
The field `meta` has `model`, `models`, `tokens`, `billing`, `cost_usd`, `num_turns`, `duration_ms`, `task_hash`, `engine`, `ais_version`, and `host`.
The field `model` is the model that did most of the work.
The field `models` lists each model that the run used, with the highest cost first.
The field `tokens` has `input`, `output`, `cache_read`, and `cache_creation`. Each value is the sum over all models.

### Digest

The daemon runs `digestLoop`. Every 30 seconds it reads the current tasks. For each enabled task with a `digest` key, it calls `digestDue`. `digestDue` computes the first tick of `digest.schedule` after the last check. It reports a due digest if that tick is not in the future. The loop starts with the daemon start time, so a daemon that was down at the scheduled minute does not send that digest. A reload (SIGHUP) needs no extra step, because the loop reads the current tasks.

`QueueDigest` in `internal/sink/digest.go` reads the finished runs of the window with `Store.RunsBetween`. Without `always`, it queues nothing if the sum of the `findings` arrays is not 0. It writes one row of kind `digest` for each sink in `sinks`, not `alerts`. The row hangs on the newest finished run of the window, or on the newest run of the task if the window has none. It stores the window in `payload`. If the task has no finished run, it returns a reason and the loop logs `digest not sent`.

The dispatcher builds the digest event from `payload` at send time. The field `digest` has `window_start`, `window_end`, `runs`, `succeeded`, `failed`, `skipped`, `findings`, `checked`, and `next_run`. The field `meta` has sums over the runs of the window. `skipEmpty` does not skip a digest, and the Splunk sink does not split it.

`ais digest` builds the same event for the window that ends now and calls the sinks once, without the queue.

### Retry rules

| Outcome | Next state |
|---|---|
| Sink returns success | `delivered` |
| HTTP status 429 or 5xx, or a network error | `pending`, with a new due time |
| Other HTTP status 4xx, a template error, a missing sink, or a missing result | `dead` |
| The attempt count reaches `delivery.maxAttempts` | `dead` |
| The sink returns a reason from `Skip` | `skipped`, with the reason in `last_error` |

The dispatcher calls `Skip` before `Deliver`. If `Skip` returns a reason, the dispatcher does not call the sink and does not try again.

The delay before attempt *n* starts at `delivery.backoff.initial`, doubles for each attempt, and stops at `delivery.backoff.max`. ais adds a random delay of up to a quarter of the value.

The dispatcher reads the event from the database at send time. A row that you reset with `ais runs redeliver` sends the current stored result. This includes a `skipped` row. The dispatcher then evaluates `Skip` again.


### Sink types

| Type | Behavior |
|---|---|
| `webhook` | Sends an HTTP POST. The body is the Go template `body`, with the event as data. The default body is the event as JSON. If the body is not valid JSON, the content type is `text/plain; charset=utf-8`. |
| `splunk_hec` | Sends an HTTP POST with the header `Authorization: Splunk <token>`. The body has one JSON object for each event. With `split`, a `result` event becomes one object for each element of that array. The key of the element is the name of the array without a final `s`. |
| `nats` | Publishes to JetStream. The message ID is `<run-id>/<kind>/<sink>`, so the server drops a repeated message. If `stream.name` is set, ais creates or updates the stream at the first connection. The client reconnects without limit. |
| `webex` | Sends an HTTP POST with the field `markdown`, built by `WebexMarkdown`. In bot mode it adds `roomId` and the header `Authorization: Bearer <token>`. With `card`, it adds an attachment of the type Adaptive Card from `WebexCard`. The `title` is a Go template. |

`Build` wraps a sink that has `skipEmpty: true` in `skipEmpty`. This wrapper implements the interface `Skipper`, which has the method `Skip(ev Event) string`. `Skip` returns a reason, or an empty string to deliver. The wrapper returns a reason for a `result` event when `EmptyFindings` is true. `EmptyFindings` is true when the result has a `findings` array with zero elements. A result without a `findings` array is not empty. An `alert` event is never skipped.

`newWebex` rejects a bot sink (with `tokenSecret`) that has no `roomId`. It also rejects a URL that is not a Webex incoming webhook when there is no token.
`WebexMarkdown` sorts the findings by severity and limits the message to `maxItems` findings and 7000 characters. It reads the findings from the `findings` array of the result. If there is no such array, it sends the result as a JSON code block.
`ais sinks test` builds the event with `SampleEvent`, or loads the clear result of a run with `Dispatcher.LoadEvent`. It calls `Skip` and, if no reason returns, `Deliver` on the sink. With `--print`, it renders the sink's `title` template and prints the markdown without sending it.

The TLS check can be turned off for `webhook`, `splunk_hec`, and `webex` with `insecureSkipVerify`.
The templates `body`, `subject`, `sourcetype`, and `source` get the event as data. They have the functions `json` and `now`.
For the NATS credentials, ais writes a file with mode 0600 in a new temporary directory, because the client library needs a file.

## Store

The database is one SQLite file in WAL mode, `ais.db`, with mode 0600. The connection pool has one connection. The tables are:

| Table | Content |
|---|---|
| `runs` | One row for each run: state, reason, cost, turns, duration, and the mode (`feed` or `full`; empty for rows from before feed checks). The cap `feeds.maxRunsPerDay` counts the rows with the mode `feed`, the trigger `schedule`, and a state other than `skipped`. |
| `task_salts` | The salt of each task. |
| `pseudonyms` | The token map of each task. |
| `results` | The pseudonymized result and the clear result of each run. |
| `leaks` | The values and the context of a leak. |
| `prompts` | The system prompt, the prompt, and the arguments of each run. The retention rule removes a row with its run. |
| `run_tokens` | Hashes of the bearer tokens, with expiry and revocation. |
| `feed_items` | The feed items of each task, with the state `new`, `handed`, or `seen`, and the `run_id` that got them. The primary key is `task` and `key`. See Feed checks. |
| `deliveries` | The delivery queue. The column `payload` holds the window of a `digest` row. `migrate` adds it to an existing database. |

CAUTION: The database holds real values: the token map, the clear results, and the leaked values. Protect the state directory like the inventory.

## Installer

`aisctl` works in the systemd user scope and refuses to run as root. It calls `systemctl`, `loginctl`, and `journalctl` through one injectable function, so tests run without them.
It reuses the packages `config`, `egress`, `image`, `doctor`, `runtime`, `secret`, and `task`.

`aisctl init` does these steps in order:

1. Preflight: not root, container engine available, `systemctl --user --version` works. It stops if `config.yaml` or the unit file exists and you did not give `--force`.
2. Copy the ais binary to `~/.local/bin/ais`. It uses the first of these: the `--ais-binary` path, a file named `ais` next to `aisctl`, a file named `ais` on `PATH`, and `aisctl` itself.
3. Write `config.yaml` with explicit `paths`, `secrets`, `runtime`, `egress`, `scheduler`, and `inventory` values, and the sink examples as comments. Write the example inventory `inventory.mdj` if none exists. Install each task template that you give with `--template`. Load the result and check it.
4. Store the token. The source order is `--token-file`, `CLAUDE_CODE_OAUTH_TOKEN`, then a hidden prompt.
5. Build the image, or pull the image from `--image` and check its flags. With `--image`, write `runtime.image` to `config.yaml`. Pull the proxy image and the sidecar image if they are not present.
6. In `proxy` mode, call `Manager.Ensure`. The backend sidecar starts later, when the daemon creates its sockets.
7. Render the unit from the template `assets/systemd/ais.service` with `text/template`, write it, run `daemon-reload`, and run `enable-linger`. If the redaction policy is approved, run `enable --now`. If not, run `enable` only and print the test report.
8. Poll `GET /healthz` on the operator socket until the timeout.

With `--force`, `aisctl` renames an existing `config.yaml` and unit file to `<name>.bak-<timestamp>` before it writes new ones.

## Redaction policy

`pseudo.Redaction` holds `Domains`, `CIDRs`, `Literals`, `HostnameMode`, and `IPMode`. `Validate` checks the modes, the ranges, and the domains.
`ApprovalHash` is the first 16 characters of the SHA-256 of the normalized policy as JSON. The normalization sorts each list and ignores case and white space. `CheckApproval` compares the hash with `pii.approvedHash`.

The policy has three uses:

1. The tokenizer. For a column with the mode `pseudonym` and the label `host`, `rot13` gives `Rot13(value)`. For the label `ip`, `cgnat` gives `CGNATAddress` with the salt of the task as the key. Other values, and the mode `token`, give an HMAC-SHA-256 token with the label and 8 hex characters or more. The token map records each token, so the host can reverse it.
2. The mode `scrub`. `Apply` passes the value to a redactor. The redactor has the task salt as its `cgnat` key. If there is no redactor, `Apply` drops the field.
3. The hook. `Prepare` builds the `Rules` with the merged lists, the two modes, and a random 32-byte key. The key is not the task salt, so the addresses that the hook rewrites do not match inventory tokens or addresses of other runs. `Rules` goes to `in/redact.json`.

`CGNATAddress` takes an HMAC-SHA-256 of the IPv4 address, uses 22 bits of it, and puts them in `100.64.0.0/10`. The redactor needs a key for `cgnat`. Without a key, it replaces the address with `[redacted]`.
In the hook, `token` mode and an IPv6 address give `[redacted]`.

`Redaction.Check` lists inventory hostnames outside the domains and addresses outside the ranges. `aisctl redact test` uses it. The command shows each record before and after redaction. It uses the `fields` of the task from `--task`, or `GenericPolicy` otherwise. `GenericPolicy` maps columns by name:

- Host-like and address-like columns become `pseudonym`.
- Columns named `usage` or `interest`, and columns with `descr`, `comment`, `note`, or `remark` in the name, become `scrub`.
- Columns with `mail`, `owner`, or `user` in the name become `drop`.
- All other columns become `clear`.

The gate is in these places:

| Place | Effect |
|---|---|
| `ais run` | Stops with an error, unless `--dry-run`. |
| `ais daemon` | Does not start. |
| `guardedRunner.Run` | Records a `skipped` run with the reason `redaction`. |
| `ais doctor` | The check `redaction` is `FAIL`. |
| `aisctl init` | Enables the unit and does not start it. |
| `aisctl update` | Installs and does not restart. |

## Prompt log

`Prepared.PromptLog` builds a record from `system.md`, `prompt.md`, and `argv.json`. The SHA-256 hash covers the system prompt and the prompt. The runner saves the record in the table `prompts` and appends a line to `<stateDir>/runs/<task>/prompts.ndjson`. It does this before the container starts. The daemon logs the run, the hash, and the size.
The file has the fields `run_id`, `task`, `time`, `sha256`, `bytes`, `system`, and `prompt`. Retention never prunes it. `ais run --dry-run` appends a line with the run ID suffix `-dry`.
`aisctl prompts list` and `aisctl prompts last` read the files `prompts.ndjson` of all tasks, so they show dry runs. `aisctl prompts show` reads the table row first and uses the file if the row is missing.
`internal/prompt` adds the isolation notice and the token notice to every system prompt, after the text of `appendSystemPrompt`. If the task has `expose.prompt.collect`, it adds a notice that `notes:` lines are operator comments. If `egress.mode` is `proxy`, it adds the egress notice: the hosts from `egress.Reachable` (embedded base list, config `baseAllowlist`, the task's `egress.allow`, `extra.acl`), the instruction to not fetch or retry other hosts, and the note that `WebSearch` is not restricted.

## Task templates

`assets/templates/<name>/task.yaml` and `README.md` are embedded in the binary. `templates.Install` writes the task file as `<tasksDir>/<name>.yaml`. It replaces the `name:` line when you give `--as`, and replaces the default inventory path with the configured path. It then loads the file to check it, and removes the file if the check fails. An existing file gives `ErrExists` unless you force it.

## Secret store

`FileStore` keeps one file for each secret in `secrets.dir`. `Set` seals the value with `Encrypt` and writes it to a temporary file with mode 0600. It then renames the file.
`Encrypt` uses a random 16-byte salt and a random 12-byte nonce for each file. It derives a 32-byte key with PBKDF2-SHA256 (600000 iterations). It seals the value with AES-256-GCM. The prefix `ais-enc-v1:` is the additional authenticated data.
The file holds `ais-enc-v1:` and the base64 text of the salt, the nonce, and the ciphertext.

`Get` reads the secret in this order:

1. The file `$CREDENTIALS_DIRECTORY/NAME`, as it is.
2. The file in `secrets.dir`. If it does not start with `ais-enc-v1:`, `Get` returns the content as it is.
3. If the file is encrypted, `Get` decrypts it with the passphrase.

`Passphrase` reads `$CREDENTIALS_DIRECTORY/ais-passphrase` first, then `<secrets.dir>/.passphrase`. If neither exists, an encrypted secret gives the error `ErrNoPassphrase`. A wrong passphrase gives `ErrBadPassphrase`.
`SetPassphrase` reads every secret under the old passphrase, writes the new passphrase, and sets every secret again. If one secret is not readable, it stops before it changes the passphrase.
`List` skips the passphrase file, because the name starts with a dot.

The scope is a casual read of the files. The passphrase is on the same host, so root can read both.

## Token age

The secret store has no expiry date for the token, because the token is opaque. `FileStore.StoredAt` returns the modification time of the secret file. `ais secret set` renews it. For a file in `CREDENTIALS_DIRECTORY`, the store uses that file first.
`secret.TokenStatus` compares the age with `claude.tokenLifetime` and `claude.tokenWarnBefore`:

| Condition | Status | `ais doctor` |
|---|---|---|
| The time left is more than `tokenWarnBefore` | `ok` | `ok` |
| The time left is `tokenWarnBefore` or less | `expiring` | `warn` |
| The time left is 0 or less | `expired` | `fail` |

The daemon runs `tokenAgeLoop` at start and then every 24 hours. It logs a warning for `warn` and an error for `fail`.
The runner reads the secret at the start of each run, so a new token applies to the next run without a restart.

## Scheduler

`internal/scheduler` starts one goroutine for each enabled task. The goroutine does these steps in a loop:

1. Compute the next tick after now, in the scheduler timezone. If the task has `feeds.fullSchedule`, compute its next tick too. If it is not more than one minute after the tick of `schedule`, it replaces that tick and the trigger becomes `schedule-full`.
2. Add a random delay between zero and the jitter.
3. Wait.
4. If the task is paused, skip the tick.
5. Take a slot of `maxParallel`.
6. Call the runner with the trigger `schedule`, or `schedule-full` for a full run.

The triggers are the constants `TriggerSchedule`, `TriggerScheduleFull`, `TriggerManual`, and `TriggerManualFull`. `scheduler.FullRun` reports whether a trigger ends in `-full`. `ais run` uses `manual`, and `manual-full` with `--full`.

The runner for the scheduler wraps `runner.Run`. Before the run it checks the redaction approval against the current policy. If the approval is not valid, it records a `skipped` run with the reason `redaction`. Then it checks the daily budget. After the run it counts the consecutive `auth` failures and pauses the task at the limit.

On SIGHUP, the daemon also reads `config.yaml` and replaces the policy (`reloadPolicy`). The runner config gets the new `pii` section under the same lock, so the next run uses it. If another section of the file differs from the running config, the daemon logs that a restart is necessary (`configOutsidePIIChanged`).

On SIGHUP, `Reload` first clears all pauses. It then compares the hash of each task file with the loaded hash. It restarts the loop of a changed task, stops the loop of a removed task, and keeps the others.
The hash is the first 16 characters of the SHA-256 of the file content.

## Feed checks

A task with `feeds` runs in one of two modes. `Prepare` sets the mode from the trigger. A trigger that ends in `-full` gives `full`, the old behavior. Any other trigger gives `feed`. A task without `feeds` is always `full`.

In `feed` mode, `Prepare` calls `readFeeds` before it creates the prompt:

1. `feed.FetchAll` fetches all URLs. `feeds.timeout` limits each fetch. A failed feed goes into the `FeedStatus` list with its error, and the others still count. If every feed fails, `readFeeds` returns an error and the run fails.
2. `readFeeds` removes duplicate keys and calls `Store.ClaimFeedItems`. The call inserts new keys with the state `new`. It selects the items in the state `new`, newest first, up to `feeds.maxItems`. It sets them to `handed` with the run ID. The selection includes items of an earlier run that failed.
3. The items go to the prompt as `.Feed`, and the mode as `.Mode`.

If no item is new and `feeds.skipWhenQuiet` is true, `Prepare` removes the run directory and returns `ErrQuiet`. The runner then inserts a run in the state `skipped` with the reason `quiet`. The column `error` holds the counts from `feedSummary`. The runner starts no container.

After the run, `Store.SettleFeedItems` sets the `handed` items of the run to `seen` if the run succeeded. In any other case it sets them to `new`, so the next feed run gets them again.
`Store.PruneFeedItems` deletes `seen` items first seen before the cutoff. The retention job in `internal/app` calls it with the same cutoff as `retention.keepDays`. It does not run if `retention.keepDays` is 0.

A dry run sets `Options.Peek`. `ClaimFeedItems` then gets an empty run ID and claims nothing. `ais feeds test` uses the same call. `BuildDigest` counts a `skipped` run with the reason `quiet` as `Quiet` and not as `Skipped`.

## Image

`ais image build` writes `Containerfile`, `entrypoint.sh`, and a `ca-certificates` directory to a temporary build context. It then runs `<engine> build`. The recipe hash covers the Containerfile, the entrypoint, `image.claudeVersion`, and the contents of the extra certificates.

The Containerfile starts from `node:22-bookworm-slim` and installs `ca-certificates`, `jq`, and `tini`. It installs Claude Code at the version `image.claudeVersion`, removes setuid and setgid bits, and renames the user `node` (uid 1000) to `ais`. It creates the mount points under `/run/ais`.
The apt options `Acquire::Check-Date=false` are explained in `README.md`.

After the build, `CheckFlags` runs `claude --help` in the image. It looks for 15 flags in the output. If one is missing, the build fails with a message that asks for another `image.claudeVersion`. The CLI accepts unknown flags without an error, so the help text is the only signal of a change.
Two flags that ais uses, `--max-turns` and `--append-system-prompt-file`, are not in the help text and are not checked.

## See also

`README.md`, `CHANGELOG.md`
