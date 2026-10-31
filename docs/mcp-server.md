# NetScan MCP server

NetScan includes an MCP server that exposes its scanner commands as tools. Use it
only for targets you are authorized to assess.

The server exposes one strongly typed tool for every NetScan command, generated
directly from that command's `argparse` declarations. Examples include:

- `netscan_portscan`
- `netscan_httpscan`
- `netscan_smbscan`
- `netscan_adscan`
- `netscan_generate_payload`
- `netscan_es_query`

Types, arrays, enums, descriptions, and native defaults are included in each MCP
input schema. Typed values are converted back to native CLI arguments internally.
For example, a typed port scan call is:

```json
{
  "targets": "192.0.2.0/24",
  "port": [22, 80, 443],
  "service_scan": true,
  "workers": 20,
  "nodb": false,
  "mcp_timeout_seconds": 600
}
```

Scanner tools return immediately with a background `scan_id`. Use the job tools
to follow and collect a scan:

```json
{
  "scan_id": "23af...",
  "state": "queued",
  "module": "portscan",
  "output": {"resource_uri": "netscan://scans/23af.../output"},
  "persistence_expected": true
}
```

General-purpose tools are also available:

- `netscan_status`: inspect configuration, policy, and typed tool names.
- `netscan_context`: get the session, index, Elasticsearch reachability, and a
  credential-safe Elastic MCP handoff.
- `netscan_module_help`: get the native help for a command.
- `netscan_list_scans`: list queued, active, and completed jobs.
- `netscan_scan_status`: poll one job and its output progress.
- `netscan_cancel_scan`: cancel a job and its complete subprocess group.
- `netscan_scan_result`: get its semantic summary, findings, and persistence
  metadata.
- `netscan_scan_output`: page through retained terminal output.
- `netscan_scan_artifacts`: list files produced by a completed job and their
  confined resource URIs.
- `run_netscan`: enqueue a command using an argv-style list.

Clients that support MCP resources can read the same output from
`netscan://scans/{scan_id}/output`. Output is bounded by
`NETSCAN_MCP_MAX_OUTPUT`, keeping server memory use predictable.

Structured findings returned by `netscan_scan_result` use event schema version
1. Each event has `category`, `severity`, `status`, `target`, `message`,
`timestamp`, `sensitive`, `data`, and `legacy_type` fields. Agents should use
these stable fields instead of parsing colored terminal output. The summary
contains counts by both normalized category and legacy output type.

Agents should prefer `netscan_<module>`. `run_netscan` remains useful as a
compatibility escape hatch when a newly added or unusual CLI behavior cannot be
represented by the generated schema.

### Capability guide for agents

Do not decide that NetScan lacks a capability merely because there is no
same-named top-level command. Some protocol features are actions of another
scanner, and every action declared by that scanner's `argparse` interface is
present in the corresponding strongly typed MCP schema. Use
`netscan_module_help` when the tool description is not sufficient.

Important mappings include:

| Objective | MCP tool and relevant arguments |
| --- | --- |
| Multi-host password testing or spraying | SMB, SSH, and WinRM use a shared scope-wide campaign engine. Select `spray=true` for secret-major ordering across every target; use `spray_round_delay`, `credential_jitter`, `max_attempts_per_account`, and `continue_on_success` to control the campaign. SMB also accepts `ntlm_file`. |
| Persist and correlate results | Leave `nodb` false. Results are stored in the configured Elasticsearch index and separated by the configured NetScan session. |
| Validate Windows administrative access | `netscan_smbscan` validates access to the remote Service Control Manager after password, NTLM, or Kerberos authentication and reports administrative privileges. |
| Validate MSSQL administrative access | `netscan_mssqlscan` checks membership in the `sysadmin` server role; `admin_check` can also test it explicitly. |
| Execute on Windows | `netscan_smbscan` with `cmd`, `powershell`, or `payload`. Select `exec_method=wmiexec`, `smbexec`, or `mmcexec`; without a method NetScan tries WMI, SMB service execution, then MMC. |
| Test WinRM at scale | `netscan_winrmscan` accepts multiple ports, HTTP or HTTPS, direct password/hash authentication, command execution, and multi-host credential files with independent target and credential worker controls. |
| Enumerate through WMI | `netscan_smbscan` with `processes`; application enumeration also uses a remote Windows command. |
| Enumerate NFS | `netscan_rpcscan` with `rpc`, `mounts`, or `list`; `uid`, `gid`, and `recurse` control NFSv3 directory access and traversal. |
| Collect AD data for BloodHound | `netscan_adscan` with `domains`, `users`, `groups`, `hosts`, `gpos`, and, when required, `cas` and `cert_templates`. SMB `admins`, `loggedin`, and `sessions` add host relationships. |
| Export BloodHound data | After persisted collection, use `netscan_es_query` with the exact `session` and `export_bloodhound` output directory. |

NetScan's database is not limited to port results. Elasticsearch stores scan
invocations, services, vulnerabilities, content, applications, credentials,
hashes, secrets, AD objects, ADCS objects, and discovered administrative
relationships. The session is the engagement boundary. Use the Elasticsearch
MCP to query and correlate those records; credentials can then be supplied to an
appropriate typed scanner tool when the operator explicitly requests credential
reuse.

The shared campaign engine schedules a spray one secret at a time over the full
target scope. A new round does not start until all attempts in the previous round
finish, then waits for `spray_round_delay`. It stops further attempts for a
target/account after success unless `continue_on_success=true`, suppresses an
account after an observed lockout, supports `DOMAIN\\user` entries and inline
`user:password` entries, and adds per-attempt delay plus random jitter. These are
safety controls, not a substitute for reviewing the domain password policy.

`workers` still controls the initial discovery scan. `bruteforce_workers`
controls the subsequent credential campaign across the whole target scope. Port
5986 selects WinRM HTTPS automatically; use `ssl=true` for HTTPS on a
non-standard port.

The BloodHound exporter reads the selected Elasticsearch session and writes
BloodHound JSON for domains, containers, OUs, users, groups, computers, GPOs,
NTAuth stores, root CAs, AIA CAs, certificate templates, and enterprise CAs.
For MCP jobs, export and dump destinations supplied to `netscan_es_query` are
replaced with a private per-job directory. Once the job is complete, call
`netscan_scan_artifacts`, then read each
`netscan://scans/{scan_id}/artifacts/{artifact_id}` resource. This prevents a
client from selecting arbitrary server filesystem output paths. `owned` can mark
known compromised users and computers in the configured Neo4j instance, while
`enrich_gpos` and `gpo_admins` provide additional GPO analysis. These actions are
not substitutes for the initial AD and SMB collection.

### Agent workflow with Kibana and Elasticsearch

NetScan is the collection layer. When the Kibana Agent Builder MCP server is
connected, agents should use it as the preferred analysis layer for persisted
Elasticsearch results:

1. Call `netscan_status` and `netscan_context`, then select the appropriate typed
   NetScan tool.
2. Start the authorized scan without `--nodb` when its results need analysis.
3. Poll `netscan_scan_status` using the returned `scan_id`, then retrieve
   `netscan_scan_result` when it reaches a terminal state.
4. Pass the result's `elasticsearch.analysis_handoff` to the Kibana MCP
   and inspect the configured index mapping.
5. Scope every search, aggregation, or ES|QL query to the exact index and session
   from the handoff so separate engagements are never mixed.
6. Retrieve credentials, hashes, secrets, or recorded command lines only when the
   operator explicitly requires them.

For a BloodHound workflow, collect the required AD and SMB records without
`nodb`, wait for every job to complete, and then run `netscan_es_query` with
`session` set to the handoff session and `export_bloodhound` set to any typed
string value. The MCP server confines the actual destination; retrieve the JSON
files through `netscan_scan_artifacts`. Do not export an unscoped or guessed
session.

The Kibana MCP identity should be read-only and restricted to the NetScan index.
If Kibana MCP is unavailable, or a NetScan-specific export is
needed, `netscan_es_query` remains available but must be used carefully because it
also exposes destructive operations. A scan performed with `--nodb` has no results
for Elasticsearch to analyze.

For HTTPS Elasticsearch deployments, set `verify_certificates=true` and set
`ca_certs` to the CA bundle when a private CA is used. The default remains false
for compatibility with existing self-signed pentest deployments.

### Nested scanner modules

The module-capable commands (`adscan`, `httpscan`, `rdpscan`, `smbscan`, and
`sshscan`) publish their nested modules as enums. Names and descriptions are
extracted from each module's `Module` class, so adding a new module updates the
MCP schema the next time the server starts.

Select multiple modules with an array and use `module_args` only for positional
arguments consumed by those modules:

```json
{
  "targets": "192.0.2.10",
  "modules": ["MS17-010", "PrintSpooler"],
  "module_args": ["192.0.2.20"],
  "nodb": true
}
```

This is converted to the native form:

```text
-m MS17-010,PrintSpooler 192.0.2.20
```

Unknown module names are rejected by the MCP schema before NetScan starts, and
`module_args` is rejected unless at least one module is selected.

All user-facing NetScan commands are available, including commands that delete
stored data, generate payloads, start listeners, or expose network services.
Starting the root launcher enables scan execution; set
`NETSCAN_MCP_ENABLE_RUN=false` for help-only operation. The allowlist is
module-level: individual scanners may also offer brute-force, exploit, or
remote-command options. Run the server only for a trusted MCP host and set
`NETSCAN_MCP_ALLOWED_MODULES` when a deployment should use a smaller subset.

The server runs a bounded pool of background commands (four by default). Each
scanner can still use NetScan's own worker concurrency. MCP cancellation and wall
clock timeout terminate the scanner's complete process group. Completed jobs are
held in memory for the life of the MCP process and evicted according to the
configured retention limit; restarting the server clears all retained jobs.

## Local stdio server

Create `config.cfg`, then configure an MCP host to launch the executable at the
repository root:

```json
{
  "mcpServers": {
    "netscan": {
      "command": "/absolute/path/to/netscan/netscan_mcp_server.py"
    }
  }
}
```

On its first host run, this launcher finds Python 3.12, creates `.venv`, and
installs `requirements.txt`. Later runs automatically reuse and re-execute under
that environment. Bootstrap diagnostics are written to stderr and therefore do
not corrupt the MCP stdio protocol. Set `DISABLE_VENV=1` to use the current
interpreter, which is also the automatic behavior inside a container.

Do not launch the stdio server through `./netscan`: launcher status messages are
ordinary stdout and can corrupt an MCP stdio connection.

To route supported TCP connections through proxychains, make proxychains the host
command and put the root launcher in its arguments:

```json
{
  "mcpServers": {
    "netscan-proxied": {
      "command": "proxychains4",
      "args": [
        "-q",
        "/absolute/path/to/netscan/netscan_mcp_server.py"
      ],
      "env": {
        "NETSCAN_MCP_ALLOWED_MODULES": "httpscan,sshscan,smbscan,portscan"
      }
    }
  }
}
```

Proxychains limitations still apply: raw sockets, ICMP, UDP, statically linked
programs, and some subprocesses may bypass or be incompatible with it. SOCKS-aware
scanner options should be preferred where a module provides them.

## Streamable HTTP

For a localhost MCP endpoint at `http://127.0.0.1:8765/mcp`:

```bash
./netscan_mcp_server.py \
  --transport streamable-http --host 127.0.0.1 --port 8765
```

The server refuses non-loopback binds unless
`NETSCAN_MCP_ALLOW_REMOTE_HTTP=true` is set. That override does not add
authentication; place any remote deployment behind an authenticated, encrypted
reverse proxy.

## Docker stdio server

After building the normal NetScan image, an MCP host can launch it over stdio:

```bash
docker run --rm -i --network host \
  --volume "$PWD/config.cfg:/app/config.cfg:ro" \
  --entrypoint /app/netscan_mcp_server.py \
  netscan:latest
```

Use the same command and arguments in the MCP host configuration. `--entrypoint`
bypasses the regular NetScan launcher so it cannot write status text to the MCP
stdio channel.

## Policy settings

- `NETSCAN_MCP_ENABLE_RUN`: the root launcher defaults this to `true`. Set it to
  `false` to force read-only/help operation. Launching the internal
  `scripts/netscan_mcp_server.py` directly remains disabled unless it is `true`.
- `NETSCAN_MCP_ALLOWED_MODULES`: comma-separated subset of scanner modules.
- `NETSCAN_MCP_MAX_TIMEOUT`: maximum tool timeout in seconds; default `3600`.
- `NETSCAN_MCP_MAX_OUTPUT`: maximum captured output bytes; default `200000`.
- `NETSCAN_MCP_MAX_JOBS`: maximum concurrently running background commands;
  default `4`.
- `NETSCAN_MCP_JOB_RETENTION`: maximum recent job records retained in memory;
  default `100` (active jobs are never evicted).
- `NETSCAN_MCP_MAX_FINDINGS`: maximum structured findings retained per job;
  default `200`. Summary counters still cover every captured event.
- `NETSCAN_MCP_MAX_ARTIFACT_BYTES`: maximum size of one downloadable artifact;
  default `25000000` bytes.
- `NETSCAN_MCP_MAX_ARTIFACT_TOTAL_BYTES`: maximum total downloadable artifact
  size retained for one job; default `100000000` bytes. Files beyond either
  limit are not published.
- `NETSCAN_KIBANA_MCP_URL`: optional override for the Kibana Agent Builder MCP
  URL returned in analysis handoffs. `NETSCAN_ELASTIC_MCP_URL` remains accepted
  as a backwards-compatible alias.
- `NETSCAN_MCP_ALLOW_REMOTE_HTTP`: permits non-loopback HTTP binding but does not
  provide authentication.
