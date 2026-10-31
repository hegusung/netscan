# MCP credential campaign network test report

Date: 2026-10-31  
Branch: `MCP`  
NetScan session: `MCP-Campaign-20261031`  
Authorized scope: `192.168.1.0/24`

## Objective

Validate the scope-wide credential campaign changes, secret-free Elasticsearch
validation records, and the strongly typed MCP execution path against the local
network. Authentication tests used one deliberately invalid account/secret pair
per protocol. No successful credential was discovered or disclosed.

## Discovery

An ARP/ping discovery found 14 active addresses. A top-2000 TCP scan with light
version detection was then restricted to those hosts. Relevant observations:

- SSH was exposed by `192.168.1.2`, `.10`, `.40`, `.42`, `.45`, `.50`, and `.41`.
- SNMP was exposed by the Synology host `192.168.1.10`.
- NFS/RPC was exposed by `192.168.1.10`.
- Elasticsearch over TLS was exposed by `192.168.1.106:9200` and required
  authentication.
- Several HTTP/HTTPS services were found on the router, Raspberry Pi systems,
  Synology, Netgear equipment, and local application hosts.
- No live FTP, MongoDB, MSSQL, MySQL, PostgreSQL, RDP, Redis, SMB, Telnet, VNC,
  or WinRM service was found in the top-2000 TCP results.

Launching NetScan's top-2000 TCP dispatcher directly against the entire `/24`
would schedule 512,000 individual connections and had a multi-hour estimate.
The run was stopped cleanly and replaced with active-host discovery followed by
Nmap top-2000 scanning. This is an efficiency limitation in the broad-scope
port-scan workflow, not in the credential campaign scheduler.

## Credential campaign coverage

Live-service tests were performed against SSH and SNMP. Error-path tests used
the closed default port on an active host for the remaining protocols. The final
Elasticsearch query returned one `credential_validation` document for every
supported campaign protocol:

- FTP
- MongoDB
- MSSQL
- MySQL
- PostgreSQL
- RDP
- Redis
- SMB
- SNMP
- SSH
- Telnet
- VNC
- WinRM

There were 13 validation documents: 9 `error` results for unavailable transports
and 4 `failure` results for completed authentication failures. Every document
contained a `credential_ref`; none contained a `password`, `hash`, `community`,
`secret`, or `b_secret` field.

Because most authentication services were not present, their successful-login
paths were verified by automated tests rather than by obtaining credentials on
the network. The test therefore validates scheduling, transport failure handling,
failure persistence, correlation, and secret redaction, but not live success for
every protocol.

## MCP end-to-end test

The root launcher started the streamable HTTP MCP server on
`http://127.0.0.1:8765/mcp`. A real MCP SDK client then:

1. initialized a session;
2. listed 42 tools;
3. inspected the strongly typed `netscan_snmpscan` schema;
4. called `netscan_status`;
5. launched an SNMP spray job against `192.168.1.10`;
6. retrieved the completed job with `netscan_scan_result`.

The job `bb9846c75a374306b60a7891057ecdd9` succeeded with exit code 0 in 4.823
seconds. It produced six normalized events and indexed three Elasticsearch
documents, with zero reported persistence failures. The result correctly handed
off index `pentest` and session `MCP-Campaign-20261031` for Kibana analysis.

## Bugs found and corrected

1. SNMP timeout paths left PySNMP timeout and asynchronous-generator tasks
   pending. The SNMP engine now closes in `finally`, and `walk_cmd` is explicitly
   closed with `aclose()`.
2. FTP, MongoDB, MSSQL, RDP, Redis, and VNC transport failures escaped their
   workers as tracebacks. Workers now persist an `error` validation and terminate
   cleanly.
3. MySQL, PostgreSQL, SNMP, and Telnet had incomplete unexpected-error coverage.
   Their fallback paths now preserve the validation invariant.
4. Telnet could fail in its constructor before a scanner object existed and skip
   persistence. It now constructs a fallback target URL and records the error.
5. SMB returned immediately after a connection failure without a validation
   record. Connection and unclassified authentication failures are now stored.
6. SSH transport/protocol error branches skipped validation or printed a raw
   traceback. They now record a secret-free `error` result.
7. redis-py applied implicit connection retries, making a one-second timeout take
   about 4.5 seconds. Campaign connections now use zero retries and complete
   promptly.
8. Stopping the HTTP MCP server with Ctrl-C propagated a Python traceback. The
   server now treats `KeyboardInterrupt` as a normal shutdown while still closing
   the job manager.

## Verification

- Python compilation succeeded.
- `git diff --check` succeeded.
- 54 automated tests passed, including three new transport-error persistence
  regression tests.
- The corrected SNMP campaign completed repeatedly without pending asyncio task
  warnings.
- Repeated closed-port campaigns completed without worker tracebacks.
- MCP startup, typed discovery, network execution, persisted result retrieval,
  and graceful shutdown were exercised successfully.
