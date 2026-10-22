# MyScoutee nginx extensions

Shared nginx implementation for MyScoutee and MyScoutee Template. Application
routes and country GeoJSON stay in each application's repository.

- `partition/`: native nginx C module with S2 C++ spherical geometry. Loads and
  indexes the complete GeoJSON Polygon/MultiPolygon snapshot during nginx config
  loading. Request processing uses the in-memory index, without HTTP hops, Lua,
  backend calls or database access. Holes and partition specificity are supported.
- `conf/`: deployed-route filtering and native per-IP request limiting. Normal
  traffic allows 30 requests/second with burst 120; unknown paths 2/second with
  burst 10. Health and runtime-status endpoints are exempt from the general limit.
- `tools/nginx-blocklist.py`: existing host-side blocklist owner, including
  scanner discovery. 100 unknown-route requests within 10 minutes produce a
  persistent ban and bounded path evidence. Its host timer applies changes with
  nginx validation and graceful reload, without restarting the nginx master.
- `tools/traffic/`: access-log statistics, with optional browser diagnostics kept
  behind `--debug`. `--summary` reports campaign sources and whether further
  application activity is visible; it does not infer proven clicks or people.
- `runtime-status/`: existing backend-readiness receiver, moved unchanged from
  the application repository. It is separate from native geometry processing.

## Native image and test

```sh
docker build -t myscoutee-nginx:native-partition-test .
PARTITIONS_FILE=/path/to/countryPartitions.json python3 tests/native-test.py
```

The test uses one disposable nginx container, with a 1 CPU/128 MiB limit. It
checks polygons, holes, multiple islands, specificity, invalid coordinates,
reload and memory-only lookup. With the full application seed it also checks
European cities and compares a constant response against native geometry under
matched concurrent load. No application backend is started.

Applications consume this repository as a pinned Git submodule. Their nginx
configuration loads `ngx_http_partition_module.so`, sets
`myscoutee_partition_file /etc/nginx/countryPartitions.json`, and uses
`myscoutee_partition_check` on the existing coordinate-eligibility endpoint.
`AUTH_REGION_SECURITY_ENABLED=false` disables that eligibility gate.

The landing, demo and public content remain geographically accessible. The
eligibility endpoint returns the existing JSON contract; it is not a site-wide
IP ban. Scanner bans are independent of geographic eligibility.

Auto-ban evidence is stored on the deployment host in
`/var/lib/<application>/nginx-blocklist/scanner-blocked-ips.json`; candidate
counters and read positions survive worker restarts in `scanner-state.json`.
Operator-edited bans remain separate and take message precedence. Remove an
entry from the generated file to unblock it. Findings can be reviewed/exported
into a versioned deployment list; the worker never publishes to GitHub.
