# MyScoutee nginx

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Shared native nginx extensions for MyScoutee and MyScoutee Template. Applications
consume the released GHCR image by digest and add their own proxy configuration.
Request processing stays inside nginx C/C++ modules. Source changes belong here.

| Documentation | Link |
| --- | --- |
| Short guide | [MyScoutee nginx (PDF)](output/pdf/MyScoutee_Nginx_Guide.pdf) |
| Verification | [Container checks and measured overhead](docs/verification-20261022.json) |
| Local log report | [Usage](tools/traffic/README.md) |
| License | [BSD-3-Clause](LICENSE) · [Logo permissions](BRANDING.md) |

## Included behavior

| Feature | Implementation / default |
| --- | --- |
| Location eligibility | Full bundled GeoJSON snapshot, indexed once with S2 spherical geometry; Polygon, MultiPolygon, holes and specificity |
| Public landing and demo | Remain available regardless of coordinate eligibility |
| Operator IP bans | Exact IPv4/IPv6 → individual plain-text 403 message; native shared cache; background refresh every second |
| Scanner bans | 100 unknown-route attempts on public listeners in 600 seconds; persistent ban with timestamp and bounded path evidence |
| Rate limits | Native nginx: 30 requests/s, burst 120; unknown routes: 2/s, burst 10; excess returns 429 |
| Endpoint inventory | Generated from each application's Spring/Angular/nginx routes at build time; literal routes use nginx's hash map |
| Basic traffic summary | Daily source/session/HTML/application/demo/login/article counters, independent of browser debug |
| Browser diagnostics | Off by default; SSI inserts the async script only when enabled |
| Backend availability | Native authenticated push leases, 20-second expiry, JSON and SSE; Kubernetes uses verified TLS EndpointSlice snapshots |
| Response policy | Shared security headers, transport policy, SSI switches and diagnostic endpoints |

Geometry applies to `/api/auth/eligibility`, using coordinates rather than IP
geolocation. It preserves the existing response contract and backend auth checks.
It does not geographically block the public site. `AUTH_REGION_SECURITY_ENABLED=false`
disables the eligibility gate.

## Build and integration

Released image: `ghcr.io/fssrepository/myscoutee-nginx:1.5.0` (Linux amd64).
The [v1.5.0 release](https://github.com/fssrepository/myscoutee-nginx/releases/tag/v1.5.0)
records its immutable digest and source commit. Git tags `vX.Y.Z` run the native
tests before publishing the image and its GitHub Release.

```sh
docker build -t myscoutee-nginx:1.5.1-candidate .
```

The current Dockerfile extends nginx **1.31.8-alpine** with two dynamic modules.
It refreshes Alpine packages during the build. Geometry uses
C++17/S2; the edge module uses C, JSON-C and libcurl for its Kubernetes background
reader. There is no Go/Python/Lua runtime process in this image. Shell entrypoints
are shared here too: dev, production TLS, E2E certificates and wait-for-it are
installed under `/scripts`. The route-inventory generator is packaged under
`/opt/myscoutee-nginx/tools` for build-time use with the host's Python; it does
not start a Python process in the deployed proxy.

Applications provide `countryPartitions.json` and generated `public-routes.map`.
Their config includes `conf/modules-main.conf`, the shared HTTP/server policy and
`conf/runtime-status.conf`. Application-specific proxy routes remain with the app.
The public server policy enables `myscoutee_public_edge`; internal listeners do
not count invalid URLs or apply client bans. Rate limiting remains independent:
successful page reloads and their 429 responses do not count as unknown URLs.
The backend/template release builder pulls the released module image; no nginx
source checkout or module compilation is required in either application.

| Persistent state | Container path |
| --- | --- |
| Operator IP/message object | `/etc/nginx/myscoutee-operator/nginx-blocked-ips.json` |
| Automatic bans and findings | `/var/lib/nginx/myscoutee/scanner-blocked-ips.json` |
| Traffic summary, updated every 30s | `/var/lib/nginx/myscoutee/traffic-summary.json` |

Mount the operator **directory** read-only so atomic edits remain visible; mount
the state directory on a persistent volume writable by nginx UID 101. Invalid
operator updates retain the last valid cache. Invalid policy or saved-ban files
prevent a new nginx configuration from starting without its bans. Messages allow up to 1000 UTF-8
bytes of single-line text. Manual messages take precedence over automatic bans.
Removing an operator entry or deleting a saved automatic-ban entry clears that
ban on background refresh. Findings are never automatically published to GitHub.

The live summary is also available **inside the container** at
`http://127.0.0.1:9081/internal/traffic-summary`. A session groups the same source
IP and user agent with a 30-minute inactivity gap. Attribution is an estimate:
Instagram alone does not prove a paid click, and no follow-up HTTP activity does
not prove that no click or reading occurred. Browser debug is a separate layer.

Shared state is bounded: 8,192 scanner/operator IP entries, 16,384 active visit
slots, 32 readiness services × 128 instances. Cache lookups probe at most 64 slots.
Bans survive workers/reloads and container replacement through the state volume;
traffic totals are checkpointed every 30 seconds. Separate proxy instances have
separate in-memory state; this is not a distributed ban service.

## Verify locally

```sh
NGINX_NATIVE_TEST_IMAGE=ghcr.io/fssrepository/myscoutee-nginx:1.5.0 python3 tests/edge-test.py
NGINX_NATIVE_TEST_IMAGE=ghcr.io/fssrepository/myscoutee-nginx:1.5.0 python3 tests/kubernetes-test.py
NGINX_NATIVE_TEST_IMAGE=ghcr.io/fssrepository/myscoutee-nginx:1.5.0 \
  PARTITIONS_FILE=/path/to/countryPartitions.json python3 tests/native-test.py
python3 -B -m unittest discover -s tools/traffic -p 'test_*.py'
MYSCOUTEE_FRONTEND_ROOT=/path/to/frontend node --test browser/landing-debug.test.mjs
```

Container tests cover shared workers, hot updates, custom IPv4/IPv6 responses,
scanner thresholds, removal/replacement persistence, readiness/SSE, TLS/token
validation, SSI and campaign statistics. Geometry tests cover holes, islands,
specificity, invalid coordinates, memory-only lookup and optional full-seed city
checks with matched constant-response/geometry load measurements. Report and test scripts are not copied into the runtime image.

The consuming projects also run `tests/application-test.py` against their built
image and `tests/gateway-test.py` with `APPLICATION_ROOT` set to the checkout;
the latter verifies the Kubernetes gateway as UID 101 with a read-only root
filesystem. `tests/packaging-test.py` checks preservation of operator state during
upgrade. The guide can be regenerated locally with `docs/build-guide.py`
(ReportLab and DejaVu Sans required).
