# Access-log journey inference — MSC-124 / MSC-125

`analyze-access-log.py` reads the existing nginx combined access log and emits a
Hungarian timeline of **observed requests**, **probable actions**, and **possible
surface loads**. It also reads optional MSC-125 browser debug packets; it performs no browser actions.
It does not identify people or prove clicks, rendering, reading or authentication
outcomes from HTTP status alone.

## Operator nginx IP blocklist

The package-owned worker, timer, per-address messages and operator commands are
documented in [the packaging guide](../../packaging/README.md#operator-nginx-ip-blocklist).
The Netcup-specific initial list is `packaging/client-tools/netcup-blocked-ips.json`.

## Run against Netcup

From the repository root, with the existing stamped assets for the observed build:

```sh
python3 tools/traffic/analyze-access-log.py --netcup \
  --since 2026-10-20T05:03:00Z --assets frontend/prod
```

This runs the analyzer locally against Netcup's live nginx logs. It reads
`docker logs --timestamps --since … --tail … nginx`, then uses `docker exec nginx`
to tail `/var/log/nginx/landing-debug.log` when that file exists. Both inputs
respect the requested time window and line bound. It installs
nothing, changes no production data/configuration and creates no login session.
Remote input uses the existing gitignored
`packaging/client-tools/netcup.local.env` (`SSH_*` keys), checks its private file
permissions and verifies the saved SHA256 host fingerprint before password
authentication. Paramiko must already be installed for this option; no dependency
is needed for offline input. The release transport's `REMOTE_*`/OpenSSH
`known_hosts` interface does not consume this retained fingerprint configuration.

Use `--client 35cc0a --client 34ba5d` to select previously reported IP hashes.
The default snapshot is limited to 50,000 lines over six hours; `--since` and
`--max-lines` control it. A limit warning means the snapshot may be incomplete.
The current container's logs cannot recover logs lost when it was replaced.

## Offline / machine-readable output

```sh
python3 tools/traffic/analyze-access-log.py \
  packaging/dist/traffic-review-20261020/nginx.log --assets frontend/prod

python3 tools/traffic/analyze-access-log.py access.log.gz \
  --assets frontend/prod --format json

ssh root@your-host 'docker logs --timestamps --since 6h nginx 2>&1' |
  python3 tools/traffic/analyze-access-log.py - --assets frontend/prod
```

`--timezone` defaults to `Europe/Prague`; reports include the full date and local
time. `--gap-minutes` defaults to 30 minutes of inactivity. IP hashes are stable
six-character SHA256 prefixes, matching the earlier traffic review. They group
network addresses, not individual visitors. Full IPs, raw user agents, forwarded
addresses, arbitrary paths/query values, profile IDs and tokens are not emitted.
Raw input remains private. Do not commit raw logs or visitor timelines.

## How to interpret the result

The catalog reads the **existing** `app-version.json`, `index.html`, `app-sw.js`
and emitted JavaScript. It follows static imports to identify initial dependencies
and uses dynamic import targets and emitted Angular selectors to label possible
lazy surfaces. No build or source map is needed. The outermost compiled selector
is a heuristic label; a shared chunk does not establish an exact button. Unknown
chunk hashes receive no surface label; the catalog build ID is always reported.
Use assets from the deployed build, especially when examining historical logs.

The production worker precaches all build chunks, including lazy modules
(`frontend/scripts/stamp-prod-build.js`, `frontend/src/app-sw.js`). Bursts with at
least 20 different manifest resources within 45 seconds are marked as probable
precache. Module/HTML guesses within that burst (including a five-second lead-in
and two-second tail) are suppressed; API evidence is retained. This conservative
heuristic can also hide genuine early navigation. Isolated module loads remain
**possible**, since the log lacks request initiator/fetch-destination headers.

Instagram's service-worker requests may omit its Instagram suffix while retaining
the Android `wv` / `Version/4.0` UA. They are grouped with the same WebView engine,
not treated as external Chrome. A subsequent external-browser document request
on the same IP within five minutes is only a **possible** handoff: shared IPs and
IP changes prevent reliable identity matching. Cache-only handoffs can be absent.

The timeline and its coverage appendix explicitly distinguish these landing actions:

| Action | Existing evidence / limit |
| --- | --- |
| More article | `GET /api/landing/articles`: probable list opening/paging in HTTP mode; not proof of reading. |
| Individual article | `eagerDetail` is already in memory; no unique request is required. |
| About, Partners, Countries, Bug report | Local popup state in the loaded landing component; not observable. |
| Login button / Firebase popup | Popup code is in the entry chunk; configuration also loads at startup. Neither proves a Login click. |
| Session login | `POST /api/auth/session/login`: request and HTTP status observed; response body and provider are absent. |
| Explore / demo selector | `/api/auth/demo-users` is probable selector use; a lazy module alone is weaker. |
| Privacy / Terms / explanation | Content requests can occur automatically or from a cache; not an exact footer-button signal. |

Source owners: `entry-landing.component.ts` (`openIdeasPopup`,
`loadIdeaCardsPage`, footer popup handlers), `entry-page.component.html/.ts`,
`HttpIdeaPostsService.loadPublishedPostsPage`, `DemoBootstrapSelectorStore`,
`HttpUsersService`, `FirebaseAppService` and the existing production worker.
The nginx log only sees requests reaching this deployment. Direct Firebase/Google
traffic is outside it; this tool neither queries Firebase statistics nor claims
those statistics contain button events.

## Focused regression checks

```sh
python3 -m unittest discover -s tools/traffic -p 'test_*.py' -v
```

These use synthetic logs/assets only, including the observed Instagram/WebView
precache pattern, article API requests during precache, failed login requests,
unknown builds and report redaction. They start no server, watcher or browser.

## Temporary landing probe (MSC-125, default off)

The existing nginx SSI HTML rendering supplies `myscoutee_landing_debug` before
Angular starts. In `/etc/nginx/nginx.conf`, change the single map from
`map $host $myscoutee_landing_debug { default 0; }` to
`map $host $myscoutee_landing_debug { default 1; }`, then run `nginx -t` and
`nginx -s reload`. Set it back to 0 and reload to disable it. The immutable image
defaults to 0; recreating the container clears an in-container temporary activation.
The KVM gateway uses the same map. No application/database setting is added.

For each fresh landing document, a bounded **memory-only** recorder sends at
15/30/45/60 seconds, then removes its listeners and timers. Hiding the page
flushes early; returning from a native permission/provider dialog can continue
the same window. Page departure or leaving the Angular landing flushes and
stops it. There are at most eight attempts including early visibility flushes;
the final slot is reserved. No storage, persistent ID, queue, retries, mousemove
recording, polling or DOM observer is used. Disabled/offline cached pages install
no recorder. The inline code still has to be parsed with the HTML.

Packets contain visible time, the first trusted interaction and bounded counts,
local popup/permission/provider/handoff states, bootstrap/route/render milestones,
and bounded error names, code locations and message fingerprints. Each of the
first four distinct error samples per batch can also contain a cleaned message
(up to 160 characters), up to three normalized stack frames and a source label
(`angular`, `window`, `promise` or `resource`). Stack frames retain only function
names, JavaScript basenames and line/column positions. URL paths/query values,
emails, credential fields, quoted values, long identifiers, IPv4 addresses and
precise decimal values are redacted from messages; raw stack headers are omitted.
No form/DOM text, account data or browser storage is read. Redaction is best effort
for arbitrary third-party messages, so retain these diagnostics privately. Older
fingerprint-only samples remain readable. The analyzer validates and redacts the
optional details again before displaying them. Ordinary API events stay in the access log; Explore/list
requests and successful landing API responses are not duplicated. A render
callback does not prove the user saw the page; requesting a native popup or
handoff does not prove it opened.

The empty-body POST terminates at nginx with 204; its bounded encoded query is
written **only** to `/var/log/nginx/landing-debug.log`, without the Referer. It
never reaches Java, Redis or Mongo. The encoded query remains limited to 3500
characters; extra error details are trimmed before surrounding milestones, and
remaining overflow is dropped within the existing bound. The KVM gateway uses `/tmp/landing-debug.log`
because its filesystem is read-only. These are temporary container-local files;
retain a private copy before replacement if the evidence is needed.

`sendBeacon` queues early-departure packets; rejected queueing falls back once
to a small `fetch(..., keepalive:true)` POST. Neither guarantees delivery on
process termination. A close before JavaScript executes can leave only the
ordinary nginx HTML request. Missing telemetry is not proof of disinterest.

The optional `page` section records the initial/current state and up to twelve
lifecycle samples per batch: document readiness, DOM/load, focus/blur,
visibility, prerender activation, freeze/resume and pageshow/pagehide. A cached
page event name means the browser reported `event.persisted`; it is not a
promise that a future restoration will occur. A distinct pagehide sample can
flush after a recent hidden report, within the same eight-attempt cap. Freeze
also permits an early flush. No beforeunload/unload listener is installed.

Navigation/paint timings are sampled only while sending, without an observer or
extra timer: response start/end, DOM readiness, load, service-worker start,
prerender activation, first paint and first contentful paint, where supported.
These timestamps use navigation time origin; `offsetMs` is the recorder's start
relative to that origin. Lifecycle sample times remain relative to the recorder.
`hiddenForMs` is the current continuous hidden duration, cleared on visibility.
Zero API timestamps mean not reached/not prerendered as defined by the browser;
absent fields mean unavailable. Paint evidence does not prove human attention.

The existing nginx configurations map only fixed numeric request hints into a
second SSI JSON element: context `[purpose, user]`, with purpose 0=no header
signal, 1=prefetch/preview, 2=prerender; user 1 means `Sec-Fetch-User: ?1` was
present on the original HTML request. Purpose reads `Sec-Purpose`, `Purpose`
and `X-Purpose`. Raw headers are never embedded. Headers are client assertions;
missing hints do not prove either a human click or the absence of preloading.

State bits in `page.initial`, `page.state` and `[ms, event, state]` samples:

| Bit | Meaning |
| --- | --- |
| 1 / 2 | document visible / has focus |
| 4 | document prerendering |
| 8 / 16 | browser userActivation hasBeenActive / isActive |
| 32 / 64 | document interactive / complete; neither means loading |
| 128 / 256 | prerendering / userActivation API supported |
| 512 / 1024 | wasDiscarded / embedded in another window |

The analyzer decodes these flags. Lifecycle overflow keeps the first and recent
samples; request-size trimming can omit intermediate samples and milestones.
These observations cannot identify the host app's native Back/Close action or
establish why a person left. No hypothesis is automatically labeled as a cause.

Focused probe checks: `node --test frontend/scripts/landing-debug.test.mjs`.
The nginx transport-policy test checks the default-off gate, activation, SSI
and separate-file routing without an application server.
