# Local traffic report

This tool runs on the operator's machine; it is not copied into the nginx image.
It reads nginx combined logs and optionally the separately enabled browser debug
log. It does not navigate the site or change the deployment.

| Option | Result |
| --- | --- |
| `--summary` | Compact campaign/session/activity counters |
| `--debug` | Add detailed browser packets to the report |
| `--netcup` | Read logs using the consuming application's existing pinned SSH configuration |
| `--json` | Machine-readable output |

Use the consuming application's `tools/traffic/analyze-access-log.py` entrypoint
for Netcup; it supplies that checkout's credentials and asset paths. No credential
belongs in this repository. See `--help` for input and time-window options.

Sessions and actions are inferred from observed requests. An Instagram user agent
alone does not prove a paid click. No further HTTP activity does not prove that
there was no click, rendering or reading. Browser debug is independent and off by
default.

```sh
python3 -B -m unittest discover -s tools/traffic -p 'test_*.py'
```
