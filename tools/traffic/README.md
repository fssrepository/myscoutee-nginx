# Local traffic report

This tool runs on the operator's machine; it is not copied into the nginx image.
It reads nginx combined logs and optionally the separately enabled browser debug
log. It does not navigate the site or change the deployment.

| Option | Result |
| --- | --- |
| `--summary` | Compact campaign/session/activity counters |
| `--debug` | Add detailed browser packets to the report |
| `--netcup` | Read logs using the consuming application's existing pinned SSH configuration |
| `--format json` | Machine-readable output |

From the consuming application's root:

```sh
python3 nginx/tools/traffic/analyze-access-log.py --netcup --summary
python3 nginx/tools/traffic/analyze-access-log.py --netcup --debug
```

The current working directory supplies the existing application credential and
asset paths. `--ssh-config` and `--assets` can select them explicitly. No
credential belongs in this repository. See `--help` for time-window options.

Sessions and actions are inferred from observed requests. An Instagram user agent
alone does not prove a paid click. No further HTTP activity does not prove that
there was no click, rendering or reading. Browser debug is independent and off by
default.

```sh
python3 -B -m unittest discover -s tools/traffic -p 'test_*.py'
```
