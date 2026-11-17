# Run the script audit in CI

`tools/script_audit_ci.py` runs [`script_audit.py`](../tools/script_audit.py) on each URL and exits 1 when the page's CSP would let a hijacked vendor script do damage. Use it against staging, so a deploy that drops or loosens the CSP fails before it reaches production.

```
python tools/script_audit_ci.py https://staging.example.com https://staging.example.com/checkout
```

## What fails the job

| `--fail-on` | Fails when | Default |
|---|---|---|
| `data-out` | `connect-src` lets a script send data to any host | yes |
| `eval` | `'unsafe-eval'` is allowed, so an `eval()` fallback runs | yes |
| `new-domain` | a script from a brand-new domain would load | no |

Pick your own set with `--fail-on data-out,eval,new-domain`. `new-domain` is off by default because a nonce policy with `'strict-dynamic'` reports "loads": trusted scripts may add scripts from anywhere. That is how `'strict-dynamic'` is meant to work, but it is also what a hijacked vendor script would do.

Exit codes: `0` every page passes, `1` a page fails a check, `2` a page could not be fetched.

## GitHub Actions

Copy both files from `tools/` into your repo (here: `tools/`), then add `.github/workflows/script-audit.yml`:

```yaml
name: script audit
on:
  deployment_status:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * *"

permissions:
  contents: read

jobs:
  audit:
    if: github.event_name != 'deployment_status' || github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: CSP would stop a hijacked vendor script
        run: >
          python tools/script_audit_ci.py
          https://staging.example.com
          https://staging.example.com/checkout
```

The daily run is there because a CSP often lives in CDN or server config, not in the repo, so it can change without a commit.

## Limits

- It checks the policy, not the scripts. A pass means a hijacked script would be boxed in, not that no script is hijacked.
- It needs a URL the runner can reach without logging in. For pages behind a login, check the login page and one public page that sends the same headers.
- `data-out` looks at `connect-src` (fetch, XHR, WebSocket). The report also names `img-src` and `form-action` when they are open to any host, since those can carry data out too, but they don't fail the job.
- It reads the HTML the server returns. For scripts added at runtime, paste [`script_audit_console.js`](../tools/script_audit_console.js) into the browser console on the page.
