#!/usr/bin/env python3
"""Fail a CI job when a page's CSP would let a hijacked vendor script do damage.

Runs script_audit.py on each URL and exits 1 if any page fails a chosen check:

  data-out     a hijacked script could send data to any host   (default)
  eval         an eval() fallback would run                    (default)
  new-domain   a script from a brand-new domain would load

Usage:
  python tools/script_audit_ci.py https://staging.example.com
  python tools/script_audit_ci.py --fail-on data-out,eval,new-domain https://staging.example.com/checkout

Exit codes: 0 all pages pass, 1 a page fails a check, 2 a page could not be fetched.
Point it at staging or production pages that send the real CSP headers.
Python 3.8+, no dependencies. Keep it next to script_audit.py.
"""
import argparse
import sys

import script_audit

CHECKS = {
    "data-out": ("data_out", "not blocked", "stolen data could be sent out"),
    "eval": ("eval_fallback", "runs", "an eval() fallback would run"),
    "new-domain": ("new_domain_script", "loads", "a payload from a new domain would load"),
}


def failures(result, checks):
    """The reasons one audit result fails, as short sentences."""
    answers = result["if_a_vendor_script_is_hijacked"]
    return [CHECKS[c][2] for c in checks if answers[CHECKS[c][0]].startswith(CHECKS[c][1])]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("urls", nargs="+")
    ap.add_argument("--fail-on", default="data-out,eval",
                    help="comma-separated checks: data-out, eval, new-domain (default: data-out,eval)")
    args = ap.parse_args()
    checks = [c.strip() for c in args.fail_on.split(",") if c.strip()]
    unknown = [c for c in checks if c not in CHECKS]
    if unknown or not checks:
        ap.error(f"--fail-on takes {', '.join(CHECKS)}; got {args.fail_on!r}")

    failed = errors = 0
    for url in args.urls:
        r = script_audit.audit(url)
        script_audit.print_report(r)
        if "error" in r:
            errors += 1
            continue
        why = failures(r, checks)
        failed += bool(why)
        print(f"  CI: {'FAIL: ' + '; '.join(why) if why else 'pass'}")
    print(f"\n{len(args.urls)} checked, {failed} failed, {errors} could not be fetched "
          f"(checks: {', '.join(checks)})")
    sys.exit(1 if failed else 2 if errors else 0)


if __name__ == "__main__":
    main()
