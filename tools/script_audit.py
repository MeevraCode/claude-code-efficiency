#!/usr/bin/env python3
"""Which third-party scripts does a page load, and would its CSP stop a hijacked one?

Built after the Optimizely incident (16 Nov 2026): attackers wrote code into Optimizely
snippets that 178+ organisations load from cdn.optimizely.com. The code loaded a script
from a new domain, had an eval() fallback for when that domain was blocked, and sent
cards, cookies and screenshots to the attacker. This script asks the same questions of
any page:

  1. which scripts come from other domains (any of them can be the next Optimizely)
  2. would a payload from a brand-new domain load?          (script-src)
  3. would an eval() fallback run?                           ('unsafe-eval')
  4. could stolen data be sent out?                          (connect-src)

A page can send several policies (headers, comma-separated lists, meta tags). Each one is
enforced on its own, so something is allowed only if every policy allows it.

Usage:
  python tools/script_audit.py https://example.com [more URLs...]
  python tools/script_audit.py --json https://example.com

Limits: it reads the HTML and headers the server returns. Scripts that tag managers or
other scripts inject at runtime don't show up, so the list is the minimum. It checks
exposure, not infection. Python 3.8+, no dependencies.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")
MAX_BYTES = 6_000_000
SCRIPT_SCHEMES = ("http", "https")
CONNECT_SCHEMES = ("http", "https", "ws", "wss")
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp",
    "com.br", "com.cn", "com.tr", "co.in", "co.za", "com.mx", "com.sg", "com.hk",
    "com.my", "com.tw", "com.vn", "com.eg", "com.ph", "co.id", "co.kr", "com.ar",
}


def site_of(host):
    """example.co.uk / example.com from any subdomain (no public suffix list)."""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_js_type(t):
    """<script type="application/ld+json"> and friends are data, the browser never runs them."""
    t = t.strip().lower()
    return t in ("", "module") or "javascript" in t or "ecmascript" in t


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []        # dicts: src, integrity, type
        self.inline = 0
        self.meta_csp = []
        self._in_inline = False
        self._inline_buf = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append({"src": a["src"], "integrity": a.get("integrity", ""),
                                     "type": a.get("type", "")})
            elif is_js_type(a.get("type", "")):
                self._in_inline, self._inline_buf = True, []
        elif tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            self.meta_csp.append(a.get("content", ""))

    def handle_data(self, data):
        if self._in_inline:
            self._inline_buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_inline:
            if "".join(self._inline_buf).strip():
                self.inline += 1
            self._in_inline = False


def parse_csp(text):
    """'a b; c d' -> {'a': ['b'], 'c': ['d']} (first occurrence of a directive wins)."""
    out = {}
    for part in (text or "").split(";"):
        bits = part.strip().split()
        if bits and bits[0].lower() not in out:
            out[bits[0].lower()] = [b.lower() for b in bits[1:]]
    return out


def parse_policies(values):
    """One dict per policy. A header value can hold several policies separated by commas,
    and a page can send several headers and meta tags. The browser enforces each policy
    on its own, so they must not be merged into one."""
    return [p for v in values for p in map(parse_csp, (v or "").split(",")) if p]


def fetch(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.8"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        body = resp.read(MAX_BYTES)
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.geturl(), resp.status, resp.headers, body.decode(charset, errors="replace")


def policy_for(csp, *names):
    for n in names:
        if n in csp:
            return csp[n]
    return None


def any_host(values, schemes=SCRIPT_SCHEMES):
    """True if the source list matches every host: *, https:, https://* and the like."""
    for v in values:
        m = re.fullmatch(r"([a-z][a-z0-9+.-]*):(//\*(:(\*|\d+))?)?", v)
        if v == "*" or (m and m.group(1) in schemes):
            return True
    return False


def script_rule(csp):
    """How one policy treats a <script src> from a domain it has never seen."""
    elem = policy_for(csp, "script-src-elem", "script-src", "default-src")
    if elem is None:
        return "unlimited"
    if "'strict-dynamic'" in elem:      # host and scheme sources are ignored then
        return "strict-dynamic"
    return "any host" if any_host(elem) else "blocked"


def eval_allowed(csp):
    """eval() follows script-src (never script-src-elem). 'wasm-unsafe-eval' doesn't allow it."""
    evalp = policy_for(csp, "script-src", "default-src")
    return evalp is None or "'unsafe-eval'" in evalp


def open_to_any_host(csp, schemes, *names):
    src = policy_for(csp, *names)
    return src is None or any_host(src, schemes)


def assess(policies):
    """Answers the three hijack questions. `policies` is the list of enforced policies;
    something is allowed only if every one of them allows it."""
    if isinstance(policies, dict):
        policies = [policies]
    if not policies:
        return {"new_domain_script": "loads", "eval_fallback": "runs",
                "data_out": "not blocked", "other_ways_out": []}
    rules = [script_rule(p) for p in policies]
    if "blocked" in rules:
        new_domain = "blocked"
    elif "strict-dynamic" in rules:
        new_domain = "loads ('strict-dynamic' trusts what a trusted script adds)"
    else:
        new_domain = "loads"
    eval_ = "runs" if all(eval_allowed(p) for p in policies) else "blocked"
    conn = all(open_to_any_host(p, CONNECT_SCHEMES, "connect-src", "default-src") for p in policies)
    # connect-src covers fetch, XHR, WebSocket and sendBeacon. An image request or a form
    # post carries data out too, and those follow img-src and form-action.
    other = []
    if all(open_to_any_host(p, SCRIPT_SCHEMES, "img-src", "default-src") for p in policies):
        other.append("img-src")
    if all(open_to_any_host(p, SCRIPT_SCHEMES, "form-action") for p in policies):
        other.append("form-action")
    return {"new_domain_script": new_domain, "eval_fallback": eval_,
            "data_out": "not blocked" if conn else "blocked", "other_ways_out": other}


def csp_label_for(policies, report_only):
    if not policies:
        return "report-only (monitors, blocks nothing)" if report_only else "none"
    rules = [r for r in map(script_rule, policies) if r != "unlimited"]
    if not rules:
        return "enforced, but it doesn't limit scripts"
    if all(r == "any host" for r in rules):
        return "enforced, but scripts may come from any https host"
    return "enforced"


def audit(url):
    if "://" not in url:
        url = "https://" + url
    try:
        final, status, headers, html = fetch(url)
    except urllib.error.HTTPError as e:
        return {"url": url, "error": f"HTTP {e.code}"}
    except Exception as e:  # network, TLS, timeouts
        return {"url": url, "error": f"{type(e).__name__}: {e}"[:160]}

    p = ScriptParser()
    try:
        p.feed(html)
    except Exception:
        pass
    host = urllib.parse.urlsplit(final).hostname or ""
    page_site = site_of(host)
    third, first = [], 0
    for s in p.scripts:
        src = urllib.parse.urljoin(final, s["src"])
        h = urllib.parse.urlsplit(src).hostname or ""
        if not h or site_of(h) == page_site:
            first += 1
        else:
            third.append({"host": h, "src": src[:200], "sri": bool(s["integrity"])})

    hdr = headers.get_all("Content-Security-Policy") or []
    ro = headers.get_all("Content-Security-Policy-Report-Only") or []
    policies = parse_policies(hdr + p.meta_csp)
    hijack = assess(policies)
    says_unsafe_eval = any("'unsafe-eval'" in (policy_for(c, "script-src", "default-src") or [])
                           for c in policies)
    domains = {}
    for t in third:
        domains[t["host"]] = domains.get(t["host"], 0) + 1
    return {
        "url": url, "final_url": final, "status": status,
        "scripts_first_party": first, "scripts_third_party": len(third),
        "inline_scripts": p.inline,
        "third_party_domains": dict(sorted(domains.items(), key=lambda kv: -kv[1])),
        "third_party_with_sri": sum(t["sri"] for t in third),
        "loads_optimizely": any("optimizely" in t["host"] for t in third),
        # wider: an Optimizely CDN host anywhere in the HTML (inline loader, preload link)
        "optimizely_in_html": bool(re.search(r"cdn(-pci)?\.optimizely\.com", html, re.I)),
        "csp": csp_label_for(policies, ro),
        "csp_unsafe_eval": says_unsafe_eval and hijack["eval_fallback"] == "runs",
        "if_a_vendor_script_is_hijacked": hijack,
    }


def print_report(r):
    print(f"\n{r['url']}")
    if "error" in r:
        print(f"  could not fetch: {r['error']}")
        return
    if r["final_url"] != r["url"]:
        print(f"  (ended at {r['final_url']})")
    print(f"  scripts: {r['scripts_third_party']} from other domains, "
          f"{r['scripts_first_party']} own, {r['inline_scripts']} inline")
    if r["third_party_domains"]:
        doms = ", ".join(f"{d} ({n})" for d, n in list(r["third_party_domains"].items())[:12])
        more = len(r["third_party_domains"]) - 12
        print(f"  other domains: {doms}{f' +{more} more' if more > 0 else ''}")
        print(f"  SRI on other-domain scripts: {r['third_party_with_sri']} of {r['scripts_third_party']}")
    if r["loads_optimizely"]:
        print("  loads Optimizely: yes")
    elif r["optimizely_in_html"]:
        print("  loads Optimizely: referenced in the HTML (loader or preload)")
    print(f"  CSP: {r['csp']}{' (allows unsafe-eval)' if r['csp_unsafe_eval'] else ''}")
    h = r["if_a_vendor_script_is_hijacked"]
    print("  if one of those scripts got hijacked like Optimizely's:")
    print(f"    payload from a new domain: {h['new_domain_script']}")
    print(f"    eval() fallback:           {h['eval_fallback']}")
    print(f"    stolen data sent out:      {h['data_out']}")
    if h["data_out"] == "blocked" and h.get("other_ways_out"):
        print(f"      (that is fetch/XHR/WebSocket; still open to any host: {', '.join(h['other_ways_out'])})")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("urls", nargs="+")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()
    results = [audit(u) for u in args.urls]
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
        return
    for r in results:
        print_report(r)
    ok = [r for r in results if "error" not in r]
    if len(ok) > 1:
        print("\nsummary")
        print(f"  pages checked: {len(ok)}")
        print(f"  no CSP at all: {sum(r['csp'] == 'none' for r in ok)}")
        print(f"  a payload from a new domain would load: "
              f"{sum(r['if_a_vendor_script_is_hijacked']['new_domain_script'] != 'blocked' for r in ok)}")
        print(f"  a hijacked vendor script could send data out: "
              f"{sum(r['if_a_vendor_script_is_hijacked']['data_out'] == 'not blocked' for r in ok)}")
        print(f"  eval() fallback would run: "
              f"{sum(r['if_a_vendor_script_is_hijacked']['eval_fallback'] == 'runs' for r in ok)}")


if __name__ == "__main__":
    main()
