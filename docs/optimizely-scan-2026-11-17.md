# The Optimizely-hit organisations, one day after

On 16 Nov 2026 attackers wrote code into the Optimizely snippets of at least 178 organisations ([Report URI's write-up](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/)). Report URI saw every infected snippet clean by 23:11 UTC that night.

On 17 Nov, 16:14-16:16 UTC, I ran `tools/script_audit.py` against the main homepage of every organisation on Report URI's list (178 listed, 175 attempted, **152 checked**). The question isn't "are they infected", it's "if one of their vendor scripts got hijacked again today, what would their CSP stop?"

## Results (N = 152 homepages)

| If a vendor script got hijacked again | Homepages |
|---|---:|
| The `eval()` fallback this attack shipped would run | **151 (99%)** |
| A payload from a brand-new domain would load | **111 (73%)** |
| Stolen data could be sent out (`connect-src`) | **111 (73%)** |
| Both: new-domain payload loads and data can go out | 108 (71%) |
| New domain blocked, `eval()` fallback still runs (the HSBC pattern) | 40 (26%) |
| All three blocked | 1 |

| The CSP itself | Homepages |
|---|---:|
| No enforced CSP at all (7 of them have Report-Only, which blocks nothing) | 57 (38%) |
| Enforced, but it doesn't limit where scripts come from | 50 (33%) |
| Enforced with `'strict-dynamic'` (a trusted script may add any script) | 4 (3%) |
| Enforced with a script host allowlist | 41 (27%) |

| Scripts | |
|---|---:|
| Homepages still loading Optimizely with a `<script src>` tag | 47 (31%) |
| ...or loading it another way visible in the HTML (loader, preload) | 71 (47%) in total |
| Scripts from other domains with Subresource Integrity | 55 of 806 (7%) |

Loading Optimizely isn't a fault in itself. The point is that the same trust path is still in place, and for most of these pages the CSP wouldn't stop the next one.

## By sector (Report URI's sectors)

| Sector | Checked | No CSP | New-domain payload loads | eval() runs | Data out not blocked |
|---|---:|---:|---:|---:|---:|
| Banking & Finance | 29 | 9 | 13 | 29 | 13 |
| Technology & SaaS | 22 | 8 | 16 | 22 | 17 |
| Retail & Fashion | 18 | 1 | 17 | 17 | 16 |
| News & Media | 10 | 5 | 10 | 10 | 10 |
| Streaming & Entertainment | 9 | 5 | 6 | 9 | 6 |
| Industrial & Manufacturing | 8 | 3 | 4 | 8 | 4 |
| Healthcare & Pharma | 7 | 5 | 7 | 7 | 7 |
| Telecoms | 7 | 4 | 7 | 7 | 7 |
| Airlines & Travel | 6 | 5 | 6 | 6 | 6 |
| Crypto & Trading | 6 | 4 | 4 | 6 | 4 |
| Insurance | 5 | 1 | 5 | 5 | 5 |
| Other sectors (9) | 25 | 10 | 16 | 25 | 16 |

## How to read it

- **Homepage only.** Checkout, login and account pages often have a different, usually stricter CSP. Several organisations were hit on a sub-site; for those the main homepage was checked instead.
- **Static HTML and headers only.** Scripts that tag managers inject later aren't seen, so script and SRI counts are minimums. The browser-console version (`tools/script_audit_console.js`) sees those.
- **Exposure, not infection.** Nothing here says any site serves malware now.
- **What "would load / run / go out" means:** the CSP read against this attack's three steps (a script from a new domain, an `eval()` fallback, data sent with fetch/XHR). CSP doesn't stop in-page address swapping, and data can leave through other channels.
- **Multiple policies** (several headers, comma-separated, `<meta>`) are each enforced, and the strictest wins, as in browsers.
- **Groups count separately**, the way Report URI lists them: HSBC country sites (11), Levi's country sites (8) and Fluke brands (6) share one policy per group.
- **23 not checked:** 14 answered HTTP 403 to a scripted client (I didn't try to get around that), 3 timed out, 1 didn't resolve, 5 were geo, WAF or duplicate pages. Those may differ from the ones that answered.
- **Not like-for-like with Report URI's table** (68 / 50 / 17 / 24 on 16 Nov, over 256 hosts). This is a second measurement one day later, homepages only.
