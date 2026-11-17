---
name: third-party-scripts
description: Audit which scripts an app loads from other domains and whether its Content Security Policy would stop a hijacked vendor script (the Optimizely attack, Nov 2026). Use when asked to check third-party scripts, CSP, browser supply-chain risk, or "could the Optimizely thing happen to us".
---

# Third-party script audit

Answer four questions for this app with file:line proof. Change nothing until the user says so.

1. Which scripts load from other domains?
2. If one of them is hijacked, would a payload from a new domain load? (`script-src`)
3. Would an `eval()` fallback run? (`'unsafe-eval'`)
4. Could stolen data be sent out? (`connect-src`)

## Steps

1. If the app has a public URL, run `python tools/script_audit.py <url>` from
   github.com/MeevraCode/claude-code-efficiency and keep the output.
2. Search, don't read whole files:
   - loaders: `<script[^>]+src=["']https?://`, `createElement\(['"]script`, `next/script`, `<Script`,
     `loadScript`, `GTM-`, `gtag(`, `unpkg.com`, `jsdelivr`, `cdnjs`, `optimizely`
   - CSP: `Content-Security-Policy`, `helmet(`, `contentSecurityPolicy`, `headers()` in next.config,
     `vercel.json`, `netlify.toml`, `_headers`, nginx `add_header`, `<meta http-equiv="Content-Security-Policy"`
3. For each other domain: what loads it (file:line), what it is (analytics, A/B tests, chat, payments),
   and whether anyone still needs it.
4. Answer questions 2-4 from the policy you found. No `script-src` and no `default-src` means scripts
   aren't limited. `'unsafe-eval'`, `*`, `https:` and `'strict-dynamic'` weaken it. Report-Only blocks nothing.
5. Propose, don't apply:
   - remove scripts nobody needs
   - a `Content-Security-Policy-Report-Only` first: `script-src 'self'` plus the exact vendor hosts and no
     `'unsafe-eval'`, `connect-src 'self'` plus the exact hosts, and a reporting endpoint; enforce it once the
     reports are clean
   - Subresource Integrity only for files that never change; vendor scripts that change can't use it
6. Output: a table (domain, loaded from, purpose, keep?), the four answers, the proposed policy. Under 40 lines.

Desktop apps (Electron, Tauri): the same questions apply to the renderer. Check the CSP meta tag in the HTML
and any `session.webRequest` header code.
