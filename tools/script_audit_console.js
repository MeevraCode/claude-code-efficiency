// script_audit_console.js: the same check as script_audit.py, run from inside the page.
//
// How: open the page, press F12, go to Console, paste this whole file, press Enter.
// (Chrome asks you to type "allow pasting" the first time.) Read it before you paste it:
// never paste code you haven't read into a console. It is about 110 lines.
//
// Why use it instead of the Python tool: the Python tool reads the HTML the server sends.
// This one sees what the browser really loaded, including scripts that a tag manager or
// another script injected after the page started. That is where most vendor scripts are.
//
// What it does: lists loaded scripts by domain, reads the page's CSP, then answers:
// if one of those scripts got hijacked like Optimizely's (16 Nov 2026), would a payload
// from a new domain load, would an eval() fallback run, could stolen data be sent out?
//
// Network: one request, to the page you are on (to read its CSP headers). Nothing else.
// Limits: the browser keeps about 250 resource entries, so very busy pages can be cut
// short; scroll and click around first to catch lazy scripts. Exposure, not infection.
(async () => {
  const TWO_PART = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.nz', 'co.jp',
    'com.br', 'com.cn', 'com.tr', 'co.in', 'co.za', 'com.mx', 'com.sg', 'com.hk',
    'com.my', 'com.tw', 'com.vn', 'com.eg', 'com.ph', 'co.id', 'co.kr', 'com.ar']);
  const siteOf = (host) => {
    const p = host.toLowerCase().split('.');
    return p.slice(p.length >= 3 && TWO_PART.has(p.slice(-2).join('.')) ? -3 : -2).join('.');
  };

  // 1. Scripts the page actually loaded.
  const tags = [...document.scripts];
  const isJs = (t) => t === '' || t === 'module' || /javascript|ecmascript/i.test(t);
  const inline = tags.filter((s) => !s.src && isJs(s.type.trim().toLowerCase()) && s.text.trim()).length;
  const sri = new Set(tags.filter((s) => s.src && s.integrity).map((s) => s.src));
  const urls = new Set(tags.filter((s) => s.src).map((s) => s.src));
  performance.getEntriesByType('resource')
    .filter((e) => e.initiatorType === 'script').forEach((e) => urls.add(e.name));
  const pageSite = siteOf(location.hostname);
  const byHost = {};
  for (const u of urls) {
    let host;
    try { host = new URL(u, location.href).hostname; } catch (e) { continue; }
    if (!host) continue; // data: and blob: scripts
    const row = byHost[host] ||= { domain: host, from: siteOf(host) === pageSite ? 'own' : 'other', scripts: 0, 'with SRI': 0, example: u.slice(0, 90) };
    row.scripts += 1;
    if (sri.has(u)) row['with SRI'] += 1;
  }
  const rows = Object.values(byHost).sort((a, b) => (a.from < b.from ? 1 : a.from > b.from ? -1 : b.scripts - a.scripts));
  const other = rows.filter((r) => r.from === 'other');

  // 2. The CSP. Headers come from one same-origin request; meta tags from the document.
  const parseCsp = (text) => {
    const out = {};
    for (const part of text.split(';')) {
      const bits = part.trim().split(/\s+/).filter(Boolean);
      if (bits.length && !(bits[0].toLowerCase() in out)) out[bits[0].toLowerCase()] = bits.slice(1).map((b) => b.toLowerCase());
    }
    return out;
  };
  // A header can hold several policies separated by commas. Each one is enforced on its own.
  const parsePolicies = (values) => values.flatMap((v) => (v || '').split(',')).map(parseCsp).filter((p) => Object.keys(p).length);
  let headers = [], reportOnly = false, note = '';
  try {
    const res = await fetch(location.href, { cache: 'no-store' });
    headers = [res.headers.get('content-security-policy')];
    reportOnly = !!res.headers.get('content-security-policy-report-only');
  } catch (e) {
    note = ' (could not re-read the headers, so this uses meta tags only: check the Network tab)';
  }
  const metas = [...document.querySelectorAll('meta[http-equiv="content-security-policy" i]')].map((m) => m.content);
  const policies = parsePolicies([...headers, ...metas]);

  // 3. The three questions. Something is allowed only if every policy allows it.
  const pick = (csp, ...names) => { for (const n of names) if (n in csp) return csp[n]; return null; };
  const anyHost = (values, schemes) => values.some((v) => {
    const m = /^([a-z][a-z0-9+.-]*):(\/\/\*(:(\*|\d+))?)?$/.exec(v);
    return v === '*' || (m && schemes.includes(m[1]));
  });
  const WEB = ['http', 'https'], CONNECT = ['http', 'https', 'ws', 'wss'];
  const scriptRule = (csp) => {
    const elem = pick(csp, 'script-src-elem', 'script-src', 'default-src');
    if (elem === null) return 'unlimited';
    if (elem.includes("'strict-dynamic'")) return 'strict-dynamic'; // host sources are ignored then
    return anyHost(elem, WEB) ? 'any host' : 'blocked';
  };
  // The eval check follows script-src, never script-src-elem. 'wasm-unsafe-eval' doesn't count.
  const evalAllowed = (csp) => { const s = pick(csp, 'script-src', 'default-src'); return s === null || s.includes("'unsafe-eval'"); };
  const open = (schemes, ...names) => policies.every((csp) => { const s = pick(csp, ...names); return s === null || anyHost(s, schemes); });

  const rules = policies.map(scriptRule);
  const limits = rules.filter((r) => r !== 'unlimited');
  let label, newDomain = 'loads', evalFallback = 'runs', dataOut = 'not blocked';
  if (!policies.length) {
    label = reportOnly ? 'report-only (monitors, blocks nothing)' : 'none';
  } else {
    label = !limits.length ? "enforced, but it doesn't limit scripts"
      : limits.every((r) => r === 'any host') ? 'enforced, but scripts may come from any https host' : 'enforced';
    if (rules.includes('blocked')) newDomain = 'blocked';
    else if (rules.includes('strict-dynamic')) newDomain = "loads ('strict-dynamic' trusts what a trusted script adds)";
    if (!policies.every(evalAllowed)) evalFallback = 'blocked';
    if (!open(CONNECT, 'connect-src', 'default-src')) {
      // connect-src covers fetch, XHR and WebSocket. Images and form posts carry data out too.
      const still = [open(WEB, 'img-src', 'default-src') && 'img-src', open(WEB, 'form-action') && 'form-action'].filter(Boolean);
      dataOut = 'blocked' + (still.length ? ` (fetch/XHR/WebSocket; still open to any host: ${still.join(', ')})` : '');
    }
  }

  console.table(rows);
  console.log([
    `${location.hostname}: ${other.reduce((n, r) => n + r.scripts, 0)} scripts from ${other.length} other domains, `
      + `${rows.filter((r) => r.from === 'own').reduce((n, r) => n + r.scripts, 0)} own, ${inline} inline. CSP: ${label}${note}`,
    `  payload from a new domain: ${newDomain}`,
    `  eval() fallback:           ${evalFallback}`,
    `  stolen data sent out:      ${dataOut}`,
  ].join('\n'));
})();
