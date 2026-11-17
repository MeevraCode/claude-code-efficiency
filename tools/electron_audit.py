#!/usr/bin/env python3
"""If a script gets into an Electron renderer, what can it reach?

A poisoned npm package, an HTML-injection bug or a hijacked vendor script all end the
same way: someone else's code runs in the window. This script reads the project's files
and reports what that code could do next:

  1. renderer CSP: would a payload from a new domain load, would an eval() fallback run,
     could stolen data be sent out? (same three answers as script_audit.py)
  2. webPreferences: risky values in BrowserWindow options
  3. navigation: will-navigate / setWindowOpenHandler, and URL prefix checks inside them
  4. IPC handlers in the main process and whether they check who is calling
  5. the preload bridge: how many methods the page can call, generic pass-throughs
  6. sinks worth a manual look (shell.openExternal, <webview>, innerHTML, eval...)
  7. Electron version and fuses

Usage:
  python tools/electron_audit.py path/to/electron-project
  python tools/electron_audit.py path/to/electron-project --json
  python tools/electron_audit.py path/to/electron-project --fail-on high

Exit codes: 0 by default, 1 with --fail-on when a finding of that severity exists,
2 on bad input.

Limits: static and regex based. It never runs, builds or installs the project. It finds
patterns, not proof: a finding is a place to look, and a clean report is not an audit.
A CSP set at runtime in a way it doesn't know (a helper library, an object of directives,
a custom protocol handler) is missed. Python 3.8+, no dependencies. Keep it next to
script_audit.py.
"""
import argparse
import bisect
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import script_audit  # noqa: E402  (CSP parsing and the three answers live there)

SKIP_DIRS = {"node_modules", "coverage", "__tests__", "__mocks__", "test", "tests", "e2e",
             "playwright-report", "test-results"}
BUILD_DIRS = {"dist", "out", "build", "release", "dist-electron"}
CODE_EXT = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx", ".vue", ".svelte"}
HTML_EXT = {".html", ".htm"}
MAX_FILE = 2_000_000
SEVERITIES = ("high", "medium", "info")

DIRECTIVE = (r"(?:default|script|script-src-elem|script-src-attr|connect|style|img|font|"
             r"worker|frame|child|object|media|manifest)-src|base-uri|form-action|frame-ancestors")
STRING = re.compile(r"""'((?:\\.|[^'\\\n])*)'|"((?:\\.|[^"\\\n])*)"|`((?:\\.|[^`\\])*)`""")
CSP_NAME = re.compile(r"Content-Security-Policy(-Report-Only)?", re.I)
CODE_META = re.compile(r"""http-equiv=\\?["']Content-Security-Policy\\?["']\s+content=\\?(["'])(.+?)\\?\1""",
                       re.I)

# key: (risky value, severity, what it means)
RISKY_PREFS = {
    "nodeIntegration": ("true", "high", "page scripts get Node.js (files, processes)"),
    "contextIsolation": ("false", "high", "page scripts share a world with the preload and can reach its internals"),
    "webSecurity": ("false", "high", "same-origin policy is off"),
    "enableRemoteModule": ("true", "high", "the page can call main-process modules"),
    "nodeIntegrationInSubFrames": ("true", "high", "iframes get the preload and Node.js"),
    "nodeIntegrationInWorker": ("true", "high", "web workers get Node.js"),
    "sandbox": ("false", "medium", "the renderer process runs without the Chromium sandbox"),
    "allowRunningInsecureContent": ("true", "medium", "an https page may run http scripts"),
    "experimentalFeatures": ("true", "medium", "experimental Chromium features are on"),
    "webviewTag": ("true", "medium", "<webview> tags are allowed"),
}
# key: (default, Electron major it became the default in)
PREF_DEFAULTS = {"contextIsolation": ("on", 12), "sandbox": ("on", 20), "nodeIntegration": ("off", 5)}

RENDERER_SINKS = [
    (r"\beval\s*\(", "eval("),
    (r"\bnew\s+Function\s*\(", "new Function("),
    (r"\.innerHTML\s*\+?=(?!=)(?!\s*(''|\"\"|``)\s*[;\n])", "innerHTML ="),
    (r"\.outerHTML\s*\+?=(?!=)", "outerHTML ="),
    (r"\binsertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\bdocument\.write(ln)?\s*\(", "document.write"),
    (r"\bdangerouslySetInnerHTML\b", "dangerouslySetInnerHTML"),
]
MAIN_HINT = re.compile(r"""(?:from|require\()\s*['"](electron|node:[\w/]+|fs|path|child_process|os)['"]""")
RENDERER_DIRS = {"renderer", "web", "ui", "frontend", "client", "views", "components", "pages"}
MAIN_DIRS = {"main", "electron", "backend", "server", "preload", "node", "scripts", "tools"}
SENDER_DIRECT = re.compile(r"\bsenderFrame\b|\.sender\s*(?:\.id\b|\.getURL\b|\.url\b|[!=]==?)|[!=]==?\s*[\w.]+\.sender\b")
SENDER_HELPER = re.compile(r"\b[\w.$]*(?:sender|trusted|origin)\w*\s*\(\s*(?:event|evt|ev|e|_event)\b", re.I)


# ---------------------------------------------------------------- reading files

def blank_comments(text):
    """Replace // and /* */ comments with spaces (newlines kept, so offsets and lines hold).
    Quotes are tracked so 'http://x' survives; a ' or " string ends at the line end at the latest."""
    out, i, n, quote = list(text), 0, len(text), ""
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote or (c == "\n" and quote != "`"):
                quote = ""
        elif c in "'\"`":
            quote = c
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out[i:end] = " " * (end - i)
            i = end
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out[i:end] = [ch if ch == "\n" else " " for ch in text[i:end]]
            i = end
            continue
        i += 1
    return "".join(out)


class Src:
    """One file: its path relative to the project, its text, and offset -> line."""

    def __init__(self, rel, text, code=True):
        self.rel = rel
        self.text = blank_comments(text) if code else text
        self._starts = [0] + [m.end() for m in re.finditer("\n", self.text)]

    def line(self, pos):
        return bisect.bisect_right(self._starts, pos)

    def line_text(self, pos):
        ln = self.line(pos)
        end = self._starts[ln] if ln < len(self._starts) else len(self.text)
        return self.text[self._starts[ln - 1]:end].strip()


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE:
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def walk(top, root, exts, skip_build):
    """Files under `top` with one of `exts`, as (relative path, text). Hidden folders,
    dependencies and tests are skipped; build output too when skip_build is set."""
    for folder, dirs, files in os.walk(top):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS
                         and not (skip_build and d in BUILD_DIRS))
        for name in sorted(files):
            low = name.lower()
            if os.path.splitext(low)[1] not in exts:
                continue
            if low.endswith((".d.ts", ".min.js")) or re.search(r"\.(test|spec)\.", low):
                continue
            text = read_text(os.path.join(folder, name))
            if text is not None:
                yield os.path.relpath(os.path.join(folder, name), root).replace(os.sep, "/"), text


def build_dirs(root):
    """Build output folders (dist, out, ...) anywhere in the project, outermost only."""
    found = []
    for folder, dirs, _ in os.walk(root):
        found += [os.path.join(folder, d) for d in dirs if d in BUILD_DIRS]
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS
                   and d not in BUILD_DIRS]
    return found


def load_project(root):
    code = [Src(rel, text) for rel, text in walk(root, root, CODE_EXT, True)]
    source_html = [Src(rel, text, code=False) for rel, text in walk(root, root, HTML_EXT, True)]
    built_html = [Src(rel, text, code=False) for top in build_dirs(root)
                  for rel, text in walk(top, root, HTML_EXT, False)]
    return {"root": root, "code": code, "source_html": source_html, "built_html": built_html}


# ---------------------------------------------------------------- small text helpers

def balanced(text, open_pos):
    """Index just past the bracket that closes the one at open_pos (strings skipped)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    depth, i, n, quote = 0, open_pos, len(text), ""
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote or (c == "\n" and quote != "`"):
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c in pairs:
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth <= 0:
                return i + 1
        i += 1
    return n


def statement_end(text, start):
    """End of the statement that starts at `start`: a ; or a line end outside all brackets."""
    depth, i, n, quote = 0, start, len(text), ""
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote or (c == "\n" and quote != "`"):
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return i
        elif depth == 0 and c == ";":
            return i
        elif depth == 0 and c == "\n" and not re.search(r"(=>|[=(,+\-*&|?:.])\s*$", text[start:i]) \
                and not re.match(r"\s*[.?:&|+)]", text[i:i + 40]):
            return i
        i += 1
    return n


def finding(severity, check, src, pos, message):
    return {"severity": severity, "check": check, "file": src.rel if src else "",
            "line": src.line(pos) if src else 0, "message": message}


def where(f):
    return f"{f['file']}:{f['line']}" if f.get("line") else f["file"]


def definition_body(code, name):
    """Text of `function name(...) {...}` or `const name = ...` anywhere in the project."""
    pat = re.compile(r"\bfunction\s+%s\s*\(|\b(?:const|let|var)\s+%s\b[^=\n]*=" % ((re.escape(name),) * 2))
    for src in code:
        m = pat.search(src.text)
        if not m:
            continue
        if m.group(0).endswith("("):
            params_end = balanced(src.text, m.end() - 1)
            brace = src.text.find("{", params_end)
            return src.text[m.start():balanced(src.text, brace) if brace >= 0 else params_end]
        return src.text[m.start():statement_end(src.text, m.end())]
    return ""


def with_called_helpers(code, body, depth=2):
    """`body` plus the bodies of project functions it calls, two levels deep. A navigation
    handler that says `if (!isAllowed(url))` is judged by what isAllowed does."""
    seen, texts, frontier = set(), [body], [body]
    for _ in range(depth):
        nxt = []
        for text in frontier:
            for name in set(re.findall(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(", text)) - seen:
                seen.add(name)
                helper = definition_body(code, name)
                if helper:
                    nxt.append(helper)
        texts += nxt
        frontier = nxt
    return texts


# ---------------------------------------------------------------- 1. CSP

def unquote(m):
    raw = next(g for g in m.groups() if g is not None)
    return re.sub(r"\\(['\"`])", r"\1", raw)


def policy_groups(src):
    """CSP policies written as string literals: one string, or neighbouring directive
    strings (an array joined in code, or strings added together). Yields (start, end, text)."""
    group = None
    for m in STRING.finditer(src.text):
        value = unquote(m)
        if not re.match(r"\s*(?:%s)\s+\S" % DIRECTIVE, value):
            continue
        gap = src.text[group[1]:m.start()] if group else ""
        if group and len(gap) < 200 and not re.search(r"[;\]]", gap):
            group = (group[0], m.end(), group[2] + [value])
        else:
            if group:
                yield group[0], group[1], "; ".join(group[2])
            group = (m.start(), m.end(), [value])
    if group:
        yield group[0], group[1], "; ".join(group[2])


def binding_name(before):
    """The constant or property a policy literal is assigned to, from the text before it."""
    m = re.search(r"(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*\[?\s*$", before) \
        or re.search(r"([\w$]+)\s*=\s*\[?\s*$", before)
    return m.group(1) if m else ""


def header_before(text):
    """'enforced' or 'report-only' from the CSP header name nearest before a policy, else ''."""
    names = CSP_NAME.findall(text)
    return ("report-only" if names[-1] else "enforced") if names else ""


def mode_from(texts):
    """enforced / report-only / unclear, from the code just before each place a policy is used."""
    modes = [header_before(t) for t in texts]
    return "enforced" if "enforced" in modes else "report-only" if "report-only" in modes else "unclear"


def usage_windows(code, name):
    """The code just before every use of a constant (where the header or meta key would be)."""
    out = []
    for src in code:
        for m in re.finditer(r"(?<![\w$.])%s\b" % re.escape(name), src.text):
            out.append(src.text[max(0, m.start() - 200):m.end()])
    return out


def classify_policy(code, src, start):
    """(mode, kind) for a policy literal. kind: 'meta' (written into the HTML) or 'header'."""
    before = src.text[max(0, start - 160):start]
    name = binding_name(before)
    windows = [before] + (usage_windows(code, name) if name else [])
    mode = mode_from(windows)
    if mode == "unclear" and re.search(r"report.?only", name, re.I):
        mode = "report-only"
    used = " ".join(w for w in windows if header_before(w) == "enforced") or " ".join(windows)
    is_meta = re.search(r"http-equiv|<meta", used, re.I) or \
        (mode == "unclear" and "transformIndexHtml" in src.text)
    return mode, "meta" if is_meta else "header", name


def code_policies(code):
    out = []
    for src in code:
        if "-src" not in src.text and "Content-Security-Policy" not in src.text:
            continue
        for m in CODE_META.finditer(src.text):
            out.append({"file": src.rel, "line": src.line(m.start()), "policy": m.group(2),
                        "mode": "enforced", "kind": "meta", "name": ""})
        for start, _end, text in policy_groups(src):
            mode, kind, name = classify_policy(code, src, start)
            out.append({"file": src.rel, "line": src.line(start), "policy": text,
                        "mode": mode, "kind": kind, "name": name})
    return out


def html_pages(sources, built):
    """Pages that run script, with the CSP meta tags each one carries."""
    pages = []
    for src in sources:
        p = script_audit.ScriptParser()
        try:
            p.feed(src.text)
        except Exception:
            continue
        if not (p.scripts or p.inline):
            continue
        m = re.search(r"http-equiv\s*=\s*[\"']?Content-Security-Policy[\"'\s>]", src.text, re.I)
        pages.append({"file": src.rel, "line": src.line(m.start()) if m else 0,
                      "policies": [c for c in p.meta_csp if c.strip()], "built": built})
    return pages


def openness(answers):
    return sum([not answers["new_domain_script"].startswith("blocked"),
                answers["eval_fallback"] == "runs", answers["data_out"] == "not blocked"])


def check_csp(project):
    code = code_policies(project["code"])
    built = html_pages(project["built_html"], True)
    source = html_pages(project["source_html"], False)
    pages = built or source
    headers = [c for c in code if c["kind"] == "header" and c["mode"] != "report-only"]
    injected = [] if built else [c for c in code if c["kind"] == "meta" and c["mode"] != "report-only"]
    extra = headers + injected

    def answers_for(page):
        values = (page["policies"] if page else []) + [c["policy"] for c in extra]
        return script_audit.assess(script_audit.parse_policies(values))

    weakest = max(pages, key=lambda p: openness(answers_for(p))) if pages else None
    answers = answers_for(weakest)
    parts = []
    if weakest and weakest["policies"]:
        same = [c for c in code if c["kind"] == "meta" and script_audit.parse_csp(c["policy"])
                in map(script_audit.parse_csp, weakest["policies"])]
        parts.append(f"{'built' if weakest['built'] else 'source'} HTML ({where(weakest)})"
                     + (f", the policy written by {where(same[0])}" if same else ""))
    parts += [f"code ({where(c)})" for c in extra]
    if not parts:
        decided = (f"no enforced policy; {'built' if weakest['built'] else 'source'} HTML "
                   f"({weakest['file']}) has no CSP meta tag") if weakest else "no enforced policy found"
    else:
        decided = " + ".join(parts)
    notes = []
    if not built:
        notes.append("no build output found: the answer is from source only")
    stale = [c for c in code if built and c["kind"] == "meta" and c["mode"] != "report-only"]
    if stale and weakest and not weakest["policies"]:
        notes.append(f"code defines a policy ({where(stale[0])}) that is not in the built HTML: "
                     "rebuild and run again")
    if any(c["mode"] == "unclear" for c in extra):
        notes.append("where a code policy is applied was not found; it is counted as enforced, check by hand")
    return {"pages": pages, "code_policies": code, "decided_by": decided, "notes": notes,
            "enforced": bool(parts), "answers": answers}


def csp_findings(csp):
    out = []
    a = csp["answers"]
    blank = {"file": "", "line": 0, "check": "csp"}
    if not csp["enforced"]:
        out.append(dict(blank, severity="high", message="no enforced CSP for the renderer"))
    else:
        for key, bad, text in (("new_domain_script", "loads", "a script from a new domain would load"),
                               ("eval_fallback", "runs", "eval() would run"),
                               ("data_out", "not blocked", "data could be sent to any host")):
            if a[key].startswith(bad):
                out.append(dict(blank, severity="medium", message=f"the CSP has a gap: {text}"))
    for c in csp["code_policies"]:
        if c["mode"] == "report-only":
            out.append({"severity": "info", "check": "csp", "file": c["file"], "line": c["line"],
                        "message": "report-only policy: it logs violations and blocks nothing"})
    return out


# ---------------------------------------------------------------- 2. webPreferences

def electron_major(version):
    m = re.search(r"(\d+)\.", version or "")
    return int(m.group(1)) if m else None


def check_web_preferences(project, version):
    out, seen, windows = [], set(), 0
    pref = re.compile(r"\b(%s)\b['\"]?\s*:\s*(true|false)\b" % "|".join(RISKY_PREFS))
    for src in project["code"]:
        windows += len(re.findall(r"\bnew\s+(?:BrowserWindow|BrowserView|WebContentsView)\s*\(", src.text))
        for m in pref.finditer(src.text):
            key, value = m.group(1), m.group(2)
            seen.add(key)
            bad, severity, why = RISKY_PREFS[key]
            if value == bad:
                out.append(finding(severity, "webPreferences", src, m.start(), f"{key}: {value} ({why})"))
    major = electron_major(version)
    defaults = []
    for key, (state, since) in PREF_DEFAULTS.items():
        if key in seen:
            continue
        if major is not None and major < since:
            out.append(finding("medium", "webPreferences", None, 0,
                               f"{key} is not set and Electron {major} is older than {since}, "
                               f"where '{state}' became the default"))
        else:
            defaults.append(f"{key} not set: Electron default is {state} (since {since})")
    return out, {"windows": windows, "defaults": defaults}


# ---------------------------------------------------------------- 3. navigation

NAV_EVENTS = ("will-navigate", "will-redirect", "will-frame-navigate", "new-window")


def prefix_checks(texts):
    """URL checks that compare only the start (or a part) of the address."""
    out = []
    for text in texts:
        for m in re.finditer(r"\.startsWith\(\s*([^)]*)\)", text):
            arg = m.group(1).strip()
            lit = STRING.fullmatch(arg)
            if not lit:
                out.append(("medium", f"startsWith({arg}): a prefix check; 'http://host:5173' also "
                                      "matches 'http://host:5173.evil.example'. Compare the parsed origin"))
            elif re.match(r"file:", unquote(lit)):
                out.append(("high", f"startsWith({arg}): any local HTML file may load in this window, "
                                    "with the preload bridge"))
            elif re.fullmatch(r"[a-z][\w+.-]*://[^/]+", unquote(lit)):
                out.append(("high", f"startsWith({arg}): also matches {unquote(lit)}.evil.example"))
        for m in re.finditer(r"\.indexOf\(\s*(['\"`][^)]*)\)\s*===?\s*0", text):
            out.append(("medium", f"indexOf({m.group(1)}) === 0: a prefix check, same problem as startsWith"))
        for m in re.finditer(r"\.includes\(\s*(['\"`][^)]*)\)", text):
            out.append(("high", f"includes({m.group(1)}): matches the text anywhere in the URL, "
                                "for example in a query string"))
    return out


def check_navigation(project):
    out, has = [], {"will-navigate": False, "window-open": False}
    event = re.compile(r"\.(?:on|once|addListener)\(\s*['\"](%s)['\"]" % "|".join(NAV_EVENTS))
    for src in project["code"]:
        handlers = [(m.group(1), m.start(), src.text.index("(", m.start())) for m in event.finditer(src.text)]
        handlers += [("setWindowOpenHandler", m.start(), m.end() - 1)
                     for m in re.finditer(r"\bsetWindowOpenHandler\s*\(", src.text)]
        for name, pos, paren in handlers:
            if name == "will-navigate":
                has["will-navigate"] = True
            if name in ("setWindowOpenHandler", "new-window"):
                has["window-open"] = True
            body = src.text[paren:balanced(src.text, paren)]
            for severity, message in prefix_checks(with_called_helpers(project["code"], body)):
                out.append(finding(severity, "navigation", src, pos, f"{name}: {message}"))
    if not has["will-navigate"]:
        out.append(finding("medium", "navigation", None, 0,
                           "no will-navigate handler: the window can be sent to any URL"))
    if not has["window-open"]:
        out.append(finding("medium", "navigation", None, 0,
                           "no setWindowOpenHandler: window.open() can create new windows"))
    return out, has


# ---------------------------------------------------------------- 4. IPC handlers

IPC_CALL = re.compile(r"\bipcMain\.(handle|handleOnce|on|once)\s*\(\s*")


def enclosing_wrapper(text, pos, channel_arg):
    """Name of the local function around an ipcMain call whose parameter is the channel."""
    decl = re.compile(r"(?:const|let|var)\s+([\w$]+)[^=;]*=\s*(?:async\s*)?(?:function\s*)?\(([^)]*)\)[^;{]*(?:=>|\{)"
                      r"|function\s+([\w$]+)\s*\(([^)]*)\)")
    best = None
    for m in decl.finditer(text[max(0, pos - 400):pos]):
        best = m
    if not best:
        return ""
    params = best.group(2) if best.group(1) else best.group(4)
    return (best.group(1) or best.group(3)) if re.search(r"\b%s\b" % re.escape(channel_arg), params) else ""


def has_sender_check(body):
    return bool(SENDER_DIRECT.search(body) or SENDER_HELPER.search(body))


def wrapper_calls(project, src, name):
    """Calls like name('channel', ...) in the wrapper's file and in files that import it."""
    call = re.compile(r"(?<![.\w$])%s\s*\(\s*['\"`]" % re.escape(name))
    imports = re.compile(r"(?:import|require)[^\n;]*\b%s\b" % re.escape(name))
    total = 0
    for other in project["code"]:
        if other is src or imports.search(other.text):
            total += len(call.findall(other.text))
    return total


def check_ipc(project):
    handlers, checked, dynamic, wrappers = 0, 0, 0, []
    for src in project["code"]:
        for m in IPC_CALL.finditer(src.text):
            paren = src.text.index("(", m.start())
            body = src.text[paren:balanced(src.text, paren)]
            first = re.match(r"[A-Za-z_$][\w$]*", src.text[m.end():])
            name = enclosing_wrapper(src.text, m.start(), first.group(0)) if first else ""
            if name:
                count = wrapper_calls(project, src, name)
                wrappers.append({"name": name, "file": src.rel, "line": src.line(m.start()),
                                 "handlers": count, "sender_check": has_sender_check(body)})
                handlers += count
                checked += count if has_sender_check(body) else 0
                continue
            handlers += 1
            after = src.text[m.end() + len(first.group(0)):][:1] if first else ""
            dynamic += 1 if first and after != "." and not first.group(0).isupper() else 0
            checked += 1 if has_sender_check(body) else 0
    proof = sender_proof(project)
    covering = [w for w in wrappers if w["sender_check"] and w["handlers"] == handlers]
    if handlers == 0:
        label = "none found"
    elif checked == 0:
        label = "none"
    elif covering and len(wrappers) == 1:
        label = f"one wrapper covers all {handlers} ({covering[0]['file']}:{covering[0]['line']})"
    else:
        label = f"{checked} of {handlers} handlers"
    out = []
    if handlers and checked < handlers:
        out.append(finding("high" if checked == 0 else "medium", "ipc", None, 0,
                           f"{handlers - checked} of {handlers} IPC handlers do not check the sender: "
                           "any frame that can reach the bridge can call them"))
    if checked and not proof:
        out.append(finding("medium", "ipc", None, 0, "a sender check helper is called, but no use of "
                           "senderFrame or event.sender was found in the project: check it by hand"))
    if dynamic:
        out.append(finding("info", "ipc", None, 0, f"{dynamic} registration(s) take the channel name "
                           "from a variable: the handler count is a minimum"))
    return out, {"handlers": handlers, "checked": checked, "sender_check": label,
                 "wrappers": wrappers, "sender_proof": proof}


def sender_proof(project):
    """First place the project reads senderFrame or compares event.sender."""
    for src in project["code"]:
        m = SENDER_DIRECT.search(src.text)
        if m:
            return f"{src.rel}:{src.line(m.start())}"
    return ""


# ---------------------------------------------------------------- 5. preload bridge

def is_preload(src):
    return "preload" in os.path.basename(src.rel).lower() or "contextBridge" in src.text


def exposed_text(src, m):
    """What an exposeInMainWorld call exposes: its arguments, plus the object literal
    behind an identifier argument (`const api = {...}; exposeInMainWorld('x', api)`)."""
    paren = src.text.index("(", m.start())
    args = src.text[paren:balanced(src.text, paren)]
    ident = re.search(r",\s*([A-Za-z_$][\w$]*)\s*\)$", args)
    if ident:
        d = re.search(r"\b(?:const|let|var)\s+%s\b[^=\n]*=\s*\{" % re.escape(ident.group(1)), src.text)
        if d:
            args += src.text[d.end() - 1:balanced(src.text, d.end() - 1)]
    return args


PARAMS = r"\(([^()]*)\)\s*(?::[^=>{]+)?(?:=>|\{)"
OWNERS = [  # (pattern, the function is a property of an object)
    (re.compile(r"([\w$]+)\s*:\s*(?:async\s*)?(?:function\s*)?" + PARAMS), True),
    (re.compile(r"[,{]\s*(?:async\s+)?([\w$]+)\s*" + PARAMS), True),
    (re.compile(r"(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\s*)?" + PARAMS), False),
    (re.compile(r"function\s+([\w$]+)\s*" + PARAMS), False),
]


def channel_owner(before, arg):
    """The nearest function before an ipcRenderer call that takes `arg` as a parameter:
    True if it is an object property (exposed as written), False if a local helper, None if none."""
    best = (-1, None)
    for pattern, is_property in OWNERS:
        for m in pattern.finditer(before):
            if re.search(r"\b%s\b" % re.escape(arg), m.group(2)) and m.end() > best[0]:
                best = (m.end(), is_property)
    return best[1]


def passthroughs(src):
    """ipcRenderer calls whose channel is a parameter of the function around them."""
    out = []
    for m in re.finditer(r"\bipcRenderer\.(invoke|send|sendSync|on|once|postMessage)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]",
                         src.text):
        arg = m.group(2)
        owner = channel_owner(src.text[max(0, m.start() - 300):m.start()], arg)
        if owner is None:
            continue
        listed = re.search(r"\.includes\(\s*%s\b|\.has\(\s*%s\b|\[\s*%s\s*\]" % ((re.escape(arg),) * 3),
                           src.text[max(0, m.start() - 300):m.end() + 50])
        out.append({"pos": m.start(), "method": m.group(1), "property": owner, "allowlist": bool(listed)})
    return out


def check_preload(project):
    out, exposes, methods, files = [], 0, 0, []
    node = r"fs|child_process|childProcess|shell|require|process|os"
    for src in filter(is_preload, project["code"]):
        files.append(src.rel)
        methods += len(re.findall(r"\bipcRenderer\.(?:invoke|send|sendSync|on|once|postMessage)\s*\(", src.text))
        for m in re.finditer(r"\bexposeInMainWorld\s*\(", src.text):
            exposes += 1
            text = exposed_text(src, m)
            if re.search(r"[,{:(]\s*ipcRenderer\s*[,})]", text):
                out.append(finding("high", "preload", src, m.start(),
                                   "ipcRenderer itself is exposed: the page can call any channel"))
            mod = re.search(r"[,{(]\s*(%s)\s*[,})]|:\s*(%s)\s*[,}]" % (node, node), text)
            if mod:
                out.append(finding("high", "preload", src, m.start(),
                                   f"a Node module is exposed to the page: {mod.group(1) or mod.group(2)}"))
        for p in passthroughs(src):
            call = f"ipcRenderer.{p['method']}(channel, ...)"
            if p["allowlist"]:
                out.append(finding("info", "preload", src, p["pos"],
                                   f"{call}: the channel comes from the caller and is checked against a list"))
            elif p["property"]:
                out.append(finding("high", "preload", src, p["pos"],
                                   f"generic pass-through {call}: the page picks the channel, so it can "
                                   "call every handler"))
            else:
                out.append(finding("medium", "preload", src, p["pos"],
                                   f"helper {call} takes the channel as an argument: make sure the helper "
                                   "itself is not exposed"))
    return out, {"files": files, "expose_calls": exposes, "methods": methods}


# ---------------------------------------------------------------- 6. sinks

def is_renderer(src, page_scripts):
    ext = os.path.splitext(src.rel)[1]
    parts = set(src.rel.lower().split("/")[:-1])
    if is_preload(src):
        return False
    if ext in (".jsx", ".tsx", ".vue", ".svelte") or os.path.basename(src.rel) in page_scripts:
        return True
    if parts & RENDERER_DIRS:
        return True
    return not (parts & MAIN_DIRS) and not MAIN_HINT.search(src.text)


def check_sinks(project):
    out = []
    page_scripts = {os.path.basename(s) for h in project["source_html"]
                    for s in re.findall(r"<script[^>]+src=[\"']([^\"']+)", h.text)}
    for src in project["code"]:
        for m in re.finditer(r"\bshell\.openExternal\s*\(\s*", src.text):
            paren = src.text.index("(", m.start())
            arg = src.text[paren + 1:balanced(src.text, paren) - 1].strip()
            lit = STRING.fullmatch(arg)
            if not lit or "${" in arg:
                out.append(finding("medium", "sinks", src, m.start(),
                                   "shell.openExternal with a value built at runtime: make sure the page "
                                   "cannot choose the scheme or host"))
        for m in re.finditer(r"\bloadURL\s*\(\s*(['\"`])(https?://[^'\"`]*)\1", src.text):
            if not re.match(r"https?://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", m.group(2)):
                sev = "high" if m.group(2).startswith("http://") else "medium"
                out.append(finding(sev, "sinks", src, m.start(),
                                   f"loadURL of a remote page ({m.group(2)[:60]}): remote content runs in "
                                   "the window"))
        if "<webview" in src.text:
            out.append(finding("medium", "sinks", src, src.text.index("<webview"), "<webview> tag"))
        if is_renderer(src, page_scripts):
            for pattern, label in RENDERER_SINKS:
                for m in re.finditer(pattern, src.text):
                    out.append(finding("medium", "sinks", src, m.start(), f"{label} in renderer code"))
    for src in project["source_html"]:
        if "<webview" in src.text:
            out.append(finding("medium", "sinks", src, src.text.index("<webview"), "<webview> tag"))
    return out


# ---------------------------------------------------------------- 7. info

def package_info(project):
    version, fuses = "", False
    for folder, dirs, files in os.walk(project["root"]):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS and d not in BUILD_DIRS]
        if "package.json" not in files:
            continue
        text = read_text(os.path.join(folder, "package.json")) or ""
        fuses = fuses or "@electron/fuses" in text
        try:
            data = json.loads(text)
        except ValueError:
            continue
        for group in ("devDependencies", "dependencies"):
            deps = data.get(group)
            if isinstance(deps, dict) and isinstance(deps.get("electron"), str):
                version = version or deps["electron"]
    fuses = fuses or any(re.search(r"\bflipFuses\b|@electron/fuses|\bFuseV1Options\b", s.text)
                         for s in project["code"])
    return {"electron": version, "fuses": fuses}


# ---------------------------------------------------------------- report

def bridge_line(ipc, preload, generic):
    count = preload["methods"] or ipc["handlers"]
    if not count:
        return "none found"
    unit = "methods" if preload["methods"] else "handlers"
    if generic and ipc["handlers"]:
        count, unit = f"every channel ({ipc['handlers']} handlers, generic pass-through)", ""
    if ipc["handlers"] == 0:
        return f"{count} {unit}; no ipcMain handlers found"
    if ipc["checked"] == 0:
        check = "no sender check"
    elif ipc["checked"] == ipc["handlers"]:
        check = "sender checked on all"
    else:
        check = f"sender checked on {ipc['checked']} of {ipc['handlers']} handlers"
    return f"{count} {unit}".strip() + f", {check}"


def audit(root):
    project = load_project(root)
    info = package_info(project)
    csp = check_csp(project)
    prefs_f, prefs = check_web_preferences(project, info["electron"])
    nav_f, nav = check_navigation(project)
    ipc_f, ipc = check_ipc(project)
    pre_f, preload = check_preload(project)
    findings = csp_findings(csp) + prefs_f + nav_f + ipc_f + pre_f + check_sinks(project)
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    node = [f for f in prefs_f if f["message"].startswith(("nodeIntegration: true", "contextIsolation: false"))]
    generic = any(f["severity"] == "high" and "pass-through" in f["message"] for f in pre_f)
    return {
        "path": root, "files_scanned": len(project["code"]), "electron": info["electron"],
        "fuses": info["fuses"], "csp": csp, "web_preferences": prefs, "navigation": nav,
        "ipc": ipc, "preload": preload, "findings": findings,
        "if_a_script_gets_into_the_renderer": dict(
            csp["answers"], ipc_bridge=bridge_line(ipc, preload, generic),
            node_in_renderer=bool(node)),
    }


def print_section(title, summary, findings, check, limit=8):
    print(f"\n{title}")
    for line in summary:
        print(f"  {line}")
    mine = [f for f in findings if f["check"] == check]
    for f in mine[:limit]:
        place = f"{where(f)}  " if f["file"] else ""
        print(f"  [{f['severity']}] {place}{f['message']}")
    if len(mine) > limit:
        print(f"  ... and {len(mine) - limit} more (see --json)")


def csp_summary(csp):
    lines = []
    for p in csp["pages"]:
        kind = "built HTML" if p["built"] else "source HTML"
        lines.append(f"{kind}: {where(p)}  {'CSP meta tag' if p['policies'] else 'no CSP meta tag'}")
    for c in csp["code_policies"]:
        name = f" {c['name']}" if c["name"] else ""
        lines.append(f"code: {where(c)}{name}  {c['mode']}, {c['kind']}")
    if not lines:
        lines.append("no HTML page and no policy found")
    lines.append(f"decided by: {csp['decided_by']}")
    return lines + [f"note: {n}" for n in csp["notes"]]


def print_report(r):
    f = r["findings"]
    print(f"Electron audit: {r['path']}")
    print(f"  {r['files_scanned']} source files; Electron {r['electron'] or 'version not found'}; "
          f"fuses: {'found' if r['fuses'] else 'not found'}")
    print_section("CSP", csp_summary(r["csp"]), f, "csp")
    prefs = r["web_preferences"]
    risky = [] if any(x["check"] == "webPreferences" for x in f) else ["no risky values set"]
    print_section("webPreferences", [f"{prefs['windows']} window(s) created"] + prefs["defaults"] + risky,
                  f, "webPreferences")
    nav = r["navigation"]
    print_section("navigation", [f"will-navigate handler: {'yes' if nav['will-navigate'] else 'no'}; "
                                 f"window open handler: {'yes' if nav['window-open'] else 'no'}"],
                  f, "navigation")
    ipc = r["ipc"]
    lines = [f"{ipc['handlers']} handlers; sender check: {ipc['sender_check']}"]
    if ipc["checked"] and ipc["sender_proof"]:
        lines.append(f"senderFrame / event.sender is read at {ipc['sender_proof']}")
    print_section("IPC handlers", lines, f, "ipc")
    pre = r["preload"]
    print_section("preload bridge", [f"{len(pre['files'])} preload file(s), {pre['expose_calls']} "
                                     f"exposeInMainWorld call(s), {pre['methods']} ipcRenderer call sites"],
                  f, "preload")
    print_section("sinks worth a manual look", [] if any(x["check"] == "sinks" for x in f) else ["none found"],
                  f, "sinks")
    counts = {s: sum(x["severity"] == s for x in f) for s in SEVERITIES}
    print(f"\nfindings: {counts['high']} high, {counts['medium']} medium, {counts['info']} info")
    h = r["if_a_script_gets_into_the_renderer"]
    print("\nif a script gets into the renderer:")
    print(f"  payload from a new domain: {h['new_domain_script']}")
    print(f"  eval() fallback:           {h['eval_fallback']}")
    print(f"  stolen data sent out:      {h['data_out']}")
    if h["data_out"] == "blocked" and h.get("other_ways_out"):
        print(f"    (that is fetch/XHR/WebSocket; still open to any host: {', '.join(h['other_ways_out'])})")
    print(f"  IPC bridge it can call:    {h['ipc_bridge']}")
    if h["node_in_renderer"]:
        print("  Node.js in the page:       yes (files and processes, no bridge needed)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("path", help="folder of the Electron project")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--fail-on", choices=SEVERITIES[:2], metavar="LEVEL",
                    help="exit 1 if a finding of this severity exists: high, or medium (medium and high)")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.path):
        print(f"not a folder: {args.path}", file=sys.stderr)
        return 2
    result = audit(args.path)
    if not result["files_scanned"]:
        print(f"no JavaScript or TypeScript source found in {args.path}", file=sys.stderr)
        return 2
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        print_report(result)
    if args.fail_on:
        levels = SEVERITIES[:SEVERITIES.index(args.fail_on) + 1]
        return 1 if any(x["severity"] in levels for x in result["findings"]) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
