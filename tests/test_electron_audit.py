"""Tests for tools/electron_audit.py. Run: python -m unittest discover -s tests"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import electron_audit  # noqa: E402

BAD = os.path.join(HERE, "fixtures", "electron_bad")
GOOD = os.path.join(HERE, "fixtures", "electron_good")

MAIN = """
const { BrowserWindow, ipcMain } = require('electron');
const win = new BrowserWindow({ webPreferences: { preload: 'preload.js' } });
win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
win.webContents.on('will-navigate', (event, url) => { %s });
"""
PAGE = '<html><head>%s</head><body><script src="./app.js"></script></body></html>'
META = '<meta http-equiv="Content-Security-Policy" content="%s">'
STRICT = "default-src 'none'; script-src 'self'; connect-src 'self'"


def audit(files):
    """Audit a temp project made from {relative path: text}."""
    with tempfile.TemporaryDirectory() as root:
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return electron_audit.audit(root)


def messages(result, check, severity=None):
    return [f["message"] for f in result["findings"]
            if f["check"] == check and severity in (None, f["severity"])]


def answers(result):
    a = result["if_a_script_gets_into_the_renderer"]
    return a["new_domain_script"], a["eval_fallback"], a["data_out"]


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = electron_audit.main(list(args))
    return code, out.getvalue()


class BadFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = electron_audit.audit(BAD)

    def test_no_csp_means_everything_open(self):
        self.assertEqual(answers(self.r), ("loads", "runs", "not blocked"))
        self.assertFalse(self.r["csp"]["enforced"])
        self.assertIn("source only", " ".join(self.r["csp"]["notes"]))

    def test_file_prefix_navigation_is_high(self):
        found = [f for f in self.r["findings"] if f["check"] == "navigation" and f["severity"] == "high"]
        self.assertEqual([(f["file"], f["line"]) for f in found], [("main.js", 15)])
        self.assertIn("startsWith('file:')", found[0]["message"])

    def test_missing_window_open_handler(self):
        self.assertFalse(self.r["navigation"]["window-open"])

    def test_three_handlers_without_sender_check(self):
        self.assertEqual(self.r["ipc"]["handlers"], 3)
        self.assertEqual(self.r["ipc"]["sender_check"], "none")

    def test_generic_pass_through_is_high(self):
        self.assertTrue(any("generic pass-through" in m for m in messages(self.r, "preload", "high")))
        self.assertIn("every channel", self.r["if_a_script_gets_into_the_renderer"]["ipc_bridge"])

    def test_sinks_and_preferences(self):
        sinks = " ".join(messages(self.r, "sinks"))
        self.assertIn("shell.openExternal", sinks)
        self.assertIn("innerHTML", sinks)
        self.assertTrue(any(m.startswith("sandbox: false") for m in messages(self.r, "webPreferences")))
        self.assertTrue(any("contextIsolation not set" in d for d in self.r["web_preferences"]["defaults"]))


class GoodFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = electron_audit.audit(GOOD)

    def test_joined_array_policy_is_enforced(self):
        self.assertEqual(answers(self.r), ("blocked", "blocked", "blocked"))
        self.assertIn("vite.config.js", self.r["csp"]["decided_by"])

    def test_report_only_policy_does_not_count(self):
        modes = {c["name"]: c["mode"] for c in self.r["csp"]["code_policies"]}
        self.assertEqual(modes, {"PRODUCTION_CSP": "enforced", "DEV_CSP_REPORT_ONLY": "report-only"})

    def test_wrapper_covers_all_handlers(self):
        self.assertEqual(self.r["ipc"]["handlers"], 3)
        self.assertTrue(self.r["ipc"]["sender_check"].startswith("one wrapper covers all 3"))
        self.assertIn("sender checked on all", self.r["if_a_script_gets_into_the_renderer"]["ipc_bridge"])

    def test_no_high_or_medium_findings(self):
        self.assertEqual([f for f in self.r["findings"] if f["severity"] != "info"], [])
        self.assertTrue(self.r["fuses"])
        self.assertEqual(self.r["electron"], "^31.0.0")


class Csp(unittest.TestCase):
    def test_built_html_wins_over_source(self):
        r = audit({"main.js": MAIN % "", "index.html": PAGE % "",
                   "dist/index.html": PAGE % (META % STRICT)})
        self.assertIn("built HTML", r["csp"]["decided_by"])
        self.assertEqual(answers(r), ("blocked", "blocked", "blocked"))

    def test_stale_build_without_the_policy_is_open(self):
        plugin = "const CSP = [\"default-src 'none'\", \"script-src 'self'\"].join('; ');\n" \
                 "export default { transformIndexHtml: () => [{ tag: 'meta', attrs: " \
                 "{ 'http-equiv': 'Content-Security-Policy', content: CSP } }] };"
        r = audit({"main.js": MAIN % "", "dist/index.html": PAGE % "", "vite.config.js": plugin})
        self.assertFalse(r["csp"]["enforced"])
        self.assertIn("rebuild", " ".join(r["csp"]["notes"]))

    def test_header_set_in_code_single_string(self):
        code = """
        session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
          callback({ responseHeaders: { ...details.responseHeaders,
            'Content-Security-Policy': ["default-src 'self'; script-src 'self' 'unsafe-eval'"] } });
        });"""
        r = audit({"main.js": MAIN % "" + code, "index.html": PAGE % ""})
        self.assertEqual(answers(r), ("blocked", "runs", "blocked"))
        self.assertTrue(any("eval()" in m for m in messages(r, "csp", "medium")))

    def test_report_only_header_enforces_nothing(self):
        code = """
        const POLICY = ["default-src 'none'", "script-src 'self'"].join('; ');
        session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
          callback({ responseHeaders: { 'Content-Security-Policy-Report-Only': [POLICY] } });
        });"""
        r = audit({"main.js": MAIN % "" + code, "index.html": PAGE % ""})
        self.assertFalse(r["csp"]["enforced"])
        self.assertEqual(answers(r), ("loads", "runs", "not blocked"))

    def test_enforced_and_report_only_side_by_side(self):
        code = """
        const A = "default-src 'self'";
        const B = "default-src 'none'";
        const headers = { 'Content-Security-Policy': A, 'Content-Security-Policy-Report-Only': B };"""
        r = audit({"main.js": MAIN % "" + code, "index.html": PAGE % ""})
        self.assertEqual({c["name"]: c["mode"] for c in r["csp"]["code_policies"]},
                         {"A": "enforced", "B": "report-only"})

    def test_policy_in_a_comment_is_ignored(self):
        r = audit({"main.js": MAIN % "" + "// 'Content-Security-Policy': \"default-src 'none'\"\n",
                   "index.html": PAGE % ""})
        self.assertEqual(r["csp"]["code_policies"], [])

    def test_same_answers_as_script_audit(self):
        policy = "script-src 'self' https:; connect-src *"
        r = audit({"main.js": MAIN % "", "index.html": PAGE % (META % policy)})
        want = electron_audit.script_audit.assess(electron_audit.script_audit.parse_policies([policy]))
        got = r["if_a_script_gets_into_the_renderer"]
        self.assertEqual({k: got[k] for k in want}, want)


class Navigation(unittest.TestCase):
    def nav(self, body, extra=""):
        return audit({"main.js": MAIN % body + extra, "index.html": PAGE % ""})

    def test_origin_prefix_without_slash_is_high(self):
        r = self.nav("if (!url.startsWith('http://127.0.0.1:5173')) event.preventDefault();")
        self.assertTrue(any("evil.example" in m for m in messages(r, "navigation", "high")))

    def test_check_inside_a_helper_is_followed(self):
        r = self.nav("if (!allowed(url)) event.preventDefault();",
                     "function allowed(url) { return url.startsWith('file:'); }")
        self.assertEqual(len(messages(r, "navigation", "high")), 1)

    def test_exact_match_is_clean(self):
        r = self.nav("if (url !== APP_URL) event.preventDefault();")
        self.assertEqual(messages(r, "navigation"), [])

    def test_no_handlers_at_all(self):
        r = audit({"main.js": "const { BrowserWindow } = require('electron'); new BrowserWindow({});"})
        self.assertEqual(len(messages(r, "navigation", "medium")), 2)


class IpcAndPreload(unittest.TestCase):
    def test_some_handlers_checked(self):
        code = """
        ipcMain.handle('a', (event) => { if (event.senderFrame.url !== APP) throw new Error('no'); });
        ipcMain.handle('b', () => 1);"""
        r = audit({"main.js": MAIN % "" + code})
        self.assertEqual(r["ipc"]["sender_check"], "1 of 2 handlers")

    def test_exposing_ipc_renderer_and_node_modules(self):
        preload = """
        const { contextBridge, ipcRenderer } = require('electron');
        const fs = require('fs');
        contextBridge.exposeInMainWorld('electron', { ipcRenderer, fs });"""
        high = " ".join(messages(audit({"main.js": MAIN % "", "preload.js": preload}), "preload", "high"))
        self.assertIn("ipcRenderer itself", high)
        self.assertIn("Node module", high)

    def test_pass_through_with_allowlist_is_info(self):
        preload = """
        const { contextBridge, ipcRenderer } = require('electron');
        const CHANNELS = ['a', 'b'];
        contextBridge.exposeInMainWorld('api', {
          send: (channel, data) => { if (CHANNELS.includes(channel)) ipcRenderer.send(channel, data); }
        });"""
        r = audit({"main.js": MAIN % "", "preload.js": preload})
        self.assertEqual(messages(r, "preload", "high"), [])
        self.assertEqual(len(messages(r, "preload", "info")), 1)

    def test_risky_web_preferences(self):
        r = audit({"main.js": "new BrowserWindow({ webPreferences: { nodeIntegration: true, "
                              "contextIsolation: false } });"})
        self.assertEqual(len(messages(r, "webPreferences", "high")), 2)
        self.assertTrue(r["if_a_script_gets_into_the_renderer"]["node_in_renderer"])


class Cli(unittest.TestCase):
    def test_fail_on_high(self):
        self.assertEqual(run_cli(BAD, "--fail-on", "high")[0], 1)
        self.assertEqual(run_cli(GOOD, "--fail-on", "high")[0], 0)
        self.assertEqual(run_cli(BAD)[0], 0)

    def test_bad_input_exits_2(self):
        self.assertEqual(run_cli(os.path.join(HERE, "no-such-folder"))[0], 2)
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(run_cli(empty)[0], 2)

    def test_text_report_ends_with_the_verdict(self):
        text = run_cli(BAD)[1]
        self.assertIn("if a script gets into the renderer:", text)
        self.assertIn("payload from a new domain: loads", text)

    def test_json_output(self):
        data = json.loads(run_cli(GOOD, "--json")[1])
        self.assertEqual(data["ipc"]["handlers"], 3)


if __name__ == "__main__":
    unittest.main()
