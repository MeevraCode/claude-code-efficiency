"""Tests for tools/limit_leaks.py. Run: python -m unittest discover -s tests"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import limit_leaks  # noqa: E402

T0 = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)
OPUS, FABLE = "claude-opus-5-5", "claude-fable-5-2"


def stamp(seconds):
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def asst(mid, sec, model=OPUS, w5m=0, w1h=0, read=0, out=100, tools=(), effort="xhigh"):
    content = [{"type": "tool_use", "id": tid, "name": name, "input": inp} for tid, name, inp in tools]
    usage = {"input_tokens": 0, "cache_creation_input_tokens": w5m + w1h, "cache_read_input_tokens": read,
             "output_tokens": out,
             "cache_creation": {"ephemeral_5m_input_tokens": w5m, "ephemeral_1h_input_tokens": w1h}}
    return {"type": "assistant", "timestamp": stamp(sec), "effort": effort,
            "message": {"id": mid, "model": model, "usage": usage, "content": content}}


def result(tid, text, sec):
    return {"type": "user", "timestamp": stamp(sec),
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid, "content": text}]}}


def compact(sec, pre, post, trigger="manual"):
    return {"type": "system", "subtype": "compact_boundary", "timestamp": stamp(sec),
            "compactMetadata": {"trigger": trigger, "preTokens": pre, "postTokens": post}}


MAIN = [
    asst("a1", 0, w1h=30_000, out=500, tools=[("t1", "Bash", {"command": "npm test"})]),
    asst("a1", 0, w1h=30_000, out=500),  # Claude Code logs one entry per content block: same id, same usage
    result("t1", "x" * 40_000, 30),
    {"type": "attachment", "timestamp": stamp(31), "attachment": {"text": "ignored"}},
    asst("a2", 60, read=30_000, w1h=10_400, out=300,
         tools=[("t2", "Read", {"file_path": "/repo/src/app.py"})]),
    result("t2", "y" * 8_000, 90),
    asst("a3", 120, read=40_400, w1h=2_100, out=200),
    asst("a4", 7_200, w1h=42_700),                      # 2 h later: the 1-hour cache is gone
    asst("a5", 7_260, model=FABLE, w1h=42_900),          # switched model: cold again
    compact(7_290, 43_000, 5_000),
    asst("a6", 7_320, model=FABLE, w1h=6_000),           # first request after the compaction
    asst("a7", 7_380, model=FABLE, read=6_000, w1h=500),
]
SUB = [
    asst("s1", 30, w5m=12_000, out=400),
    asst("s2", 40, read=12_000, w5m=1_000, out=100),
]


def write_session(root):
    """A session file plus one subagent transcript under <session>/subagents/."""
    project = Path(root) / "projects" / "D--demo"
    (project / "sess" / "subagents").mkdir(parents=True)
    main = project / "sess.jsonl"
    main.write_text("\n".join(json.dumps(e) for e in MAIN) + "\n", encoding="utf-8")
    sub = project / "sess" / "subagents" / "agent-1.jsonl"
    sub.write_text("\n".join(json.dumps({**e, "isSidechain": True, "agentId": "x1"}) for e in SUB) + "\n",
                   encoding="utf-8")
    return main, sub


class LimitLeaksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.main, self.sub = write_session(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, since=None):
        report = limit_leaks.Report()
        for chain in limit_leaks.read_file(self.main, "main"):
            limit_leaks.analyze(chain, report, since)
        for chain in limit_leaks.read_file(self.sub, "subagent"):
            limit_leaks.analyze(chain, report, since)
        return report

    def test_parses_requests_once(self):
        chains = limit_leaks.read_file(self.main, "main")
        self.assertEqual(len(chains), 1)
        reqs = chains[0].requests
        self.assertEqual(len(reqs), 7)
        self.assertEqual([len(r.results) for r in reqs], [0, 1, 1, 0, 0, 0, 0])
        self.assertEqual(reqs[1].results[0].tool, "Bash")
        self.assertEqual(reqs[2].results[0].what, "app.py (whole file)")
        self.assertIsNotNone(reqs[5].after_compact)

    def test_cold_restarts_by_cause(self):
        r = self.report()
        self.assertEqual(r.count["resumed"], 1)
        self.assertEqual(r.count["switch"], 1)
        self.assertEqual(r.count["compaction"], 1)
        self.assertEqual(r.count["miss"], 0)
        # resumed: re-wrote the 42,500 tokens that were in context, 1-hour writes on Opus ($8 / MTok)
        self.assertAlmostEqual(r.leak["resumed"], 42_500 * 8 / 1e6)
        # switch: re-wrote the previous 42,700 tokens at Fable's 1-hour write price ($16 / MTok)
        self.assertAlmostEqual(r.leak["switch"], 42_700 * 16 / 1e6)
        self.assertAlmostEqual(r.leak["compaction"], 6_000 * 16 / 1e6)

    def test_tool_results_cost_and_carry(self):
        r = self.report()
        bash = next(x for x in r.results if x.tool == "Bash")
        read = next(x for x in r.results if x.tool == "Read")
        self.assertEqual(bash.tokens, 10_000)   # 40,000 chars / 4, under the measured growth of 10,400
        self.assertEqual(bash.carried, 1)       # only a3 read it warm; a4 and a5 re-wrote it, then a compaction
        self.assertAlmostEqual(bash.cost, 10_000 * 8 / 1e6 + 10_000 * 0.2 / 1e6)
        self.assertEqual(read.tokens, 2_000)
        self.assertEqual(read.carried, 0)
        self.assertAlmostEqual(read.cost, 2_000 * 8 / 1e6)
        self.assertAlmostEqual(r.leak["results"], bash.cost + read.cost)

    def test_growth_caps_the_estimate(self):
        chains = limit_leaks.read_file(self.main, "main")
        chains[0].requests[1].w1h = 5_000  # the context only grew by 5,000 tokens
        r = limit_leaks.Report()
        limit_leaks.analyze(chains[0], r)
        bash = next(x for x in r.results if x.tool == "Bash")
        self.assertEqual(bash.tokens, 5_000)

    def test_setup_subagents_and_totals(self):
        r = self.report()
        self.assertEqual(r.requests, 9)
        self.assertEqual(len(r.sessions), 1)
        self.assertEqual(r.subagents, 1)
        self.assertEqual(r.setup_sizes, [30_000])
        main_setup = 30_000 * 8 / 1e6 + (30_000 + 30_000 + 6_000) * 0.2 / 1e6
        sub_setup = 12_000 * 5 / 1e6 + 12_000 * 0.2 / 1e6
        self.assertAlmostEqual(r.leak["setup"], main_setup + sub_setup)
        sub_total = (12_000 * 5 + 400 * 20 + 12_000 * 0.2 + 1_000 * 5 + 100 * 20) / 1e6
        self.assertAlmostEqual(r.leak["subagents"], sub_total)
        self.assertAlmostEqual(sum(r.total.values()), sum(r.by_model.values()))
        self.assertAlmostEqual(r.by_effort["xhigh"], sum(r.total.values()))

    def test_long_chat(self):
        chains = limit_leaks.read_file(self.main, "main")
        reqs = chains[0].requests
        reqs[1].read = 239_600                       # a2: 250,000 tokens of context
        reqs[2].read = 250_000                       # a3: 252,100 tokens of context
        r = limit_leaks.Report()
        limit_leaks.analyze(chains[0], r)
        self.assertEqual(r.count["long"], 2)
        self.assertAlmostEqual(r.leak["long"], (50_000 + 52_100) * 0.2 / 1e6)

    def test_window(self):
        r = self.report(since=T0 + timedelta(hours=1))
        self.assertEqual(r.requests, 4)             # a4..a7
        self.assertEqual(r.subagents, 0)
        self.assertEqual(r.results, [])             # both results were written and carried before the window
        self.assertEqual(r.count["resumed"], 1)     # a4 is still classified with a3 as its predecessor

    def test_helpers(self):
        self.assertEqual(limit_leaks.tool_group("mcp__Claude_Browser__browser_batch"), "Claude_Browser:browser_batch")
        self.assertEqual(limit_leaks.tool_group("Read"), "Read")
        self.assertEqual(limit_leaks.describe("Read", {"file_path": "/a/b.py", "offset": 10, "limit": 20}), "b.py")
        self.assertEqual(limit_leaks.describe("Bash", {"command": "npm  test\n --silent"}), "npm test --silent")
        img = [{"type": "image", "source": {"data": "A" * 99_999}}, {"type": "text", "text": "abc"}]
        self.assertEqual(limit_leaks.result_weight(img), limit_leaks.IMAGE_CHARS + 3)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            limit_leaks.main([str(self.main)])
        text = out.getvalue()
        self.assertIn("1 session, 1 subagent, 9 requests", text)
        self.assertIn("Resumed a chat after the cache expired (1x)", text)
        self.assertIn("Model switches mid-chat (1x)", text)
        self.assertIn("Re-writes after a compaction (1x, 0 auto)", text)
        self.assertIn("app.py (whole file)", text)
        self.assertIn("By model:", text)

    def test_cli_finds_sessions_in_config_dir(self):
        out = io.StringIO()
        old = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = self.tmp.name
        try:
            with contextlib.redirect_stdout(out):
                limit_leaks.main(["--days", "0", "--project", "demo"])
        finally:
            if old is None:
                os.environ.pop("CLAUDE_CONFIG_DIR", None)
            else:
                os.environ["CLAUDE_CONFIG_DIR"] = old
        self.assertIn("all time", out.getvalue())
        self.assertIn("9 requests", out.getvalue())


if __name__ == "__main__":
    unittest.main()
