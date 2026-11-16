#!/usr/bin/env python3
"""What did my Claude Code sessions really cost?

Reads Claude Code session transcripts (~/.claude/projects/<project>/<session>.jsonl, plus the
subagent transcripts in <session>/subagents/) and prints per session: duration, requests, tool
calls, subagents, tokens by type, cache hit rate and the API-equivalent cost at list prices.

Usage:
  python claude_usage.py                     # the 10 most recent sessions
  python claude_usage.py --last 3            # the 3 most recent sessions
  python claude_usage.py --project myrepo    # only projects whose folder name contains "myrepo"
  python claude_usage.py a.jsonl b.jsonl     # specific transcripts (compare two runs)

Subscription plans are not billed per token. The dollar figure is what the same tokens would
cost on the API, which makes it a fair yardstick for comparing your own sessions.
Standard library only, Python 3.8+.
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# USD per 1M tokens: (input, output, cache read). Check https://www.anthropic.com/pricing
PRICES = {
    "claude-fable-5-2": (8.00, 40.00, 0.20),
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
}
# Older or unknown model ids fall back to the current model of the same family.
FAMILY = {"fable": "claude-fable-5-2", "mythos": "claude-fable-5-2", "opus": "claude-opus-5-5",
          "sonnet": "claude-sonnet-5-5", "haiku": "claude-haiku-5-5"}
WRITE_5M, WRITE_1H = 1.25, 2.0  # cache write price as a multiple of the input price


def price_for(model):
    if model in PRICES:
        return PRICES[model], False
    for word, target in FAMILY.items():
        if word in (model or ""):
            return PRICES[target], True
    return PRICES["claude-opus-5-5"], True


class Totals:
    def __init__(self):
        self.usage = {}       # message id -> (model, usage); Claude Code repeats usage per block
        self.tools = set()
        self.first = self.last = None
        self.subagents = 0

    def add_file(self, path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                stamp = entry.get("timestamp")
                if stamp:
                    self.first = min(self.first or stamp, stamp)
                    self.last = max(self.last or stamp, stamp)
                msg = entry.get("message")
                if entry.get("type") != "assistant" or not isinstance(msg, dict):
                    continue
                if msg.get("id") and isinstance(msg.get("usage"), dict) and msg.get("model") != "<synthetic>":
                    self.usage[msg["id"]] = (msg.get("model"), msg["usage"])
                for block in msg.get("content") or []:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        self.tools.add(block.get("id"))

    def summary(self):
        t = dict(fresh=0, write=0, read=0, output=0, cost=0.0)
        models, guessed = set(), False
        for model, u in self.usage.values():
            (inp, out, rd), guess = price_for(model)
            guessed |= guess
            models.add(model)
            cache = u.get("cache_creation") or {}
            w1h = cache.get("ephemeral_1h_input_tokens") or 0
            w5m = cache.get("ephemeral_5m_input_tokens") or 0
            write = u.get("cache_creation_input_tokens") or (w1h + w5m)
            w5m += max(write - w1h - w5m, 0)  # no breakdown: count it as a 5 minute write
            fresh, read, output = (u.get("input_tokens") or 0), (u.get("cache_read_input_tokens") or 0), (u.get("output_tokens") or 0)
            t["fresh"] += fresh
            t["write"] += write
            t["read"] += read
            t["output"] += output
            t["cost"] += (fresh * inp + w5m * inp * WRITE_5M + w1h * inp * WRITE_1H + read * rd + output * out) / 1e6
        total_in = t["fresh"] + t["write"] + t["read"]
        t["hit"] = t["read"] / total_in if total_in else 0.0
        t["requests"] = len(self.usage)
        t["tools"] = len(self.tools)
        t["models"] = ", ".join(sorted(m.replace("claude-", "") for m in models if m)) or "-"
        t["guessed"] = guessed
        t["seconds"] = 0
        if self.first and self.last:
            parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
            t["seconds"] = int((parse(self.last) - parse(self.first)).total_seconds())
        return t


def k(n):
    return f"{n / 1e6:.1f}M" if n >= 1e6 else f"{n / 1e3:.0f}K" if n >= 1e3 else str(n)


def duration(sec):
    if sec >= 3600:
        return f"{sec // 3600}h{sec % 3600 // 60:02d}m"
    return f"{sec // 60}m{sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def find_sessions(root, project, last):
    files = [p for p in root.glob("*/*.jsonl") if not project or project.lower() in p.parent.name.lower()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:last]


def main():
    ap = argparse.ArgumentParser(description="API-equivalent cost of Claude Code sessions.")
    ap.add_argument("files", nargs="*", help="transcript .jsonl files (default: most recent sessions)")
    ap.add_argument("--last", type=int, default=10, help="how many recent sessions (default 10)")
    ap.add_argument("--project", default="", help="filter by project folder name")
    ap.add_argument("--no-subagents", action="store_true", help="leave subagent transcripts out")
    args = ap.parse_args()

    root = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude")) / "projects"
    files = [Path(f) for f in args.files] or find_sessions(root, args.project, args.last)
    if not files:
        sys.exit(f"No transcripts found under {root}")

    head = f"{'session':<22}{'span':>8}{'reqs':>6}{'tools':>6}{'subag':>6}{'new in':>8}{'cache wr':>9}{'cache rd':>9}{'output':>8}{'hit':>6}{'API $':>9}  models"
    print(head)
    print("-" * len(head))
    grand, any_guess = 0.0, False
    for path in files:
        tot = Totals()
        tot.add_file(path)
        sub_dir = path.with_suffix("") / "subagents"
        if not args.no_subagents and sub_dir.is_dir():
            for sub in sorted(sub_dir.glob("*.jsonl")):
                tot.add_file(sub)
                tot.subagents += 1
        s = tot.summary()
        grand += s["cost"]
        any_guess |= s["guessed"]
        name = path.stem[:20]
        print(f"{name:<22}{duration(s['seconds']):>8}{s['requests']:>6}{s['tools']:>6}{tot.subagents:>6}"
              f"{k(s['fresh']):>8}{k(s['write']):>9}{k(s['read']):>9}{k(s['output']):>8}"
              f"{s['hit']:>6.1%}{s['cost']:>9.2f}  {s['models']}{' *' if s['guessed'] else ''}")
    if len(files) > 1:
        print(f"{'total':<22}{'':>81}{grand:>9.2f}")
    print("\nAPI $ = list price for the same tokens (subscriptions bill differently).")
    if any_guess:
        print("* model not in the price table, priced as the current model of its family.")


if __name__ == "__main__":
    main()
