#!/usr/bin/env python3
"""Where did my Claude limit go?

Reads your Claude Code transcripts (~/.claude/projects) and splits what they cost into the habits
behind it: cold restarts (the whole chat written to the cache again after a break, a model switch
or a compaction), the setup every request carries (system prompt, tools, MCP servers, CLAUDE.md),
long chats, big tool results that ride along for the rest of the chat, subagents and output.
Every line names the habit that fixes it (habit and rule numbers are the ones in the README).

Usage:
  python limit_leaks.py                   # last 7 days, all projects
  python limit_leaks.py --days 30
  python limit_leaks.py --project myrepo  # projects whose folder name contains "myrepo"
  python limit_leaks.py a.jsonl           # one session, all of it (its subagents are added)

Dollars are API list prices for the same tokens: a yardstick, not your bill. On a subscription the
same tokens fill your 5-hour and weekly limits. Token counts come from the usage Claude Code logs
for every request. How many tokens a tool result brought is estimated from its size and capped by
the measured growth of the context. Standard library only, Python 3.8+. Nothing leaves your machine.
"""
import argparse
import json
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from claude_usage import WRITE_1H, WRITE_5M, k, price_for  # noqa: E402

COLD_MIN = 20_000       # a cache re-write smaller than this is noise, not a leak
LONG_CHAT = 200_000     # requests with more context than this belong to a long chat
CHARS_PER_TOKEN = 4     # rough size of a tool result in tokens
IMAGE_CHARS = 6_400     # one image counts like this many characters (about 1,600 tokens)
TTL_5M, TTL_1H = 300, 3600

# key: (label, fix). Habit and rule numbers match the README.
LEAKS = {
    "results": ("Tool results riding along", "rules 2 + 9: read only what you need, cap output"),
    "long": ("Chats past 200K tokens, the part above 200K", "habit 1: one task per chat, /clear"),
    "setup": ("Setup every request carries", "habits 7 + 8: short CLAUDE.md, unused MCP off"),
    "subagents": ("Subagents", "rule 3: no subagents by default"),
    "output": ("Output (answers, thinking, code)", "rule 5: short answers"),
    "resumed": ("Resumed a chat after the cache expired", "habit 4: fresh chat + handoff note"),
    "compaction": ("Re-writes after a compaction", "habit 3: /clear, not /compact"),
    "switch": ("Model switches mid-chat", "habit 6: one model per task"),
    "miss": ("Cache misses mid-chat (tools or setup changed)", "keep the setup fixed during a chat"),
}


def parse_time(stamp):
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None


class Request:
    """One API request: one assistant message id with its usage."""

    def __init__(self, ts, model, effort):
        self.ts, self.model, self.effort = ts, model, effort
        self.fresh = self.w5m = self.w1h = self.read = self.out = 0
        self.results = []          # tool results that arrived since the previous request
        self.after_compact = None  # compactMetadata when a compaction happened right before

    def set_usage(self, usage):
        cache = usage.get("cache_creation") or {}
        self.w1h = cache.get("ephemeral_1h_input_tokens") or 0
        self.w5m = cache.get("ephemeral_5m_input_tokens") or 0
        total = usage.get("cache_creation_input_tokens") or 0
        self.w5m += max(total - self.w1h - self.w5m, 0)  # no breakdown: count it as a 5-minute write
        self.fresh = usage.get("input_tokens") or 0
        self.read = usage.get("cache_read_input_tokens") or 0
        self.out = max(self.out, usage.get("output_tokens") or 0)  # streamed entries repeat the usage

    @property
    def write(self):
        return self.w5m + self.w1h

    @property
    def ctx(self):
        return self.fresh + self.write + self.read

    def read_price(self):
        return price_for(self.model)[0][2] / 1e6

    def write_cost(self, tokens=None):
        """Cost of writing `tokens` (default: all of this request's cache writes) at its write mix."""
        if not self.write:
            return 0.0
        inp = price_for(self.model)[0][0]
        full = (self.w5m * WRITE_5M + self.w1h * WRITE_1H) * inp / 1e6
        return full if tokens is None else full * min(tokens, self.write) / self.write

    def costs(self):
        (inp, out, _), _ = price_for(self.model)
        return {"output": self.out * out / 1e6, "fresh": self.fresh * inp / 1e6,
                "write": self.write_cost(), "read": self.read * self.read_price()}


class Result:
    """One tool result and what it cost while it stayed in the chat."""

    def __init__(self, tool, what, weight):
        self.tool, self.what, self.weight = tool, what, weight
        self.tokens = 0
        self.cost = 0.0
        self.carried = 0  # later requests that read it from the cache


class Chain:
    def __init__(self, kind, name):
        self.kind, self.name = kind, name
        self.requests = []


def describe(name, inp):
    inp = inp if isinstance(inp, dict) else {}
    if name == "Read":
        what = os.path.basename(str(inp.get("file_path", "")))
        whole = inp.get("offset") is None and inp.get("limit") is None
        return what + (" (whole file)" if whole else "")
    if name in ("Bash", "PowerShell"):
        return " ".join(str(inp.get("command", "")).split())[:60]
    if name in ("Grep", "Glob"):
        return str(inp.get("pattern", ""))[:60]
    if name == "WebFetch":
        return str(inp.get("url", ""))[:60]
    if name in ("Task", "Agent"):
        return str(inp.get("description", ""))[:60]
    return ""


def tool_group(name):
    """mcp__server__tool -> server:tool, built-in tools as they are."""
    if name.startswith("mcp__"):
        parts = name.split("__")
        if len(parts) >= 3:
            return f"{parts[1]}:{parts[2]}"
    return name


def result_weight(content):
    """Size of a tool result in characters, images counted as IMAGE_CHARS each."""
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        total = 0
        for block in content:
            if not isinstance(block, dict):
                total += len(str(block))
            elif block.get("type") == "image":
                total += IMAGE_CHARS
            elif block.get("type") == "text":
                total += len(block.get("text") or "")
            else:
                total += len(json.dumps(block))
        return total
    return 0 if content is None else len(json.dumps(content))


def read_file(path, kind):
    """Parse one transcript into chains: the chat itself plus any sidechains logged inside it."""
    chains, by_id, tools = {}, {}, {}
    pending, compacts = defaultdict(list), {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            # Most lines (attachments, request blobs, UI state) don't matter here: skip them unparsed.
            if '"assistant"' not in line and '"tool_result"' not in line and "compact_boundary" not in line:
                continue
            if '"type":"api-request' in line[:200]:  # raw request copies repeat what the chat already has
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            side = kind == "main" and bool(entry.get("isSidechain"))
            key = str(entry.get("agentId") or "sidechain") if side else ""
            etype = entry.get("type")
            if etype == "system" and entry.get("subtype") == "compact_boundary":
                compacts[key] = entry.get("compactMetadata") or {}
                continue
            msg = entry.get("message")
            if not isinstance(msg, dict):
                continue
            if etype == "assistant":
                usage, mid = msg.get("usage"), msg.get("id")
                if not isinstance(usage, dict) or not mid or msg.get("model") == "<synthetic>":
                    continue
                req = by_id.get((key, mid))
                if req is None:
                    chain = chains.get(key)
                    if chain is None:
                        chain_kind = "subagent" if (side or kind == "subagent") else "main"
                        chain = chains[key] = Chain(chain_kind, path.stem + (f"/{key}" if key else ""))
                    req = Request(parse_time(entry.get("timestamp")), msg.get("model") or "", entry.get("effort"))
                    req.results, pending[key] = pending[key], []
                    req.after_compact = compacts.pop(key, None)
                    chain.requests.append(req)
                    by_id[(key, mid)] = req
                req.set_usage(usage)
                for block in msg.get("content") or []:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        name = block.get("name") or "?"
                        tools[block.get("id")] = (name, describe(name, block.get("input")))
            elif etype == "user" and isinstance(msg.get("content"), list):
                for block in msg["content"]:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        name, what = tools.get(block.get("tool_use_id"), ("?", ""))
                        pending[key].append(Result(name, what, result_weight(block.get("content"))))
    return list(chains.values())


class Report:
    def __init__(self):
        self.total = defaultdict(float)
        self.leak = defaultdict(float)
        self.count = defaultdict(int)
        self.by_model = defaultdict(float)
        self.by_effort = defaultdict(float)
        self.by_tool = defaultdict(float)
        self.results = []
        self.sessions = set()
        self.subagents = 0
        self.requests = 0
        self.setup_sizes = []
        self.compactions = []
        self.guessed = False
        self.first = self.last = None


def analyze(chain, report, since=None):
    """Add one chain's requests inside the time window to the report."""
    reqs = chain.requests
    n = len(reqs)
    inside = [since is None or (r.ts is not None and r.ts >= since) for r in reqs]
    if not any(inside):
        return

    # 1. Which requests found the cache cold, and why.
    cause = [None] * n
    uses_1h = False
    for i, r in enumerate(reqs):
        if i == 0:
            cause[i] = "start"
        elif r.after_compact is not None:
            cause[i] = "compaction"
        elif r.write >= COLD_MIN and r.read < 0.5 * reqs[i - 1].ctx:
            prev = reqs[i - 1]
            gap = (r.ts - prev.ts).total_seconds() if (r.ts and prev.ts) else 0
            if r.model != prev.model:
                cause[i] = "switch"
            elif gap > (TTL_1H if uses_1h else TTL_5M):
                cause[i] = "resumed"
            else:
                cause[i] = "miss"
        uses_1h = uses_1h or r.w1h > 0
    warm = [c is None for c in cause]

    # 2. Cache-read price summed over the later warm requests of the same segment (until a compaction).
    later_price, later_count = [0.0] * (n + 1), [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        cont = i + 1 < n and reqs[i + 1].after_compact is None
        own = inside[i] and warm[i]
        later_price[i] = (reqs[i].read_price() if own else 0.0) + (later_price[i + 1] if cont else 0.0)
        later_count[i] = (1 if own else 0) + (later_count[i + 1] if cont else 0)

    setup = reqs[0].ctx
    if chain.kind == "main":
        report.setup_sizes.append(setup)
    for i, r in enumerate(reqs):
        if r.after_compact is not None and inside[i]:
            report.compactions.append(r.after_compact)
        if not inside[i]:
            continue
        report.requests += 1
        report.guessed |= price_for(r.model)[1]
        if r.ts:
            report.first = min(report.first or r.ts, r.ts)
            report.last = max(report.last or r.ts, r.ts)
        costs = r.costs()
        spent = sum(costs.values())
        for part, value in costs.items():
            report.total[part] += value
        report.by_model[r.model] += spent
        report.by_effort[r.effort or "-"] += spent
        report.leak["output"] += costs["output"]
        if chain.kind == "subagent":
            report.leak["subagents"] += spent
        if cause[i] == "start":
            report.leak["setup"] += costs["write"]
        elif cause[i] is not None:
            again = r.write if cause[i] == "compaction" else min(r.write, reqs[i - 1].ctx)
            report.leak[cause[i]] += r.write_cost(again)
            report.count[cause[i]] += 1
        else:
            report.leak["setup"] += min(setup, r.read) * r.read_price()
            if r.ctx > LONG_CHAT:
                report.leak["long"] += min(r.read, r.ctx - LONG_CHAT) * r.read_price()
                report.count["long"] += 1

    # 3. Tool results: size estimate capped by the measured context growth, then what they cost.
    for i, r in enumerate(reqs):
        if not r.results:
            continue
        for x in r.results:
            x.tokens = x.weight // CHARS_PER_TOKEN
        if i > 0 and warm[i]:
            growth = max(0, r.ctx - reqs[i - 1].ctx)
            estimated = sum(x.tokens for x in r.results)
            if estimated > growth:
                for x in r.results:
                    x.tokens = x.tokens * growth // estimated if estimated else 0
        cont = i + 1 < n and reqs[i + 1].after_compact is None
        for x in r.results:
            first = r.write_cost(x.tokens) if inside[i] else 0.0
            x.cost = first + x.tokens * (later_price[i + 1] if cont else 0.0)
            x.carried = later_count[i + 1] if cont else 0
            if x.cost > 0:
                report.results.append(x)
                report.by_tool[tool_group(x.tool)] += x.cost
                report.leak["results"] += x.cost
                report.count["results"] += 1

    if chain.kind == "main":
        report.sessions.add(chain.name)
    else:
        report.subagents += 1


def find_files(root, project, since):
    files = []
    if not root.is_dir():
        return files
    for folder in sorted(root.iterdir()):
        if not folder.is_dir() or (project and project.lower() not in folder.name.lower()):
            continue
        for path in folder.glob("*.jsonl"):
            try:
                if since is None or path.stat().st_mtime >= since.timestamp():
                    files.append(path)
            except OSError:
                continue
    return files


def subagent_files(path):
    folder = path.with_suffix("")
    return sorted(folder.rglob("*.jsonl")) if folder.is_dir() else []


def money(x):
    return f"${x:,.2f}"


def plural(n, word):
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def print_report(report, window, top):
    grand = sum(report.total.values())
    if not report.requests or grand <= 0:
        print(f"No requests with usage found ({window}).")
        return
    span = ""
    if report.first and report.last:
        span = f" ({report.first:%Y-%m-%d} to {report.last:%Y-%m-%d})"
    print(f"Claude Code, {window}{span}: {plural(len(report.sessions), 'session')}, "
          f"{plural(report.subagents, 'subagent')}, {plural(report.requests, 'request')}")
    t = report.total
    print(f"API-equivalent total: {money(grand)}  (output {money(t['output'])}, uncached input {money(t['fresh'])}, "
          f"cache writes {money(t['write'])}, cache reads {money(t['read'])})")

    counts = {
        "results": plural(report.count["results"], "result"),
        "long": plural(report.count["long"], "request"),
        "subagents": f"{report.subagents}",
        "resumed": f"{report.count['resumed']}x",
        "switch": f"{report.count['switch']}x",
        "miss": f"{report.count['miss']}x",
    }
    if report.setup_sizes:
        counts["setup"] = f"first request median {k(int(statistics.median(report.setup_sizes)))} tokens"
    if report.compactions:
        auto = sum(1 for m in report.compactions if m.get("trigger") == "auto")
        counts["compaction"] = f"{len(report.compactions)}x, {auto} auto"
    rows = []
    for key, (label, fix) in LEAKS.items():
        cost = report.leak.get(key, 0.0)
        if cost <= 0:
            continue
        name = label + (f" ({counts[key]})" if counts.get(key) else "")
        rows.append((cost, name, fix))
    rows.sort(reverse=True)
    width = max(len(name) for _, name, _ in rows) if rows else 30
    print(f"\n{'Where it went':<{width}}  {'cost':>10}  {'share':>6}  fix")
    for cost, name, fix in rows:
        print(f"{name:<{width}}  {money(cost):>10}  {cost / grand:>6.1%}  {fix}")
    print("Rows overlap (a big tool result in a long chat counts in both), so they add up to more than 100%.")

    if report.results:
        print("\nMost expensive tool results (first write + every later request that carried it)")
        print(f"{'cost':>10} {'tokens':>7} {'carried':>8}  {'tool':<24} what")
        for x in sorted(report.results, key=lambda r: r.cost, reverse=True)[:top]:
            print(f"{money(x.cost):>10} {k(x.tokens):>7} {x.carried:>8}  {tool_group(x.tool)[:24]:<24} {x.what}")
        tools = sorted(report.by_tool.items(), key=lambda kv: kv[1], reverse=True)[:6]
        print("By tool: " + "  |  ".join(f"{name} {money(cost)}" for name, cost in tools))

    models = sorted(report.by_model.items(), key=lambda kv: kv[1], reverse=True)
    print("\nBy model:  " + "  |  ".join(f"{(m or '?').replace('claude-', '')} {money(c)} ({c / grand:.0%})"
                                         for m, c in models))
    efforts = sorted(report.by_effort.items(), key=lambda kv: kv[1], reverse=True)
    if len(efforts) > 1 or efforts[0][0] != "-":
        print("By effort: " + "  |  ".join(f"{e} {money(c)} ({c / grand:.0%})" for e, c in efforts))
    if report.compactions:
        pre = [m.get("preTokens") or 0 for m in report.compactions]
        post = [m.get("postTokens") or 0 for m in report.compactions]
        print(f"Compactions: {len(pre)}, on average {k(int(sum(pre) / len(pre)))} tokens before, "
              f"{k(int(sum(post) / len(post)))} after")
    print("\nAPI $ = list price for the same tokens (subscriptions bill differently, the same tokens fill your limits).")
    print(f"Tool-result tokens are estimated from their size ({CHARS_PER_TOKEN} characters per token), capped by the "
          "measured growth of the context.")
    if report.guessed:
        print("Some model ids were not in the price table and were priced as the current model of their family.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Where did my Claude limit go? Splits Claude Code usage into habits.")
    ap.add_argument("files", nargs="*", help="session transcripts (.jsonl); default: every session in the window")
    ap.add_argument("--days", type=float, default=None,
                    help="time window in days (default 7, or everything when files are given; 0 = everything)")
    ap.add_argument("--project", default="", help="only projects whose folder name contains this")
    ap.add_argument("--top", type=int, default=5, help="how many of the most expensive tool results to list")
    args = ap.parse_args(argv)

    days = args.days if args.days is not None else (0 if args.files else 7)
    since = datetime.now(timezone.utc) - timedelta(days=days) if days else None
    window = f"last {days:g} days" if days else "all time"
    root = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude")) / "projects"
    files = [Path(f) for f in args.files] or find_files(root, args.project, since)
    if not files:
        sys.exit(f"No transcripts found under {root}")

    report = Report()
    for path in files:
        for chain in read_file(path, "main"):
            analyze(chain, report, since)
        for sub in subagent_files(path):
            for chain in read_file(sub, "subagent"):
                analyze(chain, report, since)
    print_report(report, window, args.top)


if __name__ == "__main__":
    main()
