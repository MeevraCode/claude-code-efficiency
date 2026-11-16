# The A/B test

## Setup

- One real, read-only question about my production repo: how does the app pick its routing engine, and when does it fall back to the other one?
- Two fresh Claude Code sessions (subagents, so nothing carried over), same model (Opus 5.5), same effort, same question.
- Run A got only the question. Run B got the question plus the five core rules from [CLAUDE.md](../CLAUDE.md) (rules 1-5).
- Costs come from the transcripts with [`tools/claude_usage.py`](../tools/claude_usage.py) at API list prices.

## Results

| | A: no rules | B: 5 rules | Change |
|---|---:|---:|---:|
| API-equivalent cost | $0.77 | $0.46 | **-40%** |
| Requests | 9 | 8 | |
| Tool calls | 16 | 12 | -25% |
| Wall time | 72 s | 48 s | -33% |
| New tokens added to context (cache writes, mostly file reads) | 94K | 47K | **-50%** |
| Cache reads | 696K | 628K | -10% |
| Output tokens | 7.9K | 5.1K | -35% |
| Cache hit rate | 88% | 93% | |
| Answer | correct, file:line refs | same conclusions, file:line refs | |

Where the money went in run A: $0.47 cache writes, $0.16 output, $0.14 cache reads. The rules mostly cut the first one: the model opened half as much code to reach the same answer.

## Correction (2026-11-16)

My first post said $1.05 vs $0.61 (-42%). That version priced every cache write at the 1-hour cache rate (2x input). The transcripts show these subagents used the 5-minute cache (1.25x input), so the right numbers are $0.77 vs $0.46. The saving barely moves: -42% became -40%. The script reads the cache type from each request, so it gets this right.

## Second test: effort low vs xhigh (2026-11-16)

A reader measured Opus on a 3D scene: $6.74 on xhigh vs $1.97 on low, and low didn't look worse. So I ran the same read-only question twice more, plain prompt (no rules), Opus 5.5, fresh subagents, only the effort changed.

| | low | xhigh |
|---|---:|---:|
| API-equivalent cost | $0.57 | **$0.51** |
| Requests | 7 | 9 |
| Tool calls | 6 | 13 |
| Wall time | 26 s | 42 s |
| New tokens added to context | 87K | 56K |
| Cache reads | 481K | 754K |
| Output tokens | 2K | 4K |
| Answer | correct, the core points with file:line refs | correct, more detail (manifest schema versions, error types) |

xhigh came out about 10% cheaper. Low made fewer calls but pulled more file text into context per call, and new context is the expensive part. My read: when a task is mostly reading code, effort barely moves the bill and the search rules matter more. When a task generates a lot (a 3D scene, a big feature), effort is the big lever. Two data points, so test it on your own work.

## Caveats

- One run each. Treat it as a direction, not a benchmark.
- A read-only question rewards the search rules most. Big refactors gain less from rules 1-4 and more from the habits (one task per chat, handoff notes).
- If a task really needs exploration (an unfamiliar repo, an architecture review), say so in the prompt. The rules are defaults, not handcuffs.

## Run it on your own repo

1. Pick a question that needs reading code: "how does X decide Y, and when does it fall back?"
2. Ask it in a fresh chat without the rules. `/clear`.
3. Ask it again with the CLAUDE.md block installed (or the 5 rules pasted on top of the prompt). Same model, same effort.
4. `python tools/claude_usage.py --last 2`
5. Compare cost, tool calls and cache writes, and check that both answers agree.

Post your numbers in an issue or tag [@hasesify](https://x.com/hasesify). More runs from more repos make this better than my n=1.
