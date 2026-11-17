# Claude Code efficiency rules

**10 lines for your CLAUDE.md. Same question on my real repo: 40% cheaper, half the code read, same answer.**

Plus the habits that keep a full workday of mine at about 25% of the weekly limit, and a small script that shows what your own sessions really cost.

**New (17 Nov):** a free check for the Optimizely-style hole in your own site, plus a Claude Code skill that audits your app's third-party scripts. [Jump to it](#check-your-site-for-the-optimizely-style-hole).

I use Claude Code every day on a production app: Fable 5.2 plans and reviews, Opus 5.5 does the work. Every number below comes from my own transcripts, not from a benchmark I read somewhere.
Danny, [@hasesify](https://x.com/hasesify)

---

## Install in 30 seconds

Copy the block from [`CLAUDE.md`](CLAUDE.md) into one of these:

- `~/.claude/CLAUDE.md` to use it in every project
- `CLAUDE.md` in your repo root to use it in one project

Then start a fresh chat (or `/clear`) so it loads. That's it.

## What it did in my test

Same read-only question about my production repo, same model (Opus 5.5), same effort, fresh session each time. Full method: [docs/ab-test.md](docs/ab-test.md).

| | No rules | With the rules |
|---|---:|---:|
| API-equivalent cost | $0.77 | **$0.46 (-40%)** |
| Tool calls | 16 | 12 |
| Wall time | 72 s | 48 s |
| New tokens added to context (mostly file reads) | 94K | **47K (-50%)** |
| Output tokens | 7.9K | 5.1K |
| Answer | correct, with file:line refs | same conclusions |

One run each, so it's a direction, not a benchmark. Run it on your own repo in 5 minutes, steps at the end of [docs/ab-test.md](docs/ab-test.md).

## The 10 rules and why they work

Claude Code re-sends the whole conversation with every request. Everything the model reads stays in context and gets paid for again (as cheap cache reads) on every message after that. So the biggest lever is not shorter prompts. It's **reading less**.

**The core 5** (the ones in the test above)

1. **Search first.** Grep for the exact function, route or error text before opening anything. One grep line finds what three whole-file reads would.
2. **Read only the lines you need.** `offset`/`limit` around the match. A 1,500-line file read "for context" is 15K+ tokens that ride along for the rest of the chat.
3. **No subagents, no directory listings by default.** Every subagent starts from zero and re-reads the files you already have. My one Fable run with 9 subagents used 95.6M tokens.
4. **Stop at file:line proof.** Models love to keep looking "to be thorough". Once there's proof, more reading is just cost.
5. **Short answers.** Output is the most expensive token type (5x input on Opus 5.5), and long recaps add nothing.

**Five more from daily use** (not measured one by one)

6. **Don't re-read files already in the chat.** They're in context already.
7. **Batch independent tool calls in one message.** Fewer round trips, fewer times the whole context is sent.
8. **Small exact edits, no whole-file rewrites.** Rewriting a 400-line file to change 3 lines pays output price for 397 lines.
9. **Cap command output, long tests in the background.** A full test log can be 20K tokens. You need the 12 lines that failed.
10. **End every task with a 3-line handoff note.** It's what makes habit #1 below painless.

## Habits that matter more than any prompt

1. **One task per chat, `/clear` between tasks.** On Opus 5.5 a 500K-token chat costs about $0.10 in cache reads for every message, even when you only type "ok". 100 messages later that's $10 for history you no longer need.
2. **3-line handoff note before every `/clear`**: what changed, which files, what's next. The next chat starts with "read the note and continue". Template: [templates/HANDOFF.md](templates/HANDOFF.md).
3. **`/clear`, not `/compact`, when you switch tasks.** `/compact` spends a whole request summarizing a chat you're about to leave anyway.
4. **Don't resume a huge chat after a long break.** The prompt cache expires (my transcripts show a 1-hour cache for the main chat, 5 minutes for subagents). The first message after that writes the whole context to cache again: a 500K chat on Opus 5.5 means about $4 for one "continue". A fresh chat plus the handoff note is cheaper.
5. **Pick the effort per task.** Routine edits don't need max; I keep max for the hard calls (my Fable 5.2 max security pass took 13% of the weekly limit in 1h20m). But measure: on a read-only question my Opus low and xhigh runs cost about the same ($0.57 vs $0.51, xhigh cheaper). For reading code the search rules matter more than effort; for generation-heavy work effort is the big lever. [Both tests](docs/ab-test.md).
6. **Plan with the big model, build with the cheaper one.** Fable 5.2 writes the plan and reviews, Opus 5.5 does the edits. Don't bounce between models mid-task: the cache is per model, so every switch starts cold.
7. **Keep CLAUDE.md short.** It's loaded into every chat. Every line in it is a line you pay for on every request.
8. **Turn off MCP servers a project doesn't use.** Their tools and instructions sit in context. In one of my sessions MCP tools alone took about 20K tokens.
9. **Keep extra usage off.** Then the weekly limit is a hard stop, not a surprise bill.
10. **Measure.** `/usage` after a task, or the script below for exact numbers.

## My numbers

| Run | Model, effort | Time | Weekly limit used | Notes |
|---|---|---|---:|---|
| Small desktop app, built end to end | Opus 5.5, xhigh | 47 min | 0.7% | 0 subagents, 98.6% cache hits, about $8 API-equivalent |
| Security + design pass on a real app | Fable 5.2, max | 1 h 20 min | 13% | 606 tool calls, 9 subagents one at a time, 95.6M tokens |
| Full workday with these habits | Max plan + Ultracode | a day | about 25% | |

## Measure your own sessions

[`tools/claude_usage.py`](tools/claude_usage.py) reads your Claude Code transcripts (`~/.claude/projects`) and prints what each session would cost at API list prices: requests, tool calls, subagents, cache writes and reads, output, cache hit rate. Python 3.8+, no dependencies, nothing leaves your machine.

```
python tools/claude_usage.py --last 5          # 5 most recent sessions
python tools/claude_usage.py --project myrepo  # one project
python tools/claude_usage.py a.jsonl b.jsonl   # compare two runs
```

```
session                   span  reqs tools subag  new in cache wr cache rd  output   hit    API $  models
---------------------------------------------------------------------------------------------------------
no-rules                 1m12s     9    16     0      18      94K     696K      8K 88.0%     0.77  opus-5-5
with-rules                 48s     8    12     0      16      47K     628K      5K 93.0%     0.46  opus-5-5
```

It reads the cache type of every request (5-minute or 1-hour), which matters: pricing every write at the 1-hour rate overstated my first A/B numbers. Prices live at the top of the script; check them against [anthropic.com/pricing](https://www.anthropic.com/pricing).

## Check your site for the Optimizely-style hole

On 16 Nov 2026 attackers wrote code into the Optimizely snippets that 178+ organisations load (BBC, Zoom, HSBC, GitLab, IKEA...). For about 19 hours it swapped crypto addresses, skimmed cards, sent cookies and screenshots out, and pushed iOS exploits. Full write-up: [Report URI](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/).

[`tools/script_audit.py`](tools/script_audit.py) asks any page the same questions. Which scripts come from other domains? If one of them got hijacked, would a payload from a new domain load, would an `eval()` fallback run, could stolen data be sent out? Python 3.8+, no dependencies.

```
python tools/script_audit.py https://your-site.com
```

What it said about 9 of the hit companies' homepages on 17 Nov, a day after the cleanup:

| If one of their vendor scripts got hijacked again | Homepages |
|---|---:|
| No CSP at all | 5 of 9 |
| A payload from a brand-new domain would load | 7 of 9 |
| Stolen data could be sent out | 7 of 9 |
| The `eval()` backup the attackers shipped would run | 9 of 9 |
| Scripts from other domains with SRI | 0 of 88 |

It agrees with Report URI on HSBC: the CSP blocks the new domain and the data theft, but `'unsafe-eval'` lets the inline backup copy run.

Then I ran it on the homepage of every organisation on Report URI's list: **152 of the 178 checked**. The `eval()` fallback would run on 151, a payload from a new domain would load on 111, stolen data could go out on 111, and 71 still load the Optimizely snippet. Method, sector table and caveats: [docs/optimizely-scan-2026-11-17.md](docs/optimizely-scan-2026-11-17.md).

It reads the HTML and headers the server returns, so scripts a tag manager injects later don't show up. It shows exposure, not infection.

**No install, from the browser:** open your page, press F12, paste [`tools/script_audit_console.js`](tools/script_audit_console.js) into the Console. It lists the scripts the browser really loaded, including the ones a tag manager added later, and answers the same three questions. It makes one request, to the page you are on, to read the CSP headers. Read it first (about 110 lines): don't paste code you haven't read into a console.

**In CI:** [`tools/script_audit_ci.py`](tools/script_audit_ci.py) exits 1 when a page would let a hijacked script send data out or run an `eval()` fallback, so a deploy that drops the CSP fails on staging. GitHub Actions example: [`docs/ci-example.md`](docs/ci-example.md).

```
python tools/script_audit_ci.py https://staging.your-site.com
python tools/script_audit_ci.py --fail-on data-out,eval,new-domain https://staging.your-site.com
```

If a page sends more than one policy (two headers, or a header and a meta tag), all three tools treat each one separately, the way the browser does: something is allowed only if every policy allows it.

**In Claude Code:** copy [`skills/third-party-scripts`](skills/third-party-scripts/SKILL.md) to `~/.claude/skills/`, then ask "check my app's third-party scripts". It finds every script your code loads from other domains and your CSP config, answers the same questions with file:line proof, and proposes a Report-Only CSP before changing anything.

## FAQ

**Will the answers get worse?** Not in my test: same conclusions, same file:line refs. If a task truly needs exploring (new repo, architecture review), say so in the prompt. The rules are defaults, not handcuffs.

**I'm on a subscription, why care about dollars?** The dollars are a yardstick. The same tokens are what fill your 5-hour and weekly limits.

**Does this only work with Claude Code?** The file is Claude Code's, the ideas aren't. Search before reading, read less, stop early, start fresh per task: that works in any agent.

**Why not more rules?** Every line in CLAUDE.md is sent with every request. Ten short lines is the point.

## Share your numbers

Ran the A/B on your own repo? Open an issue with your before/after table, or tag [@hasesify](https://x.com/hasesify) on X. I'll add good runs here.

## License

MIT
