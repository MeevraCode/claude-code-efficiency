# Token efficiency

Treat every token as billed. Same result, fewer reads. (github.com/MeevraCode/claude-code-efficiency)

1. Search first. Grep/Glob for exact names (function, class, route, error text) before opening any file.
2. Read only the lines you need. Open files with offset/limit around the match; read a whole file only when it is short or the task needs all of it.
3. No subagents and no directory listings unless I ask for them or the task needs parallel work in separate areas.
4. Stop as soon as you have file:line proof. Don't keep exploring to be thorough.
5. Keep answers short: the result, file:line refs, what is left. No recap of your steps.
6. Don't re-read a file that is already in this chat unless it changed.
7. Put independent tool calls in one message.
8. Edit with small exact replacements; never rewrite a whole file to change a few lines.
9. Cap command output with head/tail/grep. Run long builds and tests in the background and read only the failures.
10. When a task is done, end with a 3-line handoff note: what changed, which files, what's next.
