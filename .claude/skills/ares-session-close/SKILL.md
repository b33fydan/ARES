---
name: ares-session-close
description: >-
  Run at the end of an ARES working session to close it out completely and
  consistently, in three phases: (1) gate the commit/push — perform the
  standard ARES close (CLAUDE.md ledger + squash-merge to main), confirming
  before the push; (2) post the Notion session debrief plus an In Plain Terms
  layman's section under the ARES PHASE ZERO hub, in the locked house format;
  (3) crystalize the session for continuity. Use this whenever Dan signals a
  session is wrapping up — "done for today", "wrap up", "close out", "end
  session", "that's a wrap", or "/ares-session-close" — even if he doesn't name
  the skill. ARES project only. Never fire mid-task; offer rather than auto-run
  if the intent is ambiguous.
---

# ARES Session Close

This is the end-of-session ritual for the ARES project. It exists so the close
is the same every time: the work lands on `main`, the session is written up in
Notion (technical + plain-language), and a continuity crystal is saved for the
next session. Doing these by hand means steps get skipped and the Notion format
drifts; this skill makes the close one repeatable pass.

Run the three phases **in this order** — commit/push first so the debrief and
crystal can reference real commit hashes and a pushed `main`; crystalize last
because it is the session's final continuity artifact (the `crystalize` skill is
explicitly the last meaningful action of a session).

## When to run

Trigger on an explicit end-of-session signal from Dan: "done for today", "wrap
up", "close out", "let's end here", "that's a wrap", or a direct
`/ares-session-close`. If the signal is ambiguous (he might just be pausing),
**offer** the close rather than running it. **Never** run mid-task — a half-done
feature should not be squash-merged to `main`.

## Phase 0 — Gather

Before touching anything, read the session state and collect the write-up
material. You will reuse this for both the Notion debrief and the crystal, so
gather it once.

- Git state: `git rev-parse --abbrev-ref HEAD` (branch), `git status --short`
  (uncommitted), `git log --oneline main..HEAD` (commits ahead of main),
  `git rev-list --left-right --count origin/main...HEAD` (sync vs origin).
- Session substance: what was built or changed (file paths, commit hashes), the
  key decisions and *why* (the why is what git can't recover), load-bearing
  numbers, gotchas hit, and what's still open.

Decide which Phase-1 branch you're in from the git state above.

## Phase 1 — Commit/push gate (perform, confirm before push)

The default ARES convention is: never commit to `main` directly; each session
works on a `session/NNN-*` branch and squash-merges to `main` at close. Carry
that out here. **Pushing is the one outward, hard-to-undo step, so stop and
confirm before it.**

**Case A — a session branch with commits ahead of `main`** (the common case):

1. Update `CLAUDE.md`:
   - Add a condensed session-ledger entry.
   - Add a Branch-section squash record. (Convention: a session's *own* squash
     hash is recorded by the *next* session, since the hash doesn't exist until
     after the squash. Record any earlier sessions' pending hashes now.)
   - Bump the test-count floor **only if** tests changed, and only after
     confirming the real freshness-scoped count — never declare a floor higher
     than the actual count (the freshness gate is a floor, i.e. `actual >=
     declared`, so under-declaring is safe and over-declaring fails).
2. Commit the CLAUDE.md update on the branch.
3. `git checkout main` → `git merge --squash <branch>` → `git commit`.
4. **Verify the squash captured everything:** `git diff <branch> HEAD` must be
   empty.
5. Run the self-validation gate: `python -m pytest tests/test_claude_md_freshness.py -q`.
6. Show Dan the squash result + freshness outcome, then **ask for confirmation
   to push.**
7. On confirm: `git push origin main` then `git push origin <branch>` (retain
   the session branch on origin as the un-squashed audit trail).

**Case B — analysis-only / nothing to commit:** note it, skip the git, continue
to Phase 2.

**Case C — already merged and pushed** (clean tree, branch in main, origin in
sync): note it, continue.

**Stop conditions:** if the freshness gate fails, or the squash hits a conflict
or any unexpected git state, **stop before the push**, surface exactly what
happened, and do not force it. If Dan declines the push at step 6, leave `main`
merged locally, report the exact `git push` commands for later, and still
continue to Phase 2 + 3 (both are independent of the push).

### Git gotchas (carried from prior sessions)

- Commit messages: use single-quoted `-m` arguments or `git commit -F <file>` —
  piping a here-string to `git commit -F -` in PowerShell prepends a UTF-8 BOM
  to the subject line.
- Keep squash-commit subjects free of em-dashes and parentheses-quoting issues;
  a colon-form subject is safest.

## Phase 2 — Notion debrief + In Plain Terms

Post the session write-up to Notion. The **In Plain Terms (layman's) section is
always included** — that plain-language telling is a deliverable in its own
right, not an afterthought.

- **Parent hub:** the 🔱 ARES PHASE ZERO page, id
  `2e87e255421c8025a599df48b592329a`. Create the page as a child of it via
  `notion-create-pages`.
- **Title:** `SESSION <N>: <topic> (<YYYY-MM-DD>)` — colon form, matching the
  recent S089/S090/S092 pages.
- **Match the house format exactly.** Fetch the most recent prior session page
  first (`notion-fetch`) and mirror its structure rather than reinventing it.
  The locked format is:
  - A `##` outcome headline + a short intro paragraph.
  - `**Bold lead-ins**` for key beats; `###` subsections.
  - `<table header-row="true"><tr><td>…</td></tr></table>` blocks for tables.
  - A `---` rule, then a `## In Plain Terms` section in conversational,
    non-technical language.
  - A closing `---` and an italic `*Source: …*` footer with backticked paths,
    commits, and branch.
- **Hard format rules** (these are what keep the pages consistent and clean):
  - **No em-dashes anywhere.** Use commas, colons, or periods.
  - Escape dollar amounts as `\$` (e.g. `\$0.106`) — bare `$` triggers Notion
    math rendering.
  - Avoid `<` and `>` inside table cells; write "0.50 or more", "p below 0.05".
  - Inline code / paths / commits in backticks.

Return the created page URL.

## Phase 3 — Crystalize

Invoke the `crystalize` skill (a global skill). It writes the continuity crystal
to `E:\breadstick\crystals\<thread-slug>\<event-slug>-<YYYY-MM-DDTHH-MM-SS>.md`
with its own frontmatter + sections (What we built / Decisions / Open / Blockers
/ Gotchas / Wire-to-next) and returns the absolute path. Reuse the Phase-0
material. Per the crystalize skill's own rule, do **not** recap the crystal
contents back to Dan — the path is the deliverable.

## Return

Close with a three-line summary, nothing more:

```
main:    <pushed commit hash, or the local/unpushed state>
notion:  <page URL>
crystal: <absolute crystal path>
```

## What this skill does not do

- It is not a settings.json hook — the debrief and crystal need Claude's
  judgment, which a shell hook can't provide. "Every session" comes from the
  Workflow cue in `CLAUDE.md`, which points Claude here on a wrap-up signal.
- It does not change the `crystalize` skill or the Notion house format — it
  consumes both as they are.
- It is ARES-specific (the hub id, the squash-merge convention, the crystal
  thread); don't use it in other projects.
