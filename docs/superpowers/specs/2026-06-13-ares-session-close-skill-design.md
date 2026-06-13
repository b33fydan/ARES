# ARES Session-Close Skill — Design

**Date:** 2026-06-13
**Build session:** S093
**Status:** DESIGN — brainstorming output, pending user review then build (via skill-creator)
**Author:** Daniel Gmys-Casiano (Skyframe Innovations)

---

## Purpose

A project-level skill, `ares-session-close`, that runs the ARES end-of-session ritual consistently every time, in this fixed order:

1. **Gate commit/push** — perform the standard ARES close (CLAUDE.md ledger + squash-merge to `main`), confirming before the push.
2. **Notion debrief + In Plain Terms** — post the session debrief, always including the layman's section, in the locked house format.
3. **Crystalize** — invoke the existing `crystalize` skill to write the continuity crystal.

The goal is to make the close we performed in S092 repeatable and consistent, so no step is forgotten and the format never drifts.

## Trigger model (decided)

- **Mechanism:** a **skill** (`ares-session-close`), NOT a settings.json hook. A hook runs only a shell command on a session event and cannot do the Claude-reasoning work (composing the debrief, deciding what's "done as needed," calling crystalize); a Stop hook also fires every turn, not just at close.
- **"Every ARES session"** is achieved by a **CLAUDE.md cue**: a line under Workflow instructing Claude to proactively invoke (or offer) the skill when Dan signals wrap-up. The skill is also invocable by name any time.
- Explicitly rejected: a SessionEnd/Stop hook as the primary mechanism (a lightweight reminder hook could be added later as belt-and-suspenders, but is out of scope).

## Location, name, structure

- **Name:** `ares-session-close`
- **Path:** `.claude/skills/ares-session-close/SKILL.md` (project-level, versioned with the ARES repo, sibling of the existing `ares-knowledge` skill).
- **Structure:** a single self-contained `SKILL.md` — frontmatter + the 3-phase procedure + an embedded Notion-format template. Small enough that one file is clearer than splitting into `reference/` files.

## Procedure

### Phase 0 — Gather

Detect session state and collect debrief material before doing anything:
- `git rev-parse --abbrev-ref HEAD` (branch), `git status --short` (uncommitted), `git log --oneline main..HEAD` (commits ahead), sync vs `origin/main`.
- From the session: what was built/changed (file paths, commits), key decisions + why, load-bearing numbers, gotchas, what's open. This is the raw material for both the Notion debrief and the crystal.

### Phase 1 — Commit/push gate (perform, confirm before push)

Branch on session state:

- **Session branch with commits ahead of `main`** → run the close:
  1. Update `CLAUDE.md`: session-ledger entry; Branch-section squash record (the convention notes a session's own squash hash is added next session); bump the test floor **only if** tests changed (verify with the freshness-scoped count, never guess high).
  2. Commit the CLAUDE.md update on the session branch (use a message file or single-quoted `-m` to avoid the UTF-8-BOM-in-subject artifact seen in S092).
  3. `git checkout main` → `git merge --squash <branch>` → `git commit` (clean squash message; subject paren/em-dash-safe).
  4. **Verify** `git diff <branch> HEAD` is empty (squash captured everything).
  5. Run `pytest tests/test_claude_md_freshness.py` (the SSOT gate).
  6. **Show the squash result + freshness outcome, then ask for confirmation.**
  7. On confirm → `git push origin main` + `git push origin <branch>` (retain the session branch on origin as the un-squashed audit trail).
- **Analysis-only / nothing to commit** → note it, skip git, continue.
- **Already merged + pushed** → detect, note it, continue.
- **Freshness gate fails, or the squash hits a conflict / unexpected git state** → STOP before push, surface the failure, do not force.

### Phase 2 — Notion debrief + In Plain Terms

Create a page under the **🔱 ARES PHASE ZERO** hub (`2e87e255421c8025a599df48b592329a`) via `notion-create-pages`:
- **Title:** `SESSION <N>: <topic> (<YYYY-MM-DD>)` (colon form, matching S089/S090/S092).
- **Format (locked house style):** `##` outcome headline + intro; `**Bold lead-ins**`; `###` subsections; `<table header-row="true"><tr><td>…` blocks; a `---` rule; a **`## In Plain Terms`** layman's section (ALWAYS present — this is the explicit ask); a closing `---`; an italic `*Source: …*` footer with backticked paths/commits.
- **Hard rules:** EM-DASH-FREE throughout; escape dollar signs as `\$`; avoid `<`/`>` inside table cells (write "0.50 or more", "p below 0.05"); inline code in backticks.
- To match format exactly, fetch the most recent prior session page first and mirror it.
- Return the page URL.

### Phase 3 — Crystalize

Invoke the `crystalize` skill (global). It writes `E:\breadstick\crystals\<thread-slug>\<event-slug>-<YYYY-MM-DDTHH-MM-SS>.md` with its frontmatter + sections (What we built / Decisions / Open / Blockers / Gotchas / Wire-to-next) and returns the absolute path. Do not recap the crystal contents (per the crystalize skill's own rule).

### Return

A 3-line summary: `main` pushed (commit hash) or the state if not; Notion URL; crystal path.

## Edge cases / error handling

- **Not a git repo / no session branch** → skip Phase 1 with a note; still do Phase 2 + 3.
- **Push declined at the confirmation** → `main` stays merged locally; report the exact `git push` commands for later; still continue to Notion + crystalize (both are independent of the push).
- **Freshness gate fails / squash conflict** → stop before push, surface, don't force.
- **Notion unavailable** → don't lose the debrief: write the debrief markdown to a local fallback file (e.g. `docs/marketing/` or `.scratch/`), report the path, then still crystalize.
- **Already closed** → detect (branch merged + pushed, clean tree), skip git, continue.
- **Never fires mid-task** — only on an explicit end-of-session signal.

## The CLAUDE.md cue (exact wording, added under Workflow)

> **Session close:** When Dan signals the session is ending ("done for today", "wrap up", "close out", "end session", "that's a wrap"), invoke the `ares-session-close` skill — it gates commit/push (CLAUDE.md ledger + squash-merge to `main`, *confirm before push*), posts the Notion debrief + In Plain Terms, then crystalizes. Offer it if the intent is ambiguous; never fire mid-task.

(Prose only — adds no paths/floors, so the CLAUDE.md freshness gate is unaffected.)

## The skill frontmatter (exact)

```yaml
---
name: ares-session-close
description: Use at the end of an ARES working session to close it out
  completely — gate the commit/push (CLAUDE.md ledger + squash-merge to main,
  confirm before push), post the Notion debrief + In Plain Terms layman's
  version under the ARES PHASE ZERO hub, then crystalize. Trigger when Dan
  signals wrap-up: "done for today", "close out", "wrap up", "end session",
  "/ares-session-close". ARES project only; never mid-task.
---
```

## Validation

Skills aren't unit-tested. Validation = **dogfood on the building session (S093)**: after the skill is written, run `ares-session-close` to close out S093 itself. A clean gate → Notion → crystal pass is the acceptance test.

## Out of scope

- A settings.json hook (decided against as the primary mechanism; optional reminder hook deferred).
- Auto-firing without an explicit close signal.
- Non-ARES projects (this skill encodes ARES-specific conventions: the hub id, the squash-merge ritual, the crystal thread).
- Changing the `crystalize` skill or the Notion house format — the skill *consumes* both as-is.

## Build notes (for skill-creator)

- The skill is one `SKILL.md` + one CLAUDE.md cue edit. No code, no tests.
- Carry forward the S092 git gotchas into the Phase-1 instructions: single-quoted `-m` (or `-F` file) to avoid the BOM-in-subject artifact; `git diff <branch> HEAD` empty-diff verification; retain `origin/session/<branch>` as audit trail.
