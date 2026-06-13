---
name: ares-knowledge
description: Search and retrieve ARES project knowledge from the Obsidian vault — session prompts, logs, debriefs, architecture decisions, and historical context
user_invocable: true
---

# ARES Knowledge Base (Obsidian Vault)

You have access to the ARES project's knowledge base stored in an Obsidian vault. Use the `obsidian:obsidian-cli` skill to interact with it.

## Vault Location
`C:\Users\danny\Documents\Obsidian Vault\ARES`

## What's In The Vault
- **Session prompts** — The original task briefs for each development session (SESSION_001 through SESSION_016)
- **Session logs** — Detailed records of what happened during sessions
- **Debriefs** — Post-session analysis and lessons learned (e.g., SESSIONS_013_014_COMPREHENSIVE_DEBRIEF)
- **Benchmark analysis** — LLM accuracy reports and strategy analysis (SESSION_011B_*)
- **Historical CLAUDE.md snapshots** — How project instructions evolved over time
- **Project docs** — README, requirements files

## When To Use This Skill
- User asks "what was the prompt for session X?"
- User asks about decisions made in a previous session
- User wants historical context on why something was built a certain way
- User references a debrief or analysis doc
- User says "check the vault", "check Obsidian", or "look up session notes"

## How To Search
Use the Obsidian CLI skill to search within the ARES folder:

1. **Find a specific session**: Search for the session number (e.g., "SESSION_006")
2. **Find a concept**: Search across all ARES notes for keywords
3. **Read a specific note**: Read the file directly from `C:\Users\danny\Documents\Obsidian Vault\ARES\<filename>.md`

## Important
- Only search within the `ARES` folder — other vault folders belong to other projects
- Session prompts contain the original task requirements and constraints
- Debriefs contain lessons learned and things that surprised us
- If a note conflicts with current code, trust the code — notes are point-in-time snapshots
