# Phase 0 — Benchmark Runnability Decision (ARES-Harness arc)

**Date:** 2026-06-20
**Session:** 096
**Spec:** `docs/superpowers/specs/2026-06-20-ares-harness-injection-defense-design.md` (§9, §14)
**Verdict:** **GO — AgentDojo** (v1.2). InjecAgent not needed.

## What was tested

Installed and ran AgentDojo in a **throwaway venv isolated from ARES's main env** (`.scratch/bench-venv`, gitignored) — ARES's own dependencies untouched.

| Question | AgentDojo |
|---|---|
| Installable on Windows / Py 3.11 | **Yes** — `pip install agentdojo` → `agentdojo-0.1.35`, clean, pulls anthropic/openai/google-genai backends |
| Offline-enumerable suites/tasks | **Yes** — `get_suites("v1.2")` → 4 suites, 97 user tasks, 35 injection tasks (workspace 40/14, travel 20/7, banking 16/9, slack 21/5), no model calls |
| Model backend usable with our keys | **Yes, with a shim** (see Integration frictions) — Anthropic key from the UTF-16 `.env` works |
| License | Permissive (AgentDojo is the NeurIPS'24 D&B standard; the benchmark CaMeL/SecAlign report against) |
| Cost | Tiny per-case; full benchmark large (≈629 user×injection security cases at `important_instructions`) — slice for Phase 3 |

End-to-end live proof: a 6-case banking slice ran and produced real ASR + utility numbers (see `PHASE0_BASELINE_2026-06-20.md`).

**InjecAgent:** not evaluated. AgentDojo is the stronger, standard anchor and it works; revisit InjecAgent only if a second surface is wanted.

## Integration frictions (carry to Phase 3 — small, all solved here)

1. **Model-enum is frozen to the 3.x line; this account serves only claude-4.x / fable-5.** `get_suites`/pipeline `from_config` does `MODEL_PROVIDERS[ModelsEnum(config.llm)]`, so passing a current model id as a **string** raises `ValueError: not a valid ModelsEnum`. The 3.x ids it knows (e.g. `claude-3-5-sonnet-20241022`) all 404 on this account.
   - **Workaround used:** bypass the enum by constructing the LLM element directly — `AnthropicLLM(anthropic.Anthropic(), "claude-haiku-4-5-20251001")` — and passing it as `config.llm` (when `config.llm` is a `BasePipelineElement`, `from_config` uses it as-is and skips the enum).
   - **Phase 3:** add a tiny model-registry shim (register current claude-4.x ids in `ModelsEnum`/`MODEL_PROVIDERS`/`MODEL_NAMES`) so the CLI + string path work cleanly, or keep the element-bypass helper.
2. **Attacks resolve a prose model name** via `get_model_name_from_pipeline`, which substring-matches `pipeline.name` against `MODEL_NAMES`. With the element bypass `pipeline.name` is `None` → attack load fails.
   - **Workaround used:** set `pipe.name = "claude-3-5-sonnet-20241022"` (maps to prose `"Claude"`); the injection text then addresses "Claude" — accurate, since the actual element calls a Claude model (haiku-4-5). The real API calls go to haiku-4-5.
3. **Runs must be wrapped in a logger context:** `with OutputLogger(str(logdir)): ...` — otherwise `TraceLogger` hits `NullLogger.logdir` AttributeError.
4. **API key:** loaded from the UTF-16 `.env` in-process (`os.environ["ANTHROPIC_API_KEY"]=...`); never echoed.
5. **ASR semantics:** `run_task_with_injection_tasks(...)` returns `(utility_results, security_results)`, both `dict[(user_task_id, injection_task_id)] -> bool`. `security == True` means the **injection task was accomplished** (attack succeeded) → ASR = mean(security). `utility == True` = the user task was still solved.

## Reproduce

```python
# in .scratch/bench-venv
import anthropic
from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.attacks import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks
from agentdojo.logging import OutputLogger
llm = AnthropicLLM(anthropic.Anthropic(), "claude-haiku-4-5-20251001")
suite = get_suites("v1.2")["banking"]
pipe = AgentPipeline.from_config(PipelineConfig(llm=llm, model_id="claude-haiku-4-5-20251001",
        defense=None, system_message_name=None, system_message=None))
pipe.name = "claude-3-5-sonnet-20241022"   # -> prose "Claude" for the attack
attack = load_attack("important_instructions", suite, pipe)
with OutputLogger(".scratch/agentdojo-logs"):
    util, sec = run_task_with_injection_tasks(suite, pipe, suite.user_tasks["user_task_0"],
                                              attack, None, True, ["injection_task_0"], "v1.2")
```

## Decision

**GO with AgentDojo v1.2** as the Phase-3 measurement surface. The frictions above are mechanical and already solved; the only Phase-3 build item is the model-registry shim (or the element-bypass helper) to make current claude-4.x models first-class. The defense (Phase 1 `ares/harness/`, Phase 2 action gate + middleware) plugs in via the `defense` slot / a custom pipeline element wrapping tool outputs.
