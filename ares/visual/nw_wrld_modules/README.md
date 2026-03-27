# ARES Visual Modules for nw_wrld

## Setup

1. Clone nw_wrld: `git clone https://github.com/aagentah/nw_wrld.git`
2. Install: `cd nw_wrld && npm install`
3. Start: `npm start`
4. Select or create a project folder when prompted
5. Copy these module files into your nw_wrld project's `modules/` folder:
   - `AresEvidenceGraph.js`
   - `AresConfidenceHeat.js`
6. nw_wrld will hot-reload the modules automatically

## Running the ARES Emitter

1. In a separate terminal, activate the ARES venv
2. Run: `python -m ares.visual.scripts.run_visual --scenario SC-019 --speed 0.5`
3. The emitter starts a WebSocket server on ws://localhost:8765
4. In nw_wrld, configure Remote API input to connect to ws://localhost:8765

## Signal Routing in nw_wrld

Map incoming WebSocket events to module methods:
- `fact_ingested` -> AresEvidenceGraph.addFact
- `assertion_formed` -> AresEvidenceGraph.addAssertion
- `verdict_rendered` -> AresEvidenceGraph.showVerdict + AresConfidenceHeat.showVerdict
- `miscalibration_check` -> AresEvidenceGraph.showMiscalibration + AresConfidenceHeat.showMiscalibration
- `scenario_start` -> AresEvidenceGraph.reset + AresConfidenceHeat.reset

## Event Sequence

Each scenario produces events in this order:
1. `scenario_start` - metadata and fact count
2. `fact_ingested` (N events) - one per evidence fact
3. `assertion_formed` (M events) - one per architect assertion
4. `verdict_rendered` - final verdict with confidence
5. `miscalibration_check` - overconfidence detection result
6. `claim_audit` (conditional) - only if miscalibration flagged
7. `scenario_end` - timing summary

## CLI Options

```
python -m ares.visual.scripts.run_visual --scenario SC-001    # Single scenario
python -m ares.visual.scripts.run_visual --all                # All 33 scenarios
python -m ares.visual.scripts.run_visual --speed 2.0          # 2x playback speed
python -m ares.visual.scripts.run_visual --list               # List scenarios
python -m ares.visual.scripts.run_visual --no-server          # Print JSON to stdout
python -m ares.visual.scripts.run_visual --port 9000          # Custom port
```
