# ARES + nw_wrld Integration Guide

## Prerequisites

- nw_wrld installed: `git clone https://github.com/aagentah/nw_wrld.git && cd nw_wrld && npm install`
- ARES venv activated: `.\venv\Scripts\Activate.ps1`
- Python dependencies: `pip install websockets`

## Quick Start (Offline Replay)

Works without a running WebSocket server.

### 1. Export scenario events to JSON

```bash
# Single scenario
python -m ares.visual.scripts.run_export --scenario SC-001 --output-dir ./nw_wrld_events

# All 33 scenarios
python -m ares.visual.scripts.run_export --all --output-dir ./nw_wrld_events
```

### 2. Set up nw_wrld workspace

1. Start nw_wrld: `cd nw_wrld && npm start`
2. Create or select a workspace folder when prompted
3. Copy module into workspace:
   - Copy `AresScene.js` to `<workspace>/modules/`
4. Copy event data into workspace:
   - Copy `SC-*_events.json` files to `<workspace>/assets/json/`
5. nw_wrld hot-reloads the module automatically

### 3. Run the visualization

1. In nw_wrld Dashboard, create a new track
2. Add the **AresScene** module to the track
3. Trigger the **loadScenario** method with filename `SC-001_events.json`
4. The evidence graph builds up in the Projector window

## Live WebSocket Streaming

Streams events in real-time from the ARES pipeline.

### 1. Start the ARES emitter

```bash
# Single scenario at half speed
python -m ares.visual.scripts.run_visual --scenario SC-019 --speed 0.5

# All 33 scenarios
python -m ares.visual.scripts.run_visual --all --speed 0.5
```

The emitter starts a WebSocket server on `ws://localhost:8765`.

### 2. Connect from nw_wrld

1. Activate the AresScene track in nw_wrld
2. Trigger the **connect** method (default URL: `ws://localhost:8765`)
3. Events stream in real-time as the emitter replays scenarios

## Module Methods

| Method | Type | Description |
|--------|------|-------------|
| `connect(url)` | text | Open WebSocket to ARES emitter |
| `loadScenario(file)` | assetFile | Load and replay a JSON event file |
| `reset()` | — | Clear the scene |
| `setSpeed(multiplier)` | number | Adjust replay speed (1.0 = normal) |

## Event Flow

Each scenario produces events in this order:

```
scenario_start  →  fact_ingested (N)  →  assertion_formed (M)
    →  verdict_rendered  →  miscalibration_check
    →  claim_audit (conditional)  →  scenario_end
```

## Visual Mapping

| Event | 3D Object | Color |
|-------|-----------|-------|
| fact_ingested | Sphere | By source type (green=syslog, orange=netflow, blue=windows, etc.) |
| assertion_formed | Icosahedron | Cyan, sized by confidence |
| verdict_rendered | Torus | Red=threat, Blue=dismissed, Orange=inconclusive |
| miscalibration | Edge flash + camera shake | Red flash |

## CLI Reference

```bash
# Export events
python -m ares.visual.scripts.run_export --scenario SC-001
python -m ares.visual.scripts.run_export --all --output-dir ./events
python -m ares.visual.scripts.run_export --list

# Stream via WebSocket
python -m ares.visual.scripts.run_visual --scenario SC-001
python -m ares.visual.scripts.run_visual --all --speed 2.0
python -m ares.visual.scripts.run_visual --port 9000
python -m ares.visual.scripts.run_visual --no-server  # JSON lines to stdout

# List available scenarios
python -m ares.visual.scripts.run_visual --list
```

## Troubleshooting

**Module not loading in nw_wrld:**
- Check the Projector Developer Console for errors
- Ensure `AresScene.js` is in the workspace `modules/` folder (not a subdirectory)
- Verify the `@nwWrld` docblock is present at the top of the file

**WebSocket not connecting:**
- Ensure the ARES emitter is running before triggering `connect()`
- Check that port 8765 is not blocked by firewall
- Try a different port: start emitter with `--port 9000`, connect with `ws://localhost:9000`

**No events appearing:**
- For offline: ensure JSON files are in `<workspace>/assets/json/`
- For live: the emitter waits 2 seconds for clients before streaming — connect quickly
- Check the browser console in nw_wrld Projector for `[AresScene]` log messages
