# ARES-VISION Static Deployment

Upload these files to any static web host. Open index.html.
No server, no API keys, no Python required.

## Files

- `index.html` — Kill chain visualizer (v6)
- `showcase.json` — Pre-recorded session data (generate with run_live_export_v6.py)

## Replay

Open `index.html?session=showcase.json` in any browser.

## Generate showcase.json

```bash
python -m ares.visual.scripts.run_live_export_v6 --mode showcase -o ares/visual/deploy/showcase.json --no-ws
```

## Demo mode (no data needed)

Open `index.html?demo=true` for a built-in demo with synthetic PT + SC scenarios.
