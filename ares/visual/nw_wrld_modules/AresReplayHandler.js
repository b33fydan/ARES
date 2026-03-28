/*
@nwWrld name: AresReplayHandler
@nwWrld category: Data Visualization
@nwWrld imports: ModuleBase

Session 035: Handles v2 events from BenchmarkResultReplayer.
Displays a HUD overlay with confidence bars, verdict badges,
running accuracy counter, and fact citation highlights.

Designed to work alongside AresEvidenceGraph and AresConfidenceHeat —
all three modules consume the same WebSocket event stream.
*/

class AresReplayHandler extends ModuleBase {
  constructor(container) {
    super(container);

    this._ws = null;
    this._connected = false;
    this._scenarioId = null;
    this._archConfidence = 0;
    this._skepConfidence = 0;
    this._verdictOutcome = '';
    this._isCorrect = false;
    this._runningAccuracy = 0;
    this._scenariosCompleted = 0;
    this._scenariosCorrect = 0;
    this._citedFacts = { architect: [], skeptic: [] };

    // DOM elements
    this._overlay = null;
    this._archBar = null;
    this._skepBar = null;
    this._verdictBadge = null;
    this._accuracyDisplay = null;
    this._scenarioLabel = null;

    this.init();
  }

  init() {
    // Create HUD overlay container
    this._overlay = document.createElement('div');
    this._overlay.style.cssText =
      'position:absolute;top:0;left:0;width:100%;height:100%;' +
      'pointer-events:none;font-family:monospace;color:#ccc;' +
      'padding:20px;box-sizing:border-box;';
    this.container.appendChild(this._overlay);

    // Scenario label (top-left)
    this._scenarioLabel = document.createElement('div');
    this._scenarioLabel.style.cssText =
      'font-size:14px;opacity:0.8;margin-bottom:10px;';
    this._overlay.appendChild(this._scenarioLabel);

    // Confidence bars
    const barsContainer = document.createElement('div');
    barsContainer.style.cssText = 'margin-bottom:15px;';

    this._archBar = this._createBar('ARCH', '#50c878');
    this._skepBar = this._createBar('SKEP', '#4a90d9');
    barsContainer.appendChild(this._archBar.container);
    barsContainer.appendChild(this._skepBar.container);
    this._overlay.appendChild(barsContainer);

    // Verdict badge (center)
    this._verdictBadge = document.createElement('div');
    this._verdictBadge.style.cssText =
      'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);' +
      'font-size:24px;font-weight:bold;opacity:0;transition:opacity 0.5s;' +
      'text-shadow:0 0 10px currentColor;';
    this._overlay.appendChild(this._verdictBadge);

    // Running accuracy (bottom-right)
    this._accuracyDisplay = document.createElement('div');
    this._accuracyDisplay.style.cssText =
      'position:absolute;bottom:20px;right:20px;font-size:18px;opacity:0.9;';
    this._overlay.appendChild(this._accuracyDisplay);
  }

  _createBar(label, color) {
    const container = document.createElement('div');
    container.style.cssText = 'margin-bottom:5px;display:flex;align-items:center;';

    const lbl = document.createElement('span');
    lbl.textContent = label;
    lbl.style.cssText = 'width:40px;font-size:11px;opacity:0.7;';

    const track = document.createElement('div');
    track.style.cssText =
      'flex:1;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;';

    const fill = document.createElement('div');
    fill.style.cssText =
      `height:100%;width:0%;background:${color};border-radius:3px;` +
      'transition:width 0.3s ease;';
    track.appendChild(fill);

    const val = document.createElement('span');
    val.style.cssText = 'width:40px;text-align:right;font-size:11px;opacity:0.7;';

    container.appendChild(lbl);
    container.appendChild(track);
    container.appendChild(val);

    return { container, fill, val };
  }

  // --- Public methods (triggered by nw_wrld) ---

  connect(url = 'ws://localhost:8765') {
    if (this._ws) this._ws.close();

    this._ws = new WebSocket(url);
    this._ws.onopen = () => {
      this._connected = true;
      console.log('[AresReplayHandler] Connected to', url);
    };
    this._ws.onmessage = (e) => {
      try {
        this._handleEvent(JSON.parse(e.data));
      } catch (err) {
        console.warn('[AresReplayHandler] Parse error:', err);
      }
    };
    this._ws.onclose = () => {
      this._connected = false;
      this._ws = null;
    };
  }

  reset() {
    this._archConfidence = 0;
    this._skepConfidence = 0;
    this._verdictOutcome = '';
    this._isCorrect = false;
    this._citedFacts = { architect: [], skeptic: [] };
    this._updateBars();
    this._verdictBadge.style.opacity = '0';
    this._scenarioLabel.textContent = '';
  }

  // --- Event handling ---

  _handleEvent(data) {
    switch (data.event_type) {
      case 'scenario_start':
        this.reset();
        this._scenarioId = data.scenario_id;
        this._scenarioLabel.textContent =
          `${data.scenario_id}: ${data.scenario_name || ''} (${data.fact_count} facts)`;
        break;

      case 'confidence_update':
        this._archConfidence = data.architect_confidence;
        this._skepConfidence = data.skeptic_confidence;
        this._updateBars();
        break;

      case 'fact_cited':
        this._citedFacts[data.agent_role] = data.fact_ids || [];
        break;

      case 'debate_summary':
        // Pre-verdict summary — update bars one more time
        this._updateBars();
        break;

      case 'verdict_rendered':
        this._verdictOutcome = data.outcome;
        this._isCorrect = data.correct;
        this._showVerdictBadge();
        break;

      case 'accuracy_milestone':
        this._scenariosCompleted = data.scenarios_completed;
        this._scenariosCorrect = data.scenarios_correct;
        this._runningAccuracy = data.running_accuracy;
        this._updateAccuracy();
        break;
    }
  }

  _updateBars() {
    this._archBar.fill.style.width = (this._archConfidence * 100) + '%';
    this._archBar.val.textContent = this._archConfidence.toFixed(2);
    this._skepBar.fill.style.width = (this._skepConfidence * 100) + '%';
    this._skepBar.val.textContent = this._skepConfidence.toFixed(2);
  }

  _showVerdictBadge() {
    const colors = {
      threat_confirmed: '#ff2244',
      threat_dismissed: '#2288ff',
      inconclusive: '#ffaa00',
    };
    const labels = {
      threat_confirmed: 'THREAT CONFIRMED',
      threat_dismissed: 'THREAT DISMISSED',
      inconclusive: 'INCONCLUSIVE',
    };

    const color = colors[this._verdictOutcome] || '#ffffff';
    const label = labels[this._verdictOutcome] || this._verdictOutcome;
    const mark = this._isCorrect ? ' +' : ' X';

    this._verdictBadge.textContent = label + mark;
    this._verdictBadge.style.color = color;
    this._verdictBadge.style.opacity = '1';

    // Fade after 3 seconds
    setTimeout(() => {
      this._verdictBadge.style.opacity = '0.3';
    }, 3000);
  }

  _updateAccuracy() {
    const pct = (this._runningAccuracy * 100).toFixed(1);
    this._accuracyDisplay.textContent =
      `${this._scenariosCorrect}/${this._scenariosCompleted} (${pct}%)`;
  }

  destroy() {
    if (this._ws) this._ws.close();
    if (this._overlay && this._overlay.parentNode) {
      this._overlay.parentNode.removeChild(this._overlay);
    }
    super.destroy();
  }

  static methods = [
    {
      name: 'connect',
      executeOnLoad: false,
      options: [
        { name: 'url', type: 'text', defaultVal: 'ws://localhost:8765' },
      ],
    },
    {
      name: 'reset',
      executeOnLoad: false,
      options: [],
    },
  ];
}

export default AresReplayHandler;
