/*
@nwWrld name: AresScene
@nwWrld category: Data Visualization
@nwWrld imports: BaseThreeJsModule,THREE
*/

/**
 * AresScene — Unified ARES visualization for nw_wrld.
 *
 * Renders the full ARES reasoning chain as a live 3D scene:
 * - Evidence facts appear as colored spheres (by source type)
 * - Assertions appear as icosahedra connected to their cited facts
 * - The verdict appears as a central torus colored by outcome
 * - An ambient particle system reflects overall confidence state
 * - Miscalibration events trigger visual disruptions
 *
 * Data arrives via WebSocket (live) or loadJson (offline replay).
 */
class AresScene extends BaseThreeJsModule {
  constructor(container) {
    super(container);

    // --- Evidence Graph State ---
    this._factNodes = new Map();
    this._assertionNodes = new Map();
    this._edges = [];
    this._verdictMesh = null;
    this._verdictLight = null;
    this._clock = 0;
    this._shakeIntensity = 0;
    this._cameraBasePos = { x: 0, y: 2, z: 12 };

    // --- Confidence Heat State ---
    this._particles = null;
    this._positions = null;
    this._velocities = null;
    this._colors = null;
    this._particleCount = 800;
    this._confidence = 0.0;
    this._targetConfidence = 0.0;
    this._disruptionTimer = 0;
    this._convergeTimer = 0;
    this._verdictColor = { r: 1, g: 1, b: 1 };

    // --- Connection State ---
    this._ws = null;
    this._connected = false;
    this._replayTimers = [];
    this._speed = 1.0;
    this._scenarioId = null;
    this._animId = null;

    // --- Color Palettes ---
    this._SOURCE_COLORS = {
      syslog: 0x50c878,
      netflow: 0xff8c00,
      windows_event_log: 0x4a90d9,
      auth_log: 0xda70d6,
      dns_log: 0x20b2aa,
      process_list: 0xf0e68c,
      graph_computation: 0x87ceeb,
      manual: 0xaaaaaa,
      unknown: 0x888888,
    };

    this._VERDICT_COLORS = {
      threat_confirmed: 0xff2244,
      threat_dismissed: 0x2288ff,
      inconclusive: 0xffaa00,
    };

    this._VERDICT_RGB = {
      threat_confirmed: { r: 1.0, g: 0.13, b: 0.27 },
      threat_dismissed: { r: 0.13, g: 0.53, b: 1.0 },
      inconclusive: { r: 1.0, g: 0.67, b: 0.0 },
    };

    this.init();
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  init() {
    // Scene setup
    this.scene.background = new THREE.Color(0x0a0a0f);

    // Camera
    this.camera.position.set(
      this._cameraBasePos.x,
      this._cameraBasePos.y,
      this._cameraBasePos.z
    );
    this.camera.lookAt(0, 0, 0);

    // Lighting
    const ambient = new THREE.AmbientLight(0x222233, 0.6);
    this.scene.add(ambient);

    const point = new THREE.PointLight(0xffffff, 0.8, 50);
    point.position.set(5, 8, 5);
    this.scene.add(point);

    // Initialize particle system for confidence heat
    this._initParticles();

    // Start render loop
    this._animate();
  }

  destroy() {
    // Cancel animation
    if (this._animId) {
      cancelAnimationFrame(this._animId);
      this._animId = null;
    }

    // Close WebSocket
    if (this._ws) {
      this._ws.close();
      this._ws = null;
    }

    // Cancel pending replay timers
    this._replayTimers.forEach((t) => clearTimeout(t));
    this._replayTimers = [];

    // Dispose evidence graph
    this._clearGraph();

    // Dispose particles
    if (this._particles) {
      this._particles.geometry.dispose();
      this._particles.material.dispose();
      this.scene.remove(this._particles);
    }

    super.destroy();
  }

  // -----------------------------------------------------------------------
  // Public Methods (triggered by nw_wrld dashboard or sequencer)
  // -----------------------------------------------------------------------

  connect(url = 'ws://localhost:8765') {
    if (this._ws) {
      this._ws.close();
    }

    this._ws = new WebSocket(url);

    this._ws.onopen = () => {
      this._connected = true;
      console.log('[AresScene] Connected to', url);
    };

    this._ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        this._handleEvent(data);
      } catch (err) {
        console.warn('[AresScene] Failed to parse message:', err);
      }
    };

    this._ws.onclose = () => {
      this._connected = false;
      this._ws = null;
      console.log('[AresScene] Disconnected');
    };

    this._ws.onerror = (err) => {
      this._connected = false;
      console.warn('[AresScene] WebSocket error:', err);
    };
  }

  loadScenario(file = 'SC-001_events.json') {
    loadJson('json/' + file)
      .then((events) => {
        if (Array.isArray(events)) {
          console.log('[AresScene] Loaded', events.length, 'events from', file);
          this._replayOffline(events);
        }
      })
      .catch((err) => {
        console.warn('[AresScene] Failed to load', file, err);
      });
  }

  reset() {
    // Cancel pending replay timers
    this._replayTimers.forEach((t) => clearTimeout(t));
    this._replayTimers = [];

    // Clear 3D graph
    this._clearGraph();

    // Reset confidence heat
    this._confidence = 0;
    this._targetConfidence = 0;
    this._disruptionTimer = 0;
    this._convergeTimer = 0;
    this._verdictColor = { r: 1, g: 1, b: 1 };
    this._resetParticlePositions();

    this._scenarioId = null;
  }

  setSpeed(multiplier = 1.0) {
    this._speed = Math.max(0.1, Math.min(10, parseFloat(multiplier) || 1.0));
    console.log('[AresScene] Speed set to', this._speed);
  }

  // -----------------------------------------------------------------------
  // Event Dispatch
  // -----------------------------------------------------------------------

  _handleEvent(data) {
    switch (data.event_type) {
      case 'scenario_start':
        this.reset();
        this._scenarioId = data.scenario_id;
        console.log(
          '[AresScene] Scenario:',
          data.scenario_id,
          '—',
          data.scenario_name
        );
        break;

      case 'fact_ingested':
        this._addFact(data);
        break;

      case 'assertion_formed':
        this._addAssertion(data);
        this._targetConfidence = Math.max(
          this._targetConfidence,
          data.confidence || 0
        );
        break;

      case 'verdict_rendered':
        this._showVerdict(data);
        break;

      case 'miscalibration_check':
        this._showMiscalibration(data);
        break;

      case 'claim_audit':
        // Visual acknowledgement — flash edges briefly
        console.log(
          '[AresScene] Claim audit:',
          data.claims_supported,
          '/',
          data.claims_total,
          'supported'
        );
        break;

      case 'scenario_end':
        console.log(
          '[AresScene] Scenario complete:',
          data.duration_ms,
          'ms'
        );
        break;
    }
  }

  // -----------------------------------------------------------------------
  // Offline Replay
  // -----------------------------------------------------------------------

  _replayOffline(events) {
    this.reset();

    let baseTime = events.length > 0 ? events[0].timestamp_ms : 0;

    events.forEach((evt) => {
      const delay = ((evt.timestamp_ms - baseTime) / this._speed);
      const timer = setTimeout(() => {
        this._handleEvent(evt);
      }, delay);
      this._replayTimers.push(timer);
    });
  }

  // -----------------------------------------------------------------------
  // Evidence Graph Rendering
  // -----------------------------------------------------------------------

  _addFact({ fact_id, entity_type, source_type, source_index, fact_index }) {
    const color =
      this._SOURCE_COLORS[source_type] || this._SOURCE_COLORS.unknown;
    const geo = new THREE.SphereGeometry(0.25, 16, 16);
    const mat = new THREE.MeshStandardMaterial({
      color,
      emissive: color,
      emissiveIntensity: 0.3,
      metalness: 0.2,
      roughness: 0.7,
    });
    const mesh = new THREE.Mesh(geo, mat);

    const x = (source_index - 1) * 4 + (Math.random() - 0.5) * 1.5;
    const y =
      (entity_type === 'edge' ? 1.5 : -1.5) + (Math.random() - 0.5);
    const z = fact_index * 0.8 - 4 + (Math.random() - 0.5) * 0.5;
    mesh.position.set(x, y, z);

    mesh.scale.set(0.01, 0.01, 0.01);
    mesh.userData = { targetScale: 1.0, fact_id, source_type };

    this.scene.add(mesh);
    this._factNodes.set(fact_id, mesh);
  }

  _addAssertion({ assertion_id, cited_fact_ids, confidence }) {
    let cx = 0,
      cy = 0,
      cz = 0,
      count = 0;
    const cited = cited_fact_ids || [];

    cited.forEach((fid) => {
      const node = this._factNodes.get(fid);
      if (node) {
        cx += node.position.x;
        cy += node.position.y;
        cz += node.position.z;
        count++;
      }
    });

    if (count > 0) {
      cx /= count;
      cy /= count;
      cz /= count;
    }
    cy += 2.5;

    const size = 0.3 + confidence * 0.5;
    const geo = new THREE.IcosahedronGeometry(size, 1);
    const mat = new THREE.MeshStandardMaterial({
      color: 0x00ccff,
      emissive: 0x00ccff,
      emissiveIntensity: 0.2 + confidence * 0.4,
      metalness: 0.4,
      roughness: 0.3,
      transparent: true,
      opacity: 0.8,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.set(cx, cy, cz);
    mesh.scale.set(0.01, 0.01, 0.01);
    mesh.userData = { targetScale: 1.0, assertion_id };

    this.scene.add(mesh);
    this._assertionNodes.set(assertion_id, mesh);

    // Draw edges to cited facts
    cited.forEach((fid) => {
      const factMesh = this._factNodes.get(fid);
      if (factMesh) {
        const points = [mesh.position.clone(), factMesh.position.clone()];
        const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
        const lineMat = new THREE.LineBasicMaterial({
          color: 0x00ccff,
          transparent: true,
          opacity: Math.max(0.2, confidence),
        });
        const line = new THREE.Line(lineGeo, lineMat);
        this.scene.add(line);
        this._edges.push(line);
      }
    });
  }

  _showVerdict({ outcome, confidence, correct }) {
    const color = this._VERDICT_COLORS[outcome] || 0xffffff;

    // Verdict torus
    const geo = new THREE.TorusGeometry(1.2, 0.15, 16, 48);
    const mat = new THREE.MeshStandardMaterial({
      color,
      emissive: color,
      emissiveIntensity: 0.5 + confidence * 0.5,
      metalness: 0.6,
      roughness: 0.2,
      transparent: true,
      opacity: 0.9,
    });
    this._verdictMesh = new THREE.Mesh(geo, mat);
    this._verdictMesh.position.set(0, 1, 0);
    this._verdictMesh.userData = { correct, pulse: !correct };
    this.scene.add(this._verdictMesh);

    // Verdict point light
    this._verdictLight = new THREE.PointLight(color, confidence * 2, 15);
    this._verdictLight.position.set(0, 1, 0);
    this.scene.add(this._verdictLight);

    // Update confidence heat
    this._targetConfidence = confidence;
    this._convergeTimer = 2.0;
    this._verdictColor =
      this._VERDICT_RGB[outcome] || { r: 1, g: 1, b: 1 };
  }

  _showMiscalibration({ flagged, risk_score }) {
    if (!flagged) return;

    // Evidence graph: flash edges red, shake camera
    this._shakeIntensity = risk_score * 0.3;
    this._edges.forEach((line) => {
      line.material.color.setHex(0xff2244);
      setTimeout(() => {
        line.material.color.setHex(0x00ccff);
      }, 800);
    });

    // Confidence heat: scatter particles, tint red
    this._disruptionTimer = 1.5;
    for (let i = 0; i < this._particleCount; i++) {
      const i3 = i * 3;
      this._velocities[i3] += (Math.random() - 0.5) * risk_score * 0.1;
      this._velocities[i3 + 1] +=
        (Math.random() - 0.5) * risk_score * 0.1;
      this._velocities[i3 + 2] +=
        (Math.random() - 0.5) * risk_score * 0.05;
    }
  }

  _clearGraph() {
    this._factNodes.forEach((mesh) => {
      mesh.geometry.dispose();
      mesh.material.dispose();
      this.scene.remove(mesh);
    });
    this._assertionNodes.forEach((mesh) => {
      mesh.geometry.dispose();
      mesh.material.dispose();
      this.scene.remove(mesh);
    });
    this._edges.forEach((line) => {
      line.geometry.dispose();
      line.material.dispose();
      this.scene.remove(line);
    });
    if (this._verdictMesh) {
      this._verdictMesh.geometry.dispose();
      this._verdictMesh.material.dispose();
      this.scene.remove(this._verdictMesh);
      this._verdictMesh = null;
    }
    if (this._verdictLight) {
      this.scene.remove(this._verdictLight);
      this._verdictLight = null;
    }
    this._factNodes.clear();
    this._assertionNodes.clear();
    this._edges = [];
    this._shakeIntensity = 0;
  }

  // -----------------------------------------------------------------------
  // Confidence Heat Particle System
  // -----------------------------------------------------------------------

  _initParticles() {
    const geo = new THREE.BufferGeometry();
    this._positions = new Float32Array(this._particleCount * 3);
    this._velocities = new Float32Array(this._particleCount * 3);
    this._colors = new Float32Array(this._particleCount * 3);

    this._resetParticlePositions();

    geo.setAttribute(
      'position',
      new THREE.BufferAttribute(this._positions, 3)
    );
    geo.setAttribute('color', new THREE.BufferAttribute(this._colors, 3));

    const mat = new THREE.PointsMaterial({
      size: 0.08,
      vertexColors: true,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    this._particles = new THREE.Points(geo, mat);
    this.scene.add(this._particles);
  }

  _resetParticlePositions() {
    if (!this._positions) return;
    for (let i = 0; i < this._particleCount; i++) {
      const i3 = i * 3;
      this._positions[i3] = (Math.random() - 0.5) * 20;
      this._positions[i3 + 1] = (Math.random() - 0.5) * 20;
      this._positions[i3 + 2] = (Math.random() - 0.5) * 10;
      this._velocities[i3] = (Math.random() - 0.5) * 0.02;
      this._velocities[i3 + 1] = (Math.random() - 0.5) * 0.02;
      this._velocities[i3 + 2] = (Math.random() - 0.5) * 0.01;
      this._colors[i3] = 0.3;
      this._colors[i3 + 1] = 0.5;
      this._colors[i3 + 2] = 0.8;
    }
  }

  // -----------------------------------------------------------------------
  // Render Loop
  // -----------------------------------------------------------------------

  _animate() {
    this._animId = requestAnimationFrame(() => this._animate());

    this._clock += 0.01;
    const dt = 0.016;

    // --- Evidence Graph Animation ---

    // Gentle camera orbit
    this.camera.position.x =
      this._cameraBasePos.x + Math.sin(this._clock * 0.3) * 0.5;
    this.camera.position.y =
      this._cameraBasePos.y + Math.sin(this._clock * 0.2) * 0.3;

    // Camera shake decay
    if (this._shakeIntensity > 0.001) {
      this.camera.position.x +=
        (Math.random() - 0.5) * this._shakeIntensity;
      this.camera.position.y +=
        (Math.random() - 0.5) * this._shakeIntensity;
      this._shakeIntensity *= 0.95;
    }

    this.camera.lookAt(0, 0, 0);

    // Scale-up animation for facts
    this._factNodes.forEach((mesh) => {
      if (mesh.scale.x < mesh.userData.targetScale) {
        mesh.scale.multiplyScalar(1.08);
        if (mesh.scale.x > mesh.userData.targetScale) {
          mesh.scale.set(
            mesh.userData.targetScale,
            mesh.userData.targetScale,
            mesh.userData.targetScale
          );
        }
      }
      mesh.material.emissiveIntensity =
        0.2 + Math.sin(this._clock * 2 + mesh.position.x) * 0.1;
    });

    // Scale-up + rotation for assertions
    this._assertionNodes.forEach((mesh) => {
      if (mesh.scale.x < mesh.userData.targetScale) {
        mesh.scale.multiplyScalar(1.06);
      }
      mesh.rotation.y += 0.005;
    });

    // Verdict pulse if incorrect
    if (this._verdictMesh && this._verdictMesh.userData.pulse) {
      const pulse = 0.5 + Math.sin(this._clock * 4) * 0.3;
      this._verdictMesh.material.emissiveIntensity = pulse;
    }

    // --- Confidence Heat Animation ---

    this._confidence += (this._targetConfidence - this._confidence) * 0.02;
    this._disruptionTimer = Math.max(0, this._disruptionTimer - dt);
    this._convergeTimer = Math.max(0, this._convergeTimer - dt);

    const speedMult = 0.2 + this._confidence * 0.8;
    const brightMult = 0.3 + this._confidence * 0.7;

    for (let i = 0; i < this._particleCount; i++) {
      const i3 = i * 3;
      const visible =
        i < this._particleCount * (0.2 + this._confidence * 0.8);

      if (visible) {
        this._positions[i3] += this._velocities[i3] * speedMult;
        this._positions[i3 + 1] += this._velocities[i3 + 1] * speedMult;
        this._positions[i3 + 2] += this._velocities[i3 + 2] * speedMult;

        // Converge toward center on verdict
        if (this._convergeTimer > 0) {
          this._positions[i3] *= 0.995;
          this._positions[i3 + 1] *= 0.995;
          this._positions[i3 + 2] *= 0.995;
        }

        // Wrap around bounds
        if (Math.abs(this._positions[i3]) > 12) this._positions[i3] *= -0.5;
        if (Math.abs(this._positions[i3 + 1]) > 12)
          this._positions[i3 + 1] *= -0.5;
        if (Math.abs(this._positions[i3 + 2]) > 8)
          this._positions[i3 + 2] *= -0.5;

        // Color
        if (this._disruptionTimer > 0) {
          this._colors[i3] = 1.0;
          this._colors[i3 + 1] = 0.1;
          this._colors[i3 + 2] = 0.1;
        } else if (this._convergeTimer > 0) {
          this._colors[i3] = this._verdictColor.r * brightMult;
          this._colors[i3 + 1] = this._verdictColor.g * brightMult;
          this._colors[i3 + 2] = this._verdictColor.b * brightMult;
        } else {
          this._colors[i3] = 0.2 * brightMult;
          this._colors[i3 + 1] = 0.5 * brightMult;
          this._colors[i3 + 2] = 0.9 * brightMult;
        }
      } else {
        this._positions[i3] = 999;
        this._positions[i3 + 1] = 999;
        this._positions[i3 + 2] = 999;
      }
    }

    if (this._particles) {
      this._particles.geometry.attributes.position.needsUpdate = true;
      this._particles.geometry.attributes.color.needsUpdate = true;
      this._particles.material.opacity = 0.3 + this._confidence * 0.5;
    }

    // --- Render ---
    this.renderer.render(this.scene, this.camera);
  }

  // -----------------------------------------------------------------------
  // nw_wrld Method Declarations
  // -----------------------------------------------------------------------

  static methods = [
    {
      name: 'connect',
      executeOnLoad: false,
      options: [
        {
          name: 'url',
          type: 'text',
          defaultVal: 'ws://localhost:8765',
        },
      ],
    },
    {
      name: 'loadScenario',
      executeOnLoad: false,
      options: [
        {
          name: 'file',
          type: 'assetFile',
          defaultVal: 'SC-001_events.json',
        },
      ],
    },
    {
      name: 'reset',
      executeOnLoad: false,
      options: [],
    },
    {
      name: 'setSpeed',
      executeOnLoad: false,
      options: [
        {
          name: 'multiplier',
          type: 'number',
          defaultVal: 1.0,
        },
      ],
    },
  ];
}

export default AresScene;
