/**
 * @nwWrld name AresConfidenceHeat
 * @nwWrld category Data Visualization
 * @nwWrld imports three
 *
 * ARES Confidence Heat — ambient particle system representing
 * the overall confidence state of the ARES analysis.
 *
 * Particle density, speed, and brightness scale with confidence.
 * Miscalibration events scatter particles red.
 * Verdict events converge particles to center.
 */

export default AresConfidenceHeat;

function AresConfidenceHeat({ THREE, ctx, canvas }) {
  let scene, camera, renderer;
  let particles = null;
  let positions, velocities, colors;
  let clock = 0;

  const PARTICLE_COUNT = 800;
  let confidence = 0.0;
  let targetConfidence = 0.0;
  let disruptionTimer = 0;
  let convergeTimer = 0;
  let verdictColor = { r: 1, g: 1, b: 1 };

  const VERDICT_RGB = {
    threat_confirmed: { r: 1.0, g: 0.13, b: 0.27 },
    threat_dismissed: { r: 0.13, g: 0.53, b: 1.0 },
    inconclusive: { r: 1.0, g: 0.67, b: 0.0 },
  };

  return {
    construct({ width, height }) {
      scene = new THREE.Scene();
      scene.background = null; // Transparent — layer behind evidence graph

      camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 100);
      camera.position.set(0, 0, 15);

      renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
      renderer.setSize(width, height);
      renderer.setClearColor(0x000000, 0);

      // Create particle system
      const geo = new THREE.BufferGeometry();
      positions = new Float32Array(PARTICLE_COUNT * 3);
      velocities = new Float32Array(PARTICLE_COUNT * 3);
      colors = new Float32Array(PARTICLE_COUNT * 3);

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const i3 = i * 3;
        positions[i3] = (Math.random() - 0.5) * 20;
        positions[i3 + 1] = (Math.random() - 0.5) * 20;
        positions[i3 + 2] = (Math.random() - 0.5) * 10;

        velocities[i3] = (Math.random() - 0.5) * 0.02;
        velocities[i3 + 1] = (Math.random() - 0.5) * 0.02;
        velocities[i3 + 2] = (Math.random() - 0.5) * 0.01;

        colors[i3] = 0.3;
        colors[i3 + 1] = 0.5;
        colors[i3 + 2] = 0.8;
      }

      geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      geo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

      const mat = new THREE.PointsMaterial({
        size: 0.08,
        vertexColors: true,
        transparent: true,
        opacity: 0.6,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      });

      particles = new THREE.Points(geo, mat);
      scene.add(particles);
    },

    updateConfidence(newConfidence) {
      targetConfidence = Math.max(0, Math.min(1, newConfidence));
    },

    showVerdict({ outcome, confidence: conf }) {
      targetConfidence = conf;
      convergeTimer = 2.0;
      verdictColor = VERDICT_RGB[outcome] || { r: 1, g: 1, b: 1 };
    },

    showMiscalibration({ flagged, risk_score }) {
      if (flagged) {
        disruptionTimer = 1.5;
        // Scatter particles outward
        for (let i = 0; i < PARTICLE_COUNT; i++) {
          const i3 = i * 3;
          velocities[i3] += (Math.random() - 0.5) * risk_score * 0.1;
          velocities[i3 + 1] += (Math.random() - 0.5) * risk_score * 0.1;
          velocities[i3 + 2] += (Math.random() - 0.5) * risk_score * 0.05;
        }
      }
    },

    reset() {
      confidence = 0;
      targetConfidence = 0;
      disruptionTimer = 0;
      convergeTimer = 0;
      verdictColor = { r: 1, g: 1, b: 1 };

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const i3 = i * 3;
        positions[i3] = (Math.random() - 0.5) * 20;
        positions[i3 + 1] = (Math.random() - 0.5) * 20;
        positions[i3 + 2] = (Math.random() - 0.5) * 10;
        velocities[i3] = (Math.random() - 0.5) * 0.02;
        velocities[i3 + 1] = (Math.random() - 0.5) * 0.02;
        velocities[i3 + 2] = (Math.random() - 0.5) * 0.01;
        colors[i3] = 0.3;
        colors[i3 + 1] = 0.5;
        colors[i3 + 2] = 0.8;
      }
    },

    render() {
      clock += 0.016;

      confidence += (targetConfidence - confidence) * 0.02;
      disruptionTimer = Math.max(0, disruptionTimer - 0.016);
      convergeTimer = Math.max(0, convergeTimer - 0.016);

      const speedMult = 0.2 + confidence * 0.8;
      const brightMult = 0.3 + confidence * 0.7;

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const i3 = i * 3;
        const visible = i < PARTICLE_COUNT * (0.2 + confidence * 0.8);

        if (visible) {
          positions[i3] += velocities[i3] * speedMult;
          positions[i3 + 1] += velocities[i3 + 1] * speedMult;
          positions[i3 + 2] += velocities[i3 + 2] * speedMult;

          // Converge toward center on verdict
          if (convergeTimer > 0) {
            positions[i3] *= 0.995;
            positions[i3 + 1] *= 0.995;
            positions[i3 + 2] *= 0.995;
          }

          // Wrap around bounds
          if (Math.abs(positions[i3]) > 12) positions[i3] *= -0.5;
          if (Math.abs(positions[i3 + 1]) > 12) positions[i3 + 1] *= -0.5;
          if (Math.abs(positions[i3 + 2]) > 8) positions[i3 + 2] *= -0.5;

          // Color
          if (disruptionTimer > 0) {
            colors[i3] = 1.0;
            colors[i3 + 1] = 0.1;
            colors[i3 + 2] = 0.1;
          } else if (convergeTimer > 0) {
            colors[i3] = verdictColor.r * brightMult;
            colors[i3 + 1] = verdictColor.g * brightMult;
            colors[i3 + 2] = verdictColor.b * brightMult;
          } else {
            colors[i3] = 0.2 * brightMult;
            colors[i3 + 1] = 0.5 * brightMult;
            colors[i3 + 2] = 0.9 * brightMult;
          }
        } else {
          positions[i3] = 999;
          positions[i3 + 1] = 999;
          positions[i3 + 2] = 999;
        }
      }

      particles.geometry.attributes.position.needsUpdate = true;
      particles.geometry.attributes.color.needsUpdate = true;
      particles.material.opacity = 0.3 + confidence * 0.5;

      renderer.render(scene, camera);
    },

    resize({ width, height }) {
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    },

    destroy() {
      particles.geometry.dispose();
      particles.material.dispose();
      renderer.dispose();
    },
  };
}
