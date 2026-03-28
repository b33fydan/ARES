/**
 * @nwWrld name AresEvidenceGraph
 * @nwWrld category Data Visualization
 * @nwWrld imports three
 *
 * ARES Evidence Graph — renders the evidence-reasoning chain
 * from an ARES scenario as a live 3D graph.
 *
 * Facts appear as small spheres, colored by source type.
 * Assertions appear as icosahedra, connected to their cited facts.
 * The verdict appears as a central torus, colored by outcome.
 * Miscalibration triggers visual disruptions.
 */

export default AresEvidenceGraph;

function AresEvidenceGraph({ THREE, ctx, canvas }) {
  let scene, camera, renderer;
  let factNodes = new Map();
  let assertionNodes = new Map();
  let edges = [];
  let verdictMesh = null;
  let verdictLight = null;
  let clock = 0;
  let shakeIntensity = 0;
  let cameraBasePos = { x: 0, y: 2, z: 12 };

  const SOURCE_COLORS = {
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

  const VERDICT_COLORS = {
    threat_confirmed: 0xff2244,
    threat_dismissed: 0x2288ff,
    inconclusive: 0xffaa00,
  };

  return {
    construct({ width, height }) {
      scene = new THREE.Scene();
      scene.background = new THREE.Color(0x0a0a0f);

      camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 100);
      camera.position.set(cameraBasePos.x, cameraBasePos.y, cameraBasePos.z);
      camera.lookAt(0, 0, 0);

      renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

      const ambient = new THREE.AmbientLight(0x222233, 0.6);
      scene.add(ambient);

      const point = new THREE.PointLight(0xffffff, 0.8, 50);
      point.position.set(5, 8, 5);
      scene.add(point);
    },

    addFact({ fact_id, entity_type, source_type, source_index, fact_index }) {
      const color = SOURCE_COLORS[source_type] || SOURCE_COLORS.unknown;
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
      const y = (entity_type === 'edge' ? 1.5 : -1.5) + (Math.random() - 0.5);
      const z = fact_index * 0.8 - 4 + (Math.random() - 0.5) * 0.5;
      mesh.position.set(x, y, z);

      mesh.scale.set(0.01, 0.01, 0.01);
      mesh.userData = { targetScale: 1.0, fact_id, source_type };

      scene.add(mesh);
      factNodes.set(fact_id, mesh);
    },

    addAssertion({ assertion_id, cited_fact_ids, confidence }) {
      let cx = 0, cy = 0, cz = 0, count = 0;
      const cited = cited_fact_ids || [];

      cited.forEach((fid) => {
        const node = factNodes.get(fid);
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

      scene.add(mesh);
      assertionNodes.set(assertion_id, mesh);

      cited.forEach((fid) => {
        const factMesh = factNodes.get(fid);
        if (factMesh) {
          const points = [mesh.position.clone(), factMesh.position.clone()];
          const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
          const lineMat = new THREE.LineBasicMaterial({
            color: 0x00ccff,
            transparent: true,
            opacity: Math.max(0.2, confidence),
          });
          const line = new THREE.Line(lineGeo, lineMat);
          scene.add(line);
          edges.push(line);
        }
      });
    },

    showVerdict({ outcome, confidence, correct }) {
      const color = VERDICT_COLORS[outcome] || 0xffffff;
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
      verdictMesh = new THREE.Mesh(geo, mat);
      verdictMesh.position.set(0, 1, 0);
      verdictMesh.userData = { correct, pulse: !correct };
      scene.add(verdictMesh);

      verdictLight = new THREE.PointLight(color, confidence * 2, 15);
      verdictLight.position.set(0, 1, 0);
      scene.add(verdictLight);
    },

    showMiscalibration({ flagged, patterns_triggered, risk_score }) {
      if (!flagged) return;

      shakeIntensity = risk_score * 0.3;

      edges.forEach((line) => {
        line.material.color.setHex(0xff2244);
        setTimeout(() => {
          line.material.color.setHex(0x00ccff);
        }, 800);
      });
    },

    reset() {
      factNodes.forEach((mesh) => {
        mesh.geometry.dispose();
        mesh.material.dispose();
        scene.remove(mesh);
      });
      assertionNodes.forEach((mesh) => {
        mesh.geometry.dispose();
        mesh.material.dispose();
        scene.remove(mesh);
      });
      edges.forEach((line) => {
        line.geometry.dispose();
        line.material.dispose();
        scene.remove(line);
      });
      if (verdictMesh) {
        verdictMesh.geometry.dispose();
        verdictMesh.material.dispose();
        scene.remove(verdictMesh);
        verdictMesh = null;
      }
      if (verdictLight) {
        scene.remove(verdictLight);
        verdictLight = null;
      }
      factNodes.clear();
      assertionNodes.clear();
      edges = [];
      shakeIntensity = 0;
    },

    render() {
      clock += 0.01;

      // Gentle orbit
      const orbitRadius = 12;
      camera.position.x = cameraBasePos.x + Math.sin(clock * 0.3) * 0.5;
      camera.position.y = cameraBasePos.y + Math.sin(clock * 0.2) * 0.3;

      // Shake decay
      if (shakeIntensity > 0.001) {
        camera.position.x += (Math.random() - 0.5) * shakeIntensity;
        camera.position.y += (Math.random() - 0.5) * shakeIntensity;
        shakeIntensity *= 0.95;
      }

      camera.lookAt(0, 0, 0);

      // Animate scale-ups
      factNodes.forEach((mesh) => {
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
          0.2 + Math.sin(clock * 2 + mesh.position.x) * 0.1;
      });

      assertionNodes.forEach((mesh) => {
        if (mesh.scale.x < mesh.userData.targetScale) {
          mesh.scale.multiplyScalar(1.06);
        }
        mesh.rotation.y += 0.005;
      });

      // Verdict pulse if incorrect
      if (verdictMesh && verdictMesh.userData.pulse) {
        const pulse = 0.5 + Math.sin(clock * 4) * 0.3;
        verdictMesh.material.emissiveIntensity = pulse;
      }

      renderer.render(scene, camera);
    },

    resize({ width, height }) {
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    },

    destroy() {
      this.reset();
      renderer.dispose();
    },
  };
}
