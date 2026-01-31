// Biosphere3 - Sensor Activity Monitoring System
// Frontend JavaScript
window.BIOSPHERE_APP_READY = true;
window.BIOSPHERE_DATA_READY = false;

const API_BASE = '/api/Sensors';
const FLEET_TOTAL = 10000;
let allSensors = [];
let filteredSensors = [];
let currentPage = 1;
let includeArchived = false;
let demoMode = false;
let demoTimer = null;
let waveTimer = null;
let liveRefreshTimer = null;
let lastAlertSignature = '';
let rotationAngle = 0;
let threeState = null;
let threeInitAttempts = 0;
const themeClasses = ['theme-arctic', 'theme-deepsea', 'theme-desert', 'theme-ops'];

window.addEventListener('error', (event) => {
    showUiError(`UI error: ${event.message}`);
});

window.addEventListener('unhandledrejection', (event) => {
    showUiError(`UI error: ${event.reason}`);
});

document.addEventListener('DOMContentLoaded', () => {
    try {
    console.log('Biosphere3 initialized');
    setBootStatus('UI initialized. Loading data...');

    // Hello World diagnostic button
    const helloBtn = document.getElementById('helloBtn');
    const helloResult = document.getElementById('helloResult');
    const chatLog = document.getElementById('chatLog');
    const chatInput = document.getElementById('chatInput');
    const chatSend = document.getElementById('chatSend');
    const chatStatus = document.getElementById('chatStatus');
    const chatHistory = [];
    const themeSelect = document.getElementById('themeSelect');
    const missionToggle = document.getElementById('missionToggle');
    const demoToggle = document.getElementById('demoToggle');
    const snapshotBtn = document.getElementById('snapshotBtn');
    const onboardingBtn = document.getElementById('onboardingBtn');
    const onboardingClose = document.getElementById('onboardingClose');
    const onboardingOverlay = document.getElementById('onboardingOverlay');

    const alertBanner = document.getElementById('alertBanner');
    const alertDismiss = document.getElementById('alertDismiss');
    if (alertDismiss && alertBanner) {
        alertDismiss.addEventListener('click', () => {
            alertBanner.style.display = 'none';
        });
    }

    if (helloBtn) {
        helloBtn.addEventListener('click', async () => {
            helloBtn.disabled = true;
            helloBtn.textContent = 'Running diagnostic...';

            try {
                const response = await fetch('/HelloWorld');
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();

                helloResult.style.display = 'block';
                helloResult.innerHTML =
                    `<strong>System:</strong> ${data.system}\n` +
                    `<strong>Timestamp:</strong> ${data.timestamp}\n` +
                    `<strong>Message:</strong> ${data.message}`;
            } catch (err) {
                helloResult.style.display = 'block';
                helloResult.innerHTML = `<span style="color:#ef5350;">Error: ${err.message}</span>`;
            } finally {
                helloBtn.disabled = false;
                helloBtn.textContent = 'Run Hello World Diagnostic';
            }
        });
    }

    if (chatSend && chatInput && chatLog) {
        chatSend.addEventListener('click', () => sendChat(chatInput, chatSend, chatStatus, chatLog, chatHistory));
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendChat(chatInput, chatSend, chatStatus, chatLog, chatHistory);
            }
        });
    }

    if (themeSelect) {
        themeSelect.addEventListener('change', () => applyTheme(themeSelect.value));
    }

    if (missionToggle) {
        missionToggle.addEventListener('click', () => {
            document.body.classList.toggle('mission-control');
            missionToggle.textContent = document.body.classList.contains('mission-control')
                ? 'Exit Full Screen'
                : 'Full Screen';
        });
    }

    if (demoToggle) {
        demoToggle.addEventListener('click', () => {
            demoMode = !demoMode;
            demoToggle.textContent = demoMode ? 'Stop Demo' : 'Start Demo';
            if (demoMode) {
                stopLiveRefresh();
                startDemoMode();
            } else {
                stopDemoMode();
                loadSensors();
                startLiveRefresh();
            }
        });
    }

    if (snapshotBtn) {
        snapshotBtn.addEventListener('click', exportSnapshot);
    }

    if (onboardingBtn && onboardingOverlay) {
        onboardingBtn.addEventListener('click', () => {
            onboardingOverlay.style.display = 'grid';
        });
    }

    if (onboardingClose && onboardingOverlay) {
        onboardingClose.addEventListener('click', () => {
            onboardingOverlay.style.display = 'none';
        });
    }

    // Load sensor data on page load
    initTableControls();
    loadSensors();
    startLiveRefresh();
    initVisuals();
    } catch (err) {
        setBootStatus(`UI init failed: ${err.message}`);
        console.error(err);
    }
});

// ── Load and Render Sensors ──────────────────────────────────────

async function loadSensors() {
    const container = document.getElementById('sensorTableContainer');
    window.BIOSPHERE_DATA_READY = false;
    try {
        if (window.__SENSOR_BOOTSTRAP_PROMISE) {
            try {
                const preload = await window.__SENSOR_BOOTSTRAP_PROMISE;
                if (Array.isArray(preload) && preload.length) {
                    window.__SERVER_SENSORS = preload;
                }
            } catch (err) {
                // Ignore preload errors; fallback to direct fetch below.
            }
        }

        if (Array.isArray(window.__SERVER_SENSORS) && window.__SERVER_SENSORS.length) {
            allSensors = window.__SERVER_SENSORS;
            window.__SERVER_SENSORS = null;
        } else {
            const response = await fetch(`${API_BASE}?includeArchived=${includeArchived}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            allSensors = await response.json();
        }

        window.BIOSPHERE_DATA_READY = true;

        if (allSensors.length === 0) {
            container.innerHTML = '<p class="placeholder-text">No sensors found in the database.</p>';
            updateKpis([]);
            updateAlertBanner([]);
            return;
        }

        populateTypeFilter(allSensors);
        applyFilters();
        updateKpis(allSensors);
        updateAlertBanner(allSensors);
        updateLastIngest(allSensors);
        updateStory(allSensors);
        updateThreeSensors(allSensors);
        updateMiniMap(allSensors);
        if (!threeState || !threeState.ready) {
            renderBiosphereMap2D(allSensors);
        }
        renderSensorChips(allSensors);
        setBootStatus(`Data loaded. ${allSensors.length} sensors. Live refresh on.`);
    } catch (err) {
        window.BIOSPHERE_DATA_READY = false;
        container.innerHTML = `<p style="color:#ef5350;">Failed to load sensors: ${err.message}</p>`;
        setBootStatus(`Data load failed: ${err.message}`);
    }
}

function initTableControls() {
    const searchInput = document.getElementById('searchInput');
    const statusFilter = document.getElementById('statusFilter');
    const typeFilter = document.getElementById('typeFilter');
    const sortSelect = document.getElementById('sortSelect');
    const pageSize = document.getElementById('pageSize');
    const showArchived = document.getElementById('showArchived');
    const exportCsv = document.getElementById('exportCsv');
    const exportJson = document.getElementById('exportJson');
    const importJson = document.getElementById('importJson');
    const prevPage = document.getElementById('prevPage');
    const nextPage = document.getElementById('nextPage');

    [searchInput, statusFilter, typeFilter, sortSelect, pageSize].forEach((el) => {
        if (el) {
            el.addEventListener('input', () => {
                currentPage = 1;
                applyFilters();
            });
        }
    });

    if (showArchived) {
        showArchived.addEventListener('change', () => {
            includeArchived = showArchived.value === 'true';
            currentPage = 1;
            loadSensors();
        });
    }

    if (exportCsv) exportCsv.addEventListener('click', exportToCsv);
    if (exportJson) exportJson.addEventListener('click', exportToJson);
    if (importJson) {
        importJson.addEventListener('change', async (e) => {
            const files = e.target.files;
            const file = files && files.length ? files[0] : null;
            if (!file) return;
            await importFromJson(file);
            e.target.value = '';
        });
    }

    if (prevPage) {
        prevPage.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage -= 1;
                renderTable();
            }
        });
    }

    if (nextPage) {
        nextPage.addEventListener('click', () => {
            const totalPages = getTotalPages();
            if (currentPage < totalPages) {
                currentPage += 1;
                renderTable();
            }
        });
    }
}

function populateTypeFilter(sensors) {
    const typeFilter = document.getElementById('typeFilter');
    if (!typeFilter) return;

    const types = [...new Set(sensors.map((s) => s.type).filter(Boolean))].sort();
    const current = typeFilter.value;
    typeFilter.innerHTML = '<option value="">All Types</option>';
    types.forEach((type) => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type;
        typeFilter.appendChild(option);
    });
    typeFilter.value = current;
}

function applyFilters() {
    const searchInput = document.getElementById('searchInput');
    const statusFilter = document.getElementById('statusFilter');
    const typeFilter = document.getElementById('typeFilter');
    const sortSelect = document.getElementById('sortSelect');

    const search = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const status = statusFilter ? statusFilter.value : '';
    const type = typeFilter ? typeFilter.value : '';
    const sortBy = sortSelect ? sortSelect.value : 'id';

    filteredSensors = allSensors.filter((s) => {
        const matchesSearch = !search ||
            s.name.toLowerCase().includes(search) ||
            s.location.toLowerCase().includes(search) ||
            s.type.toLowerCase().includes(search);
        const matchesStatus = !status || s.status === status;
        const matchesType = !type || s.type === type;
        return matchesSearch && matchesStatus && matchesType;
    });

    filteredSensors.sort((a, b) => {
        if (sortBy === 'name') return a.name.localeCompare(b.name);
        if (sortBy === 'status') return a.status.localeCompare(b.status);
        if (sortBy === 'distance') {
            const da = Math.sqrt(a.posX ** 2 + a.posY ** 2 + a.posZ ** 2);
            const db = Math.sqrt(b.posX ** 2 + b.posY ** 2 + b.posZ ** 2);
            return da - db;
        }
        if (sortBy === 'lastUpdated') return new Date(b.lastUpdated) - new Date(a.lastUpdated);
        return a.id - b.id;
    });

    renderTable();
}

function renderTable() {
    const container = document.getElementById('sensorTableContainer');
    if (!container) return;

    if (filteredSensors.length === 0) {
        container.innerHTML = '<p class="placeholder-text">No sensors match the current filters.</p>';
        updatePagination();
        return;
    }

    const pageSize = getPageSize();
    const start = (currentPage - 1) * pageSize;
    const pageItems = filteredSensors.slice(start, start + pageSize);

    let html = `
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Location</th>
                    <th>Type</th>
                    <th>Reading</th>
                    <th>Unit</th>
                    <th>Status</th>
                    <th>Last Updated</th>
                    <th>3D Position</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>`;

    for (const s of pageItems) {
        const updated = new Date(s.lastUpdated).toLocaleString();
        const chipClass = s.isArchived ? 'chip-archived' :
                          s.status === 'Online' ? 'chip-online' :
                          s.status === 'Warning' ? 'chip-warning' : 'chip-offline';
        const chipLabel = s.isArchived ? 'Archived' : s.status;

        html += `
            <tr>
                <td>${s.id}</td>
                <td>${escapeHtml(s.name)}</td>
                <td>${escapeHtml(s.location)}</td>
                <td>${escapeHtml(s.type)}</td>
                <td>${s.lastReading}</td>
                <td>${escapeHtml(s.unit)}</td>
                <td><span class="status-chip ${chipClass}">${escapeHtml(chipLabel)}</span></td>
                <td>${updated}</td>
                <td>(${formatCoord(s.posX)}, ${formatCoord(s.posY)}, ${formatCoord(s.posZ)})</td>
                <td>
                    ${s.isArchived
                        ? `<button class="btn-secondary" onclick="restoreSensor(${s.id})">Restore</button>`
                        : `<button class="btn-edit" onclick='openEditModal(${JSON.stringify(s)})'>Edit</button>
                           <button class="btn-danger" onclick="archiveSensor(${s.id})">Archive</button>`}
                </td>
            </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;
    updatePagination();
    updateThreeSensors(filteredSensors);
    updateMiniMap(filteredSensors);
    renderSensorChips(filteredSensors);
}

function updatePagination() {
    const pageInfo = document.getElementById('pageInfo');
    const totalPages = getTotalPages();
    if (pageInfo) pageInfo.textContent = `Page ${Math.min(currentPage, totalPages)} of ${totalPages}`;
}

function getPageSize() {
    const pageSize = document.getElementById('pageSize');
    return pageSize ? parseInt(pageSize.value, 10) || 10 : 10;
}

function getTotalPages() {
    const size = getPageSize();
    return Math.max(1, Math.ceil(filteredSensors.length / size));
}

function updateKpis(sensors) {
    const alerts = sensors.filter((s) => !s.isArchived && (s.status === 'Warning' || s.status === 'Offline'));
    const online = sensors.filter((s) => s.status === 'Online' && !s.isArchived).length;
    const offline = sensors.filter((s) => s.status === 'Offline' && !s.isArchived).length;
    const warning = sensors.filter((s) => s.status === 'Warning' && !s.isArchived).length;
    const locations = new Set(sensors.map((s) => s.location)).size;
    const types = new Set(sensors.map((s) => s.type)).size;

    setText('fleetTotalValue', `${online} / ${FLEET_TOTAL.toLocaleString()}`);
    setText('kpiAlerts', alerts.length);
    setText('kpiOffline', offline);
    setText('kpiWarning', warning);
    setText('kpiLocations', locations);
    setText('kpiTypes', types);

    const headerStatus = document.getElementById('headerStatus');
    if (headerStatus) {
        headerStatus.textContent = alerts.length > 0 ? 'Degraded' : 'Operational';
        headerStatus.classList.toggle('online', alerts.length === 0);
    }
}

function updateAlertBanner(sensors) {
    const alertBanner = document.getElementById('alertBanner');
    const alertText = document.getElementById('alertText');
    if (!alertBanner || !alertText) return;

    const offline = sensors.filter((s) => s.status === 'Offline' && !s.isArchived).length;
    const warning = sensors.filter((s) => s.status === 'Warning' && !s.isArchived).length;
    if (offline + warning === 0) {
        alertBanner.style.display = 'none';
        alertBanner.classList.remove('alert-pulse');
        return;
    }

    alertText.textContent = `${offline} offline, ${warning} warning — investigate affected sensors.`;
    alertBanner.style.display = 'flex';
    alertBanner.classList.add('alert-pulse');
    speakAlertIfNeeded(offline, warning);
}

function updateLastIngest(sensors) {
    const lastIngest = document.getElementById('lastIngest');
    if (!lastIngest || sensors.length === 0) return;
    const latest = sensors.reduce((acc, s) => {
        const dt = new Date(s.lastUpdated);
        return dt > acc ? dt : acc;
    }, new Date(sensors[0].lastUpdated));
    lastIngest.textContent = latest.toLocaleString();
}

function initVisuals() {
    applyTheme('ops');
    initMiniMapEvents();
    initThreeScene();
    startWaveforms();
}

function applyTheme(theme) {
    document.body.classList.remove(...themeClasses);
    if (theme === 'arctic') document.body.classList.add('theme-arctic');
    if (theme === 'deepsea') document.body.classList.add('theme-deepsea');
    if (theme === 'desert') document.body.classList.add('theme-desert');
}

function speakAlertIfNeeded(offline, warning) {
    const signature = `${offline}-${warning}`;
    if (signature === lastAlertSignature) return;
    lastAlertSignature = signature;
    if (offline + warning === 0) return;
    if (!window.speechSynthesis) return;
    const msg = new SpeechSynthesisUtterance(
        `Alert. ${offline} offline sensors and ${warning} warning sensors detected.`
    );
    msg.rate = 1.0;
    msg.pitch = 1.0;
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(msg);
}

async function exportSnapshot() {
    if (!window.html2canvas) {
        alert('Snapshot failed: html2canvas not available.');
        return;
    }
    const main = document.querySelector('main');
    if (!main) return;
    const canvas = await window.html2canvas(main, { backgroundColor: null, scale: 2 });
    const link = document.createElement('a');
    link.download = 'biosphere3-snapshot.png';
    link.href = canvas.toDataURL('image/png');
    link.click();
}

function startDemoMode() {
    stopDemoMode();
    demoTimer = setInterval(() => {
        if (!allSensors.length) return;
        for (const sensor of allSensors) {
            const roll = Math.random();
            if (roll < 0.02) sensor.status = 'Offline';
            else if (roll < 0.08) sensor.status = 'Warning';
            else sensor.status = 'Online';
            sensor.lastReading = Math.max(0, sensor.lastReading + (Math.random() - 0.5) * 2);
            sensor.lastUpdated = new Date().toISOString();
        }
        applyFilters();
        updateKpis(allSensors);
        updateAlertBanner(allSensors);
        updateLastIngest(allSensors);
        updateStory(allSensors);
    }, 1200);
}

function startLiveRefresh() {
    if (liveRefreshTimer) clearInterval(liveRefreshTimer);
    liveRefreshTimer = setInterval(() => {
        if (!demoMode) loadSensors();
    }, 10000);
}

function stopLiveRefresh() {
    if (liveRefreshTimer) clearInterval(liveRefreshTimer);
    liveRefreshTimer = null;
}

function stopDemoMode() {
    if (demoTimer) clearInterval(demoTimer);
    demoTimer = null;
}

function updateThreeSensors(sensors) {
    if (!threeState || !threeState.ready) return;
    const { THREE, sensorInstances, sensorGroup, sensorMap, statusMaterials } = threeState;

    if (sensorInstances) {
        const statusColors = {
            Online: new THREE.Color(0x22c55e),
            Warning: new THREE.Color(0xfbbf24),
            Offline: new THREE.Color(0xef4444)
        };
        const dummy = new THREE.Object3D();
        const count = Math.min(sensors.length, sensorInstances.count);
        for (let i = 0; i < count; i++) {
            const sensor = sensors[i];
            const pos = mapSensorTo3D(sensor);
            dummy.position.copy(pos);
            dummy.scale.set(1, 1, 1);
            dummy.updateMatrix();
            sensorInstances.setMatrixAt(i, dummy.matrix);
            const status = sensor.status || 'Online';
            sensorInstances.setColorAt(i, statusColors[status] || statusColors.Online);
        }
        // Hide unused instances by scaling to zero
        for (let i = count; i < sensorInstances.count; i++) {
            dummy.position.set(0, -100, 0);
            dummy.scale.set(0, 0, 0);
            dummy.updateMatrix();
            sensorInstances.setMatrixAt(i, dummy.matrix);
        }
        sensorInstances.instanceMatrix.needsUpdate = true;
        if (sensorInstances.instanceColor) sensorInstances.instanceColor.needsUpdate = true;
        sensorInstances._activeCount = count;
        return;
    }

    // Legacy fallback (individual meshes)
    const activeIds = new Set();
    sensors.forEach((sensor) => {
        activeIds.add(sensor.id);
        let mesh = sensorMap.get(sensor.id);
        if (!mesh) {
            const geometry = new THREE.SphereGeometry(0.6, 8, 8);
            const material = statusMaterials.Online.clone();
            mesh = new THREE.Mesh(geometry, material);
            mesh.userData = { id: sensor.id };
            sensorGroup.add(mesh);
            sensorMap.set(sensor.id, mesh);
        }
        const status = sensor.status || 'Online';
        mesh.material.color.set((statusMaterials[status] ? statusMaterials[status].color : statusMaterials.Online.color));
        mesh.position.copy(mapSensorTo3D(sensor));
    });

    for (const [id, mesh] of sensorMap.entries()) {
        if (!activeIds.has(id)) {
            sensorGroup.remove(mesh);
            sensorMap.delete(id);
        }
    }
}

function initThreeScene() {
    const container = document.getElementById('biosphere3d');
    if (!container) return;

    const THREE = window.THREE;
    const OrbitControls = window.THREE && window.THREE.OrbitControls;
    if (!THREE || !OrbitControls) {
        threeInitAttempts++;
        if (threeInitAttempts > 3) {
            renderBiosphereMap2D(allSensors);
            const reason = !window.THREE ? 'Three.js not loaded.' : 'OrbitControls not loaded.';
            setBootStatus(`3D renderer unavailable after ${threeInitAttempts} attempts. ${reason}`);
            return;
        }
        loadThreeScripts().then(() => initThreeScene()).catch(() => {
            renderBiosphereMap2D(allSensors);
            const reason = !window.THREE ? 'Three.js not loaded.' : 'OrbitControls not loaded.';
            setBootStatus(`3D renderer unavailable. ${reason}`);
        });
        return;
    }

    const scene = new THREE.Scene();
    scene.background = new THREE.Color('#0b1220');

    const width = container.clientWidth;
    const height = container.clientHeight;
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 500);
    camera.position.set(0, 40, 70);

    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(window.devicePixelRatio || 1);
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.target.set(0, 4, 5);
    controls.minDistance = 25;
    controls.maxDistance = 160;
    controls.maxPolarAngle = Math.PI / 2.1;

    const grid = new THREE.GridHelper(120, 40, 0x38bdf8, 0x1f2a3a);
    grid.position.y = 0;
    scene.add(grid);

    const ambient = new THREE.AmbientLight(0x94a3b8, 0.7);
    scene.add(ambient);
    const dir = new THREE.DirectionalLight(0xffffff, 0.9);
    dir.position.set(20, 30, 10);
    scene.add(dir);
    const fill = new THREE.DirectionalLight(0x7dd3fc, 0.4);
    fill.position.set(-20, 10, -30);
    scene.add(fill);

    const sensorGroup = new THREE.Group();
    scene.add(sensorGroup);

    const statusMaterials = {
        Online: new THREE.MeshStandardMaterial({ color: 0x22c55e }),
        Warning: new THREE.MeshStandardMaterial({ color: 0xfbbf24 }),
        Offline: new THREE.MeshStandardMaterial({ color: 0xef4444 })
    };

    addBiosphereStructures(THREE, scene);
    addBiomePlates(THREE, scene);
    addBiomeLabels(THREE, scene);

    // InstancedMesh for 10k sensors (single draw call)
    let sensorInstances = null;
    try {
        const instanceGeom = new THREE.SphereGeometry(0.6, 8, 8);
        const instanceMat = new THREE.MeshStandardMaterial({ color: 0x22c55e });
        sensorInstances = new THREE.InstancedMesh(instanceGeom, instanceMat, 12000);
        sensorInstances.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        sensorInstances.instanceColor = new THREE.InstancedBufferAttribute(
            new Float32Array(12000 * 3), 3
        );
        sensorInstances.instanceColor.setUsage(THREE.DynamicDrawUsage);
        // Initialize all instances off-screen
        const dummy = new THREE.Object3D();
        dummy.position.set(0, -100, 0);
        dummy.scale.set(0, 0, 0);
        dummy.updateMatrix();
        for (let i = 0; i < 12000; i++) {
            sensorInstances.setMatrixAt(i, dummy.matrix);
        }
        sensorInstances.instanceMatrix.needsUpdate = true;
        sensorInstances._activeCount = 0;
        scene.add(sensorInstances);
    } catch (e) {
        console.warn('InstancedMesh not available, falling back to individual meshes', e);
        sensorInstances = null;
    }

    threeState = {
        THREE,
        scene,
        camera,
        renderer,
        controls,
        sensorGroup,
        sensorInstances,
        sensorMap: new Map(),
        statusMaterials,
        ready: true
    };

    const resizeObserver = new ResizeObserver(() => {
        const w = container.clientWidth;
        const h = container.clientHeight;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
    });
    resizeObserver.observe(container);

    const animate = () => {
        controls.update();
        pulseSensors(sensorGroup);
        renderer.render(scene, camera);
        requestAnimationFrame(animate);
    };
    animate();

    updateThreeSensors(filteredSensors.length ? filteredSensors : allSensors);
}

function loadThreeScripts() {
    if (window.THREE && window.THREE.OrbitControls) return Promise.resolve();
    const scripts = [
        'https://cdn.jsdelivr.net/npm/three@0.147.0/build/three.min.js',
        'https://cdn.jsdelivr.net/npm/three@0.147.0/examples/js/controls/OrbitControls.js'
    ];
    return scripts.reduce((promise, src) => {
        return promise.then(() => loadScriptOnce(src));
    }, Promise.resolve());
}

function loadScriptOnce(src) {
    return new Promise((resolve, reject) => {
        const existing = document.querySelector(`script[src="${src}"], script[src^="${src.split('?')[0]}"]`);
        if (existing) {
            // Script tag exists — check if the library it provides actually loaded
            if (src.includes('three.min') && window.THREE) { resolve(); return; }
            if (src.includes('OrbitControls') && window.THREE && window.THREE.OrbitControls) { resolve(); return; }
            // Tag exists but library didn't load — remove and re-add
            existing.remove();
        }
        const script = document.createElement('script');
        script.src = src;
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`Failed to load ${src}`));
        document.head.appendChild(script);
    });
}

function projectBlueprintDepth(x, y, z, width, height) {
    const cx = width / 2;
    const cy = height / 2;
    const depth = 1 / (1 + (z + 10) / 35);
    const dx = (x - cx) * (depth - 1) * 0.2;
    const dy = (y - cy) * (depth - 1) * 0.2;
    return {
        x: x + dx,
        y: y + dy
    };
}

function drawBlueprintGrid(ctx, w, h) {
    ctx.save();
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.12)';
    ctx.lineWidth = 1;
    const step = 30;
    for (let x = 0; x <= w; x += step) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
    }
    for (let y = 0; y <= h; y += step) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    ctx.strokeStyle = 'rgba(56, 189, 248, 0.28)';
    ctx.lineWidth = 1.5;
    for (let x = 0; x <= w; x += step * 5) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
    }
    for (let y = 0; y <= h; y += step * 5) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    ctx.fillStyle = 'rgba(148, 163, 184, 0.6)';
    ctx.font = '12px Segoe UI';
    ctx.fillText('NORTH', 12, 16);
    ctx.fillText('EAST', w - 48, h - 12);
    ctx.restore();
}

function drawBlueprintNode(ctx, x, y, radius, status, clustered) {
    const glow = status === 'Offline' ? 'rgba(239,68,68,0.35)' :
        status === 'Warning' ? 'rgba(251,191,36,0.35)' : 'rgba(34,197,94,0.3)';
    const fill = statusColor(status, clustered);
    ctx.save();
    ctx.beginPath();
    ctx.fillStyle = glow;
    ctx.arc(x, y, radius + 6, 0, Math.PI * 2);
    ctx.fill();

    ctx.beginPath();
    ctx.fillStyle = fill;
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = 'rgba(226,232,240,0.5)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(x, y, radius + 2, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();
}

function drawBiomeZones(ctx, w, h) {
    const zones = getBiomeZones();
    ctx.save();
    zones.forEach((zone) => {
        const x = zone.x * w;
        const y = zone.y * h;
        const width = zone.w * w;
        const height = zone.h * h;

        ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
        ctx.lineWidth = 1.2;
        ctx.strokeRect(x, y, width, height);

        ctx.fillStyle = 'rgba(56, 189, 248, 0.08)';
        ctx.fillRect(x, y, width, height);

        ctx.fillStyle = 'rgba(148, 163, 184, 0.85)';
        ctx.font = '12px Segoe UI';
        ctx.fillText(zone.label, x + 8, y + 18);
    });
    ctx.restore();
}

function drawBiosphereOutline(ctx, w, h) {
    ctx.save();
    const margin = 18;
    const frameX = margin;
    const frameY = margin + 10;
    const frameW = w - margin * 2;
    const frameH = h - margin * 2 - 10;

    ctx.strokeStyle = 'rgba(56, 189, 248, 0.55)';
    ctx.lineWidth = 2;
    ctx.strokeRect(frameX, frameY, frameW, frameH);

    // Dome arcs (glass biomes)
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.4)';
    ctx.lineWidth = 1.5;
    drawArch(ctx, frameX + frameW * 0.2, frameY + frameH * 0.05, frameW * 0.25, frameH * 0.35);
    drawArch(ctx, frameX + frameW * 0.55, frameY + frameH * 0.05, frameW * 0.25, frameH * 0.35);

    // "Lung" domes
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
    ctx.lineWidth = 1;
    drawCircle(ctx, frameX + frameW * 0.1, frameY + frameH * 0.8, frameW * 0.08);
    drawCircle(ctx, frameX + frameW * 0.9, frameY + frameH * 0.8, frameW * 0.08);

    // Central spine
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.35)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(frameX + frameW * 0.48, frameY);
    ctx.lineTo(frameX + frameW * 0.52, frameY + frameH);
    ctx.stroke();

    ctx.fillStyle = 'rgba(148, 163, 184, 0.7)';
    ctx.font = '11px Segoe UI';
    ctx.fillText('Biomes', frameX + 8, frameY - 6);
    ctx.restore();
}

function drawArch(ctx, x, y, w, h) {
    ctx.beginPath();
    ctx.ellipse(x + w / 2, y + h, w / 2, h, 0, Math.PI, 0, true);
    ctx.stroke();
}

function drawCircle(ctx, x, y, r) {
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.stroke();
}

function getBiomeZones() {
    return [
        { id: 'rainforest', label: 'Rainforest', x: 0.05, y: 0.08, w: 0.32, h: 0.34,
          bounds3d: { xMin: -40, xMax: -20, zMin: -8.5, zMax: 8.5, yMin: 0.5, yMax: 10 } },
        { id: 'ocean', label: 'Ocean', x: 0.38, y: 0.06, w: 0.34, h: 0.26,
          bounds3d: { xMin: -20, xMax: -7, zMin: -6, zMax: 6, yMin: 0.5, yMax: 8 } },
        { id: 'marsh', label: 'Marsh/Mangrove', x: 0.72, y: 0.38, w: 0.23, h: 0.22,
          bounds3d: { xMin: -7, xMax: 3, zMin: -6, zMax: 6, yMin: 0.5, yMax: 8 } },
        { id: 'savanna', label: 'Savanna', x: 0.42, y: 0.36, w: 0.28, h: 0.26,
          bounds3d: { xMin: 3, xMax: 20, zMin: -6, zMax: 6, yMin: 0.5, yMax: 8 } },
        { id: 'desert', label: 'Desert', x: 0.74, y: 0.08, w: 0.21, h: 0.26,
          bounds3d: { xMin: 22, xMax: 38, zMin: -6.5, zMax: 6.5, yMin: 0.5, yMax: 8 } },
        { id: 'agriculture', label: 'Agriculture', x: 0.05, y: 0.48, w: 0.30, h: 0.24,
          bounds3d: { xMin: -22, xMax: -8, zMin: 10, zMax: 24, yMin: 0.5, yMax: 5 } },
        { id: 'habitat', label: 'Human Habitat', x: 0.05, y: 0.76, w: 0.30, h: 0.18,
          bounds3d: { xMin: -10, xMax: 2, zMin: 8, zMax: 16, yMin: 0.5, yMax: 3.5 } }
    ];
}

function computeBlueprintNodes(sensors, w, h) {
    const zones = getBiomeZones();
    return sensors.map((sensor) => {
        const zone = pickBiomeZone(sensor, zones);
        const baseX = zone.x * w + zone.w * w * 0.5;
        const baseY = zone.y * h + zone.h * h * 0.5;
        const jitterX = ((sensor.posX % 10) - 5) / 5 * zone.w * w * 0.35;
        const jitterY = ((sensor.posY % 10) - 5) / 5 * zone.h * h * 0.35;
        return {
            x: baseX + jitterX,
            y: baseY + jitterY,
            z: sensor.posZ,
            status: sensor.status,
            name: sensor.name
        };
    });
}

function pickBiomeZone(sensor, zones) {
    const location = sensor.location.toLowerCase();
    const type = sensor.type.toLowerCase();

    if (location.includes('marine') || type.includes('water') || type.includes('salinity')) {
        return zones.find((z) => z.id === 'ocean');
    }
    if (location.includes('greenhouse') || location.includes('agro') || type.includes('soil')) {
        return zones.find((z) => z.id === 'agriculture');
    }
    if (location.includes('external') || type.includes('wind')) {
        return zones.find((z) => z.id === 'desert');
    }
    if (location.includes('dome a') || type.includes('co2') || type.includes('temperature')) {
        return zones.find((z) => z.id === 'rainforest');
    }
    if (location.includes('dome b') || type.includes('humidity')) {
        return zones.find((z) => z.id === 'savanna');
    }
    if (location.includes('dome c') || type.includes('pressure')) {
        return zones.find((z) => z.id === 'habitat');
    }
    return zones.find((z) => z.id === 'savanna');
}

function clusterNodes(nodes, gridSize) {
    const grid = new Map();
    nodes.forEach((n) => {
        const gx = Math.round(n.x / gridSize);
        const gy = Math.round(n.y / gridSize);
        const gz = Math.round(n.z / 2);
        const key = `${gx}-${gy}-${gz}`;
        const entry = grid.get(key) || { x: 0, y: 0, z: 0, count: 0, statuses: [] };
        entry.x += n.x;
        entry.y += n.y;
        entry.z += n.z;
        entry.count += 1;
        entry.statuses.push(n.status);
        grid.set(key, entry);
    });
    return Array.from(grid.values()).map((entry) => ({
        x: entry.x / entry.count,
        y: entry.y / entry.count,
        z: entry.z / entry.count,
        count: entry.count,
        status: dominantStatus(entry.statuses)
    }));
}

function drawAxes(ctx, w, h) {
    ctx.save();
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.4)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(w * 0.1, h * 0.9);
    ctx.lineTo(w * 0.35, h * 0.75);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(w * 0.1, h * 0.9);
    ctx.lineTo(w * 0.1, h * 0.7);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(w * 0.1, h * 0.9);
    ctx.lineTo(w * 0.25, h * 0.95);
    ctx.stroke();
    ctx.fillStyle = 'rgba(148, 163, 184, 0.8)';
    ctx.font = '11px Segoe UI';
    ctx.fillText('X', w * 0.36, h * 0.75);
    ctx.fillText('Y', w * 0.09, h * 0.68);
    ctx.fillText('Z', w * 0.25, h * 0.98);
    ctx.restore();
}

function buildPyramid(THREE, glassMat, frameMat, opts) {
    const { baseX, baseZ, height, px, py, pz } = opts;
    const group = new THREE.Group();
    const geom = new THREE.ConeGeometry(1, height, 4);
    geom.scale(baseX / 2, 1, baseZ / 2);
    geom.rotateY(Math.PI / 4);
    const mesh = new THREE.Mesh(geom, glassMat);
    mesh.position.set(0, height / 2, 0);
    group.add(mesh);
    const edges = new THREE.EdgesGeometry(geom);
    const lines = new THREE.LineSegments(edges, frameMat);
    lines.position.copy(mesh.position);
    group.add(lines);
    group.position.set(px, py, pz);
    return group;
}

function buildBarrelVault(THREE, glassMat, frameMat, opts) {
    const { radius, length, px, py, pz } = opts;
    const group = new THREE.Group();
    const geom = new THREE.CylinderGeometry(radius, radius, length, 32, 1, true, 0, Math.PI);
    geom.rotateZ(Math.PI / 2);
    const mesh = new THREE.Mesh(geom, glassMat);
    mesh.position.set(0, radius, 0);
    group.add(mesh);
    const edges = new THREE.EdgesGeometry(geom, 15);
    const lines = new THREE.LineSegments(edges, frameMat);
    lines.position.copy(mesh.position);
    group.add(lines);
    // End caps
    const capGeom = new THREE.CircleGeometry(radius, 32, 0, Math.PI);
    const capL = new THREE.Mesh(capGeom, glassMat);
    capL.rotation.y = Math.PI / 2;
    capL.position.set(-length / 2, radius, 0);
    group.add(capL);
    const capR = new THREE.Mesh(capGeom, glassMat);
    capR.rotation.y = -Math.PI / 2;
    capR.position.set(length / 2, radius, 0);
    group.add(capR);
    group.position.set(px, py, pz);
    return group;
}

function buildAgricultureWing(THREE, glassMat, frameMat, opts) {
    const { px, py, pz, length, width } = opts;
    const group = new THREE.Group();
    const vaultRadius = 2.5;
    const spacing = width / 3;
    for (let i = 0; i < 3; i++) {
        const offsetZ = (i - 1) * spacing;
        const geom = new THREE.CylinderGeometry(vaultRadius, vaultRadius, length, 16, 1, true, 0, Math.PI);
        geom.rotateX(Math.PI / 2);
        const mesh = new THREE.Mesh(geom, glassMat);
        mesh.position.set(0, vaultRadius, offsetZ);
        group.add(mesh);
        const edges = new THREE.EdgesGeometry(geom, 15);
        const lines = new THREE.LineSegments(edges, frameMat);
        lines.position.copy(mesh.position);
        group.add(lines);
    }
    group.position.set(px, py, pz);
    return group;
}

function buildHabitatBlock(THREE, solidMat, frameMat, opts) {
    const { sx, sy, sz, px, py, pz } = opts;
    const group = new THREE.Group();
    const geom = new THREE.BoxGeometry(sx, sy, sz);
    const mesh = new THREE.Mesh(geom, solidMat);
    mesh.position.set(0, sy / 2, 0);
    group.add(mesh);
    const edges = new THREE.EdgesGeometry(geom);
    const lines = new THREE.LineSegments(edges, frameMat);
    lines.position.copy(mesh.position);
    group.add(lines);
    group.position.set(px, py, pz);
    return group;
}

function buildLungDome(THREE, glassMat, frameMat, opts) {
    const { radius, px, py, pz } = opts;
    const group = new THREE.Group();
    const geom = new THREE.SphereGeometry(radius, 12, 8, 0, Math.PI * 2, 0, Math.PI / 2);
    const mesh = new THREE.Mesh(geom, glassMat);
    group.add(mesh);
    const wire = new THREE.WireframeGeometry(geom);
    const lines = new THREE.LineSegments(wire, frameMat);
    group.add(lines);
    group.position.set(px, py, pz);
    return group;
}

function buildTunnel(THREE, material, from, to) {
    const dir = new THREE.Vector3().subVectors(to, from);
    const length = dir.length();
    const geom = new THREE.CylinderGeometry(1.2, 1.2, length, 8, 1, true);
    const mesh = new THREE.Mesh(geom, material);
    const mid = new THREE.Vector3().addVectors(from, to).multiplyScalar(0.5);
    mesh.position.copy(mid);
    mesh.lookAt(to);
    mesh.rotateX(Math.PI / 2);
    return mesh;
}

function createTextSprite(THREE, text) {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = 'rgba(0,0,0,0)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = 'bold 28px Segoe UI, sans-serif';
    ctx.fillStyle = '#94a3b8';
    ctx.textAlign = 'center';
    ctx.fillText(text, 128, 40);
    const texture = new THREE.CanvasTexture(canvas);
    texture.needsUpdate = true;
    const mat = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false });
    const sprite = new THREE.Sprite(mat);
    sprite.scale.set(10, 2.5, 1);
    return sprite;
}

function addBiomeLabels(THREE, scene) {
    const zones = getBiomeZones();
    zones.forEach((zone) => {
        const b = zone.bounds3d;
        const cx = (b.xMin + b.xMax) / 2;
        const cz = (b.zMin + b.zMax) / 2;
        const top = b.yMax + 1.5;
        const sprite = createTextSprite(THREE, zone.label);
        sprite.position.set(cx, top, cz);
        scene.add(sprite);
    });
}

function addBiosphereStructures(THREE, scene) {
    const glassMat = new THREE.MeshPhysicalMaterial({
        color: 0x38bdf8,
        transmission: 0.75,
        opacity: 0.15,
        transparent: true,
        roughness: 0.1,
        metalness: 0.0,
        depthWrite: false
    });
    const frameMat = new THREE.LineBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0.35
    });
    const solidMat = new THREE.MeshStandardMaterial({
        color: 0x1f2a3a,
        transparent: true,
        opacity: 0.85
    });
    const undergroundMat = new THREE.MeshStandardMaterial({
        color: 0x1a1a2e,
        transparent: true,
        opacity: 0.5
    });

    // Rainforest pyramid (west end)
    scene.add(buildPyramid(THREE, glassMat, frameMat, {
        baseX: 20, baseZ: 17, height: 13.85, px: -30, py: 0, pz: 0
    }));

    // Central barrel vault (main axis)
    scene.add(buildBarrelVault(THREE, glassMat, frameMat, {
        radius: 6.25, length: 40, px: 0, py: 0, pz: 0
    }));

    // Desert pyramid (east end)
    scene.add(buildPyramid(THREE, glassMat, frameMat, {
        baseX: 16, baseZ: 13, height: 11, px: 30, py: 0, pz: 0
    }));

    // Agriculture wing (south, three parallel vaults)
    scene.add(buildAgricultureWing(THREE, glassMat, frameMat, {
        px: -15, py: 0, pz: 17, length: 14, width: 14
    }));

    // Habitat block (south, opaque)
    scene.add(buildHabitatBlock(THREE, solidMat, frameMat, {
        sx: 12, sy: 4, sz: 8, px: -4, py: 0, pz: 12
    }));

    // Lung dome 1 (southeast)
    scene.add(buildLungDome(THREE, glassMat, frameMat, {
        radius: 6.75, px: 25, py: 0, pz: 22
    }));

    // Lung dome 2 (northwest)
    scene.add(buildLungDome(THREE, glassMat, frameMat, {
        radius: 6.75, px: -38, py: 0, pz: 15
    }));

    // Underground connecting tunnels
    scene.add(buildTunnel(THREE, undergroundMat,
        new THREE.Vector3(20, -1, 0),
        new THREE.Vector3(25, -1, 20)
    ));
    scene.add(buildTunnel(THREE, undergroundMat,
        new THREE.Vector3(-20, -1, 0),
        new THREE.Vector3(-36, -1, 14)
    ));

    // Technosphere slab (underground platform)
    const techGeom = new THREE.BoxGeometry(82, 1.5, 18);
    const techMesh = new THREE.Mesh(techGeom, new THREE.MeshStandardMaterial({
        color: 0x1a1a2e, transparent: true, opacity: 0.6
    }));
    techMesh.position.set(0, -1.25, 0);
    scene.add(techMesh);
}

function addBiomePlates(THREE, scene) {
    const zones = getBiomeZones();
    zones.forEach((zone) => {
        const b = zone.bounds3d;
        const sizeX = b.xMax - b.xMin;
        const sizeZ = b.zMax - b.zMin;
        const cx = (b.xMin + b.xMax) / 2;
        const cz = (b.zMin + b.zMax) / 2;
        const plate = new THREE.Mesh(
            new THREE.PlaneGeometry(sizeX, sizeZ),
            new THREE.MeshStandardMaterial({ color: 0x0b1220, transparent: true, opacity: 0.65 })
        );
        plate.rotation.x = -Math.PI / 2;
        plate.position.set(cx, 0.05, cz);
        scene.add(plate);
    });
}

function mapSensorTo3D(sensor) {
    const zone = pickBiomeZone(sensor, getBiomeZones());
    const b = zone.bounds3d;
    const cx = (b.xMin + b.xMax) / 2;
    const cz = (b.zMin + b.zMax) / 2;
    const spanX = (b.xMax - b.xMin) * 0.7;
    const spanZ = (b.zMax - b.zMin) * 0.7;
    const jitterX = ((sensor.posX % 10) - 5) / 5 * (spanX / 2);
    const jitterZ = ((sensor.posY % 10) - 5) / 5 * (spanZ / 2);
    const height = Math.max(b.yMin, Math.min(b.yMax, sensor.posZ * 0.3 + (b.yMin + b.yMax) / 2));
    return new threeState.THREE.Vector3(cx + jitterX, height, cz + jitterZ);
}

function pulseSensors(group) {
    const now = Date.now() * 0.002;
    // InstancedMesh pulse: scale the whole mesh subtly
    if (threeState && threeState.sensorInstances) {
        const scale = 1 + Math.sin(now) * 0.03;
        threeState.sensorInstances.scale.set(scale, scale, scale);
        return;
    }
    // Legacy fallback: pulse individual meshes
    group.children.forEach((mesh, idx) => {
        const scale = 1 + Math.sin(now + idx) * 0.05;
        mesh.scale.set(scale, scale, scale);
    });
}

function clusterSensors(sensors, gridSize) {
    const grid = new Map();
    sensors.forEach((s) => {
        const gx = Math.round(s.posX / gridSize);
        const gy = Math.round(s.posY / gridSize);
        const gz = Math.round(s.posZ / gridSize);
        const key = `${gx}-${gy}-${gz}`;
        const entry = grid.get(key) || { x: 0, y: 0, z: 0, count: 0, statuses: [] };
        entry.x += s.posX;
        entry.y += s.posY;
        entry.z += s.posZ;
        entry.count += 1;
        entry.statuses.push(s.status);
        grid.set(key, entry);
    });
    return Array.from(grid.values()).map((entry) => ({
        x: entry.x / entry.count,
        y: entry.y / entry.count,
        z: entry.z / entry.count,
        count: entry.count,
        status: dominantStatus(entry.statuses)
    }));
}

function dominantStatus(statuses) {
    if (statuses.includes('Offline')) return 'Offline';
    if (statuses.includes('Warning')) return 'Warning';
    return 'Online';
}

function statusColor(status, clustered) {
    if (status === 'Offline') return clustered ? 'rgba(239,68,68,0.8)' : '#ef4444';
    if (status === 'Warning') return clustered ? 'rgba(251,191,36,0.8)' : '#fbbf24';
    return clustered ? 'rgba(34,197,94,0.8)' : '#22c55e';
}

function initMiniMapEvents() {
    const miniMap = document.getElementById('miniMap');
    const tooltip = document.getElementById('miniMapTooltip');
    if (!miniMap || !tooltip) return;

    miniMap.addEventListener('mousemove', (e) => {
        const rect = miniMap.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const nearest = findNearestMiniMapSensor(x, y, miniMap.width, miniMap.height);
        if (nearest) {
            tooltip.style.display = 'block';
            tooltip.textContent = `${nearest.name} (${nearest.status})`;
        } else {
            tooltip.style.display = 'none';
        }
    });
    miniMap.addEventListener('mouseleave', () => {
        tooltip.style.display = 'none';
    });
}

function updateMiniMap(sensors) {
    const miniMap = document.getElementById('miniMap');
    if (!miniMap) return;
    const ctx = miniMap.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, miniMap.width, miniMap.height);
    ctx.fillStyle = '#0b1220';
    ctx.fillRect(0, 0, miniMap.width, miniMap.height);
    const nodes = computeBlueprintNodes(sensors, miniMap.width, miniMap.height);
    nodes.forEach((n) => {
        ctx.fillStyle = statusColor(n.status, false);
        ctx.beginPath();
        ctx.arc(n.x, n.y, 3, 0, Math.PI * 2);
        ctx.fill();
    });
    miniMap._sensorCache = nodes;
}

function renderBiosphereMap2D(sensors) {
    const target = document.getElementById('biosphere3d');
    if (!target) return;
    const canvas = document.createElement('canvas');
    canvas.width = target.clientWidth || 600;
    canvas.height = target.clientHeight || 360;
    target.innerHTML = '';
    target.appendChild(canvas);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.fillStyle = '#0b0f16';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.18)';
    ctx.lineWidth = 1;
    for (let gx = 0; gx <= canvas.width; gx += 40) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, canvas.height);
        ctx.stroke();
    }
    for (let gy = 0; gy <= canvas.height; gy += 40) {
        ctx.beginPath();
        ctx.moveTo(0, gy);
        ctx.lineTo(canvas.width, gy);
        ctx.stroke();
    }

    ctx.strokeStyle = 'rgba(45, 212, 191, 0.55)';
    ctx.fillStyle = 'rgba(45, 212, 191, 0.12)';
    ctx.beginPath();
    ctx.ellipse(canvas.width * 0.28, canvas.height * 0.42, 90, 70, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    ctx.beginPath();
    ctx.ellipse(canvas.width * 0.62, canvas.height * 0.45, 80, 60, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    ctx.beginPath();
    ctx.ellipse(canvas.width * 0.72, canvas.height * 0.65, 60, 46, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    ctx.strokeStyle = 'rgba(56, 189, 248, 0.55)';
    ctx.fillStyle = 'rgba(15, 23, 42, 0.6)';
    ctx.fillRect(canvas.width * 0.42, canvas.height * 0.62, 140, 54);
    ctx.strokeRect(canvas.width * 0.42, canvas.height * 0.62, 140, 54);

    ctx.fillStyle = 'rgba(14, 165, 233, 0.6)';
    ctx.beginPath();
    ctx.arc(canvas.width * 0.46, canvas.height * 0.50, 12, 0, Math.PI * 2);
    ctx.fill();

    (sensors || []).forEach((s) => {
        const x = (s.posX % 50) / 50 * canvas.width;
        const y = (s.posY % 20) / 20 * canvas.height;
        ctx.fillStyle = s.status === 'Offline' ? '#ef4444' : s.status === 'Warning' ? '#fbbf24' : '#22c55e';
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fill();
    });
}


function findNearestMiniMapSensor(x, y, w, h) {
    const miniMap = document.getElementById('miniMap');
    const sensors = (miniMap && miniMap._sensorCache) ? miniMap._sensorCache : [];
    let closest = null;
    let minDist = 12;
    sensors.forEach((s) => {
        const dist = Math.hypot(s.x - x, s.y - y);
        if (dist < minDist) {
            minDist = dist;
            closest = s;
        }
    });
    return closest;
}

function startWaveforms() {
    const waveCanvases = [
        { id: 'waveTemp', label: 'Temperature' },
        { id: 'waveHum', label: 'Humidity' },
        { id: 'wavePres', label: 'Pressure' },
        { id: 'waveSoil', label: 'Soil Moisture' }
    ];
    const series = waveCanvases.map(() => Array(60).fill(0));

    if (waveTimer) clearInterval(waveTimer);
    waveTimer = setInterval(() => {
        waveCanvases.forEach((wave, idx) => {
            const values = getTypeSeriesValue(wave.label);
            series[idx].push(values);
            series[idx].shift();
            drawWaveform(wave.id, series[idx], wave.label);
        });
    }, 800);
}

function getTypeSeriesValue(type) {
    const items = allSensors.filter((s) => s.type.toLowerCase().includes(type.toLowerCase()));
    if (!items.length) return Math.random() * 100;
    const avg = items.reduce((sum, s) => sum + (s.lastReading || 0), 0) / items.length;
    return avg + (Math.random() - 0.5) * 2;
}

function drawWaveform(id, values, label) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#0b1220';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = '#38bdf8';
    ctx.beginPath();
    values.forEach((v, i) => {
        const x = (i / (values.length - 1)) * canvas.width;
        const y = canvas.height - (v % 100) / 100 * canvas.height;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.fillStyle = '#94a3b8';
    ctx.font = '12px Segoe UI';
    ctx.fillText(label, 8, 14);
    drawConnectionStrength(ctx, label, canvas.width, canvas.height);
}

function drawConnectionStrength(ctx, label, w, h) {
    const related = allSensors.filter((s) => s.type.toLowerCase().includes(label.toLowerCase()));
    const strength = related.length ? Math.round(related.reduce((sum, s) => sum + getConnectionStrength(s), 0) / related.length) : 0;
    ctx.fillStyle = '#1f2a3a';
    ctx.fillRect(8, h - 14, 120, 6);
    ctx.fillStyle = strength > 70 ? '#22c55e' : strength > 40 ? '#fbbf24' : '#ef4444';
    ctx.fillRect(8, h - 14, Math.max(6, strength), 6);
    ctx.fillStyle = '#94a3b8';
    ctx.fillText(`Signal ${strength}%`, 136, h - 8);
}

function renderSensorChips(sensors) {
    const container = document.getElementById('sensorChips');
    if (!container) return;
    if (!sensors.length) {
        container.innerHTML = '<p class="placeholder-text">No sensors available.</p>';
        return;
    }

    const chips = sensors.slice(0, 24).map((s) => {
        const statusClass = s.isArchived ? 'chip-archived' :
            s.status === 'Online' ? 'chip-online' : s.status === 'Warning' ? 'chip-warning' : 'chip-offline';
        const frequency = estimateTransmitFrequency(s);
        const strength = getConnectionStrength(s);
        return `
            <div class="sensor-chip">
                <div class="chip-row">
                    <span class="chip-name">${escapeHtml(s.name)}</span>
                    <span class="status-chip ${statusClass}">${escapeHtml(s.isArchived ? 'Archived' : s.status)}</span>
                </div>
                <div class="chip-meta">${escapeHtml(s.type)} · ${escapeHtml(s.location)}</div>
                <div class="chip-meta">Transmit: ${frequency}</div>
                <div class="strength-bar">
                    <div class="strength-fill" style="width:${strength}%;"></div>
                </div>
            </div>
        `;
    });

    container.innerHTML = chips.join('');
}

function estimateTransmitFrequency(sensor) {
    const type = sensor.type.toLowerCase();
    if (type.includes('temperature')) return '1 Hz';
    if (type.includes('humidity')) return '0.5 Hz';
    if (type.includes('pressure')) return '0.2 Hz';
    if (type.includes('soil')) return '0.1 Hz';
    if (type.includes('co2')) return '0.5 Hz';
    if (type.includes('wind')) return '2 Hz';
    return '0.25 Hz';
}

function getConnectionStrength(sensor) {
    const ageMs = Date.now() - new Date(sensor.lastUpdated).getTime();
    let strength = 100;
    if (sensor.status === 'Warning') strength -= 25;
    if (sensor.status === 'Offline') strength -= 60;
    if (ageMs > 60000) strength -= 15;
    if (ageMs > 300000) strength -= 20;
    return Math.max(5, Math.min(100, strength));
}

function updateStory(sensors) {
    const storyText = document.getElementById('storyText');
    if (!storyText) return;
    const online = sensors.filter((s) => s.status === 'Online' && !s.isArchived).length;
    const warning = sensors.filter((s) => s.status === 'Warning' && !s.isArchived).length;
    const offline = sensors.filter((s) => s.status === 'Offline' && !s.isArchived).length;
    const locations = new Set(sensors.map((s) => s.location)).size;
    const types = new Set(sensors.map((s) => s.type)).size;
    const lastIngestEl = document.getElementById('lastIngest');
    const lastIngestText = lastIngestEl ? lastIngestEl.textContent : 'recently';
    storyText.textContent = `Biosphere3 is tracking ${online} online sensors across ${locations} locations and ${types} types. ` +
        `${warning} warning and ${offline} offline sensors require attention. Last ingest recorded ${lastIngestText || 'recently'}.`;
}

// ── Export / Import ───────────────────────────────────────────────

function exportToJson() {
    if (filteredSensors.length === 0) {
        setImportStatus('No records to export.');
        return;
    }
    const payload = JSON.stringify(filteredSensors, null, 2);
    downloadFile('biosphere3-sensors.json', 'application/json', payload);
    setImportStatus(`Exported ${filteredSensors.length} records to JSON.`);
}

function exportToCsv() {
    if (filteredSensors.length === 0) {
        setImportStatus('No records to export.');
        return;
    }
    const header = ['Id', 'Name', 'Location', 'Type', 'LastReading', 'Unit', 'Status', 'LastUpdated', 'IsArchived', 'PosX', 'PosY', 'PosZ'];
    const rows = filteredSensors.map((s) => [
        s.id,
        s.name,
        s.location,
        s.type,
        s.lastReading,
        s.unit,
        s.status,
        s.lastUpdated,
        s.isArchived ? 'true' : 'false',
        s.posX,
        s.posY,
        s.posZ
    ]);
    const csv = [header, ...rows].map((row) => row.map(csvEscape).join(',')).join('\n');
    downloadFile('biosphere3-sensors.csv', 'text/csv', csv);
    setImportStatus(`Exported ${filteredSensors.length} records to CSV.`);
}

async function importFromJson(file) {
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!Array.isArray(data)) {
            setImportStatus('Import failed: JSON must be an array of sensors.');
            return;
        }

        const sanitized = data.map((s) => ({
            name: s.name || s.Name || '',
            location: s.location || s.Location || '',
            type: s.type || s.Type || '',
            lastReading: Number(coalesce(coalesce(s.lastReading, s.LastReading), 0)),
            unit: s.unit || s.Unit || '',
            status: s.status || s.Status || 'Online',
            posX: Number(coalesce(coalesce(s.posX, s.PosX), 0)),
            posY: Number(coalesce(coalesce(s.posY, s.PosY), 0)),
            posZ: Number(coalesce(coalesce(s.posZ, s.PosZ), 0))
        }));

        const response = await fetch(`${API_BASE}/import`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(sanitized)
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `HTTP ${response.status}`);
        }

        const result = await response.json();
        const importedCount = (result && typeof result.imported !== 'undefined') ? result.imported : sanitized.length;
        setImportStatus(`Imported ${importedCount} records.`);
        loadSensors();
    } catch (err) {
        setImportStatus(`Import failed: ${err.message}`);
    }
}

function downloadFile(filename, mime, content) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function csvEscape(value) {
    const str = String(coalesce(value, ''));
    if (str.includes('"') || str.includes(',') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

function formatCoord(value) {
    return Number(coalesce(value, 0)).toFixed(2);
}

function coalesce(value, fallback) {
    return value === null || typeof value === 'undefined' ? fallback : value;
}

// ── Archive / Restore Sensor ─────────────────────────────────────

async function archiveSensor(id) {
    if (!confirm(`Archive sensor #${id}? It will be hidden from default views.`)) return;

    try {
        const response = await fetch(`${API_BASE}/${id}`, { method: 'DELETE' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        loadSensors();
    } catch (err) {
        alert(`Archive failed: ${err.message}`);
    }
}

async function restoreSensor(id) {
    try {
        const response = await fetch(`${API_BASE}/${id}/restore`, { method: 'PATCH' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        loadSensors();
    } catch (err) {
        alert(`Restore failed: ${err.message}`);
    }
}

// ── Edit Modal ───────────────────────────────────────────────────

function openEditModal(sensor) {
    showModal('Edit Sensor', sensor, async (formData) => {
        const response = await fetch(`${API_BASE}/${sensor.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        loadSensors();
    });
}

// ── Add Modal ────────────────────────────────────────────────────

function openAddModal() {
    const blank = { name: '', location: '', type: '', lastReading: 0, unit: '', status: 'Online', posX: 0, posY: 0, posZ: 0 };
    showModal('Add Sensor', blank, async (formData) => {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `HTTP ${response.status}`);
        }
        loadSensors();
    });
}

// ── Shared Modal ─────────────────────────────────────────────────

function showModal(title, sensor, onSave) {
    // Remove any existing modal
    const existing = document.getElementById('sensorModal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'sensorModal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal">
            <h3>${title}</h3>
            <label>Name</label>
            <input id="modalName" value="${escapeAttr(sensor.name)}" placeholder="e.g. ATMO-003" />
            <label>Location</label>
            <input id="modalLocation" value="${escapeAttr(sensor.location)}" placeholder="e.g. Dome B - East Wing" />
            <label>Type</label>
            <input id="modalType" value="${escapeAttr(sensor.type)}" placeholder="e.g. Temperature" />
            <label>Last Reading</label>
            <input id="modalReading" type="number" step="0.01" value="${sensor.lastReading}" />
            <label>Unit</label>
            <input id="modalUnit" value="${escapeAttr(sensor.unit)}" placeholder="e.g. °C, %, ppm" />
            <label>Status</label>
            <select id="modalStatus">
                <option value="Online" ${sensor.status === 'Online' ? 'selected' : ''}>Online</option>
                <option value="Warning" ${sensor.status === 'Warning' ? 'selected' : ''}>Warning</option>
                <option value="Offline" ${sensor.status === 'Offline' ? 'selected' : ''}>Offline</option>
            </select>
            <label>3D Position (X, Y, Z)</label>
            <div class="position-grid">
                <input id="modalPosX" type="number" step="0.01" value="${coalesce(sensor.posX, 0)}" placeholder="X" />
                <input id="modalPosY" type="number" step="0.01" value="${coalesce(sensor.posY, 0)}" placeholder="Y" />
                <input id="modalPosZ" type="number" step="0.01" value="${coalesce(sensor.posZ, 0)}" placeholder="Z" />
            </div>
            <div class="modal-buttons">
                <button class="btn-cancel" onclick="closeModal()">Cancel</button>
                <button class="btn-save" id="modalSaveBtn">Save</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // Close on backdrop click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closeModal();
    });

    document.getElementById('modalSaveBtn').addEventListener('click', async () => {
        const formData = {
            name: document.getElementById('modalName').value.trim(),
            location: document.getElementById('modalLocation').value.trim(),
            type: document.getElementById('modalType').value.trim(),
            lastReading: parseFloat(document.getElementById('modalReading').value) || 0,
            unit: document.getElementById('modalUnit').value.trim(),
            status: document.getElementById('modalStatus').value,
            posX: parseFloat(document.getElementById('modalPosX').value) || 0,
            posY: parseFloat(document.getElementById('modalPosY').value) || 0,
            posZ: parseFloat(document.getElementById('modalPosZ').value) || 0
        };

        // Client-side validation
        if (!formData.name) { alert('Name is required'); return; }
        if (!formData.location) { alert('Location is required'); return; }
        if (!formData.type) { alert('Type is required'); return; }
        if (!formData.unit) { alert('Unit is required'); return; }

        try {
            await onSave(formData);
            closeModal();
        } catch (err) {
            alert(`Save failed: ${err.message}`);
        }
    });
}

function closeModal() {
    const modal = document.getElementById('sensorModal');
    if (modal) modal.remove();
}

// ── Chat ──────────────────────────────────────────────────────────

function addChatMessage(chatLog, role, text) {
    const msg = document.createElement('div');
    msg.className = `chat-message ${role}`;
    msg.innerHTML = escapeHtml(text).replace(/\n/g, '<br/>');
    chatLog.appendChild(msg);
    chatLog.scrollTop = chatLog.scrollHeight;
}

async function sendChat(chatInput, chatSend, chatStatus, chatLog, chatHistory) {
    const message = chatInput.value.trim();
    if (!message) return;

    chatInput.value = '';
    chatSend.disabled = true;
    chatStatus.textContent = 'Thinking...';

    addChatMessage(chatLog, 'user', message);
    chatHistory.push({ role: 'user', content: message });

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                history: chatHistory.slice(-10)
            })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        addChatMessage(chatLog, 'assistant', data.reply || 'No response');
        chatHistory.push({ role: 'assistant', content: data.reply || '' });
    } catch (err) {
        addChatMessage(chatLog, 'system', `Chat error: ${err.message}`);
    } finally {
        chatSend.disabled = false;
        chatStatus.textContent = '';
    }
}

// ── Utility ──────────────────────────────────────────────────────

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value);
}

function setImportStatus(message) {
    const el = document.getElementById('importStatus');
    if (el) el.textContent = message;
}

function showUiError(message) {
    const storyText = document.getElementById('storyText');
    if (storyText) {
        storyText.textContent = message;
        storyText.style.color = '#fca5a5';
    }
}

function setBootStatus(message) {
    const el = document.getElementById('bootStatus');
    if (el) el.textContent = message;
}
