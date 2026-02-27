/**
 * Remote Shutdown Controller — Dashboard Frontend (Hybrid Agent + SSH)
 *
 * Handles:
 *  - Adding devices by IP only (agent mode) or SSH credentials
 *  - WebSocket connection for real-time updates
 *  - Device grid rendering with live status
 *  - Command execution with confirmation dialogs
 *  - Network discovery triggers
 *  - Toast notifications
 *  - Terminal command interface
 */

// ═══════════════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════════════

const state = {
    devices: [],
    selectedDevices: new Set(),
    ws: null,
    wsConnected: false,
    controllerStatus: null,
    controllerStatusUnsupported: false,
};

const API_BASE = '';
const WS_URL = `ws://${window.location.host}/ws`;

// ═══════════════════════════════════════════════════════════════════════
//  DOM References
// ═══════════════════════════════════════════════════════════════════════

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const els = {
    deviceGrid: $('#device-grid'),
    emptyState: $('#empty-state'),
    statTotal: $('#stat-total-value'),
    statOnline: $('#stat-online-value'),
    statStatus: $('#stat-status-value'),
    statSshKey: $('#stat-ssh-key-value'),
    statSshKeyCard: $('#stat-ssh-key-card'),
    logContainer: $('#log-container'),
    terminalOutput: $('#terminal-output'),
    terminalInput: $('#terminal-input'),
    toastContainer: $('#toast-container'),

    // Confirm modal
    modalOverlay: $('#modal-overlay'),
    modalTitle: $('#modal-title'),
    modalMessage: $('#modal-message'),
    modalIcon: $('#modal-icon'),
    modalConfirm: $('#modal-confirm'),
    modalCancel: $('#modal-cancel'),

    // Add device modal
    addOverlay: $('#add-device-overlay'),
    addIp: $('#add-ip'),
    addPort: $('#add-port'),
    addMac: $('#add-mac'),
    addUsername: $('#add-username'),
    addPassword: $('#add-password'),
    addKeypath: $('#add-keypath'),
    addSubmit: $('#add-submit'),
    addSubmitText: $('#add-submit-text'),
    addSubmitSpinner: $('#add-submit-spinner'),
    addCancel: $('#add-cancel'),
    addError: $('#add-error'),
    addSuccess: $('#add-success'),

    selectAll: $('#select-all'),
    massShutdown: $('#mass-shutdown'),
    massReboot: $('#mass-reboot'),
    massSleep: $('#mass-sleep'),
    massWake: $('#mass-wake'),
};

// ═══════════════════════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════════════════════

function connectWebSocket() {
    state.ws = new WebSocket(WS_URL);

    state.ws.onopen = () => {
        state.wsConnected = true;
        els.statStatus.textContent = 'ARMED';
        els.statStatus.className = 'stat-value status-armed';
        addLog('WebSocket connected', 'system');
    };

    state.ws.onclose = () => {
        state.wsConnected = false;
        els.statStatus.textContent = 'OFFLINE';
        els.statStatus.className = 'stat-value';
        addLog('WebSocket disconnected — reconnecting...', 'warning');
        setTimeout(connectWebSocket, 3000);
    };

    state.ws.onerror = () => addLog('WebSocket error', 'error');

    state.ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWSEvent(data);
    };
}

function handleWSEvent(data) {
    switch (data.type) {
        case 'init':
            state.devices = data.devices || [];
            renderDevices();
            addLog(`Loaded ${state.devices.length} device(s)`, 'system');
            break;

        case 'device_added':
            if (data.device) {
                const exists = state.devices.find(d => d.device_id === data.device.device_id);
                if (!exists) state.devices.push(data.device);
                renderDevices();
                addLog(`Device added: ${data.device.hostname} (${data.device.ip_address})`, 'success');
            }
            break;

        case 'devices_updated':
            state.devices = data.devices || [];
            renderDevices();
            break;

        case 'discovery_started':
            addLog('Network scan started...', 'system');
            toast('Scanning network...', 'info');
            break;

        case 'discovery_complete':
            state.devices = data.devices || [];
            renderDevices();
            addLog(`Discovery complete: ${data.new_count} found, ${state.devices.length} total`, 'success');
            toast(`Found ${data.new_count} host(s) with SSH open`, 'success');
            break;

        case 'command_result': {
            const device = state.devices.find(d => d.device_id === data.device_id);
            const name = device ? device.hostname : data.device_id.slice(0, 8);
            if (data.success) {
                addLog(`${data.command} → ${name}: ${data.message || 'OK'}`, 'success');
                toast(`${data.command} sent to ${name}`, 'success');
            } else {
                addLog(`${data.command} → ${name}: ${data.message}`, 'error');
                toast(`${data.command} failed: ${data.message}`, 'error');
            }
            break;
        }

        case 'wol_sent':
            addLog(`WoL packet sent to ${data.mac}`, data.success ? 'success' : 'error');
            break;

        case 'device_removed':
            state.devices = state.devices.filter(d => d.device_id !== data.device_id);
            renderDevices();
            addLog('Device removed', 'system');
            break;

        default:
            addLog(`Event: ${data.type}`, 'system');
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  API Calls
// ═══════════════════════════════════════════════════════════════════════

async function api(path, method = 'GET', body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);

    try {
        const res = await fetch(`${API_BASE}${path}`, opts);
        return await res.json();
    } catch (err) {
        addLog(`API error: ${err.message}`, 'error');
        toast(`API error: ${err.message}`, 'error');
        return null;
    }
}

function updateControllerStatusUI(status, mode = 'normal') {
    state.controllerStatus = status || null;
    if (!els.statSshKey) return;

    if (mode === 'legacy') {
        els.statSshKey.textContent = 'LEGACY';
        els.statSshKey.className = 'stat-value status-legacy';
        if (els.statSshKeyCard) {
            els.statSshKeyCard.title = 'Controller is running an older build without /api/controller/status';
        }
        return;
    }

    const sshKey = status?.ssh_key;
    if (!status || !sshKey) {
        els.statSshKey.textContent = 'ERROR';
        els.statSshKey.className = 'stat-value status-missing';
        if (els.statSshKeyCard) els.statSshKeyCard.title = 'Controller status unavailable';
        return;
    }

    const ready = Boolean(sshKey.exists);
    els.statSshKey.textContent = ready ? 'READY' : 'MISSING';
    els.statSshKey.className = `stat-value ${ready ? 'status-ready' : 'status-missing'}`;
    if (els.statSshKeyCard) {
        els.statSshKeyCard.title = [
            `Source: ${sshKey.source || 'unknown'}`,
            sshKey.path ? `Path: ${sshKey.path}` : '',
            sshKey.fingerprint ? `Fingerprint: ${sshKey.fingerprint}` : '',
        ].filter(Boolean).join('\n');
    }
}

async function refreshControllerStatus() {
    if (state.controllerStatusUnsupported) {
        updateControllerStatusUI(null, 'legacy');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/api/controller/status`);
        if (res.status === 404) {
            state.controllerStatusUnsupported = true;
            addLog('Controller status endpoint not available on this server build', 'warning');
            updateControllerStatusUI(null, 'legacy');
            return;
        }

        const result = await res.json();
        if (!res.ok || !result?.success) {
            updateControllerStatusUI(null);
            return;
        }
        updateControllerStatusUI(result);
    } catch (_err) {
        updateControllerStatusUI(null);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Add Device
// ═══════════════════════════════════════════════════════════════════════

function showAddDeviceModal() {
    els.addIp.value = '';
    els.addPort.value = '9999';
    els.addMac.value = '';
    els.addUsername.value = '';
    els.addPassword.value = '';
    els.addKeypath.value = '';
    els.addError.style.display = 'none';
    els.addSuccess.style.display = 'none';
    els.addSubmitText.style.display = '';
    els.addSubmitSpinner.style.display = 'none';
    els.addSubmit.disabled = false;
    // Collapse advanced section
    const adv = $('#advanced-section');
    const advToggle = $('#advanced-toggle');
    if (adv) adv.style.display = 'none';
    if (advToggle) advToggle.classList.remove('open');
    if (advToggle) advToggle.innerHTML = '▸ Advanced SSH Settings <span class="advanced-hint">(leave blank for agent mode)</span>';
    els.addOverlay.classList.add('active');
    setTimeout(() => els.addIp.focus(), 100);
}

function hideAddDeviceModal() {
    els.addOverlay.classList.remove('active');
}

async function submitAddDevice() {
    const ip = els.addIp.value.trim();
    const port = parseInt(els.addPort.value) || 22;
    const mac = els.addMac.value.trim();
    const username = els.addUsername.value.trim();
    const password = els.addPassword.value;
    const keyPath = els.addKeypath.value.trim();

    // Validate — only IP is required now!
    if (!ip) {
        showAddError('IP address is required');
        return;
    }

    // Show loading state
    els.addSubmit.disabled = true;
    els.addSubmitText.style.display = 'none';
    els.addSubmitSpinner.style.display = '';
    els.addError.style.display = 'none';

    addLog(`Connecting to ${ip}:${port}...`, 'system');

    const payload = { ip, mac };
    if (username) {
        payload.mode = 'ssh';
        payload.port = port || 22;
        payload.username = username;
        payload.password = password || '';
        payload.key_path = keyPath || '';
    } else {
        payload.mode = 'agent';
        payload.agent_port = port || 9999;
        payload.agent_secret = password || '';
        payload.agent_xor_key = keyPath || '';
    }

    const result = await api('/api/devices/add', 'POST', payload);

    els.addSubmit.disabled = false;
    els.addSubmitText.style.display = '';
    els.addSubmitSpinner.style.display = 'none';

    if (!result) {
        showAddError('Network error — is the controller running?');
        return;
    }

    if (!result.success) {
        showAddError(result.error || 'Connection failed');
        return;
    }

    // Success!
    const conn = result.connection || {};
    const mode = (conn.mode || 'unknown').toUpperCase();
    els.addSuccess.textContent = `✅ Connected (${mode}): ${conn.hostname} (${conn.platform})`;
    els.addSuccess.style.display = 'block';
    els.addError.style.display = 'none';

    toast(`Device added: ${conn.hostname}`, 'success');
    addLog(`${mode} connected to ${conn.hostname} (${conn.platform})`, 'success');

    // Close after 1.5 sec
    setTimeout(() => {
        hideAddDeviceModal();
        refreshDevices();
    }, 1500);
}

function showAddError(msg) {
    els.addError.textContent = msg;
    els.addError.style.display = 'block';
    els.addSuccess.style.display = 'none';
}

async function refreshDevices() {
    const devices = await api('/api/devices');
    if (devices) {
        state.devices = devices;
        renderDevices();
    }
}

async function discoverDevices() {
    const btn = $('#btn-discover');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> SCANNING...';

    const result = await api('/api/devices/discover', 'POST');
    if (result) {
        state.devices = result.devices || [];
        renderDevices();
    }

    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">📡</span> SCAN';
}

async function sendCommand(deviceId, command, params = {}) {
    return await api(`/api/devices/${deviceId}/command`, 'POST', { command, params });
}

async function wakeDevice(deviceId) {
    return await api(`/api/devices/${deviceId}/wake`, 'POST');
}

async function pingDevice(deviceId) {
    return await api(`/api/devices/${deviceId}/ping`, 'POST');
}

async function deleteDevice(deviceId) {
    return await api(`/api/devices/${deviceId}`, 'DELETE');
}

// ═══════════════════════════════════════════════════════════════════════
//  Device Rendering
// ═══════════════════════════════════════════════════════════════════════

const STATUS_MAP = {
    0: { label: 'UNKNOWN', class: 'offline', dot: 'offline' },
    1: { label: 'ONLINE', class: 'online', dot: 'online' },
    2: { label: 'OFFLINE', class: 'offline', dot: 'offline' },
    3: { label: 'SLEEPING', class: 'sleeping', dot: 'sleeping' },
    4: { label: 'SHUTTING DOWN', class: 'offline', dot: 'offline' },
};

const PLATFORM_ICONS = {
    darwin: '🍎',
    linux: '🐧',
    windows: '🪟',
    unknown: '💻',
};

function renderDevices() {
    const total = state.devices.length;
    const online = state.devices.filter(d => d.status === 1).length;

    els.statTotal.textContent = total;
    els.statOnline.textContent = online;

    if (total === 0) {
        els.deviceGrid.innerHTML = '';
        els.deviceGrid.appendChild(els.emptyState);
        els.emptyState.style.display = 'block';
        return;
    }

    els.emptyState.style.display = 'none';
    els.deviceGrid.innerHTML = state.devices.map(d => renderDeviceCard(d)).join('');

    // Bind device actions
    $$('.device-select').forEach(cb => {
        cb.addEventListener('change', (e) => {
            if (e.target.checked) state.selectedDevices.add(e.target.dataset.id);
            else state.selectedDevices.delete(e.target.dataset.id);
            updateMassActions();
        });
    });

    $$('.device-action-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            handleDeviceAction(btn.dataset.deviceId, btn.dataset.action);
        });
    });
}

function renderDeviceCard(device) {
    const s = STATUS_MAP[device.status] || STATUS_MAP[0];
    const icon = PLATFORM_ICONS[device.platform] || PLATFORM_ICONS.unknown;
    const lastSeen = device.last_seen
        ? new Date(device.last_seen * 1000).toLocaleTimeString()
        : 'Never';
    const isSelected = state.selectedDevices.has(device.device_id);

    return `
        <div class="device-card ${s.class}" data-device-id="${device.device_id}">
            <div class="device-card-header">
                <div class="device-identity">
                    <input type="checkbox" class="device-select" data-id="${device.device_id}" ${isSelected ? 'checked' : ''}>
                    <div class="device-icon">${icon}</div>
                    <div>
                        <div class="device-name">${escapeHtml(device.hostname || device.ip_address || 'Unknown')}</div>
                        <div class="device-platform">${device.platform || 'unknown'} • remote</div>
                    </div>
                </div>
                <div class="device-status-dot ${s.dot}" title="${s.label}"></div>
            </div>

            <div class="device-details">
                <div class="device-detail">
                    <span class="detail-label">IP ADDRESS</span>
                    <span class="detail-value">${device.ip_address || '—'}</span>
                </div>
                <div class="device-detail">
                    <span class="detail-label">MAC</span>
                    <span class="detail-value">${device.mac_address || '—'}</span>
                </div>
                <div class="device-detail">
                    <span class="detail-label">STATUS</span>
                    <span class="detail-value">${s.label}</span>
                </div>
                <div class="device-detail">
                    <span class="detail-label">LAST SEEN</span>
                    <span class="detail-value">${lastSeen}</span>
                </div>
            </div>

            <div class="device-actions">
                <button class="btn btn-sm btn-info device-action-btn" data-device-id="${device.device_id}" data-action="ping">📶 PING</button>
                <button class="btn btn-sm btn-danger device-action-btn" data-device-id="${device.device_id}" data-action="shutdown">⏻ OFF</button>
                <button class="btn btn-sm btn-warning device-action-btn" data-device-id="${device.device_id}" data-action="reboot">🔄 REBOOT</button>
                <button class="btn btn-sm btn-info device-action-btn" data-device-id="${device.device_id}" data-action="sleep">🌙 SLEEP</button>
                <button class="btn btn-sm btn-success device-action-btn" data-device-id="${device.device_id}" data-action="wake">☀️ WAKE</button>
                <button class="btn btn-sm btn-secondary device-action-btn" data-device-id="${device.device_id}" data-action="status">📊 STATUS</button>
                <button class="btn btn-sm btn-danger device-action-btn" data-device-id="${device.device_id}" data-action="delete" style="margin-left:auto">🗑️</button>
            </div>
        </div>
    `;
}

// ═══════════════════════════════════════════════════════════════════════
//  Command Handling
// ═══════════════════════════════════════════════════════════════════════

function handleDeviceAction(deviceId, action) {
    const device = state.devices.find(d => d.device_id === deviceId);
    const name = device ? (device.hostname || device.ip_address) : deviceId.slice(0, 8);

    switch (action) {
        case 'ping':
            pingDevice(deviceId);
            addLog(`PING → ${name}`, 'system');
            break;

        case 'status':
            sendCommand(deviceId, 'status').then(r => {
                if (r?.success) addLog(`STATUS ${name}:\n${r.output}`, 'success');
                else addLog(`STATUS ${name}: ${r?.error || 'failed'}`, 'error');
            });
            break;

        case 'shutdown':
            showConfirmModal('Shutdown Device', `SHUTDOWN "${name}"? This will power off the device.`, '⏻',
                () => { sendCommand(deviceId, 'shutdown'); addLog(`SHUTDOWN → ${name}`, 'system'); });
            break;

        case 'reboot':
            showConfirmModal('Reboot Device', `REBOOT "${name}"?`, '🔄',
                () => { sendCommand(deviceId, 'reboot'); addLog(`REBOOT → ${name}`, 'system'); });
            break;

        case 'sleep':
            sendCommand(deviceId, 'sleep');
            addLog(`SLEEP → ${name}`, 'system');
            break;

        case 'wake':
            wakeDevice(deviceId);
            addLog(`WoL → ${name}`, 'system');
            break;

        case 'delete':
            showConfirmModal('Remove Device', `Remove "${name}" from the device list?`, '🗑️',
                async () => { await deleteDevice(deviceId); await refreshDevices(); });
            break;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Mass Actions
// ═══════════════════════════════════════════════════════════════════════

function updateMassActions() {
    const has = state.selectedDevices.size > 0;
    els.massShutdown.disabled = !has;
    els.massReboot.disabled = !has;
    els.massSleep.disabled = !has;
    els.massWake.disabled = !has;
}

function executeMassAction(command) {
    const count = state.selectedDevices.size;
    if (!count) return;

    showConfirmModal(`Mass ${command}`, `Execute ${command} on ${count} selected device(s)?`, '⚠️',
        async () => {
            for (const id of state.selectedDevices) {
                if (command === 'WAKE') await wakeDevice(id);
                else await sendCommand(id, command.toLowerCase());
                await new Promise(r => setTimeout(r, 200));
            }
            toast(`${command} sent to ${count} device(s)`, 'info');
        }
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Confirmation Modal
// ═══════════════════════════════════════════════════════════════════════

let modalCallback = null;

function showConfirmModal(title, message, icon, onConfirm) {
    els.modalTitle.textContent = title;
    els.modalMessage.textContent = message;
    els.modalIcon.textContent = icon;
    modalCallback = onConfirm;
    els.modalOverlay.classList.add('active');
}

function hideModal() {
    els.modalOverlay.classList.remove('active');
    modalCallback = null;
}

// ═══════════════════════════════════════════════════════════════════════
//  Logs
// ═══════════════════════════════════════════════════════════════════════

function addLog(message, type = 'system') {
    const now = new Date().toLocaleTimeString('en-US', { hour12: false });
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerHTML = `<span class="log-time">${now}</span><span class="log-msg">${escapeHtml(message)}</span>`;
    els.logContainer.appendChild(entry);
    els.logContainer.scrollTop = els.logContainer.scrollHeight;
    while (els.logContainer.children.length > 200) els.logContainer.removeChild(els.logContainer.firstChild);
}

// ═══════════════════════════════════════════════════════════════════════
//  Toast
// ═══════════════════════════════════════════════════════════════════════

function toast(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    els.toastContainer.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

// ═══════════════════════════════════════════════════════════════════════
//  Terminal
// ═══════════════════════════════════════════════════════════════════════

const TERMINAL_CMDS = {
    help: () => `Available commands:
  add <ip>                 — Add target in agent mode (IP-only)
  add <ip> agent [port] [secret]  — Agent mode with optional port/secret
  add <ip> <user> [pass]   — SSH mode
  qping <ip>              — Quick ICMP ping any IP
  devices                 — List all devices
  scan                    — Discover SSH hosts on network
  shutdown <id>           — Shutdown (first 8 chars of ID or IP)
  reboot <id>             — Reboot
  sleep <id>              — Sleep
  wake <id>               — WoL (needs MAC)
  ping <id>               — ICMP ping a registered device
  keyauth <id|ip>          — Push controller SSH key (passwordless login)
  status <id>              — Get system info (SSH mode only)
  clear                    — Clear terminal
  help                     — This message`,

    devices: () => {
        if (!state.devices.length) return 'No devices. Run "add <ip>" or "scan".';
        return state.devices.map(d => {
            const s = STATUS_MAP[d.status]?.label || '???';
            return `  ${d.device_id.slice(0, 8)}  ${(d.hostname || '?').padEnd(20)} ${(d.ip_address || '').padEnd(16)} ${s}`;
        }).join('\n');
    },

    scan: async () => { termPrint('Scanning...'); await discoverDevices(); return `Done. ${state.devices.length} device(s).`; },

    clear: () => { els.terminalOutput.innerHTML = ''; return null; },

    status: () => {
        const sshKey = state.controllerStatus?.ssh_key;
        const keyLabel = state.controllerStatusUnsupported
            ? 'SSH_KEY=LEGACY'
            : sshKey?.exists
                ? `SSH_KEY=${(sshKey.source || 'ready').toUpperCase()}`
                : 'SSH_KEY=MISSING';
        return `Controller:  WS=${state.wsConnected ? 'OK' : 'DOWN'}  Devices=${state.devices.length}  Online=${state.devices.filter(d => d.status === 1).length}  ${keyLabel}`;
    },
};

function findDeviceByRef(ref) {
    return state.devices.find(d => d.device_id.startsWith(ref) || d.ip_address === ref || d.hostname === ref);
}

async function runTerminalCmd(input) {
    const parts = input.trim().split(/\s+/);
    const cmd = parts[0]?.toLowerCase();
    if (!cmd) return;

    termPrint(`rshd > ${input}`, 'cyan');

    // Quick ICMP ping any IP — no SSH, no registration
    if (cmd === 'qping') {
        if (parts.length < 2) { termPrint('Usage: qping <ip>'); return; }
        const ip = parts[1];
        termPrint(`ICMP pinging ${ip}...`);
        const result = await api('/api/ping', 'POST', { ip, count: 3 });
        if (result?.alive) {
            const lat = result.latency_ms ? ` (${result.latency_ms}ms avg)` : '';
            termPrint(`✅ ${ip} is ALIVE${lat}`, 'green');
            // Show raw output
            if (result.output) termPrint(result.output);
        } else {
            termPrint(`❌ ${ip} is UNREACHABLE`, 'red');
            if (result?.output) termPrint(result.output);
        }
        return;
    }

    // keyauth <ref> — push controller key to device
    if (cmd === 'keyauth') {
        if (parts.length < 2) { termPrint('Usage: keyauth <id|ip>'); return; }
        const device = findDeviceByRef(parts[1]);
        if (!device) { termPrint(`❌ Device "${parts[1]}" not found. Use "devices" to list.`, 'red'); return; }
        termPrint(`Pushing controller SSH key to ${device.hostname} (${device.ip_address})...`);
        const result = await api(`/api/devices/${device.device_id}/keyauth`, 'POST');
        if (result?.success) {
            termPrint(`✅ ${result.message}`, 'green');
            if (result.fingerprint) termPrint(`   Key: ${result.fingerprint}`);
            termPrint(`   You can now reconnect without a password: add ${device.ip_address} ${device.ssh_username || '<user>'}`);
        } else {
            termPrint(`❌ ${result?.error || 'Failed to push key'}`, 'red');
        }
        return;
    }

    // Quick-add:
    // add <ip>
    // add <ip> agent [port] [secret]
    // add <ip> <user> [pass]
    if (cmd === 'add') {
        if (parts.length < 2) { termPrint('Usage: add <ip> | add <ip> agent [port] [secret] | add <ip> <username> [password]'); return; }

        const ip = parts[1];
        const modeArg = (parts[2] || '').toLowerCase();
        let payload;

        if (!parts[2]) {
            payload = { ip, mode: 'agent', agent_port: 9999 };
            termPrint(`Connecting to ${ip} (agent mode, port 9999)...`);
        } else if (modeArg === 'agent') {
            payload = {
                ip,
                mode: 'agent',
                agent_port: parseInt(parts[3] || '9999', 10) || 9999,
                agent_secret: parts[4] || '',
            };
            termPrint(`Connecting to ${ip} (agent mode, port ${payload.agent_port})...`);
        } else {
            payload = {
                ip,
                mode: 'ssh',
                username: parts[2] || '',
                password: parts[3] || '',
                port: 22,
            };
            termPrint(`Connecting to ${ip} (ssh mode)...`);
        }

        const result = await api('/api/devices/add', 'POST', payload);
        if (result?.success) {
            const conn = result.connection || {};
            termPrint(`✅ Connected [${(conn.mode || 'unknown').toUpperCase()}]: ${conn.hostname} (${conn.platform})`);
        }
        else termPrint(`❌ ${result?.error || 'Failed'}`, 'red');
        await refreshDevices();
        return;
    }

    if (TERMINAL_CMDS[cmd]) {
        const r = await TERMINAL_CMDS[cmd]();
        if (r) termPrint(r);
        return;
    }

    const deviceCmds = ['shutdown', 'reboot', 'sleep', 'wake', 'ping', 'status'];
    if (deviceCmds.includes(cmd)) {
        if (!parts[1]) { termPrint(`Usage: ${cmd} <device-id | ip>`); return; }
        const dev = findDeviceByRef(parts[1]);
        if (!dev) { termPrint(`Device not found: ${parts[1]}`); return; }

        if (cmd === 'wake') { await wakeDevice(dev.device_id); termPrint(`WoL → ${dev.hostname}`); }
        else if (cmd === 'ping') {
            const r = await pingDevice(dev.device_id);
            termPrint(r?.online ? `${dev.hostname}: PONG ✅` : `${dev.hostname}: OFFLINE ❌`);
        } else {
            const r = await sendCommand(dev.device_id, cmd);
            termPrint(r?.success ? `${cmd.toUpperCase()} → ${dev.hostname}: OK` : `${cmd.toUpperCase()} → ${dev.hostname}: ${r?.error || 'failed'}`);
        }
        return;
    }

    termPrint(`Unknown: ${cmd}. Type "help".`);
}

function termPrint(text, color = 'green') {
    const pre = document.createElement('pre');
    pre.style.color = color === 'cyan' ? 'var(--accent-cyan)' :
        color === 'red' ? 'var(--accent-red)' :
            color === 'yellow' ? 'var(--accent-orange)' :
                'var(--accent-green)';
    pre.textContent = text;
    els.terminalOutput.appendChild(pre);
    els.terminalOutput.scrollTop = els.terminalOutput.scrollHeight;
}

// ═══════════════════════════════════════════════════════════════════════
//  Tab Switching
// ═══════════════════════════════════════════════════════════════════════

function switchTab(tab) {
    $$('.tab').forEach(t => t.classList.remove('active'));
    $$('.tab-content').forEach(c => c.classList.remove('active'));
    $(`[data-tab="${tab}"]`).classList.add('active');
    $(`#content-${tab}`).classList.add('active');
    if (tab === 'terminal') els.terminalInput.focus();
}

// ═══════════════════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════════════════

function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

// ═══════════════════════════════════════════════════════════════════════
//  Init
// ═══════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();

    // Load devices
    refreshDevices();
    refreshControllerStatus();
    setInterval(refreshControllerStatus, 15000);

    // Add device buttons
    $('#btn-add-device').addEventListener('click', showAddDeviceModal);
    const emptyBtn = $('#btn-add-device-empty');
    if (emptyBtn) emptyBtn.addEventListener('click', showAddDeviceModal);

    // Add device modal
    els.addSubmit.addEventListener('click', submitAddDevice);
    els.addCancel.addEventListener('click', hideAddDeviceModal);
    els.addOverlay.addEventListener('click', (e) => { if (e.target === els.addOverlay) hideAddDeviceModal(); });

    // Advanced toggle
    const advToggle = $('#advanced-toggle');
    if (advToggle) {
        advToggle.addEventListener('click', () => {
            const section = $('#advanced-section');
            const isOpen = section.style.display !== 'none';
            section.style.display = isOpen ? 'none' : 'block';
            advToggle.classList.toggle('open', !isOpen);
            advToggle.innerHTML = (isOpen ? '▸' : '▾') + ' Advanced SSH Settings <span class="advanced-hint">(leave blank for agent mode)</span>';
        });
    }

    // Allow Enter to submit add-device form
    [els.addIp, els.addPort, els.addUsername, els.addPassword, els.addKeypath, els.addMac].forEach(input => {
        if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitAddDevice(); });
    });

    // Discover
    $('#btn-discover').addEventListener('click', discoverDevices);

    // Invite modal
    const btnInvite = $('#btn-invite');
    if (btnInvite) btnInvite.addEventListener('click', showInviteModal);
    const inviteCancel = $('#invite-cancel');
    if (inviteCancel) inviteCancel.addEventListener('click', hideInviteModal);
    const inviteSubmit = $('#invite-submit');
    if (inviteSubmit) inviteSubmit.addEventListener('click', submitInvite);
    const inviteOverlay = $('#invite-overlay');
    if (inviteOverlay) inviteOverlay.addEventListener('click', (e) => { if (e.target === inviteOverlay) hideInviteModal(); });

    // SMTP settings toggle
    const smtpToggle = $('#smtp-toggle');
    if (smtpToggle) {
        smtpToggle.addEventListener('click', () => {
            const section = $('#smtp-section');
            const isOpen = section.style.display !== 'none';
            section.style.display = isOpen ? 'none' : 'block';
            smtpToggle.classList.toggle('open', !isOpen);
            smtpToggle.innerHTML = (isOpen ? '▸' : '▾') + ' SMTP Settings <span class="advanced-hint">(required first time)</span>';
        });
    }

    // Tabs
    $$('.tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

    // Terminal
    els.terminalInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const v = els.terminalInput.value;
            els.terminalInput.value = '';
            runTerminalCmd(v);
        }
    });

    // Confirm modal
    els.modalConfirm.addEventListener('click', () => { if (modalCallback) modalCallback(); hideModal(); });
    els.modalCancel.addEventListener('click', hideModal);
    els.modalOverlay.addEventListener('click', (e) => { if (e.target === els.modalOverlay) hideModal(); });

    // Select all
    els.selectAll.addEventListener('change', (e) => {
        state.selectedDevices.clear();
        if (e.target.checked) state.devices.forEach(d => state.selectedDevices.add(d.device_id));
        renderDevices();
        updateMassActions();
    });

    // Mass actions
    els.massShutdown.addEventListener('click', () => executeMassAction('SHUTDOWN'));
    els.massReboot.addEventListener('click', () => executeMassAction('REBOOT'));
    els.massSleep.addEventListener('click', () => executeMassAction('SLEEP'));
    els.massWake.addEventListener('click', () => executeMassAction('WAKE'));

    // Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { hideModal(); hideAddDeviceModal(); hideInviteModal(); }
    });

    addLog('Controller initialized — hybrid agent/SSH mode', 'system');
});

// ═══════════════════════════════════════════════════════════════════════
//  Email Invite
// ═══════════════════════════════════════════════════════════════════════

// Persist SMTP settings in localStorage
const SMTP_STORAGE_KEY = 'rshd_smtp';

function loadSmtpSettings() {
    try {
        const saved = JSON.parse(localStorage.getItem(SMTP_STORAGE_KEY));
        if (saved) {
            const h = $('#smtp-host'); if (h && saved.host) h.value = saved.host;
            const p = $('#smtp-port'); if (p && saved.port) p.value = saved.port;
            const u = $('#smtp-user'); if (u && saved.user) u.value = saved.user;
            // Password NOT persisted for security
        }
    } catch (e) { /* ignore */ }
}

function saveSmtpSettings() {
    const host = $('#smtp-host')?.value || '';
    const port = $('#smtp-port')?.value || '';
    const user = $('#smtp-user')?.value || '';
    localStorage.setItem(SMTP_STORAGE_KEY, JSON.stringify({ host, port, user }));
}

function showInviteModal() {
    loadSmtpSettings();
    const invTo = $('#invite-to'); if (invTo) invTo.value = '';
    const invMsg = $('#invite-message'); if (invMsg) invMsg.value = '';
    const invErr = $('#invite-error'); if (invErr) invErr.style.display = 'none';
    const invSuc = $('#invite-success'); if (invSuc) invSuc.style.display = 'none';
    const invText = $('#invite-submit-text'); if (invText) invText.style.display = '';
    const invSpin = $('#invite-submit-spinner'); if (invSpin) invSpin.style.display = 'none';
    const invSubmit = $('#invite-submit'); if (invSubmit) invSubmit.disabled = false;
    const overlay = $('#invite-overlay'); if (overlay) overlay.classList.add('active');
    setTimeout(() => { const t = $('#invite-to'); if (t) t.focus(); }, 100);
}

function hideInviteModal() {
    const overlay = $('#invite-overlay');
    if (overlay) overlay.classList.remove('active');
}

async function submitInvite() {
    const to = $('#invite-to')?.value?.trim();
    const subject = $('#invite-subject')?.value?.trim();
    const message = $('#invite-message')?.value?.trim();
    const smtpHost = $('#smtp-host')?.value?.trim();
    const smtpPort = parseInt($('#smtp-port')?.value) || 587;
    const smtpUser = $('#smtp-user')?.value?.trim();
    const smtpPass = $('#smtp-pass')?.value;

    if (!to) {
        showInviteError('Recipient email is required');
        return;
    }
    if (!smtpUser || !smtpPass) {
        showInviteError('SMTP credentials required — expand SMTP Settings');
        // Auto-open SMTP section
        const section = $('#smtp-section');
        if (section) section.style.display = 'block';
        return;
    }

    // Loading state
    const invSubmit = $('#invite-submit'); if (invSubmit) invSubmit.disabled = true;
    const invText = $('#invite-submit-text'); if (invText) invText.style.display = 'none';
    const invSpin = $('#invite-submit-spinner'); if (invSpin) invSpin.style.display = '';
    const invErr = $('#invite-error'); if (invErr) invErr.style.display = 'none';

    saveSmtpSettings();
    addLog(`Sending invite to ${to}...`, 'system');

    const result = await api('/api/invite', 'POST', {
        to, subject, message,
        smtp_host: smtpHost,
        smtp_port: smtpPort,
        smtp_user: smtpUser,
        smtp_pass: smtpPass,
    });

    if (invSubmit) invSubmit.disabled = false;
    if (invText) invText.style.display = '';
    if (invSpin) invSpin.style.display = 'none';

    if (!result) {
        showInviteError('Network error — is the controller running?');
        return;
    }

    if (!result.success) {
        showInviteError(result.error || 'Failed to send');
        return;
    }

    // Success
    const invSuc = $('#invite-success');
    if (invSuc) {
        invSuc.textContent = `✅ Invite sent to ${to}!`;
        invSuc.style.display = 'block';
    }
    toast(`Invite sent to ${to}`, 'success');
    addLog(`Invite email sent to ${to}`, 'success');

    setTimeout(hideInviteModal, 2000);
}

function showInviteError(msg) {
    const el = $('#invite-error');
    if (el) { el.textContent = msg; el.style.display = 'block'; }
    const suc = $('#invite-success');
    if (suc) suc.style.display = 'none';
}
