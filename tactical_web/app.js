/* ==========================================================================
   DESTROYER TACTICAL P2P LOCAL LAB & TELEMETRY COMMAND CENTER (JS)
   CSP Level 3 compliant (zero inline handlers, zero eval, zero innerHTML XSS)
   ========================================================================== */

const state = {
  currentTab: 'overview',
  cadenceMs: 20,
  quantumBytes: 1232,
  entropy: null,
  sentCells: 0,
  chaffCells: 0,
  dataCells: 0,
  drops: 0,
  sas: 'UNVERIFIED',
  drillRunning: false,
  tpiOfficer1: false,
  tpiOfficer2: false,
};

document.addEventListener('DOMContentLoaded', () => {
  bindUIEvents();
  initZuluClock();
  initOscilloscope();
  initDiodeMatrix();
  updateEntropyGauge(state.entropy);
  fetchServerStatus();
  setInterval(fetchServerStatus, 2500);
});

function bindUIEvents() {
  document.querySelectorAll('.nav-tab[data-tab]').forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  document.querySelectorAll('.preset-btn[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => sendPreset(btn.dataset.preset));
  });

  const eamBtn = document.getElementById('btn-trigger-eam');
  if (eamBtn) eamBtn.addEventListener('click', triggerEAMDirective);

  const zgdpBtn = document.getElementById('btn-run-zgdp');
  if (zgdpBtn) zgdpBtn.addEventListener('click', runZGDPTelemetry);

  const chatForm = document.getElementById('chat-form');
  if (chatForm) chatForm.addEventListener('submit', handleSendMsg);

  const cotForm = document.getElementById('cot-form');
  if (cotForm) cotForm.addEventListener('submit', handleSendCoT);

  const diodeForm = document.getElementById('diode-form');
  if (diodeForm) diodeForm.addEventListener('submit', handleSendDiode);

  const sasBtn = document.getElementById('btn-confirm-sas');
  if (sasBtn) sasBtn.addEventListener('click', confirmSAS);

  const drillBtn = document.getElementById('btn-run-drill');
  if (drillBtn) drillBtn.addEventListener('click', runAutomatedDrill);

  const closeDrillBtn = document.getElementById('btn-close-drill');
  if (closeDrillBtn) closeDrillBtn.addEventListener('click', closeDrillStatus);

  const sw1 = document.getElementById('tpi-switch-1');
  if (sw1) sw1.addEventListener('change', checkTPIStatus);

  const sw2 = document.getElementById('tpi-switch-2');
  if (sw2) sw2.addEventListener('change', checkTPIStatus);

  const zeroBtn = document.getElementById('btn-zeroize');
  if (zeroBtn) zeroBtn.addEventListener('click', executeEmergencyZeroize);
}

// ZULU CLOCK
function initZuluClock() {
  const clockEl = document.getElementById('header-clock');
  function update() {
    const now = new Date();
    const utcHours = String(now.getUTCHours()).padStart(2, '0');
    const utcMins = String(now.getUTCMinutes()).padStart(2, '0');
    const utcSecs = String(now.getUTCSeconds()).padStart(2, '0');
    if (clockEl) {
      clockEl.textContent = `${utcHours}:${utcMins}:${utcSecs} Z`;
    }
  }
  update();
  setInterval(update, 1000);
}

// TAB NAVIGATION
function switchTab(tabId) {
  state.currentTab = tabId;

  document.querySelectorAll('.nav-tab').forEach((tab) => {
    tab.classList.remove('active');
    tab.setAttribute('aria-selected', 'false');
  });
  const activeTab = document.getElementById(`tab-${tabId}`);
  if (activeTab) {
    activeTab.classList.add('active');
    activeTab.setAttribute('aria-selected', 'true');
  }

  document.querySelectorAll('.view-panel').forEach((view) => {
    view.classList.remove('active');
  });
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) {
    targetView.classList.add('active');
  }
}

// REAL-TIME HARDWARE OSCILLOSCOPE RENDERER (DISPLAYS LIVE CADENCE STATE)
let scopeCanvas;
let scopeCtx;
const scopeBuffer = new Array(70).fill(1232);

function initOscilloscope() {
  scopeCanvas = document.getElementById('scopeCanvas');
  if (!scopeCanvas) return;
  scopeCtx = scopeCanvas.getContext('2d');

  function renderScope() {
    if (!scopeCtx) return;
    const w = scopeCanvas.width;
    const h = scopeCanvas.height;

    scopeCtx.fillStyle = '#020408';
    scopeCtx.fillRect(0, 0, w, h);

    scopeCtx.strokeStyle = 'rgba(0, 243, 255, 0.08)';
    scopeCtx.lineWidth = 1;

    for (let x = 0; x < w; x += 40) {
      scopeCtx.beginPath();
      scopeCtx.moveTo(x, 0);
      scopeCtx.lineTo(x, h);
      scopeCtx.stroke();
    }
    for (let y = 0; y < h; y += 30) {
      scopeCtx.beginPath();
      scopeCtx.moveTo(0, y);
      scopeCtx.lineTo(w, y);
      scopeCtx.stroke();
    }

    const baseLineY = h * 0.45;
    scopeCtx.strokeStyle = 'rgba(0, 255, 136, 0.3)';
    scopeCtx.setLineDash([4, 4]);
    scopeCtx.beginPath();
    scopeCtx.moveTo(0, baseLineY);
    scopeCtx.lineTo(w, baseLineY);
    scopeCtx.stroke();
    scopeCtx.setLineDash([]);

    scopeCtx.strokeStyle = '#00f3ff';
    scopeCtx.lineWidth = 2;
    scopeCtx.shadowColor = '#00f3ff';
    scopeCtx.shadowBlur = 8;
    scopeCtx.beginPath();

    const step = w / scopeBuffer.length;
    for (let i = 0; i < scopeBuffer.length; i++) {
      const isHigh = i % 2 === 0;
      const pulseY = isHigh ? baseLineY : h * 0.85;
      const x = i * step;
      if (i === 0) {
        scopeCtx.moveTo(x, pulseY);
      } else {
        scopeCtx.lineTo(x, pulseY);
      }
    }
    scopeCtx.stroke();
    scopeCtx.shadowBlur = 0;

    scopeCtx.fillStyle = '#00f3ff';
    scopeCtx.font = '10px monospace';
    scopeCtx.fillText(
      `FRAME SIZE: ${state.quantumBytes}B // CADENCE: ${state.cadenceMs}ms`,
      15,
      20
    );

    requestAnimationFrame(renderScope);
  }

  requestAnimationFrame(renderScope);
}

// SHANNON ENTROPY GAUGE (REFLECTS MEASURED BACKEND ENTROPY)
function updateEntropyGauge(measuredVal) {
  const meterBar = document.getElementById('gauge-meter-bar');
  const readOut = document.getElementById('gauge-entropy-val');
  const measured = document.getElementById('measured-entropy');
  const headerEntropy = document.getElementById('header-entropy');

  if (typeof measuredVal !== 'number' || Number.isNaN(measuredVal)) {
    if (readOut) readOut.textContent = '--';
    if (measured) measured.textContent = 'AWAITING LIVE TELEMETRY';
    if (headerEntropy) headerEntropy.textContent = 'H = --';
    return;
  }

  const formatted = measuredVal.toFixed(3);
  if (readOut) readOut.textContent = formatted;
  if (measured) measured.textContent = `${formatted} bits / byte`;
  if (headerEntropy) headerEntropy.textContent = `H = ${formatted} bits/B`;

  if (meterBar) {
    const maxH = 8.0;
    const pct = Math.max(0, Math.min(1, measuredVal / maxH));
    meterBar.style.strokeDashoffset = String(502 * (1 - pct));
  }
}

// SIMPLEX OPTICAL DIODE CHUNK MATRIX
function initDiodeMatrix() {
  const grid = document.getElementById('chunk-grid');
  if (!grid) return;
  grid.textContent = '';

  for (let i = 0; i < 10; i++) {
    const d = document.createElement('div');
    d.className = 'chunk-cell';
    d.id = `chunk-cell-${i}`;
    d.textContent = `D${i < 10 ? '0' + i : i}`;
    grid.appendChild(d);
  }
  for (let j = 0; j < 3; j++) {
    const p = document.createElement('div');
    p.className = 'chunk-cell parity';
    p.id = `chunk-cell-p${j}`;
    p.textContent = `P0${j}`;
    grid.appendChild(p);
  }
}

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// WEBAUTHN / FIDO2 LEVEL 3 HARDWARE PRESENCE
async function acquireWebAuthnL3Assertion() {
  try {
    const cRes = await fetch('/api/auth/webauthn/challenge');
    if (!cRes.ok) return null;
    const challengeData = await cRes.json();
    const challengeStr = challengeData.challenge;
    if (!challengeStr) return null;

    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
      return null;
    }

    const challengeBytes = new TextEncoder().encode(challengeStr);
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: challengeBytes,
        rpId: window.location.hostname || '127.0.0.1',
        userVerification: 'required',
        timeout: 15000,
      },
    });
    if (credential && credential.response) {
      return {
        credential_id: credential.id,
        authenticator_data_b64: arrayBufferToBase64(credential.response.authenticatorData),
        client_data_json_b64: arrayBufferToBase64(credential.response.clientDataJSON),
        signature_b64: arrayBufferToBase64(credential.response.signature),
      };
    }
    return null;
  } catch (err) {
    console.warn('Hardware WebAuthn L3 assertion unavailable or canceled', err);
    return null;
  }
}

async function postApiJson(url, bodyObj) {
  const assertion = await acquireWebAuthnL3Assertion();
  const payload = Object.assign({}, bodyObj || {});
  if (assertion) {
    payload.webauthn_assertion = assertion;
  }
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  return { ok: res.ok, status: res.status, data };
}

// IN-BAND CHAT SENDING
async function handleSendMsg(event) {
  event.preventDefault();
  const input = document.getElementById('msg-input');
  const text = input ? input.value.trim() : '';
  if (!text) return;

  const senderSelect = document.getElementById('chat-sender-select');
  const sender = senderSelect ? senderSelect.value : 'NORAD_ALPHA';

  appendChatMessage(sender, text);
  if (input) input.value = '';

  try {
    const { ok, status, data } = await postApiJson('/api/send', {
      sender,
      message: text,
    });
    if (!ok) {
      appendChatMessage('SYSTEM', `[REJECTED HTTP ${status}] ${data.error || data.status || 'Authorization denied'}`);
      return;
    }
    state.dataCells += 1;
    const dataEl = document.getElementById('metric-data-cells');
    if (dataEl) dataEl.textContent = String(state.dataCells);
    scopeBuffer[scopeBuffer.length - 1] = state.quantumBytes;

    if (data.reply) {
      const peer = sender === 'NORAD_ALPHA' ? 'PENTAGON_BRAVO' : 'NORAD_ALPHA';
      const simTag = data.simulated ? ' [SIMULATED]' : '';
      appendChatMessage(peer, `${data.reply}${simTag}`);
    }
  } catch (err) {
    appendChatMessage('SYSTEM', `[DISPATCH ERROR] Backend unreachable: ${err}`);
  }
}

function sendPreset(presetText) {
  const input = document.getElementById('msg-input');
  if (input && presetText) {
    input.value = presetText;
    const form = document.getElementById('chat-form');
    if (form) form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
  }
}

async function triggerEAMDirective() {
  const senderSelect = document.getElementById('chat-sender-select');
  const sender = senderSelect ? senderSelect.value : 'NORAD_ALPHA';
  const directive = 'DEFCON-1 AUTHORIZE STRATCOM STRIKE PACKAGE ALPHA';

  appendChatMessage(sender, `[NC3 EAM REQUEST SUBMITTED] ${directive}`);

  try {
    const { ok, status, data } = await postApiJson('/api/eam', {
      originator: sender,
      directive,
    });
    if (!ok) {
      appendChatMessage('SYSTEM', `[NC3 EAM REJECTED HTTP ${status}] ${data.error || data.status || 'Denied'}`);
      return;
    }
    const peer = sender === 'NORAD_ALPHA' ? 'PENTAGON_BRAVO' : 'NORAD_ALPHA';
    const digestPreview = data.authenticator_sha3_512
      ? data.authenticator_sha3_512.substring(0, 24)
      : 'UNAVAILABLE';
    const modeLabel = data.simulated
      ? `SIMULATED LAB FIXTURE (${data.dual_custody || 'UNVERIFIED'})`
      : `VERIFIED RELEASE (${data.dual_custody || '2-OF-2'})`;
    appendChatMessage(peer, `[NC3 EAM STATUS: ${data.status}] ${modeLabel} // SHA3: ${digestPreview}`);
  } catch (err) {
    appendChatMessage('SYSTEM', `[NC3 EAM ERROR] Backend unreachable: ${err}`);
  }
}

async function runZGDPTelemetry() {
  const senderSelect = document.getElementById('chat-sender-select');
  const sender = senderSelect ? senderSelect.value : 'NORAD_ALPHA';

  appendChatMessage(sender, '[ZGDP QUERY] Requesting Zero-Gap Defense Pipeline diagnostic sweep...');

  try {
    const { ok, status, data } = await postApiJson('/api/zgdp', {
      message: 'ZGDP_DIAGNOSTIC_FRAME',
    });
    if (!ok) {
      appendChatMessage('SYSTEM', `[ZGDP REJECTED HTTP ${status}] ${data.error || data.status || 'Denied'}`);
      return;
    }
    if (typeof data.shannon_entropy === 'number') {
      updateEntropyGauge(data.shannon_entropy);
    }
    appendChatMessage(
      'SYSTEM',
      `[ZGDP TELEMETRY: ${data.status}] Native Envelope: ${Boolean(data.rust_bare_metal_envelope)} // Cell: ${data.sealed_byte_length}B // H=${data.shannon_entropy} // Cadence: ${data.cadence_ms}ms`
    );
  } catch (err) {
    appendChatMessage('SYSTEM', `[ZGDP ERROR] Backend unreachable: ${err}`);
  }
}

function appendChatMessage(sender, text, isCoT = false) {
  const screen = document.getElementById('chat-screen');
  if (!screen) return;

  const now = new Date();
  const timeStr = now.toISOString().substring(11, 19) + 'Z';

  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-msg ${isCoT ? 'cot-msg' : ''}`;

  const header = document.createElement('div');
  header.className = 'msg-header';

  const senderSpan = document.createElement('span');
  senderSpan.className = `msg-sender ${String(sender).toLowerCase().includes('norad') ? 'norad' : 'pentagon'}`;
  senderSpan.textContent = `[${sender}]`;

  const tsSpan = document.createElement('span');
  tsSpan.className = 'msg-ts';
  tsSpan.textContent = `${timeStr} • SHA-384`;

  header.appendChild(senderSpan);
  header.appendChild(tsSpan);

  const textSpan = document.createElement('div');
  textSpan.className = 'msg-text';
  textSpan.textContent = String(text);

  msgDiv.appendChild(header);
  msgDiv.appendChild(textSpan);

  screen.appendChild(msgDiv);
  screen.scrollTop = screen.scrollHeight;
}

// CURSOR-ON-TARGET (COT) DISPATCHER (SAFE DOM, NO innerHTML)
async function handleSendCoT(event) {
  event.preventDefault();
  const callsignEl = document.getElementById('cot-callsign');
  const typeEl = document.getElementById('cot-type');
  const latEl = document.getElementById('cot-lat');
  const lonEl = document.getElementById('cot-lon');
  const altEl = document.getElementById('cot-alt');

  const callsign = callsignEl ? callsignEl.value.trim() : '';
  const type = typeEl ? typeEl.value : 'a-f-G-U-C';
  const lat = parseFloat(latEl ? latEl.value : '0');
  const lon = parseFloat(lonEl ? lonEl.value : '0');
  const alt = parseFloat(altEl ? altEl.value : '0') || 0;

  try {
    const { ok, status, data } = await postApiJson('/api/cot', {
      callsign,
      type,
      lat,
      lon,
      alt,
    });
    if (!ok) {
      appendChatMessage('TACTICAL_RADAR', `[COT REJECTED HTTP ${status}] ${data.error || data.status || 'Denied'}`, true);
      return;
    }

    const sigBadge = data.signature_verified ? 'ML-DSA-87 VERIFIED' : 'LOCAL DEMO (UNSIGNED)';
    appendChatMessage(
      'TACTICAL_RADAR',
      `COT BEACON: Callsign=${data.callsign || callsign} | Type=${type} | Pos=(${lat}, ${lon}, ${alt}m) | ${sigBadge}`,
      true
    );

    const trackList = document.getElementById('cot-tracks-list');
    if (trackList) {
      const item = document.createElement('div');
      item.className = 'cot-track-item';

      const callSpan = document.createElement('span');
      callSpan.className = 'track-call';
      callSpan.textContent = String(data.callsign || callsign);

      const coordsSpan = document.createElement('span');
      coordsSpan.className = 'track-coords';
      coordsSpan.textContent = `${lat}° N, ${lon}° W`;

      const badgeSpan = document.createElement('span');
      badgeSpan.className = data.signature_verified ? 'badge badge-green' : 'badge badge-yellow';
      badgeSpan.textContent = sigBadge;

      item.appendChild(callSpan);
      item.appendChild(coordsSpan);
      item.appendChild(badgeSpan);
      trackList.prepend(item);
    }
  } catch (err) {
    appendChatMessage('TACTICAL_RADAR', `[COT ERROR] Backend unreachable: ${err}`, true);
  }
}

// SIMPLEX OPTICAL DIODE BEAMING
async function handleSendDiode(event) {
  event.preventDefault();
  const fileEl = document.getElementById('diode-file-name');
  const redEl = document.getElementById('diode-redundancy');
  const statusEl = document.getElementById('diode-fec-status');
  const btn = document.getElementById('btn-send-diode');

  const fileName = fileEl ? fileEl.value.trim() : '';
  const redundancy = redEl ? redEl.value : '0.30';

  if (btn) btn.disabled = true;
  if (statusEl) {
    statusEl.textContent = 'DISPATCHING CAUCHY-RS FEC TRANSFER...';
    statusEl.className = 'badge badge-yellow';
  }

  try {
    const { ok, status, data } = await postApiJson('/api/diode/send', {
      fileName,
      redundancy,
    });
    if (!ok) {
      if (statusEl) {
        statusEl.textContent = `REJECTED (HTTP ${status})`;
        statusEl.className = 'badge badge-red';
      }
      appendChatMessage('SIMPLEX_DIODE', `[DIODE REJECTED HTTP ${status}] ${data.error || data.status || 'Denied'}`);
      return;
    }

    const total = data.chunks_total || 13;
    const label = data.simulated
      ? `SIMULATED EMULATION (${total}/${total} CHUNKS)`
      : `TRANSFER VERIFIED (${total}/${total} CHUNKS)`;
    if (statusEl) {
      statusEl.textContent = label;
      statusEl.className = data.simulated ? 'badge badge-yellow' : 'badge badge-green';
    }
    appendChatMessage('SIMPLEX_DIODE', `[${data.status}] File=${data.file || fileName}: ${data.notice || 'Complete'}`);
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = 'BACKEND UNREACHABLE';
      statusEl.className = 'badge badge-red';
    }
    appendChatMessage('SIMPLEX_DIODE', `[DIODE ERROR] ${err}`);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// SAS CONFIRMATION
function confirmSAS() {
  const btn = document.getElementById('btn-confirm-sas');
  if (btn) {
    btn.textContent = 'VERIFIED MUTUAL MATCH (LOCAL OPERATOR CONFIRMATION)';
    btn.className = 'btn btn-success';
    btn.disabled = true;
  }
}

// TWO-PERSON INTEGRITY (TPI) EMERGENCY ZEROIZE
function checkTPIStatus() {
  const s1 = document.getElementById('tpi-switch-1');
  const s2 = document.getElementById('tpi-switch-2');
  const stat1 = document.getElementById('tpi-status-1');
  const stat2 = document.getElementById('tpi-status-2');
  const zeroBtn = document.getElementById('btn-zeroize');

  state.tpiOfficer1 = s1 ? s1.checked : false;
  state.tpiOfficer2 = s2 ? s2.checked : false;

  if (stat1) {
    stat1.textContent = state.tpiOfficer1 ? 'ARMED (OFFICER 1 CONFIRMED)' : 'LOCKED (UNARMED)';
    stat1.className = state.tpiOfficer1 ? 'switch-status armed' : 'switch-status';
  }
  if (stat2) {
    stat2.textContent = state.tpiOfficer2 ? 'ARMED (OFFICER 2 CONFIRMED)' : 'LOCKED (UNARMED)';
    stat2.className = state.tpiOfficer2 ? 'switch-status armed' : 'switch-status';
  }

  if (zeroBtn) {
    zeroBtn.disabled = !(state.tpiOfficer1 && state.tpiOfficer2);
  }
}

async function executeEmergencyZeroize() {
  if (!confirm('Initiate NIST SP 800-88 3-Pass Emergency Sanitization on local volatile state files?')) {
    return;
  }

  const logBox = document.getElementById('zeroize-log');
  const outPre = document.getElementById('zeroize-output');
  if (logBox) logBox.classList.remove('hidden');

  let logs = '';
  function appendLog(line) {
    logs += `[${new Date().toISOString()}] ${line}\n`;
    if (outPre) outPre.textContent = logs;
  }

  appendLog('Submitting TPI dual-custody purge command to /api/zeroize...');
  try {
    const { ok, status, data } = await postApiJson('/api/zeroize', {
      confirm: 'ZEROIZE-ALL',
    });
    if (!ok) {
      appendLog(`PURGE REJECTED (HTTP ${status}): ${data.error || data.status || 'Authorization denied'}`);
      return;
    }
    appendLog(`STATUS: ${data.status} | VERDICT: ${data.verdict || ''}`);
    appendLog(`PURGED TARGETS: ${JSON.stringify(data.purged_targets || [])}`);

    const airgapBadge = document.getElementById('airgap-badge');
    if (airgapBadge && data.status === 'PURGE_COMPLETE') {
      airgapBadge.textContent = 'SYSTEM SANITIZED (ZEROIZED)';
      airgapBadge.className = 'status-pill badge-red';
    }
  } catch (err) {
    appendLog(`PURGE ERROR: Backend unreachable: ${err}`);
  }
}

// AUTOMATED DEFENSE DRILL
async function runAutomatedDrill() {
  if (state.drillRunning) return;
  state.drillRunning = true;

  const bar = document.getElementById('drill-status-bar');
  const textEl = document.getElementById('drill-status-text');
  const btn = document.getElementById('btn-run-drill');

  if (btn) btn.disabled = true;
  if (bar) bar.classList.remove('hidden');

  function setStep(msg) {
    if (textEl) textEl.textContent = msg;
  }

  try {
    setStep('EXECUTING BACKEND TWO-TERMINAL DEFENSE DRILL (/api/drill)...');
    const { ok, status, data } = await postApiJson('/api/drill', {});
    if (!ok) {
      setStep(`DRILL DENIED/FAILED (HTTP ${status}): ${data.error || data.status || 'Error'}`);
      return;
    }
    setStep(`DRILL RESULT: ${data.status}${data.details ? ' — ' + data.details : ''}`);
  } catch (err) {
    setStep(`DRILL ERROR: ${err}`);
  } finally {
    state.drillRunning = false;
    if (btn) btn.disabled = false;
  }
}

function closeDrillStatus() {
  const bar = document.getElementById('drill-status-bar');
  if (bar) bar.classList.add('hidden');
}

function setStatusPillText(pillEl, text, className) {
  if (!pillEl) return;
  pillEl.textContent = '';
  const dot = document.createElement('span');
  dot.className = 'pill-dot';
  pillEl.appendChild(dot);
  pillEl.appendChild(document.createTextNode(` ${text}`));
  pillEl.className = className;
}

// FETCH SERVER STATUS
async function fetchServerStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const data = await res.json();

    if (data.sas) {
      state.sas = String(data.sas);
      const sasEl = document.getElementById('display-sas');
      if (sasEl) sasEl.textContent = state.sas;
    }
    if (typeof data.entropy_shannon === 'number') {
      state.entropy = data.entropy_shannon;
      updateEntropyGauge(state.entropy);
    }
    if (typeof data.sent_cells === 'number') {
      state.sentCells = data.sent_cells;
      const sentEl = document.getElementById('metric-sent-cells');
      if (sentEl) sentEl.textContent = state.sentCells.toLocaleString();
    }
    if (typeof data.chaff_cells === 'number') {
      state.chaffCells = data.chaff_cells;
      const chaffEl = document.getElementById('metric-chaff-cells');
      if (chaffEl) chaffEl.textContent = state.chaffCells.toLocaleString();
    }
    if (typeof data.drops === 'number') {
      state.drops = data.drops;
      const dropsEl = document.getElementById('metric-drops');
      if (dropsEl) dropsEl.textContent = String(state.drops);
    }
    if (data.pcr_0) {
      const p0 = document.getElementById('pcr-0');
      if (p0) p0.textContent = String(data.pcr_0).substring(0, 19).toUpperCase();
    }
    if (data.pcr_7) {
      const p7 = document.getElementById('pcr-7');
      if (p7) p7.textContent = String(data.pcr_7).substring(0, 19).toUpperCase();
    }
    if (data.pcr_11) {
      const p11 = document.getElementById('pcr-11');
      if (p11) p11.textContent = String(data.pcr_11).substring(0, 19).toUpperCase();
    }
    if (data.mtls_profile) {
      const pivEl = document.getElementById('mtls-piv-badge');
      const details = data.mtls_profile.client_cert_details || {};
      if (data.mtls_profile.client_cert_present || details.valid) {
        const edipi = String(details.edipi || 'VERIFIED');
        setStatusPillText(pivEl, `CAC/PIV: ${edipi} (mTLS 1.3)`, 'status-pill green-pill');
      } else {
        setStatusPillText(pivEl, 'CAC/PIV: UNATTACHED', 'status-pill yellow-pill');
      }
    }
    if (data.webauthn_profile) {
      const wEl = document.getElementById('webauthn-badge');
      const count = Number(data.webauthn_profile.registered_credentials_count || 0);
      setStatusPillText(
        wEl,
        count > 0 ? `FIDO2 L3: ${count} KEY(S) REGISTERED` : 'FIDO2 L3: NO KEY REGISTERED',
        count > 0 ? 'status-pill green-pill' : 'status-pill yellow-pill'
      );
    }
  } catch (err) {
    console.debug('fetchServerStatus error', err);
  }
}
