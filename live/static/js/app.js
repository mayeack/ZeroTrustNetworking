/* Zero Trust Live: pages, live feed (server-sent events), timeline canvas, pipeline, triggers, settings. */
(function () {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const ST_ORDER = ['cilium:hubble:flow', 'cisco:isovalent:processConnect', 'cisco:isovalent:processExec', 'cisco:isovalent', 'ci:job:event', 'cisco:nexus:endpoint', 'cisco:nexus:liveprotect', 'cisco:nexus:config', 'cisco:dc:nd:advisories', 'cisco:dc:nd:anomalies', 'kube:apiserver:audit', 'zt:enforcement:audit'];
  const ST_COLOR = { 'cilium:hubble:flow': '#009CEB', 'cisco:isovalent:processConnect': '#00CDAF', 'cisco:isovalent:processExec': '#00CDAF', 'cisco:isovalent': '#00CDAF', 'ci:job:event': '#8C9BA5', 'cisco:nexus:endpoint': '#7B56DB', 'cisco:nexus:liveprotect': '#DD9900', 'cisco:nexus:config': '#7B56DB', 'cisco:dc:nd:advisories': '#DD9900', 'cisco:dc:nd:anomalies': '#7B56DB', 'kube:apiserver:audit': '#F1813F', 'zt:enforcement:audit': '#53A051' };
  const K_COLOR = { background: null, incident: '#ff4d7d', attack: '#ff9f43', trigger: '#f6e05e' };
  const WINDOW = 10 * 60 * 1000;
  const state = { events: [], lastSeq: 0, paused: false, filters: new Set(), kinds: new Set(), status: null, catalog: null, pipeline: null };
  const fmtT = (e) => e ? new Date(e * 1000).toISOString().substr(11, 8) : '';
  const clock = (e) => e ? new Date(e * 1000).toLocaleTimeString([], { hour12: false }) : '';

  // ---- navigation
  $$('.nav-link').forEach(a => a.addEventListener('click', (ev) => { ev.preventDefault(); goto(a.dataset.page); }));
  $$('[data-goto]').forEach(a => a.addEventListener('click', (ev) => { ev.preventDefault(); goto(a.dataset.goto); }));
  function goto(page) { $$('.nav-link').forEach(a => a.classList.toggle('active', a.dataset.page === page)); $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page)); }

  // ---- API
  async function api(path, method, body) {
    const r = await fetch(path, { method: method || 'GET', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({ error: 'bad response' }));
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  }
  function show(id, text, ok) {
    [id, id === 'r-fire' ? 'r-dash' : null].forEach(i => { const el = i && $('#' + i); if (!el) return; el.textContent = text; el.className = 'result ' + (ok ? 'ok' : 'err'); });
  }

  // ---- live feed
  function connect() {
    const es = new EventSource('/api/stream');
    es.onmessage = (m) => { try { push(JSON.parse(m.data)); } catch (e) { /* ignore */ } };
    es.onopen = () => setDot('running', 'Streaming');
    es.onerror = () => { setDot('error', 'Reconnecting'); };
  }
  function setDot(cls, text) { $('#dot').className = 'status-dot ' + cls; $('#dot-text').textContent = text; }
  function push(e) {
    state.events.push(e); state.lastSeq = e.seq;
    const cutoff = Date.now() - WINDOW - 60000;
    while (state.events.length && state.events[0].sent * 1000 < cutoff) state.events.shift();
    if (!state.paused) appendLine(e);
  }
  async function backfill() {
    const items = await api('/api/events?limit=1500');
    items.forEach(e => { state.events.push(e); state.lastSeq = e.seq; });
    renderLog();
  }

  // ---- events page
  function passes(e) { return (!state.filters.size || state.filters.has(e.sourcetype)) && (!state.kinds.size || state.kinds.has(e.kind)); }
  function lineEl(e) {
    const d = document.createElement('div'); d.className = 'line ' + e.kind;
    d.innerHTML = '<span>' + fmtT(e.t) + '</span><span class="st">' + e.sourcetype + '</span><span>' + escapeHtml(e.summary) + '</span>';
    return d;
  }
  function appendLine(e) {
    if (!passes(e)) return;
    const log = $('#log'); const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    log.appendChild(lineEl(e));
    while (log.children.length > 1200) log.removeChild(log.firstChild);
    if (atBottom) log.scrollTop = log.scrollHeight;
  }
  function renderLog() { const log = $('#log'); log.innerHTML = ''; state.events.slice(-1200).filter(passes).forEach(e => log.appendChild(lineEl(e))); log.scrollTop = log.scrollHeight; }
  function escapeHtml(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
  function buildChips() {
    const box = $('#ev-filters'); box.innerHTML = '';
    ST_ORDER.forEach(st => { const c = document.createElement('span'); c.className = 'chip'; c.textContent = st; c.style.borderColor = ST_COLOR[st]; c.onclick = () => { toggle(state.filters, st); c.classList.toggle('on'); renderLog(); }; box.appendChild(c); });
    ['incident', 'attack', 'trigger'].forEach(k => { const c = document.createElement('span'); c.className = 'chip'; c.textContent = k; c.style.borderColor = K_COLOR[k]; c.onclick = () => { toggle(state.kinds, k); c.classList.toggle('on'); renderLog(); }; box.appendChild(c); });
  }
  function toggle(set, v) { set.has(v) ? set.delete(v) : set.add(v); }
  $('#ev-pause').onclick = () => { state.paused = !state.paused; $('#ev-pause').textContent = state.paused ? 'Resume' : 'Pause'; if (!state.paused) renderLog(); };
  $('#ev-clear').onclick = () => { $('#log').innerHTML = ''; };

  // ---- timeline canvas
  const cv = $('#timeline'); const ctx = cv.getContext('2d');
  function drawTimeline() {
    const W = cv.clientWidth, H = 300; if (cv.width !== W * devicePixelRatio) { cv.width = W * devicePixelRatio; cv.height = H * devicePixelRatio; }
    ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const left = 210, right = W - 16, top = 14, rowH = (H - 40) / ST_ORDER.length;
    const now = Date.now(), t0 = now - WINDOW;
    ctx.font = '12px -apple-system, Helvetica, Arial'; ctx.textBaseline = 'middle';
    ST_ORDER.forEach((st, i) => {
      const y = top + i * rowH + rowH / 2;
      ctx.fillStyle = '#8b949e'; ctx.textAlign = 'right'; ctx.fillText(st, left - 10, y);
      ctx.strokeStyle = '#21262d'; ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
    });
    ctx.textAlign = 'center'; ctx.fillStyle = '#484f58';
    for (let m = 0; m <= 10; m += 2) { const x = left + (right - left) * (m / 10); ctx.fillText('-' + (10 - m) + 'm', x, H - 12); ctx.strokeStyle = '#161b22'; ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, H - 26); ctx.stroke(); }
    state.events.forEach(e => {
      const i = ST_ORDER.indexOf(e.sourcetype); if (i < 0) return;
      const x = left + (right - left) * ((e.t * 1000 - t0) / WINDOW); if (x < left || x > right) return;
      const y = top + i * rowH + rowH / 2;
      const special = K_COLOR[e.kind];
      ctx.fillStyle = special || ST_COLOR[e.sourcetype] || '#8b949e'; ctx.globalAlpha = special ? 1 : 0.55;
      ctx.beginPath(); ctx.arc(x, y, special ? 4 : 2.5, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
    });
    ctx.strokeStyle = '#f85149'; ctx.beginPath(); ctx.moveTo(right, top); ctx.lineTo(right, H - 26); ctx.stroke();
  }
  setInterval(drawTimeline, 1000);

  // ---- status / counts
  async function pollStatus() {
    try {
      const s = await api('/api/status'); state.status = s;
      $('#s-total').textContent = s.events_total.toLocaleString();
      $('#s-rate').textContent = Object.values(s.counts_last_minute).reduce((a, b) => a + b, 0);
      const st = s.state;
      $('#s-plan').textContent = st.plan_status + (st.plan_status === 'running' ? ' · attempt ' + st.plan_attempt : '');
      $('#s-plan-l').textContent = st.plan_status === 'running' ? 'incident, fired ' + clock(st.last_fire_epoch) : (st.last_fire_epoch > st.last_reset_epoch ? 'incident, fired ' + clock(st.last_fire_epoch) : 'no incident since the last reset');
      $('#s-owner').textContent = s.lease.mine ? 'this app' : (s.lease.holder || 'search head');
      $('#s-cp').textContent = s.checkpoint_age_s + 's';
      $('#speed-now').textContent = 'now: ' + st.speed; $('#rm-now').textContent = 'now: ' + st.response_mode; $('#am-now').textContent = 'now: ' + st.agent_mode;
      $('#owner-info').innerHTML = kv({ 'This app': s.owner, 'Lease holder': s.lease.holder || '(none)', 'Lease age': s.lease.age_s == null ? '–' : s.lease.age_s + ' s', 'Search head input': s.search_head_input_paused ? 'paused by this app (stack app ' + s.stack_version + ')' : 'active (honours the lease from 1.0.3)', 'Ticks': s.tick_count + (s.last_error ? ' · last error: ' + s.last_error : ''), 'Last tick': JSON.stringify(s.last_tick) });
      $('#endpoints').innerHTML = kv({ 'Splunk': s.splunk_url, 'HEC': s.hec_url, 'Emulator': s.emulator_url, 'Stack app': s.stack_version });
      const tb = $('#counts tbody'); tb.innerHTML = '';
      ST_ORDER.forEach(stn => { if (!s.counts_total[stn] && !s.counts_last_minute[stn]) return; const tr = document.createElement('tr'); tr.innerHTML = '<td style="color:' + ST_COLOR[stn] + '">' + stn + '</td><td class="num">' + (s.counts_last_minute[stn] || 0) + '</td><td class="num">' + (s.counts_total[stn] || 0).toLocaleString() + '</td>'; tb.appendChild(tr); });
      $('#link-splunk').href = s.splunk_url.replace(':8089', '') + '/en-US/app/zt_incident_demo/zt_home';
      $('#link-timeline').href = s.splunk_url.replace(':8089', '') + '/en-US/app/zt_incident_demo/zt_incident_timeline';
      $('#link-approvals').href = s.splunk_url.replace(':8089', '') + '/en-US/app/zt_incident_demo/zt_enforcement_approvals';
      if (s.last_error) setDot('error', 'Tick error'); else if ($('#dot').classList.contains('error') && !s.last_error) setDot('running', 'Streaming');
    } catch (e) { setDot('error', 'API unreachable'); }
  }
  function kv(o) { return Object.entries(o).map(([k, v]) => '<b>' + escapeHtml(k) + '</b><span>' + escapeHtml(v) + '</span>').join(''); }

  // ---- pipeline
  function step(done, name, detail) { return '<div class="step ' + (done ? 'done' : '') + '"><span class="mark">' + (done ? '✓' : '…') + '</span><span class="name">' + name + '</span><span class="detail">' + escapeHtml(detail || '') + '</span></div>'; }
  function renderPipeline(p) {
    const box = $('#pipeline');
    if (!p.incident && !(p.attacks || []).length) { box.innerHTML = '<p class="muted">No incident since the last reset. Fire it, then watch the steps fill in.</p>'; return; }
    let h = '';
    const inc = p.incident;
    if (inc) {
      h += '<h4>CI runner incident · fired ' + clock(inc.t0) + '</h4>';
      h += step(true, 'Fired', 'job 88213 · attempt ' + inc.attempt + ' · ' + inc.plan_status);
      h += step(+inc.risk_count >= 2, 'Risk events', inc.risk_count ? inc.risk_count + ' signals, risk ' + inc.risk_total + ' at ' + clock(inc.risk_at) : 'next detection run');
      h += step(+inc.finding_count > 0, 'Finding group', inc.finding_count > 0 ? 'risk ' + inc.finding_risk + ' at ' + clock(inc.finding_at) : 'after both risk events');
      h += step(+inc.brief_count > 0, 'Agent brief', inc.brief_count > 0 ? (inc.investigation_id || '') + ' · ' + (inc.disposition || '') + ' at ' + clock(inc.brief_at) : 'ZTFlowInvestigator runs on the finding');
      h += step(!!inc.request_id, 'Quarantine request', inc.request_id ? inc.request_id + ' · ' + inc.status : 'after the brief');
      h += step(+inc.applied_epoch > 0, 'Approved and applied', inc.applied_epoch > 0 ? 'applied ' + clock(inc.applied_epoch) : 'approve on the Enforcement Approvals page (or in SOAR)');
      h += step(+inc.dropped > 0, 'Retries dropped', inc.dropped > 0 ? inc.dropped + ' dropped, first ' + clock(inc.first_drop) : 'the next attempt after the policy');
      h += step(+inc.verified_epoch > 0, 'Verified', inc.verified_epoch > 0 ? clock(inc.verified_epoch) + ' · investigation resolved' : 'a minute after the first drop');
      h += step(inc.job_status === 'failed', 'CI job', inc.job_status ? inc.job_status + (inc.job_failure ? ' (' + inc.job_failure + ')' : '') : 'running');
    }
    (p.attacks || []).forEach(a => {
      h += '<h4>Path attack · ' + escapeHtml(a.workload) + ' → ' + escapeHtml(a.dest_workload) + ' · ' + a.status + ' · attempt ' + a.attempt + '</h4>';
      h += step(+a.risk_count >= 2, 'Risk events', a.risk_count ? a.risk_count + ' signals, risk ' + a.risk_total : 'next detection run');
      h += step(+a.finding_count > 0, 'Finding group', a.finding_count > 0 ? 'risk ' + a.finding_risk + ' at ' + clock(a.finding_at) : '');
      h += step(+a.brief_count > 0, 'Agent brief', a.brief_count > 0 ? (a.investigation_id || '') + ' · ' + (a.disposition || '') : '');
      h += step(!!a.request_id, 'Quarantine request', a.request_id ? a.request_id + ' · ' + a.status_req : '');
      h += step(+a.dropped > 0, 'Retries dropped', a.dropped > 0 ? a.dropped + ' dropped' : '');
      h += step(+a.verified_epoch > 0, 'Verified', a.verified_epoch > 0 ? clock(a.verified_epoch) : '');
    });
    box.innerHTML = h;
  }
  async function pollPipeline() { try { const p = await api('/api/pipeline'); (p.attacks || []).forEach(a => { a.status_req = a.status; }); state.pipeline = p; renderPipeline(p); } catch (e) { /* keep last */ } }
  async function pollAttacks() {
    try {
      const rows = await api('/api/attacks'); const box = $('#attacks');
      if (!rows.length) { box.innerHTML = '<p class="muted">None running.</p>'; return; }
      box.innerHTML = rows.slice(0, 6).map(r => '<div class="attack"><div class="top"><b>' + escapeHtml(r.src_workload) + ' → ' + escapeHtml(r.dest_workload) + '</b><span class="pill">' + r.status + '</span></div><div class="muted">' + escapeHtml(r.program) + ' from ' + escapeHtml(r.src_pod) + ' · attempt ' + r.attempt + ' · dropped ' + r.dropped_attempts + ' · started ' + clock(r.t0) + '</div>' + (r.status === 'running' ? '<div class="row" style="margin-top:6px"><button class="btn small" data-stop="' + escapeHtml(r._key) + '">Stop</button></div>' : '') + '</div>').join('');
      $$('[data-stop]').forEach(b => b.onclick = async () => { b.disabled = true; try { await api('/api/attacks/' + encodeURIComponent(b.dataset.stop) + '/stop', 'POST'); } catch (e) { alert(e.message); } pollAttacks(); });
    } catch (e) { /* ignore */ }
  }

  // ---- triggers
  async function loadCatalog() {
    const c = await api('/api/catalog'); state.catalog = c;
    const wlOpts = c.workloads.map(w => '<option value="' + w.key + '">' + w.key + '</option>').join('');
    const stOpts = c.stores.map(s => '<option value="' + s.key + '">' + s.key + ' :' + s.port + ' (' + s.data_class + ')</option>').join('');
    const prOpts = c.programs.map(p => '<option>' + p + '</option>').join('');
    ['pa-src', 'af-src', 'pc-src', 'en-target'].forEach(id => { $('#' + id).innerHTML = wlOpts; });
    ['pa-dest', 'af-dest', 'pc-dest'].forEach(id => { $('#' + id).innerHTML = stOpts; });
    ['pa-prog', 'pc-prog'].forEach(id => { $('#' + id).innerHTML = '<option value="">(program of the workload)</option>' + prOpts; });
    $('#pc-prog').value = '/usr/bin/curl';
    $('#lp-switch').innerHTML = c.switches.map(s => '<option>' + s + '</option>').join(''); $('#nc-device').innerHTML = $('#lp-switch').innerHTML;
    $('#en-point').innerHTML = c.points.map(p => '<option>' + p + '</option>').join('');
    $('#en-by').innerHTML = c.approvers.map(a => '<option value="' + a.user + '">' + a.user + ' (' + a.label + ')</option>').join('');
    const pick = (id, v) => { const el = $('#' + id); if ([...el.options].some(o => o.value === v)) el.value = v; };
    pick('pa-src', 'ml-notebooks/jupyter'); pick('af-src', 'data-eng/spark-driver'); pick('pc-src', 'observability/log-shipper'); pick('en-target', 'platform/jump-host');
  }
  const paramsFor = {
    path_attack: () => ({ src_workload: $('#pa-src').value, dest_workload: $('#pa-dest').value, program: $('#pa-prog').value, max_attempts: +$('#pa-max').value }),
    audit_flow: () => ({ src_workload: $('#af-src').value, dest_workload: $('#af-dest').value }),
    program_connect: () => ({ src_workload: $('#pc-src').value, dest_workload: $('#pc-dest').value, program: $('#pc-prog').value }),
    liveprotect: () => ({ switch: $('#lp-switch').value }),
    nexus_config: () => ({ device: $('#nc-device').value, user: $('#nc-user').value, change: $('#nc-change').value }),
    enforcement: () => ({ point: $('#en-point').value, target_workload: $('#en-target').value, approved_by: $('#en-by').value, comment: $('#en-comment').value }),
  };
  async function fire(btn) { await act(btn, '/api/fire', null, 'r-fire', (j) => j.result + ' at ' + j.t0_iso + ' · ' + j.next); }
  async function reset(btn) {
    // two clicks within 5 s instead of a native dialog: releases the quarantine, cancels open requests, stamps a new run
    if (btn.dataset.armed !== '1') {
      btn.dataset.label = btn.dataset.label || btn.textContent; btn.dataset.armed = '1'; btn.textContent = 'Click again to reset';
      setTimeout(() => { btn.dataset.armed = ''; btn.textContent = btn.dataset.label; }, 5000); return;
    }
    btn.dataset.armed = ''; btn.textContent = btn.dataset.label;
    await act(btn, '/api/reset', null, 'r-fire', (j) => j.result + ' · released ' + j.released_policies + ' · cancelled ' + j.cancelled_requests + (j.note ? ' · ' + j.note : ''));
  }
  async function act(btn, path, body, rid, fmt) {
    btn.disabled = true; show(rid, 'sending…', true);
    try { const j = await api(path, 'POST', body); show(rid, fmt(j), true); pollPipeline(); pollAttacks(); pollStatus(); }
    catch (e) { show(rid, e.message, false); }
    btn.disabled = false;
  }
  $$('[data-trigger]').forEach(b => b.onclick = async () => {
    const k = b.dataset.trigger;
    if (k === 'fire') return fire(b);
    if (k === 'reset') return reset(b);
    await act(b, '/api/trigger/' + k, paramsFor[k](), 'r-' + k, (j) => j.result + ' (' + j.events + ' events) · ' + j.next);
  });
  $('#btn-fire').onclick = () => fire($('#btn-fire')); $('#btn-reset').onclick = () => reset($('#btn-reset'));
  $$('[data-speed]').forEach(b => b.onclick = () => act(b, '/api/speed', { value: b.dataset.speed }, 'r-speed', (j) => JSON.stringify(j)));
  $$('[data-config]').forEach(b => b.onclick = () => act(b, '/api/config', JSON.parse(b.dataset.config), 'r-config', (j) => 'now ' + JSON.stringify(j)));
  $('#btn-health').onclick = async () => { show('r-health', 'checking…', true); try { const s = await api('/api/status?health=1'); show('r-health', 'emulator: ' + s.health.emulator + '\nHEC: ' + s.health.hec, true); } catch (e) { show('r-health', e.message, false); } };

  // ---- boot
  buildChips(); backfill().catch(() => {}); connect(); loadCatalog().catch(e => show('r-path_attack', 'catalog: ' + e.message, false));
  pollStatus(); pollPipeline(); pollAttacks();
  setInterval(pollStatus, 5000); setInterval(pollPipeline, 10000); setInterval(pollAttacks, 15000);
})();
