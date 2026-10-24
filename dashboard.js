(function(){
'use strict';
const API = location.origin;
let currentTarget = null;
let currentView = 'overview';
let allTargets = [];

// Triage state local storage key builders
const getStarKey = (host) => `triage_star_${currentTarget}_${host}`;
const getIgnoreKey = (host) => `triage_ignore_${currentTarget}_${host}`;

// Triage filter states
let triagePriorityFilter = 'all';
let triageTextFilter = '';
let triageHideIgnored = true;
let huntQueueItems = [];

// Cockpit (Phase 1/2): current filtered rows, keyboard cursor, selected asset
let triageVisible = [];
let triageCursor = -1;
let selectedHost = null;

// Finding-model filters (Phase 3b): filter the queue by finding tier / verdict
let triageTierFilter = 'all';          // all | confirmed | suspicious | observation
let triageHideDismissed = false;       // hide assets whose findings are all false-positive / wont-fix
const DISMISSED_VERDICTS = ['false_positive', 'wont_fix'];

// Hunt Queue rendering is chunked: only the first TRIAGE_RENDER_STEP rows are
// put in the DOM, "Show more" (or the j/k cursor) extends it. Thousands of rows
// at once froze phones.
const TRIAGE_RENDER_STEP = 100;
let triageRenderLimit = TRIAGE_RENDER_STEP;
// Hosts whose (not-downloaded) findings match the text filter, from the server.
let triageSearchHosts = null;
let triageSearchFor = '';
let triageSearchTimer = null;

// Historical filters
let histActiveTab = 'interesting';
let histTextQuery = '';
let histHostQuery = '';
let histExtQuery = '';
let histHideStatic = true;
let histHide404 = true;
let histHideDupes = true;
let histCurrentPage = 0;
let histPageSize = 50;
let histTotalItems = 0;

// WebApps filters
let webappsTextQuery = '';
let webappsStatusQuery = '';
let webappsHideDupes = true;

// Raw files
let rawFilesList = [];
let activeRawFile = null;

// Controls registry
const allCtrls = [];
const filterHandlers = {};

// Helper APIs
async function fetchJSON(p){try{const r=await fetch(API+p);if(!r.ok)return null;return await r.json()}catch{return null}}
async function fetchText(p){try{const r=await fetch(API+p);if(!r.ok)return'';return await r.text()}catch{return''}}
async function postJSON(p,body){try{const r=await fetch(API+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return await r.json()}catch{return null}}
function T(p){return `/api/file/${currentTarget}/${p}`}

// HTML-escape for text AND attribute contexts (quotes included: target data such
// as archived URLs routinely contains " and ').
const ESC_MAP={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(s){return (s == null ? '' : String(s)).replace(/[&<>"']/g,c=>ESC_MAP[c])}
// A string literal for use inside an inline on*="..." handler. Entity-escaping
// alone is not enough there (the browser decodes &#39; back to ' before the JS
// runs), so JSON-encode first, then HTML-escape.
function jsq(s){return esc(JSON.stringify(s == null ? '' : String(s)))}
function parseLines(t){return t.split('\n').map(l=>l.strip ? l.strip() : l.trim()).filter(Boolean)}

// ── Toasts (surface failures instead of swallowing them) ──
function toast(msg, type = 'info', timeout = 4000) {
  let host = document.getElementById('toast-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toast-host';
    document.body.appendChild(host);
  }
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  host.appendChild(el);
  // force reflow then show, so the CSS transition runs
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 250);
  }, timeout);
}
window.toast = toast;

// ── Server-side triage state (star / ignore) — localStorage is fallback only ──
let triageStarred = new Set();
let triageIgnored = new Set();

async function loadTriageState() {
  triageStarred = new Set();
  triageIgnored = new Set();
  const data = await fetchJSON(`/api/triage?target=${encodeURIComponent(currentTarget)}`);
  if (data) {
    (data.starred || []).forEach(h => triageStarred.add(h));
    (data.ignored || []).forEach(h => triageIgnored.add(h));
  } else {
    // Fallback: rebuild from localStorage cache if the server is unreachable
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(`triage_star_${currentTarget}_`) && localStorage.getItem(k) === 'true') {
          triageStarred.add(k.slice(`triage_star_${currentTarget}_`.length));
        }
        if (k && k.startsWith(`triage_ignore_${currentTarget}_`) && localStorage.getItem(k) === 'true') {
          triageIgnored.add(k.slice(`triage_ignore_${currentTarget}_`.length));
        }
      }
    } catch (e) {}
  }
}

async function persistTriage() {
  const body = {
    target: currentTarget,
    starred: [...triageStarred],
    ignored: [...triageIgnored]
  };
  const res = await postJSON('/api/triage', body);
  if (!res?.ok) toast('Could not save triage state to server (kept locally).', 'warn');
}

const isStarred = (host) => triageStarred.has(host);
const isIgnored = (host) => triageIgnored.has(host);

function sBadge(c){const n=parseInt(c);if(!n)return'<span class="st st-x">--</span>';const k=n<300?'2':n<400?'3':n<500?'4':'5';return`<span class="st st-${k}">${n}</span>`}
function hilite(text,q){if(!q)return esc(text);const re=new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`,'gi');return (text == null ? '' : String(text)).split(re).map((p,i)=>i%2?`<span class="hl">${esc(p)}</span>`:esc(p)).join('')}

// ── Paged table registry (shared by makeServerTable) ──
let _pagId = 0;
const _pagRegistry = {};
// ── Server-paged table ──
// Table markup + sort/pager controls, but the server filters, sorts and
// slices (see /api/data/*), so only one page ever reaches the browser. Large
// scopes used to download and parse whole result files here, which was slow
// on the Pi and crashed mobile browsers.
//   urlFn(params) -> request URL, params = {page, pageSize, sort, dir, ...args}
//   renderRowFn(item, index, args) -> '<tr>…</tr>'
function makeServerTable(containerId, urlFn, columns, renderRowFn, opts = {}) {
  const pageSize = opts.pageSize || 50;
  let page = 0, sortBy = null, sortAsc = true, args = opts.args || {};
  let total = 0, seq = 0, timer = null;
  const id = _pagId++;

  async function render() {
    const el = document.getElementById(containerId);
    if (!el) return;
    const mySeq = ++seq;
    const params = { page, pageSize, ...args };
    if (sortBy) { params.sort = sortBy; params.dir = sortAsc ? 'asc' : 'desc'; }
    if (!el.querySelector('table')) el.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    const res = await fetchJSON(urlFn(params));
    if (mySeq !== seq) return;                    // a newer request superseded this one
    if (!res) {
      el.innerHTML = '<div class="empty">Error fetching data.</div>';
      toast('Failed to load data from the server.', 'err');
      return;
    }
    total = res.total || 0;
    page = res.page || 0;
    const items = res.items || [];
    const start = page * pageSize;
    const pages = Math.ceil(total / pageSize) || 1;

    let h = `<table><thead><tr>`;
    columns.forEach(col => {
      const arrow = sortBy === col.key ? (sortAsc ? ' ▴' : ' ▾') : '';
      h += `<th style="${col.style || ''}" onclick="_tblSort(${id}, '${col.key}')">${col.label}${arrow}</th>`;
    });
    h += `</tr></thead><tbody>`;
    if (!items.length) {
      h += `<tr><td colspan="${columns.length}" style="text-align:center;color:var(--muted);padding:2rem;">No matching items found.</td></tr>`;
    } else {
      items.forEach((item, i) => { h += renderRowFn(item, start + i, args); });
    }
    h += `</tbody></table><div class="tbl-foot">`;
    h += `<span>Showing ${total === 0 ? 0 : start + 1}–${Math.min(start + pageSize, total)} of ${total.toLocaleString()} entries</span>`;
    if (pages > 1) {
      h += `<div style="display:flex;gap:4px;">`;
      h += `<button class="btn btn-sm" onclick="_tblPage(${id}, 'prev')" ${page === 0 ? 'disabled' : ''}>Prev</button>`;
      h += `<button class="btn btn-sm" onclick="_tblPage(${id}, 'next')" ${page >= pages - 1 ? 'disabled' : ''}>Next</button>`;
      h += `</div>`;
    }
    h += `</div>`;
    el.innerHTML = h;
    if (opts.onTotal) opts.onTotal(total);
  }

  function filter(newArgs) {
    args = { ...args, ...newArgs };
    page = 0;
    clearTimeout(timer);
    timer = setTimeout(render, 200);              // debounce typing
  }

  // One live table per container: drop the previous one's registry entry.
  for (const k of Object.keys(_pagRegistry)) {
    if (_pagRegistry[k].containerId === containerId) delete _pagRegistry[k];
  }
  _pagRegistry[id] = {
    containerId,
    sortData(key) {
      if (sortBy === key) sortAsc = !sortAsc; else { sortBy = key; sortAsc = true; }
      page = 0; render();
    },
    prev() { if (page > 0) { page--; render(); } },
    next() { if ((page + 1) * pageSize < total) { page++; render(); } },
    render
  };
  return { render, filter, count: () => total };
}

// Single-column server-paged list over one target file (JS / Dorks / subs).
function renderServerList(containerId, file, label, searchGetter) {
  const q = (searchGetter() || '').toLowerCase();
  const ctrl = makeServerTable(
    containerId,
    (p) => `/api/data/list?${new URLSearchParams({ target: currentTarget, file, ...p })}`,
    [{ key: 'value', label }],
    (v, _i, a) => `<tr><td class="wrap-cell">${hilite(v, a.q || '')}</td></tr>`,
    { args: { q } }
  );
  ctrl.render();
  return { render: ctrl.render, filter: (text) => ctrl.filter({ q: text }), count: ctrl.count };
}

// Fill tab badges from server line counts: {elementId: relativeFile}.
async function fillTabCounts(map) {
  const files = [...new Set(Object.values(map))];
  const res = await fetchJSON(`/api/data/counts?${new URLSearchParams({ target: currentTarget, files: files.join(',') })}`);
  const counts = res?.counts || {};
  for (const [elId, file] of Object.entries(map)) {
    const el = document.getElementById(elId);
    if (el) el.textContent = (counts[file] || 0).toLocaleString();
  }
  return counts;
}

window._tblSort = (id, key) => _pagRegistry[id]?.sortData(key);
window._tblPage = (id, dir) => {
  if (dir === 'prev') _pagRegistry[id]?.prev();
  if (dir === 'next') _pagRegistry[id]?.next();
};

// Copy helper
window.copyToClipboard = (text, btn) => {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = btn.textContent;
    btn.textContent = 'copied!';
    btn.style.color = 'var(--good)';
    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.color = '';
    }, 1200);
  });
};

// ── Explorer Screen ──
async function loadExplorer() {
  const data = await fetchJSON('/api/targets');
  allTargets = data?.targets || [];
  renderTargets(allTargets);
  checkScanStatus();
  loadScanTracker();
  startScanTrackerPoll();
}

// ── Explorer scan tracker (live multi-target run board) ──
let scanTrackerTimer = null;
let scanDetailTarget = null;
let scanDetailTimer = null;

function _fmtElapsed(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec / 60), s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function _explorerVisible() {
  const el = document.getElementById('explorer-screen');
  return el && el.offsetParent !== null;
}

async function loadScanTracker() {
  const panel = document.getElementById('scan-tracker');
  const grid = document.getElementById('scan-tracker-grid');
  const meta = document.getElementById('scan-tracker-meta');
  if (!panel || !grid) return false;
  const data = await fetchJSON('/api/scans/active');
  const runs = data?.runs || [];
  if (!runs.length) { panel.hidden = true; return false; }
  panel.hidden = false;
  const active = data.active || 0;
  meta.textContent = `${active} running · cap ${data.max_concurrent}`;

  let h = '';
  runs.forEach(r => {
    const running = r.running;
    const failed = !running && r.returncode && r.returncode !== 0;
    const state = running ? 'running' : (failed ? 'failed' : 'done');
    const pct = running ? (r.progress_percent || 0) : 100;
    h += `<div class="scan-card ${running ? 'running' : ''}" onclick="openScanDetail(${jsq(r.target)})">`;
    h += `<div class="scan-card-top">`;
    h += `<span class="scan-dot ${state}"></span>`;
    h += `<span class="scan-card-host">${esc(r.domain || r.target)}</span>`;
    h += `<span class="scan-card-kind">${esc(r.kind || 'scan')}</span>`;
    h += `</div>`;
    h += `<div class="scan-card-step">${esc(running ? (r.current_step || 'Working…') : (failed ? 'Stopped / failed' : 'Completed'))}</div>`;
    h += `<div class="scan-prog"><div class="scan-prog-fill ${failed ? 'failed' : (running ? '' : 'done')}" style="width:${pct}%"></div></div>`;
    h += `<div class="scan-card-foot"><span>${_fmtElapsed(r.elapsed)}</span><span>${running ? pct + '%' : (failed ? 'code ' + r.returncode : 'done')}</span></div>`;
    h += `</div>`;
  });
  grid.innerHTML = h;
  return runs.some(r => r.running);
}

function startScanTrackerPoll() {
  if (scanTrackerTimer) return;
  scanTrackerTimer = setInterval(async () => {
    if (document.hidden) return;                 // no polling while backgrounded
    if (!_explorerVisible()) { stopScanTrackerPoll(); return; }
    const anyRunning = await loadScanTracker();
    // Keep polling while runs are active OR the detail drawer is open.
    if (!anyRunning && !scanDetailTarget) stopScanTrackerPoll();
  }, 2500);
}
function stopScanTrackerPoll() {
  if (scanTrackerTimer) { clearInterval(scanTrackerTimer); scanTrackerTimer = null; }
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  if (scanDetailTarget) refreshScanDetail();
});

window.openScanDetail = function(target) {
  scanDetailTarget = target;
  document.getElementById('scan-detail').classList.add('open');
  document.getElementById('scan-detail-host').textContent = target;
  refreshScanDetail();
  if (scanDetailTimer) clearInterval(scanDetailTimer);
  scanDetailTimer = setInterval(() => { if (!document.hidden) refreshScanDetail(); }, 2000);
  startScanTrackerPoll();
};

window.closeScanDetail = function() {
  document.getElementById('scan-detail').classList.remove('open');
  scanDetailTarget = null;
  if (scanDetailTimer) { clearInterval(scanDetailTimer); scanDetailTimer = null; }
};

async function refreshScanDetail() {
  if (!scanDetailTarget) return;
  const prog = await fetchJSON(`/api/scan/progress?target=${encodeURIComponent(scanDetailTarget)}`);
  if (!prog) return;
  const sub = document.getElementById('scan-detail-sub');
  const stopBtn = document.getElementById('scan-detail-stop');
  const done = (prog.stages || []).filter(s => s.status === 'done').length;
  sub.textContent = `${prog.running ? 'Running' : 'Idle'} · ${done}/${(prog.stages || []).length} stages · ${prog.progress_percent || 0}%`;
  if (stopBtn) stopBtn.hidden = !prog.running;

  const tl = document.getElementById('scan-detail-timeline');
  let h = '';
  (prog.stages || []).forEach(s => {
    const mark = s.status === 'done' ? '✓' : (s.status === 'active' ? '' : '');
    const dur = s.seconds != null ? `${s.seconds}s` : '';
    h += `<div class="stage-row ${s.status}">`;
    h += `<span class="stage-mark">${mark}</span>`;
    h += `<span class="stage-label">${esc(s.label)}</span>`;
    h += `<span class="stage-dur">${dur}</span>`;
    h += `</div>`;
  });
  tl.innerHTML = h;

  const logEl = document.getElementById('scan-detail-log');
  const wasBottom = isNearBottom(logEl);
  logEl.textContent = (prog.log_tail || []).join('\n');
  if (wasBottom) logEl.scrollTop = logEl.scrollHeight;

  if (!prog.running && scanDetailTimer) {
    // one final paint, then stop polling the detail view
    clearInterval(scanDetailTimer); scanDetailTimer = null;
  }
}

window.stopScanTarget = async function(target, btn) {
  if (!target) return;
  if (btn) btn.disabled = true;
  const res = await postJSON('/api/scan/stop', { target });
  toast(res?.message || 'Stop requested', res?.ok ? 'ok' : 'err');
  loadScanTracker();
  refreshScanDetail();
};

function renderTargets(targets) {
  const el = document.getElementById('targets-container');
  if (!targets.length) {
    el.innerHTML = '<div class="empty">No targets found. Run a scan to register your first project.</div>';
    return;
  }
  let h = '';
  for (const t of targets) {
    const s = t.stats || {};
    const date = t.scan_date ? new Date(t.scan_date).toLocaleDateString() : '';
    const mon = t.monitor_enabled;

    h += `<div class="target-card" onclick="openTarget(${jsq(t.name)})">`;
    h += `<div class="tc-info">`;
    h += `<div class="tc-domain">${esc(t.domain || t.name)}</div>`;
    h += `<div class="tc-stats">`;
    if (date) h += `<span>Scanned: <b>${date}</b></span>`;
    if (s.total_subdomains) h += `<span>Subs: <b>${s.total_subdomains}</b></span>`;
    if (s.alive_services) h += `<span>Alive: <b>${s.alive_services}</b></span>`;
    if (s.open_ports) h += `<span>Ports: <b>${s.open_ports}</b></span>`;
    if (s.dork_findings) h += `<span>Dorks: <b style="color:var(--accent)">${s.dork_findings}</b></span>`;
    h += `</div></div>`;
    h += `<div class="tc-actions">`;
    h += `<button class="btn btn-sm btn-accent" onclick="event.stopPropagation(); openTarget(${jsq(t.name)})">Open</button>`;
    h += `<label class="chk-label" onclick="event.stopPropagation()">`;
    h += `<input type="checkbox" ${mon ? 'checked' : ''} onchange="event.stopPropagation(); toggleMonitor(${jsq(t.name)}, this.checked)"/> Monitor`;
    h += `</label>`;
    h += `</div></div>`;
  }
  el.innerHTML = h;
}

window.filterTargets = function(q) {
  q = q.toLowerCase();
  const f = q ? allTargets.filter(t => (t.name + ' ' + t.domain).toLowerCase().includes(q)) : allTargets;
  renderTargets(f);
};

window.showExplorer = function() {
  currentTarget = null;
  document.getElementById('explorer-screen').style.display = 'flex';
  loadExplorer();
};

// ── Target Switch View ──
window.switchView = function(viewId) {
  currentView = viewId;
  document.querySelectorAll('.sidebar-nav li').forEach(item => item.classList.remove('on'));
  document.getElementById('nav-' + viewId)?.classList.add('on');

  document.querySelectorAll('.content > .view').forEach(sec => sec.classList.remove('on'));
  document.getElementById('view-' + viewId)?.classList.add('on');

  if (viewId === 'overview') {
    renderOverview();
  } else if (viewId === 'triage') {
    renderTriageList();
  } else if (viewId === 'triagereport') {
    loadTriageReport();
  } else if (viewId === 'assets') {
    loadAssetsSection();
  } else if (viewId === 'webapps') {
    loadWebApps();
  } else if (viewId === 'screenshots') {
    loadScreenshots();
  } else if (viewId === 'historical') {
    loadHistoricalSection();
  } else if (viewId === 'js') {
    loadJSSection();
  } else if (viewId === 'ports') {
    loadPortsSection();
  } else if (viewId === 'dorks') {
    loadDorksSection();
  } else if (viewId === 'diff') {
    loadDiffSection();
  } else if (viewId === 'monitor') {
    loadMonitor();
  } else if (viewId === 'logs') {
    loadLogsSection();
  } else if (viewId === 'rawfiles') {
    loadRawFilesSection();
  }
};

// ── Navigation & Section Tabs ──
function switchSectionSubTab(secId, tabKey) {
  const container = document.getElementById('view-' + secId);
  if (!container) return;
  container.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('on'));
  container.querySelector(`#tab-${secId}-${tabKey}`)?.classList.add('on');

  if (secId === 'assets') {
    assetsActiveTab = tabKey;
    renderAssetsTab();
  } else if (secId === 'historical') {
    histActiveTab = tabKey;
    histCurrentPage = 0;
    fetchAndRenderHistorical();
  } else if (secId === 'js') {
    jsActiveTab = tabKey;
    renderJSTab();
  } else if (secId === 'ports') {
    portsActiveTab = tabKey;
    renderPortsTab();
  } else if (secId === 'dorks') {
    dorksActiveTab = tabKey;
    renderDorksTab();
  }
}
window.switchSectionSubTab = switchSectionSubTab;

// ── Open Target ──
window.openTarget = async function(name) {
  currentTarget = name;
  document.getElementById('explorer-screen').style.display = 'none';

  // Load target stats
  const stats = await fetchJSON(`/api/stats?target=${name}`);
  if (stats) {
    document.getElementById('topbar-domain').textContent = stats.domain || name;
    document.getElementById('topbar-date').textContent = stats.scan_date ? new Date(stats.scan_date).toLocaleDateString() : '--';
    populateSidebarBadges(stats.statistics);
  } else {
    toast(`Could not load stats for ${name}.`, 'err');
  }

  // Load persisted triage state (star/ignore) from the server
  await loadTriageState();

  // Pre-load the tiered Hunt Queue from the unified finding model
  await loadFindings();

  // Triage-first: land directly in the Hunt Queue cockpit
  selectedHost = null;
  triageCursor = -1;
  switchView('triage');
};

function populateSidebarBadges(s) {
  if (!s) return;
  const mappings = {
    assets: (s.total_subdomains || 0),
    webapps: (s.alive_services || 0),
    screenshots: (s.screenshots || 0),
    historical: (s.historical_urls || 0),
    js: (s.js_endpoints || 0),
    ports: (s.open_ports || 0),
    dorks: (s.dork_findings || 0)
  };
  for (const [key, val] of Object.entries(mappings)) {
    const el = document.getElementById(`badge-${key}`);
    if (el) el.textContent = val.toLocaleString();
  }
}

// ── Overview Page ──
function renderOverview() {
  // Render quick stats boxes
  const el = document.getElementById('stats-grid');
  const items = [
    { key: 'assets', label: 'Subdomains', val: parseInt(document.getElementById('badge-assets').textContent) || 0 },
    { key: 'webapps', label: 'Web Services', val: parseInt(document.getElementById('badge-webapps').textContent) || 0 },
    { key: 'screenshots', label: 'Screenshots', val: parseInt(document.getElementById('badge-screenshots').textContent) || 0 },
    { key: 'ports', label: 'Open Ports', val: parseInt(document.getElementById('badge-ports').textContent) || 0 },
    { key: 'historical', label: 'Historical URLs', val: parseInt(document.getElementById('badge-historical').textContent) || 0 },
    { key: 'dorks', label: 'Dork findings', val: parseInt(document.getElementById('badge-dorks').textContent) || 0 }
  ];

  let h = '';
  items.forEach(it => {
    h += `<div class="stat-box" onclick="switchView('${it.key}')">`;
    h += `<div class="stat-val">${it.val.toLocaleString()}</div>`;
    h += `<div class="stat-lbl">${it.label}</div>`;
    h += `</div>`;
  });
  el.innerHTML = h;

  // Render overview top interesting assets (High / Med priority queue items)
  const topAssetsContainer = document.getElementById('overview-top-assets');
  const interesting = huntQueueItems
    .filter(item => !isIgnored(item.host))
    .filter(item => item.priority === 'HIGH' || item.priority === 'MED')
    .slice(0, 8);

  if (interesting.length === 0) {
    topAssetsContainer.innerHTML = '<div class="empty">No high priority triage assets found.</div>';
  } else {
    let ah = '';
    interesting.forEach(item => {
      const starred = isStarred(item.host);
      const findings = item.findings || [];
      // Group findings by tier for the overview header line
      const critCount = findings.filter(f => (f.tier || '') === 'confirmed').length;
      const highCount = findings.filter(f => (f.tier || '') === 'suspicious').length;

      ah += `<div class="overview-asset-card">`;

      // Domain header row
      ah += `<div class="overview-asset-header">`;
      ah += `<div class="triage-priority ${item.priority.toLowerCase()}">${item.priority}</div>`;
      ah += `<a href="${esc(item.url)}" target="_blank" class="triage-host" style="font-size:13px;">${esc(item.host)}</a>`;
      if (item.status_code) ah += sBadge(item.status_code);
      if (critCount) ah += `<span class="finding-count-badge sev-crit">${critCount} confirmed</span>`;
      if (highCount) ah += `<span class="finding-count-badge sev-high">${highCount} suspicious</span>`;
      ah += `<div style="flex:1"></div>`;
      ah += `<button class="btn btn-sm btn-star ${starred ? 'active' : ''}" onclick="toggleTriageStar(${jsq(item.host)}, this); event.stopPropagation();">★</button>`;
      ah += `<button class="btn btn-sm" onclick="switchView('triage')" style="font-size:10px;">full queue</button>`;
      ah += `</div>`;

      // Findings list — show up to 5 most severe
      if (findings.length) {
        const SEV_ORDER = { crit: 4, high: 3, med: 2, low: 1 };
        const sorted = [...findings].sort((a, b) => (SEV_ORDER[b.sev] || 0) - (SEV_ORDER[a.sev] || 0));
        ah += `<div class="overview-asset-findings">`;
        const groups = groupFindings(sorted);
        groups.slice(0, 5).forEach(g => ah += renderFindingChip(g.head, true, g.members.length));
        if (groups.length > 5) {
          ah += `<span class="finding-more">+${groups.length - 5} more</span>`;
        }
        ah += `</div>`;
      } else {
        const titleInfo = item.title ? ` — ${esc(item.title)}` : '';
        ah += `<div class="overview-asset-findings"><span style="color:var(--muted);font-size:11px;">No detailed findings${titleInfo}</span></div>`;
      }

      ah += `</div>`;
    });
    topAssetsContainer.innerHTML = ah;
  }

  // Load latest monitor change summary + scan-history ribbon
  loadOverviewMonitorSummary();
  loadOverviewScanSummary();
}

// ── Overview scan-summary ribbon: "time & scans done", compact ──
function _relTime(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return '—';
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  const days = Math.floor(s / 86400);
  return days < 30 ? days + 'd ago' : d.toLocaleDateString();
}
function _fmtDur(min) {
  const m = Number(min);
  if (!isFinite(m) || m <= 0) return '<1m';
  if (m < 60) return m + 'm';
  const h = Math.floor(m / 60);
  return h + 'h' + (m % 60 ? ' ' + (m % 60) + 'm' : '');
}

async function loadOverviewScanSummary() {
  const el = document.getElementById('overview-scan-ribbon');
  if (!el) return;
  const data = await fetchJSON(`/api/scans?target=${encodeURIComponent(currentTarget)}`);
  const scans = (data?.scans || []).filter(s => s && s.timestamp);
  if (!scans.length) { el.hidden = true; return; }
  el.hidden = false;

  // scans arrive newest-first; latest + averages
  const latest = scans[0];
  const durs = scans.map(s => Number(s.duration_minutes)).filter(d => isFinite(d) && d > 0);
  const avg = durs.length ? Math.round(durs.reduce((a, b) => a + b, 0) / durs.length) : 0;

  const item = (val, lbl) => `<div class="sr-item"><span class="sr-val">${esc(String(val))}</span><span class="sr-lbl">${esc(lbl)}</span></div>`;
  let h = '';
  h += item(scans.length, scans.length === 1 ? 'scan' : 'scans');
  h += `<div class="sr-sep"></div>`;
  h += item(_relTime(latest.timestamp), 'last run');
  h += `<div class="sr-sep"></div>`;
  h += item(_fmtDur(latest.duration_minutes), 'duration');
  if (avg && scans.length > 1) {
    h += `<div class="sr-sep"></div>`;
    h += item(_fmtDur(avg), 'avg');
  }

  // Tiny inline bar chart of the last up-to-10 scan durations (oldest→newest).
  const recent = scans.slice(0, 10).reverse();
  const rdurs = recent.map(s => Math.max(0, Number(s.duration_minutes) || 0));
  const max = Math.max(1, ...rdurs);
  if (recent.length > 1) {
    h += `<div class="sr-spark" title="Recent scan durations (oldest → newest)">`;
    h += `<span class="sr-spark-lbl">trend</span>`;
    recent.forEach((s, i) => {
      const pct = Math.round((rdurs[i] / max) * 100);
      const last = i === recent.length - 1 ? ' sr-last' : '';
      const when = new Date(s.timestamp);
      const tip = `${_fmtDur(s.duration_minutes)} · ${isNaN(when) ? '' : when.toLocaleString()}`;
      h += `<div class="sr-bar${last}" style="height:${Math.max(2, pct * 0.22)}px" title="${esc(tip)}"></div>`;
    });
    h += `</div>`;
  }
  el.innerHTML = h;
}

async function loadOverviewMonitorSummary() {
  const container = document.getElementById('overview-monitor-changes');
  const data = await fetchJSON(`/api/monitor/changes?target=${currentTarget}`);
  const changes = data?.changes || [];
  if (changes.length === 0) {
    container.innerHTML = '<div class="empty">No monitor changes logged.</div>';
    return;
  }
  const latest = changes[0];
  const s = latest.summary || {};
  let h = '<div style="display:flex; flex-direction:column; gap:8px;">';
  h += `<div style="font-size:11px; color:var(--muted);">Check run: <b>${new Date(latest.timestamp).toLocaleString()}</b></div>`;
  h += `<div style="display:flex; gap:12px; margin-top:4px;">`;
  if (s.subdomains_added) h += `<span class="badge-status s2xx">+${s.subdomains_added} subdomains</span>`;
  if (s.subdomains_removed) h += `<span class="badge-status s5xx">-${s.subdomains_removed} subdomains</span>`;
  if (s.ports_added) h += `<span class="badge-status s2xx">+${s.ports_added} ports</span>`;
  h += `</div>`;
  h += `<button class="btn btn-sm" style="margin-top:8px; width:fit-content;" onclick="switchView('monitor')">View Full Timeline</button>`;
  h += `</div>`;
  container.innerHTML = h;
}

// ── Finding type definitions (icon, label, severity class) ──
const FINDING_DEFS = {
  secret:   { icon: 'SEC',   label: 'JS Secret',          sev: 'crit'  },
  leak:     { icon: 'LEAK',  label: 'JS Leakage',          sev: 'high'  },
  api:      { icon: 'API',   label: 'JS API Endpoint',     sev: 'med'   },
  hist:     { icon: 'HIST',  label: 'Live Historical Page', sev: 'high'  },
  param:    { icon: 'PARAM', label: 'Interesting Param',   sev: 'med'   },
  dork:     { icon: 'DORK',  label: 'Dork Hit',            sev: 'high'  },
  port:     { icon: 'PORT',  label: 'Open Port',           sev: 'low'   },
  auth:     { icon: 'AUTH',  label: 'Auth/Login Page',     sev: 'med'   },
  tech:     { icon: 'TECH',  label: 'Admin Tech',          sev: 'high'  },
  frbdn:    { icon: 'FRBDN', label: 'Forbidden/Unauth',    sev: 'med'   },
  sensdom:  { icon: 'SDOM',  label: 'Sensitive Domain',    sev: 'med'   },
  screenshot:{ icon: 'SS',  label: 'Screenshot',          sev: 'low'   },
};

function makeFinding(type, label, url = null) {
  return { type, label, url, ...FINDING_DEFS[type] };
}

// ══════════════════════════════════════════════════════════════════
// Unified finding model — frontend (Phase 3)
// The Hunt Queue + dossier are driven by server /api/findings (tiered),
// falling back to the legacy file-based compileHuntQueue() only if the
// server returns nothing (resilience).
// ══════════════════════════════════════════════════════════════════
let findingsRaw = [];
let findingsCounts = {};

// tier → visual weight (reusing existing sev-* chip colors; NOT severity)
const TIER_SEV = { confirmed: 'crit', suspicious: 'high', observation: 'low' };
const TIER_ORDER = ['confirmed', 'suspicious', 'observation'];
const FTYPE_ICON = {
  secret: 'SEC', 'info-leak': 'LEAK', 'exposed-file': 'FILE', 'sensitive-file': 'FILE',
  bucket: 'BKT', 'access-control-signal': 'ACL', 'auth-surface': 'AUTH',
  'tech-fingerprint': 'TECH', 'sensitive-host': 'SDOM', 'web-service': 'WEB',
  'open-port': 'PORT', 'source-map': 'MAP', websocket: 'WS', endpoint: 'EP',
  'api-endpoint': 'API', 'api-path': 'API', 'interesting-param': 'PARAM',
  'historical-url': 'HIST', change: 'CHG', 'service-banner': 'SVC', 'shared-infra': 'INFRA',
  comment: 'NOTE',
};
// 'confirmed' = a human (or the triage-results skill) verified the signal live.
const VERDICTS = ['new', 'reviewing', 'interesting', 'confirmed', 'reported', 'false_positive', 'wont_fix'];
const SEVERITIES = ['', 'info', 'low', 'medium', 'high', 'critical'];

function mapFinding(f) {
  return {
    type: f.type,
    label: f.title || f.url || f.type,
    url: f.url || '',
    tier: f.tier,
    sev: TIER_SEV[f.tier] || 'low',
    icon: FTYPE_ICON[f.type] || (f.type || '?').slice(0, 4).toUpperCase(),
    fingerprint: f.fingerprint,
    source: f.source,
    detector: f.detector,
    score: f.score || 0,
    score_detail: f.score_detail || {},
    verdict: f.verdict || 'new',
    severity: f.severity || '',
    evidence: f.evidence || {},
  };
}

function buildQueueFromFindings(findings, assets) {
  assets = assets || {};
  const byAsset = {};
  findings.forEach(f => {
    const a = f.asset || '(unattributed)';
    (byAsset[a] = byAsset[a] || []).push(mapFinding(f));
  });
  const items = Object.entries(byAsset).map(([host, fs]) => {
    const web = fs.find(f => f.type === 'web-service');
    const tech = fs.find(f => f.type === 'tech-fingerprint');
    // Priority/score/reasons are computed server-side (db.score_assets) so the
    // correlation logic stays in one place. Fall back to a local estimate only
    // if the server map is missing this asset.
    const a = assets[host];
    let priority, score, reasons;
    if (a) {
      priority = a.priority; score = a.score; reasons = a.reasons || [];
    } else {
      score = fs.reduce((m, f) => Math.max(m, f.score), 0);
      priority = score >= 8 ? 'HIGH' : score >= 4 ? 'MED' : 'LOW';
      reasons = [];
    }
    const withUrl = fs.find(f => f.url);
    const statusF = fs.find(f => f.evidence && f.evidence.status_code);
    return {
      host,
      url: (web && web.url) || (withUrl && withUrl.url) || ('http://' + host),
      title: (web && web.evidence && web.evidence.title) || '',
      status_code: (web && web.evidence && web.evidence.status_code) || (statusF && statusF.evidence.status_code) || null,
      tech: (tech && tech.evidence && tech.evidence.tech) || [],
      findings: fs,
      priority,
      score,
      reasons,
    };
  });
  const pm = { HIGH: 3, MED: 2, LOW: 1 };
  items.sort((a, b) => (pm[b.priority] - pm[a.priority]) || (b.score - a.score) || (b.findings.length - a.findings.length));
  return items;
}

// One compact server row per asset -> queue item. `findings` starts as a short
// preview (enough for the list chips); the dossier fetches the asset's full
// findings on demand (`partial` until then).
function assetToItem(a) {
  return {
    host: a.host,
    url: a.url,
    title: a.title || '',
    status_code: a.status_code || null,
    tech: a.tech || [],
    priority: a.priority,
    score: a.score,
    reasons: a.reasons || [],
    n: a.n || 0,
    tiers: a.tiers || {},
    dismissed: !!a.dismissed,
    findings: (a.preview || []).map(mapFinding),
    partial: true,
    screenshot: a.screenshot || null,
  };
}

async function loadFindings() {
  const url = `/api/findings/assets?target=${encodeURIComponent(currentTarget)}`;
  let res = await fetchJSON(url);
  let assets = res?.assets || [];
  findingsCounts = res?.counts || {};

  // Auto-heal: a target may not be ingested yet. Ingest once, then refetch.
  if (!assets.length) {
    const ing = await postJSON('/api/db/ingest', { target: currentTarget });
    if (ing?.ok) {
      res = await fetchJSON(url);
      assets = res?.assets || [];
      findingsCounts = res?.counts || {};
    } else if (ing && ing.ok === false) {
      toast('Could not ingest scan data: ' + (ing.error || 'unknown error'), 'warn');
    }
  }

  // Last-resort fallback: legacy client-side scoring from raw files.
  if (!assets.length) {
    await compileHuntQueue();
    updateTierSummary();
    return;
  }

  findingsRaw = [];
  triageSearchHosts = null;
  triageRenderLimit = TRIAGE_RENDER_STEP;
  huntQueueItems = assets.map(assetToItem);

  const activeTriage = huntQueueItems.filter(it => !isIgnored(it.host));
  document.getElementById('badge-triage').textContent = activeTriage.length;
  updateTierSummary();
}

function updateTierSummary() {
  const el = document.getElementById('triage-tier-summary');
  if (!el) return;
  const c = findingsCounts || {};
  const pill = (tier, n, label) => {
    const active = triageTierFilter === tier ? ' active' : '';
    return `<span class="tier-pill tier-${tier}${active}" role="button" tabindex="0" onclick="filterTriageTier('${tier}')" title="Filter: ${label}">${n} ${label}</span>`;
  };
  const parts = [];
  if (c.confirmed) parts.push(pill('confirmed', c.confirmed, 'confirmed'));
  if (c.suspicious) parts.push(pill('suspicious', c.suspicious, 'suspicious'));
  if (c.observation) parts.push(pill('observation', c.observation, 'obs'));
  el.innerHTML = parts.join('');
}

window.filterTriageTier = (tier) => {
  // click an active pill again to clear the filter
  triageTierFilter = (triageTierFilter === tier) ? 'all' : tier;
  triageRenderLimit = TRIAGE_RENDER_STEP;
  updateTierSummary();
  renderTriageList();
};

window.toggleHideDismissed = (checked) => {
  triageHideDismissed = checked;
  triageRenderLimit = TRIAGE_RENDER_STEP;
  renderTriageList();
};

window.setFindingState = async (fp, field, value, quiet = false) => {
  const res = await postJSON('/api/finding/state', { target: currentTarget, fingerprint: fp, [field]: value });
  if (!res?.ok) { toast('Failed to save ' + field, 'err'); return false; }
  // keep local copies in sync so re-renders reflect the change
  findingsRaw.forEach(f => { if (f.fingerprint === fp) f[field] = value; });
  huntQueueItems.forEach(it => {
    let hit = false;
    (it.findings || []).forEach(f => { if (f.fingerprint === fp) { f[field] = value; hit = true; } });
    if (hit && !it.partial) it.dismissed = itemDismissed(it);
  });
  if (!quiet) toast(`${field} → ${value || 'unrated'}`, 'ok', 1500);
  return true;
};

// Grouped dossier rows carry every duplicate's fingerprint (comma-joined).
window.setFindingStateMany = async (fps, field, value) => {
  const list = String(fps || '').split(',').filter(Boolean);
  let ok = 0;
  for (const fp of list) if (await window.setFindingState(fp, field, value, true)) ok++;
  if (ok) toast(`${field} → ${value || 'unrated'}${list.length > 1 ? ' (' + ok + ' grouped)' : ''}`, 'ok', 1500);
};

// ── Hunt Queue Engine (legacy file-based fallback) ──
async function compileHuntQueue() {
  huntQueueItems = [];

  // Fetch all signal sources in parallel
  const [
    httpxRaw, naabuRaw, dorksRaw,
    secretsRaw, leakageRaw, apiEndpointsRaw,
    endpointsRaw, validatedRaw, screenshotsData
  ] = await Promise.all([
    fetchText(T('httpx/results.json')),
    fetchText(T('ports/naabu.txt')),
    fetchText(T('dorks/all_findings.txt')),
    fetchText(T('js/secrets.txt')),
    fetchText(T('js/leakage.txt')),
    fetchText(T('js/api_endpoints.txt')),
    fetchText(T('endpoints/all.txt')),
    fetchText(T('historical/validated_interesting.json')),
    fetchJSON(`/api/screenshots?target=${currentTarget}`)
  ]);

  const screenshots = new Set(screenshotsData?.files || []);

  // Build port map: host -> [ports]
  const naabuPorts = {};
  parseLines(naabuRaw).forEach(line => {
    const col = line.lastIndexOf(':');
    if (col < 1) return;
    const host = line.slice(0, col);
    const port = line.slice(col + 1);
    if (!naabuPorts[host]) naabuPorts[host] = [];
    naabuPorts[host].push(port);
  });

  // Build known host set from httpx for cross-referencing
  const allKnownHosts = new Set(Object.keys(naabuPorts));
  const httpxEntries = [];
  httpxRaw.split('\n').filter(Boolean).forEach(line => {
    try {
      const r = JSON.parse(line);
      const url = r.url || r.input;
      const host = new URL(url).hostname;
      allKnownHosts.add(host);
      httpxEntries.push({ host, url, title: r.title || '', status_code: r.status_code, tech: r.tech || [], webserver: r.webserver || '' });
    } catch(e) {}
  });
  const hostsFound = new Set(httpxEntries.map(e => e.host));

  // ── Per-host findings maps ──

  // JS Secrets: map line to nearest matching host
  const secretsByHost = {};
  parseLines(secretsRaw).forEach(line => {
    const match = [...allKnownHosts].find(h => line.includes(h));
    const key = match || '__global';
    if (!secretsByHost[key]) secretsByHost[key] = [];
    secretsByHost[key].push(line);
  });

  // JS Leakage: internal IPs, dev domains, comments
  const leakageByHost = {};
  parseLines(leakageRaw).forEach(line => {
    const match = [...allKnownHosts].find(h => line.includes(h));
    const key = match || '__global';
    if (!leakageByHost[key]) leakageByHost[key] = [];
    leakageByHost[key].push(line);
  });

  // JS API endpoints
  const apiByHost = {};
  parseLines(apiEndpointsRaw).forEach(line => {
    try {
      const host = new URL(line.startsWith('http') ? line : 'https://' + line).hostname;
      if (!apiByHost[host]) apiByHost[host] = [];
      apiByHost[host].push(line);
    } catch(e) {
      // Relative paths — attribute to all hosts or skip
    }
  });

  // Dorks: count per host
  const dorksMap = {};
  const dorksUrls = {};
  parseLines(dorksRaw).forEach(line => {
    [...allKnownHosts].forEach(host => {
      if (line.includes(host)) {
        if (!dorksMap[host]) dorksMap[host] = 0;
        if (!dorksUrls[host]) dorksUrls[host] = [];
        dorksMap[host]++;
        if (dorksUrls[host].length < 3) dorksUrls[host].push(line.trim());
      }
    });
  });

  // Validated live historical pages: map to host
  // Interesting patterns (no redirects, not boring pages)
  const BORING_TITLES = ['not found', '404', 'moved', 'redirect', 'home', 'welcome', '403 forbidden', 'access denied'];
  const SENSITIVE_HIST_PATTERNS = /(\/api\/|\/admin|\/login|\/auth|\/config|\/debug|\/backup|\/staging|\/internal|\/dev\/|\.env|\.json|\.xml|\.sql|\.log|\.bak|\/graphql|\/swagger|\/v[0-9]+\/)/i;
  const histByHost = {};
  validatedRaw.split('\n').filter(Boolean).forEach(line => {
    try {
      const r = JSON.parse(line);
      if (!r.url) return;
      // Only include: 2xx that aren't boring, or 403/401
      const sc = parseInt(r.status_code);
      const titleLower = (r.title || '').toLowerCase();
      const isBoring = BORING_TITLES.some(t => titleLower.includes(t));
      const isSensitive = SENSITIVE_HIST_PATTERNS.test(r.url);
      if (!isSensitive) return;
      if (sc >= 200 && sc < 300 && !isBoring) {
        // Live sensitive page
      } else if (sc === 403 || sc === 401) {
        // Forbidden sensitive path - still interesting
      } else {
        return; // skip redirects, 404s, boring 200s
      }
      const host = new URL(r.url).hostname;
      if (!histByHost[host]) histByHost[host] = [];
      histByHost[host].push({ url: r.url, status: sc, title: r.title || '' });
    } catch(e) {}
  });

  // Interesting params from crawled endpoints
  const INTERESTING_PARAMS = /[?&](redirect|url|next|target|dest|return|returnurl|continue|file|path|page|id|token|key|secret|debug|admin|config|callback|ref|referrer|redir|load|include|require|src|source|template|cmd|exec|command|shell|query|search|q|lang|locale|format|output|type|action|method|api_key|apikey|access_token)/i;
  const paramsByHost = {};
  parseLines(endpointsRaw).forEach(url => {
    if (!INTERESTING_PARAMS.test(url)) return;
    try {
      const host = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
      if (!paramsByHost[host]) paramsByHost[host] = [];
      if (paramsByHost[host].length < 5) paramsByHost[host].push(url);
    } catch(e) {}
  });

  // ── Build triage items for each web app ──
  httpxEntries.forEach(app => {
    const findings = [];
    let score = 0;

    // Screenshot
    const cleanHost = app.host.replace(/\./g, '_');
    const ssMatch = [...screenshots].find(f => f.includes(cleanHost));
    if (ssMatch) findings.push(makeFinding('screenshot', 'Screenshot available'));

    // Ports
    const ports = naabuPorts[app.host];
    if (ports) {
      const nonStd = ports.filter(p => p !== '80' && p !== '443');
      if (nonStd.length) {
        findings.push(makeFinding('port', `Port${nonStd.length > 1 ? 's' : ''}: ${nonStd.join(', ')}`));
        score += 2;
      }
    }

    // Dorks
    if (dorksMap[app.host]) {
      (dorksUrls[app.host] || []).slice(0, 2).forEach(u =>
        findings.push(makeFinding('dork', u.length > 80 ? u.slice(0, 80) + '...' : u))
      );
      score += 4;
    }

    // JS Secrets
    const mySecrets = (secretsByHost[app.host] || []).concat(secretsByHost['__global'] || []);
    if (mySecrets.length) {
      mySecrets.slice(0, 3).forEach(s =>
        findings.push(makeFinding('secret', s.length > 80 ? s.slice(0, 80) + '...' : s))
      );
      score += 5;
    }

    // JS Leakage
    const myLeaks = (leakageByHost[app.host] || []).concat(leakageByHost['__global'] || []);
    if (myLeaks.length) {
      myLeaks.slice(0, 2).forEach(l =>
        findings.push(makeFinding('leak', l.length > 80 ? l.slice(0, 80) + '...' : l))
      );
      score += 3;
    }

    // JS API endpoints
    if (apiByHost[app.host]?.length) {
      apiByHost[app.host].slice(0, 3).forEach(ep =>
        findings.push(makeFinding('api', ep.length > 80 ? ep.slice(0, 80) + '...' : ep, ep))
      );
      score += 2;
    }

    // Live sensitive historical pages
    if (histByHost[app.host]?.length) {
      histByHost[app.host].slice(0, 3).forEach(h =>
        findings.push(makeFinding('hist', `[${h.status}] ${h.url}`, h.url))
      );
      score += 4;
    }

    // Interesting params
    if (paramsByHost[app.host]?.length) {
      paramsByHost[app.host].slice(0, 3).forEach(u =>
        findings.push(makeFinding('param', u.length > 90 ? u.slice(0, 90) + '...' : u, u))
      );
      score += 2;
    }

    // Title / tech signals
    const titleLower = app.title.toLowerCase();
    const hostLower = app.host.toLowerCase();
    const techString = app.tech.join(' ').toLowerCase();

    if (titleLower.includes('login') || titleLower.includes('sign in') || titleLower.includes('portal') || titleLower.includes('admin') || titleLower.includes('dashboard')) {
      findings.push(makeFinding('auth', `Auth page: "${app.title}"`));
      score += 3;
    }
    if (hostLower.includes('admin') || hostLower.includes('api') || hostLower.includes('dev') || hostLower.includes('staging') || hostLower.includes('internal') || hostLower.includes('jenkins') || hostLower.includes('jira')) {
      findings.push(makeFinding('sensdom', `Sensitive subdomain: ${app.host}`));
      score += 3;
    }
    const ADMIN_TECH = ['jenkins', 'jira', 'kubernetes', 'docker', 'tomcat', 'grafana', 'kibana', 'prometheus', 'sonarqube', 'gitlab', 'nexus', 'artifactory', 'confluence', 'bitbucket'];
    const matchedTech = ADMIN_TECH.filter(t => techString.includes(t));
    if (matchedTech.length) {
      findings.push(makeFinding('tech', matchedTech.join(', ')));
      score += 4;
    }
    if (app.status_code === 403 || app.status_code === 401) {
      findings.push(makeFinding('frbdn', `HTTP ${app.status_code} — possible access control`));
      score += 3;
    }

    // Priority classification
    let priority = 'LOW';
    if (score >= 7) priority = 'HIGH';
    else if (score >= 3) priority = 'MED';

    huntQueueItems.push({
      priority,
      host: app.host,
      url: app.url,
      title: app.title,
      status_code: app.status_code,
      tech: app.tech,
      findings,
      screenshot: ssMatch ? `/screenshots/${currentTarget}/${encodeURIComponent(ssMatch)}` : null
    });
  });

  // Port-only hosts (no HTTP service detected)
  Object.keys(naabuPorts).forEach(host => {
    if (!hostsFound.has(host)) {
      const nonStd = naabuPorts[host].filter(p => p !== '80' && p !== '443');
      huntQueueItems.push({
        priority: nonStd.length ? 'MED' : 'LOW',
        host,
        url: `http://${host}`,
        title: 'Port-Only Asset',
        status_code: null,
        tech: [],
        findings: [makeFinding('port', `Port${naabuPorts[host].length > 1 ? 's' : ''}: ${naabuPorts[host].join(', ')}`)],
        screenshot: null
      });
    }
  });

  // Sort: HIGH first, then by number of findings desc
  const prioMap = { HIGH: 3, MED: 2, LOW: 1 };
  huntQueueItems.sort((a, b) => {
    const pd = prioMap[b.priority] - prioMap[a.priority];
    return pd !== 0 ? pd : b.findings.length - a.findings.length;
  });

  const activeTriage = huntQueueItems.filter(item => !isIgnored(item.host));
  document.getElementById('badge-triage').textContent = activeTriage.length;
}

// ── Evidence formatting ──
// Findings can carry raw scanner lines (minified JS, long URLs, SVG strings).
// Split them into {source, preview, raw}: the preview is a short single line
// for the list, the raw text stays available behind an expandable <details>.
const PREVIEW_MAX = 140;
const RAW_MAX = 4000;

function _collapseWs(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }

function _truncMid(s, n) {
  if (s.length <= n) return s;
  const head = Math.ceil(n * 0.65), tail = n - head - 1;
  return s.slice(0, head) + '…' + s.slice(s.length - tail);
}

function splitEvidence(f) {
  const ev = f.evidence || {};
  let raw = String(ev.match || f.label || f.url || '');
  let source = ev.source || '';
  let content = raw;
  // Scanner lines look like "[<url-or-file>:<line>] [Type] match" or
  // "[<url-or-file>:<line>] // comment" — pull the location out.
  const m = /^\[([^\]\s]+?)(?::(\d+))?\]\s*(.*)$/s.exec(raw);
  if (m && !source) {
    source = m[2] ? `${m[1]}:${m[2]}` : m[1];
    content = m[3];
  }
  let kind = '';
  const k = /^\[([^\]]{1,40})\]\s*(.*)$/s.exec(content);
  if (k) { kind = k[1]; content = k[2]; }
  // Titles from the server may embed the raw line; prefer the parsed content.
  let text = _collapseWs(content) || _collapseWs(f.label);
  if (f.url && text === f.url) source = source || '';
  const isUrl = /^[a-z]+:\/\//i.test(text);
  const preview = isUrl ? _truncMid(text, PREVIEW_MAX) : (text.length > PREVIEW_MAX ? text.slice(0, PREVIEW_MAX) + '…' : text);
  return {
    kind,
    source,
    preview: (kind ? kind + ': ' : '') + preview,
    raw: raw.length > RAW_MAX ? raw.slice(0, RAW_MAX) + `\n… (${(raw.length - RAW_MAX).toLocaleString()} more chars — see raw files)` : raw,
    long: raw.length > PREVIEW_MAX || /\n/.test(raw),
  };
}

// Group identical evidence (same type + same normalized preview) so repeated
// hits across files/URLs show once with a count instead of N copies.
function groupFindings(fs) {
  const groups = new Map();
  fs.forEach(f => {
    const e = splitEvidence(f);
    const key = (f.type || '') + '|' + (f.tier || '') + '|' + e.preview.toLowerCase();
    let g = groups.get(key);
    if (!g) {
      g = { key, head: f, ev: e, members: [], sources: new Set() };
      groups.set(key, g);
    }
    g.members.push(f);
    if (e.source) g.sources.add(e.source);
    if (f.url && f.url !== e.source) g.sources.add(f.url);
    if ((f.score || 0) > (g.head.score || 0)) { g.head = f; g.ev = e; }
  });
  return [...groups.values()];
}

function renderFindingChip(f, linkable = false, count = 1) {
  const def = FINDING_DEFS[f.type] || {};
  const sev = f.sev || def.sev || 'low';
  const icon = f.icon || def.icon || '?';
  const cls = `finding-chip sev-${sev}`;
  const e = splitEvidence(f);
  const title = esc(e.preview);
  const label = linkable && f.url
    ? `<a href="${esc(f.url)}" target="_blank" rel="noopener" class="finding-link" title="${title}" onclick="event.stopPropagation()">${esc(e.preview)}</a>`
    : `<span class="finding-text" title="${title}">${esc(e.preview)}</span>`;
  const cnt = count > 1 ? `<span class="finding-count">×${count}</span>` : '';
  return `<div class="${cls}"><span class="finding-icon">${icon}</span>${label}${cnt}</div>`;
}

// Expandable evidence block for the dossier: short summary, full detail inside.
function renderFindingGroup(g) {
  const f = g.head;
  const n = g.members.length;
  const srcs = [...g.sources];
  let h = `<details class="f-group">`;
  h += `<summary>${renderFindingChip(f, false, n)}</summary>`;
  h += `<div class="f-detail">`;
  const sd = f.score_detail || {};
  if (Array.isArray(sd.reasons) && sd.reasons.length) {
    h += `<div class="f-detail-lbl">Score ${esc(String(f.score || 0))}</div><ul class="f-reasons">`;
    sd.reasons.forEach(r => h += `<li>${esc(r)}</li>`);
    h += `</ul>`;
  }
  if (srcs.length) {
    h += `<div class="f-detail-lbl">Source${srcs.length > 1 ? 's (' + srcs.length + ')' : ''}</div><ul class="f-sources">`;
    srcs.slice(0, 25).forEach(s => {
      const link = /^https?:\/\//i.test(s) ? `<a href="${esc(s.replace(/:\d+$/, ''))}" target="_blank" rel="noopener">${esc(s)}</a>` : esc(s);
      h += `<li>${link}</li>`;
    });
    if (srcs.length > 25) h += `<li class="finding-more">+${srcs.length - 25} more</li>`;
    h += `</ul>`;
  }
  h += `<div class="f-detail-lbl">Evidence${n > 1 ? ' (first of ' + n + ')' : ''}</div>`;
  h += `<pre class="f-raw">${esc(g.ev.raw)}</pre>`;
  h += `</div></details>`;
  return h;
}

function itemHasTier(item, tier) {
  if (item.tiers) return (item.tiers[tier] || 0) > 0;
  return (item.findings || []).some(f => (f.tier || 'observation') === tier);
}

function itemDismissed(item) {
  if (item.partial) return !!item.dismissed;
  return !(item.findings || []).some(f => !DISMISSED_VERDICTS.includes(f.verdict || 'new'));
}

window.triageShowMore = () => {
  triageRenderLimit += TRIAGE_RENDER_STEP * 2;
  renderTriageList();
};

function renderTriageList() {
  const container = document.getElementById('triage-list-container');
  let filtered = [...huntQueueItems];

  // 1. Priority filters
  if (triagePriorityFilter !== 'all') {
    if (triagePriorityFilter === 'starred') {
      filtered = filtered.filter(item => isStarred(item.host));
    } else {
      filtered = filtered.filter(item => item.priority.toLowerCase() === triagePriorityFilter);
    }
  }

  // 2. Hide ignored
  if (triageHideIgnored) {
    filtered = filtered.filter(item => !isIgnored(item.host));
  }

  // 3. Text search — also searches findings labels (all of them: labels not
  //    loaded in the browser are matched server-side, see filterTriageText)
  if (triageTextFilter) {
    const q = triageTextFilter.toLowerCase();
    const remote = (triageSearchFor === q) ? triageSearchHosts : null;
    filtered = filtered.filter(item =>
      item.host.toLowerCase().includes(q) ||
      item.title.toLowerCase().includes(q) ||
      item.tech.join(' ').toLowerCase().includes(q) ||
      (item.findings || []).some(f => f.label.toLowerCase().includes(q)) ||
      (remote && remote.has(item.host))
    );
  }

  // 4. Tier filter — asset must have at least one finding of the chosen tier
  if (triageTierFilter !== 'all') {
    filtered = filtered.filter(item => itemHasTier(item, triageTierFilter));
  }

  // 5. Hide dismissed — hide assets whose findings are ALL false-positive/wont-fix
  if (triageHideDismissed) {
    filtered = filtered.filter(item => !itemDismissed(item));
  }

  triageVisible = filtered;

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty">No hunt queue items matching current filters.</div>';
    triageCursor = -1;
    return;
  }

  let h = '';
  filtered.slice(0, triageRenderLimit).forEach((item, idx) => {
    const starred = isStarred(item.host);
    const ignored = isIgnored(item.host);
    const findings = item.findings || [];
    const sel = item.host === selectedHost ? ' selected' : '';

    h += `<div class="triage-row${ignored ? ' triage-ignored' : ''}${sel}" data-host="${esc(item.host)}" data-idx="${idx}" tabindex="0" onclick="selectAsset(${jsq(item.host)})">`;
    h += `<div class="triage-priority ${item.priority.toLowerCase()}">${item.priority}</div>`;
    h += `<div class="triage-info">`;
    h += `<div class="triage-title-line">`;
    h += `<a href="${esc(item.url)}" target="_blank" rel="noopener" class="triage-host" onclick="event.stopPropagation()">${esc(item.host)}</a>`;
    if (item.status_code) h += sBadge(item.status_code);
    if (item.title) h += `<span class="triage-page-title">${esc(item.title)}</span>`;
    if (item.tech?.length) {
      h += `<div class="triage-badges">`;
      item.tech.slice(0, 4).forEach(t => h += `<span class="triage-badge tech">${esc(t)}</span>`);
      h += `</div>`;
    }
    h += `</div>`;
    if (findings.length) {
      // Short, grouped preview in the list; full evidence lives in the dossier.
      const groups = groupFindings(findings);
      const ROW_MAX = 5;
      h += `<div class="triage-findings">`;
      groups.slice(0, ROW_MAX).forEach(g => h += renderFindingChip(g.head, true, g.members.length));
      const unseen = Math.max(0, (item.n || 0) - findings.length);
      if (groups.length > ROW_MAX || unseen) {
        const more = Math.max(0, groups.length - ROW_MAX) + unseen;
        h += `<span class="finding-more">+${more} more — open dossier</span>`;
      }
      h += `</div>`;
    }
    h += `</div>`;

    h += `<div class="triage-actions">`;
    h += `<button class="btn btn-sm" onclick="event.stopPropagation(); copyToClipboard(${jsq(item.url)}, this)">copy</button>`;
    if (item.screenshot) {
      h += `<button class="btn btn-sm" onclick="event.stopPropagation(); openLightbox(${jsq(item.screenshot)}, ${jsq(item.host)})">ss</button>`;
    }
    h += `<button class="btn btn-sm btn-star ${starred ? 'active' : ''}" onclick="event.stopPropagation(); toggleTriageStar(${jsq(item.host)}, this)" aria-label="Star ${esc(item.host)}">★</button>`;
    h += `<button class="btn btn-sm btn-ignore ${ignored ? 'active' : ''}" onclick="event.stopPropagation(); toggleTriageIgnore(${jsq(item.host)}, this)">ignore</button>`;
    h += `</div>`;
    h += `</div>`;
  });
  if (filtered.length > triageRenderLimit) {
    const rest = filtered.length - triageRenderLimit;
    h += `<div class="tbl-foot"><span>Showing ${triageRenderLimit} of ${filtered.length.toLocaleString()} assets</span>` +
      `<button class="btn btn-sm" onclick="triageShowMore()">Show ${Math.min(rest, TRIAGE_RENDER_STEP * 2)} more</button></div>`;
  }
  container.innerHTML = h;

  // Keep selection/cursor coherent with the (re)rendered list
  if (selectedHost) {
    const i = filtered.findIndex(it => it.host === selectedHost);
    triageCursor = i;
    if (i >= 0) {
      renderDossier(filtered[i]);
      if (filtered[i].partial) loadAssetFindings(filtered[i]);
    }
  } else if (filtered.length && window.innerWidth > 1100) {
    // Desktop: populate the dossier with the top asset on landing.
    // (Skipped on narrow screens so the slide-over doesn't pop unbidden.)
    selectAsset(filtered[0].host);
  }
}

// ── Asset Dossier (Phase 1): everything known about one host, in one pane ──
const SEV_RANK = { crit: 4, high: 3, med: 2, low: 1 };

window.selectAsset = function(host) {
  selectedHost = host;
  const i = triageVisible.findIndex(it => it.host === host);
  if (i >= 0) triageCursor = i;
  // highlight the row
  document.querySelectorAll('#triage-list-container .triage-row').forEach(r => {
    r.classList.toggle('selected', r.getAttribute('data-host') === host);
  });
  const item = huntQueueItems.find(it => it.host === host);
  renderDossier(item);
  // on narrow screens the dossier is a slide-over
  if (window.innerWidth <= 1100) document.getElementById('asset-dossier').classList.add('open');
  if (item && item.partial) loadAssetFindings(item);
};

// Fetch the full findings (evidence, score detail) for one asset on demand.
async function loadAssetFindings(item) {
  if (item._loading) return;
  item._loading = true;
  const res = await fetchJSON(`/api/findings?${new URLSearchParams({ target: currentTarget, asset: item.host })}`);
  item._loading = false;
  if (!res || res.error) {
    toast('Could not load findings for ' + item.host, 'err');
    return;
  }
  item.findings = (res.findings || []).map(mapFinding);
  item.partial = false;
  item.dismissed = itemDismissed(item);
  if (selectedHost === item.host) renderDossier(item);
}

window.closeDossier = function() {
  document.getElementById('asset-dossier').classList.remove('open');
};

function renderDossier(item) {
  const d = document.getElementById('asset-dossier');
  if (!d) return;
  if (!item) {
    d.innerHTML = '<div class="dossier-empty">Select an asset to open its dossier.</div>';
    return;
  }
  const starred = isStarred(item.host);
  const ignored = isIgnored(item.host);
  const findings = [...(item.findings || [])].sort((a, b) => (SEV_RANK[b.sev] || 0) - (SEV_RANK[a.sev] || 0));

  let h = '';
  h += `<div class="dossier-hd">`;
  h += `<div style="display:flex;align-items:center;gap:8px;">`;
  h += `<div class="dossier-host" style="flex:1;">${esc(item.host)}</div>`;
  h += `<button class="dossier-close btn btn-sm" onclick="closeDossier()" aria-label="Close dossier">✕</button>`;
  h += `</div>`;
  h += `<div class="dossier-sub">`;
  h += `<span class="triage-priority ${item.priority.toLowerCase()}">${item.priority}</span>`;
  if (typeof item.score === 'number') h += `<span class="dossier-score">Score ${item.score}</span>`;
  if (item.status_code) h += sBadge(item.status_code);
  if (item.title) h += `<span>${esc(item.title)}</span>`;
  h += `</div></div>`;

  h += `<div class="dossier-bd">`;
  // Why this asset got its priority — the correlated score breakdown.
  if (item.reasons && item.reasons.length) {
    h += `<div class="score-why"><div class="dossier-sec-hd">Why this score</div><ul class="f-reasons">`;
    item.reasons.forEach(r => h += `<li>${esc(r)}</li>`);
    h += `</ul></div>`;
  }
  if (item.screenshot) {
    h += `<div class="dossier-shot"><img src="${esc(item.screenshot)}" alt="Screenshot of ${esc(item.host)}" loading="lazy" onclick="openLightbox(${jsq(item.screenshot)}, ${jsq(item.host)})"></div>`;
  }
  if (item.tech?.length) {
    h += `<div><div class="dossier-sec-hd">Technologies</div><div class="triage-badges">`;
    item.tech.forEach(t => h += `<span class="triage-badge tech">${esc(t)}</span>`);
    h += `</div></div>`;
  }
  if (item.partial) {
    h += `<div class="loading"><div class="spinner"></div></div>`;
  } else if (findings.length) {
    // Group by tier: Confirmed → Suspicious → Observations
    TIER_ORDER.forEach(tier => {
      const fs = findings.filter(f => (f.tier || 'observation') === tier);
      if (!fs.length) return;
      const label = tier === 'observation' ? 'Observations' : tier.charAt(0).toUpperCase() + tier.slice(1);
      const groups = groupFindings(fs);
      h += `<div><div class="dossier-sec-hd">${label} (${groups.length}${groups.length !== fs.length ? ' · ' + fs.length + ' hits' : ''})</div>`;
      const shown = tier === 'observation' ? groups.slice(0, 15) : groups;
      shown.forEach(g => {
        const f = g.head;
        h += `<div class="dossier-finding">`;
        h += renderFindingGroup(g);
        // verdict / severity controls only for actionable tiers (not raw observations);
        // a grouped row applies the choice to every duplicate it represents.
        const fps = g.members.map(m => m.fingerprint).filter(Boolean);
        if (tier !== 'observation' && fps.length) {
          const fpArg = jsq(fps.join(','));
          h += `<div class="f-controls">`;
          h += `<select class="f-ctrl" title="Verdict" onchange="setFindingStateMany(${fpArg},'verdict',this.value)">`;
          VERDICTS.forEach(v => h += `<option value="${v}" ${f.verdict === v ? 'selected' : ''}>${v.replace('_', ' ')}</option>`);
          h += `</select>`;
          h += `<select class="f-ctrl" title="Severity (your call)" onchange="setFindingStateMany(${fpArg},'severity',this.value)">`;
          SEVERITIES.forEach(s => h += `<option value="${s}" ${(f.severity || '') === s ? 'selected' : ''}>${s || 'unrated'}</option>`);
          h += `</select>`;
          h += `</div>`;
        }
        h += `</div>`;
      });
      if (tier === 'observation' && groups.length > 15) {
        h += `<span class="finding-more">+${groups.length - 15} more observations</span>`;
      }
      h += `</div>`;
    });
  } else {
    h += `<div class="dossier-sec-hd">No detailed findings for this asset</div>`;
  }
  h += `</div>`;

  h += `<div class="dossier-acts">`;
  h += `<a class="btn btn-sm btn-accent" href="${esc(item.url)}" target="_blank" rel="noopener">open ▸</a>`;
  h += `<button class="btn btn-sm" onclick="copyToClipboard(${jsq(item.url)}, this)">copy url</button>`;
  h += `<button class="btn btn-sm btn-star ${starred ? 'active' : ''}" onclick="toggleTriageStar(${jsq(item.host)}, this)" aria-label="Star">★</button>`;
  h += `<button class="btn btn-sm btn-ignore ${ignored ? 'active' : ''}" onclick="toggleTriageIgnore(${jsq(item.host)}, this)">ignore</button>`;
  h += `</div>`;

  d.innerHTML = h;
}


window.filterTriagePriority = (prio) => {
  triagePriorityFilter = prio;
  triageRenderLimit = TRIAGE_RENDER_STEP;
  document.querySelectorAll('.triage-bar button').forEach(btn => btn.classList.remove('btn-accent'));
  document.getElementById('btn-triage-' + prio)?.classList.add('btn-accent');
  renderTriageList();
};

window.filterTriageText = (val) => {
  triageTextFilter = val;
  triageRenderLimit = TRIAGE_RENDER_STEP;
  renderTriageList();
  // Full-text match against every finding label happens server-side (the
  // browser only holds a preview per asset). Debounced; re-render on reply.
  clearTimeout(triageSearchTimer);
  const q = val.trim().toLowerCase();
  if (q.length < 2 || !huntQueueItems.some(it => it.partial)) return;
  triageSearchTimer = setTimeout(async () => {
    const res = await fetchJSON(`/api/findings/assets?${new URLSearchParams({ target: currentTarget, q })}`);
    if (triageTextFilter.trim().toLowerCase() !== q) return;   // stale
    triageSearchHosts = new Set(res?.hosts || []);
    triageSearchFor = q;
    renderTriageList();
  }, 300);
};

window.toggleHideIgnored = (checked) => {
  triageHideIgnored = checked;
  triageRenderLimit = TRIAGE_RENDER_STEP;
  renderTriageList();
};

function cacheTriageLocal(key, on) {
  try { localStorage.setItem(key, on ? 'true' : 'false'); } catch (e) {}
}

window.toggleTriageStar = (host, btn) => {
  const nowStarred = !triageStarred.has(host);
  if (nowStarred) triageStarred.add(host); else triageStarred.delete(host);
  cacheTriageLocal(getStarKey(host), nowStarred);
  if (btn) btn.classList.toggle('active', nowStarred);
  persistTriage();
  if (currentView === 'triage') renderTriageList();
};

window.toggleTriageIgnore = (host, btn) => {
  const nowIgnored = !triageIgnored.has(host);
  if (nowIgnored) triageIgnored.add(host); else triageIgnored.delete(host);
  cacheTriageLocal(getIgnoreKey(host), nowIgnored);
  if (btn) btn.classList.toggle('active', nowIgnored);

  // Re-calculate triage badge count
  const activeTriage = huntQueueItems.filter(item => !isIgnored(item.host));
  document.getElementById('badge-triage').textContent = activeTriage.length;

  persistTriage();
  if (currentView === 'triage') renderTriageList();
};

// ── Assets Section ──
let assetsActiveTab = 'subs';
let assetsTableCtrl = null;

async function loadAssetsSection() {
  fillTabCounts({ 'tc-assets-subs': 'subs/all.txt', 'tc-assets-dns': 'dns/resolved.txt' });
  renderAssetsTab();
}

function renderAssetsTab() {
  const containerId = 'data-assets-content';
  document.getElementById(containerId).innerHTML = '';

  if (assetsActiveTab === 'subs') {
    assetsTableCtrl = renderServerList(containerId, 'subs/all.txt', 'Subdomain', _assetsSearchVal);
  } else {
    // Resolved hosts joined with their httpx IP — server-side, one page at a time.
    const q = _assetsSearchVal().toLowerCase();
    const ctrl = makeServerTable(
      containerId,
      (p) => `/api/data/table?${new URLSearchParams({ target: currentTarget, kind: 'dns', ...p })}`,
      [{ key: 'host', label: 'Subdomain' }, { key: 'ip', label: 'IP Address' }],
      (item, _i, a) => `<tr><td>${hilite(item.host, a.q || '')}</td><td>${hilite(item.ip, a.q || '')}</td></tr>`,
      { args: { q } }
    );
    ctrl.render();
    assetsTableCtrl = { filter: (text) => ctrl.filter({ q: text }) };
  }
}

function _assetsSearchVal() {
  return document.getElementById('filter-assets-search').value;
}

window.assetsFilter = (val) => {
  assetsTableCtrl?.filter(val.toLowerCase());
};

// ── Web Apps Section ──
// httpx results are filtered (text / status / duplicate titles), sorted and
// paged on the server; the browser only ever holds one page.
let webappsTableCtrl = null;

function _webappsArgs() {
  return { q: webappsTextQuery.toLowerCase(), status: webappsStatusQuery, hideDupes: webappsHideDupes };
}

async function loadWebApps() {
  renderWebAppsTable();
}

function renderWebAppsTable() {
  const containerId = 'data-webapps-content';
  document.getElementById(containerId).innerHTML = '';
  webappsTableCtrl = makeServerTable(
    containerId,
    (p) => `/api/data/table?${new URLSearchParams({ target: currentTarget, kind: 'webapps', ...p })}`,
    [
      { key: 'url', label: 'Web URL' },
      { key: 'status_code', label: 'Status' },
      { key: 'title', label: 'Page Title' },
      { key: 'webserver', label: 'Web Server' },
      { key: 'tech', label: 'Technologies' }
    ],
    (item) => {
      const tech = (item.tech || []).join(', ');
      return `<tr>
        <td class="wrap-cell"><a href="${esc(item.url)}" target="_blank" rel="noopener" class="triage-host">${hilite(item.url, webappsTextQuery)}</a></td>
        <td>${sBadge(item.status_code)}</td>
        <td class="wrap-cell">${hilite(item.title || '', webappsTextQuery)}</td>
        <td>${hilite(item.webserver || '', webappsTextQuery)}</td>
        <td class="wrap-cell" style="color:var(--blue); font-size:11px;">${hilite(tech, webappsTextQuery)}</td>
      </tr>`;
    },
    { args: _webappsArgs() }
  );
  webappsTableCtrl.render();
}

window.webappsFilter = (val) => {
  webappsTextQuery = val;
  webappsTableCtrl?.filter(_webappsArgs());
};

window.webappsStatusFilter = (val) => {
  webappsStatusQuery = val;
  webappsTableCtrl?.filter(_webappsArgs());
};

window.toggleWebappsHideDuplicates = (checked) => {
  webappsHideDupes = checked;
  webappsTableCtrl?.filter(_webappsArgs());
};

// ── Screenshots ──
// Paged gallery (48 per page, server-side): rendering thousands of cards and
// images at once exhausted memory on phones.
let ssPage = 0;
let ssQuery = '';
let ssSeq = 0;
let ssFilterTimer = null;
const SS_PAGE_SIZE = 48;

async function loadScreenshots() {
  ssPage = 0;
  await renderScreenshotsPage();
}

async function renderScreenshotsPage() {
  const container = document.getElementById('data-screenshots');
  const pager = document.getElementById('ss-pager');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  const mySeq = ++ssSeq;
  const data = await fetchJSON(`/api/screenshots?${new URLSearchParams({ target: currentTarget, page: ssPage, pageSize: SS_PAGE_SIZE, q: ssQuery })}`);
  if (mySeq !== ssSeq) return;
  if (!data) {
    container.innerHTML = '<div class="empty">Error fetching screenshots.</div>';
    if (pager) pager.innerHTML = '';
    toast('Failed to load screenshots.', 'err');
    return;
  }
  const files = data.files || [];
  const total = data.total || 0;
  if (!ssQuery) document.getElementById('badge-screenshots').textContent = total.toLocaleString();

  if (files.length === 0) {
    container.innerHTML = `<div class="empty">${ssQuery ? 'No screenshots match this filter.' : 'No screenshots collected.'}</div>`;
    if (pager) pager.innerHTML = '';
    return;
  }

  let h = '';
  files.forEach(f => {
    const src = `/screenshots/${currentTarget}/${encodeURIComponent(f)}`;
    const label = f.replace(/\.(png|jpg|jpeg)$/i, '');
    h += `<div class="ss-card" onclick="openLightbox(${jsq(src)}, ${jsq(label)})">`;
    h += `<img src="${esc(src)}" alt="${esc(label)}" loading="lazy" decoding="async" width="220" height="140" />`;
    h += `<div class="ss-footer"><span>${esc(label)}</span></div>`;
    h += `</div>`;
  });
  container.innerHTML = h;

  const pages = Math.ceil(total / SS_PAGE_SIZE) || 1;
  const start = ssPage * SS_PAGE_SIZE;
  if (pager) {
    let p = `<span>Showing ${start + 1}–${Math.min(start + SS_PAGE_SIZE, total)} of ${total.toLocaleString()}</span>`;
    if (pages > 1) {
      p += `<div style="display:flex;gap:4px;">`;
      p += `<button class="btn btn-sm" onclick="ssGoPage(-1)" ${ssPage === 0 ? 'disabled' : ''}>Prev</button>`;
      p += `<button class="btn btn-sm" onclick="ssGoPage(1)" ${ssPage >= pages - 1 ? 'disabled' : ''}>Next</button>`;
      p += `</div>`;
    }
    pager.innerHTML = p;
  }
}

window.ssGoPage = (delta) => {
  ssPage = Math.max(0, ssPage + delta);
  renderScreenshotsPage();
  document.getElementById('view-screenshots')?.scrollIntoView({ block: 'start' });
};

window.screenshotsFilter = (val) => {
  ssQuery = val.trim().toLowerCase();
  ssPage = 0;
  clearTimeout(ssFilterTimer);
  ssFilterTimer = setTimeout(renderScreenshotsPage, 250);
};

// ── Historical Section Tabs ──
async function loadHistoricalSection() {
  histCurrentPage = 0;
  await fetchAndRenderHistorical();
}

async function fetchAndRenderHistorical() {
  const container = document.getElementById('data-historical-content');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const qs = new URLSearchParams({
    target: currentTarget,
    tab: histActiveTab,
    query: histTextQuery,
    host: histHostQuery,
    ext: histExtQuery,
    hideStatic: histHideStatic,
    hide404: histHide404,
    hideDupes: histHideDupes,
    page: histCurrentPage,
    pageSize: histPageSize
  });

  const res = await fetchJSON(`/api/data/historical?${qs.toString()}`);
  if (!res) {
    container.innerHTML = '<div class="empty">Error fetching data.</div>';
    toast('Failed to load historical URLs.', 'err');
    return;
  }

  const { counts, items, total } = res;
  histTotalItems = total;

  // Update tab badges
  const badgeKeys = {
    interesting: 'tc-historical-interesting',
    validated: 'tc-historical-validated',
    auth: 'tc-historical-auth',
    apis: 'tc-historical-apis',
    sensitive: 'tc-historical-sensitive',
    static: 'tc-historical-static',
    all: 'tc-historical-all'
  };
  for (const [k, id] of Object.entries(badgeKeys)) {
    const el = document.getElementById(id);
    if (el && counts[k] !== undefined) {
      el.textContent = counts[k].toLocaleString();
    }
  }

  // Render Table
  let h = '';
  if (histActiveTab === 'validated') {
    h += `<table class="custom-table"><thead><tr>
      <th>URL</th>
      <th style="width:90px;">Status</th>
      <th>Title</th>
      <th>Content-Type</th>
      <th>Length</th>
    </tr></thead><tbody>`;

    if (items.length === 0) {
      h += `<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem;">No matching items found.</td></tr>`;
    } else {
      items.forEach(item => {
        h += `<tr>
          <td class="wrap-cell"><a href="${esc(item.url)}" target="_blank" class="triage-host">${hilite(item.url, histTextQuery)}</a></td>
          <td>${sBadge(item.status_code)}</td>
          <td class="wrap-cell">${esc(item.title || '')}</td>
          <td style="color:var(--muted);">${esc(item.content_type || '')}</td>
          <td style="color:var(--muted);">${item.content_length ? Number(item.content_length).toLocaleString() : ''}</td>
        </tr>`;
      });
    }
    h += `</tbody></table>`;
  } else {
    h += `<table class="custom-table"><thead><tr>
      <th style="width:60px;">#</th>
      <th>URL</th>
      <th style="width:120px;text-align:right;">Actions</th>
    </tr></thead><tbody>`;

    if (items.length === 0) {
      h += `<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:2rem;">No matching items found.</td></tr>`;
    } else {
      items.forEach((url, idx) => {
        const rowNum = histCurrentPage * histPageSize + idx + 1;
        h += `<tr>
          <td style="color:var(--muted);">${rowNum}</td>
          <td class="wrap-cell"><a href="${esc(url)}" target="_blank" class="triage-host">${hilite(url, histTextQuery)}</a></td>
          <td style="text-align:right;">
            <button class="btn btn-sm" onclick="copyToClipboard(${jsq(url)}, this)">copy</button>
          </td>
        </tr>`;
      });
    }
    h += `</tbody></table>`;
  }

  // Footer bar with pagination
  const pages = Math.ceil(histTotalItems / histPageSize) || 1;
  const start = histCurrentPage * histPageSize;

  h += `<div class="table-footer-bar">`;
  h += `<span>Showing ${histTotalItems === 0 ? 0 : start + 1}–${Math.min(start + histPageSize, histTotalItems)} of ${histTotalItems.toLocaleString()} entries</span>`;
  if (pages > 1) {
    h += `<div style="display:flex;gap:4px;">`;
    h += `<button class="btn btn-sm" onclick="window.changeHistPage('prev')" ${histCurrentPage === 0 ? 'disabled' : ''}>Prev</button>`;
    h += `<span style="align-self:center;margin:0 8px;font-size:12px;color:var(--muted);">Page ${histCurrentPage + 1} of ${pages}</span>`;
    h += `<button class="btn btn-sm" onclick="window.changeHistPage('next')" ${histCurrentPage >= pages - 1 ? 'disabled' : ''}>Next</button>`;
    h += `</div>`;
  }
  h += `</div>`;

  container.innerHTML = h;
}

window.changeHistPage = (dir) => {
  const pages = Math.ceil(histTotalItems / histPageSize) || 1;
  if (dir === 'prev' && histCurrentPage > 0) {
    histCurrentPage--;
    fetchAndRenderHistorical();
  } else if (dir === 'next' && histCurrentPage < pages - 1) {
    histCurrentPage++;
    fetchAndRenderHistorical();
  }
};

window.historicalFilter = (val) => {
  histTextQuery = val;
  histCurrentPage = 0;
  fetchAndRenderHistorical();
};

window.historicalHostFilter = (val) => {
  histHostQuery = val;
  histCurrentPage = 0;
  fetchAndRenderHistorical();
};

window.historicalExtFilter = (val) => {
  histExtQuery = val;
  histCurrentPage = 0;
  fetchAndRenderHistorical();
};

window.toggleHistHideStatic = (checked) => {
  histHideStatic = checked;
  histCurrentPage = 0;
  fetchAndRenderHistorical();
};

window.toggleHistHide404 = (checked) => {
  histHide404 = checked;
  histCurrentPage = 0;
  fetchAndRenderHistorical();
};

window.toggleHistHideDupes = (checked) => {
  histHideDupes = checked;
  histCurrentPage = 0;
  fetchAndRenderHistorical();
};

// ── JS Section ──
let jsActiveTab = 'scripts';
let jsTableCtrl = null;
const JS_TAB_FILES = {
  scripts: 'js/scripts_alive.txt', endpoints: 'js/endpoints.txt', secrets: 'js/secrets.txt',
  leakage: 'js/leakage.txt', comments: 'js/comments.txt', maps: 'js/maps_files.txt',
  api: 'js/api_endpoints.txt', buckets: 'js/buckets.txt', ws: 'js/websockets.txt'
};

async function loadJSSection() {
  const map = {};
  for (const [k, f] of Object.entries(JS_TAB_FILES)) map[`tc-js-${k}`] = f;
  fillTabCounts(map);
  renderJSTab();
}

function renderJSTab() {
  document.getElementById('data-js-content').innerHTML = '';
  jsTableCtrl = renderServerList('data-js-content', JS_TAB_FILES[jsActiveTab], 'Item details', _jsSearchVal);
}

function _jsSearchVal() {
  return document.getElementById('filter-js-search').value;
}

window.jsFilter = (val) => {
  jsTableCtrl?.filter(val.toLowerCase());
};

// ── Ports Section ──
let portsActiveTab = 'naabu';
let portsTableCtrl = null;
let portsRawSeq = 0;
const RAW_PANEL_MAX = 512 * 1024;   // bytes of a raw dump rendered in-page

async function loadPortsSection() {
  const counts = await fillTabCounts({ 'tc-ports-naabu': 'ports/naabu.txt', 'tc-ports-targets': 'ports/nmap_targets.txt' });
  // nmap dumps: just "present or not" for the badge (no download needed).
  const raw = await fetchJSON(`/api/data/counts?${new URLSearchParams({ target: currentTarget, files: 'ports/nmap_results.nmap,ports/nmap_results.gnmap' })}`);
  const rc = raw?.counts || {};
  document.getElementById('tc-ports-nmap').textContent = rc['ports/nmap_results.nmap'] ? '1' : '0';
  document.getElementById('tc-ports-gnmap').textContent = rc['ports/nmap_results.gnmap'] ? '1' : '0';
  renderPortsTab();
}

// Fetch at most `max` bytes of a target file; returns {text, truncated, total}.
async function fetchTextHead(rel, max = RAW_PANEL_MAX, mode = 'max') {
  try {
    const r = await fetch(API + T(rel) + `?${mode}=${max}`);
    if (!r.ok) return { text: '', truncated: false, total: 0 };
    return {
      text: await r.text(),
      truncated: r.headers.get('X-Truncated') === '1',
      total: parseInt(r.headers.get('X-Total-Size') || '0', 10)
    };
  } catch { return { text: '', truncated: false, total: 0 }; }
}

function truncNote(rel, res, where = 'first') {
  if (!res.truncated) return '';
  const mb = (n) => (n / 1048576).toFixed(1) + ' MB';
  return `<div class="empty" style="padding:8px;text-align:left;">Showing the ${where} ${mb(RAW_PANEL_MAX)} of ${mb(res.total)}. ` +
    `<a href="${esc(T(rel))}" target="_blank" rel="noopener">Open full file</a></div>`;
}

// Triage Report: render reports/triage_report.md (written by the triage-results skill).
// Shown as readable preformatted text — no markdown lib (keeps the zero-dependency goal).
async function loadTriageReport() {
  const el = document.getElementById('triage-report-body');
  if (!el || !currentTarget) return;
  el.textContent = 'Loading…';
  // Reveal the Run Triage button only when the server has agent runs enabled.
  const status = await fetchJSON('/api/scans/active');
  const btn = document.getElementById('run-triage-btn');
  if (btn) btn.hidden = !(status && status.agent_runs_enabled);
  const rel = 'reports/triage_report.md';
  const res = await fetchTextHead(rel);
  if (!res.text) {
    el.innerHTML = '<div class="empty" style="padding:12px;text-align:left;">' +
      'No triage report yet. Run the <strong>triage-results</strong> skill against this ' +
      'target to generate <code>reports/triage_report.md</code>.</div>';
    return;
  }
  el.innerHTML = truncNote(rel, res) + esc(res.text);
}
window.loadTriageReport = loadTriageReport;

// Launch the triage-results skill as a tracked agent run for the current target.
window.runTriage = async function() {
  if (!currentTarget) return;
  const btn = document.getElementById('run-triage-btn');
  if (btn) btn.disabled = true;
  const res = await postJSON('/api/triage/start', { target: currentTarget });
  if (btn) btn.disabled = false;
  if (res && res.ok) {
    toast('Triage started — watch the run tracker; refresh when it completes.', 'info', 6000);
    startScanTrackerPoll();
  } else {
    toast((res && res.message) || 'Could not start triage.', 'err');
  }
};

async function renderPortsTab() {
  const containerId = 'data-ports-content';
  const container = document.getElementById(containerId);
  const q = document.getElementById('filter-ports-search').value;
  container.innerHTML = '';
  portsRawSeq++;

  if (portsActiveTab === 'naabu') {
    const ctrl = makeServerTable(
      containerId,
      (p) => `/api/data/table?${new URLSearchParams({ target: currentTarget, kind: 'ports', ...p })}`,
      [{ key: 'host', label: 'Host' }, { key: 'port', label: 'Port' }],
      (item, _i, a) => `<tr><td>${hilite(item.host, a.q || '')}</td><td style="color:var(--accent); font-weight:600;">${hilite(item.port, a.q || '')}</td></tr>`,
      { args: { q: q.toLowerCase() } }
    );
    ctrl.render();
    portsTableCtrl = { filter: (text) => ctrl.filter({ q: text }) };
  } else if (portsActiveTab === 'targets') {
    portsTableCtrl = renderServerList(containerId, 'ports/nmap_targets.txt', 'Targets block',
      () => document.getElementById('filter-ports-search').value);
  } else {
    // Raw nmap / greppable dumps (head only — these can be large)
    portsTableCtrl = null;
    const rel = portsActiveTab === 'nmap' ? 'ports/nmap_results.nmap' : 'ports/nmap_results.gnmap';
    container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    const mySeq = ++portsRawSeq;
    const res = await fetchTextHead(rel);
    if (mySeq === portsRawSeq && (portsActiveTab === 'nmap' || portsActiveTab === 'gnmap')) {
      container.innerHTML = truncNote(rel, res) + `<div class="raw-view-panel">${esc(res.text || 'No raw output data.')}</div>`;
    }
  }
}

window.portsFilter = (val) => {
  portsTableCtrl?.filter(val.toLowerCase());
};

// ── Dorks Section ──
let dorksActiveTab = 'all';
let dorksTableCtrl = null;
const DORK_TAB_FILES = {
  all: 'dorks/all_findings.txt', config: 'dorks/passive_config_files.txt',
  backups: 'dorks/passive_backup_files.txt', logs: 'dorks/passive_log_files.txt',
  admin: 'dorks/passive_admin_panels.txt', cloud: 'dorks/passive_cloud_assets.txt',
  auth: 'dorks/passive_auth_tokens.txt', active: 'dorks/active_hits.txt',
  confirmed: 'dorks/active_confirmed.txt'
};

async function loadDorksSection() {
  const map = {};
  for (const [k, f] of Object.entries(DORK_TAB_FILES)) map[`tc-dorks-${k}`] = f;
  fillTabCounts(map);
  renderDorksTab();
}

function _dorksSearchVal() {
  return document.getElementById('filter-dorks-search').value;
}

function renderDorksTab() {
  document.getElementById('data-dorks-content').innerHTML = '';
  dorksTableCtrl = renderServerList('data-dorks-content', DORK_TAB_FILES[dorksActiveTab], 'Dork findings & context', _dorksSearchVal);
}

window.dorksFilter = (val) => {
  dorksTableCtrl?.filter(val.toLowerCase());
};

// ── Raw Files Page ──
async function loadRawFilesSection() {
  const indexContainer = document.getElementById('raw-files-index');
  indexContainer.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const res = await fetchJSON(`/api/target/files?target=${currentTarget}`);
  rawFilesList = res?.files || [];

  if (rawFilesList.length === 0) {
    indexContainer.innerHTML = '<div class="empty">No raw files detected.</div>';
    return;
  }

  let h = '';
  rawFilesList.forEach(file => {
    h += `<div class="raw-file-item" onclick="viewRawFile(${jsq(file)}, this)">${esc(file)}</div>`;
  });
  indexContainer.innerHTML = h;

  // Auto-open first file
  const first = indexContainer.querySelector('.raw-file-item');
  if (first) first.click();
}

window.viewRawFile = async function(file, el) {
  document.querySelectorAll('.raw-file-item').forEach(item => item.classList.remove('active'));
  el.classList.add('active');

  const viewer = document.getElementById('raw-file-viewer');
  viewer.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  // Head only: multi-MB raw files would freeze (or crash) a phone.
  const res = await fetchTextHead(file);
  viewer.innerHTML = truncNote(file, res) + `<div class="raw-view-panel" style="max-height: 600px;">${esc(res.text)}</div>`;
};

// ── Monitor Scan ──
async function loadMonitor() {
  const container = document.getElementById('data-monitor');
  const summaryContainer = document.getElementById('monitor-baseline-summary');
  if (!container) return;

  const data = await fetchJSON(`/api/monitor/changes?target=${currentTarget}`);
  const changes = data?.changes || [];

  document.getElementById('badge-monitor').textContent = changes.length;

  const status = await fetchJSON(`/api/monitor/status?target=${currentTarget}`);
  
  let sh = `<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 12px;">`;
  sh += `<div class="overview-stat-box" style="padding: 10px 14px;"><div class="overview-stat-val" style="font-size:18px;">${status?.baseline_subdomains ?? '--'}</div><div class="overview-stat-lbl">Subs Baseline</div></div>`;
  sh += `<div class="overview-stat-box" style="padding: 10px 14px;"><div class="overview-stat-val" style="font-size:18px;">${status?.baseline_ports ?? '--'}</div><div class="overview-stat-lbl">Ports Baseline</div></div>`;
  sh += `<div class="overview-stat-box" style="padding: 10px 14px;"><div class="overview-stat-val" style="font-size:18px;">${changes.length}</div><div class="overview-stat-lbl">Checks Run</div></div>`;
  sh += `</div>`;
  summaryContainer.innerHTML = sh;

  if (changes.length === 0) {
    container.innerHTML = '<div class="empty">No monitor history changes logged. Run a monitor check first.</div>';
    return;
  }

  let h = '';
  changes.forEach((c, idx) => {
    const s = c.summary || {};
    h += `<div class="panel" style="margin-bottom:12px;">`;
    h += `<div style="font-family:var(--font-mono); font-size:11px; color:var(--muted); margin-bottom:8px;">Check run: <b>${new Date(c.timestamp).toLocaleString()}</b></div>`;
    h += `<div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">`;
    if (s.subdomains_added > 0) h += `<span class="badge-status s2xx">+${s.subdomains_added} subdomains</span>`;
    if (s.subdomains_removed > 0) h += `<span class="badge-status s5xx">-${s.subdomains_removed} subdomains</span>`;
    if (s.ports_added > 0) h += `<span class="badge-status s2xx">+${s.ports_added} ports</span>`;
    if (s.ports_removed > 0) h += `<span class="badge-status s5xx">-${s.ports_removed} ports</span>`;
    if (s.total_changes === 0) h += `<span class="badge-status s-na">no changes detected</span>`;
    h += `</div>`;

    if (s.total_changes > 0) {
      h += `<button class="btn btn-sm" onclick="this.nextElementSibling.classList.toggle('hide')">inspect diff details</button>`;
      h += `<div class="raw-view-panel hide" style="margin-top:8px; max-height:220px; font-size:11px;">`;
      if (c.new_subdomains?.length) h += `New subdomains:\n${c.new_subdomains.map(sub => '+ ' + sub).join('\n')}\n\n`;
      if (c.removed_subdomains?.length) h += `Removed subdomains:\n${c.removed_subdomains.map(sub => '- ' + sub).join('\n')}\n\n`;
      if (c.new_ports?.length) h += `New ports:\n${c.new_ports.map(port => '+ ' + port).join('\n')}\n\n`;
      if (c.removed_ports?.length) h += `Removed ports:\n${c.removed_ports.map(port => '- ' + port).join('\n')}\n\n`;
      h += `</div>`;
    }
    h += `</div>`;
  });
  container.innerHTML = h;
}

// ── Modals, Lightbox & Options ──
const MODULES = [
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'dns', label: 'DNS Resolve' },
  { id: 'http', label: 'HTTP Probing' },
  { id: 'screenshots', label: 'Screenshots' },
  { id: 'ports', label: 'Port Scanning' },
  { id: 'js', label: 'Deep JS analysis' },
  { id: 'historical', label: 'Historical URLs' },
  { id: 'crawl', label: 'Crawl endpoints' },
  { id: 'dorks', label: 'Passive Dorking' },
  { id: 'infra', label: 'Infra mapping' },
  { id: 'report', label: 'Summary Report' }
];
const enabledModules = new Set(MODULES.map(m => m.id));

function renderModulesGrid() {
  const el = document.getElementById('modules-grid');
  let h = '';
  MODULES.forEach(m => {
    const active = enabledModules.has(m.id);
    h += `<div class="mod-toggle ${active ? 'active' : ''}" onclick="toggleModule('${m.id}', this)">`;
    h += `<span class="dot"></span>${m.label}`;
    h += `</div>`;
  });
  el.innerHTML = h;
}

window.toggleModule = (id, el) => {
  if (enabledModules.has(id)) {
    enabledModules.delete(id);
    el.classList.remove('active');
  } else {
    enabledModules.add(id);
    el.classList.add('active');
  }
};

window.openScanModal = () => {
  renderModulesGrid();
  document.getElementById('scan-modal').classList.add('open');
};

window.closeScanModal = () => {
  document.getElementById('scan-modal').classList.remove('open');
};

window.openScanLog = () => {
  document.getElementById('scan-log').classList.add('vis');
};

window.openLightbox = (src, label) => {
  document.getElementById('lb-img').src = src;
  document.getElementById('lb-label').textContent = label;
  document.getElementById('lightbox').classList.add('open');
};

document.getElementById('lightbox').addEventListener('click', function() {
  this.classList.remove('open');
});

// Start active scan trigger
window.startScan = async function() {
  const domain = document.getElementById('scan-domain').value.trim();
  if (!domain) {
    document.getElementById('scan-domain').style.borderColor = 'var(--danger)';
    return;
  }
  const skip = MODULES.filter(m => !enabledModules.has(m.id)).map(m => m.id);
  const threads = document.getElementById('scan-threads').value || undefined;
  const top_ports = document.getElementById('scan-ports').value || undefined;
  // Two user selections: "overall" paces both HTTP probing and port scanning;
  // "firewall-prone" paces the noisy stages and is kept ≤ overall.
  const overall = document.getElementById('scan-overall-rate')?.value || undefined;
  let active_rate = document.getElementById('scan-active-rate')?.value || undefined;
  const headers = (document.getElementById('scan-headers')?.value || '')
    .split('\n').map(s => s.trim()).filter(Boolean);

  if (overall && active_rate && Number(active_rate) > Number(overall)) {
    active_rate = overall;
    toast('Firewall-prone rate clamped to overall rate', 'info', 2500);
  }

  // The one "overall" dial maps to both the HTTP rate and the port-scan rate.
  const res = await postJSON('/api/scan/start',
    { domain, skip, threads, rate: overall, top_ports,
      http_rate: overall, active_rate, headers });
  if (res?.ok) {
    toast(`Scan started for ${domain}`, 'ok');
    // Multi-target: don't lock the UI — surface progress in the Explorer
    // tracker and let the user queue more targets (backend enforces the cap).
    closeScanModal();
    loadScanTracker();
    startScanTrackerPoll();
    openScanDetail(domain);
  } else {
    toast(res?.message || 'Failed to start scan', 'err');
  }
};

window.stopScan = async function(target) {
  await postJSON('/api/scan/stop', target ? { target } : {});
};

// Active scan logger check with smart auto-scroll
let scanPollTimer = null;
function isNearBottom(el) {
  if (!el) return true;
  return el.scrollHeight - el.scrollTop - el.clientHeight < 60;
}

function pollScanLog() {
  if (scanPollTimer) clearInterval(scanPollTimer);
  scanPollTimer = setInterval(async () => {
    if (document.hidden) return;                 // no polling while backgrounded
    const s = await fetchJSON('/api/scan/status');
    if (!s) return;
    const logEl = document.getElementById('scan-log');
    const logsViewEl = document.getElementById('logs-scan-log');
    const autoScrollEnabled = document.getElementById('log-auto-scroll')?.checked !== false;

    if (s.log_tail?.length) {
      const tail = s.log_tail.join('\n');
      logEl.textContent = tail;
      
      // Update logs view dynamically if active stream
      if (logsViewEl && (logsViewEl.textContent.startsWith('No logs active') || logsViewEl.classList.contains('active-stream'))) {
        const wasAtBottom = isNearBottom(logsViewEl);
        logsViewEl.textContent = tail;
        logsViewEl.classList.add('active-stream');
        if (wasAtBottom && autoScrollEnabled) {
          logsViewEl.scrollTop = logsViewEl.scrollHeight;
        }
      }
    }
    if (isNearBottom(logEl)) {
      logEl.scrollTop = logEl.scrollHeight;
    }

    updateScanBar(s);

    if (!s.running && s.finished) {
      clearInterval(scanPollTimer);
      scanPollTimer = null;
      document.getElementById('start-scan-btn').disabled = false;
      if (logsViewEl) logsViewEl.classList.remove('active-stream');
      loadExplorer();
    }
  }, 2000);
}

function updateScanBar(s) {
  const bar = document.getElementById('scan-bar');
  if (s.running) {
    bar.classList.add('vis');
    const elapsed = s.elapsed ? `${Math.floor(s.elapsed/60)}m ${s.elapsed%60}s` : '';
    const stepText = s.current_step ? ` [Step: ${s.current_step}]` : '';
    const label = s.kind === 'monitor' ? 'Monitor check' : 'Active scan';
    document.getElementById('scan-bar-text').textContent = `${label} running for ${s.domain || ''}... ${elapsed}${stepText}`;
    
    const progressEl = document.getElementById('scan-progress-bar');
    if (progressEl) {
      progressEl.style.width = `${s.progress_percent || 0}%`;
    }
  } else {
    bar.classList.remove('vis');
  }
}

async function checkScanStatus() {
  const s = await fetchJSON('/api/scan/status');
  if (s?.running) {
    updateScanBar(s);
    pollScanLog();
  }
}

// ── Logs Section ──
let loadedLogFiles = [];
async function loadLogsSection() {
  const selector = document.getElementById('log-file-selector');
  const consoleEl = document.getElementById('logs-scan-log');
  selector.innerHTML = '<option value="">Loading...</option>';
  
  const res = await fetchJSON(`/api/logs?target=${currentTarget}`);
  if (!res || !res.files || res.files.length === 0) {
    selector.innerHTML = '<option value="">No logs found</option>';
    consoleEl.textContent = 'No historical scan logs found for this target.';
    return;
  }
  
  loadedLogFiles = res.files;
  
  let h = '';
  res.files.forEach(f => {
    let label = f;
    const match = f.match(/scan_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})\.log/);
    if (match) {
      label = `${match[1]}-${match[2]}-${match[3]} ${match[4]}:${match[5]}:${match[6]}`;
    }
    h += `<option value="${esc(f)}">${esc(label)}</option>`;
  });
  selector.innerHTML = h;
  
  if (res.files.length > 0) {
    selectLogFile(res.files[0]);
  }
}

window.selectLogFile = async function(filename) {
  const consoleEl = document.getElementById('logs-scan-log');
  if (!filename) {
    consoleEl.textContent = 'Select a log run from the dropdown above to inspect.';
    return;
  }
  consoleEl.textContent = 'Loading log file...';
  consoleEl.classList.remove('active-stream');
  
  // Tail only: the end of a long scan log is what matters, and the full file
  // can be many MB.
  const res = await fetchTextHead(`logs/${filename}`, RAW_PANEL_MAX, 'tail');
  consoleEl.textContent = (res.truncated ? `… (showing the last ${(RAW_PANEL_MAX / 1048576).toFixed(1)} MB of ${(res.total / 1048576).toFixed(1)} MB)\n` : '') + (res.text || 'Empty log file.');
  consoleEl.scrollTop = consoleEl.scrollHeight;
};

// ── Monitor check modals ──
window.openMonitorModal = () => {
  document.getElementById('monitor-modal').classList.add('open');
};
window.closeMonitorModal = () => {
  document.getElementById('monitor-modal').classList.remove('open');
};
window.toggleMonitor = async (target, enabled) => {
  const res = await postJSON('/api/monitor/toggle', { target, enabled });
  if (res?.ok) {
    toast(`Monitoring ${enabled ? 'enabled' : 'disabled'} for ${target}`, 'ok');
  } else {
    toast('Failed to update monitoring.', 'err');
  }
};
window.submitMonitorModal = async () => {
  const domain = document.getElementById('monitor-domain').value.trim();
  if (!domain) {
    document.getElementById('monitor-domain').style.borderColor = 'var(--danger)';
    return;
  }
  closeMonitorModal();
  const status = await fetchJSON(`/api/monitor/status?target=${domain}`);
  const init = !(status?.has_baselines);
  const res = await postJSON('/api/monitor/start', { domain, target: domain, init });
  if (res?.ok) {
    openScanModal();
    document.getElementById('scan-log').classList.add('vis');
    toast(`Monitor check started for ${domain}`, 'ok');
    pollScanLog();
  } else {
    toast(res?.message || 'Failed to start monitor check.', 'err');
  }
};

window.runMonitorScan = async () => {
  if (!currentTarget) {
    openMonitorModal();
    return;
  }
  const domain = document.getElementById('topbar-domain')?.textContent || currentTarget;
  const status = await fetchJSON(`/api/monitor/status?target=${currentTarget}`);
  const init = !(status?.has_baselines);
  const res = await postJSON('/api/monitor/start', { domain, target: currentTarget, init });
  if (res?.ok) {
    openScanModal();
    document.getElementById('scan-log').classList.add('vis');
    toast(`Monitor check started for ${domain}`, 'ok');
    pollScanLog();
  } else {
    toast(res?.message || 'Failed to start monitor check.', 'err');
  }
};

// ── Mobile Sidebar ──
window.openSidebar = () => {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').classList.add('on');
};

window.closeSidebar = () => {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('on');
};

// Close sidebar when nav item is clicked on mobile
document.querySelectorAll('.sidebar-nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    if (window.innerWidth <= 768) closeSidebar();
  });
});

// ── Log Search/Filter ──
window.filterLogContent = (query) => {
  const consoleEl = document.getElementById('logs-scan-log');
  if (!consoleEl) return;
  const text = consoleEl.textContent;
  if (!query || !query.trim()) {
    consoleEl.innerHTML = '';
    consoleEl.textContent = text;
    return;
  }
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(${escaped})`, 'gi');
  consoleEl.innerHTML = text.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(re, '<span class="hl">$1</span>');
};

// ── Diff Matrix Section ──
async function loadDiffSection() {
  if (!currentTarget) return;
  const selA = document.getElementById('diff-scan-a');
  const selB = document.getElementById('diff-scan-b');

  const data = await fetchJSON(`/api/scans?target=${currentTarget}`);
  const scans = data?.scans || [];
  
  if (scans.length === 0) {
    selA.innerHTML = '<option value="">No scans found</option>';
    selB.innerHTML = '<option value="">No scans found</option>';
    document.getElementById('diff-results').innerHTML = '<div class="empty">No scan data ingested yet. Run a scan or trigger manual ingest first.</div>';
    return;
  }

  let opts = '<option value="">Select scan...</option>';
  scans.forEach(s => {
    const label = s.timestamp ? new Date(s.timestamp).toLocaleString() : `Scan #${s.id}`;
    opts += `<option value="${s.id}">${esc(label)} (${esc(s.domain || '')})</option>`;
  });
  selA.innerHTML = opts;
  selB.innerHTML = opts;
}

window.runDiff = async function() {
  const scanA = document.getElementById('diff-scan-a').value;
  const scanB = document.getElementById('diff-scan-b').value;
  const resultsEl = document.getElementById('diff-results');

  if (!scanA || !scanB) {
    resultsEl.innerHTML = '<div class="empty">Please select both scans to compare.</div>';
    return;
  }
  if (scanA === scanB) {
    resultsEl.innerHTML = '<div class="empty">Select two different scans to compare.</div>';
    return;
  }

  resultsEl.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const diff = await fetchJSON(`/api/diff?target=${currentTarget}&scan_a=${scanA}&scan_b=${scanB}`);
  if (!diff || diff.error) {
    resultsEl.innerHTML = `<div class="empty">${diff?.error || 'Failed to load diff.'}</div>`;
    return;
  }

  let h = '';

  // Summary cards
  const sections = [
    { key: 'subdomains', label: 'Subdomains' },
    { key: 'ports', label: 'Ports' },
    { key: 'web_apps', label: 'Web Apps' }
  ];

  h += '<div class="diff-summary">';
  for (const sec of sections) {
    const d = diff[sec.key] || {};
    const added = (d.added || []).length;
    const removed = (d.removed || []).length;
    h += `<div class="diff-stat"><div class="diff-stat-val" style="color:var(--green);">+${added}</div><div class="diff-stat-lbl">${sec.label} Added</div></div>`;
    h += `<div class="diff-stat"><div class="diff-stat-val" style="color:var(--red);">-${removed}</div><div class="diff-stat-lbl">${sec.label} Removed</div></div>`;
  }
  if (diff.web_apps?.status_changed) {
    h += `<div class="diff-stat"><div class="diff-stat-val" style="color:var(--amber);">${diff.web_apps.status_changed.length}</div><div class="diff-stat-lbl">Status Changed</div></div>`;
  }
  h += '</div>';

  // Detail sections
  for (const sec of sections) {
    const d = diff[sec.key] || {};
    if ((d.added?.length || 0) + (d.removed?.length || 0) === 0) continue;
    
    h += `<div class="diff-section"><h4>${sec.label}</h4>`;
    (d.added || []).forEach(item => {
      const val = typeof item === 'string' ? item : item.url || item.hostname || JSON.stringify(item);
      h += `<div class="diff-added">${esc(val)}</div>`;
    });
    (d.removed || []).forEach(item => {
      const val = typeof item === 'string' ? item : item.url || item.hostname || JSON.stringify(item);
      h += `<div class="diff-removed">${esc(val)}</div>`;
    });
    h += '</div>';
  }

  // Status changes
  if (diff.web_apps?.status_changed?.length) {
    h += '<div class="diff-section"><h4>Status Code Changes</h4>';
    diff.web_apps.status_changed.forEach(item => {
      h += `<div style="font-family:var(--mono);font-size:11px;padding:3px 0;color:var(--fg-2);">${esc(item.url)} <span style="color:var(--red)">${item.old_status}</span> → <span style="color:var(--green)">${item.new_status}</span></div>`;
    });
    h += '</div>';
  }

  if (!h.trim()) h = '<div class="empty">No differences found between selected scans.</div>';
  resultsEl.innerHTML = h;
};

// ── Scope Loader (for scan modal) ──
async function loadScopeRules() {
  const data = await fetchJSON('/api/scope');
  if (!data?.rules) return;
  const inEl = document.getElementById('scope-in');
  const outEl = document.getElementById('scope-out');
  if (inEl) inEl.value = (data.rules.in_scope || []).join('\n');
  if (outEl) outEl.value = (data.rules.out_of_scope || []).join('\n');
}

async function saveScopeRules() {
  const inVal = (document.getElementById('scope-in')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const outVal = (document.getElementById('scope-out')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  await postJSON('/api/scope', {
    global_rules: { in_scope: inVal, out_of_scope: outVal },
    target_overrides: {}
  });
}

// Override openScanModal to also load scope rules
const _origOpenScanModal = window.openScanModal;
window.openScanModal = function() {
  _origOpenScanModal();
  loadScopeRules();
};

// Override startScan to also save scope before starting
const _origStartScan = window.startScan;
window.startScan = async function() {
  await saveScopeRules();
  _origStartScan();
};

// ════════════════════════════════════════════════════════════════
// Keyboard model + command bar (Phase 2) — makes it a workstation
// ════════════════════════════════════════════════════════════════

function _typing() {
  const el = document.activeElement;
  if (!el) return false;
  const t = el.tagName;
  return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el.isContentEditable;
}
function _cmdOpen() { return document.getElementById('cmdbar-overlay')?.classList.contains('open'); }
function _helpOpen() { return document.getElementById('help-modal')?.classList.contains('open'); }

function openHelp() { document.getElementById('help-modal').classList.add('open'); }
function closeHelp() { document.getElementById('help-modal').classList.remove('open'); }
window.closeHelp = closeHelp;

const GO_MAP = { o: 'overview', q: 'triage', a: 'assets', w: 'webapps', s: 'screenshots', h: 'historical', j: 'js', p: 'ports', d: 'dorks', m: 'monitor', f: 'diff', l: 'logs', r: 'rawfiles' };
let _pendingG = false;

function moveTriageCursor(delta) {
  if (!triageVisible.length) return;
  let i = triageCursor;
  i = (i < 0) ? 0 : Math.max(0, Math.min(triageVisible.length - 1, i + delta));
  triageCursor = i;
  const item = triageVisible[i];
  if (!item) return;
  if (i >= triageRenderLimit) {
    triageRenderLimit = i + TRIAGE_RENDER_STEP;
    renderTriageList();
  }
  selectAsset(item.host);
  const sel = (window.CSS && CSS.escape) ? CSS.escape(item.host) : item.host.replace(/"/g, '\\"');
  const row = document.querySelector(`#triage-list-container .triage-row[data-host="${sel}"]`);
  if (row) row.scrollIntoView({ block: 'nearest' });
}

document.addEventListener('keydown', (e) => {
  if (_cmdOpen()) { if (e.key === 'Escape') { closeCmd(); e.preventDefault(); } return; }
  if (_helpOpen()) { if (e.key === 'Escape') { closeHelp(); e.preventDefault(); } return; }

  // Cmd/Ctrl+K opens the command bar from anywhere (even while typing)
  if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); openCmd(); return; }

  if (_typing()) return;                       // never hijack text fields
  if (e.metaKey || e.ctrlKey || e.altKey) return;

  if (_pendingG) {
    _pendingG = false;
    const v = GO_MAP[e.key.toLowerCase()];
    if (v && currentTarget) { e.preventDefault(); switchView(v); }
    return;
  }

  if (e.key === '/') { e.preventDefault(); openCmd(); return; }
  if (e.key === '?') { e.preventDefault(); openHelp(); return; }
  if (e.key === 'g') { _pendingG = true; return; }
  if (e.key === 'Escape') { closeDossier(); return; }

  if (currentView === 'triage' && currentTarget) {
    const k = e.key.toLowerCase();
    const it = triageVisible[triageCursor];
    if (k === 'j') { e.preventDefault(); moveTriageCursor(1); }
    else if (k === 'k') { e.preventDefault(); moveTriageCursor(-1); }
    else if (k === 'o' || e.key === 'Enter') { if (it) { e.preventDefault(); window.open(it.url, '_blank', 'noopener'); } }
    else if (k === 's') { if (it) { e.preventDefault(); toggleTriageStar(it.host, null); } }
    else if (k === 'x') { if (it) { e.preventDefault(); toggleTriageIgnore(it.host, null); } }
  }
});

// ── Command bar: quick-nav + global search across the current target ──
let cmdResults = [];
let cmdCursor = 0;

const CMD_VIEWS = [
  { id: 'overview', label: 'Overview' }, { id: 'triage', label: 'Hunt Queue' },
  { id: 'triagereport', label: 'Triage Report' },
  { id: 'assets', label: 'Assets' }, { id: 'webapps', label: 'Web Apps' },
  { id: 'screenshots', label: 'Screenshots' }, { id: 'historical', label: 'Historical' },
  { id: 'js', label: 'JS' }, { id: 'ports', label: 'Ports' }, { id: 'dorks', label: 'Dorks' },
  { id: 'diff', label: 'Diff Matrix' }, { id: 'monitor', label: 'Monitor' },
  { id: 'logs', label: 'Logs' }, { id: 'rawfiles', label: 'Raw Files' },
];

function openCmd() {
  const o = document.getElementById('cmdbar-overlay');
  o.classList.add('open');
  const i = document.getElementById('cmdbar-input');
  i.value = '';
  i.focus();
  buildCmd('');
}
function closeCmd() { document.getElementById('cmdbar-overlay').classList.remove('open'); }
window.openCmd = openCmd;
window.closeCmd = closeCmd;
window._cmdInput = (v) => buildCmd(v);

function buildCmd(q) {
  q = (q || '').trim().toLowerCase();
  const res = [];

  if (!q || 'start new scan'.includes(q) || 'scan'.includes(q)) {
    res.push({ kind: 'action', label: 'Start new scan', run: () => { closeCmd(); openScanModal(); } });
  }
  if (!q || 'run monitor check'.includes(q) || 'monitor'.includes(q)) {
    res.push({ kind: 'action', label: 'Run monitor check', run: () => { closeCmd(); runMonitorScan(); } });
  }
  if (currentTarget) {
    CMD_VIEWS.forEach(v => {
      if (!q || v.label.toLowerCase().includes(q) || v.id.includes(q)) {
        res.push({ kind: 'go', label: v.label, run: () => { closeCmd(); switchView(v.id); } });
      }
    });
    if (q) {
      huntQueueItems
        .filter(it => it.host.toLowerCase().includes(q) || (it.title || '').toLowerCase().includes(q))
        .slice(0, 8)
        .forEach(it => res.push({
          kind: 'host',
          label: `${it.host}${it.title ? ' — ' + it.title : ''}`,
          run: () => { closeCmd(); switchView('triage'); selectAsset(it.host); }
        }));
      res.push({
        kind: 'hist',
        label: `Search historical for "${q}"`,
        run: () => {
          closeCmd();
          switchView('historical');
          histTextQuery = q;
          histCurrentPage = 0;
          const inp = document.getElementById('filter-historical-search');
          if (inp) inp.value = q;
          fetchAndRenderHistorical();
        }
      });
    }
  }

  cmdResults = res;
  cmdCursor = 0;
  renderCmd();
}

function renderCmd() {
  const el = document.getElementById('cmdbar-results');
  if (!cmdResults.length) {
    el.innerHTML = '<div class="cmd-item"><span class="cmd-label" style="color:var(--fg-3)">No matches</span></div>';
    return;
  }
  el.innerHTML = cmdResults.map((r, i) =>
    `<div class="cmd-item ${i === cmdCursor ? 'on' : ''}" data-i="${i}" onclick="window._cmdRun(${i})">
       <span class="cmd-kind">${r.kind}</span><span class="cmd-label">${esc(r.label)}</span>
     </div>`).join('');
}
window._cmdRun = (i) => { const r = cmdResults[i]; if (r) r.run(); };

(function wireCmdInput() {
  const inp = document.getElementById('cmdbar-input');
  if (!inp) return;
  inp.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); cmdCursor = Math.min(cmdResults.length - 1, cmdCursor + 1); renderCmd(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); cmdCursor = Math.max(0, cmdCursor - 1); renderCmd(); }
    else if (e.key === 'Enter') { e.preventDefault(); const r = cmdResults[cmdCursor]; if (r) r.run(); }
    else if (e.key === 'Escape') { e.preventDefault(); closeCmd(); }
  });
})();

// Initialize
loadExplorer();
})();
