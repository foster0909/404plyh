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

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function parseLines(t){return t.split('\n').map(l=>l.strip ? l.strip() : l.trim()).filter(Boolean)}
function sBadge(c){const n=parseInt(c);if(!n)return'<span class="badge-status s-na">--</span>';const k=n<300?'2xx':n<400?'3xx':n<500?'4xx':'5xx';return`<span class="badge-status s${k}">${n}</span>`}
function hilite(text,q){if(!q)return esc(text);const re=new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`,'gi');return esc(text).replace(re,'<span class="hl">$1</span>')}

// ── Advanced Reusable Paged Table Maker ──
let _pagId = 0;
const _pagRegistry = {};
function makePagedTable(containerId, items, columns, renderRowFn, filterFn, pageSize = 50) {
  let page = 0;
  let filtered = [...items];
  let sortBy = null;
  let sortAsc = true;
  const id = _pagId++;

  function sortData(colKey) {
    if (sortBy === colKey) {
      sortAsc = !sortAsc;
    } else {
      sortBy = colKey;
      sortAsc = true;
    }
    filtered.sort((a, b) => {
      let valA = a[colKey] !== undefined ? a[colKey] : '';
      let valB = b[colKey] !== undefined ? b[colKey] : '';
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
    page = 0;
    render();
  }

  function filter(filterArgs) {
    filtered = items.filter(item => filterFn(item, filterArgs));
    page = 0;
    render();
    return filtered.length;
  }

  function render() {
    const el = document.getElementById(containerId);
    if (!el) return;
    const total = filtered.length;
    const pages = Math.ceil(total / pageSize) || 1;
    const start = page * pageSize;
    const slice = filtered.slice(start, start + pageSize);

    let h = `<table class="custom-table"><thead><tr>`;
    columns.forEach(col => {
      const arrow = sortBy === col.key ? (sortAsc ? ' ▴' : ' ▾') : '';
      h += `<th style="${col.style || ''}" onclick="_tblSort(${id}, '${col.key}')">${col.label}${arrow}</th>`;
    });
    h += `</tr></thead><tbody>`;

    if (slice.length === 0) {
      h += `<tr><td colspan="${columns.length}" style="text-align:center;color:var(--muted);padding:2rem;">No matching items found.</td></tr>`;
    } else {
      slice.forEach((item, index) => {
        h += renderRowFn(item, start + index);
      });
    }
    h += `</tbody></table>`;

    // Pagination
    h += `<div class="table-footer-bar">`;
    h += `<span>Showing ${total === 0 ? 0 : start + 1}–${Math.min(start + pageSize, total)} of ${total} entries</span>`;
    if (pages > 1) {
      h += `<div style="display:flex;gap:4px;">`;
      h += `<button class="btn btn-sm" onclick="_tblPage(${id}, 'prev')" ${page === 0 ? 'disabled' : ''}>Prev</button>`;
      h += `<button class="btn btn-sm" onclick="_tblPage(${id}, 'next')" ${page >= pages - 1 ? 'disabled' : ''}>Next</button>`;
      h += `</div>`;
    }
    h += `</div>`;

    el.innerHTML = h;
  }

  _pagRegistry[id] = {
    sortData,
    prev() { if (page > 0) { page--; render(); } },
    next() { if (page < Math.ceil(filtered.length / pageSize) - 1) { page++; render(); } },
    render
  };

  return { render, filter, count: () => filtered.length, items: () => filtered };
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
}

function renderTargets(targets) {
  const el = document.getElementById('targets-container');
  if (!targets.length) {
    el.innerHTML = '<tr><td colspan="2" class="empty-placeholder">No targets found. Run a scan to register your first project.</td></tr>';
    return;
  }
  let h = '';
  for (const t of targets) {
    const s = t.stats || {};
    const date = t.scan_date ? new Date(t.scan_date).toLocaleDateString() : '';
    const mon = t.monitor_enabled;

    h += `<tr>`;
    h += `<td>`;
    h += `<div class="target-name" onclick="openTarget('${esc(t.name)}')">${esc(t.domain || t.name)}</div>`;
    h += `<div class="target-stats-inline">`;
    if (date) h += `<span>Date: <b>${date}</b></span>`;
    if (s.total_subdomains) h += `<span>Subs: <b>${s.total_subdomains}</b></span>`;
    if (s.alive_services) h += `<span>Web apps: <b>${s.alive_services}</b></span>`;
    if (s.open_ports) h += `<span>Ports: <b>${s.open_ports}</b></span>`;
    if (s.dork_findings) h += `<span>Dorks: <b style="color:var(--accent)">${s.dork_findings}</b></span>`;
    h += `</div>`;
    h += `</td>`;
    h += `<td>`;
    h += `<div style="display:flex;align-items:center;gap:12px;">`;
    h += `<button class="btn btn-sm" onclick="openTarget('${esc(t.name)}')">View Dashboard</button>`;
    h += `<label class="toolbar-checkbox-label" onclick="event.stopPropagation()">`;
    h += `<input type="checkbox" ${mon ? 'checked' : ''} onchange="toggleMonitor('${esc(t.name)}', this.checked)"/> Monitor`;
    h += `</label>`;
    h += `</div>`;
    h += `</td>`;
    h += `</tr>`;
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
  document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
  document.getElementById('nav-' + viewId)?.classList.add('active');

  document.querySelectorAll('.content-area > .view-section').forEach(sec => sec.classList.remove('active'));
  document.getElementById('view-' + viewId)?.classList.add('active');

  if (viewId === 'overview') {
    renderOverview();
  } else if (viewId === 'triage') {
    renderTriageList();
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
  container.querySelectorAll('.section-tab-btn').forEach(btn => btn.classList.remove('active'));
  container.querySelector(`#tab-${secId}-${tabKey}`)?.classList.add('active');

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
  }

  // Pre-load critical Hunt Queue data asynchronously
  await compileHuntQueue();

  // Go to default triage-first dashboard (Overview)
  switchView('overview');
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
    h += `<div class="overview-stat-box ${it.val > 0 ? 'has-data' : ''}" onclick="switchView('${it.key}')">`;
    h += `<div class="overview-stat-val">${it.val.toLocaleString()}</div>`;
    h += `<div class="overview-stat-lbl">${it.label}</div>`;
    h += `</div>`;
  });
  el.innerHTML = h;

  // Render overview top interesting assets (High / Med priority queue items)
  const topAssetsContainer = document.getElementById('overview-top-assets');
  const interesting = huntQueueItems
    .filter(item => !localStorage.getItem(getIgnoreKey(item.host)))
    .filter(item => item.priority === 'HIGH' || item.priority === 'MED')
    .slice(0, 8);

  if (interesting.length === 0) {
    topAssetsContainer.innerHTML = '<div class="empty-placeholder">No high priority triage assets found.</div>';
  } else {
    let ah = '';
    interesting.forEach(item => {
      const starred = localStorage.getItem(getStarKey(item.host)) === 'true';
      const findings = item.findings || [];
      // Group findings by severity for the overview header line
      const critCount = findings.filter(f => f.sev === 'crit').length;
      const highCount = findings.filter(f => f.sev === 'high').length;

      ah += `<div class="overview-asset-card">`;

      // Domain header row
      ah += `<div class="overview-asset-header">`;
      ah += `<div class="triage-priority ${item.priority.toLowerCase()}">${item.priority}</div>`;
      ah += `<a href="${esc(item.url)}" target="_blank" class="triage-host" style="font-size:13px;">${esc(item.host)}</a>`;
      if (item.status_code) ah += sBadge(item.status_code);
      if (critCount) ah += `<span class="finding-count-badge sev-crit">${critCount} crit</span>`;
      if (highCount) ah += `<span class="finding-count-badge sev-high">${highCount} high</span>`;
      ah += `<div style="flex:1"></div>`;
      ah += `<button class="btn btn-sm btn-star ${starred ? 'active' : ''}" onclick="toggleTriageStar('${esc(item.host)}', this); event.stopPropagation();">★</button>`;
      ah += `<button class="btn btn-sm" onclick="switchView('triage')" style="font-size:10px;">full queue</button>`;
      ah += `</div>`;

      // Findings list — show up to 5 most severe
      if (findings.length) {
        const SEV_ORDER = { crit: 4, high: 3, med: 2, low: 1 };
        const sorted = [...findings].sort((a, b) => (SEV_ORDER[b.sev] || 0) - (SEV_ORDER[a.sev] || 0));
        ah += `<div class="overview-asset-findings">`;
        sorted.slice(0, 5).forEach(f => ah += renderFindingChip(f, true));
        if (findings.length > 5) {
          ah += `<span class="finding-more">+${findings.length - 5} more</span>`;
        }
        ah += `</div>`;
      } else {
        const titleInfo = item.title ? ` — ${item.title}` : '';
        ah += `<div class="overview-asset-findings"><span style="color:var(--muted);font-size:11px;">No detailed findings${titleInfo}</span></div>`;
      }

      ah += `</div>`;
    });
    topAssetsContainer.innerHTML = ah;
  }

  // Load latest monitor change summary
  loadOverviewMonitorSummary();
}

async function loadOverviewMonitorSummary() {
  const container = document.getElementById('overview-monitor-changes');
  const data = await fetchJSON(`/api/monitor/changes?target=${currentTarget}`);
  const changes = data?.changes || [];
  if (changes.length === 0) {
    container.innerHTML = '<div class="empty-placeholder">No monitor changes logged.</div>';
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

// ── Hunt Queue Engine ──
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

  const activeTriage = huntQueueItems.filter(item => !localStorage.getItem(getIgnoreKey(item.host)));
  document.getElementById('badge-triage').textContent = activeTriage.length;
}

function renderFindingChip(f, linkable = false) {
  const def = FINDING_DEFS[f.type] || { icon: '?', sev: 'low' };
  const cls = `finding-chip sev-${def.sev}`;
  const icon = `<span class="finding-icon">${def.icon}</span>`;
  const label = linkable && f.url
    ? `<a href="${esc(f.url)}" target="_blank" class="finding-link">${esc(f.label)}</a>`
    : `<span>${esc(f.label)}</span>`;
  return `<div class="${cls}">${icon}${label}</div>`;
}

function renderTriageList() {
  const container = document.getElementById('triage-list-container');
  let filtered = [...huntQueueItems];

  // 1. Priority filters
  if (triagePriorityFilter !== 'all') {
    if (triagePriorityFilter === 'starred') {
      filtered = filtered.filter(item => localStorage.getItem(getStarKey(item.host)) === 'true');
    } else {
      filtered = filtered.filter(item => item.priority.toLowerCase() === triagePriorityFilter);
    }
  }

  // 2. Hide ignored
  if (triageHideIgnored) {
    filtered = filtered.filter(item => localStorage.getItem(getIgnoreKey(item.host)) !== 'true');
  }

  // 3. Text search — also searches findings labels
  if (triageTextFilter) {
    const q = triageTextFilter.toLowerCase();
    filtered = filtered.filter(item =>
      item.host.toLowerCase().includes(q) ||
      item.title.toLowerCase().includes(q) ||
      item.tech.join(' ').toLowerCase().includes(q) ||
      (item.findings || []).some(f => f.label.toLowerCase().includes(q))
    );
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-placeholder">No hunt queue items matching current filters.</div>';
    return;
  }

  let h = '';
  filtered.forEach(item => {
    const starred = localStorage.getItem(getStarKey(item.host)) === 'true';
    const ignored = localStorage.getItem(getIgnoreKey(item.host)) === 'true';
    const findings = item.findings || [];

    h += `<div class="triage-row${ignored ? ' triage-ignored' : ''}">`;
    h += `<div class="triage-priority ${item.priority.toLowerCase()}">${item.priority}</div>`;
    h += `<div class="triage-info">`;
    h += `<div class="triage-title-line">`;
    h += `<a href="${esc(item.url)}" target="_blank" class="triage-host">${esc(item.host)}</a>`;
    if (item.status_code) h += sBadge(item.status_code);
    if (item.title) h += `<span class="triage-page-title">${esc(item.title)}</span>`;
    if (item.tech?.length) {
      h += `<div class="triage-badges">`;
      item.tech.slice(0, 4).forEach(t => h += `<span class="triage-badge tech">${esc(t)}</span>`);
      h += `</div>`;
    }
    h += `</div>`;
    if (findings.length) {
      h += `<div class="triage-findings">`;
      findings.forEach(f => h += renderFindingChip(f, true));
      h += `</div>`;
    }
    h += `</div>`;

    h += `<div class="triage-actions">`;
    h += `<button class="btn btn-sm" onclick="copyToClipboard('${esc(item.url)}', this)">copy</button>`;
    if (item.screenshot) {
      h += `<button class="btn btn-sm" onclick="openLightbox('${esc(item.screenshot)}', '${esc(item.host)}')">ss</button>`;
    }
    h += `<button class="btn btn-sm btn-star ${starred ? 'active' : ''}" onclick="toggleTriageStar('${esc(item.host)}', this)">★</button>`;
    h += `<button class="btn btn-sm btn-ignore ${ignored ? 'active' : ''}" onclick="toggleTriageIgnore('${esc(item.host)}', this)">ignore</button>`;
    h += `</div>`;
    h += `</div>`;
  });
  container.innerHTML = h;
}


window.filterTriagePriority = (prio) => {
  triagePriorityFilter = prio;
  document.querySelectorAll('.triage-filters button').forEach(btn => btn.classList.remove('btn-primary'));
  document.getElementById('btn-triage-' + prio)?.classList.add('btn-primary');
  renderTriageList();
};

window.filterTriageText = (val) => {
  triageTextFilter = val;
  renderTriageList();
};

window.toggleHideIgnored = (checked) => {
  triageHideIgnored = checked;
  renderTriageList();
};

window.toggleTriageStar = (host, btn) => {
  const starred = localStorage.getItem(getStarKey(host)) === 'true';
  localStorage.setItem(getStarKey(host), !starred);
  btn.classList.toggle('active', !starred);
  if (currentView === 'triage') renderTriageList();
};

window.toggleTriageIgnore = (host, btn) => {
  const ignored = localStorage.getItem(getIgnoreKey(host)) === 'true';
  localStorage.setItem(getIgnoreKey(host), !ignored);
  btn.classList.toggle('active', !ignored);
  
  // Re-calculate triage badge count
  const activeTriage = huntQueueItems.filter(item => !localStorage.getItem(getIgnoreKey(item.host)));
  document.getElementById('badge-triage').textContent = activeTriage.length;

  if (currentView === 'triage') renderTriageList();
};

// ── Assets Section ──
let assetsActiveTab = 'subs';
let assetsTableCtrl = null;
let assetsListItems = [];

async function loadAssetsSection() {
  const container = document.getElementById('data-assets-content');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const [subsRaw, dnsRaw, httpxRaw] = await Promise.all([
    fetchText(T('subs/all.txt')),
    fetchText(T('dns/resolved.txt')),
    fetchText(T('httpx/results.json'))
  ]);

  // Build IP lookup from httpx JSON (has -ip flag data)
  const ipMap = {};
  httpxRaw.split('\n').filter(Boolean).forEach(line => {
    try {
      const r = JSON.parse(line);
      const host = r.input || (r.url ? new URL(r.url).hostname : '');
      const ip = r.a ? (Array.isArray(r.a) ? r.a[0] : r.a) : (r.host || '');
      if (host && ip) ipMap[host] = ip;
    } catch(e) {}
  });

  assetsListItems = {
    subs: parseLines(subsRaw).map(line => ({ value: line })),
    dns: parseLines(dnsRaw).map(host => ({
      host: host,
      ip: ipMap[host] || ''
    }))
  };

  document.getElementById('tc-assets-subs').textContent = assetsListItems.subs.length;
  document.getElementById('tc-assets-dns').textContent = assetsListItems.dns.length;

  renderAssetsTab();
}

function renderAssetsTab() {
  const containerId = 'data-assets-content';
  const q = document.getElementById('filter-assets-search').value;

  if (assetsActiveTab === 'subs') {
    assetsTableCtrl = makePagedTable(
      containerId,
      assetsListItems.subs,
      [{ key: 'value', label: 'Subdomain' }],
      (item, idx) => `<tr><td class="wrap-cell">${hilite(item.value, _assetsSearchVal())}</td></tr>`,
      (item, filterText) => item.value.toLowerCase().includes(filterText)
    );
  } else {
    assetsTableCtrl = makePagedTable(
      containerId,
      assetsListItems.dns,
      [{ key: 'host', label: 'Subdomain' }, { key: 'ip', label: 'IP Address' }],
      (item, idx) => `<tr><td>${hilite(item.host, _assetsSearchVal())}</td><td>${hilite(item.ip, _assetsSearchVal())}</td></tr>`,
      (item, filterText) => (item.host + ' ' + item.ip).toLowerCase().includes(filterText)
    );
  }
  assetsTableCtrl.render();
  if (q) assetsTableCtrl.filter(q.toLowerCase());
}

function _assetsSearchVal() {
  return document.getElementById('filter-assets-search').value;
}

window.assetsFilter = (val) => {
  assetsTableCtrl?.filter(val.toLowerCase());
};

// ── Web Apps Section ──
let webappsTableCtrl = null;
let webappsListItems = [];

async function loadWebApps() {
  const container = document.getElementById('data-webapps-content');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const text = await fetchText(T('httpx/results.json'));
  webappsListItems = text.split('\n').filter(Boolean).map(line => {
    try {
      return JSON.parse(line);
    } catch(e) {
      return null;
    }
  }).filter(Boolean);

  renderWebAppsTable();
}

function renderWebAppsTable() {
  const containerId = 'data-webapps-content';
  
  // Filter CDN, duplicates, status codes
  const uniqueTitles = new Set();
  const filtered = webappsListItems.filter(item => {
    // Duplicate title check
    if (webappsHideDupes && item.title) {
      if (uniqueTitles.has(item.title.toLowerCase())) return false;
      uniqueTitles.add(item.title.toLowerCase());
    }
    return true;
  });

  webappsTableCtrl = makePagedTable(
    containerId,
    filtered,
    [
      { key: 'url', label: 'Web URL' },
      { key: 'status_code', label: 'Status' },
      { key: 'title', label: 'Page Title' },
      { key: 'webserver', label: 'Web Server' },
      { key: 'tech', label: 'Technologies' }
    ],
    (item, idx) => {
      const tech = (item.tech || []).join(', ');
      return `<tr>
        <td class="wrap-cell"><a href="${esc(item.url)}" target="_blank" class="triage-host">${hilite(item.url, webappsTextQuery)}</a></td>
        <td>${sBadge(item.status_code)}</td>
        <td class="wrap-cell">${hilite(item.title || '', webappsTextQuery)}</td>
        <td>${hilite(item.webserver || '', webappsTextQuery)}</td>
        <td class="wrap-cell" style="color:var(--blue); font-size:11px;">${hilite(tech, webappsTextQuery)}</td>
      </tr>`;
    },
    (item, filterArgs) => {
      const { text, status } = filterArgs;
      if (status && !String(item.status_code).startsWith(status)) return false;
      if (!text) return true;
      const techStr = (item.tech || []).join(' ');
      return [item.url, item.title, item.webserver, techStr].join(' ').toLowerCase().includes(text);
    }
  );

  webappsTableCtrl.render();
  webappsTableCtrl.filter({ text: webappsTextQuery.toLowerCase(), status: webappsStatusQuery });
}

window.webappsFilter = (val) => {
  webappsTextQuery = val;
  webappsTableCtrl?.filter({ text: val.toLowerCase(), status: webappsStatusQuery });
};

window.webappsStatusFilter = (val) => {
  webappsStatusQuery = val;
  webappsTableCtrl?.filter({ text: webappsTextQuery.toLowerCase(), status: val });
};

window.toggleWebappsHideDuplicates = (checked) => {
  webappsHideDupes = checked;
  renderWebAppsTable();
};

// ── Screenshots ──
async function loadScreenshots() {
  const container = document.getElementById('data-screenshots');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const data = await fetchJSON(`/api/screenshots?target=${currentTarget}`);
  const files = data?.files || [];

  document.getElementById('badge-screenshots').textContent = files.length;

  if (files.length === 0) {
    container.innerHTML = '<div class="empty-placeholder">No screenshots collected.</div>';
    return;
  }

  let h = '';
  files.forEach(f => {
    const src = `/screenshots/${currentTarget}/${encodeURIComponent(f)}`;
    const label = f.replace(/\.(png|jpg|jpeg)$/i, '');
    h += `<div class="ss-card" onclick="openLightbox('${src}', '${esc(label)}')">`;
    h += `<img src="${src}" alt="${esc(label)}" loading="lazy" />`;
    h += `<div class="ss-footer"><span>${esc(label)}</span></div>`;
    h += `</div>`;
  });
  container.innerHTML = h;
}

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
    container.innerHTML = '<div class="empty-placeholder">Error fetching data.</div>';
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
            <button class="btn btn-sm" onclick="copyToClipboard('${esc(url)}', this)">copy</button>
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
let jsListItems = {};

async function loadJSSection() {
  const container = document.getElementById('data-js-content');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const [scriptsRaw, endpointsRaw, secretsRaw, leakageRaw, commentsRaw, mapsRaw, apiRaw, bucketsRaw, wsRaw] = await Promise.all([
    fetchText(T('js/scripts_alive.txt')),
    fetchText(T('js/endpoints.txt')),
    fetchText(T('js/secrets.txt')),
    fetchText(T('js/leakage.txt')),
    fetchText(T('js/comments.txt')),
    fetchText(T('js/maps_files.txt')),
    fetchText(T('js/api_endpoints.txt')),
    fetchText(T('js/buckets.txt')),
    fetchText(T('js/websockets.txt'))
  ]);

  jsListItems = {
    scripts: parseLines(scriptsRaw).map(line => ({ value: line })),
    endpoints: parseLines(endpointsRaw).map(line => ({ value: line })),
    secrets: parseLines(secretsRaw).map(line => ({ value: line })),
    leakage: parseLines(leakageRaw).map(line => ({ value: line })),
    comments: parseLines(commentsRaw).map(line => ({ value: line })),
    maps: parseLines(mapsRaw).map(line => ({ value: line })),
    api: parseLines(apiRaw).map(line => ({ value: line })),
    buckets: parseLines(bucketsRaw).map(line => ({ value: line })),
    ws: parseLines(wsRaw).map(line => ({ value: line }))
  };

  // Populate tab badges
  for (const k of Object.keys(jsListItems)) {
    const el = document.getElementById(`tc-js-${k}`);
    if (el) el.textContent = jsListItems[k].length;
  }

  renderJSTab();
}

function renderJSTab() {
  const containerId = 'data-js-content';
  const dataset = jsListItems[jsActiveTab];
  const q = document.getElementById('filter-js-search').value;

  jsTableCtrl = makePagedTable(
    containerId,
    dataset,
    [{ key: 'value', label: 'Item details' }],
    (item, idx) => `<tr><td class="wrap-cell">${hilite(item.value, _jsSearchVal())}</td></tr>`,
    (item, filterText) => item.value.toLowerCase().includes(filterText)
  );

  jsTableCtrl.render();
  if (q) jsTableCtrl.filter(q.toLowerCase());
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
let portsListItems = {};

async function loadPortsSection() {
  const container = document.getElementById('data-ports-content');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const [naabuRaw, targetsRaw, nmapRaw, gnmapRaw] = await Promise.all([
    fetchText(T('ports/naabu.txt')),
    fetchText(T('ports/nmap_targets.txt')),
    fetchText(T('ports/nmap_results.nmap')),
    fetchText(T('ports/nmap_results.gnmap'))
  ]);

  portsListItems = {
    naabu: parseLines(naabuRaw).map(line => {
      const parts = line.split(':');
      return { host: parts[0] || '', port: parts[1] || '' };
    }),
    targets: parseLines(targetsRaw).map(line => ({ value: line })),
    nmap: nmapRaw,
    gnmap: gnmapRaw
  };

  document.getElementById('tc-ports-naabu').textContent = portsListItems.naabu.length;
  document.getElementById('tc-ports-targets').textContent = portsListItems.targets.length;
  document.getElementById('tc-ports-nmap').textContent = portsListItems.nmap ? '1' : '0';
  document.getElementById('tc-ports-gnmap').textContent = portsListItems.gnmap ? '1' : '0';

  renderPortsTab();
}

function renderPortsTab() {
  const containerId = 'data-ports-content';
  const q = document.getElementById('filter-ports-search').value;

  if (portsActiveTab === 'naabu') {
    portsTableCtrl = makePagedTable(
      containerId,
      portsListItems.naabu,
      [{ key: 'host', label: 'Host' }, { key: 'port', label: 'Port' }],
      (item, idx) => `<tr><td>${hilite(item.host, q)}</td><td style="color:var(--accent); font-weight:600;">${hilite(item.port, q)}</td></tr>`,
      (item, filterText) => (item.host + ' ' + item.port).toLowerCase().includes(filterText)
    );
    portsTableCtrl.render();
    if (q) portsTableCtrl.filter(q.toLowerCase());
  } else if (portsActiveTab === 'targets') {
    portsTableCtrl = makePagedTable(
      containerId,
      portsListItems.targets,
      [{ key: 'value', label: 'Targets block' }],
      (item, idx) => `<tr><td>${hilite(item.value, q)}</td></tr>`,
      (item, filterText) => item.value.toLowerCase().includes(filterText)
    );
    portsTableCtrl.render();
    if (q) portsTableCtrl.filter(q.toLowerCase());
  } else {
    // Render raw nmap / greppable dumps
    const rawData = portsListItems[portsActiveTab];
    document.getElementById(containerId).innerHTML = `<div class="raw-view-panel">${esc(rawData || 'No raw output data.')}</div>`;
  }
}

window.portsFilter = (val) => {
  portsTableCtrl?.filter(val.toLowerCase());
};

// ── Dorks Section ──
let dorksActiveTab = 'all';
let dorksTableCtrl = null;
let dorksListItems = {};

async function loadDorksSection() {
  const container = document.getElementById('data-dorks-content');
  container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const tabsKeys = ['all', 'config', 'backups', 'logs', 'admin', 'cloud', 'auth', 'active', 'confirmed'];
  const fetches = tabsKeys.map(k => {
    let filename = 'all_findings.txt';
    if (k === 'config') filename = 'passive_config_files.txt';
    else if (k === 'backups') filename = 'passive_backup_files.txt';
    else if (k === 'logs') filename = 'passive_log_files.txt';
    else if (k === 'admin') filename = 'passive_admin_panels.txt';
    else if (k === 'cloud') filename = 'passive_cloud_assets.txt';
    else if (k === 'auth') filename = 'passive_auth_tokens.txt';
    else if (k === 'active') filename = 'active_hits.txt';
    else if (k === 'confirmed') filename = 'active_confirmed.txt';
    return fetchText(T(`dorks/${filename}`));
  });

  const responses = await Promise.all(fetches);
  tabsKeys.forEach((k, idx) => {
    dorksListItems[k] = parseLines(responses[idx]).map(line => ({ value: line }));
    document.getElementById(`tc-dorks-${k}`).textContent = dorksListItems[k].length;
  });

  renderDorksTab();
}

function renderDorksTab() {
  const containerId = 'data-dorks-content';
  const dataset = dorksListItems[dorksActiveTab];
  const q = document.getElementById('filter-dorks-search').value;

  dorksTableCtrl = makePagedTable(
    containerId,
    dataset,
    [{ key: 'value', label: 'Dork findings & context' }],
    (item, idx) => `<tr><td class="wrap-cell">${hilite(item.value, q)}</td></tr>`,
    (item, filterText) => item.value.toLowerCase().includes(filterText)
  );

  dorksTableCtrl.render();
  if (q) dorksTableCtrl.filter(q.toLowerCase());
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
    indexContainer.innerHTML = '<div class="empty-placeholder">No raw files detected.</div>';
    return;
  }

  let h = '';
  rawFilesList.forEach(file => {
    h += `<div class="raw-file-item" onclick="viewRawFile('${esc(file)}', this)">${esc(file)}</div>`;
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

  const raw = await fetchText(T(file));
  viewer.innerHTML = `<div class="raw-view-panel" style="max-height: 600px;">${esc(raw)}</div>`;
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
    container.innerHTML = '<div class="empty-placeholder">No monitor history changes logged. Run a monitor check first.</div>';
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
  document.getElementById('scan-log').classList.add('visible');
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
  const rate = document.getElementById('scan-rate').value || undefined;
  const top_ports = document.getElementById('scan-ports').value || undefined;

  const res = await postJSON('/api/scan/start', { domain, skip, threads, rate, top_ports });
  if (res?.ok) {
    document.getElementById('start-scan-btn').disabled = true;
    document.getElementById('scan-log').classList.add('visible');
    pollScanLog();
  } else {
    alert(res?.message || 'Failed to start scan');
  }
};

window.stopScan = async function() {
  await postJSON('/api/scan/stop', {});
};

// Active scan logger check
let scanPollTimer = null;
function pollScanLog() {
  if (scanPollTimer) clearInterval(scanPollTimer);
  scanPollTimer = setInterval(async () => {
    const s = await fetchJSON('/api/scan/status');
    if (!s) return;
    const logEl = document.getElementById('scan-log');
    const logsViewEl = document.getElementById('logs-scan-log');

    if (s.log_tail?.length) {
      const tail = s.log_tail.join('\n');
      logEl.textContent = tail;
      
      // Update historical logs view dynamically if it's currently active or empty
      if (logsViewEl && (logsViewEl.textContent.startsWith('No logs active') || logsViewEl.classList.contains('active-stream'))) {
        logsViewEl.textContent = tail;
        logsViewEl.classList.add('active-stream');
        logsViewEl.scrollTop = logsViewEl.scrollHeight;
      }
    }
    logEl.scrollTop = logEl.scrollHeight;

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
    bar.classList.add('visible');
    const elapsed = s.elapsed ? `${Math.floor(s.elapsed/60)}m ${s.elapsed%60}s` : '';
    const stepText = s.current_step ? ` [Step: ${s.current_step}]` : '';
    document.getElementById('scan-bar-text').textContent = `Active scan running for ${s.domain || ''}... ${elapsed}${stepText}`;
    
    const progressEl = document.getElementById('scan-progress-bar');
    if (progressEl) {
      progressEl.style.width = `${s.progress_percent || 0}%`;
    }
  } else {
    bar.classList.remove('visible');
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
  
  const text = await fetchText(`/api/file/${currentTarget}/logs/${filename}`);
  consoleEl.textContent = text || 'Empty log file.';
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
  await postJSON('/api/monitor/toggle', { target, enabled });
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
    document.getElementById('scan-log').classList.add('visible');
    pollScanLog();
  } else {
    alert(res?.message || 'Failed to start monitor check.');
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
    document.getElementById('scan-log').classList.add('visible');
    pollScanLog();
  } else {
    alert(res?.message || 'Failed to start monitor check.');
  }
};

// Initialize
loadExplorer();
})();
