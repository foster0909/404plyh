(function(){
'use strict';
const API = location.origin;
let currentTarget = null;

async function fetchJSON(p){try{const r=await fetch(API+p);if(!r.ok)return null;return await r.json()}catch{return null}}
async function fetchText(p){try{const r=await fetch(API+p);if(!r.ok)return'';return await r.text()}catch{return''}}
async function postJSON(p,body){try{const r=await fetch(API+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return await r.json()}catch{return null}}

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function parseLines(t){return t.split('\n').map(l=>l.trim()).filter(Boolean)}
function sBadge(c){const n=parseInt(c);if(!n)return'<span class="badge b-na">--</span>';const k=n<300?'2xx':n<400?'3xx':n<500?'4xx':'5xx';return`<span class="badge b-${k}">${n}</span>`}
function hilite(text,q){if(!q)return esc(text);const re=new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`,'gi');return esc(text).replace(re,'<span class="hl">$1</span>')}

const PAGE_SZ=100, _pagCtrl={};let _pagId=0;
function makePaged(cid,items,renderFn,filterFn){
  let page=0,filtered=items,query='';const id=_pagId++;
  function filter(q){query=q.toLowerCase();filtered=query?items.filter(x=>filterFn(x,query)):items;page=0;render();return filtered.length}
  function render(){
    const el=document.getElementById(cid);if(!el)return;
    const pages=Math.ceil(filtered.length/PAGE_SZ),start=page*PAGE_SZ,slice=filtered.slice(start,start+PAGE_SZ);
    let h=renderFn(slice,query,start);
    if(pages>1){
      h+=`<div class="paging"><span class="paging-info">${start+1}–${Math.min(start+PAGE_SZ,filtered.length)} of ${filtered.length}</span><div class="paging-btns">`;
      h+=`<button class="pg-btn" onclick="_pgNav(${id},'prev')" ${page===0?'disabled':''}>prev</button>`;
      let bs=Math.max(0,page-2),be=Math.min(pages,bs+5);if(be-bs<5)bs=Math.max(0,be-5);
      for(let i=bs;i<be;i++)h+=`<button class="pg-btn ${i===page?'active':''}" onclick="_pgNav(${id},'go',${i})">${i+1}</button>`;
      h+=`<button class="pg-btn" onclick="_pgNav(${id},'next')" ${page>=pages-1?'disabled':''}>next</button></div></div>`;
    }
    el.innerHTML=h;
  }
  _pagCtrl[id]={prev(){if(page>0){page--;render()}},next(){if(page<Math.ceil(filtered.length/PAGE_SZ)-1){page++;render()}},go(p){page=p;render()}};
  return{render,filter,count:()=>filtered.length};
}
window._pgNav=function(id,a,arg){const c=_pagCtrl[id];if(!c)return;if(a==='prev')c.prev();else if(a==='next')c.next();else if(a==='go')c.go(arg)};

// ── Explorer ──
let allTargets=[];
async function loadExplorer(){
  const data=await fetchJSON('/api/targets');
  allTargets=data?.targets||[];
  renderTargets(allTargets);
  checkScanStatus();
}

function renderTargets(targets){
  const el=document.getElementById('targets-container');
  if(!targets.length){el.innerHTML='<div class="empty-state"><p>no targets found</p><p>start a scan or point dashboard at your projects directory</p></div>';return}
  let h='<div class="target-list">';
  for(const t of targets){
    const s=t.stats||{};
    const date=t.scan_date?new Date(t.scan_date).toLocaleDateString():(t.last_modified?new Date(t.last_modified*1000).toLocaleDateString():'');
    const mon=t.monitor_enabled;
    h+=`<div class="target-row" onclick="openTarget('${esc(t.name)}')">`;
    h+=`<div class="tr-left">`;
    h+=`<span class="tr-domain">${esc(t.domain||t.name)}</span>`;
    h+=`<span class="tr-stats">`;
    if(s.total_subdomains)h+=`<span><b>${s.total_subdomains}</b>subs</span>`;
    if(s.alive_services)h+=`<span><b>${s.alive_services}</b>alive</span>`;
    if(s.open_ports)h+=`<span><b>${s.open_ports}</b>ports</span>`;
    if(s.js_endpoints)h+=`<span><b>${s.js_endpoints}</b>js</span>`;
    if(s.crawled_endpoints)h+=`<span><b>${s.crawled_endpoints}</b>endpoints</span>`;
    h+=`</span></div>`;
    h+=`<div class="tr-right">`;
    if(date)h+=`<span class="tr-date">${date}</span>`;
    h+=`<div class="monitor-sw" onclick="event.stopPropagation()"><label class="toggle-sw"><input type="checkbox" ${mon?'checked':''} onchange="toggleMonitor('${esc(t.name)}',this.checked)"/><span class="toggle-slider"></span></label></div>`;
    h+=`</div></div>`;
  }
  el.innerHTML=h+'</div>';
}

window.filterTargets=function(q){
  q=q.toLowerCase();
  const f=q?allTargets.filter(t=>(t.name+' '+t.domain).toLowerCase().includes(q)):allTargets;
  renderTargets(f);
};

window.showExplorer=function(){
  currentTarget=null;allCtrls.length=0;Object.keys(filterHandlers).forEach(k=>delete filterHandlers[k]);
  document.getElementById('view-explorer').classList.remove('hide');
  document.getElementById('view-target').classList.add('hide');
  document.getElementById('back-btn').classList.add('hide');
  document.getElementById('target-meta').classList.add('hide');
  loadExplorer();
};

// ── Target view ──
const SECTIONS=[
  {id:'subdomains',label:'subs'},{id:'dns',label:'dns'},
  {id:'http',label:'httpx'},{id:'screenshots',label:'screenshots'},
  {id:'ports',label:'ports',tabs:[{key:'naabu',label:'naabu'},{key:'naabujson',label:'naabu.json'},{key:'nmap',label:'nmap'},{key:'gnmap',label:'greppable'},{key:'targets',label:'targets'}]},
  {id:'js',label:'js',tabs:[{key:'endpoints',label:'endpoints'},{key:'secrets',label:'secrets'},{key:'api',label:'api'},{key:'buckets',label:'buckets'},{key:'ws',label:'websockets'}]},
  {id:'historical',label:'historical'},
  {id:'endpoints',label:'endpoints',tabs:[{key:'all',label:'all'},{key:'auth',label:'auth/admin'},{key:'api',label:'api paths'},{key:'sensitive',label:'sensitive'}]},
  {id:'dorks',label:'dorks',tabs:[{key:'all',label:'all findings'},{key:'config',label:'config files'},{key:'backups',label:'backups'},{key:'logs',label:'logs'},{key:'admin',label:'admin panels'},{key:'cloud',label:'cloud assets'},{key:'auth',label:'auth tokens'},{key:'active',label:'active hits'},{key:'confirmed',label:'confirmed'}]},
  {id:'infra',label:'infra',tabs:[{key:'ips',label:'ip groups'},{key:'cdn',label:'cdn'},{key:'orgs',label:'ip > org'}]},
  {id:'monitor',label:'monitor',isCustom:true},
  {id:'logs',label:'logs',isMeta:true}
];
const allCtrls=[];const filterHandlers={};

function T(p){return`/api/file/${currentTarget}/${p}`}

function buildStats(stats){
  const s=stats?.statistics||{};
  const items=[
    {key:'subdomains',label:'subs',val:s.total_subdomains??0},
    {key:'dns',label:'resolved',val:s.resolved_hosts??0},
    {key:'http',label:'alive',val:s.alive_services??0},
    {key:'screenshots',label:'screenshots',val:s.screenshots??0},
    {key:'ports',label:'ports',val:s.open_ports??0},
    {key:'js',label:'js',val:s.js_endpoints??0},
    {key:'historical',label:'historical',val:s.historical_urls??0},
    {key:'endpoints',label:'crawled',val:s.crawled_endpoints??0},
    {key:'dorks',label:'dorks',val:s.dork_findings??0},
  ];
  let h='';
  for(const it of items){
    if(it.val>0) h+=`<div class="stat-item" onclick="jumpTo('${it.key}')"><span class="stat-val">${it.val.toLocaleString()}</span><span class="stat-label">${it.label}</span></div>`;
  }
  document.getElementById('stats-grid').innerHTML=h;
}

function buildNav(){
  let h='';
  for(const s of SECTIONS) h+=`<button class="nav-btn" id="nav-${s.id}" onclick="showSection('${s.id}')">${s.label}<span class="nav-count" id="navcount-${s.id}"></span></button>`;
  document.getElementById('nav-bar').innerHTML=h;
}

function buildSections(){
  let h='';
  for(const s of SECTIONS){
    h+=`<div class="section visible" id="sec-${s.id}"><div class="section-head" onclick="toggleSec('${s.id}')"><span class="section-title">${s.label}<span class="sec-badge" id="badge-${s.id}"></span></span><span class="sec-chevron">▾</span></div><div class="section-body">`;
    if(s.tabs){
      h+=`<div class="sec-tabs">`;s.tabs.forEach((t,i)=>h+=`<button class="sec-tab ${i===0?'active':''}" data-sec="${s.id}" data-tab="${t.key}" onclick="switchSecTab('${s.id}','${t.key}')">${t.label}<span class="sec-tab-count" id="tc-${s.id}-${t.key}"></span></button>`);h+=`</div>`;
      s.tabs.forEach((t,i)=>{h+=`<div class="tab-pane ${i===0?'active':''}" id="tp-${s.id}-${t.key}"><div class="section-inner"><div class="sec-filter"><input type="text" placeholder="filter ${t.label}..." oninput="secFilter('${s.id}_${t.key}',this.value)"/></div><div id="data-${s.id}-${t.key}"><div class="loading"><div class="spinner"></div></div></div></div></div>`});
    }else if(s.id==='screenshots'){h+=`<div class="section-inner"><div id="data-screenshots"><div class="loading"><div class="spinner"></div></div></div></div>`}
    else if(s.isMeta){h+=`<div class="section-inner"><div id="data-logs"><div class="empty">log files stored in logs/ directory</div></div></div>`}
    else if(s.isCustom&&s.id==='monitor'){h+=`<div class="section-inner"><div id="data-monitor"><div class="loading"><div class="spinner"></div></div></div></div>`}
    else{h+=`<div class="section-inner"><div class="sec-filter"><input type="text" placeholder="filter..." oninput="secFilter('${s.id}',this.value)"/></div><div id="data-${s.id}"><div class="loading"><div class="spinner"></div></div></div></div>`}
    h+=`</div></div>`;
  }
  document.getElementById('sections').innerHTML=h;
}

window.toggleSec=function(id){document.getElementById('sec-'+id)?.classList.toggle('open')};
window.showSection=function(id){
  const navBtns=document.querySelectorAll('.nav-btn'),secs=document.querySelectorAll('.section'),clicked=document.getElementById('nav-'+id);
  if(clicked.classList.contains('active')){navBtns.forEach(b=>b.classList.remove('active'));secs.forEach(s=>s.classList.add('visible'))}
  else{navBtns.forEach(b=>b.classList.remove('active'));clicked.classList.add('active');secs.forEach(s=>s.classList.toggle('visible',s.id==='sec-'+id));const sec=document.getElementById('sec-'+id);if(sec&&!sec.classList.contains('open'))sec.classList.add('open');sec?.scrollIntoView({behavior:'smooth',block:'start'})}
};
window.jumpTo=function(id){document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));document.querySelectorAll('.section').forEach(s=>s.classList.add('visible'));const sec=document.getElementById('sec-'+id);if(sec&&!sec.classList.contains('open'))sec.classList.add('open');sec?.scrollIntoView({behavior:'smooth',block:'start'})};
window.switchSecTab=function(secId,tabKey){const sec=document.getElementById('sec-'+secId);sec.querySelectorAll('.sec-tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===tabKey));sec.querySelectorAll('.tab-pane').forEach(p=>p.classList.toggle('active',p.id===`tp-${secId}-${tabKey}`))};
window.secFilter=function(key,val){if(filterHandlers[key])filterHandlers[key](val)};
window.openLightbox=function(src,label){document.getElementById('lb-img').src=src;document.getElementById('lb-label').textContent=label;document.getElementById('lightbox').classList.add('open')};
document.getElementById('lightbox').addEventListener('click',function(){this.classList.remove('open')});

function loadTextList(secKey,dataId,badgeId,filePath){
  return async function(){
    const text=await fetchText(filePath);const lines=parseLines(text);const badge=document.getElementById(badgeId);
    if(badge&&lines.length)badge.textContent=lines.length.toLocaleString();
    if(!lines.length){document.getElementById(dataId).innerHTML='<div class="empty">no data</div>';return 0}
    const ctrl=makePaged(dataId,lines,(items,q,off)=>{let h='<div class="tbl-wrap"><table class="tbl"><thead><tr><th>value</th></tr></thead><tbody>';items.forEach((it)=>h+=`<tr><td class="url-cell">${hilite(it,q)}</td></tr>`);return h+'</tbody></table></div>'},(it,q)=>it.toLowerCase().includes(q));
    ctrl.render();filterHandlers[secKey]=v=>ctrl.filter(v);allCtrls.push({key:secKey,ctrl,items:lines});return lines.length;
  };
}
function loadRawFile(secKey,dataId,badgeId,filePath){
  return async function(){
    const text=await fetchText(filePath);const content=text.trim();const badge=document.getElementById(badgeId);
    if(!content){document.getElementById(dataId).innerHTML='<div class="empty">no data</div>';if(badge)badge.textContent='';return 0}
    const lines=content.split('\n');
    if(badge)badge.textContent=lines.length.toLocaleString();

    function renderRaw(filteredLines, query){
      let h='<div class="raw-output">';
      for(const line of filteredLines){
        let out=esc(line);
        out=out.replace(/^(Nmap scan report for .+)$/,'<span style="color:var(--accent);font-weight:600">$1</span>');
        out=out.replace(/(\d+\/tcp\s+open)\b/g,'<span style="color:var(--grn)">$1</span>');
        out=out.replace(/(\d+\/tcp\s+closed)\b/g,'<span style="color:var(--red)">$1</span>');
        out=out.replace(/(\d+\/tcp\s+filtered)\b/g,'<span style="color:var(--accent)">$1</span>');
        out=out.replace(/(\d+\/udp\s+open)\b/g,'<span style="color:var(--grn)">$1</span>');
        out=out.replace(/^(PORT\s+STATE\s+SERVICE.*)$/,'<span style="color:var(--fg3);font-weight:600">$1</span>');
        out=out.replace(/^(Host is up.*)$/,'<span style="color:var(--blu)">$1</span>');
        out=out.replace(/^(\|.*)$/,'<span style="color:var(--fg3)">$1</span>');
        if(query){const re=new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`,'gi');out=out.replace(re,'<span class="hl">$1</span>')}
        h+=out+'\n';
      }
      document.getElementById(dataId).innerHTML=h+'</div>';
    }

    renderRaw(lines,'');
    filterHandlers[secKey]=function(val){
      const q=val.trim().toLowerCase();
      const fl=q?lines.filter(l=>l.toLowerCase().includes(q)):lines;
      renderRaw(fl,val.trim());
    };
    allCtrls.push({key:secKey,ctrl:{filter(q){const fl=q?lines.filter(l=>l.toLowerCase().includes(q)):lines;renderRaw(fl,q);return fl.length},count:()=>lines.length},items:lines});
    return lines.length;
  };
}

async function loadHTTP(){
  const text=await fetchText(T('httpx/results.json'));if(!text){document.getElementById('data-http').innerHTML='<div class="empty">no httpx data</div>';return}
  const recs=[];for(const l of parseLines(text)){try{recs.push(JSON.parse(l))}catch{}}
  const badge=document.getElementById('badge-http');
  if(badge&&recs.length)badge.textContent=recs.length.toLocaleString();
  if(!recs.length){document.getElementById('data-http').innerHTML='<div class="empty">no data</div>';return}
  const ctrl=makePaged('data-http',recs,(items,q,off)=>{
    let h='<div class="tbl-wrap"><table class="tbl"><thead><tr><th>url</th><th>status</th><th>title</th><th>server</th><th>tech</th><th>ip</th></tr></thead><tbody>';
    items.forEach((r)=>{const tech=(r.tech||[]).join(', '),ip=(r.a||[]).join(', ');h+=`<tr><td class="url-cell">${hilite(r.url||'',q)}</td><td>${sBadge(r.status_code)}</td><td class="url-cell">${hilite(r.title||'',q)}</td><td>${hilite(r.webserver||'',q)}</td><td style="color:var(--fg3);font-size:11px">${hilite(tech,q)}</td><td style="color:var(--fg4)">${hilite(ip,q)}</td></tr>`});
    return h+'</tbody></table></div>';
  },(r,q)=>[r.url,r.title,r.webserver,(r.tech||[]).join(' '),(r.a||[]).join(' ')].join(' ').toLowerCase().includes(q));
  ctrl.render();filterHandlers['http']=v=>ctrl.filter(v);allCtrls.push({key:'http',ctrl,items:recs.map(r=>JSON.stringify(r))});
}

async function loadScreenshots(){
  const data=await fetchJSON(`/api/screenshots?target=${currentTarget}`);const files=data?.files||[];
  const badge=document.getElementById('badge-screenshots');
  if(badge&&files.length)badge.textContent=files.length.toLocaleString();
  if(!files.length){document.getElementById('data-screenshots').innerHTML='<div class="empty">no screenshots</div>';return}
  let h='<div class="ss-grid">';
  for(const f of files){const src=`/screenshots/${currentTarget}/${encodeURIComponent(f)}`;const label=f.replace(/\.(png|jpg|jpeg)$/i,'');h+=`<div class="ss-card" onclick="openLightbox('${src}','${esc(label)}')"><img src="${src}" alt="${esc(label)}" loading="lazy"/><div class="ss-name">${esc(label)}</div></div>`}
  document.getElementById('data-screenshots').innerHTML=h+'</div>';
}

async function loadNaabuTable(){
  const text=await fetchText(T('ports/naabu.txt'));const lines=parseLines(text);
  const badge=document.getElementById('badge-ports');
  if(badge&&lines.length)badge.textContent=lines.length.toLocaleString();
  if(!lines.length){document.getElementById('data-ports-naabu').innerHTML='<div class="empty">no naabu data</div>';return 0}
  const ctrl=makePaged('data-ports-naabu',lines,(items,q,off)=>{
    let h='<div class="tbl-wrap"><table class="tbl"><thead><tr><th>host</th><th>port</th></tr></thead><tbody>';
    items.forEach((it)=>{const[host,port]=it.includes(':')?it.split(':'):[it,''];h+=`<tr><td>${hilite(host,q)}</td><td style="color:var(--accent);font-weight:600">${hilite(port,q)}</td></tr>`});
    return h+'</tbody></table></div>';
  },(it,q)=>it.toLowerCase().includes(q));
  ctrl.render();filterHandlers['ports_naabu']=v=>ctrl.filter(v);allCtrls.push({key:'ports_naabu',ctrl,items:lines});return lines.length;
}

async function loadInfraIPs(){
  const text=await fetchText(T('infra/ip_groups.txt'));const orgText=await fetchText(T('infra/ip_orgs.txt'));
  const lines=parseLines(text);
  const badge=document.getElementById('badge-infra');
  if(badge&&lines.length)badge.textContent=lines.length.toLocaleString();
  const orgs={};parseLines(orgText).forEach(l=>{const m=l.match(/^(\S+)\s*=>\s*(.+)$/);if(m)orgs[m[1]]=m[2].trim()});
  if(!lines.length){document.getElementById('data-infra-ips').innerHTML='<div class="empty">no infra data</div>';return}
  const entries=lines.map(l=>{const m=l.match(/^(\S+)\s*=>\s*(.+)$/);return m?{ip:m[1],hosts:m[2].split(',').map(h=>h.trim()).filter(Boolean),org:orgs[m[1]]||''}:null}).filter(Boolean);
  const ctrl=makePaged('data-infra-ips',entries,(items,q)=>{
    let h='<div class="infra-grid">';items.forEach(e=>{h+=`<div class="infra-card"><div class="infra-ip">${hilite(e.ip,q)}</div>`;if(e.org)h+=`<div class="infra-org">${hilite(e.org,q)}</div>`;h+=`<div class="infra-hosts">${e.hosts.map(host=>`<span class="infra-tag">${hilite(host,q)}</span>`).join('')}</div></div>`});
    return h+'</div>';
  },(e,q)=>(e.ip+' '+e.hosts.join(' ')+' '+e.org).toLowerCase().includes(q));
  ctrl.render();filterHandlers['infra_ips']=v=>ctrl.filter(v);allCtrls.push({key:'infra_ips',ctrl,items:entries.map(e=>e.ip+' '+e.hosts.join(' '))});
}

// Global search
const gSearch=document.getElementById('global-search'),gCount=document.getElementById('search-count');
gSearch.addEventListener('input',function(){
  const q=this.value.trim();if(!q){gCount.textContent='';allCtrls.forEach(c=>c.ctrl.filter(''));return}
  let total=0;allCtrls.forEach(c=>{total+=c.ctrl.filter(q)});gCount.textContent=total+' matches';
  for(const s of SECTIONS){const rel=allCtrls.filter(c=>c.key===s.id||c.key.startsWith(s.id+'_'));if(rel.some(c=>c.ctrl.count()>0)){const sec=document.getElementById('sec-'+s.id);if(sec&&!sec.classList.contains('open'))sec.classList.add('open');sec?.classList.add('visible')}}
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));document.querySelectorAll('.section').forEach(s=>s.classList.add('visible'));
});

window.openTarget=async function(name){
  currentTarget=name;allCtrls.length=0;Object.keys(filterHandlers).forEach(k=>delete filterHandlers[k]);
  document.getElementById('view-explorer').classList.add('hide');document.getElementById('view-target').classList.remove('hide');
  document.getElementById('back-btn').classList.remove('hide');document.getElementById('target-meta').classList.remove('hide');
  buildNav();buildSections();

  const stats=await fetchJSON(`/api/stats?target=${name}`);
  if(stats){document.getElementById('m-domain').textContent=stats.domain||name;document.getElementById('m-date').textContent=stats.scan_date?new Date(stats.scan_date).toLocaleDateString():'--';buildStats(stats)}
  const s=stats?.statistics||{};
  const navCounts={subdomains:s.total_subdomains,dns:s.resolved_hosts,http:s.alive_services,screenshots:s.screenshots,ports:s.open_ports,js:s.js_endpoints,historical:s.historical_urls,endpoints:s.crawled_endpoints,dorks:s.dork_findings};
  for(const[k,v]of Object.entries(navCounts)){const el=document.getElementById('navcount-'+k);if(el&&v)el.textContent='('+v+')'}

  await Promise.all([
    loadTextList('subdomains','data-subdomains','badge-subdomains',T('subs/all.txt'))(),
    loadTextList('dns','data-dns','badge-dns',T('dns/resolved.txt'))(),
    loadHTTP(),loadScreenshots(),loadNaabuTable(),
    loadTextList('ports_naabujson','data-ports-naabujson','tc-ports-naabujson',T('ports/naabu.json'))(),
    loadRawFile('ports_nmap','data-ports-nmap','tc-ports-nmap',T('ports/nmap_results.nmap'))(),
    loadRawFile('ports_gnmap','data-ports-gnmap','tc-ports-gnmap',T('ports/nmap_results.gnmap'))(),
    loadTextList('ports_targets','data-ports-targets','tc-ports-targets',T('ports/nmap_targets.txt'))(),
    loadTextList('js_endpoints','data-js-endpoints','tc-js-endpoints',T('js/endpoints.txt'))(),
    loadTextList('js_secrets','data-js-secrets','tc-js-secrets',T('js/secrets.txt'))(),
    loadTextList('js_api','data-js-api','tc-js-api',T('js/api_endpoints.txt'))(),
    loadTextList('js_buckets','data-js-buckets','tc-js-buckets',T('js/buckets.txt'))(),
    loadTextList('js_ws','data-js-ws','tc-js-ws',T('js/websockets.txt'))(),
    loadTextList('historical','data-historical','badge-historical',T('historical/all_urls.txt'))(),
    loadTextList('endpoints_all','data-endpoints-all','tc-endpoints-all',T('endpoints/all.txt'))(),
    loadTextList('endpoints_auth','data-endpoints-auth','tc-endpoints-auth',T('endpoints/interesting_paths.txt'))(),
    loadTextList('endpoints_api','data-endpoints-api','tc-endpoints-api',T('endpoints/api_paths.txt'))(),
    loadTextList('endpoints_sensitive','data-endpoints-sensitive','tc-endpoints-sensitive',T('endpoints/sensitive_files.txt'))(),
    loadTextList('dorks_all','data-dorks-all','tc-dorks-all',T('dorks/all_findings.txt'))(),
    loadTextList('dorks_config','data-dorks-config','tc-dorks-config',T('dorks/passive_config_files.txt'))(),
    loadTextList('dorks_backups','data-dorks-backups','tc-dorks-backups',T('dorks/passive_backup_files.txt'))(),
    loadTextList('dorks_logs','data-dorks-logs','tc-dorks-logs',T('dorks/passive_log_files.txt'))(),
    loadTextList('dorks_admin','data-dorks-admin','tc-dorks-admin',T('dorks/passive_admin_panels.txt'))(),
    loadTextList('dorks_cloud','data-dorks-cloud','tc-dorks-cloud',T('dorks/passive_cloud_assets.txt'))(),
    loadTextList('dorks_auth','data-dorks-auth','tc-dorks-auth',T('dorks/passive_auth_tokens.txt'))(),
    loadTextList('dorks_active','data-dorks-active','tc-dorks-active',T('dorks/active_hits.txt'))(),
    loadTextList('dorks_confirmed','data-dorks-confirmed','tc-dorks-confirmed',T('dorks/active_confirmed.txt'))(),
    loadInfraIPs(),
    loadTextList('infra_cdn','data-infra-cdn','tc-infra-cdn',T('infra/cdn_hosts.txt'))(),
    loadTextList('infra_orgs','data-infra-orgs','tc-infra-orgs',T('infra/ip_orgs.txt'))(),
    loadMonitor(),
  ]);
};

// ── Scan Modal ──
const MODULES=[
  {id:'subdomains',label:'Subdomain Discovery'},{id:'dns',label:'DNS Resolution'},{id:'http',label:'HTTP Probing'},
  {id:'screenshots',label:'Screenshots'},{id:'ports',label:'Port Scanning'},{id:'js',label:'JS Analysis'},
  {id:'historical',label:'Historical URLs'},{id:'crawl',label:'Endpoint Crawling'},{id:'dorks',label:'Dork-Style Discovery'},{id:'infra',label:'Infra Mapping'},{id:'report',label:'Report Generation'}
];
const enabledModules=new Set(MODULES.map(m=>m.id));

function renderModulesGrid(){
  const el=document.getElementById('modules-grid');
  let h='';for(const m of MODULES){const active=enabledModules.has(m.id);h+=`<div class="mod-toggle ${active?'active':''}" onclick="toggleModule('${m.id}',this)"><span class="dot"></span>${m.label}</div>`}
  el.innerHTML=h;
}

window.toggleModule=function(id,el){if(enabledModules.has(id)){enabledModules.delete(id);el.classList.remove('active')}else{enabledModules.add(id);el.classList.add('active')}};
window.openScanModal=function(){renderModulesGrid();document.getElementById('scan-modal').classList.add('open')};
window.closeScanModal=function(){document.getElementById('scan-modal').classList.remove('open');document.getElementById('scan-log').classList.remove('visible')};

window.startScan=async function(){
  const domain=document.getElementById('scan-domain').value.trim();
  if(!domain){document.getElementById('scan-domain').style.borderColor='var(--red)';return}
  const skip=MODULES.filter(m=>!enabledModules.has(m.id)).map(m=>m.id);
  const threads=document.getElementById('scan-threads').value||undefined;
  const rate=document.getElementById('scan-rate').value||undefined;
  const top_ports=document.getElementById('scan-ports').value||undefined;
  const res=await postJSON('/api/scan/start',{domain,skip,threads,rate,top_ports});
  if(res?.ok){
    document.getElementById('start-scan-btn').disabled=true;
    document.getElementById('scan-log').classList.add('visible');
    pollScanLog();
  }else{alert(res?.message||'Failed to start scan')}
};

window.stopScan=async function(){await postJSON('/api/scan/stop',{})};
window.openScanLog=function(){openScanModal();document.getElementById('scan-log').classList.add('visible');pollScanLog()};

let scanPollTimer=null;
function pollScanLog(){
  if(scanPollTimer)clearInterval(scanPollTimer);
  scanPollTimer=setInterval(async()=>{
    const s=await fetchJSON('/api/scan/status');if(!s)return;
    const logEl=document.getElementById('scan-log');
    if(s.log_tail?.length)logEl.textContent=s.log_tail.join('\n');
    logEl.scrollTop=logEl.scrollHeight;
    updateScanBar(s);
    if(!s.running&&s.finished){clearInterval(scanPollTimer);scanPollTimer=null;document.getElementById('start-scan-btn').disabled=false;loadExplorer()}
  },2000);
}

function updateScanBar(s){
  const bar=document.getElementById('scan-bar');
  if(s.running){
    bar.classList.add('visible');
    const elapsed=s.elapsed?`${Math.floor(s.elapsed/60)}m ${s.elapsed%60}s`:'';
    document.getElementById('scan-bar-text').textContent=`scanning ${s.domain||''}... ${elapsed}`;
  }else{bar.classList.remove('visible')}
}

async function checkScanStatus(){const s=await fetchJSON('/api/scan/status');if(s?.running){updateScanBar(s);pollScanLog()}}

// ── Monitor section ──
let _monitorEntryId=0;
async function loadMonitor(){
  const el=document.getElementById('data-monitor');
  if(!el)return;
  const data=await fetchJSON(`/api/monitor/changes?target=${currentTarget}`);
  const changes=data?.changes||[];
  const badge=document.getElementById('badge-monitor');
  const navCount=document.getElementById('navcount-monitor');

  if(badge&&changes.length)badge.textContent=changes.length.toLocaleString();
  if(navCount&&changes.length)navCount.textContent='('+changes.length+')';

  const hasRecent=changes.some(c=>{
    if(!c.timestamp)return false;
    const diff=Date.now()-new Date(c.timestamp).getTime();
    return diff<86400000&&(c.summary?.total_changes||0)>0;
  });
  const navBtn=document.getElementById('nav-monitor');
  if(navBtn&&hasRecent){
    if(!navBtn.querySelector('.pulse-dot'))navBtn.insertAdjacentHTML('beforeend','<span class="pulse-dot"></span>');
  }

  if(!changes.length){
    el.innerHTML='<div class="monitor-empty"><p>no monitor data</p><p>run: ./monitor.sh -d '+esc(currentTarget)+' --init</p></div>';
    return;
  }

  const status=await fetchJSON(`/api/monitor/status?target=${currentTarget}`);
  let h='<div class="monitor-summary">';
  h+=`<div class="ms-item"><div class="ms-val">${status?.baseline_subdomains??'--'}</div><div class="ms-label">baseline subs</div></div>`;
  h+=`<div class="ms-item"><div class="ms-val">${status?.baseline_ports??'--'}</div><div class="ms-label">baseline ports</div></div>`;
  h+=`<div class="ms-item"><div class="ms-val">${changes.length}</div><div class="ms-label">checks</div></div>`;
  if(status?.last_check){
    const d=new Date(status.last_check*1000);
    h+=`<div class="ms-item"><div class="ms-val" style="font-size:13px">${d.toLocaleDateString()}</div><div class="ms-label">last check</div></div>`;
  }
  h+='</div>';

  h+='<div class="monitor-timeline">';
  for(const c of changes){
    const eid=_monitorEntryId++;
    const s=c.summary||{};
    const total=s.total_changes||0;
    const date=c.timestamp?new Date(c.timestamp).toLocaleString():(c._filename||'');

    h+=`<div class="monitor-entry">`;
    h+=`<div class="me-time">${esc(date)}</div>`;
    h+=`<div class="me-badges">`;
    if(s.subdomains_added>0)h+=`<span class="me-badge add">+${s.subdomains_added} subs</span>`;
    if(s.subdomains_removed>0)h+=`<span class="me-badge rem">-${s.subdomains_removed} subs</span>`;
    if(s.ports_added>0)h+=`<span class="me-badge add">+${s.ports_added} ports</span>`;
    if(s.ports_removed>0)h+=`<span class="me-badge rem">-${s.ports_removed} ports</span>`;
    if(total===0)h+=`<span class="me-badge neutral">no changes</span>`;
    h+=`</div>`;

    if(total>0){
      h+=`<button class="me-toggle" onclick="document.getElementById('med-${eid}').classList.toggle('open')">details ▾</button>`;
      h+=`<div class="me-details" id="med-${eid}">`;
      if(c.new_subdomains?.length){
        h+=`<div style="color:var(--fg4);margin-bottom:2px">new subdomains:</div>`;
        for(const sub of c.new_subdomains)h+=`<div class="me-detail-item add">+ ${esc(sub)}</div>`;
      }
      if(c.removed_subdomains?.length){
        h+=`<div style="color:var(--fg4);margin:4px 0 2px">removed subdomains:</div>`;
        for(const sub of c.removed_subdomains)h+=`<div class="me-detail-item rem">- ${esc(sub)}</div>`;
      }
      if(c.new_ports?.length){
        h+=`<div style="color:var(--fg4);margin:4px 0 2px">new ports:</div>`;
        for(const p of c.new_ports)h+=`<div class="me-detail-item add">+ ${esc(p)}</div>`;
      }
      if(c.removed_ports?.length){
        h+=`<div style="color:var(--fg4);margin:4px 0 2px">removed ports:</div>`;
        for(const p of c.removed_ports)h+=`<div class="me-detail-item rem">- ${esc(p)}</div>`;
      }
      h+=`</div>`;
    }
    h+=`</div>`;
  }
  h+='</div>';
  el.innerHTML=h;
}

// ── Monitor toggle per target ──
window.toggleMonitor=async function(target,enabled){
  await postJSON('/api/monitor/toggle',{target,enabled});
};

// ── Monitor modal ──
window.openMonitorModal=function(){document.getElementById('monitor-modal').classList.add('open')};
window.closeMonitorModal=function(){document.getElementById('monitor-modal').classList.remove('open')};
window.submitMonitorModal=async function(){
  const domain=document.getElementById('monitor-domain').value.trim();
  if(!domain){document.getElementById('monitor-domain').style.borderColor='var(--red)';return}
  closeMonitorModal();
  const hasBaseline=await fetchJSON(`/api/monitor/status?target=${domain}`);
  const init=!(hasBaseline?.has_baselines);
  const res=await postJSON('/api/monitor/start',{domain,target:domain,init});
  if(res?.ok){
    openScanModal();
    document.getElementById('scan-log').classList.add('visible');
    pollScanLog();
  }else{alert(res?.message||'Failed to start monitor')}
};

window.runMonitorScan=async function(){
  if(!currentTarget){
    openMonitorModal();
    return;
  }
  const domain=document.getElementById('m-domain')?.textContent||currentTarget;
  const hasBaseline=await fetchJSON(`/api/monitor/status?target=${currentTarget}`);
  const init=!(hasBaseline?.has_baselines);
  const res=await postJSON('/api/monitor/start',{domain,target:currentTarget,init});
  if(res?.ok){
    openScanModal();
    document.getElementById('scan-log').classList.add('visible');
    pollScanLog();
  }else{alert(res?.message||'Failed to start monitor')}
};

// ── Init ──
loadExplorer();
})();
