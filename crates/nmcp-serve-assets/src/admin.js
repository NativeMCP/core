const S = {
  section: 'dashboard',
  policy: {roots:[],tool_paths:{},execution_profiles:{},auto_approve:false,admin_bind:'127.0.0.1:18769',mcp_bind:'127.0.0.1:18770'},
  drives: [],
  currentPath: null,
  fsHistory: [],
  fsHistoryIdx: -1,
  fsEntries: [],
  fsFilter: '',
  fsSortKey: 'name',
  fsSortAsc: true,
  auditEvents: [],
  auditFilter: '',
  auditAction: '',
  execTab: 'toolpaths',
  execJobs: [],
  envVars: {},
  doctorData: null,
  inspectorTab: 'overview',
  inspectorLive: [],
  inspectorEventSource: null,
  healthy: null,
  adminToken: localStorage.getItem('nmcp.admin.token') || sessionStorage.getItem('nmcp.admin.token') || '',
};

function $(id){return document.getElementById(id);}
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function num(v){return Number.isFinite(Number(v))?Number(v):0;}
function diagLatencyMs(v){return v==null?'--':num(v)+'ms';}
function diagLatencyBuckets(buckets,total){const denom=Math.max(1,num(total));return (buckets||[]).map(b=>{const pct=Math.min(100,Math.round((num(b.count)/denom)*100));return `<div class="diag-latency-bucket"><div class="diag-latency-label"><span>${esc(b.label||'bucket')}</span><span>${num(b.count)}</span></div><div class="diag-latency-bar"><span style="width:${pct}%"></span></div></div>`;}).join('')||'<div class="diag-detail">No latency buckets available.</div>'; }
function diagSlowestRows(items){return (items||[]).slice(0,8).map(e=>`<div class="health-item"><span class="health-name">${esc(e.action||'action')}</span><span class="health-val">${diagLatencyMs(e.duration_ms)} - ${esc(e.duration_bucket||'unbucketed')}</span><div class="health-dot ${e.timeout_like?'warn':'ok'}"></div></div>`).join('')||'<div class="diag-detail" style="padding:12px 14px">No timed calls recorded.</div>';}
function fmt_size(b){if(b==null)return '';if(b<1024)return b+' B';const u=['KB','MB','GB','TB'];let i=-1,n=b;do{n/=1024;i++;}while(n>=1024&&i<u.length-1);return(n<10?n.toFixed(1):Math.round(n))+' '+u[i];}
function fmt_date(ms){if(!ms)return '';const d=new Date(ms);return (d.getMonth()+1)+'/'+d.getDate()+'/'+d.getFullYear()+' '+(d.getHours()%12||12)+':'+(String(d.getMinutes()).padStart(2,'0'))+' '+(d.getHours()>=12?'PM':'AM');}
function fmt_ts(iso){try{const d=new Date(iso);const now=new Date();const diff=now-d;if(diff<60000)return 'just now';if(diff<3600000)return Math.floor(diff/60000)+'m ago';if(diff<86400000)return Math.floor(diff/3600000)+'h ago';return (d.getMonth()+1)+'/'+d.getDate()+' '+(d.getHours()%12||12)+':'+(String(d.getMinutes()).padStart(2,'0'))+(d.getHours()>=12?'pm':'am');}catch(e){return iso;}}
function adminAuthHeaders(opts={}){const headers={...(opts.headers||{})};if(S.adminToken)headers['x-nmcp-admin-token']=S.adminToken;return {...opts,headers};}
function setAdminToken(value,persist){S.adminToken=(value||'').trim();sessionStorage.removeItem('nmcp.admin.token');localStorage.removeItem('nmcp.admin.token');if(S.adminToken){(persist?localStorage:sessionStorage).setItem('nmcp.admin.token',S.adminToken);}toast(S.adminToken?'Admin token saved':'Admin token cleared',S.adminToken?'ok':'info');}
async function jsonFetch(url,opts={}){const res=await fetch(url,adminAuthHeaders(opts));const body=await res.json().catch(()=>({}));if(!res.ok){const err=new Error(body.message||body.error||res.statusText);err.body=body;err.status=res.status;if(res.status===401||res.status===503){err.message=(body.message||body.error||res.statusText)+'; configure admin token in Settings';}throw err;}return body;}
function isAbortError(e){return !!(e&&(e.name==='AbortError'||String(e.message||'').toLowerCase().includes('aborted')));}
async function jsonFetchTimeout(url,opts={},ms=5000){const ctl=new AbortController();let timedOut=false;const timer=setTimeout(()=>{timedOut=true;try{ctl.abort();}catch(_){ }},ms);try{return await jsonFetch(url,{...opts,signal:ctl.signal});}catch(e){if(timedOut){const err=new Error('Request timed out after '+ms+'ms: '+url);err.cause=e;throw err;}throw e;}finally{clearTimeout(timer);}}
function downloadBlob(filename,blob){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=filename||'nmcp-download.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
async function downloadAdminApi(url,filename){const res=await fetch(url,adminAuthHeaders({headers:{accept:'application/json'}}));if(!res.ok){let body={};try{body=await res.json();}catch(_){}let msg=body.message||body.error||res.statusText;if(res.status===401||res.status===503)msg+='; configure admin token in Settings';throw new Error(msg);}const blob=await res.blob();downloadBlob(filename,blob);toast('Download started','ok');}
async function openAdminJson(url,filename){const data=await jsonFetch(url);downloadBlob(filename||'nmcp-api-response.json',new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));}

function denialMetaFrom(v){
  const src=v&&v.body?v.body:v||{};
  let msg=src.message||src.error||'';
  let meta={error_kind:src.error_kind||'',message:msg,remediation:src.remediation||'',provider:src.provider||'',source:src.source||'',policy:src.policy||src.root||src.permission_context||''};
  if((!meta.error_kind||!meta.remediation||!meta.message)&&typeof src.summary==='string'&&src.summary.trim().startsWith('{')){try{const parsed=JSON.parse(src.summary);meta={...meta,error_kind:meta.error_kind||parsed.error_kind||'',message:meta.message||parsed.message||parsed.error||'',remediation:meta.remediation||parsed.remediation||'',provider:meta.provider||parsed.provider||'',source:meta.source||parsed.source||'',policy:meta.policy||parsed.policy||parsed.root||parsed.permission_context||''};}catch(_){}}
  return meta;
}
function denialHasMeta(m){return !!(m&&(m.error_kind||m.message||m.remediation||m.provider||m.source||m.policy));}
function denialMetaBlock(m){if(!denialHasMeta(m))return '';return `<div class="av-meta" style="margin-bottom:10px"><div class="label">Error kind:</div><div class="value">${esc(m.error_kind||'-')}</div><div class="label">Message:</div><div class="value">${esc(m.message||'-')}</div><div class="label">Remediation:</div><div class="value">${esc(m.remediation||'-')}</div><div class="label">Provider:</div><div class="value">${esc(m.provider||'-')}</div><div class="label">Source:</div><div class="value">${esc(m.source||'-')}</div><div class="label">Policy/root:</div><div class="value">${esc(typeof m.policy==='string'?m.policy:(m.policy?JSON.stringify(m.policy):'-'))}</div></div>`;}
function setJobResult(v){const el=$('job-result');if(!el)return;const meta=denialMetaFrom(v);if(denialHasMeta(meta)){el.outerHTML=`<div id="job-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px;min-height:90px">${denialMetaBlock(meta)}<pre style="margin:0;white-space:pre-wrap">${esc(JSON.stringify((v&&v.body)||v,null,2))}</pre></div>`;}else{el.outerHTML=`<pre id="job-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px;min-height:90px">${esc(typeof v==='string'?v:JSON.stringify(v,null,2))}</pre>`;}}
function toast(msg,type='info'){const el=document.createElement('div');el.className='toast '+type;el.textContent=msg;$('toast-layer').appendChild(el);setTimeout(()=>el.remove(),3200);}
function setContentMode(mode='standard'){const c=$('content');if(!c)return;c.classList.remove('content-standard','content-fullbleed','content-compact');c.classList.add('content-'+mode);c.style.padding='';c.style.overflow='';}
let pendingConfirmAction=null;
function confirmAction(opts){pendingConfirmAction=opts||{};const danger=pendingConfirmAction.danger?'danger':'primary';$('modal-layer').innerHTML=`<div class="modal-backdrop" onclick="if(event.target===this)cancelConfirmedAction()"><div class="modal confirm-modal"><div class="modal-head"><span class="modal-title">${esc(pendingConfirmAction.title||'Confirm action')}</span><button class="modal-close" onclick="cancelConfirmedAction()">&times;</button></div><div class="modal-body"><div class="confirm-message">${esc(pendingConfirmAction.message||'Continue?')}</div>${pendingConfirmAction.detail?`<div class="confirm-detail">${esc(pendingConfirmAction.detail)}</div>`:''}</div><div class="modal-foot"><button class="btn" onclick="cancelConfirmedAction()">Cancel</button><button class="btn ${danger}" onclick="runConfirmedAction()">${esc(pendingConfirmAction.confirmText||'Confirm')}</button></div></div></div>`;}
async function runConfirmedAction(){const action=pendingConfirmAction;pendingConfirmAction=null;closeModal();if(action&&typeof action.onConfirm==='function')await action.onConfirm();}
function cancelConfirmedAction(){const action=pendingConfirmAction;pendingConfirmAction=null;closeModal();if(action&&typeof action.onCancel==='function')action.onCancel();}

/* NAVIGATION */
function nav(section){
  if(S.section==='inspector'&&section!=='inspector')stopInspectorLive();
  S.section=section;
  document.querySelectorAll('.sb-item').forEach(el=>el.classList.toggle('active',el.dataset.section===section));
  const titles={dashboard:'Dashboard',files:'Files',policy:'Policy & Roots',execution:'Execution',upstreams:'MCP Gateway',inspector:'Inspector',audit:'Audit Viewer',diagnostics:'Diagnostics',settings:'Settings'};
  $('tb-title').textContent=titles[section]||section;
  const content=$('content');
  setContentMode('standard');
  content.innerHTML='<div class="loading"><div class="spinner"></div> Loading&hellip;</div>';
  if(section==='dashboard')renderDashboard();
  else if(section==='files')renderFiles();
  else if(section==='policy')renderPolicy();
  else if(section==='execution')renderExecution();
  else if(section==='upstreams')renderUpstreams();
  else if(section==='inspector')renderInspector();
  else if(section==='audit')renderAudit();
  else if(section==='diagnostics')renderDiagnostics();
  else if(section==='settings')renderSettings();
}



/* SIDEBAR STATUS */
async function checkHealth(){
  try{
    await fetch('/healthz');
    $('sb-dot').classList.remove('off');
    $('sb-status-lbl').textContent='Daemon online';
    S.healthy=true;
    $('sb-health').textContent='Online';
    $('sb-health').style.background='#dcfce7';
    $('sb-health').style.color='#166534';
  }catch(e){
    $('sb-dot').classList.add('off');
    $('sb-status-lbl').textContent='Daemon offline';
    S.healthy=false;
    $('sb-health').textContent='Offline';
    $('sb-health').style.background='#fee2e2';
    $('sb-health').style.color='#991b1b';
  }
}

async function loadPolicy(){
  try{
    S.policy=await jsonFetch('/api/policy');
    S.policy.tool_paths=S.policy.tool_paths||{};
    S.policy.execution_profiles=S.policy.execution_profiles||{};
    $('sb-ep-admin').textContent='Admin: '+(S.policy.admin_bind||'127.0.0.1:18769');
    $('sb-ep-mcp').textContent='MCP: '+(S.policy.mcp_bind||'127.0.0.1:18770');
    $('sb-auto').textContent='Auto-approve: '+(S.policy.auto_approve?'on':'off');
    $('sb-auto').style.background=S.policy.auto_approve?'#fef9c3':'#dbeafe';
    $('sb-auto').style.color=S.policy.auto_approve?'#854d0e':'#1e40af';
  }catch(e){console.warn('policy load failed',e);}
}

async function loadDrives(){
  try{const d=await jsonFetch('/api/fs/drives');S.drives=d.drives||[];}catch(e){}
}

/* DASHBOARD */
async function renderDashboard(){
  try{
    const [auditData,doctor]=await Promise.all([
      jsonFetchTimeout('/api/audit/recent?limit=5',{},5000).catch(()=>({events:[]})),
      jsonFetchTimeout('/api/doctor',{},5000).catch(()=>null),
    ]);
    const events=auditData.events||[];
    const roots=S.policy.roots||[];
    const checks=doctor?doctor.checks||[]:[],pass=checks.filter(c=>c.ok).length,fail=checks.length-pass;
    const evCount=auditData.total||events.length;
    const execCount=Object.keys(S.policy.execution_profiles||{}).length;

    $('content').innerHTML=`
<div class="cards">
  <div class="card"><div class="card-lbl">Active roots</div><div class="card-val">${roots.length}</div><div class="card-sub">${S.drives.length} drives visible</div></div>
  <div class="card"><div class="card-lbl">Audit events</div><div class="card-val">${evCount.toLocaleString()}</div><div class="card-sub">in log file</div></div>
  <div class="card"><div class="card-lbl">Exec profiles</div><div class="card-val">${execCount}</div><div class="card-sub">${Object.keys(S.policy.tool_paths||{}).length} tool paths</div></div>
  <div class="card"><div class="card-lbl">Doctor checks</div><div class="card-val ${fail>0?'warn':'ok'}">${fail>0?fail+' warn':'All OK'}</div><div class="card-sub">${pass}/${checks.length} passed</div></div>
</div>
<div class="row2">
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M9 12h6M9 16h4M7 4H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V6a2 2 0 00-2-2h-2M9 4h6v4H9V4z"/></svg> Recent audit</div>
      <button class="panel-action" onclick="nav('audit')">View all &rarr;</button>
    </div>
    ${events.length===0?'<div class="empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12h6M9 16h4M7 4H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V6a2 2 0 00-2-2h-2M9 4h6v4H9V4z"/></svg><span>No audit events yet</span></div>':
    events.slice().reverse().slice(0,6).map(e=>`
      <div class="audit-item">
        <div class="audit-dot ${dotClass(e.action)}"></div>
        <div class="audit-body">
          <div class="audit-op">${esc(e.action)}${e.decision&&e.decision!=='auto_approved'?` <span class="audit-decision ${e.decision==='allowed'?'allowed':'denied'}">${esc(e.decision)}</span>`:''}</div>
          <div class="audit-path">${esc(e.summary||e.path||'')}</div>
        </div>
        <div class="audit-time">${fmt_ts(e.timestamp)}</div>
      </div>`).join('')}
  </div>
  <div style="display:flex;flex-direction:column;gap:14px">
    <div class="panel">
      <div class="panel-head"><div class="panel-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M12 2l8 4v6c0 5-3.5 9.74-8 11-4.5-1.26-8-6-8-11V6l8-4z"/></svg> Active roots</div><button class="panel-action" onclick="nav('policy')">Manage &rarr;</button></div>
      ${roots.length===0?'<div class="empty"><span>No roots configured</span></div>':roots.map(r=>`
        <div style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid #f3f4f6">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="1.5"><path d="M3 7.5A2.5 2.5 0 015.5 5h3.7l2.8 1.75H18.5A2.5 2.5 0 0121 9.25V16.5A2.5 2.5 0 0118.5 19h-13A2.5 2.5 0 013 16.5v-9z"/></svg>
          <div style="flex:1;min-width:0"><div style="font-size:12px;font-weight:500;color:#1f1f1f">${esc(r.id)}</div><div style="font-size:11px;color:#6b7280;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:monospace">${esc(r.path)}</div></div>
          <div class="perms">${(r.permissions||[]).slice(0,3).map(p=>permBadge(p,true)).join('')}${r.permissions&&r.permissions.length>3?`<span class="perm">+${r.permissions.length-3}</span>`:''}</div>
        </div>`).join('')}
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg> Health</div><button class="panel-action" onclick="nav('diagnostics')">Details &rarr;</button></div>
      ${[
        {n:'Admin API',v:S.policy.admin_bind||'127.0.0.1:18769',ok:S.healthy!==false},
        {n:'MCP endpoint',v:S.policy.mcp_bind||'127.0.0.1:18770',ok:S.healthy!==false},
        {n:'Policy',v:S.policy._path?'persisted':'in-memory',ok:true},
      ].map(h=>`<div class="health-item"><span class="health-name">${esc(h.n)}</span><span class="health-val">${esc(h.v)}</span><div class="health-dot ${h.ok?'ok':'bad'}"></div></div>`).join('')}
    </div>
  </div>
</div>`;
  }catch(e){$('content').innerHTML=`<div class="empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg><span>Failed to load dashboard: ${esc(e.message)}</span></div>`;}
}

function dotClass(action){const a=(action||'').toLowerCase();if(a.includes('read')||a.includes('report'))return 'read';if(a.includes('write')||a.includes('create')||a.includes('modify'))return 'write';if(a.includes('exec'))return 'exec';if(a.includes('list')||a.includes('search'))return 'list';return 'other';}


/* FILES */

async function renderFiles(){
  $('content').style.padding='0';
  $('content').style.overflow='hidden';
  if(!S.fx){S.fx={drives:[],currentPath:'',entries:[],filtered:[],selectionIndex:-1,selectedPath:null,sortKey:'name',sortDir:'asc',history:[],historyIndex:-1,showHidden:false,truncated:false,props:null};}
  $('content').innerHTML=fxShell();
  await fxLoadDrives();
  if(!S.fx.currentPath&&(S.policy.roots||[]).length>0)S.fx.currentPath=S.policy.roots[0].path;
  else if(!S.fx.currentPath&&S.fx.drives.length>0)S.fx.currentPath=S.fx.drives[0].path||S.fx.drives[0].name||'-';
  else if(!S.fx.currentPath)S.fx.currentPath='C:\\';
  fxBindChrome();
  await fxNavigate(S.fx.currentPath,{push:false});
}
function fxShell(){return `<div class="fx-shell">
  <div class="fx-commandbar">

    <button class="fx-cmd" id="fx-refresh"><span class="ic">&#8635;</span><span>Refresh</span></button>
    <button class="fx-cmd" id="fx-hidden"><span class="ic">H</span><span>Hidden</span></button>
    <span class="fx-spacer"></span><button class="fx-cmd" onclick="nav('policy')"><span class="ic">P</span><span>Policy</span></button><button class="fx-cmd" onclick="nav('execution')"><span class="ic">E</span><span>Execution</span></button>
  </div>
  <div class="fx-addressbar"><button class="fx-navbtn" id="fx-back" disabled>&lsaquo;</button><button class="fx-navbtn" id="fx-fwd" disabled>&rsaquo;</button><button class="fx-navbtn" id="fx-up">&uarr;</button><div class="fx-breadcrumb" id="fx-breadcrumb"></div><div class="fx-search"><span>Search</span><input id="fx-filter" placeholder="Filter current folder" /></div></div>
  <div class="fx-workspace"><aside class="fx-navpane"><h3>Quick access</h3><div id="fx-quick-access"></div><div class="sep"></div><h3>This PC</h3><div id="fx-this-pc"></div><div class="sep"></div><h3>Policy</h3><div class="fx-nav-item" onclick="nav('policy')"><span class="ic">P</span><span class="label">Policy roots</span></div></aside>
    <main class="fx-details"><div class="fx-columns" id="fx-columns"><div class="fx-col fx-col-name active" data-sort="name"><span>Name</span></div><div class="fx-col fx-col-status" data-sort="status"><span>Status</span></div><div class="fx-col fx-col-modified" data-sort="modified"><span>Date modified</span></div><div class="fx-col fx-col-type" data-sort="type"><span>Type</span></div><div class="fx-col fx-col-size" data-sort="size"><span>Size</span></div></div><div class="fx-entries" id="fx-entries"></div></main>
  </div>
  <div class="fx-statusbar"><span id="fx-status-count">0 items</span><span id="fx-status-selection"></span><span class="grow"></span><span class="fx-pill" id="fx-status-root">&mdash;</span><span class="fx-pill ok" id="fx-status-auto">Auto-approve: &hellip;</span><span class="fx-pill" id="fx-status-mcp">MCP: 127.0.0.1:18770</span></div>
</div>`;}
function fxBindChrome(){
  $('fx-refresh').onclick=()=>fxNavigate(S.fx.currentPath,{push:false});
  $('fx-hidden').onclick=()=>{S.fx.showHidden=!S.fx.showHidden;$('fx-hidden').classList.toggle('primary',S.fx.showHidden);fxNavigate(S.fx.currentPath,{push:false});};
  $('fx-back').onclick=()=>{if(S.fx.historyIndex>0){S.fx.historyIndex--;fxNavigate(S.fx.history[S.fx.historyIndex],{push:false});}};
  $('fx-fwd').onclick=()=>{if(S.fx.historyIndex<S.fx.history.length-1){S.fx.historyIndex++;fxNavigate(S.fx.history[S.fx.historyIndex],{push:false});}};
  $('fx-up').onclick=()=>{const p=S.fx.currentPath||'';const norm=p.replace(/\\/g,'/').replace(/\/+$/,'');const idx=norm.lastIndexOf('/');if(idx>2)fxNavigate(norm.slice(0,idx).replace(/\//g,'\\'));else{const m=norm.match(/^([A-Za-z]:)/);if(m)fxNavigate(m[1]+'\\');}};
  $('fx-filter').oninput=()=>{S.fx.selectionIndex=-1;S.fx.selectedPath=null;fxRenderEntries();};
  document.querySelectorAll('#fx-columns .fx-col').forEach(c=>{c.onclick=()=>{const k=c.dataset.sort;if(S.fx.sortKey===k)S.fx.sortDir=S.fx.sortDir==='asc'?'desc':'asc';else{S.fx.sortKey=k;S.fx.sortDir='asc';}fxRenderEntries();};});
}
async function fxLoadDrives(){try{const d=await jsonFetch('/api/fs/drives');S.fx.drives=d.drives||[];}catch(e){S.fx.drives=[];}}
async function fxNavigate(path,opts={}){
  const entries=$('fx-entries');if(!entries)return;entries.innerHTML='<div class="fx-empty">Loading&hellip;</div>';
  try{
    const url='/api/fs/list?path='+encodeURIComponent(path)+'&limit=1000'+(S.fx.showHidden?'&include_hidden=true':'');
    const data=await jsonFetch(url);
    S.fx.currentPath=data.path||path;S.fx.entries=data.entries||[];S.fx.truncated=!!data.truncated;S.fx.selectionIndex=-1;S.fx.selectedPath=null;
    if(opts.push!==false){S.fx.history=S.fx.history.slice(0,S.fx.historyIndex+1);S.fx.history.push(S.fx.currentPath);S.fx.historyIndex=S.fx.history.length-1;}
    fxRenderSidebar();fxRenderAddress();fxRenderEntries();fxRenderStatus();fxUpdateNav();
  }catch(e){entries.innerHTML='<div class="fx-empty">'+esc(e.message)+'</div>';}
}
function fxPathNorm(p){return String(p||'').replace(/\\/g,'/').replace(/\/+$/,'').toLowerCase();}
function fxDisplayPath(p){return String(p||'').replace(/^\\\?\\/,'').replace(/^\\\?\//,'').replace(/^\?\\/,'').replace(/^\?\//,'');}
function fxApiPath(p){return String(p||'');}
async function fxCalculateSize(path,maxEntries=15000){
  let total=0,count=0,queue=[path];
  while(queue.length&&count<maxEntries){
    const cur=queue.shift();
    const data=await jsonFetch('/api/fs/list?path='+encodeURIComponent(cur)+'&limit=1000&include_hidden=true');
    for(const e of (data.entries||[])){
      count++;
      if(e.kind==='directory')queue.push(e.path);
      else if(typeof e.size==='number')total+=e.size;
      if(count>=maxEntries)break;
    }
  }
  return {bytes:total,count,truncated:queue.length>0||count>=maxEntries};
}
function fxMatchRoot(path){const p=fxPathNorm(path);return (S.policy.roots||[]).find(r=>p.startsWith(fxPathNorm(r.path)));}
function fxExactRoot(path){const p=fxPathNorm(path);return (S.policy.roots||[]).find(r=>p===fxPathNorm(r.path));}
function fxRenderSidebar(){
  const qa=$('fx-quick-access'),tp=$('fx-this-pc');const roots=S.policy.roots||[];
  qa.innerHTML=roots.length?roots.map(r=>`<div class="fx-nav-item ${fxPathNorm(r.path)===fxPathNorm(S.fx.currentPath)?'active':''}" data-path="${esc(r.path)}" title="${esc(fxDisplayPath(r.path))}"><span class="ic">${fxIconFolder()}</span><span class="label">${esc(r.id)}</span><span class="sub">${(r.permissions||[]).length}</span></div>`).join(''):'<div class="fx-nav-item" style="color:#9ca3af;cursor:default"><span class="label">No roots configured</span></div>';
  tp.innerHTML=S.fx.drives.map(d=>{const active=S.fx.currentPath&&fxPathNorm(S.fx.currentPath).startsWith(fxPathNorm(d.path).slice(0,2));return `<div class="fx-nav-item ${active?'active':''}" data-path="${esc(d.path||d.name||'')}" title="${esc(fxDisplayPath(d.path||''))}"><span class="ic">${fxIconDrive()}</span><span class="label">Local Disk (${esc(d.name||d.path||'')})</span></div>`;}).join('');
  document.querySelectorAll('.fx-nav-item[data-path]').forEach(el=>{el.onclick=()=>fxNavigate(el.dataset.path);el.oncontextmenu=ev=>{ev.preventDefault();fxOpenNavContextMenu(ev.clientX,ev.clientY,el.dataset.path,el.querySelector('.label')?el.querySelector('.label').textContent:'Root');};});
}
function fxRenderAddress(){
  const bc=$('fx-breadcrumb');const path=S.fx.currentPath||'';const displayPath=fxDisplayPath(path);const norm=displayPath.replace(/\//g,'\\');const m=norm.match(/^([A-Za-z]:)\\?(.*)$/);let html='';
  if(m){let built=m[1]+'\\';html+=`<span class="fx-crumb icon" data-path="${esc(built)}">${esc(m[1])}</span>`;const rest=m[2]?m[2].split('\\').filter(Boolean):[];rest.forEach(part=>{html+='<span class="fx-bc-sep">Âº</span>';built+=part+'\\';html+=`<span class="fx-crumb" data-path="${esc(built)}">${esc(part)}</span>`;});}
  else html=`<span class="fx-crumb" data-path="${esc(path)}">${esc(fxDisplayPath(path)||'Computer')}</span>`;
  html+=`<input class="fx-path-input" id="fx-path-input" value="${esc(fxDisplayPath(path))}" />`;bc.innerHTML=html;
  bc.querySelectorAll('.fx-crumb').forEach(c=>c.onclick=()=>fxNavigate(c.dataset.path));
  bc.ondblclick=()=>{bc.classList.add('editing');const inp=$('fx-path-input');inp.focus();inp.select();};
  const inp=$('fx-path-input');inp.onkeydown=e=>{if(e.key==='Enter'){bc.classList.remove('editing');fxNavigate(inp.value);}if(e.key==='Escape')bc.classList.remove('editing');};inp.onblur=()=>bc.classList.remove('editing');
}
function fxRenderEntries(){
  const filter=($('fx-filter')&&$('fx-filter').value||'').toLowerCase();let arr=S.fx.entries.filter(e=>!filter||String(e.name||'').toLowerCase().includes(filter));fxSortEntries(arr);S.fx.filtered=arr;const list=$('fx-entries');
  const selectedNorm=fxPathNorm(S.fx.selectedPath);
  if(selectedNorm){const idx=arr.findIndex(e=>fxPathNorm(e.path)===selectedNorm);if(idx>=0)S.fx.selectionIndex=idx;else{S.fx.selectionIndex=-1;S.fx.selectedPath=null;}}else S.fx.selectionIndex=-1;
  if(arr.length===0){list.innerHTML='<div class="fx-empty">This folder is empty'+(filter?' (filter active)':'')+'.</div>';fxRenderStatus();return;}
  let html=arr.map((e,i)=>{const root=fxMatchRoot(e.path);let dot='none',title='Not under any policy root';if(root){const n=(root.permissions||[]).length;if(n>=8){dot='ok';title='Under '+root.id+' - '+n+' permissions';}else{dot='warn';title='Under '+root.id+' - '+n+' permissions';}}
    const status=`<span class="fx-badge-dot ${dot}" title="${esc(title)}"></span>${root?esc(root.id):'<span style="color:#9ca3af">no root</span>'}`;
    return `<div class="fx-entry ${e.hidden?'hidden-row':''} ${S.fx.selectedPath&&fxPathNorm(e.path)===fxPathNorm(S.fx.selectedPath)?'selected':''}" data-i="${i}" data-kind="${esc(e.kind||'')}" data-path="${esc(e.path||'')}"><div class="fx-cell fx-col-name"><span class="fx-icon">${fxIconFor(e)}</span><span class="fx-name">${esc(e.name||'')}</span></div><div class="fx-cell fx-col-status">${status}</div><div class="fx-cell fx-col-modified">${esc(fxDate(e.modified_unix_ms||e.modified))}</div><div class="fx-cell fx-col-type">${esc(fxType(e))}</div><div class="fx-cell fx-col-size">${esc(fxSize(e.size))}</div></div>`;}).join('');
  if(S.fx.truncated)html+='<div class="fx-truncated">Directory listing truncated at 1000 entries.</div>';list.innerHTML=html;
  list.querySelectorAll('.fx-entry').forEach(row=>{row.onclick=()=>fxSelect(row);row.ondblclick=()=>fxOpen(row);row.oncontextmenu=ev=>{ev.preventDefault();fxSelect(row);fxOpenContextMenu(ev.clientX,ev.clientY,row);};});
  fxRenderColumns();fxRenderStatus();
}
function fxSortEntries(arr){const k=S.fx.sortKey,d=S.fx.sortDir==='asc'?1:-1;arr.sort((a,b)=>{if(a.kind==='directory'&&b.kind!=='directory')return -1;if(a.kind!=='directory'&&b.kind==='directory')return 1;let va='',vb='';if(k==='name'){va=String(a.name||'').toLowerCase();vb=String(b.name||'').toLowerCase();return va<vb?-d:va>vb?d:0;}if(k==='modified')return ((a.modified_unix_ms||a.modified||0)-(b.modified_unix_ms||b.modified||0))*d;if(k==='size')return ((a.size||0)-(b.size||0))*d;if(k==='type'){va=fxType(a);vb=fxType(b);return va<vb?-d:va>vb?d:0;}if(k==='status'){va=fxMatchRoot(a.path)?0:1;vb=fxMatchRoot(b.path)?0:1;return (va-vb)*d;}return 0;});}
function fxRenderColumns(){document.querySelectorAll('#fx-columns .fx-col').forEach(c=>{c.classList.toggle('active',c.dataset.sort===S.fx.sortKey);let old=c.querySelector('.arrow');if(old)old.remove();if(c.dataset.sort===S.fx.sortKey){let a=document.createElement('span');a.className='arrow';a.textContent=S.fx.sortDir==='asc'?'^':'v';c.appendChild(a);}});}
function fxSelect(row){document.querySelectorAll('.fx-entry.selected').forEach(x=>x.classList.remove('selected'));row.classList.add('selected');S.fx.selectionIndex=Number(row.dataset.i);const entry=S.fx.filtered[S.fx.selectionIndex];S.fx.selectedPath=entry?entry.path:null;fxRenderStatus();}
function fxOpen(row){const e=S.fx.filtered[Number(row.dataset.i)];if(!e)return;if(e.kind==='directory')fxNavigate(e.path);else fxOpenProperties(e);}
function fxRenderStatus(){const count=$('fx-status-count');if(!count)return;count.textContent=S.fx.entries.length+' item'+(S.fx.entries.length===1?'':'s');const selectedNorm=fxPathNorm(S.fx.selectedPath);const sel=selectedNorm?S.fx.filtered.find(e=>fxPathNorm(e.path)===selectedNorm):null;if(!sel)S.fx.selectionIndex=-1;$('fx-status-selection').textContent=sel?('|  '+sel.name+(sel.size!=null?' - '+fxSize(sel.size):'')):'';const root=fxMatchRoot(S.fx.currentPath);$('fx-status-root').textContent=root?('Root: '+root.id):'No matching root';$('fx-status-root').className='fx-pill'+(root?' ok':' warn');$('fx-status-auto').textContent='Auto-approve: '+(S.policy.auto_approve?'on':'off');$('fx-status-auto').className='fx-pill'+(S.policy.auto_approve?' ok':'');$('fx-status-mcp').textContent='MCP: '+(S.policy.mcp_bind||'127.0.0.1:18770');}
function fxUpdateNav(){$('fx-back').disabled=S.fx.historyIndex<=0;$('fx-fwd').disabled=S.fx.historyIndex>=S.fx.history.length-1;const p=S.fx.currentPath||'';$('fx-up').disabled=!!p.match(/^[A-Za-z]:[\\\/]?$/);}
function fxClosePopups(){document.querySelectorAll('.fx-ctx-menu,.fx-perm-popover').forEach(el=>el.remove());}
function fxOpenNavContextMenu(x,y,path,label){
  fxClosePopups();
  const exact=fxExactRoot(path);
  const entry={name:label||fxDisplayPath(path),path:path,kind:'directory'};
  const items=[
    {label:'Open',handler:()=>fxNavigate(path)},
    {label:'Refresh',handler:()=>fxNavigate(path,{push:false})},
    {sep:true},
    {label:'Copy path',handler:()=>fxCopyPath(fxDisplayPath(path))},
    {label:'Permissions',handler:()=>fxShowPermPopover(x,y,entry,fxMatchRoot(path))},
    exact?{label:'Remove from policy',handler:()=>removeRoot(exact.id,async()=>{await loadPolicy();await fxNavigate(S.fx.currentPath,{push:false});})}:{label:'Add as root...',handler:()=>fxOpenProperties(entry,{tab:'security',addRoot:true})},
    {sep:true},
    {label:'Properties',handler:()=>fxOpenProperties(entry)}
  ];
  const menu=document.createElement('div');menu.className='fx-ctx-menu';menu.style.left=x+'px';menu.style.top=y+'px';
  menu.innerHTML=items.map((it,i)=>it.sep?'<div class="fx-ctx-sep"></div>':`<div class="fx-ctx-item ${it.disabled?'disabled':''}" data-i="${i}"><span>${esc(it.label)}</span></div>`).join('');
  document.body.appendChild(menu);const r=menu.getBoundingClientRect();if(r.right>innerWidth-4)menu.style.left=(innerWidth-r.width-6)+'px';if(r.bottom>innerHeight-4)menu.style.top=(innerHeight-r.height-6)+'px';
  menu.querySelectorAll('.fx-ctx-item').forEach(div=>div.onclick=()=>{const it=items[Number(div.dataset.i)];if(it.disabled)return;fxClosePopups();if(it.handler)it.handler();});
}
function fxOpenContextMenu(x,y,row){
  fxClosePopups();const e=S.fx.filtered[Number(row.dataset.i)];if(!e)return;const root=fxMatchRoot(e.path),exact=fxExactRoot(e.path);const items=[];
  if(e.kind==='directory')items.push({label:'Open',handler:()=>fxNavigate(e.path)});
  items.push({label:'Refresh',handler:()=>fxNavigate(S.fx.currentPath,{push:false})});
  items.push({sep:true});
  items.push({label:'Copy path',handler:()=>fxCopyPath(e.path)});
  items.push({sep:true});
  items.push({label:'Permissions',handler:()=>fxShowPermPopover(x,y,e,root)});
  if(!exact)items.push({label:'Add as root...',handler:()=>fxOpenProperties(e,{tab:'security',addRoot:true})});
  else items.push({label:'Remove from policy',handler:()=>removeRoot(exact.id,async()=>{await fxNavigate(S.fx.currentPath,{push:false});})});
  items.push({sep:true});items.push({label:'Properties',handler:()=>fxOpenProperties(e)});
  const menu=document.createElement('div');menu.className='fx-ctx-menu';menu.style.left=x+'px';menu.style.top=y+'px';
  menu.innerHTML=items.map((it,i)=>it.sep?'<div class="fx-ctx-sep"></div>':`<div class="fx-ctx-item ${it.disabled?'disabled':''}" data-i="${i}"><span>${esc(it.label)}</span></div>`).join('');
  document.body.appendChild(menu);const r=menu.getBoundingClientRect();if(r.right>innerWidth-4)menu.style.left=(innerWidth-r.width-6)+'px';if(r.bottom>innerHeight-4)menu.style.top=(innerHeight-r.height-6)+'px';
  menu.querySelectorAll('.fx-ctx-item').forEach(div=>div.onclick=()=>{const it=items[Number(div.dataset.i)];if(it.disabled)return;fxClosePopups();if(it.handler)it.handler();});
}
async function fxCopyPath(path){const display=fxDisplayPath(path);try{await navigator.clipboard.writeText(display);toast('Path copied','ok');}catch(e){toast(display,'info');}}
function fxShowPermPopover(x,y,entry,root){
  fxClosePopups();const grants=root?new Set(root.permissions||[]):new Set();
  const rows=ALL_PERMS.map(p=>`<div class="row ${grants.has(p)?'granted':''}"><span>${grants.has(p)?'yes':'-'}</span><span>${esc(p)}</span></div>`).join('');
  const pop=document.createElement('div');pop.className='fx-perm-popover';
  pop.innerHTML='<h4>Effective permissions</h4>'+(root?`<div class="root-line">${esc(root.id)} - ${esc(fxDisplayPath(root.path))}</div>`:'<div class="none">Not under any policy root.</div>')+`<div class="grid">${rows}</div><div class="foot">${root?'<button class="btn" data-act="props">Edit in Properties...</button>':'<button class="btn primary" data-act="add">Add as root...</button>'}<button class="btn" data-act="close">Close</button></div>`;
  pop.style.left=x+'px';pop.style.top=y+'px';document.body.appendChild(pop);
  pop.querySelector('[data-act="close"]').onclick=fxClosePopups;
  const props=pop.querySelector('[data-act="props"]');if(props)props.onclick=()=>{fxClosePopups();fxOpenProperties(entry,{tab:'security'});};
  const add=pop.querySelector('[data-act="add"]');if(add)add.onclick=()=>{fxClosePopups();fxOpenProperties(entry,{tab:'security',addRoot:true});};
}
function fxOpenProperties(entry,opts={}){S.fx.props={entry,tab:opts.tab||'general',addRoot:!!opts.addRoot};fxRenderProperties();}


function fxRenderProperties(){
  const ctx=S.fx.props;if(!ctx)return;
  const entry=ctx.entry,exact=fxExactRoot(entry.path),root=fxMatchRoot(entry.path);
  $('modal-layer').innerHTML=`<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal" style="width:640px"><div class="modal-head"><span class="modal-title">${esc(entry.name)} Properties</span><button class="modal-close" onclick="closeModal()">&times;</button></div><div class="fx-modal-tabs"><div class="fx-modal-tab ${ctx.tab==='general'?'active':''}" onclick="S.fx.props.tab='general';fxRenderProperties()">General</div><div class="fx-modal-tab ${ctx.tab==='security'?'active':''}" onclick="S.fx.props.tab='security';fxRenderProperties()">Security</div></div><div class="modal-body" id="fx-props-body"></div><div class="modal-foot"><button class="btn primary" onclick="closeModal()">OK</button><button class="btn" onclick="closeModal()">Cancel</button><button class="btn" disabled>Apply</button></div></div></div>`;
  const body=$('fx-props-body');
  if(ctx.tab==='general'){
    const isFile=entry.kind!=='directory';
    const created=fxDate(entry.created_unix_ms||entry.created);
    const modified=fxDate(entry.modified_unix_ms||entry.modified);
    const accessed=fxDate(entry.accessed_unix_ms||entry.accessed);
    const sizeText=fxSize(entry.size)||'-';
    const byteText=entry.size!=null?' ('+Number(entry.size).toLocaleString()+' bytes)':'';
    body.innerHTML=`<div class="fx-props">
      <div class="header-row"><span class="big-icon">${fxIconFor(entry)}</span><div style="flex:1"><input class="input" value="${esc(entry.name)}" readonly style="width:100%;max-width:430px"></div></div>
      <div class="label">Type ${isFile?'of file':''}:</div><div class="value">${esc(fxType(entry))}</div>
      ${isFile?'<div class="label">Opens with:</div><div class="value">Default app <button class="btn" style="float:right" disabled>Change...</button></div>':''}
      <hr>
      <div class="label">Location:</div><div class="value">${esc(fxDisplayPath(fxParent(entry.path)))}</div>
      <div class="label">Size:</div><div class="value"><span id="fx-props-size">${esc(sizeText)}${byteText}</span></div>
      <div class="label">Size on disk:</div><div class="value"><span id="fx-props-size-disk">${esc(sizeText)}</span></div>
      <hr>
      <div class="label">Created:</div><div class="value">${esc(created||'Not reported by current file API')}</div>
      <div class="label">Modified:</div><div class="value">${esc(modified||'-')}</div>
      <div class="label">Accessed:</div><div class="value">${esc(accessed||'Not reported by current file API')}</div>
      <hr>
      <div class="label">Attributes:</div><div class="value fx-attr-row"><label><input type="checkbox" ${entry.readonly?'checked':''} disabled> Read-only</label><label><input type="checkbox" ${entry.hidden?'checked':''} disabled> Hidden</label><button class="btn" onclick="fxOpenAdvancedSecurity()">Advanced...</button></div>
      <div class="label">Full path:</div><div class="value">${esc(fxDisplayPath(entry.path))}</div>
    </div>`;
    if(entry.kind==='directory')fxPopulateFolderSize(entry.path);
  }else{
    const grants=root?new Set(root.permissions||[]):new Set();
    const nativeRows=[['Full control',grants.size>=ALL_PERMS.length],['Modify',grants.has('modify')||grants.has('write')],['Read & execute',grants.has('read')||grants.has('execute')],['Read',grants.has('read')],['Write',grants.has('write')],['Special permissions',grants.size>0&&grants.size<ALL_PERMS.length]];
    let html=`<div style="font-size:13px"><div style="margin-bottom:8px">Object name: <span class="fx-security-object">${esc(fxDisplayPath(entry.path))}</span></div><div>Group or user names:</div><div class="fx-security-list"><div class="fx-security-principal selected">nMCP Policy</div></div><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span>To change nMCP access, edit the policy root.</span><button class="btn" onclick="fxOpenAdvancedSecurity()">Edit...</button></div>`;
    html+=`<div style="margin-bottom:4px">Permissions for nMCP Policy</div><div class="fx-perm-table"><div class="fx-perm-row" style="font-weight:500"><span></span><span>Allow</span><span>Deny</span></div>${nativeRows.map(r=>`<div class="fx-perm-row"><span>${esc(r[0])}</span><span class="fx-check">${r[1]?'yes':''}</span><span></span></div>`).join('')}</div>`;
    html+=`<div style="margin-top:10px;display:flex;justify-content:space-between;gap:12px"><span>For special permissions or advanced settings, click Advanced.</span><button class="btn" onclick="fxOpenAdvancedSecurity()">Advanced</button></div>`;
    body.innerHTML=html+'</div>';
  }
}
async function fxPopulateFolderSize(path){
  const sizeEl=$('fx-props-size'),diskEl=$('fx-props-size-disk');
  if(!sizeEl||!diskEl)return;
  sizeEl.textContent='Calculating...';diskEl.textContent='Calculating...';
  try{
    const res=await fxCalculateSize(path);
    const text=fxSize(res.bytes)+' ('+Number(res.bytes).toLocaleString()+' bytes)'+(res.truncated?' â€ partial':'');
    sizeEl.textContent=text;diskEl.textContent=text;
  }catch(e){sizeEl.textContent='Unable to calculate';diskEl.textContent='Unable to calculate';}
}

function fxOpenAdvancedSecurity(){
  const ctx=S.fx.props;if(!ctx)return;
  const entry=ctx.entry,root=fxMatchRoot(entry.path),exact=fxExactRoot(entry.path);
  const permissions=root?(root.permissions||[]):[];
  $('modal-layer').innerHTML=`<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal" style="width:720px"><div class="modal-head"><span class="modal-title">Advanced Security Settings for ${esc(entry.name)}</span><button class="modal-close" onclick="closeModal()">&times;</button></div><div class="modal-body"><div style="margin-bottom:10px">Object name: <span class="fx-security-object">${esc(fxDisplayPath(entry.path))}</span></div><div class="fx-root-box"><strong>Owner:</strong> <span class="fx-principal-badge">nMCP Policy</span><div style="font-size:12px;color:#6b7280;margin-top:6px">This dialog models nMCP policy permissions, not Windows ACL ownership.</div></div><div style="font-weight:600;margin-top:12px">Permission entries</div><div class="fx-advanced-grid"><div class="fx-advanced-row fx-advanced-head"><div>Principal</div><div>Access</div><div>Applies to</div></div><div class="fx-advanced-row"><div>nMCP Policy</div><div>${permissions.length?esc(permissions.join(', ')):'No policy root grants this object'}</div><div>This folder, subfolders and files</div></div></div><div style="margin-top:14px"><strong>${root?'Edit permissions':'Add policy root'}</strong><div style="font-size:12px;color:#6b7280;margin:4px 0 8px">Choose the nMCP permissions that MCP tools may use for this path.</div><div class="form-row"><label>Root ID</label><input id="fx-add-root-id" value="${esc(root?root.id:(entry.name||'-').toLowerCase().replace(/[^a-z0-9_-]+/g,'-'))}" ${root?'readonly':''}></div><div class="form-row"><label>Path</label><input id="fx-add-root-path" value="${esc(fxDisplayPath(root?root.path:entry.path))}"></div><div class="policy-permission-note"><strong>Outbound publish authority is separate.</strong> <code>execute</code> does not imply <code>git.publish</code>.</div><div class="fx-perm-checklist policy-permission-grid">${ALL_PERMS.map(p=>permOption(p,permissions.includes(p)||(!root&&p!=='git.publish'),'fx-perm')).join('')}</div></div></div><div class="modal-foot"><button class="btn danger" ${exact?'':'disabled'} onclick="removeRoot('${esc(exact?exact.id:'')}',async()=>{closeModal();await loadPolicy();await fxNavigate(S.fx.currentPath,{push:false});})">Remove</button><span style="flex:1"></span><button class="btn" onclick="S.fx.props.tab='security';fxRenderProperties()">Cancel</button><button class="btn primary" onclick="fxSaveAdvancedSecurity(${root?'true':'false'})">OK</button></div></div></div>`;
}
async function fxSaveAdvancedSecurity(isUpdate){
  const id=$('fx-add-root-id').value.trim(),path=$('fx-add-root-path').value.trim();
  if(!id||!path){toast('ID and path are required','bad');return;}
  const permissions=ALL_PERMS.filter(p=>$('fx-perm-'+p)&&$('fx-perm-'+p).checked);
  try{
    await jsonFetch(isUpdate?'/api/roots/update':'/api/roots/add',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,path,permissions})});
    closeModal();await loadPolicy();toast(isUpdate?'Policy permissions updated':'Policy root added','ok');fxNavigate(S.fx.currentPath,{push:false});
  }catch(e){toast(e.message,'bad');}
}
async function fxAddRootFromProps(){const id=$('fx-add-root-id').value.trim(),path=$('fx-add-root-path').value.trim();if(!id||!path){toast('ID and path are required','bad');return;}const permissions=ALL_PERMS.filter(p=>$('fx-perm-'+p)&&$('fx-perm-'+p).checked);try{await jsonFetch('/api/roots/add',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,path,permissions})});closeModal();await loadPolicy();toast('Root added','ok');fxNavigate(S.fx.currentPath,{push:false});}catch(e){toast(e.message,'bad');}}
function fxParent(path){const p=String(path||'').replace(/\\/g,'/');const i=p.lastIndexOf('/');return i>=0?p.slice(0,i).replace(/\//g,'\\'):'';}
function fxType(e){if(e.kind==='directory')return 'File folder';if(e.kind==='symlink')return 'Symbolic link';if(e.extension)return String(e.extension).toUpperCase()+' file';return 'File';}
function fxSize(b){if(b==null)return '';if(b<1024)return b+' B';const u=['KB','MB','GB','TB'];let i=-1,n=b;do{n/=1024;i++;}while(n>=1024&&i<u.length-1);return(n<10?n.toFixed(1):Math.round(n))+' '+u[i];}
function fxDate(ms){if(!ms)return '';const d=new Date(ms);return (d.getMonth()+1)+'/'+d.getDate()+'/'+d.getFullYear()+' '+(d.getHours()%12||12)+':'+String(d.getMinutes()).padStart(2,'0')+' '+(d.getHours()>=12?'PM':'AM');}
function fxIconFolder(){return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M3 7.5C3 6.12 4.12 5 5.5 5h3.7l2.8 1.75h6.5C19.88 6.75 21 7.87 21 9.25v7.25c0 1.38-1.12 2.5-2.5 2.5h-13C4.12 19 3 17.88 3 16.5v-9Z" fill="#dcb35b"/></svg>';}
function fxIconDrive(){return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><rect x="3" y="6" width="18" height="12" rx="2" fill="#dfeaf7" stroke="#8aa9c8"/><circle cx="17" cy="15" r="1" fill="#2563eb"/></svg>';}
function fxIconFile(){return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M6 3h8l5 5v12c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2V5c0-1.1.9-2 2-2Z" fill="#e9eef5" stroke="#9bb4d4"/><path d="M14 3v5h5" fill="#fff" stroke="#9bb4d4"/></svg>';}
function fxIconFor(e){return e.kind==='directory'?fxIconFolder():fxIconFile();}
document.addEventListener('click',ev=>{if(!ev.target.closest('.fx-ctx-menu')&&!ev.target.closest('.fx-perm-popover'))fxClosePopups();});

/* POLICY & ROOTS */
const ALL_PERMS=['list','read','search','create','write','modify','rename','move','backup','execute','scan','report','git.publish'];
const PERM_META={
  'git.publish':{label:'git.publish',kind:'publish',title:'Outbound publish authority. Not implied by execute.',help:'Allows governed git publishing from this root. Use only for repositories approved for outbound publish.'},
  execute:{label:'execute',kind:'exec',title:'Run approved local commands inside this root.',help:'Execution authority does not include git.publish.'},
  write:{label:'write',kind:'write',title:'Write file contents.'},
  create:{label:'create',kind:'write',title:'Create files or folders.'},
  modify:{label:'modify',kind:'write',title:'Modify existing content.'},
  scan:{label:'scan',kind:'scan',title:'Run scanning/reporting workflows.'},
  report:{label:'report',kind:'scan',title:'Generate reports.'}
};
function permMeta(p){return PERM_META[p]||{label:p,kind:'',title:p,help:''};}
function permLabel(p){return permMeta(p).label||p;}
function permTitle(p){const m=permMeta(p);return m.title||m.help||m.label||p;}
function permClass(p){return permMeta(p).kind||'';}
function permBadge(p,on=true){return `<span class="perm ${on?permClass(p):'off'}" title="${esc(permTitle(p))}">${esc(permLabel(p))}</span>`;}
function permOption(p,checked,idPrefix){const m=permMeta(p);return `<label class="perm-option ${m.kind||''}" title="${esc(m.title||'')}"><input type="checkbox" id="${idPrefix}-${p}" ${checked?'checked':''}><span><strong>${esc(m.label||p)}</strong>${m.help?`<small>${esc(m.help)}</small>`:''}</span></label>`;}

async function renderPolicy(){
  const roots=S.policy.roots||[];
  $('content').innerHTML=`
<div class="section-header"><h3>Roots</h3><button class="btn primary" onclick="openAddRoot()">+ Add root</button></div>
<div class="panel">
  <table class="tbl">
    <thead><tr><th>ID</th><th>Path</th><th>Permissions</th><th style="width:80px">Actions</th></tr></thead>
    <tbody id="roots-tbody">${roots.length===0?'<tr><td colspan="4"><div class="empty" style="padding:20px">No roots configured</div></td></tr>':roots.map(r=>`
      <tr>
        <td style="font-weight:500">${esc(r.id)}</td>
        <td class="mono">${esc(r.path)}</td>
        <td><div class="perms">${ALL_PERMS.map(p=>permBadge(p,(r.permissions||[]).includes(p))).join('')}</div></td>
        <td><div class="actions"><button class="act-btn primary" onclick="openEditRoot('${esc(r.id)}')">Edit</button><button class="act-btn danger" onclick="removeRoot('${esc(r.id)}')">Remove</button></div></td>
      </tr>`).join('')}
    </tbody>
  </table>
</div>
<div class="section-header" style="margin-top:8px"><h3>Approval mode</h3></div>
<div class="panel" style="padding:14px">
  <div style="display:flex;align-items:center;gap:14px;padding:8px 0">
    <div style="flex:1"><div style="font-size:13px;font-weight:500">Auto-approve mode</div><div style="font-size:11px;color:#6b7280;margin-top:2px">When enabled, policy checks are bypassed for local MCP operations. Use only for isolated development.</div></div>
    <label class="toggle"><input type="checkbox" id="auto-toggle" ${S.policy.auto_approve?'checked':''} onchange="toggleAutoApprove(this.checked)"><div class="toggle-track"></div><div class="toggle-thumb"></div></label>
  </div>
</div>`;
}

async function toggleAutoApprove(on){
  if(on){confirmAction({title:'Enable auto-approve',message:'Bypass policy checks for local MCP operations?',detail:'Use this only for isolated development. This reduces the safety value of policy roots until disabled.',confirmText:'Enable auto-approve',danger:true,onConfirm:()=>applyAutoApprove(true),onCancel:()=>renderPolicy()});return;}
  await applyAutoApprove(false);
}
async function applyAutoApprove(on){
  try{
    const pol={...S.policy,auto_approve:on};
    await jsonFetch('/api/policy',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(pol)});
    await loadPolicy();
    toast('Auto-approve '+(on?'enabled':'disabled'),on?'bad':'ok');
    renderPolicy();
  }catch(e){toast(e.message,'bad');renderPolicy();}
}

function openAddRoot(){showRootModal(null);}
function openEditRoot(id){const r=S.policy.roots.find(r=>r.id===id);if(r)showRootModal(r);}

function showRootModal(root){
  const existing=root!=null;
  $('modal-layer').innerHTML=`
<div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-head"><span class="modal-title">${existing?'Edit root: '+esc(root.id):'Add root'}</span><button class="modal-close" onclick="closeModal()">&times;</button></div>
    <div class="modal-body">
      <div class="form-row"><label>Root ID</label><input id="r-id" value="${existing?esc(root.id):''}" placeholder="e.g. projects" ${existing?'disabled':''}></div>
      <div class="form-row"><label>Path</label><input id="r-path" value="${existing?esc(root.path):''}" placeholder="e.g. D:\\projects"></div>
      <div style="margin-top:14px;margin-bottom:8px;font-size:12px;font-weight:500;color:#374151">Permissions</div>
      <div class="policy-permission-note"><strong>Publish authority is explicit.</strong> <code>execute</code> does not imply <code>git.publish</code>. Grant <code>git.publish</code> only to repository roots approved for outbound publish.</div>
      <div class="policy-permission-grid">
        ${ALL_PERMS.map(p=>permOption(p,existing&&(root.permissions||[]).includes(p),'r-perm')).join('')}
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn primary" onclick="${existing?`saveRoot('${esc(root.id)}')`:'addRoot()'}">${existing?'Save':'Add root'}</button>
    </div>
  </div>
</div>`;
}

function closeModal(){$('modal-layer').innerHTML='';}

async function addRoot(){
  const id=$('r-id').value.trim(),path=$('r-path').value.trim();
  if(!id||!path){toast('ID and path are required','bad');return;}
  const perms=ALL_PERMS.filter(p=>$('r-perm-'+p)&&$('r-perm-'+p).checked);
  try{await jsonFetch('/api/roots/add',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,path,permissions:perms})});closeModal();await loadPolicy();toast('Root "'+id+'" added','ok');renderPolicy();}
  catch(e){toast(e.message,'bad');}
}

async function saveRoot(id){
  const path=$('r-path').value.trim();
  if(!path){toast('Path is required','bad');return;}
  const perms=ALL_PERMS.filter(p=>$('r-perm-'+p)&&$('r-perm-'+p).checked);
  try{await jsonFetch('/api/roots/update',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,path,permissions:perms})});closeModal();await loadPolicy();toast('Root "'+id+'" updated','ok');renderPolicy();}
  catch(e){toast(e.message,'bad');}
}

async function removeRoot(id,onDone){
  confirmAction({title:'Remove policy root',message:'Remove root "'+id+'" from policy?',detail:'This retracts nMCP permissions for that path. Files are not deleted.',confirmText:'Remove root',danger:true,onConfirm:async()=>{
    try{await jsonFetch('/api/roots/remove',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});await loadPolicy();toast('Root "'+id+'" removed','ok');if(onDone)await onDone();else if(S.section==='policy')renderPolicy();}
    catch(e){toast(e.message,'bad');}
  }});
}

/* EXECUTION */
async function renderExecution(){
  $('content').innerHTML=`
<div class="panel" style="overflow:visible">
  <div class="exec-tabs">
    <div class="exec-tab ${S.execTab==='toolpaths'?'active':''}" onclick="switchExecTab('toolpaths')">Tools</div>
    <div class="exec-tab ${S.execTab==='profiles'?'active':''}" onclick="switchExecTab('profiles')">Profiles</div>
    <div class="exec-tab ${S.execTab==='env'?'active':''}" onclick="switchExecTab('env')">Environment</div>
    <div class="exec-tab ${S.execTab==='resolve'?'active':''}" onclick="switchExecTab('resolve')">Resolver</div>
    <div class="exec-tab ${S.execTab==='jobs'?'active':''}" onclick="switchExecTab('jobs')">Jobs</div>
  </div>
  <div class="exec-body" id="exec-body"></div>
</div>`;
  renderExecTab();
}

function switchExecTab(tab){S.execTab=tab;document.querySelectorAll('.exec-tab').forEach(t=>t.classList.toggle('active',t.textContent.toLowerCase().replace(/\s+/g,'')===tab));renderExecTab();}

async function renderExecTab(){
  const el=$('exec-body');if(!el)return;
  if(S.execTab==='toolpaths'){
    const paths=S.policy.tool_paths||{};
    el.innerHTML=`
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><div style="font-size:12px;color:#6b7280">Map tool names to explicit executable paths for the service context.</div><button class="btn primary" onclick="openAddToolPath()">+ Add</button></div>
${Object.keys(paths).length===0?'<div class="empty" style="padding:20px">No tool paths configured</div>':`
<table class="tbl">
  <thead><tr><th>Tool name</th><th>Executable path</th><th style="width:80px">Actions</th></tr></thead>
  <tbody>${Object.entries(paths).map(([k,v])=>`
    <tr><td style="font-weight:500">${esc(k)}</td><td class="mono">${esc(v)}</td>
    <td><div class="actions"><button class="act-btn danger" onclick="removeToolPath('${esc(k)}')">Remove</button></div></td></tr>`).join('')}
  </tbody>
</table>`}`;
  }else if(S.execTab==='profiles'){
    const profiles=S.policy.execution_profiles||{};
    el.innerHTML=`
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><div style="font-size:12px;color:#6b7280">Define PATH prepend, environment variables, and service environment inheritance per profile.</div><button class="btn primary" onclick="openAddProfile()">+ Add profile</button></div>
${Object.keys(profiles).length===0?'<div class="empty" style="padding:20px">No execution profiles configured</div>':`
<table class="tbl">
  <thead><tr><th>Profile</th><th>PATH prepend</th><th>Env vars</th><th>Inherit service env</th><th style="width:60px">Actions</th></tr></thead>
  <tbody>${Object.entries(profiles).map(([k,v])=>`
    <tr><td style="font-weight:500">${esc(k)}${S.policy.default_execution_profile===k?'<span style="font-size:10px;margin-left:6px;padding:1px 6px;background:#dbeafe;color:#1e40af;border-radius:4px">default</span>':''}</td>
    <td class="mono" style="font-size:11px">${(v.path_prepend||[]).join('; ')||'-'}</td>
    <td>${Object.keys(v.env||{}).length} vars</td>
    <td>${v.inherit_service_env?'Yes':'No'}</td>
    <td><button class="act-btn danger" onclick="removeProfile('${esc(k)}')">Remove</button></td></tr>`).join('')}
  </tbody>
</table>`}`;
  }else if(S.execTab==='env'){
    el.innerHTML='<div class="loading"><div class="spinner"></div> Loading environment&hellip;</div>';
    try{
      const data=await jsonFetch('/api/execution/env');
      const env=data.env||{};
      const keys=Object.keys(env).sort();
      el.innerHTML=`<div style="font-size:12px;color:#6b7280;margin-bottom:10px">${keys.length} variables in service execution environment (PATH-relevant subset)</div>
<div class="env-grid">${keys.map(k=>`<div class="env-k">${esc(k)}</div><div class="env-v">${esc(env[k]||'')}</div>`).join('')}</div>`;
    }catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
  }else if(S.execTab==='resolve'){
    el.innerHTML=`
<div style="font-size:12px;color:#6b7280;margin-bottom:14px">Resolve a tool name to its executable path as the service would see it.</div>
<div class="form-row"><label>Tool name</label><input id="resolve-input" placeholder="e.g. cargo" onkeydown="if(event.key==='Enter')runResolve()"></div>
<div class="form-actions"><button class="btn primary" onclick="runResolve()">Resolve</button></div>
<div id="resolve-result" style="margin-top:12px"></div>`;
  }else if(S.execTab==='jobs'){
    renderExecJobs();
  }
}

function renderExecJobs(){
  const el=$('exec-body');
  const rows=S.execJobs.slice().reverse();
  el.innerHTML=`
<div style="display:grid;grid-template-columns:1.2fr .8fr;gap:14px">
  <div>
    <div style="font-size:12px;color:#6b7280;margin-bottom:12px">Start governed commands. Jobs are session-local here and can be polled, tailed, waited, or cancelled.</div>
    <div class="form-row"><label>Working directory</label><input id="job-cwd" placeholder="Leave blank for first policy root"></div>
    <div class="form-row"><label>Program</label><input id="job-program" placeholder="e.g. powershell"></div>
    <div class="form-row"><label>Arguments JSON</label><textarea id="job-args" style="height:70px;font-family:ui-monospace,Consolas,monospace">[]</textarea></div>
    <div class="form-row"><label>Profile</label><input id="job-profile" placeholder="optional execution profile"></div>
    <div class="form-actions"><button class="btn primary" onclick="startExecJob()">Start job</button></div>
  </div>
  <div>
    <div class="section-header" style="margin-bottom:8px"><h3>Recent jobs</h3><button class="btn" onclick="refreshExecJobs()">Refresh</button></div>
    <div id="job-list">${rows.length?rows.map(j=>jobRow(j)).join(''):'<div class="empty" style="padding:18px">No jobs started from this admin session.</div>'}</div>
  </div>
</div>
<pre id="job-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px;min-height:90px"></pre>`;
}
function jobRow(j){return `<div class="health-item" style="align-items:flex-start;gap:8px"><div style="flex:1;min-width:0"><div class="mono" style="font-size:11px;overflow:hidden;text-overflow:ellipsis">${esc(j.job_id)}</div><div style="font-size:12px;margin-top:3px">${esc(j.program||'-')} <span style="color:#6b7280">${esc(j.status||'')}</span></div></div><div class="actions"><button class="act-btn" onclick="pollExecJob('${esc(j.job_id)}','status')">Status</button><button class="act-btn" onclick="pollExecJob('${esc(j.job_id)}','tail')">Tail</button><button class="act-btn" onclick="waitExecJob('${esc(j.job_id)}')">Wait</button><button class="act-btn danger" onclick="cancelExecJob('${esc(j.job_id)}')">Cancel</button></div></div>`;}
async function startExecJob(){
  const cwd=$('job-cwd').value.trim(),program=$('job-program').value.trim(),profile=$('job-profile').value.trim();
  if(!program){toast('Program required','bad');return;}
  let args=[];try{args=JSON.parse($('job-args').value||'-');if(!Array.isArray(args))throw new Error('args must be an array');}catch(e){toast('Args must be a JSON array','bad');return;}
  try{const out=await jsonFetchTimeout('/api/execution/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({cwd,program,args,profile:profile||undefined})},5000);S.execJobs.push({...out,program,args});renderExecJobs();setJobResult(out);toast('Execution job started','ok');}
  catch(e){setJobResult(e);toast(e.message,'bad');}
}
async function pollExecJob(id,kind){try{const url=kind==='tail'?'/api/execution/tail':'/api/execution/status';const out=await jsonFetchTimeout(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({job_id:id,max_bytes:24000})},5000);const idx=S.execJobs.findIndex(j=>j.job_id===id);if(idx>=0)S.execJobs[idx]={...S.execJobs[idx],...out};renderExecJobs();setJobResult(out);}catch(e){setJobResult(e);toast(e.message,'bad');}}
async function waitExecJob(id){try{const out=await jsonFetchTimeout('/api/execution/wait',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({job_id:id,timeout_ms:5000,max_bytes:24000})},7000);const idx=S.execJobs.findIndex(j=>j.job_id===id);if(idx>=0)S.execJobs[idx]={...S.execJobs[idx],...out};renderExecJobs();setJobResult(out);}catch(e){setJobResult(e);toast(e.message,'bad');}}
async function refreshExecJobs(){for(const j of S.execJobs.slice()){await pollExecJob(j.job_id,'status');}}
async function cancelExecJob(id){confirmAction({title:'Cancel execution job',message:'Cancel job '+id+'?',detail:'The process receives a cancellation request. Partial output remains available in the job result.',confirmText:'Cancel job',danger:true,onConfirm:async()=>{try{const out=await jsonFetchTimeout('/api/execution/cancel',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({job_id:id})},6000);const idx=S.execJobs.findIndex(j=>j.job_id===id);if(idx>=0)S.execJobs[idx]={...S.execJobs[idx],...out};renderExecJobs();setJobResult(out);toast('Cancel requested','ok');}catch(e){setJobResult(e);toast(e.message,'bad');}}});}

function openAddToolPath(){
  $('modal-layer').innerHTML=`
<div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-head"><span class="modal-title">Add tool path</span><button class="modal-close" onclick="closeModal()">&times;</button></div>
    <div class="modal-body">
      <div class="form-row"><label>Tool name</label><input id="tp-name" placeholder="e.g. cargo"></div>
      <div class="form-row"><label>Path</label><input id="tp-path" placeholder="e.g. C:\\Users\\...\\cargo.exe"></div>
    </div>
    <div class="modal-foot"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="addToolPath()">Add</button></div>
  </div>
</div>`;
}

async function addToolPath(){
  const name=$('tp-name').value.trim(),path=$('tp-path').value.trim();
  if(!name||!path){toast('Name and path required','bad');return;}
  try{await jsonFetch('/api/execution/tool-paths/upsert',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,path})});closeModal();await loadPolicy();toast('Tool path added','ok');renderExecution();}
  catch(e){toast(e.message,'bad');}
}

async function removeToolPath(name){
  try{await jsonFetch('/api/execution/tool-paths/remove',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name})});await loadPolicy();toast('Tool path removed','ok');renderExecution();}
  catch(e){toast(e.message,'bad');}
}

function openAddProfile(){
  $('modal-layer').innerHTML=`
<div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-head"><span class="modal-title">Add execution profile</span><button class="modal-close" onclick="closeModal()">&times;</button></div>
    <div class="modal-body">
      <div class="form-row"><label>Profile name</label><input id="pr-name" placeholder="e.g. dev"></div>
      <div class="form-row"><label>PATH prepend</label><input id="pr-path" placeholder="C:\\tools;C:\\...  (semicolon-separated)"></div>
      <div class="form-row"><label>Env vars (JSON)</label><textarea id="pr-env" style="height:80px" placeholder='{"RUST_LOG":"info"}'></textarea></div>
      <div style="display:flex;align-items:center;gap:10px;margin-top:8px"><label style="font-size:12px;font-weight:500">Inherit service env</label><input type="checkbox" id="pr-inherit" checked></div>
    </div>
    <div class="modal-foot"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="addProfile()">Add</button></div>
  </div>
</div>`;
}

async function addProfile(){
  const name=$('pr-name').value.trim();
  if(!name){toast('Profile name required','bad');return;}
  const pathPrepend=($('pr-path').value||'').split(';').map(s=>s.trim()).filter(Boolean);
  let env={};
  try{const raw=$('pr-env').value.trim();if(raw)env=JSON.parse(raw);}catch(e){toast('Env vars must be valid JSON','bad');return;}
  const inherit=$('pr-inherit').checked;
  try{await jsonFetch('/api/execution/profiles/upsert',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,profile:{path_prepend:pathPrepend,env,inherit_service_env:inherit}})});closeModal();await loadPolicy();toast('Profile added','ok');renderExecution();}
  catch(e){toast(e.message,'bad');}
}

async function removeProfile(name){
  try{await jsonFetch('/api/execution/profiles/remove',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name})});await loadPolicy();toast('Profile removed','ok');renderExecution();}
  catch(e){toast(e.message,'bad');}
}

async function runResolve(){
  const program=$('resolve-input').value.trim();if(!program)return;
  const el=$('resolve-result');el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{const d=await jsonFetch('/api/execution/resolve',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({program})});
  el.innerHTML=`<div style="padding:12px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;font-family:monospace;font-size:12px;color:#166534">&#10003; ${esc(d.resolved_path||d.path||JSON.stringify(d))}</div>`;}
  catch(e){el.innerHTML=`<div style="padding:12px;background:#fef2f2;border:1px solid #fecaca;border-radius:6px;font-size:12px;color:#dc2626">&#10007; ${esc(e.message)}</div>`;}
}

/* MCP GATEWAY */
async function renderUpstreams(){
  const c=$('content');
  c.innerHTML='<div class="loading"><div class="spinner"></div> Loading&hellip;</div>';
  try{
    const d=await jsonFetchTimeout('/api/upstreams',{},5000);
    const ups=d.upstreams||[];
    const [gwSummarySettled,gwDecisionsSettled]=await Promise.allSettled([jsonFetchTimeout('/api/gateway/catalog/summary',{},5000),jsonFetchTimeout('/api/gateway/decisions/export',{},5000)]);
    const gwSummary=gwSummarySettled.status==='fulfilled'?gwSummarySettled.value:null;
    const gwDecisions=gwDecisionsSettled.status==='fulfilled'?gwDecisionsSettled.value:null;
    const gatewayPairs=obj=>Object.entries(obj||{}).map(([k,v])=>`<div style="display:flex;justify-content:space-between;gap:12px;font-size:12px;line-height:1.7"><span style="color:#6b7280">${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')||'<div style="font-size:12px;color:#9ca3af">No data</div>';
    const gatewayOverview=gwSummary?`
      <div class="panel" style="margin-bottom:14px">
        <div class="panel-head"><span class="panel-title">Catalog summary</span><span class="sb-tag ok">schema v${esc(gwSummary.schema_version)}</span></div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;padding:14px">
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:#f8fafc"><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em">Catalog servers</div><div style="font-size:24px;font-weight:700">${esc(gwSummary.server_count)}</div></div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:#f8fafc"><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em">Decisions</div><div style="font-size:24px;font-weight:700">${esc(gwDecisions&&gwDecisions.decision_count!=null?gwDecisions.decision_count:'--')}</div></div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:#f8fafc"><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em">Registered upstreams</div><div style="font-size:24px;font-weight:700">${esc(ups.length)}</div></div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:#f8fafc"><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em">Default policy</div><div style="font-size:12px;line-height:1.45;color:#374151">${esc(gwSummary.default_policy)}</div></div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;padding:0 14px 14px">
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px"><strong style="font-size:12px">Risk tiers</strong>${gatewayPairs(gwSummary.risk_summary)}</div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px"><strong style="font-size:12px">Sources</strong>${gatewayPairs(gwSummary.source_summary)}</div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px"><strong style="font-size:12px">Profiles</strong>${gatewayPairs(gwSummary.profiles_summary)}</div>
        </div>
      </div>`:'<div class="panel" style="margin-bottom:14px;padding:14px;color:#b45309">Gateway catalog summary is unavailable.</div>';
    // Update sidebar badge.
    const offline=ups.filter(u=>u.status==='offline').length;
    const badge=$('upstream-badge');
    if(offline>0){badge.textContent=offline;badge.style.display='';}else{badge.style.display='none';}
    const statusDot=u=>{
      const color={online:'#22c55e',connecting:'#f59e0b',offline:'#ef4444'}[u.status]||'#9ca3af';
      return `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px;flex-shrink:0"></span>`;
    };
    const rows=ups.map(u=>`
      <tr>
        <td>${statusDot(u)}<strong>${esc(u.id)}</strong></td>
        <td>${esc(u.label||'')}</td>
        <td class="mono">${esc(u.url)}</td>
        <td><span class="sb-tag ${u.status==='online'?'ok':'info'}">${esc(u.status)}</span></td>
        <td>${u.tool_count}</td>
        <td>
          <div class="actions">
            <button class="act-btn primary" onclick="upstreamRefresh('${esc(u.id)}')">Refresh</button>
            <button class="act-btn" onclick="upstreamToggle('${esc(u.id)}',${!u.enabled})">${u.enabled?'Disable':'Enable'}</button>
          </div>
        </td>
      </tr>`).join('');
    c.innerHTML=`
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <h3 style="margin:0;font-size:14px;font-weight:500">MCP Gateway</h3>
        <button class="tb-btn" onclick="openAddUpstream()">+ Add upstream</button>
      </div>
      ${gatewayOverview}
      <div class="panel">
        <div class="panel-head"><span class="panel-title">Upstreams</span><button class="act-btn" onclick="renderGatewayDecisionExport()">View decisions</button></div>
        ${ups.length===0?'<div style="padding:24px;text-align:center;color:#9ca3af;font-size:13px">No upstreams registered. Add a governed Streamable HTTP endpoint, for example http://127.0.0.1:18880.</div>':
        `<table class="tbl">
          <thead><tr><th>ID</th><th>Label</th><th>URL</th><th>Status</th><th>Tools</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`}
      </div>`;
  }catch(e){c.innerHTML=`<div style="padding:20px;color:#dc2626">${esc(e.message)}</div>`;}
}

async function upstreamRefresh(id){
  try{
    await jsonFetch('/api/upstreams/refresh',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});
    toast('Refresh triggered','ok');
    setTimeout(()=>renderUpstreams(),1500);
  }catch(e){toast(e.message,'bad');}
}

async function upstreamToggle(id,enabled){
  try{
    await jsonFetch('/api/upstreams/toggle',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,enabled})});
    toast(enabled?'Upstream enabled':'Upstream disabled','ok');
    renderUpstreams();
  }catch(e){toast(e.message,'bad');}
}

async function renderGatewayDecisionExport(){
  const c=$('content');
  c.innerHTML='<div class="loading"><div class="spinner"></div> Loading gateway decisions&hellip;</div>';
  try{
    const d=await jsonFetch('/api/gateway/decisions/export');
    const rows=(d.decisions||[]).map(x=>`<tr><td><strong>${esc(x.id)}</strong><div style="font-size:11px;color:#6b7280">${x.catalog_known?'catalog known':'custom decision'}</div></td><td>${esc(x.label||'')}</td><td class="mono">${esc(x.url||'')}</td><td><span class="sb-tag ${x.enabled?'ok':'info'}">${x.enabled?'enabled':'disabled'}</span></td><td>${esc((x.profiles||[]).join(', '))}</td><td><div class="actions"><button class="act-btn primary" onclick="openConfigureGatewayDecision('${esc(x.id)}')">Configure</button><button class="act-btn" onclick="gatewayDeactivateDecision('${esc(x.id)}')">Deactivate</button></div></td></tr>`).join('');
    c.innerHTML=`<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><h3 style="margin:0;font-size:14px;font-weight:500">Gateway policy decisions</h3><button class="tb-btn" onclick="renderUpstreams()">Back to gateway</button></div><div class="panel"><div class="panel-head"><span class="panel-title">Policy decisions</span><span class="sb-tag info">${esc(d.decision_count||0)} decisions</span></div>${rows?`<table class="tbl"><thead><tr><th>ID</th><th>Label</th><th>URL</th><th>State</th><th>Profiles</th><th></th></tr></thead><tbody>${rows}</tbody></table>`:'<div style="padding:24px;color:#9ca3af;text-align:center">No gateway decisions exported.</div>'}</div>`;
  }catch(e){c.innerHTML=`<div style="padding:20px;color:#dc2626">${esc(e.message)}</div>`;}
}

async function openConfigureGatewayDecision(id){
  try{
    const d=await jsonFetch('/api/gateway/decisions/export');
    const x=(d.decisions||[]).find(v=>v.id===id)||{id,label:id,url:'',enabled:false,tool_allowlist:null,catalog_known:false,catalog_risk_tier:null};
    const allow=(x.tool_allowlist||[]).join('\n');
    const risk=x.catalog_risk_tier||'Custom';
    const html=`
      <div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
      <div class="modal">
        <div class="modal-head"><span class="modal-title">Configure gateway policy: ${esc(id)}</span><button class="modal-close" onclick="closeModal()">&#x2715;</button></div>
        <div class="modal-body" style="display:flex;flex-direction:column;gap:12px">
          <div style="font-size:12px;color:#6b7280;line-height:1.45">Configure URL, label, allowlist, and enabled state. Enabling registers the upstream with the live router. Disabling retracts any live provider.</div>
          <div style="display:flex;gap:8px"><span class="sb-tag ${x.catalog_known?'ok':'info'}">${x.catalog_known?'catalog known':'custom'}</span><span class="sb-tag info">risk: ${esc(risk)}</span></div>
          <label style="font-size:12px;color:#6b7280">ID</label>
          <input id="gw-cfg-id" class="input" value="${esc(id)}" readonly style="width:100%"/>
          <label style="font-size:12px;color:#6b7280">URL</label>
          <input id="gw-cfg-url" class="input" value="${esc(x.url||'')}" placeholder="http://127.0.0.1:19999" style="width:100%"/>
          <label style="font-size:12px;color:#6b7280">Label</label>
          <input id="gw-cfg-label" class="input" value="${esc(x.label||id)}" style="width:100%"/>
          <label style="font-size:12px;color:#6b7280">Tool allowlist, one tool per line. Leave blank for no allowlist.</label>
          <textarea id="gw-cfg-allow" class="input" style="width:100%;min-height:92px;font-family:monospace">${esc(allow)}</textarea>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px"><input id="gw-cfg-enabled" type="checkbox" ${x.enabled?'checked':''}/> Enable and register live provider</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px"><input id="gw-cfg-force" type="checkbox"/> Force high-risk enablement</label>
        </div>
        <div class="modal-foot">
          <button class="btn" onclick="closeModal()">Cancel</button>
          <button class="btn primary" onclick="submitConfigureGatewayDecision()">Save</button>
        </div>
      </div></div>`;
    $('modal-layer').innerHTML=html;
  }catch(e){toast(e.message,'bad');}
}

async function submitConfigureGatewayDecision(){
  const id=$('gw-cfg-id').value.trim();
  const url=$('gw-cfg-url').value.trim();
  const label=$('gw-cfg-label').value.trim();
  const enabled=$('gw-cfg-enabled').checked;
  const force=$('gw-cfg-force').checked;
  const tools=$('gw-cfg-allow').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  if(!id){toast('ID is required','bad');return;}
  if(enabled&&!url){toast('URL is required before enabling','bad');return;}
  try{
    await jsonFetch('/api/gateway/decisions/configure',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,url,label,enabled,force,tool_allowlist:tools.length?tools:null})});
    closeModal();toast('Gateway decision configured','ok');renderGatewayDecisionExport();
  }catch(e){toast(e.message,'bad');}
}

async function gatewayDeactivateDecision(id){
  confirmAction({title:'Deactivate gateway policy',message:'Deactivate gateway policy '+id+'?',detail:'This disables the decision and retracts any live provider. It does not delete the recorded decision.',confirmText:'Deactivate',danger:true,onConfirm:async()=>{
    try{
      await jsonFetch('/api/gateway/decisions/deactivate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});
      toast('Gateway policy deactivated','ok');
      renderGatewayDecisionExport();
    }catch(e){toast(e.message,'bad');}
  }});
}

function openAddUpstream(){
  const html=`
    <div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
    <div class="modal">
      <div class="modal-head"><span class="modal-title">Add upstream MCP server</span><button class="modal-close" onclick="closeModal()">&#x2715;</button></div>
      <div class="modal-body" style="display:flex;flex-direction:column;gap:12px">
        <div style="font-size:12px;color:#6b7280;line-height:1.45">Register another MCP server so nMCP can surface its tools through the gateway. Good test candidates are another nMCP instance on a different port or any MCP Streamable HTTP endpoint.</div>
        <label style="font-size:12px;color:#6b7280">ID (unique, no spaces)</label>
        <input id="add-up-id" class="input" placeholder="e.g. github" style="width:100%"/>
        <label style="font-size:12px;color:#6b7280">URL</label>
        <input id="add-up-url" class="input" placeholder="http://127.0.0.1:18880" style="width:100%"/>
        <label style="font-size:12px;color:#6b7280">Label (optional)</label>
        <input id="add-up-label" class="input" placeholder="GitHub MCP" style="width:100%"/>
      </div>
      <div class="modal-foot">
        <button class="btn" onclick="closeModal()">Cancel</button>
        <button class="btn primary" onclick="submitAddUpstream()">Add</button>
      </div>
    </div></div>`;
  $('modal-layer').innerHTML=html;
}

async function submitAddUpstream(){
  const id=$('add-up-id').value.trim();
  const url=$('add-up-url').value.trim();
  const label=$('add-up-label').value.trim();
  if(!id||!url){toast('ID and URL are required','bad');return;}
  try{
    await jsonFetch('/api/upstreams/add',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,url,label:label||undefined})});
    closeModal();toast('Upstream added','ok');renderUpstreams();
  }catch(e){toast(e.message,'bad');}
}

/* AUDIT LOG */


/* INSPECTOR / HITL */
async function renderInspector(){
  $('content').style.padding='20px';
  $('content').style.overflow='auto';
  if(!S.inspectorTab)S.inspectorTab='overview';
  $('content').innerHTML=`
<div class="panel" style="overflow:visible">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
    <div><h2 style="margin:0 0 4px">Inspector</h2><div style="color:#6b7280;font-size:12px">Live events, human approval, replay, schema validation, simulation, and latency.</div></div>
    <button class="btn" onclick="renderInspector()">Refresh</button>
  </div>
  <div class="exec-tabs">
    <div class="exec-tab ${S.inspectorTab==='overview'?'active':''}" onclick="switchInspectorTab('overview')">Overview</div>
    <div class="exec-tab ${S.inspectorTab==='live'?'active':''}" onclick="switchInspectorTab('live')">Live events</div>
    <div class="exec-tab ${S.inspectorTab==='hitl'?'active':''}" onclick="switchInspectorTab('hitl')">Human approval</div>
    <div class="exec-tab ${S.inspectorTab==='simulate'?'active':''}" onclick="switchInspectorTab('simulate')">Simulator</div>
    <div class="exec-tab ${S.inspectorTab==='schema'?'active':''}" onclick="switchInspectorTab('schema')">Schema</div>
    <div class="exec-tab ${S.inspectorTab==='latency'?'active':''}" onclick="switchInspectorTab('latency')">Latency</div>
    <div class="exec-tab ${S.inspectorTab==='replay'?'active':''}" onclick="switchInspectorTab('replay')">Replay</div>
  </div>
  <div class="exec-body" id="inspector-body"></div>
</div>`;
  await renderInspectorTab();
}
function switchInspectorTab(tab){S.inspectorTab=tab;renderInspectorTab();document.querySelectorAll('.exec-tab').forEach(t=>t.classList.toggle('active',t.textContent.toLowerCase().replace(/[^a-z]/g,'').startsWith(tab.replace(/[^a-z]/g,''))));}
async function renderInspectorTab(){
  const el=$('inspector-body');if(!el)return;
  if(S.inspectorTab==='overview'){
    el.innerHTML='<div class="loading"><div class="spinner"></div> Loading inspector status&hellip;</div>';
    const [lat,pending]=await Promise.allSettled([jsonFetchTimeout('/api/inspector/latency?limit=20',{},3000),jsonFetchTimeout('/api/hitl/pending',{},3000)]);
    const latency=lat.status==='fulfilled'?(lat.value.entries||[]):[];
    const hitl=pending.status==='fulfilled'?(pending.value.pending||pending.value.items||pending.value.requests||[]):[];
    setHitlBadge(hitl.length);
    el.innerHTML=`<div class="cards"><div class="card"><div class="card-lbl">Latency samples</div><div class="card-val">${latency.length}</div></div><div class="card"><div class="card-lbl">Pending approvals</div><div class="card-val">${hitl.length}</div></div><div class="card"><div class="card-lbl">Live stream</div><div class="card-val">SSE</div></div><div class="card"><div class="card-lbl">Simulator</div><div class="card-val">Governed</div></div></div><div class="empty" style="margin-top:14px;text-align:left">Inspector backends are wired: event stream, replay, simulator, schema validator, latency, cross-agent audit, and human approval.</div>`;
  }else if(S.inspectorTab==='live'){
    el.innerHTML=`<div style="display:flex;justify-content:space-between;margin-bottom:10px"><div style="color:#6b7280;font-size:12px">Connects to <code>/api/inspector/events</code> and shows live audit events after this tab is opened.</div><div><button class="btn" onclick="startInspectorLive()">Connect</button> <button class="btn" onclick="stopInspectorLive()">Disconnect</button></div></div><div id="insp-live-state" class="empty" style="padding:10px;text-align:left">Disconnected</div><table class="tbl"><thead><tr><th>Time</th><th>Action</th><th>Decision</th><th>Summary</th></tr></thead><tbody id="insp-live-rows"></tbody></table>`;
    renderInspectorLiveRows();
  }else if(S.inspectorTab==='hitl'){
    el.innerHTML='<div class="loading"><div class="spinner"></div> Loading HITL queue&hellip;</div>';
    try{const data=await jsonFetchTimeout('/api/hitl/pending',{},3000);const items=data.pending||data.items||data.requests||[];setHitlBadge(items.length);el.innerHTML=`<div style="margin-bottom:10px;color:#6b7280;font-size:12px">Pending human approvals from <code>/api/hitl/pending</code>.</div>${items.length?`<table class="tbl"><thead><tr><th>ID</th><th>Decision context</th><th>Requested</th><th style="width:180px">Actions</th></tr></thead><tbody>${items.map(x=>{const ctx=x.args_for_approval||x.args_redacted||{};const reasons=(x.risk_reasons||[]).join('; ');return `<tr><td class="mono">${esc(x.id||x.request_id||'')}</td><td><div><strong>${esc(x.tool||'-')}</strong> ${esc(reasons||x.summary||x.reason||'requires approval')}</div><pre class="mono" style="white-space:pre-wrap;margin:6px 0 0;background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;padding:8px;max-height:220px;overflow:auto">${esc(JSON.stringify(ctx,null,2))}</pre></td><td>${esc(x.timestamp||x.created_at||'')}</td><td><button class="act-btn" onclick="hitlApprove('${esc(x.id||x.request_id||'')}')">Approve</button> <button class="act-btn danger" onclick="hitlDeny('${esc(x.id||x.request_id||'')}')">Deny</button></td></tr>`}).join('')}</tbody></table>`:'<div class="empty">No pending HITL requests.</div>'}`;}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
  }else if(S.inspectorTab==='simulate'){
    el.innerHTML=`<div style="color:#6b7280;font-size:12px;margin-bottom:10px">Dispatch a governed simulation through <code>/api/inspector/simulate</code>. This should exercise policy/routing without hiding backend decisions.</div><div class="form-row"><label>Tool name</label><input id="sim-tool" placeholder="e.g. list_files"></div><div class="form-row"><label>Params JSON</label><textarea id="sim-params" style="min-height:120px;font-family:ui-monospace,Consolas,monospace">{}</textarea></div><div class="form-actions"><button class="btn primary" onclick="runInspectorSimulate()">Run simulation</button></div><pre id="sim-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px"></pre>`;
  }else if(S.inspectorTab==='schema'){
    el.innerHTML=`<div style="color:#6b7280;font-size:12px;margin-bottom:10px">Validate a tool schema with <code>/api/inspector/validate-schema</code>.</div><textarea id="schema-json" style="width:100%;min-height:240px;font-family:ui-monospace,Consolas,monospace">{"name":"example","inputSchema":{"type":"object","properties":{}}}</textarea><div class="form-actions"><button class="btn primary" onclick="runSchemaValidate()">Validate schema</button></div><pre id="schema-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px"></pre>`;
  }else if(S.inspectorTab==='latency'){
    el.innerHTML='<div class="loading"><div class="spinner"></div> Loading latency timeline&hellip;</div>';
    try{const data=await jsonFetchTimeout('/api/inspector/latency?limit=200',{},5000);const entries=data.entries||[];el.innerHTML=`<div style="margin-bottom:10px;color:#6b7280;font-size:12px">Latency timeline from audit data.</div>${entries.length?`<table class="tbl"><thead><tr><th>Time</th><th>Action</th><th>Duration</th><th>Decision</th></tr></thead><tbody>${entries.map(x=>`<tr><td>${esc(x.timestamp||x.time||'')}</td><td>${esc(x.action||'')}</td><td>${esc(x.duration_ms||'')}</td><td>${esc(x.decision||'')}</td></tr>`).join('')}</tbody></table>`:'<div class="empty">No latency entries yet.</div>'}`;}catch(e){el.innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
  }else if(S.inspectorTab==='replay'){
    el.innerHTML=`<div class="form-row"><label>Session ID</label><input id="replay-session" placeholder="session/call/correlation id"></div><div class="form-actions"><button class="btn primary" onclick="runReplay()">Replay session</button></div><pre id="replay-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px"></pre><hr style="margin:18px 0"><div class="form-row"><label>Agent IDs</label><input id="agent-ids" placeholder="agent-a,agent-b"></div><div class="form-actions"><button class="btn" onclick="runAgentAudit()">Load cross-agent audit</button></div><pre id="agent-result" class="mono" style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-top:12px"></pre>`;
  }
}
function setHitlBadge(n){const b=$('hitl-badge');if(!b)return;b.textContent=n;b.style.display=n>0?'inline-flex':'none';}
async function startInspectorLive(){
  stopInspectorLive();
  const state=$('insp-live-state');
  const ctl=new AbortController();
  S.inspectorEventSource=ctl;
  if(state)state.textContent='Connecting...';
  let reader=null;
  try{
    const res=await fetch('/api/inspector/events',adminAuthHeaders({headers:{accept:'text/event-stream'},signal:ctl.signal}));
    if(!res.ok){let msg=res.statusText;try{const body=await res.json();msg=body.message||body.error||msg;}catch(_){}throw new Error(msg);}
    if(state)state.textContent='Connected';
    reader=res.body.getReader();
    const decoder=new TextDecoder();
    let buf='';
    while(S.inspectorEventSource===ctl){
      const {value,done}=await reader.read();
      if(done)break;
      buf+=decoder.decode(value,{stream:true});
      const frames=buf.split(/\r?\n\r?\n/);buf=frames.pop()||'';
      for(const frame of frames){
        const data=frame.split(/\r?\n/).filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n');
        if(!data)continue;
        try{S.inspectorLive.unshift(JSON.parse(data));S.inspectorLive=S.inspectorLive.slice(0,200);renderInspectorLiveRows();}catch(_){ }
      }
    }
    if(S.inspectorEventSource===ctl&&state)state.textContent='Disconnected';
  }catch(e){
    if(ctl.signal.aborted||isAbortError(e)){if(S.inspectorEventSource===ctl)S.inspectorEventSource=null;if(state)state.textContent='Disconnected';return;}
    if(S.inspectorEventSource===ctl){S.inspectorEventSource=null;if(state)state.textContent='Disconnected: '+e.message;toast(e.message,'bad');}
  }finally{
    if(reader){try{reader.releaseLock();}catch(_){}}
  }
}
function stopInspectorLive(){if(S.inspectorEventSource){S.inspectorEventSource.abort();S.inspectorEventSource=null;}const state=$('insp-live-state');if(state)state.textContent='Disconnected';}
window.addEventListener('beforeunload',stopInspectorLive);
function renderInspectorLiveRows(){const body=$('insp-live-rows');if(!body)return;body.innerHTML=(S.inspectorLive||[]).map(e=>`<tr><td>${esc(e.timestamp||'')}</td><td>${esc(e.action||'')}</td><td>${esc(e.decision||'')}</td><td>${esc(e.summary||JSON.stringify(e))}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">No live events yet.</td></tr>';}
async function hitlApprove(id){if(!id)return;try{await jsonFetch('/api/hitl/'+encodeURIComponent(id)+'/approve',{method:'POST'});toast('Approved','ok');renderInspectorTab();}catch(e){toast(e.message,'bad');}}
async function hitlDeny(id){if(!id)return;try{await jsonFetch('/api/hitl/'+encodeURIComponent(id)+'/deny',{method:'POST'});toast('Denied','ok');renderInspectorTab();}catch(e){toast(e.message,'bad');}}
async function runInspectorSimulate(){try{const tool=$('sim-tool').value.trim();const params=JSON.parse($('sim-params').value||'-');const out=await jsonFetchTimeout('/api/inspector/simulate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({tool,params})},5000);$('sim-result').textContent=JSON.stringify(out,null,2);}catch(e){$('sim-result').textContent=e.message;}}
async function runSchemaValidate(){try{const body=JSON.parse($('schema-json').value||'-');const out=await jsonFetchTimeout('/api/inspector/validate-schema',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)},5000);$('schema-result').textContent=JSON.stringify(out,null,2);}catch(e){$('schema-result').textContent=e.message;}}
async function runReplay(){try{const id=$('replay-session').value.trim();const out=await jsonFetchTimeout('/api/inspector/replay?session_id='+encodeURIComponent(id),{},5000);$('replay-result').textContent=JSON.stringify(out,null,2);}catch(e){$('replay-result').textContent=e.message;}}
async function runAgentAudit(){try{const ids=$('agent-ids').value.trim();const out=await jsonFetchTimeout('/api/inspector/audit/agents?ids='+encodeURIComponent(ids)+'&limit=200',{},5000);$('agent-result').textContent=JSON.stringify(out,null,2);}catch(e){$('agent-result').textContent=e.message;}}

async function renderAudit(){
  $('content').style.padding='0';
  $('content').style.overflow='hidden';
  if(!S.auditViewer){S.auditViewer={events:[],filtered:[],selectedIndex:0,category:'Administrative Events',tab:'general',detailMode:'friendly',query:'',level:'all'};}
  $('content').innerHTML=avShell();
  avBind();
  await avLoad();
}
function avShell(){return `<div class="av-shell">
  <aside class="av-tree"><div class="av-tree-title">Audit Viewer</div><div class="av-tree-node active" data-cat="Administrative Events"><span>All events</span><span class="count" id="av-count-all">0</span></div><div class="av-tree-node child" data-cat="File System"><span class="av-code">FS</span><span>File System</span></div><div class="av-tree-node child" data-cat="Execution"><span class="av-code">EX</span><span>Execution</span></div><div class="av-tree-node child" data-cat="Policy"><span class="av-code">POL</span><span>Policy</span></div><div class="av-tree-node child" data-cat="Publish / Git"><span class="av-code">PUB</span><span>Publish / Git</span></div><div class="av-tree-node child" data-cat="MCP Gateway"><span class="av-code">GW</span><span>MCP Gateway</span></div><div class="av-tree-node child" data-cat="Security / ABAC"><span class="av-code">SEC</span><span>Security / ABAC</span></div><div class="av-tree-node child" data-cat="HITL"><span class="av-code">HITL</span><span>Human approval</span></div><div class="av-tree-node child" data-cat="Diagnostics"><span class="av-code">DIAG</span><span>Diagnostics</span></div></aside>
  <section class="av-main"><div class="av-titlebar"><h2 id="av-title">Administrative Events</h2><span class="muted" id="av-source">Source: -</span><span class="grow"></span><button class="btn" onclick="avLoad()">Refresh</button></div><div class="av-filterbar"><input id="av-search" placeholder="Find path, action, source, summary..."/><select id="av-level"><option value="all">All levels</option><option value="Information">Information</option><option value="Warning">Warning</option><option value="Error">Error</option></select><button class="btn" onclick="avExportJson()">Export</button></div><div class="av-table-wrap"><table class="av-table"><thead><tr><th style="width:130px">Level</th><th style="width:190px">Time</th><th>Source</th><th style="width:90px">Event ID</th><th style="width:170px">Category</th></tr></thead><tbody id="av-rows"><tr><td colspan="5"><div class="av-empty">Loading&hellip;</div></td></tr></tbody></table></div><div class="av-preview"><div class="av-preview-head"><strong id="av-preview-title">Event</strong><button class="av-close" onclick="S.auditViewer.selectedIndex=-1;avRenderPreview()">â€”</button></div><div class="av-tabs"><div class="av-tab active" data-tab="general">General</div><div class="av-tab" data-tab="details">Details</div></div><div class="av-pane" id="av-pane"></div><div class="av-footer"><div id="av-footer-left">Log Name: nMCP</div><div id="av-footer-right">Ready</div></div></div></section>
  <aside class="av-actions"><div class="av-action-section"><div class="av-action-title">Administrative Events</div><div class="av-action" onclick="avLoad()">Refresh</div><div class="av-action" onclick="$('av-search').focus()">Find</div><div class="av-action" onclick="avExportJson()">Export JSON</div><div class="av-action" onclick="avCopySelected()">Copy</div></div><div class="av-action-section"><div class="av-action-title" id="av-action-selected">Event</div><div class="av-action" onclick="avShowProperties()">Properties</div><div class="av-action" onclick="avCopySelected()">Copy</div><div class="av-action" onclick="avLoad()">Refresh</div></div></aside>
</div>`;}
function avBind(){
  document.querySelectorAll('.av-tree-node[data-cat]').forEach(n=>n.onclick=()=>{S.auditViewer.category=n.dataset.cat;S.auditViewer.selectedIndex=0;document.querySelectorAll('.av-tree-node').forEach(x=>x.classList.remove('active'));n.classList.add('active');avApplyFilters();});
  $('av-search').value=S.auditViewer.query||'';$('av-level').value=S.auditViewer.level||'all';
  $('av-search').oninput=e=>{S.auditViewer.query=e.target.value;avApplyFilters();};
  $('av-level').onchange=e=>{S.auditViewer.level=e.target.value;avApplyFilters();};
  document.querySelectorAll('.av-tab').forEach(t=>t.onclick=()=>{S.auditViewer.tab=t.dataset.tab;document.querySelectorAll('.av-tab').forEach(x=>x.classList.remove('active'));t.classList.add('active');avRenderPreview();});
}
async function avLoad(){
  const rows=$('av-rows');if(rows)rows.innerHTML='<tr><td colspan="5"><div class="av-empty">Loading&hellip;</div></td></tr>';
  try{const data=await jsonFetch('/api/audit/recent?limit=1000');S.auditViewer.path=data.path||'';S.auditViewer.events=(data.events||[]).slice().map((e,i)=>avNormalize(e,i));$('av-source').textContent='Source: '+(S.auditViewer.path||'audit jsonl');$('av-count-all').textContent=S.auditViewer.events.length;avApplyFilters();}
  catch(e){rows.innerHTML='<tr><td colspan="5"><div class="av-empty">'+esc(e.message)+'</div></td></tr>';}
}
function avNormalize(e,i){
  const action=e.action||e.tool||'audit';const summaryData=avSummaryData(e);const category=avCategory(action,e,summaryData);const level=avLevel(e);const eventId=avEventId(action,level,e,summaryData);const source=avSource(action,e,summaryData);const meta=avDenialMetadata(e);const publish=avPublishData(e,summaryData);
  return {raw:e,index:i,record_id:i+1,id:e.id||'',level,source,event_id:eventId,task_category:category,time:e.timestamp||e.time_created||'',action,decision:e.decision||'',summary:e.summary||'',path:e.path||e.normalized_path||publish.repo_root||'',duration_ms:e.duration_ms||publish.duration_ms,client:e.client||'',agent_id:e.agent_id||'',call_id:e.call_id||'',upstream_id:e.upstream_id||'',error_kind:meta.error_kind||'',remediation:meta.remediation||'',message:meta.message||'',provider:meta.provider||e.provider||'',error_source:meta.source||e.source||'',policy_context:meta.policy||e.policy||e.root||'',publish,summary_data:summaryData,category};
}
function avSummaryData(e){if(typeof e.summary==='string'&&e.summary.trim().startsWith('{')){try{return JSON.parse(e.summary);}catch(_){}}return {};}
function avDenialMetadata(e){return denialMetaFrom(e);}
function avPublishData(e,summaryData){const s=summaryData||avSummaryData(e);const action=String(e.action||e.tool||s.action||'').toLowerCase();const isPublish=action.includes('git_publish')||String(s.action||'').toLowerCase()==='git_publish';if(!isPublish)return {};return {repo_root:s.repo_root||e.repo_root||'',branch:s.branch||e.branch||'',head:s.head||e.head||'',dry_run:s.dry_run ?? e.dry_run,exit_code:s.exit_code ?? e.exit_code,target_redacted:s.target_redacted||e.target_redacted||'',duration_ms:s.duration_ms ?? e.duration_ms};}
function avCategory(action,e,summaryData){action=String(action||'').toLowerCase();const publish=avPublishData(e,summaryData);if(action.includes('git_publish')||publish.repo_root||publish.target_redacted)return 'Publish / Git';if(action.includes('execute'))return 'Execution';if(action.includes('policy')||action.includes('root'))return 'Policy';if(action.includes('upstream')||action.includes('gateway')||e.upstream_id)return 'MCP Gateway';if(action.includes('hitl'))return 'HITL';if(action.includes('abac')||action.includes('deny')||action.includes('reject'))return 'Security / ABAC';if(action.includes('doctor')||action.includes('diagnostic'))return 'Diagnostics';if(action.includes('file')||action.includes('read')||action.includes('write')||action.includes('move')||action.includes('rename')||action.includes('backup')||e.path||e.normalized_path)return 'File System';return 'Administrative Events';}
function avLevel(e){const d=String(e.decision||'').toLowerCase();const s=String(e.summary||'').toLowerCase();if(d.includes('deny')||d.includes('reject')||s.includes('error')||s.includes('failed'))return 'Error';if(d.includes('pending')||d.includes('hitl')||s.includes('warning'))return 'Warning';return 'Information';}
function avSource(action,e,summaryData){const c=avCategory(action,e,summaryData);if(c==='File System')return 'nMCP-FS';if(c==='Execution')return 'nMCP-Exec';if(c==='Publish / Git')return 'nMCP-Publish';if(c==='MCP Gateway')return 'nMCP-Gateway';if(c==='HITL')return 'nMCP-HITL';if(c==='Security / ABAC')return 'nMCP-Security';if(c==='Policy')return 'nMCP-Policy';return 'nMCP';}
function avEventId(action,level,e,summaryData){const c=avCategory(action,e,summaryData);if(level==='Error')return c==='Execution'?1302:c==='File System'?1201:c==='Publish / Git'?1601:1101;if(c==='File System')return 1200;if(c==='Execution')return String(action).includes('completed')?1301:1300;if(c==='Policy')return 1400;if(c==='MCP Gateway')return 1500;if(c==='Publish / Git')return 1600;if(c==='Security / ABAC')return 1700;if(c==='HITL')return 1750;if(c==='Diagnostics')return 1900;return 1100;}
function avApplyFilters(){const q=(S.auditViewer.query||'').toLowerCase(),lvl=S.auditViewer.level||'-',cat=S.auditViewer.category||'Administrative Events';$('av-title').textContent=cat;S.auditViewer.filtered=S.auditViewer.events.filter(e=>{const inCat=cat==='Administrative Events'||e.category===cat;const inLevel=lvl==='all'||e.level===lvl;const hay=JSON.stringify(e.raw).toLowerCase()+' '+Object.values(e).join(' ').toLowerCase();return inCat&&inLevel&&(!q||hay.includes(q));});if(S.auditViewer.selectedIndex>=S.auditViewer.filtered.length)S.auditViewer.selectedIndex=0;avRenderRows();setTimeout(()=>{const r=document.querySelector('.av-row.selected');if(r)r.scrollIntoView({block:'nearest'});},0);avRenderPreview();}
function avRenderRows(){const rows=$('av-rows'),items=S.auditViewer.filtered;if(!items.length){rows.innerHTML='<tr><td colspan="5"><div class="av-empty">No events match this Audit Viewer category or filter.</div></td></tr>';return;}rows.innerHTML=items.map((e,i)=>`<tr class="av-row ${i===S.auditViewer.selectedIndex?'selected':''}" data-i="${i}"><td><span class="av-level"><span class="av-dot ${e.level==='Error'?'av-error':e.level==='Warning'?'av-warn':'av-info'}">${e.level==='Information'?'i':'!'}</span>${esc(e.level)}</span></td><td>${esc(avTime(e.time))}</td><td>${esc(e.source)}</td><td>${esc(e.event_id)}</td><td>${esc(e.task_category)}</td></tr>`).join('');document.querySelectorAll('.av-row').forEach(r=>{r.onclick=()=>{S.auditViewer.selectedIndex=Number(r.dataset.i);avRenderRows();avRenderPreview();};r.ondblclick=()=>avShowProperties();});}
function avRenderPreview(){const e=S.auditViewer.filtered[S.auditViewer.selectedIndex];if(!e){$('av-preview-title').textContent='No event selected';$('av-pane').innerHTML='<div class="av-empty">Select an event.</div>';$('av-action-selected').textContent='No event selected';$('av-footer-right').textContent='Ready';return;}$('av-preview-title').textContent=`Event ${e.event_id}, ${e.source}`;$('av-action-selected').textContent=`Event ${e.event_id}, ${e.source}`;$('av-footer-left').textContent=`Log Name: nMCP`; $('av-footer-right').textContent=`Logged: ${avTime(e.time)}`;document.querySelectorAll('.av-tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===S.auditViewer.tab));if(S.auditViewer.tab==='details')avRenderDetails(e);else avRenderGeneral(e);}
function avRenderGeneral(e){$('av-pane').innerHTML=`<div class="av-general-msg">${esc(avMessage(e))}</div>${avPublishBlock(e)}${avDenialBlock(e)}<div class="av-meta"><div class="label">Log Name:</div><div class="value">nMCP</div><div class="label">Source:</div><div class="value">${esc(e.source)}</div><div class="label">Event ID:</div><div class="value">${esc(e.event_id)}</div><div class="label">Category:</div><div class="value">${esc(e.task_category)}</div><div class="label">Level:</div><div class="value">${esc(e.level)}</div><div class="label">User:</div><div class="value">${esc(e.client||'nMCP')}</div><div class="label">Computer:</div><div class="value">${esc(location.hostname||'localhost')}</div><div class="label">Correlation ID:</div><div class="value">${esc(e.call_id||e.id||'-')}</div></div>`;}
function avPublishBlock(e){const p=e.publish||{};if(!p.repo_root&&!p.target_redacted&&!p.branch&&!p.head&&p.dry_run==null&&p.exit_code==null)return '';return `<div class="av-meta av-publish-meta" style="margin-bottom:10px"><div class="label">Publish target:</div><div class="value">${esc(p.target_redacted||'-')}</div><div class="label">Repository root:</div><div class="value">${esc(p.repo_root||'-')}</div><div class="label">Branch:</div><div class="value">${esc(p.branch||'-')}</div><div class="label">HEAD:</div><div class="value mono">${esc(p.head||'-')}</div><div class="label">Dry run:</div><div class="value">${p.dry_run===true?'true':p.dry_run===false?'false':'-'}</div><div class="label">Exit code:</div><div class="value">${p.exit_code==null?'-':esc(p.exit_code)}</div><div class="label">Duration:</div><div class="value">${p.duration_ms==null?'-':esc(p.duration_ms)+'ms'}</div></div>`;}
function avDenialBlock(e){return denialMetaBlock({error_kind:e.error_kind,message:e.message,remediation:e.remediation,provider:e.provider,source:e.error_source,policy:e.policy_context});}
function avRenderDetails(e){$('av-pane').innerHTML=`<div class="av-detail-toolbar"><label class="av-radio"><input type="radio" name="avmode" value="friendly" ${S.auditViewer.detailMode==='friendly'?'checked':''}> Friendly View</label><label class="av-radio"><input type="radio" name="avmode" value="json" ${S.auditViewer.detailMode==='json'?'checked':''}> JSON View</label></div><div id="av-detail-body"></div>`;document.querySelectorAll('input[name="avmode"]').forEach(r=>r.onchange=()=>{S.auditViewer.detailMode=r.value;avRenderDetails(e);});const b=$('av-detail-body');if(S.auditViewer.detailMode==='json'){b.innerHTML=`<pre class="av-json">${esc(JSON.stringify(e.raw,null,2))}</pre>`;return;}b.innerHTML=`<div class="av-friendly"><div>- <strong>System</strong></div><div class="av-treeblock av-kv"><div class="av-k">Provider</div><div>${esc(e.source)}</div><div class="av-k">EventID</div><div>${esc(e.event_id)}</div><div class="av-k">Level</div><div>${esc(e.level)}</div><div class="av-k">TimeCreated</div><div>${esc(e.time)}</div><div class="av-k">RecordID</div><div>${esc(e.record_id)}</div><div class="av-k">Correlation</div><div>${esc(e.call_id||e.id||'-')}</div></div><div>- <strong>EventData</strong></div><div class="av-treeblock av-kv">${avEventDataRows(e)}</div></div>`;}
function avEventDataRows(e){const p=e.publish||{};const data={action:e.action,decision:e.decision,error_kind:e.error_kind,message:e.message,remediation:e.remediation,provider:e.provider,source:e.error_source,policy_context:typeof e.policy_context==='string'?e.policy_context:(e.policy_context?JSON.stringify(e.policy_context):''),publish_target:p.target_redacted,repo_root:p.repo_root,branch:p.branch,head:p.head,dry_run:p.dry_run,exit_code:p.exit_code,summary:e.summary,path:e.path,duration_ms:e.duration_ms,client:e.client,agent_id:e.agent_id,upstream_id:e.upstream_id};return Object.entries(data).filter(([k,v])=>v!=null&&v!=='').map(([k,v])=>`<div class="av-k">${esc(k)}</div><div>${esc(String(v))}</div>`).join('');}
function avMessage(e){const p=e.publish||{};if(e.category==='Publish / Git'){let msg=`nMCP recorded governed git publish`;if(e.decision)msg+=` with decision ${e.decision}`;if(p.branch)msg+=` to ${p.branch}`;if(p.target_redacted)msg+=` via ${p.target_redacted}`;if(p.dry_run===true)msg+=` (dry run)`;if(p.exit_code!=null)msg+=` with exit code ${p.exit_code}`;return msg;}let msg=`nMCP recorded ${e.action}`;if(e.decision)msg+=` with decision ${e.decision}`;if(e.path)msg+=` for ${e.path}`;if(e.summary)msg+=`.\n\n${e.summary}`;return msg;}
function avTime(t){if(!t)return 'â€';const d=new Date(t);if(isNaN(d.getTime()))return t;return d.toLocaleString();}
function avShowProperties(){const e=S.auditViewer.filtered[S.auditViewer.selectedIndex];if(!e)return;S.auditViewer.tab='general';avRenderPreview();const pane=$('av-pane');if(pane)pane.scrollTop=0;}
async function avCopySelected(){const e=S.auditViewer.filtered[S.auditViewer.selectedIndex];if(!e)return;const text=`Event ${e.event_id}, ${e.source}\n${avMessage(e)}\n\n${JSON.stringify(e.raw,null,2)}`;try{await navigator.clipboard.writeText(text);toast('Event copied','ok');}catch(err){toast('Copy failed','bad');}}
function avExportJson(){const blob=new Blob([JSON.stringify(S.auditViewer.filtered.map(e=>e.raw),null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='nmcp-audit-viewer-export.json';a.click();URL.revokeObjectURL(a.href);}

async function renderDiagnostics(){
  $('content').innerHTML='<div class="loading"><div class="spinner"></div> Loading diagnostics&hellip;</div>';
  try{
    const [runtime,doctor,latencyHistory,logTopology,healthy,ready]=await Promise.all([
      jsonFetchTimeout('/api/diagnostics/runtime',{},5000),
      jsonFetchTimeout('/api/doctor',{},5000),
      jsonFetchTimeout('/api/diagnostics/latency-history?limit=200',{},5000),
      jsonFetchTimeout('/api/diagnostics/log-topology',{},5000),
      fetch('/healthz').then(r=>r.ok).catch(()=>false),
      fetch('/readyz').then(r=>r.ok).catch(()=>false),
    ]);
    const checks=doctor.checks||[];
    const pass=checks.filter(c=>c.ok),fail=checks.filter(c=>!c.ok);
    const t=runtime.transport||{},a=runtime.audit||{},ex=runtime.execution||{},pol=runtime.policy||{},doc=runtime.doctor||{},lat=runtime.latency||{},hist=latencyHistory||{},logs=logTopology||{},buckets=hist.buckets||[],slowest=hist.slowest||[];
    $('content').innerHTML=`
<div class="section-header" style="margin-bottom:8px"><h3>Runtime</h3><button class="btn" onclick="renderDiagnostics()">Refresh</button></div>
<div class="grid-cards" style="margin-bottom:14px">
  <div class="card"><div class="card-lbl">Runtime</div><div class="card-val ${runtime.ok?'ok':'bad'}">${runtime.ok?'Ready':'Degraded'}</div><div class="card-sub">${esc(runtime.generated_at||'')}</div></div>
  <div class="card"><div class="card-lbl">Active sessions</div><div class="card-val">${num(t.active_sessions)}</div><div class="card-sub">max ${num(t.max_sessions)}</div></div>
  <div class="card"><div class="card-lbl">Job watchers</div><div class="card-val">${num(t.active_job_watchers)}</div><div class="card-sub">transport core ${t.core_available?'available':'unavailable'}</div></div>
  <div class="card"><div class="card-lbl">Audit subscribers</div><div class="card-val">${num(a.subscriber_count)}</div><div class="card-sub">Event Log mirror ${a.windows_event_log_mirror_enabled?'on':'off'}</div></div>
</div>
<div class="grid-cards" style="margin-bottom:14px">
  <div class="card"><div class="card-lbl">Latency samples</div><div class="card-val ${lat.ok===false?'bad':''}">${num(lat.sample_count)}</div><div class="card-sub">measured ${num(lat.measured_count)} of ${num(lat.sample_limit)}</div></div>
  <div class="card"><div class="card-lbl">Latest latency</div><div class="card-val">${lat.latest_duration_ms==null?'--':num(lat.latest_duration_ms)+'ms'}</div><div class="card-sub">${esc(lat.latest_action||'no timed action')}</div></div>
  <div class="card"><div class="card-lbl">Max latency</div><div class="card-val">${lat.max_duration_ms==null?'--':num(lat.max_duration_ms)+'ms'}</div><div class="card-sub">average ${lat.average_duration_ms==null?'--':num(lat.average_duration_ms)+'ms'}</div></div>
  <div class="card"><div class="card-lbl">Latency source</div><div class="card-val ${lat.ok===false?'bad':'ok'}">${lat.ok===false?'Error':'Audit'}</div><div class="card-sub">${lat.ok===false?esc(lat.error||'unavailable'):esc(lat.latest_decision||'ready')}</div></div>
  <div class="card"><div class="card-lbl">Timeout-like events</div><div class="card-val ${num(hist.timeout_like_count)>0?'bad':'ok'}">${num(hist.timeout_like_count)}</div><div class="card-sub">history ${num(hist.sample_count)} calls</div></div>
</div>
<div class="panel" style="margin-bottom:14px"><div class="panel-head"><div class="panel-title">Latency history</div><button class="panel-action" onclick="openAdminJson('/api/diagnostics/latency-history?limit=200','nmcp-latency-history.json')">JSON</button></div><div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px;padding:12px 14px"><div><div class="diag-lbl" style="margin-bottom:8px">Duration buckets</div>${diagLatencyBuckets(buckets,hist.measured_count)}</div><div><div class="diag-lbl" style="margin-bottom:8px">Slowest calls</div>${diagSlowestRows(slowest)}</div></div></div>
<div class="panel" style="margin-bottom:14px"><div class="panel-head"><div class="panel-title">Log topology</div><button class="panel-action" onclick="openAdminJson('/api/diagnostics/log-topology','nmcp-log-topology.json')">JSON</button></div><div style="padding:12px 14px;display:grid;gap:8px;font-size:12px"><div><strong>Canonical logs:</strong> <code>${esc(logs.canonical?.logs_dir||'')}</code></div><div><strong>Audit JSONL:</strong> <code>${esc(logs.active?.policy_audit_path||'')}</code></div><div><strong>Execution jobs:</strong> <code>${esc(logs.active?.effective_exec_state_dir||'')}</code></div><div><strong>Event Log:</strong> ${logs.audit_logs&&logs.audit_logs[1]&&logs.audit_logs[1].enabled?'enabled':'off'} / ${esc(logs.audit_logs&&logs.audit_logs[1]?logs.audit_logs[1].source:'nMCP')}</div></div></div>
<div class="row2">
  <div>
    <div class="section-header" style="margin-bottom:8px"><h3>Doctor checks</h3><span style="font-size:12px;color:#6b7280">${num(doc.failures)} failing of ${num(doc.checks)}</span></div>
    <div style="display:flex;flex-direction:column;gap:6px">
      ${checks.map(c=>`
        <div class="diag-item ${c.ok?'ok':'warn'}">
          <div class="diag-icon">${c.ok?'&#10003;':'&#9888;'}</div>
          <div class="diag-body">
            <div class="diag-lbl">${esc(c.id||c.name||c.check||'check')}</div>
            ${c.message?`<div class="diag-detail">${esc(c.message)}</div>`:''}
            ${c.remediation?`<div class="diag-detail" style="color:#ca8a04">&#9432; ${esc(c.remediation)}</div>`:''}
          </div>
        </div>`).join('')}
    </div>
  </div>
  <div style="display:flex;flex-direction:column;gap:14px">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">Endpoints</div></div>
      ${[
        {n:'/healthz',url:'/healthz',ok:healthy},
        {n:'/readyz',url:'/readyz',ok:ready},
        {n:'/metrics',url:'/metrics',ok:true},
        {n:'/api/doctor',url:'/api/doctor',ok:true},
        {n:'/api/diagnostics/runtime',url:'/api/diagnostics/runtime',ok:runtime.ok},
        {n:'/api/diagnostics/latency-history',url:'/api/diagnostics/latency-history?limit=200',ok:latencyHistory.ok!==false},
        {n:'/api/diagnostics/log-topology',url:'/api/diagnostics/log-topology',ok:logTopology.ok!==false},
        {n:'/api/support-bundle',url:'/api/support-bundle',ok:true},
      ].map(ep=>`<div class="health-item"><button class="link-btn mono" onclick="openAdminJson('${esc(ep.url)}','${esc(ep.n.replaceAll('/','_').replace(/^_/,''))}.json')">${esc(ep.n)}</button><div class="health-dot ${ep.ok?'ok':'bad'}"></div></div>`).join('')}
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">Configuration counts</div></div>
      <div style="padding:12px 14px;display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <div class="card" style="margin:0"><div class="card-lbl">Roots</div><div class="card-val">${num(pol.roots)}</div></div>
        <div class="card" style="margin:0"><div class="card-lbl">Profiles</div><div class="card-val">${num(ex.profiles)}</div></div>
        <div class="card" style="margin:0"><div class="card-lbl">Tools</div><div class="card-val">${num(ex.tool_paths)}</div></div>
        <div class="card" style="margin:0"><div class="card-lbl">Failures</div><div class="card-val ${fail.length>0?'bad':'ok'}">${fail.length}</div></div>
      </div>
      <div style="padding:0 14px 12px;font-size:11px;color:#6b7280;font-family:monospace;word-break:break-all">${esc(ex.exec_state_dir||'')}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">Support bundle</div></div>
      <div style="padding:12px 14px;font-size:12px;color:#6b7280">Download a redacted support bundle. Sensitive paths and values are removed.</div>
      <div style="padding:0 14px 12px"><button class="btn primary" onclick="downloadAdminApi('/api/support-bundle','nmcp-support-bundle.json')" style="display:inline-flex;text-decoration:none;align-items:center;gap:6px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg> Download bundle</button></div>
    </div>
  </div>
</div>`;
  }catch(e){$('content').innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
}

/* SETTINGS */
async function renderSettings(){
  const pol=JSON.stringify(S.policy,null,2);
  $('content').innerHTML=`
<div class="section-header"><h3>Admin authentication</h3></div>
<div class="panel" style="padding:14px;margin-bottom:14px">
  <div style="font-size:12px;color:#6b7280;margin-bottom:10px">API calls require <code>NMCP_ADMIN_TOKEN</code>. Session storage is default; Remember stores it in this browser profile.</div>
  <div style="display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;align-items:center">
    <input id="admin-token-input" type="password" placeholder="Admin token" value="${esc(S.adminToken||'')}" style="font-family:monospace">
    <label style="font-size:12px;color:#6b7280;display:flex;gap:6px;align-items:center"><input type="checkbox" id="admin-token-persist"> Remember on this device</label>
    <button class="btn primary" onclick="setAdminToken($('admin-token-input').value,$('admin-token-persist').checked);loadPolicy()">Save token</button>
  </div>
  <div style="margin-top:8px"><button class="btn" onclick="setAdminToken('',false);renderSettings()">Clear token</button></div>
</div>
<div class="section-header"><h3>Raw policy editor</h3></div>
<div class="panel" style="overflow:hidden">
  <div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;background:#fafafa;font-size:12px;color:#6b7280">Edit the full policy JSON directly. Validate locally before saving; the server validates again before applying changes.</div>
  <div style="padding:14px">
    <textarea class="policy-editor" id="policy-editor" spellcheck="false">${esc(pol)}</textarea>
    <div class="form-actions" style="margin-top:8px">
      <button class="btn" onclick="renderSettings()">Reset</button>
      <button class="btn" onclick="validateRawPolicy()">Validate</button>
      <button class="btn" onclick="downloadRawPolicy()">Download</button>
      <button class="btn primary" onclick="saveRawPolicy()">Save policy</button>
    </div>
  </div>
</div>
<div class="section-header" style="margin-top:8px"><h3>Server info</h3></div>
<div class="panel" style="padding:14px">
  <div style="display:grid;grid-template-columns:160px minmax(0,1fr);gap:8px 16px;font-size:12px">
    <div style="color:#6b7280;font-weight:500">Admin bind</div><div style="font-family:monospace;word-break:break-all">${esc(S.policy.admin_bind||'')}</div>
    <div style="color:#6b7280;font-weight:500">MCP bind</div><div style="font-family:monospace;word-break:break-all">${esc(S.policy.mcp_bind||'')}</div>
    <div style="color:#6b7280;font-weight:500">Audit path</div><div style="font-family:monospace;word-break:break-all">${esc(S.policy.audit_path||'')}</div>
    <div style="color:#6b7280;font-weight:500">Exec state dir</div><div style="font-family:monospace;word-break:break-all">${esc(S.policy.exec_state_dir||'')}</div>
  </div>
</div>`;
}

async function saveRawPolicy(){
  const raw=$('policy-editor').value;
  let pol;
  try{pol=JSON.parse(raw);}catch(e){toast('Invalid JSON: '+e.message,'bad');return;}
  try{await jsonFetch('/api/policy',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(pol)});await loadPolicy();toast('Policy saved','ok');renderSettings();}
  catch(e){toast(e.message,'bad');}
}
function validateRawPolicy(){
  try{JSON.parse($('policy-editor').value);toast('Policy JSON is valid','ok');}
  catch(e){toast('Invalid JSON: '+e.message,'bad');}
}
function downloadRawPolicy(){
  const raw=$('policy-editor').value;
  try{JSON.parse(raw);}catch(e){toast('Invalid JSON: '+e.message,'bad');return;}
  downloadBlob('nmcp-policy.json',new Blob([raw],{type:'application/json'}));
}

/* INIT */
async function init(){
  await Promise.all([checkHealth(),loadPolicy(),loadDrives()]);
  nav('dashboard');
  setInterval(checkHealth,15000);
}
init();
