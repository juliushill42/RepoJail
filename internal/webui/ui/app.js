const $ = s => document.querySelector(s);
const out = $('#output');
const token = localStorage.getItem('repojail_token') || '';

async function api(path, options = {}) {
  const headers = {'Content-Type':'application/json', ...(options.headers||{})};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, {...options, headers});
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

function shellSplit(input) {
  const args=[]; let cur='', quote=null, esc=false;
  for (const ch of input.trim()) {
    if (esc) { cur += ch; esc=false; continue; }
    if (ch === '\\' && quote !== "'") { esc=true; continue; }
    if (quote) { if (ch === quote) quote=null; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { quote=ch; continue; }
    if (/\s/.test(ch)) { if (cur) { args.push(cur); cur=''; } continue; }
    cur += ch;
  }
  if (quote || esc) throw new Error('Unclosed quote or escape');
  if (cur) args.push(cur);
  return args;
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ago = iso => { const s=Math.max(0,Math.round((new Date(iso)-Date.now())/1000)); return `${s}s left`; };
const bytes = n => { if (n < 1024) return `${n} B`; const u=['KiB','MiB','GiB','TiB']; let v=n,i=-1; do {v/=1024;i++} while(v>=1024&&i<u.length-1); return `${v.toFixed(1)} ${u[i]}`; };

async function refresh() {
  try {
    const [status, data] = await Promise.all([api('/api/v1/status'), api('/api/v1/jails')]);
    $('#status').textContent = `${status.isolation} · ${status.active_jails} active`;
    const host = $('#jails'); host.innerHTML='';
    if (!data.jails.length) { host.innerHTML='<div class="empty">No active jails.</div>'; return; }
    for (const j of data.jails) {
      const card=document.createElement('article'); card.className='card';
      card.innerHTML=`<div class="card-top"><div class="id">${esc(j.id.slice(0,12))}</div><div class="badge">${esc(j.status)}</div></div>
        <div class="meta"><span>isolation</span><span>${esc(j.isolation)}</span><span>repo</span><span title="${esc(j.repo_url||'empty workspace')}">${esc(j.repo_url||'empty workspace')}</span><span>expires</span><span>${esc(ago(j.expires_at))}</span><span>size</span><span>${esc(bytes(j.workspace_bytes||0))}</span><span>network</span><span>${j.allow_network?'allowed':'blocked when runtime supports it'}</span></div>
        <div class="exec-row"><input data-cmd placeholder="git status"><button data-run>Run</button></div>
        <div class="actions"><button class="ghost" data-events>Audit</button><button class="danger" data-destroy>Destroy</button></div>`;
      card.querySelector('[data-run]').onclick=()=>run(j.id,card.querySelector('[data-cmd]').value);
      card.querySelector('[data-events]').onclick=()=>events(j.id);
      card.querySelector('[data-destroy]').onclick=()=>destroy(j.id);
      host.appendChild(card);
    }
  } catch(e) { $('#status').textContent='error'; log(e.message); }
}

async function create() {
  const allow = $('#network').checked;
  try {
    const j=await api('/api/v1/jails',{method:'POST',body:JSON.stringify({repo_url:$('#repo').value.trim(),ref:$('#ref').value.trim(),ttl_seconds:Number($('#ttl').value||1800),allow_network:allow})});
    log(`created ${j.id}\n${j.path}`); await refresh();
  } catch(e){log(e.message)}
}
async function run(id, command) {
  try { const argv=shellSplit(command); if(!argv.length) throw new Error('Enter a command'); log(`$ ${argv.join(' ')}`); const r=await api(`/api/v1/jails/${id}/exec`,{method:'POST',body:JSON.stringify({argv,timeout_seconds:300})}); log(`${r.stdout}${r.stderr}\nexit=${r.exit_code} isolation=${r.isolation} network_isolated=${r.network_isolated}`); await refresh(); } catch(e){log(e.message)}
}
async function destroy(id){try{await api(`/api/v1/jails/${id}`,{method:'DELETE'});log(`destroyed ${id}`);await refresh()}catch(e){log(e.message)}}
async function events(id){try{const d=await api(`/api/v1/jails/${id}/events?limit=50`);log(JSON.stringify(d.events,null,2))}catch(e){log(e.message)}}
function log(s){out.textContent=`${new Date().toLocaleTimeString()}  ${s}\n\n${out.textContent}`}

$('#create').onclick=create; $('#refresh').onclick=refresh; $('#clear').onclick=()=>out.textContent='';
refresh(); setInterval(refresh,15000);
