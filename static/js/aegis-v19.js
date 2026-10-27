// LawCypenLab v19 :: station-map, alerts, API portal, OTP pad, CSRF demo

// ── Station Map ───────────────────────────────────────────────────────
(function () {
  const svg = document.getElementById('aegis-map');
  if (!svg) return;
  const detail = document.getElementById('map-detail');
  const modules = {
    'mod-core':       {label:'CORE MODULE',      status:'nominal',    detail:'Central hub connecting all station arms. All systems nominal.'},
    'mod-reactor':    {label:'REACTOR MODULE',    status:'warning',    detail:'Core temperature elevated: 9,182 °C. Override key exposed to internal network (SSRF target).'},
    'mod-lifesupport':{label:'LIFE SUPPORT',      status:'nominal',    detail:'O₂ at 98.4 %. Scrubbers replaced last cycle. All crew sustained.'},
    'mod-crew':       {label:'CREW QUARTERS',     status:'nominal',    detail:'6 crew in residence. Bunk assignments logged.'},
    'mod-comms':      {label:'COMMS HUB',         status:'nominal',    detail:'Uplink restored after EVA relay maintenance. CRLF injection possible in lang-set header.'},
    'mod-cargo':      {label:'CARGO BAY',         status:'nominal',    detail:'24 / 40 cargo slots in use. CSV formula injection possible on manifest export.'},
    'mod-docking':    {label:'DOCKING RING',      status:'nominal',    detail:'Bay 1 clear. Docking webhook SSRF active on status-change POST.'},
    'mod-science':    {label:'SCIENCE LAB',       status:'warning',    detail:'Quarantine active. Pickle deserialization RCE possible via inventory import endpoint.'},
    'mod-medical':    {label:'MEDICAL BAY',       status:'nominal',    detail:'Dr. Osei on duty. Medical records exposed via IDOR at /vrt/medical/<id>.'},
  };

  document.querySelectorAll('.map-module').forEach(el => {
    const id = el.id;
    const info = modules[id];
    if (!info) return;
    el.setAttribute('role', 'button');
    el.setAttribute('tabindex', '0');
    el.addEventListener('click', () => {
      if (!detail) return;
      detail.querySelector('.map-module-panel h3').textContent = info.label;
      const s = detail.querySelector('.map-status');
      s.textContent = info.status.toUpperCase();
      s.className = 'map-status ' + info.status;
      detail.querySelector('.map-module-detail').textContent = info.detail;
    });
  });
})();

// ── Alert dismiss (client-side only, no re-auth) ─────────────────────
document.querySelectorAll('.alert-dismiss').forEach(btn => {
  btn.addEventListener('click', async () => {
    const row = btn.closest('.alert-row');
    const aid = btn.dataset.id;
    // VULN: sends DELETE via POST + X-HTTP-Method-Override — server
    // checks the override header to decide whether to delete the alert,
    // skipping its own RBAC check because "only admins can DELETE".
    const r = await fetch(`/alerts/${aid}/dismiss`, {
      method: 'POST',
      headers: {'X-HTTP-Method-Override': 'DELETE', 'X-Requested-With': 'XMLHttpRequest'}
    });
    if (r.ok) {
      row.classList.add('dismissed');
      btn.disabled = true;
    }
  });
});

// ── API Portal accordion ─────────────────────────────────────────────
document.querySelectorAll('.api-ep-head').forEach(head => {
  head.addEventListener('click', () => {
    const body = head.nextElementSibling;
    if (!body) return;
    body.classList.toggle('open');
  });
});

// ── OTP pad ──────────────────────────────────────────────────────────
(function () {
  const disp = document.getElementById('otp-display');
  if (!disp) return;
  document.querySelectorAll('.otp-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const v = btn.dataset.val;
      if (v === '⌫') { disp.textContent = disp.textContent.slice(0, -1); return; }
      if (v === '✓') {
        document.getElementById('otp-hidden').value = disp.textContent;
        disp.closest('form').submit();
        return;
      }
      if (disp.textContent.length < 6) disp.textContent += v;
    });
  });
})();

// ── CSRF demo: auto-submit a cross-origin transfer form ──────────────
function doCsrfDemo() {
  const f = document.getElementById('csrf-demo-form');
  if (f) f.submit();
}

// ── Generic JSON API tester ──────────────────────────────────────────
async function apiTest(url, method, body, outId) {
  const out = document.getElementById(outId);
  if (out) { out.style.display = 'block'; out.textContent = 'Sending…'; }
  const opts = {method: method||'GET', headers:{}};
  if (body) {
    opts.body = typeof body === 'string' ? body : JSON.stringify(body);
    opts.headers['Content-Type'] = body && typeof body === 'object' ?
      'application/json' : 'application/x-www-form-urlencoded';
  }
  try {
    const res = await fetch(url, opts);
    const ct = res.headers.get('content-type')||'';
    const data = ct.includes('json') ? JSON.stringify(await res.json(),null,2) : await res.text();
    if (out) out.textContent = `HTTP ${res.status}\n\n${data}`;
  } catch (e) {
    if (out) out.textContent = 'Error: ' + e.message;
  }
}
