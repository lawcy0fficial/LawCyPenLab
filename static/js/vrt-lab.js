// LawCypenLab :: VRT Bug Bounty Lab interactions
// Severity filter chips + generic fetch/test helper shared by demo buttons.

document.addEventListener('DOMContentLoaded', () => {
  const filters = document.querySelectorAll('.vrt-filter');
  const cards = document.querySelectorAll('.vrt-card');
  if (filters.length) {
    filters.forEach(btn => {
      btn.addEventListener('click', () => {
        filters.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const sev = btn.dataset.sev;
        cards.forEach(card => {
          const show = sev === 'all' || card.dataset.sev === sev;
          card.classList.toggle('hidden', !show);
        });
      });
    });
  }
});

// Generic helper: run a fetch, dump JSON/text into a <pre> target.
async function vrtTest(url, opts, outId) {
  const out = document.getElementById(outId);
  if (out) { out.style.display = 'block'; out.textContent = 'Sending request…'; }
  try {
    const res = await fetch(url, opts || {});
    let body;
    const ct = res.headers.get('content-type') || '';
    body = ct.includes('application/json') ? JSON.stringify(await res.json(), null, 2) : await res.text();
    if (out) out.textContent = `HTTP ${res.status}\n\n${body}`;
    return { status: res.status, body };
  } catch (e) {
    if (out) out.textContent = 'Error: ' + e.message;
  }
}
