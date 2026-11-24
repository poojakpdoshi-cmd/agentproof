// Repair dashboard. textContent rendering only; writes carry the same-origin token header.
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const token = document.querySelector('meta[name="agentproof-token"]').content;
  const embedded = document.getElementById('state');
  const el = (tag, attrs, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (k === 'class') n.className = v; else if (k === 'onclick') n.addEventListener('click', v); else if (v !== false) n.setAttribute(k, v === true ? '' : v); }
    for (const c of kids) n.append(c === null || c === undefined ? '' : (typeof c === 'object' ? c : String(c)));
    return n;
  };
  const kv = (k, v, mono) => [el('dt', {}, k), el('dd', mono ? { class: 'mono' } : {}, v)];
  async function act(url, body) {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-AgentProof-Token': token }, body: JSON.stringify({ ...body, approver: $('approver').value }) });
    const r = await res.json();
    $('message').textContent = res.ok ? 'Done: ' + JSON.stringify(r) : 'Refused: ' + (r.code || r.error || res.status);
    load();
  }
  function render(s) {
    const live = !embedded && token;
    $('badges').replaceChildren(el('span', { class: 'badge demo' }, 'SYNTHETIC ENVIRONMENT: ' + s.environment.id), el('span', { class: 'badge ' + (s.evidence.ok ? 'ok' : 'bad') },
      s.evidence.ok ? 'Repair evidence verified (' + s.evidence.entries + ' entries)' : 'Evidence verification FAILED'), el('span', { class: 'badge' }, live ? 'Interactive' : 'Read-only snapshot'));
    const kpi = (v, l) => el('div', { class: 'panel kpi' }, el('div', { class: 'v' }, v), el('div', { class: 'l' }, l));
    $('kpis').replaceChildren(kpi(s.summary.attacksGenerated, 'Attack traces generated'), kpi(s.summary.initialVulnerabilities, 'Vulnerabilities found'),
      kpi(s.proposals.length, 'Repairs proposed'), kpi(s.summary.residual, 'Residual after all repairs'), kpi(s.summary.latencyMs + ' ms', 'Engine time'), kpi('v' + s.summary.currentVersion, 'Live policy version'));
    $('proposals').replaceChildren(...s.proposals.map(p => {
      const v = p.verification;
      const diff = el('pre', { class: 'diff' }, ...p.diff.map(([t, line]) => el('span', { class: t === '+' ? 'add' : t === '-' ? 'del' : '' }, t + ' ' + line + '\n')));
      const alt = el('table', { class: 'cards' }, el('tr', {}, el('th', {}, 'Alternative'), el('th', {}, 'Score'), el('th', {}, 'Fixes'), el('th', {}, 'Legit blocked / held')),
        ...p.alternatives.map(a => el('tr', {}, el('td', { 'data-label': 'Alternative' }, a.summary), el('td', { 'data-label': 'Score' }, a.score), el('td', { 'data-label': 'Fixes' }, a.fixes), el('td', { 'data-label': 'Legit' }, a.blocked + ' / ' + a.held))));
      return el('article', { class: 'panel' },
        el('h2', {}, p.id + ' · ' + p.status),
        el('div', { class: 'grid2' },
          el('div', { class: 'stack' }, el('dl', { class: 'kv' }, ...kv('Vulnerability', p.violation.property + ': ' + (p.violation.asset || '') + ' → ' + p.violation.sink + ' ' + p.violation.target + (p.violation.transform ? ' (' + p.violation.transform + ')' : '')),
            ...kv('Root cause', p.causes.join(', ')), ...kv('Why', p.explanation.join(' ')), ...kv('Proposed repair', p.repair), ...kv('Operator', p.operator, true))),
          el('div', { class: 'stack' }, el('dl', { class: 'kv' }, ...kv('Vulnerable trace', v.targetBefore + '  →  ' + v.targetAfter, true), ...kv('Vulnerabilities fixed', v.vulnerabilitiesFixed),
            ...kv('Security regressions', v.securityRegressions), ...kv('Legit blocked / held', v.legitBlocked + ' / ' + v.legitHeld), ...kv('Rank score', v.score),
            ...kv('Certificate', v.certificate.slice(0, 24) + '…', true), ...kv('Independent re-verification', v.reverified ? 'reproduced exactly' : 'MISMATCH')))),
        el('h2', { style: 'margin-top:12px' }, 'Policy diff'), diff,
        el('h2', { style: 'margin-top:12px' }, 'Ranked alternatives'), el('div', { class: 'table-wrap' }, alt),
        el('div', { style: 'margin-top:12px; display:flex; gap:8px; flex-wrap:wrap' },
          el('button', { class: 'btn primary', disabled: !live || !p.applicable, onclick: () => act('api/apply', { id: p.id }) }, 'Approve and apply'),
          el('button', { class: 'btn', disabled: !live || p.status !== 'pending', onclick: () => act('api/reject', { id: p.id }) }, 'Reject'),
          p.status === 'pending' && !p.applicable ? el('span', { class: 'muted' }, 'Apply earlier proposals first (verified against that exact policy).') : ''));
    }));
    $('versions').replaceChildren(el('tr', {}, el('th', {}, 'Version'), el('th', {}, 'Change'), el('th', {}, 'By'), el('th', {}, 'Digest'), el('th', {}, '')),
      ...s.versions.map(x => el('tr', {}, el('td', { 'data-label': 'Version' }, 'v' + x.n), el('td', { 'data-label': 'Change' }, x.change + (x.proposal ? ' · ' + x.proposal : '')),
        el('td', { 'data-label': 'By' }, x.by), el('td', { class: 'mono', 'data-label': 'Digest' }, x.digest),
        el('td', { 'data-label': '' }, el('button', { class: 'btn', disabled: !live || x.n === s.summary.currentVersion, onclick: () => act('api/rollback', { version: x.n }) }, 'Roll back to v' + x.n)))));
    $('footer').textContent = 'Every figure comes from deterministic replay in a synthetic environment. Certificates can be re-verified with: node src/repair/cli.ts verify REPORT ENV.';
  }
  function load() { fetch('api/state', { cache: 'no-store' }).then(r => r.json()).then(render).catch(() => { $('footer').textContent = 'Repair API unavailable.'; }); }
  if (embedded) render(JSON.parse(embedded.textContent)); else load();
})();
