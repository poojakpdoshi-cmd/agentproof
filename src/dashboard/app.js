// Renders dashboard state with DOM APIs and textContent only (no HTML injection from evidence).
(function () {
  'use strict';
  let selected = null;
  const $ = id => document.getElementById(id);
  const el = (tag, attrs, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') node.className = v; else if (k === 'onclick') node.addEventListener('click', v); else node.setAttribute(k, v);
    }
    for (const c of children) node.append(c === null || c === undefined ? '' : (typeof c === 'object' ? c : String(c)));
    return node;
  };
  const chip = d => el('span', { class: 'chip ' + d }, d === 'REQUIRE_APPROVAL' ? 'APPROVAL' : d);
  const time = ts => (ts || '').replace('T', ' ').replace(/\.\d+Z$/, 'Z');

  function render(state) {
    const t = state.totals, i = state.integrity;
    $('badges').replaceChildren(
      el('span', { class: 'badge' + (state.source.mode.startsWith('DEMO') ? ' demo' : '') }, state.source.mode),
      el('span', { class: 'badge mono' }, state.source.file),
      el('span', { class: 'badge ' + (i.ok ? 'ok' : 'bad') }, i.ok ? (i.macVerified ? 'Evidence verified (hash chain + HMAC)' : 'Evidence verified (hash chain)') : 'Evidence verification FAILED'));
    const kpi = (v, l) => el('div', { class: 'panel kpi' }, el('div', { class: 'v' }, v ?? '–'), el('div', { class: 'l' }, l));
    $('kpis').replaceChildren(kpi(t.evaluated, 'Actions evaluated'), kpi(t.allowed, 'Allowed'), kpi(t.blocked, 'Blocked'), kpi(t.approval, 'Awaiting approval'),
      kpi(t.approvedByHuman, 'Approved by a human'), kpi(t.executed, 'Executed'), kpi(t.bindingViolations, 'Binding violations stopped'),
      kpi(state.latency.p95 === null ? '–' : state.latency.p95 + ' ms', 'p95 decision latency (' + state.latency.decisions + ')'));
    const threats = Object.entries(state.threats).sort((a, b) => b[1] - a[1]);
    const max = Math.max(1, ...threats.map(x => x[1]));
    $('threats').replaceChildren(...(threats.length ? threats.map(([k, n]) => {
      const fill = el('div', { class: 'fill' }); fill.style.width = (100 * n / max) + '%';
      return el('div', { class: 'bar' }, el('span', {}, k.replaceAll('_', ' ').toLowerCase()), el('div', { class: 'track' }, fill), el('span', { class: 'n' }, n));
    }) : [el('div', { class: 'empty' }, 'No blocked or held actions.')]));
    const kv = (k, v, mono) => [el('dt', {}, k), el('dd', mono ? { class: 'mono' } : {}, v)];
    $('integrity').replaceChildren(...kv('Status', i.ok ? 'Intact: every hash recomputed from content' : 'Tampering or corruption detected'),
      ...kv('Entries', i.entries), ...kv('Head', i.head ? '#' + i.head.seq + ' ' + i.head.hash : '–', true),
      ...kv('Authenticity', i.macVerified ? 'HMAC verified with operator key' : 'No key supplied: chain only (cannot detect a full rewrite)'),
      ...kv('Truncation', 'Detectable only against an externally recorded head (anchor)'),
      ...(i.issues.length ? kv('Issues', i.issues.map(x => x.code + (x.seq === null ? '' : ' @#' + x.seq)).join(', ')) : []));
    $('mandates').replaceChildren(el('tr', {}, el('th', {}, 'Mandate'), el('th', {}, 'Agent'), el('th', {}, 'User'), el('th', {}, 'Objective'), el('th', {}, 'Expires')),
      ...state.mandates.map(m => el('tr', {}, el('td', { class: 'mono' }, m.id), el('td', {}, m.agent), el('td', {}, m.user), el('td', {}, m.objective), el('td', { class: 'mono' }, time(m.expiresAt)))));
    const rows = state.timeline;
    $('timeline').replaceChildren(el('tr', {}, el('th', {}, 'Time'), el('th', {}, 'Tool'), el('th', {}, 'Target'), el('th', {}, 'Decision'), el('th', {}, 'Risk')),
      ...rows.map(r => el('tr', { class: 'row' + (selected === r.actionId ? ' sel' : ''), onclick: () => { selected = r.actionId; render(state); } },
        el('td', { class: 'mono' }, time(r.ts).slice(11)), el('td', { class: 'mono' }, r.tool), el('td', { class: 'mono' }, r.resource ?? '–'),
        el('td', {}, chip(r.final)), el('td', {}, r.score + ' ' + r.level.toLowerCase()))));
    const r = rows.find(x => x.actionId === selected);
    if (!r) { $('detail').className = 'empty'; $('detail').replaceChildren('Select an action in the timeline.'); }
    else {
      $('detail').className = '';
      $('detail').replaceChildren(el('dl', { class: 'kv' }, ...kv('Decision', chip(r.final)), ...kv('Action', r.actionId, true), ...kv('Tool / target', r.tool + ' → ' + (r.resource ?? '–'), true),
        ...kv('Agent', r.agent), ...kv('Policy', r.policyId, true), ...kv('Intent', r.objective ?? '–'), ...kv('Reason codes', r.reasons.join(', ') || 'authorized'),
        ...kv('Threats', r.threats.join(', ') || 'none'), ...kv('External', r.external ?? '–'), ...kv('Human review', r.approval ?? '–'), ...kv('Execution', r.execution ?? 'not executed'),
        ...kv('Evidence', 'ledger entry #' + r.seq), ...kv('Latency', r.latencyMs === null ? '–' : r.latencyMs + ' ms')),
        el('h2', { style: 'margin-top:16px' }, 'Risk factors (score ' + r.score + '/100)'),
        ...(r.factors.length ? r.factors.map(f => el('div', { class: 'factor' }, el('b', {}, '+' + f.points), el('div', {}, el('div', { class: 'mono' }, f.code), el('div', { class: 'muted' }, f.detail))))
          : [el('div', { class: 'empty' }, 'No contextual risk factors.')]));
    }
    $('footer').textContent = 'All figures are derived from ' + state.source.file + ' (' + i.entries + ' entries). Nothing is sampled, estimated or simulated by this page.';
  }

  const embedded = document.getElementById('state');
  if (embedded) { render(JSON.parse(embedded.textContent)); return; }
  const load = () => fetch('api/state', { cache: 'no-store' }).then(r => r.json()).then(render).catch(() => { $('footer').textContent = 'Dashboard API unavailable.'; });
  load();
  setInterval(load, 3000);
})();
