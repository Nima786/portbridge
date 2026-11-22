(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const h = (tag, props, ...kids) => {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, String(v));
      }
    }
    for (const c of kids) {
      if (c === null || c === undefined || c === false) continue;
      el.append(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return el;
  };

  let token = '';
  let pollTimer = null;
  let latestResults = [];
  let latestReport = null;

  // Theme toggle
  const applyTheme = (t) => {
    if (t === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem('pb-scan-theme', t); } catch (_) {}
  };
  try {
    const saved = localStorage.getItem('pb-scan-theme');
    if (saved === 'dark' || saved === 'light') applyTheme(saved);
    else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) applyTheme('dark');
  } catch (_) {}

  $('theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  });

  async function api(method, path, body) {
    const headers = { 'X-PB-Token': token };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const resp = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await resp.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) {}
    if (!resp.ok) {
      throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
  }

  function renderISP(isp) {
    const pill = $('isp-pill');
    const title = $('isp-name');
    const meta = $('isp-meta');
    if (!isp || !isp.detected) {
      pill.className = 'isp-pill is-warn';
      pill.textContent = 'Local Device Mode';
      title.textContent = 'Ready to scan from this device';
      meta.textContent = (isp && isp.error) || 'Disconnect any VPN before starting so tests reflect your real ISP.';
      return;
    }
    pill.className = 'isp-pill is-ok';
    pill.textContent = `Direct ISP · ${isp.ip}${isp.colo ? ' · Edge ' + isp.colo : ''}`;
    title.textContent = isp.isp || isp.asn || isp.ip;
    const loc = [isp.city, isp.country, isp.asn].filter(Boolean).join(' · ');
    meta.textContent = (loc ? loc + ' — ' : '') + 'Make sure your VPN is OFF before starting so results match your real ISP.';
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      $('copy-status').textContent = label || 'Copied to clipboard.';
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      $('copy-status').textContent = label || 'Copied to clipboard.';
    }
  }

  function statusPill(r) {
    if (r.status === 'ok') return h('span', { class: 'pill ok' }, r.selected ? '★ Clean' : 'Verified');
    if (r.status === 'stage1_ok') return h('span', { class: 'pill s1' }, 'TLS OK');
    if (r.status === 'throttled') return h('span', { class: 'pill warn', title: r.error || '' }, 'Throttled');
    return h('span', { class: 'pill bad', title: r.error || '' }, r.error ? r.error : 'Blocked');
  }

  function renderResults(list) {
    latestResults = list || [];
    const card = $('results-card');
    const tbody = $('results-tbody');
    if (!latestResults.length) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const hideBlocked = $('filter-clean-only').checked;
    const shown = hideBlocked
      ? latestResults.filter((r) => r.status === 'ok' || r.status === 'stage1_ok' || r.status === 'throttled')
      : latestResults;

    const rows = shown.map((r, i) => {
      const dl = r.down_mbps > 0 ? `${r.down_mbps.toFixed(1)} Mbps` : '—';
      const ul = r.up_mbps > 0 ? `${r.up_mbps.toFixed(1)} Mbps` : '—';
      const rtt = r.rtt_ms > 0 ? `${Math.round(r.rtt_ms)} ms` : '—';
      const jit = r.jitter_ms > 0 ? `${r.jitter_ms.toFixed(1)} ms` : (r.rtt_ms > 0 ? '0 ms' : '—');
      const score = r.score > 0 ? h('span', { class: 'score-pill' }, `${r.score}/100`) : '—';
      return h('tr', { class: r.selected ? 'is-winner' : '' },
        h('td', { class: 'muted' }, String(i + 1)),
        h('td', { class: 'mono' }, h('strong', null, r.ip)),
        h('td', { class: 'mono muted' }, r.colo || '—'),
        h('td', null, statusPill(r)),
        h('td', null, score),
        h('td', { class: 'mono' }, dl),
        h('td', { class: 'mono' }, ul),
        h('td', { class: 'mono' }, rtt),
        h('td', { class: 'mono muted' }, jit),
        h('td', null,
          h('button', {
            type: 'button',
            class: 'row-copy-btn',
            onclick: () => copyText(r.ip, `Copied ${r.ip} to clipboard.`),
          }, 'Copy')));
    });
    tbody.replaceChildren(...rows);
  }

  function renderWinners(rep) {
    latestReport = rep;
    const card = $('winners-card');
    if (!rep || !rep.recommended || !rep.recommended.length) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const byIP = {};
    for (const r of (rep.results || [])) byIP[r.ip] = r;
    const ispTitle = (rep.isp && rep.isp.isp) ? ` for ${rep.isp.isp}` : '';
    $('winners-title').textContent = `Top ${rep.recommended.length} Clean Cloudflare IPs${ispTitle}`;
    $('winners-note').textContent = (rep.notes && rep.notes[0]) || '';
    $('copy-status').textContent = '';

    const chips = rep.recommended.map((ip) => {
      const r = byIP[ip] || {};
      const meta = [
        r.down_mbps > 0 ? `↓ ${r.down_mbps.toFixed(1)} Mbps` : '',
        r.rtt_ms > 0 ? `${Math.round(r.rtt_ms)} ms` : '',
        r.colo || '',
      ].filter(Boolean).join(' · ');
      return h('button', {
        type: 'button',
        class: 'ip-chip',
        title: 'Click to copy this IP',
        onclick: () => copyText(ip, `Copied ${ip} to clipboard.`),
      },
        h('strong', { class: 'mono' }, ip),
        meta ? h('span', { class: 'ip-chip-meta' }, meta) : null);
    });
    $('winners-chips').replaceChildren(...chips);
  }

  function setRunningUI(running) {
    $('start-btn').disabled = running;
    $('start-btn').textContent = running ? 'Scanning…' : 'Start Real Scan';
    $('stop-btn').hidden = !running;
    $('prog-spinner').hidden = !running;
  }

  async function pollStatus() {
    try {
      const st = await api('GET', '/api/scan/status');
      $('progress-card').hidden = false;
      $('prog-msg').textContent = st.message || 'Scanning…';
      const pct = Math.max(0, Math.min(100, Math.round(st.percent || 0)));
      $('prog-pct').textContent = `${pct}%`;
      $('prog-bar').value = pct;
      $('prog-stat-tested').textContent = `Tested: ${st.done || 0} / ${st.total || 0}`;
      $('prog-stat-s1').textContent = `TLS Reachable: ${st.passed_stage1 || 0}`;
      $('prog-stat-verified').textContent = `Speed Verified: ${st.verified_count || 0}`;

      if (st.results && st.results.length) renderResults(st.results);

      if (st.running) {
        setRunningUI(true);
        pollTimer = setTimeout(pollStatus, 500);
        return;
      }
      setRunningUI(false);
      if (st.error) {
        $('scan-error').textContent = st.error;
      }
      if (st.report) {
        if (st.report.isp && st.report.isp.detected) renderISP(st.report.isp);
        renderWinners(st.report);
        if (st.report.results) renderResults(st.report.results);
      }
    } catch (e) {
      setRunningUI(false);
      $('scan-error').textContent = e.message;
    }
  }

  $('scan-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('scan-error').textContent = '';
    $('winners-card').hidden = true;
    $('copy-status').textContent = '';
    if (pollTimer) clearTimeout(pollTimer);

    const depthEl = document.querySelector('input[name="scan-depth"]:checked');
    const count = Number((depthEl && depthEl.value) || 64);
    const rangesText = $('scan-ranges').value.trim();
    const body = {
      domain: $('scan-domain').value.trim(),
      port: Number($('scan-port').value || 443),
      count,
      max_select: Number($('scan-top').value || 5),
      fragment: $('scan-fragment').checked,
      custom_ranges: rangesText ? [rangesText] : [],
    };
    try {
      setRunningUI(true);
      $('progress-card').hidden = false;
      $('prog-msg').textContent = 'Starting real TLS & speed scan…';
      $('prog-pct').textContent = '2%';
      $('prog-bar').value = 2;
      await api('POST', '/api/scan/start', body);
      pollStatus();
    } catch (e) {
      setRunningUI(false);
      $('scan-error').textContent = e.message;
    }
  });

  $('stop-btn').addEventListener('click', async () => {
    $('stop-btn').disabled = true;
    try { await api('POST', '/api/scan/stop', {}); } catch (_) {}
    $('stop-btn').disabled = false;
  });

  $('filter-clean-only').addEventListener('change', () => renderResults(latestResults));

  $('copy-csv-btn').addEventListener('click', () => {
    if (!latestReport || !latestReport.recommended) return;
    copyText(latestReport.recommended.join(','), `Copied ${latestReport.recommended.length} comma-separated IPs (ready for PortBridge).`);
  });

  $('copy-lines-btn').addEventListener('click', () => {
    if (!latestReport || !latestReport.recommended) return;
    copyText(latestReport.recommended.join('\n'), `Copied ${latestReport.recommended.length} IPs (one per line).`);
  });

  $('export-csv-btn').addEventListener('click', () => {
    if (!latestResults.length) return;
    const header = 'ip,colo,status,selected,score,down_mbps,up_mbps,rtt_ms,jitter_ms,loss_pct,error\n';
    const body = latestResults.map((r) => [
      r.ip, r.colo || '', r.status, r.selected ? 'yes' : 'no', r.score || 0,
      r.down_mbps || 0, r.up_mbps || 0, r.rtt_ms || 0, r.jitter_ms || 0, r.loss_pct || 0,
      JSON.stringify(r.error || ''),
    ].join(',')).join('\n');
    const blob = new Blob([header + body], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'portbridge-clean-cf-ips.csv';
    a.click();
    URL.revokeObjectURL(url);
  });

  $('isp-refresh-btn').addEventListener('click', async () => {
    const btn = $('isp-refresh-btn');
    btn.disabled = true;
    btn.textContent = 'Checking…';
    try {
      const isp = await api('GET', '/api/isp');
      renderISP(isp);
    } catch (_) {}
    btn.disabled = false;
    btn.textContent = 'Re-check ISP';
  });

  $('quit-btn').addEventListener('click', async () => {
    try { await api('POST', '/api/quit', {}); } catch (_) {}
    document.body.replaceChildren(
      h('main', { class: 'container' },
        h('section', { class: 'card' },
          h('h2', null, 'PortBridge Local Scanner Stopped'),
          h('p', { class: 'muted' }, 'You can safely close this browser tab.'))));
  });

  async function init() {
    try {
      const info = await api('GET', '/api/info');
      token = info.token || '';
      if (info.version) $('app-version').textContent = `Local Real-Speed Scanner · ${info.version}`;
      renderISP(info.isp);
    } catch (e) {
      $('scan-error').textContent = 'Could not connect to local scanner server: ' + e.message;
    }
  }

  init();
})();
