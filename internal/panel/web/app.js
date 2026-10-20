// PortBridge panel page.
//
// Plain JavaScript, no libraries. Everything shown is built with DOM calls and
// textContent, never by pasting text in as HTML, so nothing a server reports can
// turn into script on this page. Requests that change something carry the
// session's anti-forgery token in a header.
'use strict';

(() => {
  const $ = (id) => document.getElementById(id);

  let csrf = '';
  let currentUser = '';
  let currentTab = 'servers';
  let refreshTimer = null;
  let lastServers = '';
  let lastTunnels = '';
  const REFRESH_MS = 10000;

  // ------------------------------------------------------------------- theme

  const THEME_KEY = 'pb-theme';

  function getSavedTheme() {
    try {
      return localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light';
    } catch (e) {
      return 'light';
    }
  }

  function applyTheme(theme) {
    const isDark = theme === 'dark';
    if (isDark) document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
    for (const lbl of document.querySelectorAll('.theme-label')) {
      lbl.textContent = isDark ? 'Light mode' : 'Dark mode';
    }
    try {
      localStorage.setItem(THEME_KEY, isDark ? 'dark' : 'light');
    } catch (e) {
      // Storage may be unavailable in private browsing.
    }
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  }

  applyTheme(getSavedTheme());
  for (const id of ['theme-toggle', 'login-theme-toggle']) {
    const btn = $(id);
    if (btn) btn.addEventListener('click', toggleTheme);
  }

  // ------------------------------------------------------------------ helpers

  // h builds an element: h('p', {class: 'x'}, 'text', child, ...).
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function api(method, path, body) {
    const opts = { method, headers: {}, credentials: 'same-origin', cache: 'no-store' };
    if (method !== 'GET') opts.headers['X-PB-CSRF'] = csrf;
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      throw new ApiError(0, 'The panel cannot be reached right now. Check your connection.');
    }
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      data = null;
    }
    if (res.status === 401 && path !== '/api/login') {
      showLogin(csrf ? 'You were logged out. Please sign in again.' : '');
      throw new ApiError(401, (data && data.error) || 'Please sign in.');
    }
    if (!res.ok) throw new ApiError(res.status, (data && data.error) || `The panel answered with error ${res.status}.`);
    return data;
  }

  function sentence(s) {
    if (!s) return '';
    s = String(s).trim();
    s = s.charAt(0).toUpperCase() + s.slice(1);
    return /[.!?]$/.test(s) ? s : s + '.';
  }

  function plural(n, one, many) {
    return `${n} ${n === 1 ? one : (many || one + 's')}`;
  }

  function ago(iso) {
    const t = Date.parse(iso);
    if (!t) return '';
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 10) return 'just now';
    if (s < 60) return `${s} seconds ago`;
    if (s < 3600) return `${plural(Math.round(s / 60), 'minute')} ago`;
    if (s < 86400) return `${plural(Math.round(s / 3600), 'hour')} ago`;
    return new Date(t).toLocaleString();
  }

  function duration(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    const d = Math.floor(sec / 86400), hr = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d > 0) return `${plural(d, 'day')} ${hr} h`;
    if (hr > 0) return `${hr} h ${m} min`;
    if (m > 0) return `${m} min`;
    return `${sec} s`;
  }

  function ports(list) {
    if (!list || !list.length) return '';
    return list.join(', ');
  }

  // syncChoiceCards keeps .is-selected in sync on .choice-card and .check-card
  function syncChoiceCards(root = document) {
    for (const card of root.querySelectorAll('.choice-card, .check-card')) {
      const inp = card.querySelector('input[type="radio"], input[type="checkbox"]');
      if (inp) card.classList.toggle('is-selected', !!inp.checked);
    }
  }
  document.addEventListener('change', (ev) => {
    if (ev.target && (ev.target.type === 'radio' || ev.target.type === 'checkbox')) {
      syncChoiceCards();
    }
  });

  // setStatus shows a short message at the foot of the page. A problem stays until
  // things work again; good news goes after a little while.
  let statusTimer = null;
  let statusIsProblem = false;
  function setStatus(msg, bad) {
    const el = $('status-line');
    el.textContent = msg || '';
    el.classList.toggle('bad', !!bad);
    statusIsProblem = !!bad;
    if (statusTimer) clearTimeout(statusTimer);
    statusTimer = msg && !bad ? setTimeout(() => setStatus(''), 8000) : null;
  }

  // Re-drawing a list must not throw away where the keyboard was.
  function keepFocus(draw) {
    const key = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.focus : '';
    draw();
    if (key) {
      const el = document.querySelector(`[data-focus="${CSS.escape(key)}"]`);
      if (el) el.focus();
    }
  }

  // Dialogs give the keyboard back to whatever opened them.
  function openDialog(dlg) {
    const key = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.focus : '';
    dlg.dataset.returnTo = key || '';
    syncChoiceCards(dlg);
    dlg.showModal();
  }
  for (const dlg of document.querySelectorAll('dialog')) {
    dlg.addEventListener('close', () => {
      const key = dlg.dataset.returnTo;
      const el = key ? document.querySelector(`[data-focus="${CSS.escape(key)}"]`) : null;
      if (el) el.focus();
    });
  }

  // -------------------------------------------------------------- logging in

  function showLogin(msg) {
    stopRefresh();
    csrf = '';
    for (const dlg of document.querySelectorAll('dialog[open]')) dlg.close();
    $('shell').hidden = true;
    $('login').hidden = false;
    $('login-error').textContent = msg || '';
    $('login-user').focus();
  }

  let loadedVersion = '';

  function enter(me) {
    if ((loadedVersion && me.version && loadedVersion !== me.version) || !$('tn-probe-live')) {
      window.location.reload();
      return;
    }
    loadedVersion = me.version || loadedVersion;
    csrf = me.csrf;
    currentUser = me.user;
    $('version').textContent = me.version || '';
    $('login').hidden = true;
    $('shell').hidden = false;
    lastServers = lastTunnels = '';
    selectTab(currentTab, false);
    startRefresh();
  }

  $('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = ev.target.querySelector('button[type=submit]');
    const user = $('login-user').value.trim();
    const password = $('login-pass').value;
    if (!user || !password) {
      $('login-error').textContent = 'Enter your username and password.';
      return;
    }
    btn.disabled = true;
    $('login-error').textContent = '';
    try {
      const me = await api('POST', '/api/login', { user, password });
      $('login-pass').value = '';
      enter(me);
    } catch (e) {
      $('login-error').textContent = e.message;
      $('login-pass').select();
    } finally {
      btn.disabled = false;
    }
  });

  $('logout').addEventListener('click', async () => {
    try {
      await api('POST', '/api/logout');
    } catch (e) {
      // Logged out either way.
    }
    showLogin('');
  });

  if ($('account-shortcut')) {
    $('account-shortcut').addEventListener('click', () => {
      selectTab('settings', false);
      if ($('acc-current')) $('acc-current').focus();
    });
  }

  // ------------------------------------------------------------------- tabs

  const TABS = ['servers', 'tunnels', 'websites', 'dns', 'settings'];
  let cfLoadedOnce = false;

  function isWebsiteBridge(t) {
    if (!t) return false;
    const ei = t.edge && t.edge.info ? t.edge.info : null;
    const oi = t.origin && t.origin.info ? t.origin.info : null;
    return !!((ei && ei.website_bridge) || (oi && oi.website_bridge));
  }

  function selectTab(name, focus) {
    currentTab = name;
    if (name === 'dns') cfLoadedOnce = false;
    for (const t of TABS) {
      const on = t === name;
      const tab = $('tab-' + t);
      if (!tab) continue;
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      const view = $('view-' + t);
      if (view) view.hidden = !on;
    }
    if (focus && $('tab-' + name)) $('tab-' + name).focus();
    refresh();
  }

  for (const t of TABS) {
    const tab = $('tab-' + t);
    if (!tab) continue;
    tab.addEventListener('click', () => selectTab(t, false));
    tab.addEventListener('keydown', (ev) => {
      let i = TABS.indexOf(t);
      if (ev.key === 'ArrowRight') i = (i + 1) % TABS.length;
      else if (ev.key === 'ArrowLeft') i = (i + TABS.length - 1) % TABS.length;
      else if (ev.key === 'Home') i = 0;
      else if (ev.key === 'End') i = TABS.length - 1;
      else return;
      ev.preventDefault();
      selectTab(TABS[i], true);
    });
  }

  // --------------------------------------------------------------- refreshing

  let serversCache = [];
  let tunnelsCache = [];
  let updatesCache = null;

  function updateSummaryStrip() {
    const relays = serversCache.filter((s) => s.group === 'relay');
    const foreigns = serversCache.filter((s) => s.group === 'foreign');
    const relaysOnline = relays.filter((s) => s.online).length;
    const foreignsOnline = foreigns.filter((s) => s.online).length;

    if ($('sum-relays')) {
      $('sum-relays').textContent = String(relays.length);
      $('sum-relays-sub').textContent = relays.length ? `${relaysOnline} of ${relays.length} online` : 'No relay servers yet';
    }
    if ($('sum-foreigns')) {
      $('sum-foreigns').textContent = String(foreigns.length);
      $('sum-foreigns-sub').textContent = foreigns.length ? `${foreignsOnline} of ${foreigns.length} online` : 'No foreign servers yet';
    }

    const totalServers = serversCache.length;
    const cs = $('count-servers');
    if (cs) {
      cs.textContent = String(totalServers);
      cs.hidden = totalServers === 0;
    }

    const vpnTunnels = tunnelsCache.filter((t) => !isWebsiteBridge(t));
    const webBridges = tunnelsCache.filter((t) => isWebsiteBridge(t));
    const totalTunnels = tunnelsCache.length;
    let runningTunnels = 0;
    let activeUsers = 0;
    let activeConns = 0;
    for (const t of tunnelsCache) {
      const e = t.edge, o = t.origin;
      const halves = [e, o].filter(Boolean);
      if (halves.length && halves.every((x) => x.info && x.info.running)) runningTunnels++;
      const edgeLive = e && e.info && e.info.live ? e.info.live : null;
      const live = edgeLive || (o && o.info && o.info.live) || null;
      if (edgeLive && typeof edgeLive.active_users === 'number') {
        activeUsers += Number(edgeLive.active_users) || 0;
      } else if (live && typeof live.active_users === 'number') {
        activeUsers += Number(live.active_users) || 0;
      }
      if (live && live.active_sessions) activeConns += Number(live.active_sessions) || 0;
    }

    if ($('sum-tunnels')) {
      $('sum-tunnels').textContent = String(totalTunnels);
      $('sum-tunnels-sub').textContent = totalTunnels ? `${runningTunnels} running now` : 'No tunnels configured';
    }
    if ($('sum-users')) {
      $('sum-users').textContent = String(activeUsers);
      $('sum-users-sub').textContent = `${activeUsers === 1 ? '1 unique IP' : activeUsers + ' unique IPs'} · ${activeConns} TCP ${activeConns === 1 ? 'conn' : 'conns'}`;
    }

    const ct = $('count-tunnels');
    if (ct) {
      ct.textContent = String(vpnTunnels.length);
      ct.hidden = vpnTunnels.length === 0;
    }
    const cw = $('count-websites');
    if (cw) {
      cw.textContent = String(webBridges.length);
      cw.hidden = webBridges.length === 0;
    }
  }

  async function refresh() {
    if ($('shell').hidden) return;
    try {
      if (currentTab === 'servers') {
        await Promise.all([loadServers(), loadTunnels()]);
      } else if (currentTab === 'tunnels' || currentTab === 'websites') {
        await Promise.all([loadTunnels(), loadServers()]);
      } else if (currentTab === 'dns') {
        await Promise.all([loadServers(), loadCloudflare(false)]);
      } else {
        await loadSettings();
      }
      if (statusIsProblem) setStatus('');
    } catch (e) {
      if (e.status !== 401 && !(e.status === 0 && $('job-dialog') && $('job-dialog').open)) {
        setStatus(e.message, true);
      }
    }
  }

  function startRefresh() {
    stopRefresh();
    refreshTimer = setInterval(() => {
      // Settings holds a form; refreshing it would wipe what is being typed.
      if (document.visibilityState === 'visible' && currentTab !== 'settings') refresh();
    }, REFRESH_MS);
  }

  function stopRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = null;
  }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && currentTab !== 'settings') refresh();
  });

  // ---------------------------------------------------------------- servers

  async function loadServers() {
    const [data] = await Promise.all([api('GET', '/api/servers'), loadUpdates()]);
    serversCache = data.servers || [];
    updateSummaryStrip();
    const text = JSON.stringify(serversCache) + JSON.stringify(updatesCache && updatesCache.servers);
    if (text === lastServers) return;
    lastServers = text;
    keepFocus(() => renderServers(serversCache));
  }

  function renderServers(list) {
    const relay = [], foreign = [];
    let unassigned = null;
    for (const s of list) {
      if (s.group === 'relay') relay.push(serverCard(s));
      else if (s.group === 'foreign') foreign.push(serverCard(s));
      else if (s.this) unassigned = s;
    }
    $('this-unassigned').hidden = !unassigned;
    $('this-card').replaceChildren(...(unassigned ? [serverCard(unassigned)] : []));
    $('col-relay').replaceChildren(...(relay.length ? relay
      : [h('p', { class: 'empty' }, 'No relay servers yet. Click "+ Add Server" to add one.')]));
    $('col-foreign').replaceChildren(...(foreign.length ? foreign
      : [h('p', { class: 'empty' }, 'No foreign servers yet. Click "+ Add Server" to add one.')]));
  }

  function serverState(s) {
    if (s.online) return h('span', { class: 'state ok' }, 'Online');
    if (s.problem === 'not checked yet') return h('span', { class: 'state unknown' }, 'Checking');
    return h('span', { class: 'state bad' }, 'Offline');
  }

  function serverCard(s) {
    const ov = s.overview;
    const tunnels = (ov && ov.tunnels) || [];
    const running = tunnels.filter((t) => t.running).length;
    const name = s.name || s.address || 'Server';
    const headingId = 'srv-' + s.id;
    const isDraggable = s.group === 'relay' || s.group === 'foreign';
    const roleClass = s.group === 'relay' ? ' server-relay' : (s.group === 'foreign' ? ' server-foreign' : '');

    const chips = [];
    if (s.address) chips.push(h('span', { class: 'meta-chip chip-ip', title: 'Server IP / Hostname' }, s.address));
    if (ov && ov.version) chips.push(h('span', { class: 'meta-chip' }, 'PortBridge ' + ov.version));
    chips.push(h('span', { class: 'meta-chip' }, tunnels.length ? `${plural(tunnels.length, 'tunnel')} (${running} running)` : 'No tunnels'));

    const badges = [];
    if (s.this) badges.push(h('span', { class: 'badge badge-accent' }, 'Panel Host (This Server)'));
    if (s.calls_panel) {
      badges.push(h('span', { class: 'badge', title: 'This server connects in to the panel automatically.' },
        'Callback Mode'));
    }
    if (ov && ov.bbr_active) {
      badges.push(h('span', { class: 'badge badge-ok', title: 'BBR TCP congestion control is active on this server.' }, 'BBR Active'));
    } else if (ov && ov.congestion_control) {
      badges.push(h('span', { class: 'badge', title: `TCP congestion control: ${ov.congestion_control}` }, `TCP: ${ov.congestion_control}`));
    }

    let problem = null;
    if (!s.online && s.problem && s.problem !== 'not checked yet') {
      let text = sentence(s.problem);
      if (s.last_seen) text += ` Last seen ${ago(s.last_seen)}.`;
      problem = h('p', { class: 'problem' }, text);
    }

    const mini = tunnels.length ? h('ul', { class: 'mini', 'aria-label': `Tunnels on ${name}` },
      tunnels.map((t) => {
        const isV6 = String(t.peer_ip || '').includes(':') || String(t.local_ip || '').includes(':');
        const modeTag = (t.mode === 'reverse' ? 'Reverse' : 'Direct') + (isV6 ? ' (IPv6)' : '');
        const detail = [modeTag, shortLinkLabel(t)].filter(Boolean).join(' · ');
        return h('li', null,
          h('div', { class: 'mini-left' },
            h('span', { class: 'state ' + (t.running ? 'ok' : 'bad') }, t.running ? 'Running' : 'Stopped'),
            ' ',
            h('span', null, t.name)),
          detail ? h('span', { class: 'mini-right' }, detail) : null);
      })) : null;

    const upd = updatesCache && (updatesCache.servers || []).find((u) => u.id === s.id);
    const sshUpdate = upd && upd.needs_ssh ? h('p', { class: 'problem' },
      `Its PortBridge (${upd.version}) is older than the panel's and needs a one-time SSH upgrade. `,
      h('button', { type: 'button', class: 'link', 'data-focus': `srv-${s.id}-ssh`, onclick: () => openSSHUpdate(s) },
        'Upgrade via SSH')) : null;

    const card = h('article', { class: 'card server' + roleClass, 'aria-labelledby': headingId },
      h('div', { class: 'head' },
        h('div', { class: 'server-title-wrap' },
          isDraggable ? h('span', { class: 'drag-grip', 'aria-hidden': 'true', title: 'Drag onto a server in the other column to link them' }, '⠿') : null,
          h('h4', { id: headingId }, name)),
        serverState(s)),
      h('div', { class: 'meta-chips' }, chips),
      badges.length ? h('div', { class: 'badges' }, badges) : null,
      problem,
      sshUpdate,
      mini,
      h('div', { class: 'actions' },
        isDraggable
          ? h('button', { type: 'button', 'data-focus': `srv-${s.id}-tunnel`, 'aria-label': `New tunnel with ${name}`, onclick: () => openNewTunnel(s.group === 'relay' ? s.id : '', s.group === 'foreign' ? s.id : '') }, '+ New Tunnel')
          : null,
        h('button', { type: 'button', 'data-focus': `srv-${s.id}-tune`, 'aria-label': `Speed tuning (BBR) for ${name}`, onclick: () => openServerTune(s) },
          'BBR Tuning'),
        h('button', { type: 'button', 'data-focus': `srv-${s.id}-fw`, 'aria-label': `Firewall rules for ${name}`, onclick: () => openServerFirewall(s) },
          'Firewall'),
        h('button', { type: 'button', 'data-focus': `srv-${s.id}-edit`, 'aria-label': `Edit ${name}`, onclick: () => openEdit(s) },
          'Edit'),
        s.this ? null : h('button', { type: 'button', class: 'danger-text', 'data-focus': `srv-${s.id}-remove`, 'aria-label': `Remove ${name} from the panel`, onclick: () => confirmRemove(s) },
          'Remove')));
    makeDraggable(card, s);
    return card;
  }

  // Dragging a relay server onto a foreign one (or the other way round) starts
  // a new tunnel between them. "New Tunnel" on each card does the same from the
  // keyboard.
  let dragged = null;

  function makeDraggable(card, s) {
    if (s.group !== 'relay' && s.group !== 'foreign') return;
    card.draggable = true;
    card.addEventListener('dragstart', (ev) => {
      dragged = s;
      ev.dataTransfer.effectAllowed = 'link';
      ev.dataTransfer.setData('text/plain', s.id);
      card.classList.add('dragging');
    });
    card.addEventListener('dragend', () => {
      dragged = null;
      card.classList.remove('dragging');
      for (const c of document.querySelectorAll('.drop-target')) c.classList.remove('drop-target');
    });
    card.addEventListener('dragover', (ev) => {
      if (!dragged || dragged.group === s.group) return;
      ev.preventDefault();
      ev.dataTransfer.dropEffect = 'link';
      card.classList.add('drop-target');
    });
    card.addEventListener('dragleave', () => card.classList.remove('drop-target'));
    card.addEventListener('drop', (ev) => {
      ev.preventDefault();
      card.classList.remove('drop-target');
      if (!dragged || dragged.group === s.group) return;
      const relay = dragged.group === 'relay' ? dragged : s;
      const foreign = dragged.group === 'foreign' ? dragged : s;
      dragged = null;
      openNewTunnel(relay.id, foreign.id);
    });
  }

  for (const btn of document.querySelectorAll('[data-this-group]')) {
    btn.addEventListener('click', async () => {
      try {
        await api('PATCH', '/api/servers/this', { group: btn.dataset.thisGroup });
        lastServers = '';
        await refresh();
      } catch (e) {
        setStatus(e.message, true);
      }
    });
  }

  // Editing / Renaming / Moving

  let editing = null;

  function openEdit(s) {
    editing = s;
    $('edit-title').textContent = s.this ? 'Edit This Server' : `Edit ${s.name || s.address}`;
    $('edit-name').value = s.name || '';
    for (const r of document.querySelectorAll('input[name="edit-group"]')) r.checked = r.value === s.group;
    $('edit-error').textContent = '';
    openDialog($('edit-dialog'));
    $('edit-name').focus();
  }

  $('edit-cancel').addEventListener('click', () => $('edit-dialog').close());

  $('edit-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const checked = document.querySelector('input[name="edit-group"]:checked');
    const name = $('edit-name').value.trim();
    if (!checked) {
      $('edit-error').textContent = 'Select a server role.';
      return;
    }
    if (!name && !editing.this) {
      $('edit-error').textContent = 'Enter a display name.';
      return;
    }
    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      await api('PATCH', '/api/servers/' + encodeURIComponent(editing.id), { name, group: checked.value });
      $('edit-dialog').close();
      lastServers = '';
      await refresh();
    } catch (e) {
      $('edit-error').textContent = e.message;
    } finally {
      btn.disabled = false;
    }
  });

  // Removing

  let confirmAction = null;

  function openConfirm(title, text, yes, action) {
    $('confirm-title').textContent = title;
    $('confirm-text').textContent = text;
    $('confirm-yes').textContent = yes;
    $('confirm-yes').dataset.origLabel = yes;
    $('confirm-yes').classList.remove('is-loading');
    $('confirm-yes').disabled = false;
    $('confirm-no').disabled = false;
    if ($('confirm-loading-wrap')) $('confirm-loading-wrap').hidden = true;
    $('confirm-error').textContent = '';
    confirmAction = action;
    openDialog($('confirm-dialog'));
    $('confirm-no').focus();
  }

  $('confirm-no').addEventListener('click', () => $('confirm-dialog').close());
  $('confirm-yes').addEventListener('click', async () => {
    const btn = $('confirm-yes');
    const orig = btn.dataset.origLabel || btn.textContent;
    btn.disabled = true;
    btn.classList.add('is-loading');
    if (/^delete/i.test(orig)) {
      btn.textContent = 'Deleting…';
    } else if (/^remove/i.test(orig)) {
      btn.textContent = 'Removing…';
    } else {
      btn.textContent = 'Working…';
    }
    $('confirm-no').disabled = true;
    $('confirm-error').textContent = '';
    if ($('confirm-loading-wrap')) $('confirm-loading-wrap').hidden = false;
    try {
      await confirmAction();
      $('confirm-dialog').close();
    } catch (e) {
      $('confirm-error').textContent = e.message;
    } finally {
      if ($('confirm-loading-wrap')) $('confirm-loading-wrap').hidden = true;
      btn.classList.remove('is-loading');
      btn.textContent = orig;
      btn.disabled = false;
      $('confirm-no').disabled = false;
    }
  });

  function confirmRemove(s) {
    const name = s.name || s.address;
    openConfirm(`Remove ${name} from the panel?`,
      'PortBridge and any active tunnels on that server will continue running untouched. This only unlinks it from the panel, and you can add it back anytime.',
      'Remove from Panel',
      async () => {
        await api('DELETE', '/api/servers/' + encodeURIComponent(s.id));
        lastServers = '';
        await refresh();
      });
  }

  // ------------------------------------------------------------ adding a server

  let keyFromFile = '';
  let jobTimer = null;
  let jobLines = 0;

  function authKind() {
    const c = document.querySelector('input[name="auth"]:checked');
    return c ? c.value : 'password';
  }

  function showAuth() {
    const kind = authKind();
    $('auth-password').hidden = kind !== 'password';
    $('auth-key').hidden = kind !== 'key';
    $('auth-file').hidden = kind !== 'file';
    $('auth-passphrase').hidden = kind === 'password';
    if (kind === 'password') $('add-passphrase').value = '';
    syncChoiceCards($('add-dialog'));
  }
  for (const r of document.querySelectorAll('input[name="auth"]')) {
    r.addEventListener('change', () => {
      $('add-passphrase').value = '';
      showAuth();
    });
  }

  function clearSecrets() {
    $('add-password').value = '';
    $('add-key').value = '';
    $('add-passphrase').value = '';
    $('add-file').value = '';
    keyFromFile = '';
  }

  $('add-file').addEventListener('change', () => {
    keyFromFile = '';
    $('add-error').textContent = '';
    const f = $('add-file').files[0];
    if (!f) return;
    if (f.size > 64 * 1024) {
      $('add-error').textContent = 'That file is too large to be an SSH private key.';
      $('add-file').value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => { keyFromFile = String(reader.result || ''); };
    reader.onerror = () => { $('add-error').textContent = 'Could not read that file.'; };
    reader.readAsText(f);
  });

  let addMode = { kind: 'add' };

  function setAddMode(mode) {
    addMode = mode;
    const add = mode.kind === 'add';
    $('add-only').hidden = !add;
    $('add-only-name').hidden = !add;
    $('add-update-row').hidden = !add;
    $('add-title').textContent = add ? 'Add a Server' : `Upgrade ${mode.server.name} via SSH`;
    $('add-intro').textContent = add
      ? 'The panel connects via SSH once to install or pair PortBridge, and communicates directly through the agent afterwards. Your SSH password or key is never stored.'
      : 'This server runs an older PortBridge version from before one-click updates. Enter its SSH login once to upgrade it; future updates will work with one click.';
    $('add-submit').textContent = add ? 'Add Server' : 'Upgrade Server';
    $('add-form').hidden = false;
    $('add-progress').hidden = true;
    $('add-error').textContent = '';
    showAuth();
  }

  function openSSHUpdate(s) {
    setAddMode({ kind: 'ssh-update', server: s });
    openDialog($('add-dialog'));
    $('add-user').focus();
  }

  $('add-server').addEventListener('click', () => {
    setAddMode({ kind: 'add' });
    openDialog($('add-dialog'));
    const first = document.querySelector('input[name="group"]:checked') || document.querySelector('input[name="group"]');
    first.focus();
  });

  $('add-cancel').addEventListener('click', () => {
    clearSecrets();
    $('add-dialog').close();
  });
  $('add-close').addEventListener('click', () => {
    clearSecrets();
    $('add-dialog').close();
  });
  $('add-back').addEventListener('click', () => {
    $('add-progress').hidden = true;
    $('add-form').hidden = false;
    $('add-error').textContent = '';
    (addMode.kind === 'add' ? $('add-address') : $('add-user')).focus();
  });

  $('add-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const err = $('add-error');
    err.textContent = '';
    const group = document.querySelector('input[name="group"]:checked');
    const address = $('add-address').value.trim();
    const port = Number($('add-port').value || 22);
    const kind = authKind();
    if (kind === 'file' && !keyFromFile.trim()) {
      const f = $('add-file').files && $('add-file').files[0];
      if (f) {
        if (f.size > 64 * 1024) {
          err.textContent = 'That file is too large to be an SSH private key.';
          return;
        }
        try {
          keyFromFile = await f.text();
        } catch (_) {
          err.textContent = 'Could not read that file.';
          return;
        }
      }
    }
    const body = {
      name: $('add-name').value.trim(),
      group: group ? group.value : '',
      address,
      ssh_port: port,
      user: $('add-user').value.trim() || 'root',
      allow_update: $('add-update').checked,
    };
    if (kind === 'password') body.password = $('add-password').value;
    else body.private_key = kind === 'key' ? $('add-key').value : keyFromFile;
    if (kind !== 'password' && $('add-passphrase').value) body.passphrase = $('add-passphrase').value;

    const updating = addMode.kind === 'ssh-update';
    if (updating) {
      delete body.name;
      delete body.group;
      delete body.address;
      delete body.allow_update;
    }
    if (!updating && !body.group) { err.textContent = 'Select whether this is a Relay (Iran) or Foreign server.'; return; }
    if (!updating && !address) { err.textContent = 'Enter the server IP address or hostname.'; $('add-address').focus(); return; }
    if (!Number.isInteger(port) || port < 1 || port > 65535) { err.textContent = 'SSH port must be between 1 and 65535.'; return; }
    if (kind === 'password' && !body.password) { err.textContent = 'Enter the SSH password.'; $('add-password').focus(); return; }
    if (kind === 'key' && !body.private_key.trim()) { err.textContent = 'Paste the SSH private key (OpenSSH, PEM, or PuTTY .ppk).'; $('add-key').focus(); return; }
    if (kind === 'file' && !body.private_key.trim()) { err.textContent = 'Select the SSH private key file (OpenSSH, PEM, or PuTTY .ppk).'; $('add-file').focus(); return; }

    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const path = updating ? `/api/servers/${encodeURIComponent(addMode.server.id)}/ssh-update` : '/api/servers';
      const res = await api('POST', path, body);
      startJob(res.job);
    } catch (e) {
      err.textContent = e.message;
    } finally {
      btn.disabled = false;
    }
  });

  function startJob(id) {
    $('add-form').hidden = true;
    $('add-progress').hidden = false;
    $('add-log').replaceChildren();
    $('add-result').textContent = 'Connecting...';
    $('add-result').className = '';
    $('add-note').hidden = false;
    $('add-back').hidden = true;
    $('add-progress-title').focus();
    jobLines = 0;
    if (jobTimer) clearTimeout(jobTimer);
    const poll = async () => {
      let job;
      try {
        job = await api('GET', '/api/jobs/' + encodeURIComponent(id));
      } catch (e) {
        if (e.status === 401) return;
        $('add-result').textContent = e.message;
        $('add-result').className = 'bad';
        $('add-note').hidden = true;
        return;
      }
      const lines = job.lines || [];
      for (; jobLines < lines.length; jobLines++) $('add-log').append(h('li', null, lines[jobLines]));
      const log = $('add-log');
      log.scrollTop = log.scrollHeight;
      if (!job.done) {
        jobTimer = setTimeout(poll, 1000);
        return;
      }
      $('add-note').hidden = true;
      const updating = addMode.kind === 'ssh-update';
      if (job.error) {
        if (/older than the panel/i.test(job.error)) $('add-update').checked = true;
        $('add-result').textContent = (updating ? 'Upgrade failed. ' : 'Could not add server. ') + sentence(job.error);
        $('add-result').className = 'bad';
        $('add-back').hidden = false;
      } else {
        clearSecrets();
        $('add-result').textContent = updating ? 'Success: server is updated and supports one-click updates from now on.'
          : 'Success: server has been added to the panel.';
        $('add-result').className = 'good';
        $('add-address').value = '';
        $('add-name').value = '';
      }
      lastServers = '';
      refresh();
    };
    poll();
  }

  // ---------------------------------------------------------- following a job

  function followJob(id, title, okText, failText) {
    $('job-title').textContent = title;
    $('job-log').replaceChildren();
    $('job-result').textContent = 'Working...';
    $('job-result').className = '';
    $('job-note').hidden = false;
    if (!$('job-dialog').open) openDialog($('job-dialog'));
    $('job-title').focus();
    let seen = 0;
    let restartTries = 0;
    const syncMe = async () => {
      try {
        const me = await api('GET', '/api/me');
        if (me && me.version) {
          loadedVersion = me.version;
          $('version').textContent = me.version;
        }
        if (me && me.csrf) csrf = me.csrf;
      } catch (_) {}
    };
    const poll = async () => {
      let job;
      try {
        job = await api('GET', '/api/jobs/' + encodeURIComponent(id));
        restartTries = 0;
      } catch (e) {
        if (e.status === 401) return;
        if (e.status === 404 && restartTries < 25) {
          restartTries++;
          try {
            const u = await api('GET', '/api/updates');
            if (u && u.job && u.job !== id) {
              id = u.job;
              setTimeout(poll, 1000);
              return;
            }
            if (u && !u.running && !u.panel_older) {
              await syncMe();
              $('job-log').append(h('li', null, `The panel's own server is now on ${u.panel}.`));
              $('job-log').scrollTop = $('job-log').scrollHeight;
              $('job-note').hidden = true;
              $('job-result').textContent = u.note ? `${failText} ${sentence(u.note)}` : okText;
              $('job-result').className = u.note ? 'bad' : 'good';
              lastServers = lastTunnels = '';
              refresh();
              return;
            }
          } catch (_) {}
        }
        if ((e.status === 0 || e.status === 404 || e.status === 502 || e.status === 503 || e.status === 504) && restartTries < 25) {
          restartTries++;
          $('job-result').textContent = 'Restarting panel service on the new version, please wait...';
          $('job-result').className = '';
          setTimeout(poll, 1500);
          return;
        }
        $('job-result').textContent = e.message;
        $('job-result').className = 'bad';
        $('job-note').hidden = true;
        return;
      }
      const lines = job.lines || [];
      for (; seen < lines.length; seen++) $('job-log').append(h('li', null, lines[seen]));
      $('job-log').scrollTop = $('job-log').scrollHeight;
      if (!job.done) {
        setTimeout(poll, 1500);
        return;
      }
      await syncMe();
      $('job-note').hidden = true;
      $('job-result').textContent = job.error ? `${failText} ${sentence(job.error)}` : okText;
      $('job-result').className = job.error ? 'bad' : 'good';
      lastServers = lastTunnels = '';
      refresh();
    };
    poll();
  }
  $('job-close').addEventListener('click', () => $('job-dialog').close());

  function showResults(title, results) {
    $('msg-title').textContent = title;
    $('msg-list').replaceChildren(...(results || []).map((r) => h('li', { class: r.ok ? 'good' : 'bad' },
      h('strong', null, r.server + ': '), r.ok ? 'completed.' : sentence(r.error),
      r.manual ? h('p', { class: 'manual' }, 'Manual command: ' + r.manual) : null)));
    openDialog($('msg-dialog'));
    $('msg-close').focus();
  }
  $('msg-close').addEventListener('click', () => $('msg-dialog').close());

  // ---------------------------------------------------------------- tunnels

  async function loadTunnels() {
    const data = await api('GET', '/api/tunnels');
    tunnelsCache = data.tunnels || [];
    updateSummaryStrip();
    const text = JSON.stringify(tunnelsCache);
    if (text === lastTunnels) return;
    lastTunnels = text;
    keepFocus(() => renderTunnels(tunnelsCache));
  }

  function renderTunnels(list) {
    const vpnList = (list || []).filter((t) => !isWebsiteBridge(t));
    const webList = (list || []).filter((t) => isWebsiteBridge(t));
    const box = $('tunnel-list');
    if (box) {
      if (!vpnList.length) {
        box.replaceChildren(h('p', { class: 'empty' },
          'No VPN tunnels yet. Click "+ New Tunnel", or drag a Relay server onto a Foreign server on the Servers tab.'));
      } else {
        box.replaceChildren(...vpnList.map(tunnelCard));
      }
    }
    renderWebsiteBridges(webList);
  }

  const PATH_WORDS = {
    ok: ['ok', 'Healthy'],
    degraded: ['warn', 'Degraded'],
    blocked: ['bad', 'Blocked'],
    unknown: ['unknown', 'Checking...'],
  };

  const expandedTunnels = new Set();

  function shortLinkLabel(any) {
    if (!any) return 'TCP';
    if (any.gre) return 'GRE';
    if (any.sit) return '6in4 (Protocol 41)';
    if (any.ip_spoof) return any.spoof_ip ? `IP Spoof (${any.spoof_ip})` : 'IP Spoof (KCP)';
    if (any.anti_freeze) return 'Split-Stream TLS';
    const raw = String(any.link || any.transport || '');
    if (/source IP spoofing/i.test(raw)) return 'IP Spoof (KCP)';
    if (/6in4/i.test(raw)) return '6in4 (Protocol 41)';
    if (/split-stream/i.test(raw)) return 'Split-Stream TLS';
    if (/FakeTCP/i.test(raw) || any.transport === 'faketcp') return 'FakeTCP · Paqet (KCP)';
    if (/ICMP/i.test(raw) || any.transport === 'icmp') return 'ICMP Ping (KCP)';
    const m = raw.match(/\(([^(),]+)\)/);
    const host = m ? m[1] : '';
    const sniSuffix = any.sni_spoof ? ' + Decoy SNI' : '';
    if (/CDN backup/i.test(raw)) return (host ? `HTTPS (${host}) + CDN` : 'HTTPS + CDN Backup') + sniSuffix;
    if (/gRPC through a CDN/i.test(raw)) return (host ? `gRPC + CDN (${host})` : 'gRPC + CDN') + sniSuffix;
    if (/through a CDN/i.test(raw)) return (host ? `CDN (${host})` : 'CDN (WebSocket)') + sniSuffix;
    if (/gRPC/i.test(raw)) return (host ? `gRPC (${host})` : 'gRPC') + sniSuffix;
    if (/HTTPS site/i.test(raw) || any.transport === 'tls' || any.transport === 'tlsmux') {
      return (host ? `HTTPS (${host})` : 'HTTPS') + sniSuffix;
    }
    if (/KCP/i.test(raw) || any.transport === 'kcp') return 'KCP (UDP)' + sniSuffix;
    if (/website header/i.test(raw)) return (host ? `TCP + HTTP (${host})` : 'TCP + HTTP Header') + sniSuffix;
    if (/plain/i.test(raw) || any.transport === 'tcp' || any.transport === 'tcpmux') return 'Plain TCP' + sniSuffix;
    return (raw.length > 28 ? raw.slice(0, 28) + '…' : (raw || 'TCP')) + sniSuffix;
  }

  function tunnelCard(t) {
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const any = ei || oi || {};
    const reverse = any.mode === 'reverse';
    const shortLink = shortLinkLabel(any);
    const linkPort = (ei && ei.link_port) || (oi && oi.link_port) || 0;
    const userPorts = ei && ei.user_ports && ei.user_ports.length ? ei.user_ports : (oi ? oi.service_ports : null);
    const servicePorts = (oi && oi.service_ports && oi.service_ports.length) ? oi.service_ports : (ei ? ei.service_ports : null);
    const live = (ei && ei.live) || (oi && oi.live) || null;

    const relayBridgeIP = (ei && ei.local_ip) || (oi && oi.peer_ip) || '';
    const foreignBridgeIP = (ei && ei.peer_ip) || (oi && oi.local_ip) || '';
    const isIPv6 = relayBridgeIP.includes(':') || foreignBridgeIP.includes(':');
    const protoTag = isIPv6 ? 'IPv6' : 'IPv4';

    let overall = ['ok', 'Running'];
    const halves = [e, o].filter(Boolean);
    if (halves.some((x) => !x.info.running)) overall = ['bad', 'Stopped'];
    else if (live && live.path_state === 'blocked') overall = ['bad', 'Blocked'];
    else if (halves.some((x) => x.info.problem)) overall = ['warn', 'Warning'];
    else if (live && live.path_state === 'degraded') overall = ['warn', 'Degraded'];
    else if (!e || !o) overall = ['unknown', 'Unpaired'];

    const relayName = e ? (e.server_name || e.address) : (oi && oi.peer_ip ? oi.peer_ip : 'Not in panel');
    const foreignName = o ? (o.server_name || o.address) : (ei && ei.peer_ip ? ei.peer_ip : 'Not in panel');
    const mainPort = ports(userPorts || servicePorts);
    const edgeLive = ei && ei.live ? ei.live : null;
    const uniqueUsers = (edgeLive && typeof edgeLive.active_users === 'number')
      ? (Number(edgeLive.active_users) || 0)
      : (live && typeof live.active_users === 'number' ? (Number(live.active_users) || 0) : 0);
    const activeConns = live ? (Number(live.active_sessions) || 0) : 0;
    const userBadgeText = `${uniqueUsers} ${uniqueUsers === 1 ? 'user' : 'users'} · ${activeConns} ${activeConns === 1 ? 'conn' : 'conns'}`;

    const tunKey = `${t.name}:${e ? e.server_id : ''}:${o ? o.server_id : ''}`;
    const headingId = 'tun-' + t.name + (e ? e.server_id : '') + (o ? o.server_id : '');
    const isOpen = expandedTunnels.has(tunKey);

    // Essential details inside expanded view
    const relayAddr = e && e.address ? e.address : (oi && oi.peer_ip ? oi.peer_ip : '—');
    const foreignAddr = o && o.address ? o.address : (ei && ei.peer_ip ? ei.peer_ip : '—');
    const modeLabel = reverse
      ? `Reverse · ${protoTag} (Foreign → Relay)`
      : `Direct · ${protoTag} (Relay → Foreign)`;
    const combinedLinkDesc = `${(ei && ei.link) || ''} ${(oi && oi.link) || ''}`;
    const extraTags = [];
    if (/fragmented/i.test(combinedLinkDesc)) extraTags.push('Stealth (uTLS + Frag)');
    else if (/browser TLS/i.test(combinedLinkDesc)) extraTags.push('uTLS');
    if (any.sit) extraTags.push('6in4 (Protocol 41)');
    if (any.anti_freeze) extraTags.push('Anti-Freeze (24KB Rotation)');
    if (any.sni_spoof) extraTags.push(`Decoy SNI (${any.spoof_sni || 'challenges.cloudflare.com'})`);
    if (any.ip_spoof) extraTags.push(`Spoof IP (${any.spoof_ip || '104.18.4.130'})`);
    if (any.real_site) extraTags.push('Real-Site Cover');
    if (any.cdn && !/CDN/i.test(shortLink)) extraTags.push('CDN Ready');
    if (any.proxy_protocol && any.proxy_protocol !== 'off') extraTags.push(`PROXY ${any.proxy_protocol}`);
    if (live && live.on_backup_route) extraTags.push('On Backup Route');

    let healthParts = [];
    if (live) {
      const pw = PATH_WORDS[live.path_state] || PATH_WORDS.unknown;
      healthParts.push(pw[1]);
      healthParts.push(`${uniqueUsers} online ${uniqueUsers === 1 ? 'user' : 'users'} (${activeConns} TCP ${activeConns === 1 ? 'conn' : 'conns'})`);
      if (any.mux) {
        healthParts.push(`${live.links || 0}/${live.link_target || any.mux_links || 1} mux links`);
      } else {
        healthParts.push(`${live.parked_spares || 0}/${live.pool_target || any.pool_size || 1} pool ready`);
      }
      if (live.uptime_seconds) healthParts.push(`Up ${duration(live.uptime_seconds)}`);
    } else if (halves.some((x) => x.info.running)) {
      healthParts.push('Syncing live stats...');
    } else {
      healthParts.push('Service stopped');
    }

    const relaySub = isIPv6 && relayBridgeIP
      ? `${relayAddr} · IPv6 [${relayBridgeIP}] · Listen :${ports(userPorts) || '—'}`
      : `${relayAddr} · Listen :${ports(userPorts) || '—'}`;
    const foreignSub = isIPv6 && foreignBridgeIP
      ? `${foreignAddr} · IPv6 [${foreignBridgeIP}] · Inbound :${ports(servicePorts) || '—'}`
      : `${foreignAddr} · Inbound :${ports(servicePorts) || '—'}`;

    const detailsGrid = h('div', { class: 'tunnel-details-grid' },
      h('div', { class: 'detail-item detail-relay' },
        h('span', { class: 'detail-label' }, 'Relay (Iran) · Entry'),
        h('span', { class: 'detail-primary' }, relayName),
        h('span', { class: 'detail-sub mono' }, relaySub)),
      h('div', { class: 'detail-item detail-foreign' },
        h('span', { class: 'detail-label' }, 'Foreign · Exit'),
        h('span', { class: 'detail-primary' }, foreignName),
        h('span', { class: 'detail-sub mono' }, foreignSub)),
      h('div', { class: 'detail-item' },
        h('span', { class: 'detail-label' }, 'Bridge & Transport'),
        h('span', { class: 'detail-primary' }, `${shortLink}${linkPort ? ' · :' + linkPort : ''}${isIPv6 ? ' (IPv6)' : ''}`),
        h('span', { class: 'detail-sub' }, [modeLabel, ...extraTags].join(' · '))),
      h('div', { class: 'detail-item' },
        h('span', { class: 'detail-label' }, 'Health & Capacity'),
        h('span', { class: 'detail-primary' }, healthParts.slice(0, 2).join(' · ')),
        h('span', { class: 'detail-sub' }, healthParts.slice(2).join(' · ') || 'End-to-end tunnel monitor')));

    const problems = halves.filter((x) => x.info.problem).map((x) => `${x.server_name}: ${sentence(x.info.problem)}`);
    if (live && live.path_note && live.path_state !== 'ok') problems.push(sentence(live.path_note));

    const bodyEl = h('div', { class: 'tunnel-body', hidden: !isOpen },
      detailsGrid,
      problems.map((p) => h('p', { class: 'problem' }, p)),
      t.stale ? h('p', { class: 'muted small' }, 'One of the servers cannot be reached right now, so these stats may be cached.') : null,
      tunnelActions(t, halves));

    const ah = t.auto_heal || {};
    let ahBadge = null;
    if (ah.state === 'probing' || ah.state === 'switching') {
      ahBadge = h('span', { class: 'badge badge-autoheal is-healing', title: ah.last_note || 'Auto-healing tunnel...' }, 'Auto-Healing…');
    } else if (ah.enabled) {
      ahBadge = h('span', { class: 'badge badge-autoheal is-on', title: ah.last_note || 'Auto-Heal & Smart Failover enabled' }, 'Auto-Heal: ON');
    }

    const toggleBtn = h('button', {
      type: 'button',
      class: 'tunnel-summary',
      'aria-expanded': String(isOpen),
      'data-focus': `tun-toggle-${tunKey}`,
    },
      h('div', { class: 'tunnel-summary-left' },
        h('span', { class: 'state ' + overall[0] }, overall[1]),
        h('span', { class: 'tunnel-summary-name', id: headingId }, t.name),
        h('span', { class: 'tunnel-summary-route' },
          `${relayName} ↔ ${foreignName}`,
          mainPort ? h('span', { class: 'tunnel-summary-port mono' }, `:${mainPort}`) : null)),
      h('div', { class: 'tunnel-summary-right' },
        ahBadge,
        h('span', { class: 'badge badge-transport' }, `${reverse ? 'Reverse' : 'Direct'}${isIPv6 ? ' (IPv6)' : ''} · ${shortLink}`),
        live ? h('span', { class: 'badge badge-users', title: 'Unique connected client IPs · Active TCP connections' }, userBadgeText) : null,
        h('span', { class: 'tunnel-chevron', 'aria-hidden': 'true' }, '▾')));

    const card = h('article', { class: 'card tunnel' + (isOpen ? ' is-open' : ''), 'aria-labelledby': headingId },
      toggleBtn,
      bodyEl);

    toggleBtn.addEventListener('click', () => {
      const nowOpen = !expandedTunnels.has(tunKey);
      if (nowOpen) expandedTunnels.add(tunKey);
      else expandedTunnels.delete(tunKey);
      card.classList.toggle('is-open', nowOpen);
      toggleBtn.setAttribute('aria-expanded', String(nowOpen));
      bodyEl.hidden = !nowOpen;
    });

    return card;
  }

  function tunnelActions(t, halves) {
    const target = { name: t.name, edge: t.edge ? t.edge.server_id : '', origin: t.origin ? t.origin.server_id : '' };
    const key = `tun-${t.name}-${target.edge}-${target.origin}`;
    const allRunning = halves.length > 0 && halves.every((x) => x.info.running);
    const service = (action, doing) => async (ev) => {
      const btn = ev.currentTarget;
      const orig = btn.textContent;
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.textContent = `${doing}…`;
      setStatus(`${doing} ${t.name}...`);
      try {
        const res = await api('POST', '/api/tunnels/service', { ...target, action });
        const bad = (res.results || []).filter((r) => !r.ok);
        setStatus(bad.length ? '' : `${t.name}: done.`);
        if (bad.length) showResults(`${t.name}: action incomplete`, res.results);
        lastTunnels = '';
        await refresh();
      } catch (e) {
        setStatus(e.message, true);
      } finally {
        btn.classList.remove('is-loading');
        btn.textContent = orig;
        btn.disabled = false;
      }
    };
    const ahOn = !!(t.auto_heal && t.auto_heal.enabled);
    return h('div', { class: 'actions left tunnel-actions' },
      target.edge && target.origin
        ? h('button', {
            type: 'button',
            class: ahOn ? 'btn-autoheal is-on' : 'btn-autoheal',
            'data-focus': key + '-autoheal',
            onclick: () => openTunnelAutoHeal(t)
          }, ahOn ? 'Auto-Heal (ON)' : 'Auto-Heal & Failover')
        : null,
      target.edge ? h('button', { type: 'button', 'data-focus': key + '-edit', onclick: () => openEditTunnel(t) }, 'Edit') : null,
      h('button', { type: 'button', 'data-focus': key + '-diag', onclick: () => openTunnelDiag(t, target) }, 'Diagnose & Speed Test'),
      h('button', { type: 'button', 'data-focus': key + '-logs', onclick: () => openTunnelLogs(t, target) }, 'Logs'),
      h('button', { type: 'button', 'data-focus': key + '-restart', onclick: service('restart', 'Restarting') }, 'Restart'),
      allRunning
        ? h('button', { type: 'button', 'data-focus': key + '-stop', onclick: service('stop', 'Stopping') }, 'Stop')
        : h('button', { type: 'button', 'data-focus': key + '-start', onclick: service('start', 'Starting') }, 'Start'),
      target.edge ? h('button', { type: 'button', 'data-focus': key + '-code', onclick: () => showCode(target) }, 'Pairing Code') : null,
      h('button', { type: 'button', class: 'danger-text', 'data-focus': key + '-delete', onclick: () => confirmDeleteTunnel(t, target) }, 'Delete'));
  }

  // ------------------------------------------------------------- edit tunnel

  let editingTunnel = null;

  function editTunnelLinkKey(any) {
    if (!any) return 'website';
    if (any.gre) return 'gre';
    if (any.sit) return 'sit';
    if (any.ip_spoof) return 'ip-spoof';
    if (any.anti_freeze) return 'split';
    if (any.sni_spoof && !any.cdn) return 'sni-spoof';
    if (any.cdn && any.transport === 'grpc') return 'grpc-cdn';
    if (any.cdn && any.alt_target) return 'website-cdn-backup';
    if (any.cdn) return 'cdn';
    if (['grpc', 'kcp', 'icmp', 'faketcp', 'plain'].includes(any.transport)) return any.transport;
    return 'website';
  }

  function recommendCapacityFor(linkKey, loadPreset) {
    const preset = ['light', 'medium', 'heavy'].includes(loadPreset) ? loadPreset : 'light';
    const isRawKCP = ['icmp', 'faketcp', 'ip-spoof'].includes(linkKey);
    const isCDN = ['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(linkKey);
    const isMuxFirst = ['split', 'grpc', 'kcp'].includes(linkKey);

    if (isRawKCP) {
      if (preset === 'heavy') return { shared: true, muxLinks: 4, pool: 100, maxConn: 8000 };
      if (preset === 'medium') return { shared: true, muxLinks: 2, pool: 50, maxConn: 4000 };
      return { shared: true, muxLinks: 2, pool: 25, maxConn: 2000 };
    }
    if (isCDN) {
      if (preset === 'heavy') return { shared: true, muxLinks: 8, pool: 100, maxConn: 8000 };
      if (preset === 'medium') return { shared: true, muxLinks: 6, pool: 50, maxConn: 4000 };
      return { shared: true, muxLinks: 4, pool: 25, maxConn: 2000 };
    }
    if (isMuxFirst) {
      if (preset === 'heavy') return { shared: true, muxLinks: 16, pool: 120, maxConn: 8000 };
      if (preset === 'medium') return { shared: true, muxLinks: 8, pool: 60, maxConn: 4000 };
      return { shared: true, muxLinks: 4, pool: 30, maxConn: 2000 };
    }
    // Standard direct links: website, sni-spoof, plain, gre, sit
    if (preset === 'heavy') return { shared: true, muxLinks: 16, pool: 120, maxConn: 8000 };
    if (preset === 'medium') return { shared: true, muxLinks: 8, pool: 60, maxConn: 4000 };
    return { shared: false, muxLinks: 4, pool: 30, maxConn: 2000 };
  }

  function detectCapacityPreset(linkKey, isShared, poolSize, muxLinks, maxConn) {
    for (const p of ['light', 'medium', 'heavy']) {
      const rec = recommendCapacityFor(linkKey, p);
      if (rec.shared === isShared && rec.maxConn === maxConn) {
        if (isShared && rec.muxLinks === muxLinks) return p;
        if (!isShared && (rec.pool === poolSize || (p === 'light' && poolSize === 25))) return p;
      }
    }
    return 'custom';
  }

  function describeCapacityAdvice(linkKey, isShared, poolSize, muxLinks, maxConn) {
    const isRawKCP = ['icmp', 'faketcp', 'ip-spoof'].includes(linkKey);
    const isCDN = ['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(linkKey);
    const sessions = (maxConn || 2000).toLocaleString();
    if (isRawKCP) {
      if (!isShared) {
        return `⚠ Note: Raw packet modes (ICMP, FakeTCP, IP-Spoof) work best with Multiplexed Shared Links (Mux) using 2–4 links to avoid raw-socket contention.`;
      }
      return `✓ Recommended for raw packet transport: ${muxLinks || 2} Multiplexed Shared Link(s) carry up to ${sessions} concurrent user sessions smoothly without raw-socket overhead.`;
    }
    if (isCDN) {
      if (!isShared) {
        return `⚠ Note: Opening ${poolSize || 25} separate pool connections through a CDN can trigger Cloudflare rate limits. Multiplexed Shared Links (4–8 links) is recommended for CDN tunnels.`;
      }
      return `✓ Recommended for CDN transport: ${muxLinks || 4} Multiplexed Shared links avoid Cloudflare connection-rate limits while serving up to ${sessions} concurrent sessions.`;
    }
    if (isShared) {
      return `✓ Multiplexed Shared Links (${muxLinks || 4} parallel trunks, up to ${sessions} sessions): All users share ${muxLinks || 4} persistent encrypted connections — best for 30–500+ concurrent users because it prevents connection spikes and avoids head-of-line blocking.`;
    }
    return `✓ Dedicated Connection Pool (${poolSize || 30} pre-warmed spare links, up to ${sessions} sessions): Each user session gets its own dedicated bridge connection — lowest latency for 1–30 users on clean links. For 30+ concurrent users, switch to Multiplexed Shared Links (Mux).`;
  }

  function currentEditLinkKey() {
    if (!editingTunnel) return 'website';
    const e = editingTunnel.edge, o = editingTunnel.origin;
    const any = (e && e.info) || (o && o.info) || {};
    return editTunnelLinkKey(any);
  }

  function syncEditTunnelCapacityUI() {
    const isMux = radio('et-shared') === 'shared';
    if ($('et-pool-wrap')) $('et-pool-wrap').hidden = isMux;
    if ($('et-mux-wrap')) $('et-mux-wrap').hidden = !isMux;
    if ($('et-spare-ttl-wrap')) $('et-spare-ttl-wrap').hidden = isMux;
    if ($('et-capacity-hint')) {
      const poolSize = Number(($('et-pool') && $('et-pool').value) || 30);
      const muxLinks = Number(($('et-mux-links') && $('et-mux-links').value) || 4);
      const maxConn = Number(($('et-max-conn') && $('et-max-conn').value) || 2000);
      $('et-capacity-hint').textContent = describeCapacityAdvice(currentEditLinkKey(), isMux, poolSize, muxLinks, maxConn);
    }
    syncChoiceCards($('edit-tunnel-dialog'));
  }

  function openEditTunnel(t) {
    editingTunnel = t;
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const any = ei || oi || {};
    const servicePorts = (oi && oi.service_ports && oi.service_ports.length) ? oi.service_ports : (ei ? ei.service_ports : []);
    const userPorts = (ei && ei.user_ports && ei.user_ports.length) ? ei.user_ports : servicePorts;
    const linkPort = (ei && ei.link_port) || (oi && oi.link_port) || 443;
    const isMux = !!any.mux;
    const poolVal = (ei && ei.pool_size) || (oi && oi.pool_size) || 30;
    const muxVal = (ei && ei.mux_links) || (oi && oi.mux_links) || 4;
    const maxConnVal = (ei && ei.max_conn) || (oi && oi.max_conn) || 2000;

    $('et-title').textContent = `Edit Tunnel: ${t.name}`;
    const where = [e && e.server_name, o && o.server_name].filter(Boolean).join(' ↔ ');
    $('et-sub').textContent = where
      ? `Update ports, capacity, or firewall settings across ${where}. Both servers will restart automatically.`
      : 'Update ports, capacity, or firewall settings for this tunnel.';

    $('et-service').value = (servicePorts || []).join(',');
    $('et-users').value = (userPorts || []).join(',') === (servicePorts || []).join(',') ? '' : (userPorts || []).join(',');
    $('et-linkport').value = String(linkPort);

    setRadio('et-shared', isMux ? 'shared' : 'one');
    $('et-pool').value = String(poolVal);
    $('et-mux-links').value = String(muxVal);
    $('et-max-conn').value = String(maxConnVal);
    const linkKey = editTunnelLinkKey(any);
    setRadio('et-load', detectCapacityPreset(linkKey, isMux, Number(poolVal), Number(muxVal), Number(maxConnVal)));

    const pp = (ei && ei.proxy_protocol) || (oi && oi.proxy_protocol) || 'off';
    setRadio('et-proxy', ['off', 'v1', 'v2'].includes(pp) ? pp : 'off');

    const fw = ei && typeof ei.firewall === 'boolean' ? ei.firewall : true;
    $('et-firewall').checked = fw;

    if ($('et-peer-ip')) $('et-peer-ip').value = (ei && ei.peer_ip) || (oi && oi.peer_ip) || '';
    if ($('et-peer-wrap')) $('et-peer-wrap').hidden = !!(any.gre || any.sit);
    if ($('et-spare-ttl')) $('et-spare-ttl').value = (ei && ei.spare_ttl) || (oi && oi.spare_ttl) || '1m0s';
    if ($('et-drain')) $('et-drain').value = (ei && ei.drain) || (oi && oi.drain) || '10s';
    if ($('et-advanced')) $('et-advanced').open = false;

    syncEditTunnelCapacityUI();

    $('et-error').textContent = '';
    $('et-ports-result').replaceChildren();
    $('edit-tunnel-form').hidden = false;
    $('et-progress').hidden = true;
    openDialog($('edit-tunnel-dialog'));
    $('et-service').focus();
  }

  for (const el of document.querySelectorAll('input[name="et-load"]')) {
    el.addEventListener('change', () => {
      const preset = radio('et-load');
      if (preset && preset !== 'custom') {
        const rec = recommendCapacityFor(currentEditLinkKey(), preset);
        setRadio('et-shared', rec.shared ? 'shared' : 'one');
        if ($('et-pool')) $('et-pool').value = String(rec.pool);
        if ($('et-mux-links')) $('et-mux-links').value = String(rec.muxLinks);
        if ($('et-max-conn')) $('et-max-conn').value = String(rec.maxConn);
      }
      syncEditTunnelCapacityUI();
    });
  }
  for (const el of document.querySelectorAll('input[name="et-shared"]')) {
    el.addEventListener('change', () => {
      setRadio('et-load', 'custom');
      syncEditTunnelCapacityUI();
    });
  }
  for (const id of ['et-pool', 'et-mux-links', 'et-max-conn']) {
    if ($(id)) {
      $(id).addEventListener('input', () => {
        setRadio('et-load', 'custom');
        syncEditTunnelCapacityUI();
      });
    }
  }
  for (const el of document.querySelectorAll('input[name="et-proxy"]')) {
    el.addEventListener('change', () => syncChoiceCards($('edit-tunnel-dialog')));
  }

  $('et-cancel').addEventListener('click', () => $('edit-tunnel-dialog').close());
  $('et-close').addEventListener('click', () => $('edit-tunnel-dialog').close());
  $('et-back').addEventListener('click', () => {
    $('et-progress').hidden = true;
    $('edit-tunnel-form').hidden = false;
    $('et-service').focus();
  });

  const CDN_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const CDN_OTHER_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const ALL_CDN_PORTS = [...CDN_HTTPS_PORTS, ...CDN_OTHER_PORTS];

  async function scanCDNPorts(relayId, foreignId, mode, ownTag, outEl, linkInput) {
    outEl.replaceChildren(h('li', null, 'Scanning Cloudflare & CDN ports on both servers...'));
    const portStr = ALL_CDN_PORTS.join(',');
    const fetchMap = async (srvId) => {
      if (!srvId) return null;
      try {
        const res = await api('POST', '/api/ports', { server: srvId, ports: portStr });
        const map = {};
        for (const p of (res.ports || [])) map[p.port] = p;
        return map;
      } catch (e) {
        return null;
      }
    };
    const [rMap, fMap] = await Promise.all([fetchMap(relayId), fetchMap(foreignId)]);
    if (!rMap && !fMap) {
      outEl.replaceChildren(h('li', { class: 'bad' }, 'Could not query ports on either server.'));
      return;
    }
    const items = ALL_CDN_PORTS.map((port) => {
      const rp = rMap ? rMap[port] : null;
      const fp = fMap ? fMap[port] : null;
      const rFree = rp && (rp.state === 'free' || (ownTag && rp.by === ownTag));
      const fFree = fp && (fp.state === 'free' || (ownTag && fp.by === ownTag));
      const isCF = CDN_HTTPS_PORTS.includes(port);
      const cdnLabel = isCF ? 'Cloudflare HTTPS' : 'Other CDN';
      const needFree = mode === 'direct' ? fFree : rFree;
      const bothFree = (!rMap || rFree) && (!fMap || fFree);
      let cls = 'bad';
      let statusText = 'Busy';
      if (bothFree) {
        cls = 'good';
        statusText = 'Free on both servers';
      } else if (needFree) {
        cls = 'good';
        statusText = mode === 'direct' ? 'Usable (free on Foreign)' : 'Usable (free on Relay)';
      } else {
        const rDesc = rp ? rp.state : '—';
        const fDesc = fp ? fp.state : '—';
        statusText = `Relay: ${rDesc} · Foreign: ${fDesc}`;
      }
      const useBtn = (bothFree || needFree) && linkInput
        ? h('button', {
            type: 'button',
            class: 'use-port-btn',
            onclick: () => { linkInput.value = String(port); linkInput.focus(); }
          }, `Use :${port}`)
        : null;
      return h('li', { class: cls },
        h('strong', { class: 'mono' }, `Port ${port}`),
        ` (${cdnLabel}) — ${statusText}`,
        useBtn);
    });
    outEl.replaceChildren(...items);
  }

  if ($('et-scan-cdn')) {
    $('et-scan-cdn').addEventListener('click', () => {
      if (!editingTunnel) return;
      const t = editingTunnel;
      const e = t.edge, o = t.origin;
      const any = (e && e.info) || (o && o.info) || {};
      scanCDNPorts(
        e ? e.server_id : '',
        o ? o.server_id : '',
        any.mode || 'reverse',
        `PortBridge tunnel "${t.name}"`,
        $('et-ports-result'),
        $('et-linkport')
      );
    });
  }

  $('et-check').addEventListener('click', async () => {
    if (!editingTunnel) return;
    const t = editingTunnel;
    const e = t.edge, o = t.origin;
    const any = (e && e.info) || (o && o.info) || {};
    const mode = any.mode || 'reverse';
    const servicePorts = $('et-service').value.trim();
    const userPorts = $('et-users').value.trim() || servicePorts;
    const linkPort = Number($('et-linkport').value || 0);
    const out = $('et-ports-result');
    if (!portList.test(servicePorts) || !portList.test(userPorts) || !linkPort) {
      out.replaceChildren(h('li', { class: 'bad' }, 'Enter valid Inbound Port(s) and Tunnel Bridge Port first.'));
      return;
    }
    out.replaceChildren(h('li', null, 'Checking ports on servers...'));
    const relayPorts = userPorts + (mode === 'reverse' ? ',' + linkPort : '');
    const foreignPorts = servicePorts + (mode === 'direct' ? ',' + linkPort : '');
    const ownTag = `PortBridge tunnel "${t.name}"`;
    const describe = async (half, list, role) => {
      if (!half) return [];
      const sName = half.server_name || half.server_id;
      try {
        const res = await api('POST', '/api/ports', { server: half.server_id, ports: list });
        return res.ports.map((p) => {
          let what = 'User listen port';
          if (p.port === linkPort && ((role === 'relay' && mode === 'reverse') || (role === 'foreign' && mode === 'direct'))) what = 'Tunnel bridge port';
          else if (role === 'foreign') what = 'Inbound port';
          const isSelf = p.by === ownTag;
          const by = p.by ? ` (${p.by.replace(/^PortBridge /, '')})` : '';
          let cls = 'good', text;
          if (what === 'Inbound port') {
            text = p.state === 'free' ? 'no service is listening on this port yet (is your X-UI / inbound running?)' : `active service listening${by} (ready)`;
            if (p.state === 'free') cls = 'warn';
            if (/^PortBridge tunnel/.test(p.by || '') && !isSelf) { cls = 'bad'; text = `already used by ${p.by.replace(/^PortBridge /, '')}`; }
          } else if (isSelf || p.state === 'free') {
            text = isSelf ? `currently used by this tunnel "${t.name}" (will be kept)` : 'available (free)';
            cls = 'good';
          } else {
            text = `${p.state}${by}`;
            cls = 'bad';
          }
          return h('li', { class: cls }, `${sName} — ${what} ${p.port}: ${text}`);
        });
      } catch (err) {
        return [h('li', { class: 'warn' }, `${sName}: could not check ports (${err.message})`)];
      }
    };
    const [a, b] = await Promise.all([describe(e, relayPorts, 'relay'), describe(o, foreignPorts, 'foreign')]);
    out.replaceChildren(...a, ...b);
  });

  $('edit-tunnel-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!editingTunnel) return;
    const t = editingTunnel;
    const err = $('et-error');
    err.textContent = '';
    const fail = (msg, el) => { err.textContent = msg; if (el) el.focus(); };

    const servicePorts = $('et-service').value.trim();
    const userPorts = $('et-users').value.trim();
    const linkPort = Number($('et-linkport').value || 0);
    const isMux = radio('et-shared') === 'shared';
    const poolSize = Number($('et-pool').value || 0);
    const muxLinks = Number($('et-mux-links').value || 0);
    const maxConn = Number($('et-max-conn').value || 0);
    const proxyProto = radio('et-proxy') || 'off';
    const firewall = $('et-firewall').checked ? 'on' : 'off';
    const peerIP = $('et-peer-ip') ? $('et-peer-ip').value.trim() : '';
    const spareTTL = ($('et-spare-ttl') && !isMux) ? $('et-spare-ttl').value.trim() : '';
    const drain = $('et-drain') ? $('et-drain').value.trim() : '';

    if (!portList.test(servicePorts)) return fail('Enter the Foreign Inbound Port(s), separated by commas.', $('et-service'));
    if (userPorts && !portList.test(userPorts)) return fail('Enter the Relay User Listen Port(s) separated by commas, or leave empty to match Inbound Port(s).', $('et-users'));
    if (userPorts && userPorts.split(',').length !== servicePorts.split(',').length) {
      return fail('The number of User Listen Ports must match the number of Inbound Ports.', $('et-users'));
    }
    if (!(linkPort >= 1 && linkPort <= 65535)) return fail('Tunnel Bridge Port must be between 1 and 65535.', $('et-linkport'));
    if (!isMux && !(poolSize >= 1 && poolSize <= 10000)) return fail('Connection Pool Size must be between 1 and 10000.', $('et-pool'));
    if (isMux && !(muxLinks >= 1 && muxLinks <= 16)) return fail('Shared Mux Connections must be between 1 and 16.', $('et-mux-links'));
    if (!(maxConn >= 1 && maxConn <= 100000)) return fail('Max Concurrent User Sessions must be between 1 and 100000.', $('et-max-conn'));

    const body = {
      name: t.name,
      edge: t.edge ? t.edge.server_id : '',
      origin: t.origin ? t.origin.server_id : '',
      service_ports: servicePorts,
      user_ports: userPorts || servicePorts,
      link_port: linkPort,
      mux: isMux ? 'on' : 'off',
      pool: !isMux ? poolSize : 0,
      mux_links: isMux ? muxLinks : 0,
      max_conn: maxConn,
      spare_ttl: spareTTL,
      drain,
      peer_ip: peerIP,
      proxy_protocol: proxyProto,
      firewall,
    };

    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const res = await api('POST', '/api/tunnels/edit', body);
      followEditTunnelJob(res.job, t.name);
    } catch (e) {
      fail(e.message);
    } finally {
      btn.disabled = false;
    }
  });

  function followEditTunnelJob(id, name) {
    $('edit-tunnel-form').hidden = true;
    $('et-progress').hidden = false;
    $('et-log').replaceChildren();
    $('et-result').textContent = 'Applying updated settings...';
    $('et-result').className = '';
    $('et-back').hidden = true;
    $('et-progress-title').focus();
    let seen = 0;
    const poll = async () => {
      let job;
      try {
        job = await api('GET', '/api/jobs/' + encodeURIComponent(id));
      } catch (e) {
        if (e.status === 401) return;
        $('et-result').textContent = e.message;
        $('et-result').className = 'bad';
        return;
      }
      const lines = job.lines || [];
      for (; seen < lines.length; seen++) $('et-log').append(h('li', null, lines[seen]));
      $('et-log').scrollTop = $('et-log').scrollHeight;
      if (!job.done) {
        setTimeout(poll, 1000);
        return;
      }
      if (job.error) {
        $('et-result').textContent = 'Could not update tunnel. ' + sentence(job.error);
        $('et-result').className = 'bad';
        $('et-back').hidden = false;
      } else {
        $('et-result').textContent = `Success: tunnel "${name}" has been updated and restarted.`;
        $('et-result').className = 'good';
      }
      lastTunnels = lastServers = '';
      refresh();
    };
    poll();
  }

  // ------------------------------------------------------------- tunnel logs

  let activeLogsTarget = null;

  async function loadTunnelLogs() {
    if (!activeLogsTarget) return;
    const btn = $('logs-refresh');
    btn.disabled = true;
    $('logs-body').replaceChildren(h('p', { class: 'muted' }, 'Fetching recent service logs...'));
    try {
      const res = await api('POST', '/api/tunnels/logs', activeLogsTarget);
      const list = res.results || res.logs || [];
      const panes = list.map((entry) =>
        h('div', { class: 'log-pane' },
          h('div', { class: 'log-pane-head' },
            h('span', null, `${entry.server} (${entry.role})`),
            entry.ok ? h('span', { class: 'state ok' }, 'Loaded') : h('span', { class: 'state bad' }, 'Unavailable')),
          h('pre', { class: 'log-view' }, entry.ok ? (entry.logs || 'No log entries yet.') : sentence(entry.error))));
      $('logs-body').replaceChildren(...(panes.length ? panes : [h('p', { class: 'muted' }, 'No logs available.')]));
    } catch (e) {
      $('logs-body').replaceChildren(h('p', { class: 'error' }, e.message));
    } finally {
      btn.disabled = false;
    }
  }

  function openTunnelLogs(t, target) {
    activeLogsTarget = target;
    $('logs-title').textContent = `Logs: ${t.name}`;
    openDialog($('logs-dialog'));
    loadTunnelLogs();
    $('logs-close').focus();
  }

  $('logs-refresh').addEventListener('click', loadTunnelLogs);
  $('logs-close').addEventListener('click', () => $('logs-dialog').close());

  // ----------------------------------------- tunnel diagnostics & speed test

  let activeDiagTarget = null;

  async function runTunnelChecks() {
    if (!activeDiagTarget) return;
    const btn = $('diag-refresh');
    btn.disabled = true;
    $('diag-checks').replaceChildren(h('p', { class: 'muted' }, 'Running live diagnostic checks on both servers...'));
    try {
      const res = await api('POST', '/api/tunnels/check', activeDiagTarget);
      const list = res.results || res.reports || [];
      const cols = list.map((rep) => {
        if (!rep.ok && rep.error && !(rep.checks && rep.checks.length)) {
          return h('div', { class: 'diag-col' },
            h('div', { class: 'diag-col-head' },
              h('span', null, `${rep.server} (${rep.role})`),
              h('span', { class: 'state bad' }, 'Error')),
            h('p', { class: 'error' }, sentence(rep.error)));
        }
        const rawChecks = rep.checks || [];
        const dialsOut = rawChecks.some((c) => c.label === 'Peer bridge port');
        const checks = rawChecks.filter((c) => !(dialsOut && c.label === 'Bridge port firewall'));
        const hasBad = checks.some((c) => c.status === 'bad');
        const hasWarn = checks.some((c) => c.status === 'warn');
        const headState = hasBad ? ['bad', 'Needs Attention'] : (hasWarn ? ['warn', 'Warning'] : ['ok', 'Healthy']);
        const items = checks.map((c) => {
          const isFwLocked = c.label === 'Bridge port firewall' && /^Enabled/i.test(c.detail || '');
          const effStatus = isFwLocked ? 'ok' : c.status;
          const st = effStatus === 'ok'
            ? ['ok', 'OK']
            : (effStatus === 'warn'
              ? ['warn', 'Warning']
              : (effStatus === 'note' ? ['note', 'Info'] : ['bad', 'Problem']));
          return h('li', { class: 'check-item ' + st[0] },
            h('div', { class: 'check-item-top' },
              h('span', null, c.label),
              h('span', { class: 'state ' + st[0] }, st[1])),
            c.detail ? h('div', { class: 'check-item-detail' }, c.detail) : null,
            c.note ? h('div', { class: 'check-item-detail muted' }, c.note) : null);
        });
        return h('div', { class: 'diag-col' },
          h('div', { class: 'diag-col-head' },
            h('span', null, `${rep.server} (${rep.role})`),
            h('span', { class: 'state ' + headState[0] }, headState[1])),
          h('ul', { class: 'check-list' }, items));
      });
      $('diag-checks').replaceChildren(...(cols.length ? cols : [h('p', { class: 'muted' }, 'No diagnostic data returned.')]));
    } catch (e) {
      $('diag-checks').replaceChildren(h('p', { class: 'error' }, e.message));
    } finally {
      btn.disabled = false;
    }
  }

  function openTunnelDiag(t, target) {
    activeDiagTarget = target;
    $('diag-title').textContent = `Diagnose & Speed Test: ${t.name}`;
    const where = [t.edge && t.edge.server_name, t.origin && t.origin.server_name].filter(Boolean).join(' ↔ ');
    if ($('diag-sub')) {
      $('diag-sub').textContent = where ? `Health verification and throughput testing across ${where}.` : 'Health verification and throughput testing.';
    }
    $('speedtest-out').hidden = true;
    $('speedtest-out').textContent = '';
    if ($('speedtest-error')) $('speedtest-error').textContent = '';
    openDialog($('diag-dialog'));
    runTunnelChecks();
    $('diag-close').focus();
  }

  $('diag-refresh').addEventListener('click', runTunnelChecks);
  $('diag-close').addEventListener('click', () => $('diag-dialog').close());

  $('speedtest-run').addEventListener('click', async () => {
    if (!activeDiagTarget) return;
    const btn = $('speedtest-run');
    const out = $('speedtest-out');
    const err = $('speedtest-error');
    btn.disabled = true;
    if (err) err.textContent = '';
    out.hidden = false;
    out.textContent = `Running latency, download & upload speed test through tunnel "${activeDiagTarget.name}"...\nPlease wait (up to 15–30 seconds)...`;
    try {
      const res = await api('POST', '/api/tunnels/speedtest', activeDiagTarget);
      out.textContent = res.output || 'Speed test finished.';
    } catch (e) {
      out.hidden = true;
      if (err) err.textContent = e.message;
    } finally {
      btn.disabled = false;
    }
  });

  // ------------------------------------------------ server speed tuning (BBR)

  let tuningServer = null;

  function renderTuneDialog(info) {
    const banner = $('tune-banner');
    banner.hidden = false;
    const tunedByPB = !!(info.tuned_by_pb || info.tuned_by_portbridge);
    if (info.bbr_active) {
      banner.className = 'notice';
      banner.replaceChildren(
        h('strong', null, 'BBR TCP Acceleration is Active. '),
        h('span', null, tunedByPB
          ? 'This server is tuned by PortBridge with BBR congestion control and enlarged socket buffers.'
          : 'BBR congestion control is already enabled on this server by the operating system.'));
    } else {
      banner.className = 'notice update';
      banner.replaceChildren(
        h('strong', null, 'Standard TCP Congestion Control. '),
        h('span', null, 'Enabling BBR & buffer tuning can significantly improve throughput and stability over long-distance or lossy links.'));
    }

    const rows = [];
    const row = (k, v) => rows.push(h('dt', null, k), h('dd', { class: 'mono' }, v || '—'));
    row('TCP Congestion Control', info.congestion_control || '—');
    row('Default Queue Discipline', info.qdisc || '—');
    row('Max Socket Buffer (rmem_max / wmem_max)', `${info.rmem_max || '—'} / ${info.wmem_max || '—'}`);
    row('Managed by PortBridge', tunedByPB ? 'Yes (/etc/sysctl.d/99-portbridge-tuning.conf)' : 'No');
    $('tune-facts').replaceChildren(...rows);

    $('tune-enable').hidden = !!info.bbr_active && tunedByPB;
    $('tune-disable').hidden = !tunedByPB;
  }

  async function openServerTune(s) {
    tuningServer = s;
    $('tune-title').textContent = `Speed Tuning (BBR): ${s.name || s.address}`;
    if ($('tune-sub')) {
      $('tune-sub').textContent = 'Google BBR congestion control and high-throughput TCP socket buffers for long-distance links.';
    }
    if ($('tune-error')) $('tune-error').textContent = '';
    $('tune-banner').hidden = true;
    $('tune-facts').replaceChildren(h('dt', null, 'Status'), h('dd', null, 'Reading kernel TCP settings...'));
    $('tune-enable').hidden = true;
    $('tune-disable').hidden = true;
    openDialog($('tune-dialog'));
    $('tune-close').focus();
    try {
      const info = await api('GET', '/api/servers/' + encodeURIComponent(s.id) + '/tune');
      renderTuneDialog(info);
    } catch (e) {
      $('tune-facts').replaceChildren();
      if ($('tune-error')) $('tune-error').textContent = e.message;
    }
  }

  async function applyServerTune(enable) {
    if (!tuningServer) return;
    const btn = enable ? $('tune-enable') : $('tune-disable');
    btn.disabled = true;
    if ($('tune-error')) $('tune-error').textContent = '';
    try {
      const info = await api('POST', '/api/servers/' + encodeURIComponent(tuningServer.id) + '/tune', { enable });
      renderTuneDialog(info);
      lastServers = '';
      refresh();
    } catch (e) {
      if ($('tune-error')) $('tune-error').textContent = e.message;
    } finally {
      btn.disabled = false;
    }
  }

  $('tune-enable').addEventListener('click', () => applyServerTune(true));
  $('tune-disable').addEventListener('click', () => applyServerTune(false));
  $('tune-close').addEventListener('click', () => $('tune-dialog').close());

  // ------------------------------------------------ server firewall manager

  let firewallServer = null;

  function renderFirewallDialog(info) {
    if ($('fw-status')) {
      $('fw-status').textContent = (info && info.status) || 'No firewall rules reported.';
    }
    if ($('fw-msg')) {
      if (info && info.output) {
        $('fw-msg').hidden = false;
        $('fw-msg').textContent = info.output;
      } else {
        $('fw-msg').hidden = true;
        $('fw-msg').textContent = '';
      }
    }
  }

  async function openServerFirewall(s) {
    firewallServer = s;
    $('fw-title').textContent = `Bridge Port Firewall: ${s.name || s.address}`;
    if ($('fw-error')) $('fw-error').textContent = '';
    if ($('fw-msg')) { $('fw-msg').hidden = true; $('fw-msg').textContent = ''; }
    if ($('fw-status')) $('fw-status').textContent = 'Reading firewall rules...';
    openDialog($('fw-dialog'));
    $('fw-close').focus();
    try {
      const info = await api('GET', '/api/servers/' + encodeURIComponent(s.id) + '/firewall');
      renderFirewallDialog(info);
    } catch (e) {
      if ($('fw-status')) $('fw-status').textContent = '';
      if ($('fw-error')) $('fw-error').textContent = e.message;
    }
  }

  async function applyServerFirewall(action) {
    if (!firewallServer) return;
    const btns = [$('fw-sweep'), $('fw-on-all'), $('fw-off-all')].filter(Boolean);
    for (const b of btns) b.disabled = true;
    if ($('fw-error')) $('fw-error').textContent = '';
    try {
      const info = await api('POST', '/api/servers/' + encodeURIComponent(firewallServer.id) + '/firewall', { action });
      renderFirewallDialog(info);
      lastServers = lastTunnels = '';
      refresh();
    } catch (e) {
      if ($('fw-error')) $('fw-error').textContent = e.message;
    } finally {
      for (const b of btns) b.disabled = false;
    }
  }

  if ($('fw-sweep')) $('fw-sweep').addEventListener('click', () => applyServerFirewall('sweep'));
  if ($('fw-on-all')) $('fw-on-all').addEventListener('click', () => applyServerFirewall('on-all'));
  if ($('fw-off-all')) $('fw-off-all').addEventListener('click', () => applyServerFirewall('off-all'));
  if ($('fw-close')) $('fw-close').addEventListener('click', () => $('fw-dialog').close());

  async function showCode(target) {
    try {
      const res = await api('POST', '/api/tunnels/code', target);
      $('code-text').value = res.code;
      $('code-msg').textContent = '';
      openDialog($('code-dialog'));
      $('code-text').select();
    } catch (e) {
      setStatus(e.message, true);
    }
  }
  $('code-close').addEventListener('click', () => {
    $('code-text').value = '';
    $('code-dialog').close();
  });
  $('code-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('code-text').value);
      $('code-msg').textContent = 'Copied to clipboard.';
    } catch (e) {
      $('code-text').select();
      $('code-msg').textContent = 'Press Ctrl+C (or Cmd+C) to copy the selected code.';
    }
  });

  function confirmDeleteTunnel(t, target) {
    const where = [t.edge && t.edge.server_name, t.origin && t.origin.server_name].filter(Boolean).join(' and ');
    openConfirm(`Delete tunnel "${t.name}"?`,
      `This stops and deletes "${t.name}" from ${where}. Active user connections on this tunnel will be closed. This cannot be undone.`,
      'Delete Tunnel',
      async () => {
        const res = await api('POST', '/api/tunnels/delete', target);
        lastTunnels = lastServers = '';
        await refresh();
        const bad = (res.results || []).filter((r) => !r.ok);
        if (bad.length) {
          $('confirm-dialog').close();
          showResults(`${t.name} could not be removed everywhere`, res.results);
        } else {
          setStatus(`Tunnel "${t.name}" deleted from ${where}.`);
        }
      });
  }

  // --------------------------------------------------------------- settings

  async function loadSettings() {
    const [info] = await Promise.all([api('GET', '/api/panel'), loadUpdates()]);
    const rows = [];
    const row = (k, v) => rows.push(h('dt', null, k), h('dd', null, v));
    row('Panel Version', info.version || '');
    row('Panel URL(s)', (info.addresses || []).length
      ? h('span', null, ...info.addresses.map((a, i) => [i ? h('br') : null, a])) : '—');
    const c = info.certificate || {};
    if (c.real) {
      const until = c.until ? new Date(c.until).toLocaleDateString() : '';
      row('SSL Certificate', `Valid certificate for ${c.domain} (${c.issuer || 'Let\'s Encrypt'}), expires ${until}. Auto-renews.`);
    } else {
      row('SSL Certificate', c.domain
        ? `Self-signed for now. Certificate for ${c.domain}: ${sentence(c.note)}`
        : 'Self-signed certificate. Configure a domain name in the CLI menu on this server to get a trusted Let\'s Encrypt certificate.');
    }
    row('Cert Fingerprint', h('span', { class: 'mono' }, info.fingerprint || ''));
    row('Agent Callback URL', info.public_url || 'Not configured (can be set in the CLI menu on this server)');
    $('panel-info').replaceChildren(...rows);
    if (!$('acc-user').value) $('acc-user').value = currentUser;
  }

  $('account-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const msg = $('acc-msg');
    msg.className = '';
    msg.textContent = '';
    const current = $('acc-current').value;
    const user = $('acc-user').value.trim();
    const pw = $('acc-new').value;
    const again = $('acc-again').value;
    const fail = (text, el) => {
      msg.className = 'error';
      msg.textContent = text;
      if (el) el.focus();
    };
    if (!current) return fail('Enter your current password.', $('acc-current'));
    if (!user) return fail('Username cannot be empty.', $('acc-user'));
    if (pw && pw.length < 10) return fail('New password must be at least 10 characters.', $('acc-new'));
    if (pw !== again) return fail('The two new passwords do not match.', $('acc-again'));
    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const res = await api('POST', '/api/account', { current_password: current, new_user: user, new_password: pw });
      csrf = res.csrf;
      currentUser = res.user;
      $('acc-current').value = $('acc-new').value = $('acc-again').value = '';
      msg.className = 'okay';
      msg.textContent = 'Credentials updated. Use the new login next time you sign in.';
    } catch (e) {
      fail(e.message);
    } finally {
      btn.disabled = false;
    }
  });

  // ------------------------------------------------------------- new tunnel

  const radio = (name) => {
    const c = document.querySelector(`input[name="${name}"]:checked`);
    return c ? c.value : '';
  };
  const setRadio = (name, value) => {
    for (const r of document.querySelectorAll(`input[name="${name}"]`)) r.checked = r.value === value;
  };
  let sharingTouched = false;

  function serverOption(s) {
    return h('option', { value: s.id }, `${s.name || s.address}${s.address ? ' (' + s.address + ')' : ''}${s.online ? '' : ' — offline'}`);
  }

  function serverById(id) {
    return serversCache.find((s) => s.id === id);
  }

  function hasIPv6(s) {
    const ov = s && s.overview;
    return !!(ov && ov.ipv6 && ov.ipv6.length);
  }

  // ------------------------------------------------------- cloudflare dns

  let cfAccounts = [];
  let cfZones = [];
  let cfRecords = [];
  let editingCFRecord = null;

  function makeCloudIcon() {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('class', 'cf-proxy-cloud');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(svgNS, 'path');
    path.setAttribute('d', 'M18.42 9.22A7 7 0 0 0 5.06 11a4.5 4.5 0 0 0 .44 8.98h12.5a4.5 4.5 0 0 0 .42-8.98z');
    svg.append(path);
    return svg;
  }

  function currentCFZone() {
    const sel = $('cf-zone-select');
    const id = sel ? sel.value : '';
    return cfZones.find((z) => z.id === id) || cfZones[0] || null;
  }

  function serverMatchingIP(ip) {
    if (!ip) return null;
    const clean = String(ip).trim().toLowerCase();
    for (const s of serversCache) {
      if (s.address && s.address.toLowerCase() === clean) return s;
      const ov = s.overview;
      if (ov) {
        if ((ov.ipv4 || []).some((v) => String(v).toLowerCase() === clean)) return s;
        if ((ov.ipv6 || []).some((v) => String(v).toLowerCase() === clean)) return s;
      }
    }
    return null;
  }

  function renderCFAccountsBar() {
    const bar = $('cf-accounts-bar');
    if (!bar) return;
    if (!cfAccounts.length) {
      bar.hidden = true;
      bar.replaceChildren();
      return;
    }
    bar.hidden = false;
    const pills = cfAccounts.map((a) => h('div', { class: 'cf-account-pill' },
      h('span', { class: 'cf-dot', 'aria-hidden': 'true' }),
      h('strong', null, a.name || 'Cloudflare'),
      h('span', { class: 'cf-hint' }, a.hint || '••••'),
      h('button', {
        type: 'button',
        class: 'cf-del-acct danger-text',
        title: 'Remove this Cloudflare API token',
        onclick: () => openConfirm(
          `Remove "${a.name || 'Cloudflare'}" API token?`,
          'This removes the encrypted Cloudflare API token from the panel. Your DNS records on Cloudflare are not touched.',
          'Remove Token',
          async () => {
            await api('DELETE', '/api/cf/accounts/' + encodeURIComponent(a.id));
            cfLoadedOnce = false;
            await loadCloudflare(true);
            setStatus('Cloudflare API token removed.');
          }
        )
      }, 'Remove')));
    bar.replaceChildren(...pills);
  }

  async function loadCloudflare(force) {
    if (!force && cfLoadedOnce) return;
    if ($('cf-error')) $('cf-error').textContent = '';
    const acctData = await api('GET', '/api/cf/accounts');
    cfAccounts = acctData.accounts || [];
    renderCFAccountsBar();

    const cz = $('count-zones');
    if (!cfAccounts.length) {
      cfZones = [];
      cfRecords = [];
      if (cz) cz.hidden = true;
      if ($('cf-empty')) $('cf-empty').hidden = false;
      if ($('cf-workspace')) $('cf-workspace').hidden = true;
      if ($('cf-refresh')) $('cf-refresh').hidden = true;
      if ($('cf-add-record')) $('cf-add-record').hidden = true;
      cfLoadedOnce = true;
      return;
    }

    if ($('cf-empty')) $('cf-empty').hidden = true;
    if ($('cf-workspace')) $('cf-workspace').hidden = false;
    if ($('cf-refresh')) $('cf-refresh').hidden = false;
    if ($('cf-add-record')) $('cf-add-record').hidden = false;

    try {
      const zdata = await api('GET', '/api/cf/zones');
      cfZones = zdata.zones || [];
    } catch (e) {
      cfZones = [];
      if ($('cf-error')) $('cf-error').textContent = e.message;
    }

    if (cz) {
      cz.textContent = String(cfZones.length);
      cz.hidden = cfZones.length === 0;
    }

    const sel = $('cf-zone-select');
    const prev = sel ? sel.value : '';
    if (sel) {
      sel.replaceChildren(...cfZones.map((z) => h('option', { value: z.id },
        `${z.name}${z.status && z.status !== 'active' ? ' (' + z.status + ')' : ''}${cfAccounts.length > 1 ? ' — ' + z.account_name : ''}`)));
      if (prev && cfZones.some((z) => z.id === prev)) sel.value = prev;
    }

    await loadCFRecordsForCurrentZone();
    cfLoadedOnce = true;
  }

  async function loadCFRecordsForCurrentZone() {
    const wrap = $('cf-records-wrap');
    if (!wrap) return;
    const z = currentCFZone();
    if (!z) {
      cfRecords = [];
      wrap.replaceChildren(h('p', { class: 'empty' }, 'No domains (zones) found under your Cloudflare API token. Ensure your token has Zone:Read permission.'));
      return;
    }
    if ($('cf-error')) $('cf-error').textContent = '';
    wrap.replaceChildren(h('p', { class: 'muted' }, `Loading DNS records for ${z.name}...`));
    try {
      const data = await api('GET', `/api/cf/zones/${encodeURIComponent(z.id)}/records?account_id=${encodeURIComponent(z.account_id)}`);
      cfRecords = data.records || [];
      renderCFRecords();
    } catch (e) {
      wrap.replaceChildren();
      if ($('cf-error')) $('cf-error').textContent = e.message;
    }
  }

  function formatTTL(ttl, proxied) {
    if (proxied || !ttl || ttl === 1) return 'Auto';
    if (ttl < 60) return `${ttl}s`;
    if (ttl < 3600) return `${Math.round(ttl / 60)} min`;
    if (ttl < 86400) return `${Math.round(ttl / 3600)} hr`;
    return `${Math.round(ttl / 86400)} d`;
  }

  function renderCFRecords() {
    const wrap = $('cf-records-wrap');
    if (!wrap) return;
    const z = currentCFZone();
    if (!z) return;
    const typeFilter = ($('cf-type-filter') && $('cf-type-filter').value) || '';
    const q = (($('cf-search') && $('cf-search').value) || '').trim().toLowerCase();

    const list = cfRecords.filter((r) => {
      if (typeFilter && r.type !== typeFilter) return false;
      if (q) {
        const hay = `${r.name || ''} ${r.content || ''} ${r.comment || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (!list.length) {
      wrap.replaceChildren(h('p', { class: 'empty' },
        cfRecords.length
          ? 'No DNS records match your current filter.'
          : `No DNS records found in ${z.name}. Click "+ Add Record" to create a subdomain.`));
      return;
    }

    const rows = list.map((r) => {
      const canProxy = r.proxiable || ['A', 'AAAA', 'CNAME'].includes(r.type);
      const matchedSrv = serverMatchingIP(r.content);
      const proxyCell = canProxy
        ? h('button', {
            type: 'button',
            class: 'cf-proxy-btn ' + (r.proxied ? 'is-proxied' : 'is-dns-only'),
            title: r.proxied
              ? 'Proxied through Cloudflare CDN (Orange Cloud) — click to switch to DNS Only'
              : 'DNS Only (Grey Cloud) — click to enable Cloudflare Proxy',
            onclick: async (ev) => {
              const btn = ev.currentTarget;
              btn.disabled = true;
              try {
                const updated = await api('PATCH', `/api/cf/zones/${encodeURIComponent(z.id)}/records/${encodeURIComponent(r.id)}`, {
                  account_id: z.account_id,
                  proxied: !r.proxied,
                });
                r.proxied = updated.proxied;
                r.ttl = updated.ttl || r.ttl;
                renderCFRecords();
                setStatus(`${r.name}: Cloudflare Proxy ${r.proxied ? 'enabled (Proxied)' : 'disabled (DNS Only)'}.`);
              } catch (e) {
                setStatus(e.message, true);
                btn.disabled = false;
              }
            }
          }, makeCloudIcon(), r.proxied ? 'Proxied' : 'DNS Only')
        : h('span', { class: 'muted small' }, 'DNS Only');

      const useInTunnelBtn = ['A', 'AAAA', 'CNAME'].includes(r.type)
        ? h('button', {
            type: 'button',
            title: 'Create a CDN tunnel with this subdomain',
            onclick: async () => {
              const foreignID = matchedSrv && matchedSrv.group === 'foreign' ? matchedSrv.id : '';
              await openNewTunnel('', foreignID);
              setRadio('tn-link', 'cdn');
              $('tn-domain').value = r.name;
              showTunnelOptions();
              $('tn-name').focus();
            }
          }, '+ Tunnel')
        : null;

      return h('div', { class: 'cf-record-row' },
        h('span', { class: 'cf-type-badge cf-type-' + r.type }, r.type),
        h('div', { class: 'cf-rec-main' },
          h('span', { class: 'cf-rec-fqdn' }, r.name),
          r.comment ? h('span', { class: 'cf-rec-note' }, r.comment) : null),
        h('div', { class: 'cf-rec-target' },
          h('span', { class: 'cf-rec-ip' }, r.content),
          matchedSrv
            ? h('span', { class: 'cf-srv-match' }, `${matchedSrv.name || matchedSrv.address} (${matchedSrv.group === 'foreign' ? 'Foreign' : 'Relay'})`)
            : null),
        h('div', null, proxyCell),
        h('div', { class: 'cf-rec-ttl-cell' }, formatTTL(r.ttl, r.proxied)),
        h('div', { class: 'cf-rec-actions' },
          useInTunnelBtn,
          h('button', { type: 'button', onclick: () => openCFRecordModal(r) }, 'Edit'),
          h('button', {
            type: 'button',
            class: 'danger-text',
            onclick: () => openConfirm(
              `Delete DNS record "${r.name}"?`,
              `This permanently deletes the ${r.type} record "${r.name}" → "${r.content}" from ${z.name} in Cloudflare.`,
              'Delete Record',
              async () => {
                await api('DELETE', `/api/cf/zones/${encodeURIComponent(z.id)}/records/${encodeURIComponent(r.id)}?account_id=${encodeURIComponent(z.account_id)}`);
                await loadCFRecordsForCurrentZone();
                setStatus(`Deleted DNS record ${r.name}.`);
              }
            )
          }, 'Delete')));
    });

    wrap.replaceChildren(...rows);
  }

  async function saveCFToken(name, token, errEl, btnEl, closeDlg) {
    if (!token) {
      if (errEl) errEl.textContent = 'Paste your Cloudflare API token.';
      return;
    }
    if (errEl) errEl.textContent = '';
    if (btnEl) btnEl.disabled = true;
    try {
      await api('POST', '/api/cf/accounts', { name, token });
      if (closeDlg) closeDlg.close();
      cfLoadedOnce = false;
      await loadCloudflare(true);
      setStatus('Cloudflare API token verified and encrypted.');
    } catch (e) {
      if (errEl) errEl.textContent = e.message;
    } finally {
      if (btnEl) btnEl.disabled = false;
    }
  }

  if ($('cf-inline-token-form')) {
    $('cf-inline-token-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      await saveCFToken(
        $('cf-inline-name').value.trim(),
        $('cf-inline-token').value.trim(),
        $('cf-inline-error'),
        $('cf-inline-submit'),
        null
      );
      $('cf-inline-token').value = '';
    });
  }

  if ($('cf-open-tokens')) {
    $('cf-open-tokens').addEventListener('click', () => {
      $('cf-token-name').value = '';
      $('cf-token-val').value = '';
      $('cf-token-error').textContent = '';
      openDialog($('cf-token-dialog'));
      $('cf-token-val').focus();
    });
  }
  if ($('cf-token-cancel')) $('cf-token-cancel').addEventListener('click', () => $('cf-token-dialog').close());
  if ($('cf-token-form')) {
    $('cf-token-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      await saveCFToken(
        $('cf-token-name').value.trim(),
        $('cf-token-val').value.trim(),
        $('cf-token-error'),
        $('cf-token-submit'),
        $('cf-token-dialog')
      );
    });
  }

  if ($('cf-refresh')) {
    $('cf-refresh').addEventListener('click', () => {
      cfLoadedOnce = false;
      loadCloudflare(true);
    });
  }
  if ($('cf-zone-select')) {
    $('cf-zone-select').addEventListener('change', () => loadCFRecordsForCurrentZone());
  }
  if ($('cf-type-filter')) {
    $('cf-type-filter').addEventListener('change', renderCFRecords);
  }
  if ($('cf-search')) {
    $('cf-search').addEventListener('input', renderCFRecords);
  }

  function syncCFRecordFormType() {
    const t = $('cf-rec-type').value;
    const canProxy = ['A', 'AAAA', 'CNAME'].includes(t);
    $('cf-rec-proxy-row').hidden = !canProxy;
    const lbl = $('cf-rec-content-label');
    const inp = $('cf-rec-content');
    if (t === 'A') {
      lbl.textContent = 'IPv4 Address';
      inp.placeholder = 'e.g. 203.0.113.5';
    } else if (t === 'AAAA') {
      lbl.textContent = 'IPv6 Address';
      inp.placeholder = 'e.g. 2001:db8::1';
    } else if (t === 'CNAME') {
      lbl.textContent = 'Target Domain';
      inp.placeholder = 'e.g. target.example.com';
    } else {
      lbl.textContent = 'Record Content';
      inp.placeholder = 'Enter record value';
    }
    syncChoiceCards($('cf-record-dialog'));
  }

  function populateCFServerPick() {
    const pick = $('cf-rec-server-pick');
    if (!pick) return;
    const opts = [h('option', { value: '' }, 'Fill IP from Foreign / Relay server…')];
    const sorted = [...serversCache].sort((a, b) => (a.group === 'foreign' ? -1 : 1) - (b.group === 'foreign' ? -1 : 1));
    for (const s of sorted) {
      const role = s.group === 'foreign' ? 'Foreign' : 'Relay';
      const v4 = (s.overview && s.overview.ipv4 && s.overview.ipv4[0]) || s.address || '';
      if (v4) {
        opts.push(h('option', { value: `A:${v4}` }, `${s.name || v4} (${role} IPv4: ${v4})`));
      }
      const v6 = s.overview && s.overview.ipv6 && s.overview.ipv6[0];
      if (v6) {
        opts.push(h('option', { value: `AAAA:${v6}` }, `${s.name || v6} (${role} IPv6: ${v6})`));
      }
    }
    pick.replaceChildren(...opts);
    pick.value = '';
  }

  if ($('cf-rec-type')) {
    $('cf-rec-type').addEventListener('change', syncCFRecordFormType);
  }
  if ($('cf-rec-server-pick')) {
    $('cf-rec-server-pick').addEventListener('change', (ev) => {
      const val = ev.target.value;
      if (!val) return;
      const idx = val.indexOf(':');
      const rtype = val.slice(0, idx);
      const ip = val.slice(idx + 1);
      $('cf-rec-type').value = rtype;
      $('cf-rec-content').value = ip;
      syncCFRecordFormType();
      ev.target.value = '';
    });
  }

  function openCFRecordModal(rec) {
    const z = currentCFZone();
    if (!z) return;
    editingCFRecord = rec || null;
    $('cf-rec-title').textContent = rec ? `Edit DNS Record (${z.name})` : `Add DNS Record (${z.name})`;
    $('cf-rec-zone-hint').textContent = `(use @ for ${z.name}, or a subdomain like edge1)`;
    populateCFServerPick();

    $('cf-rec-type').value = (rec && rec.type) || 'A';
    $('cf-rec-ttl').value = String((rec && rec.ttl) || 1);
    $('cf-rec-name').value = (rec && rec.name) || '';
    $('cf-rec-content').value = (rec && rec.content) || '';
    $('cf-rec-proxied').checked = rec ? !!rec.proxied : true;
    $('cf-rec-comment').value = (rec && rec.comment) || '';
    $('cf-rec-error').textContent = '';

    syncCFRecordFormType();
    openDialog($('cf-record-dialog'));
    $('cf-rec-name').focus();
  }

  if ($('cf-add-record')) {
    $('cf-add-record').addEventListener('click', () => openCFRecordModal(null));
  }
  if ($('cf-rec-cancel')) {
    $('cf-rec-cancel').addEventListener('click', () => $('cf-record-dialog').close());
  }
  if ($('cf-record-form')) {
    $('cf-record-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const z = currentCFZone();
      if (!z) return;
      const btn = $('cf-rec-submit');
      const err = $('cf-rec-error');
      err.textContent = '';
      btn.disabled = true;
      const body = {
        account_id: z.account_id,
        type: $('cf-rec-type').value,
        name: $('cf-rec-name').value.trim(),
        content: $('cf-rec-content').value.trim(),
        ttl: Number($('cf-rec-ttl').value || 1),
        proxied: $('cf-rec-proxied').checked,
        comment: $('cf-rec-comment').value.trim(),
      };
      try {
        if (editingCFRecord) {
          await api('PUT', `/api/cf/zones/${encodeURIComponent(z.id)}/records/${encodeURIComponent(editingCFRecord.id)}`, body);
          setStatus(`Updated DNS record ${body.name}.`);
        } else {
          await api('POST', `/api/cf/zones/${encodeURIComponent(z.id)}/records`, body);
          setStatus(`Created DNS record ${body.name}.`);
        }
        $('cf-record-dialog').close();
        await loadCFRecordsForCurrentZone();
      } catch (e) {
        err.textContent = e.message;
      } finally {
        btn.disabled = false;
      }
    });
  }

  // Cloudflare helper inside + New Tunnel modal
  async function ensureTunnelCFHelper() {
    const box = $('tn-cf-helper');
    if (!box) return;
    if (!cfZones.length) {
      try {
        const acctData = await api('GET', '/api/cf/accounts');
        cfAccounts = acctData.accounts || [];
        if (cfAccounts.length) {
          const zdata = await api('GET', '/api/cf/zones');
          cfZones = zdata.zones || [];
        }
      } catch (e) {
        // Ignore if Cloudflare is not configured.
      }
    }
    if (!cfZones.length) {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    const zSel = $('tn-cf-zone');
    const prev = zSel.value;
    zSel.replaceChildren(...cfZones.map((z) => h('option', { value: z.id }, z.name)));
    if (prev && cfZones.some((z) => z.id === prev)) zSel.value = prev;
    await loadTunnelCFRecords();
  }

  async function loadTunnelCFRecords() {
    const zSel = $('tn-cf-zone');
    const pick = $('tn-cf-pick');
    if (!zSel || !pick) return;
    const z = cfZones.find((x) => x.id === zSel.value) || cfZones[0];
    if (!z) return;
    try {
      const data = await api('GET', `/api/cf/zones/${encodeURIComponent(z.id)}/records?account_id=${encodeURIComponent(z.account_id)}`);
      const recs = (data.records || []).filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type));
      pick.replaceChildren(
        h('option', { value: '' }, `— Pick from ${z.name} (${recs.length}) —`),
        ...recs.map((r) => h('option', { value: r.name }, `${r.name} → ${r.content} (${r.proxied ? 'Proxied' : 'DNS Only'})`))
      );
    } catch (e) {
      pick.replaceChildren(h('option', { value: '' }, '— Could not load records —'));
    }
  }

  if ($('tn-cf-zone')) {
    $('tn-cf-zone').addEventListener('change', loadTunnelCFRecords);
  }
  if ($('tn-cf-pick')) {
    $('tn-cf-pick').addEventListener('change', (ev) => {
      if (ev.target.value) {
        $('tn-domain').value = ev.target.value;
      }
    });
  }
  if ($('tn-cf-create-btn')) {
    $('tn-cf-create-btn').addEventListener('click', async () => {
      const msg = $('tn-cf-msg');
      const sub = $('tn-cf-sub').value.trim();
      const z = cfZones.find((x) => x.id === $('tn-cf-zone').value) || cfZones[0];
      if (!z) return;
      if (!sub) {
        msg.className = 'small error';
        msg.textContent = 'Enter a subdomain name (e.g. edge1).';
        $('tn-cf-sub').focus();
        return;
      }
      const fSrv = serverById($('tn-foreign').value);
      const ip = (fSrv && fSrv.overview && fSrv.overview.ipv4 && fSrv.overview.ipv4[0]) || (fSrv && fSrv.address) || '';
      if (!ip) {
        msg.className = 'small error';
        msg.textContent = 'Select a Foreign server with a valid IPv4 address first.';
        return;
      }
      const btn = $('tn-cf-create-btn');
      btn.disabled = true;
      msg.className = 'small muted';
      msg.textContent = 'Creating Cloudflare A record with Proxy enabled...';
      try {
        const created = await api('POST', `/api/cf/zones/${encodeURIComponent(z.id)}/records`, {
          account_id: z.account_id,
          type: 'A',
          name: sub,
          content: ip,
          ttl: 1,
          proxied: true,
          comment: 'PortBridge CDN tunnel',
        });
        $('tn-domain').value = created.name;
        $('tn-cf-sub').value = '';
        msg.className = 'small okay';
        msg.textContent = `Created ${created.name} → ${ip} (Proxied ON) and filled above.`;
        cfLoadedOnce = false;
        await loadTunnelCFRecords();
      } catch (e) {
        msg.className = 'small error';
        msg.textContent = e.message;
      } finally {
        btn.disabled = false;
      }
    });
  }

  function currentCreateLinkKey() {
    if ($('tn-gre') && $('tn-gre').checked) return 'gre';
    return radio('tn-link') || 'website';
  }

  function applyCreateLoadPreset(preset) {
    const rec = recommendCapacityFor(currentCreateLinkKey(), preset);
    setRadio('tn-shared', rec.shared ? 'shared' : 'one');
    if ($('tn-pool')) $('tn-pool').value = String(rec.pool);
    if ($('tn-links-n')) $('tn-links-n').value = String(rec.muxLinks);
    if ($('tn-max-conn')) $('tn-max-conn').value = String(rec.maxConn);
  }

  function showTunnelOptions() {
    const mode = radio('tn-mode');
    const gre = $('tn-gre').checked;
    $('tn-links').hidden = gre;
    const backup = $('tn-backup-choice');
    backup.hidden = mode !== 'direct';
    if (mode !== 'direct' && radio('tn-link') === 'website-cdn-backup') setRadio('tn-link', 'website');
    const link = gre ? 'plain' : radio('tn-link');
    $('tn-opt-webheader').hidden = gre || link !== 'plain';
    $('tn-webhost').disabled = !$('tn-webheader').checked;
    $('tn-opt-claim').hidden = !['website', 'split', 'sit', 'website-cdn-backup', 'grpc'].includes(link);
    const needDomain = ['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(link);
    $('tn-opt-domain').hidden = !needDomain;
    if (needDomain) ensureTunnelCFHelper();
    $('tn-opt-clean').hidden = !['cdn', 'grpc-cdn'].includes(link);
    $('tn-opt-stealth').hidden = !['website', 'split', 'sit', 'sni-spoof', 'grpc'].includes(link);
    if ($('tn-opt-snispoof')) {
      $('tn-opt-snispoof').hidden = gre || ['kcp', 'icmp', 'faketcp', 'sit'].includes(link);
      if (link === 'ip-spoof' || link === 'sni-spoof') {
        $('tn-snispoof').checked = true;
        $('tn-snispoof').disabled = true;
        $('tn-snispoof-fields').hidden = false;
      } else {
        $('tn-snispoof').disabled = false;
        $('tn-snispoof-fields').hidden = !$('tn-snispoof').checked;
      }
    }
    if ($('tn-opt-ipspoof')) {
      $('tn-opt-ipspoof').hidden = gre || link !== 'ip-spoof';
    }
    if (link === 'grpc' && $('tn-claim').value === 'www.bing.com') $('tn-claim').value = 'www.google.com';
    if (link !== 'grpc' && $('tn-claim').value === 'www.google.com') $('tn-claim').value = 'www.bing.com';
    const v6ok = !gre && ['plain', 'website', 'split', 'sni-spoof', 'grpc', 'kcp'].includes(link) &&
      hasIPv6(serverById($('tn-relay').value)) && hasIPv6(serverById($('tn-foreign').value));
    $('tn-ipv6-row').hidden = !v6ok;
    if (!v6ok) $('tn-ipv6').checked = false;

    const loadPreset = radio('tn-load') || 'light';
    if (!sharingTouched && loadPreset !== 'custom') {
      applyCreateLoadPreset(loadPreset);
    }
    const isShared = radio('tn-shared') === 'shared';
    if ($('tn-pool-wrap')) $('tn-pool-wrap').hidden = isShared;
    $('tn-opt-links').hidden = !isShared;
    if ($('tn-capacity-hint')) {
      const poolSize = Number(($('tn-pool') && $('tn-pool').value) || 30);
      const muxLinks = Number(($('tn-links-n') && $('tn-links-n').value) || 4);
      const maxConn = Number(($('tn-max-conn') && $('tn-max-conn').value) || 2000);
      $('tn-capacity-hint').textContent = describeCapacityAdvice(currentCreateLinkKey(), isShared, poolSize, muxLinks, maxConn);
    }
    syncChoiceCards($('tunnel-dialog'));
  }

  for (const el of document.querySelectorAll('#tunnel-form input[name="tn-mode"], #tunnel-form input[name="tn-link"], #tn-gre, #tn-webheader, #tn-snispoof, #tn-relay, #tn-foreign')) {
    el.addEventListener('change', showTunnelOptions);
  }
  for (const el of document.querySelectorAll('input[name="tn-load"]')) {
    el.addEventListener('change', () => {
      const preset = radio('tn-load');
      if (preset && preset !== 'custom') {
        sharingTouched = false;
        applyCreateLoadPreset(preset);
      } else {
        sharingTouched = true;
      }
      showTunnelOptions();
    });
  }
  for (const el of document.querySelectorAll('input[name="tn-shared"]')) {
    el.addEventListener('change', () => {
      sharingTouched = true;
      setRadio('tn-load', 'custom');
      showTunnelOptions();
    });
  }
  for (const id of ['tn-pool', 'tn-links-n', 'tn-max-conn']) {
    if ($(id)) {
      $(id).addEventListener('input', () => {
        sharingTouched = true;
        setRadio('tn-load', 'custom');
        showTunnelOptions();
      });
    }
  }

  if ($('tn-spoofsni-preset')) {
    $('tn-spoofsni-preset').addEventListener('change', (ev) => {
      if (ev.target.value && $('tn-spoofsni')) {
        $('tn-spoofsni').value = ev.target.value;
        ev.target.value = '';
      }
    });
  }
  if ($('tn-spoofip-preset')) {
    $('tn-spoofip-preset').addEventListener('change', (ev) => {
      if (ev.target.value && $('tn-spoofip')) {
        $('tn-spoofip').value = ev.target.value;
        ev.target.value = '';
      }
    });
  }

  if ($('tn-test-snispoof-btn')) {
    $('tn-test-snispoof-btn').addEventListener('click', async () => {
      const btn = $('tn-test-snispoof-btn');
      const out = $('tn-sni-scan-results');
      const relay = $('tn-relay').value;
      const foreign = $('tn-foreign').value;
      const spoofSNI = ($('tn-spoofsni') && $('tn-spoofsni').value.trim()) || 'challenges.cloudflare.com';
      if (!relay || !foreign) {
        out.replaceChildren(h('li', { class: 'bad' }, 'Select both a Relay (Iran) server and a Foreign server first.'));
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Testing Decoy SNI Tunnel…';
      out.replaceChildren(h('li', null, `Testing Decoy Whitelisted SNI ("${spoofSNI}") tunnel between Relay and Foreign in both Direct and Reverse directions…`));
      try {
        const rep = await api('POST', '/api/probe/sni-test', { relay, foreign, spoof_sni: spoofSNI });
        const rName = rep.relay_name || 'Relay';
        const fName = rep.foreign_name || 'Foreign';
        const items = [];
        const renderDir = (title, modeKey, res) => {
          if (!res) return;
          const ok = res.status === 'ok' || res.status === 'degraded';
          const v6Tag = res.ipv6 ? ' (over IPv6)' : '';
          const useBtn = ok
            ? h('button', {
                type: 'button',
                class: 'use-port-btn',
                onclick: () => {
                  setRadio('tn-mode', modeKey);
                  if (res.ipv6 && $('tn-ipv6')) $('tn-ipv6').checked = true;
                  showTunnelOptions();
                }
              }, `Use ${modeKey === 'reverse' ? 'Reverse' : 'Direct'} Mode`)
            : null;
          items.push(h('li', { class: ok ? 'good' : 'bad' },
            h('strong', null, `${title}${v6Tag}: `),
            ok
              ? `✓ Working! Connected & verified — ${(res.avg_mbps || 0).toFixed(1)} Mbps avg, ${Math.round(res.rtt_ms || 0)} ms ping using decoy SNI "${spoofSNI}".`
              : `Blocked / Unreachable (${res.error || 'connection failed'}).`,
            useBtn));
        };
        renderDir(`Direct (${rName} → ${fName})`, 'direct', rep.direct);
        renderDir(`Reverse (${fName} → ${rName})`, 'reverse', rep.reverse);
        if (rep.summary) {
          const anyOK = (rep.direct && (rep.direct.status === 'ok' || rep.direct.status === 'degraded')) ||
                        (rep.reverse && (rep.reverse.status === 'ok' || rep.reverse.status === 'degraded'));
          items.push(h('li', { class: anyOK ? 'good' : 'warn' },
            h('strong', null, anyOK ? '✓ Result: ' : 'Note: '),
            rep.summary));
        }
        out.replaceChildren(...items);
      } catch (e) {
        out.replaceChildren(h('li', { class: 'bad' }, e.message));
      } finally {
        btn.disabled = false;
        btn.textContent = 'Test Decoy SNI Tunnel (Relay ↔ Foreign)';
      }
    });
  }

  if ($('tn-scan-sni-btn')) {
    $('tn-scan-sni-btn').addEventListener('click', async () => {
      const btn = $('tn-scan-sni-btn');
      const out = $('tn-sni-scan-results');
      const relay = $('tn-relay').value;
      if (!relay) {
        out.replaceChildren(h('li', { class: 'bad' }, 'Select a Relay (Iran) server first.'));
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Scanning Whitelisted SNIs…';
      out.replaceChildren(h('li', null, 'Probing whitelisted SNIs (challenges.cloudflare.com, www.recaptcha.net, security.vercel.com, etc.) from Relay server…'));
      try {
        const rep = await api('POST', '/api/probe/sni-scan', { relay });
        const list = Array.isArray(rep) ? rep : (rep.results || []);
        const best = (!Array.isArray(rep) && rep.best_sni) || (list.find((x) => x.reachable) || {}).sni || '';
        if (best && $('tn-spoofsni')) {
          $('tn-spoofsni').value = best;
        }
        const items = list.map((item) => {
          const ok = !!item.reachable;
          const useBtn = ok
            ? h('button', {
                type: 'button',
                class: 'use-port-btn',
                onclick: () => {
                  $('tn-spoofsni').value = item.sni;
                  $('tn-spoofsni').focus();
                }
              }, `Use ${item.sni}`)
            : null;
          return h('li', { class: ok ? 'good' : 'bad' },
            h('strong', { class: 'mono' }, item.sni),
            ok
              ? ` — ✓ Reachable · ${Math.round(item.rtt_ms || 0)} ms`
              : ` — Blocked (${item.error || 'timeout'})`,
            useBtn);
        });
        out.replaceChildren(...(items.length ? items : [h('li', { class: 'warn' }, 'No SNI scan results returned.')]));
      } catch (e) {
        out.replaceChildren(h('li', { class: 'bad' }, e.message));
      } finally {
        btn.disabled = false;
        btn.textContent = 'Scan Best Whitelisted SNIs';
      }
    });
  }

  if ($('tn-test-spoof-btn')) {
    $('tn-test-spoof-btn').addEventListener('click', async () => {
      const btn = $('tn-test-spoof-btn');
      const out = $('tn-spoof-test-results');
      const relay = $('tn-relay').value;
      const foreign = $('tn-foreign').value;
      const spoofIP = ($('tn-spoofip') && $('tn-spoofip').value.trim()) || '104.18.4.130';
      if (!relay || !foreign) {
        out.replaceChildren(h('li', { class: 'bad' }, 'Select both a Relay server and a Foreign server first.'));
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Testing Raw IP Spoofing…';
      out.replaceChildren(h('li', null, `Testing whether either server can send raw UDP packets with forged Source IP ${spoofIP}…`));
      try {
        const rep = await api('POST', '/api/probe/spoof-test', { relay, foreign, spoof_ip: spoofIP });
        const rName = rep.relay_name || 'Relay (Iran)';
        const fName = rep.foreign_name || 'Foreign';
        const f2rSpoof = !!(rep.foreign_to_relay_spoof_ok || rep.foreign_can_spoof);
        const f2rNorm = !!(rep.foreign_to_relay_normal_ok || (rep.foreign_to_relay && rep.foreign_to_relay.normal_received > 0));
        const r2fSpoof = !!(rep.relay_to_foreign_spoof_ok || rep.relay_can_spoof);
        const r2fNorm = !!(rep.relay_to_foreign_normal_ok || (rep.relay_to_foreign && rep.relay_to_foreign.normal_received > 0));
        const items = [];

        items.push(h('li', { class: r2fSpoof ? 'good' : (r2fNorm ? 'warn' : 'bad') },
          h('strong', null, `${rName} → ${fName} (Relay → Foreign): `),
          r2fSpoof
            ? `✓ Supported! Spoofed UDP packets pretending to be ${spoofIP} sent from ${rName} arrived at ${fName}.`
            : (r2fNorm
                ? `Filtered by datacenter — ${rName}'s provider drops forged source IPs, but normal UDP works (automatic fallback active).`
                : `UDP test packets from ${rName} did not reach ${fName} over IPv4.`)));

        items.push(h('li', { class: f2rSpoof ? 'good' : (f2rNorm ? 'warn' : 'bad') },
          h('strong', null, `${fName} → ${rName} (Foreign → Relay): `),
          f2rSpoof
            ? `✓ Supported! Spoofed UDP packets pretending to be ${spoofIP} sent from ${fName} arrived at ${rName}.`
            : (f2rNorm
                ? `Filtered by datacenter — ${fName}'s provider drops forged source IPs, but normal UDP works (automatic fallback active).`
                : `Filtered in transit — UDP packets from ${fName} did not reach ${rName} over IPv4 (return traffic uses automatic fallback).`)));

        if (rep.summary) {
          items.push(h('li', { class: (f2rSpoof || r2fSpoof) ? 'good' : 'warn' },
            h('strong', null, (f2rSpoof || r2fSpoof) ? '✓ Ready to Use: ' : 'Recommendation: '),
            rep.summary));
        }
        out.replaceChildren(...items);
      } catch (e) {
        out.replaceChildren(h('li', { class: 'bad' }, e.message));
      } finally {
        btn.disabled = false;
        btn.textContent = 'Test VPS IP-Spoof Capability on Both Servers';
      }
    });
  }

  // ----------------------------------------- smart route & transport probe

  async function populateProbeCFPick() {
    const wrap = $('tn-probe-cf-wrap');
    const pick = $('tn-probe-cf-pick');
    if (!wrap || !pick) return;
    if (!cfZones.length) {
      try {
        const acctData = await api('GET', '/api/cf/accounts');
        cfAccounts = acctData.accounts || [];
        if (cfAccounts.length) {
          const zdata = await api('GET', '/api/cf/zones');
          cfZones = zdata.zones || [];
        }
      } catch (e) {
        // Ignore if Cloudflare is not configured.
      }
    }
    if (!cfZones.length) {
      wrap.hidden = true;
      return;
    }
    try {
      const z = cfZones[0];
      const data = await api('GET', `/api/cf/zones/${encodeURIComponent(z.id)}/records?account_id=${encodeURIComponent(z.account_id)}`);
      const recs = (data.records || []).filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type));
      if (!recs.length) {
        wrap.hidden = true;
        return;
      }
      wrap.hidden = false;
      pick.replaceChildren(
        h('option', { value: '' }, `— Pick from ${z.name} —`),
        ...recs.map((r) => h('option', { value: r.name }, `${r.name} → ${r.content}${r.proxied ? ' (Proxied)' : ''}`))
      );
    } catch (e) {
      wrap.hidden = true;
    }
  }

  if ($('tn-probe-cf-pick')) {
    $('tn-probe-cf-pick').addEventListener('change', (ev) => {
      if (ev.target.value && $('tn-probe-cdn')) {
        $('tn-probe-cdn').value = ev.target.value;
      }
    });
  }

  function applyProbeCandidate(cand) {
    if (!cand) return;
    $('tn-gre').checked = false;
    setRadio('tn-mode', cand.mode === 'reverse' ? 'reverse' : 'direct');
    setRadio('tn-link', cand.ip_spoof ? 'ip-spoof' : (cand.anti_freeze ? 'split' : (cand.sni_spoof ? 'sni-spoof' : (cand.link || 'website'))));
    $('tn-stealth').checked = !!cand.stealth;
    $('tn-webheader').checked = !!cand.web_header;
    $('tn-ipv6').checked = !!cand.ipv6;
    if ($('tn-snispoof')) {
      $('tn-snispoof').checked = !!(cand.sni_spoof || cand.ip_spoof);
    }
    if (cand.spoof_sni && $('tn-spoofsni')) {
      $('tn-spoofsni').value = cand.spoof_sni;
    }
    if (cand.spoof_ip && $('tn-spoofip')) {
      $('tn-spoofip').value = cand.spoof_ip;
    }
    if (cand.server_name && ['website', 'split', 'sit', 'website-cdn-backup', 'grpc'].includes(cand.link)) {
      $('tn-claim').value = cand.server_name;
    }
    if (cand.domain) {
      $('tn-domain').value = cand.domain;
    }
    const preset = radio('tn-load') || 'light';
    if (preset === 'custom') {
      sharingTouched = true;
      setRadio('tn-shared', cand.shared ? 'shared' : 'one');
      if (cand.shared && $('tn-links-n')) {
        const isRawKCP = cand.link === 'icmp' || cand.link === 'faketcp' || cand.ip_spoof;
        $('tn-links-n').value = isRawKCP ? '2' : '4';
      }
    } else {
      sharingTouched = false;
      applyCreateLoadPreset(preset);
    }
    if (cand.port && ['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(cand.link)) {
      $('tn-linkport').value = String(cand.port);
    }
    showTunnelOptions();
    setStatus(`Applied "${cand.label}" (Score ${cand.score}/100). Enter your Inbound Port(s) in Step 5 and click Create Tunnel.`);
    $('tn-service').focus();
  }

  function renderProbeRow(r, isLive, isActive) {
    if (isActive) {
      return h('div', { class: 'probe-row active' },
        h('div', { class: 'probe-row-label' }, r.label,
          h('span', { class: 'probe-row-sub' }, 'Running handshake, ping & download/upload burst...')),
        h('span', { class: 'state note' }, 'Testing…'),
        h('span', { class: 'probe-metric' }, '…'),
        h('span', { class: 'probe-metric' }, '…'),
        h('span', { class: 'muted small' }, '—'),
        h('span', { class: 'muted small' }, '—'));
    }
    if (!r.status) {
      return h('div', { class: 'probe-row' },
        h('div', { class: 'probe-row-label' }, r.label),
        h('span', { class: 'state' }, 'Queued'),
        h('span', { class: 'probe-metric' }, '—'),
        h('span', { class: 'probe-metric' }, '—'),
        h('span', { class: 'muted small' }, '—'),
        h('span', { class: 'muted small' }, '—'));
    }
    const stMap = {
      ok: ['ok', 'Healthy'],
      throttled: ['warn', 'Throttled'],
      degraded: ['warn', 'Degraded'],
      blocked: ['bad', 'Blocked'],
    };
    const st = stMap[r.status] || ['bad', r.status || 'Blocked'];
    const scoreCls = r.score >= 75 ? '' : (r.score >= 45 ? ' warn' : ' bad');
    const canUse = !isLive && (r.status === 'ok' || r.status === 'degraded');
    let speedNode = '—';
    if (r.successes > 0) {
      if (r.status === 'throttled' && !(r.avg_mbps > 0)) {
        speedNode = 'Frozen';
      } else if (r.down_mbps > 0 || r.up_mbps > 0) {
        speedNode = h('span', { title: `Download: ${(r.down_mbps || 0).toFixed(1)} Mbps · Upload: ${(r.up_mbps || 0).toFixed(1)} Mbps` },
          `${r.avg_mbps.toFixed(1)} Mbps`,
          h('span', { class: 'probe-row-sub' }, `↓${(r.down_mbps || 0).toFixed(1)} · ↑${(r.up_mbps || 0).toFixed(1)}`));
      } else {
        speedNode = `${r.avg_mbps.toFixed(1)} Mbps`;
      }
    }
    return h('div', { class: 'probe-row' },
      h('div', { class: 'probe-row-label' },
        r.label,
        r.error && r.status !== 'ok' ? h('span', { class: 'probe-row-sub' }, r.error) : null),
      h('span', { class: 'state ' + st[0] }, st[1]),
      h('span', { class: 'probe-metric' }, r.successes > 0 ? `${Math.round(r.rtt_ms)} ms` : '—'),
      h('span', { class: 'probe-metric' }, speedNode),
      isLive
        ? h('span', { class: 'muted small' }, r.status === 'ok' ? 'Done' : (r.status === 'throttled' ? 'Capped' : '—'))
        : h('span', { class: 'probe-score-pill' + scoreCls }, `${r.score}/100`),
      canUse
        ? h('button', {
            type: 'button',
            class: 'probe-use-btn',
            onclick: () => applyProbeCandidate(r)
          }, 'Use')
        : h('span', { class: 'muted small' }, '—'));
  }

  function renderProbeResults(rep, isLive, activeIdx) {
    const box = $('tn-probe-results');
    if (!box) return;
    box.hidden = false;

    const kids = [];
    if (!isLive && rep.recommended) {
      const rec = rep.recommended;
      kids.push(h('div', { class: 'probe-rec-card' },
        h('div', { class: 'probe-rec-main' },
          h('div', { class: 'probe-rec-top' },
            h('span', { class: 'probe-score-pill' }, `★ Recommended · ${rec.score}/100`),
            h('strong', null, rec.label)),
          h('p', { class: 'probe-rec-summary' }, rec.summary || '')),
        h('button', {
          type: 'button',
          class: 'primary',
          onclick: () => applyProbeCandidate(rec)
        }, 'Apply Recommended')));
    }

    const rows = (rep.results || []).map((r, idx) => renderProbeRow(r, !!isLive, isLive && idx === activeIdx));
    if (rows.length) {
      kids.push(h('div', { class: 'probe-list' }, ...rows));
    }
    for (const note of rep.notes || []) {
      kids.push(h('p', { class: 'muted small' }, note));
    }
    box.replaceChildren(...kids);
  }

  function setProbeProgress(text, pct) {
    const live = $('tn-probe-live');
    const st = $('tn-probe-status');
    const pctEl = $('tn-probe-pct');
    const bar = $('tn-probe-progress');
    if (live) live.hidden = false;
    if (st) st.textContent = text;
    const clamped = Math.max(0, Math.min(100, Math.round(pct)));
    if (pctEl) pctEl.textContent = `${clamped}%`;
    if (bar) bar.value = clamped;
  }

  if ($('tn-probe-btn')) {
    $('tn-probe-btn').addEventListener('click', async () => {
      const btn = $('tn-probe-btn');
      const live = $('tn-probe-live');
      const err = $('tn-probe-error');
      const resBox = $('tn-probe-results');
      const relay = $('tn-relay').value;
      const foreign = $('tn-foreign').value;
      const cdn = ($('tn-probe-cdn') && $('tn-probe-cdn').value.trim()) || ($('tn-domain') && $('tn-domain').value.trim()) || '';

      err.textContent = '';
      resBox.hidden = true;
      resBox.replaceChildren();
      btn.disabled = true;
      btn.textContent = 'Starting…';
      setProbeProgress('Preparing temporary benchmark listeners on both servers…', 4);
      if (live && live.scrollIntoView) {
        live.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      let sess = null;
      const doneResults = [];
      try {
        sess = await api('POST', '/api/tunnels/probe', {
          action: 'start',
          relay,
          foreign,
          cdn_domain: cdn,
        });
        const cands = sess.candidates || [];
        if (!cands.length) {
          throw new Error('No benchmark candidates could be prepared for these two servers.');
        }

        const liveState = cands.map((c) => Object.assign({}, c));
        const deadTCP = {};

        for (let i = 0; i < cands.length; i++) {
          const spec = cands[i];
          const pct = Math.round(((i + 0.2) / cands.length) * 92) + 4;
          btn.textContent = `Testing (${i + 1}/${cands.length})…`;
          setProbeProgress(`Step ${i + 1} of ${cands.length}: ${spec.label}…`, pct);
          renderProbeResults({ results: liveState, notes: sess.notes }, true, i);

          const isTCPDirect = !spec.cdn && !['kcp', 'icmp', 'faketcp'].includes(spec.transport) && spec.target_addr;
          if (isTCPDirect && (deadTCP[spec.target_addr] || 0) >= 2) {
            const skipped = Object.assign({}, spec, {
              status: 'blocked',
              attempts: 1,
              successes: 0,
              error: 'TCP port unreachable (connection timed out)',
              summary: 'Blocked / Unreachable — TCP port unreachable',
            });
            liveState[i] = skipped;
            doneResults.push(skipped);
            continue;
          }

          const dialerID = spec.mode === 'reverse' ? sess.foreign_id : sess.relay_id;
          const secret = spec.mode === 'reverse' ? sess.reverse_secret : sess.direct_secret;
          const stepRes = await api('POST', '/api/tunnels/probe', {
            action: 'step',
            dialer_id: dialerID,
            secret,
            spec,
          });
          if (isTCPDirect && stepRes.successes === 0 && (stepRes.error === 'TCP port unreachable (connection timed out)' || stepRes.error === 'connection refused')) {
            deadTCP[spec.target_addr] = (deadTCP[spec.target_addr] || 0) + 1;
          }
          liveState[i] = stepRes;
          doneResults.push(stepRes);
          renderProbeResults({ results: liveState, notes: sess.notes }, true, -1);
        }

        setProbeProgress('Calculating final scores and best tunnel recommendation…', 98);
        const finalRep = await api('POST', '/api/tunnels/probe', {
          action: 'finish',
          session: sess,
          results: doneResults,
        });
        sess = null;
        if (live) live.hidden = true;
        renderProbeResults(finalRep, false, -1);
      } catch (e) {
        if (live) live.hidden = true;
        err.textContent = e.message;
      } finally {
        if (sess) {
          api('POST', '/api/tunnels/probe', { action: 'finish', session: sess, results: doneResults }).catch(() => {});
        }
        btn.disabled = false;
        btn.textContent = 'Find Best Tunnel Mode';
      }
    });
  }

  async function openNewTunnel(relayID, foreignID) {
    if (!serversCache.length) {
      try { serversCache = (await api('GET', '/api/servers')).servers || []; } catch (e) { setStatus(e.message, true); return; }
    }
    const relays = serversCache.filter((s) => s.group === 'relay');
    const foreigns = serversCache.filter((s) => s.group === 'foreign');
    if (!relays.length || !foreigns.length) {
      setStatus('A tunnel connects a Relay (Iran) server and a Foreign server. Please add at least one of each first.', true);
      return;
    }
    $('tn-relay').replaceChildren(...relays.map(serverOption));
    $('tn-foreign').replaceChildren(...foreigns.map(serverOption));
    if (relayID) $('tn-relay').value = relayID;
    if (foreignID) $('tn-foreign').value = foreignID;
    $('tn-error').textContent = '';
    $('tn-ports-result').replaceChildren();
    if ($('tn-sni-scan-results')) $('tn-sni-scan-results').replaceChildren();
    if ($('tn-spoof-test-results')) $('tn-spoof-test-results').replaceChildren();
    if ($('tn-probe-error')) $('tn-probe-error').textContent = '';
    if ($('tn-probe-live')) $('tn-probe-live').hidden = true;
    if ($('tn-probe-results')) {
      $('tn-probe-results').hidden = true;
      $('tn-probe-results').replaceChildren();
    }
    populateProbeCFPick();
    $('tunnel-form').hidden = false;
    $('tn-progress').hidden = true;
    sharingTouched = false;
    setRadio('tn-load', 'light');
    showTunnelOptions();
    openDialog($('tunnel-dialog'));
    $('tn-name').focus();
  }

  for (const b of document.querySelectorAll('.new-tunnel')) b.addEventListener('click', () => openNewTunnel('', ''));
  $('tn-cancel').addEventListener('click', () => $('tunnel-dialog').close());
  $('tn-close').addEventListener('click', () => $('tunnel-dialog').close());
  $('tn-back').addEventListener('click', () => {
    $('tn-progress').hidden = true;
    $('tunnel-form').hidden = false;
    $('tn-name').focus();
  });

  function tunnelRequest() {
    const gre = $('tn-gre').checked;
    const link = gre ? 'plain' : radio('tn-link');
    const shared = radio('tn-shared') === 'shared';
    const ipSpoof = !gre && link === 'ip-spoof';
    const sit = !gre && link === 'sit';
    const antiFreeze = !gre && link === 'split';
    const sniSpoof = !gre && !sit && (ipSpoof || link === 'sni-spoof' || ($('tn-snispoof') && !$('tn-opt-snispoof').hidden && $('tn-snispoof').checked));
    return {
      name: $('tn-name').value.trim(),
      relay: $('tn-relay').value,
      foreign: $('tn-foreign').value,
      mode: radio('tn-mode'),
      link,
      server_name: $('tn-claim').value.trim(),
      domain: $('tn-domain').value.trim(),
      clean_ips: $('tn-cleanips').value.replace(/\s+/g, ''),
      stealth: ['sni-spoof', 'split'].includes(link) || $('tn-stealth').checked,
      web_header: !gre && $('tn-webheader').checked,
      web_host: $('tn-webhost').value.trim(),
      real_site: $('tn-realsite').checked,
      sni_spoof: sniSpoof,
      spoof_sni: $('tn-spoofsni') ? $('tn-spoofsni').value.trim() : '',
      ip_spoof: ipSpoof,
      spoof_ip: $('tn-spoofip') ? $('tn-spoofip').value.trim() : '',
      gre,
      sit,
      anti_freeze: antiFreeze,
      ipv6: $('tn-ipv6').checked,
      shared,
      shared_links: shared ? Number($('tn-links-n').value || 4) : 0,
      pool: !shared ? Number(($('tn-pool') && $('tn-pool').value) || 30) : 0,
      max_conn: Number(($('tn-max-conn') && $('tn-max-conn').value) || 2000),
      service_ports: $('tn-service').value.trim(),
      user_ports: $('tn-users').value.trim(),
      link_port: Number($('tn-linkport').value || 0),
      proxy_protocol: radio('tn-proxy'),
      relay_ip: $('tn-relayip').value.trim(),
      auto_heal: $('tn-autoheal') ? $('tn-autoheal').checked : true,
    };
  }

  // ------------------------------------------------ auto-heal & smart failover

  let autoHealTunnel = null;

  function renderAutoHealModal(t) {
    const ah = (t && t.auto_heal) || {};
    $('ah-title').textContent = `Auto-Heal & Smart Failover: ${t.name}`;
    $('ah-enabled').checked = !!ah.enabled;
    $('ah-cdn').value = ah.cdn_domain || '';
    $('ah-msg').textContent = '';
    $('ah-msg').className = '';
    $('ah-error').textContent = '';

    const banner = $('ah-status-banner');
    if (banner) {
      let stateText = ah.enabled
        ? 'Active — Monitoring tunnel health every 20 seconds.'
        : 'Disabled — Enable below so PortBridge automatically benchmarks and switches modes if this tunnel gets blocked.';
      if (ah.last_note) {
        stateText += ` Latest status: ${ah.last_note}`;
      }
      if (ah.last_heal) {
        stateText += ` (Last failover: ${ago(ah.last_heal)})`;
      }
      banner.textContent = stateText;
    }

    const histBox = $('ah-history');
    const history = ah.history || [];
    if (!history.length) {
      histBox.replaceChildren(h('p', { class: 'muted small' }, 'No automatic or manual mode switches recorded for this tunnel yet.'));
    } else {
      histBox.replaceChildren(...history.map((ev) => {
        const cls = ev.success ? 'ok' : 'bad';
        const title = ev.success
          ? `Switched: ${ev.from_desc || 'Previous'} → ${ev.to_desc || ev.candidate}`
          : `Failover attempt failed (${ev.from_desc || 'Tunnel'})`;
        const sub = ev.success
          ? `Score ${ev.score}/100 · Reason: ${ev.reason || 'blocked'} · ${ago(ev.at)}`
          : `${ev.error || 'Could not switch'} · Reason: ${ev.reason || 'blocked'} · ${ago(ev.at)}`;
        return h('div', { class: 'diag-card' },
          h('div', { class: 'diag-card-head' },
            h('span', { class: 'state ' + cls }, ev.success ? 'Switched' : 'Failed'),
            h('strong', null, title)),
          h('p', { class: 'muted small' }, sub));
      }));
    }
  }

  function openTunnelAutoHeal(t) {
    autoHealTunnel = t;
    renderAutoHealModal(t);
    openDialog($('autoheal-dialog'));
    $('ah-enabled').focus();
  }

  if ($('ah-close')) {
    $('ah-close').addEventListener('click', () => $('autoheal-dialog').close());
  }

  if ($('autoheal-form')) {
    $('autoheal-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (!autoHealTunnel) return;
      const btn = $('ah-save');
      btn.disabled = true;
      $('ah-error').textContent = '';
      $('ah-msg').textContent = '';
      try {
        const enabled = $('ah-enabled').checked;
        const cdnDomain = $('ah-cdn').value.trim();
        await api('POST', '/api/tunnels/autoheal', {
          name: autoHealTunnel.name,
          enabled,
          cdn_domain: cdnDomain,
        });
        $('ah-msg').className = 'good';
        $('ah-msg').textContent = enabled
          ? 'Auto-Heal enabled. This tunnel will now automatically benchmark and switch modes if it gets blocked.'
          : 'Auto-Heal disabled for this tunnel.';
        lastTunnels = '';
        await refresh();
        const updated = tunnelsCache.find((x) => x.name === autoHealTunnel.name);
        if (updated) {
          autoHealTunnel = updated;
          renderAutoHealModal(updated);
          $('ah-msg').className = 'good';
          $('ah-msg').textContent = enabled
            ? 'Auto-Heal enabled. This tunnel will now automatically benchmark and switch modes if it gets blocked.'
            : 'Auto-Heal disabled for this tunnel.';
        }
      } catch (e) {
        $('ah-error').textContent = e.message;
      } finally {
        btn.disabled = false;
      }
    });
  }

  if ($('ah-trigger-btn')) {
    $('ah-trigger-btn').addEventListener('click', async () => {
      if (!autoHealTunnel) return;
      const t = autoHealTunnel;
      const edge = t.edge ? t.edge.server_id : '';
      const origin = t.origin ? t.origin.server_id : '';
      const cdnDomain = $('ah-cdn').value.trim();
      const btn = $('ah-trigger-btn');
      btn.disabled = true;
      $('ah-error').textContent = '';
      try {
        if ($('ah-enabled').checked || cdnDomain) {
          await api('POST', '/api/tunnels/autoheal', {
            name: t.name,
            enabled: $('ah-enabled').checked,
            cdn_domain: cdnDomain,
          });
        }
        const res = await api('POST', '/api/tunnels/autoheal/trigger', {
          name: t.name,
          edge,
          origin,
          cdn_domain: cdnDomain,
        });
        $('autoheal-dialog').close();
        followJob(
          res.job,
          `Smart Failover: ${t.name}`,
          `Tunnel "${t.name}" has been switched to the best working mode.`,
          `Could not switch tunnel "${t.name}":`
        );
      } catch (e) {
        $('ah-error').textContent = e.message;
      } finally {
        btn.disabled = false;
      }
    });
  }

  const portList = /^\s*\d{1,5}(\s*,\s*\d{1,5})*\s*$/;

  if ($('tn-scan-cdn')) {
    $('tn-scan-cdn').addEventListener('click', () => {
      const r = tunnelRequest();
      scanCDNPorts(r.relay, r.foreign, r.mode || 'reverse', '', $('tn-ports-result'), $('tn-linkport'));
    });
  }

  $('tn-check').addEventListener('click', async () => {
    const r = tunnelRequest();
    const out = $('tn-ports-result');
    const users = r.user_ports || r.service_ports;
    if (!portList.test(r.service_ports) || !portList.test(users) || !r.link_port) {
      out.replaceChildren(h('li', { class: 'bad' }, 'Enter the Inbound Port(s) and Tunnel Bridge Port first.'));
      return;
    }
    out.replaceChildren(h('li', null, 'Checking ports on both servers...'));
    const relayPorts = users + (r.mode === 'reverse' ? ',' + r.link_port : '');
    const foreignPorts = r.service_ports + (r.mode === 'direct' ? ',' + r.link_port : '');
    const describe = async (server, list, role) => {
      const s = serverById(server);
      try {
        const res = await api('POST', '/api/ports', { server, ports: list });
        return res.ports.map((p) => {
          let what = 'User listen port';
          if (p.port === r.link_port && ((role === 'relay' && r.mode === 'reverse') || (role === 'foreign' && r.mode === 'direct'))) what = 'Tunnel bridge port';
          else if (role === 'foreign') what = 'Inbound port';
          const by = p.by ? ` (${p.by.replace(/^PortBridge /, '')})` : '';
          let cls = 'good', text;
          if (what === 'Inbound port') {
            text = p.state === 'free' ? 'no service is listening on this port yet (is your X-UI / inbound running?)' : `active service listening${by} (ready)`;
            if (p.state === 'free') cls = 'warn';
            if (/^PortBridge tunnel/.test(p.by || '')) { cls = 'bad'; text = `already used by ${p.by.replace(/^PortBridge /, '')}`; }
          } else {
            text = p.state === 'free' ? 'available (free)' : `${p.state}${by}`;
            if (p.state !== 'free') cls = 'bad';
          }
          return h('li', { class: cls }, `${s ? s.name : server} — ${what} ${p.port}: ${text}`);
        });
      } catch (e) {
        return [h('li', { class: 'warn' }, `${s ? s.name : server}: could not check ports (${e.message})`)];
      }
    };
    const [a, b] = await Promise.all([describe(r.relay, relayPorts, 'relay'), describe(r.foreign, foreignPorts, 'foreign')]);
    out.replaceChildren(...a, ...b);
  });

  $('tunnel-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const err = $('tn-error');
    err.textContent = '';
    const r = tunnelRequest();
    const fail = (msg, el) => { err.textContent = msg; if (el) el.focus(); };
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(r.name)) return fail('Enter a valid tunnel name (letters, numbers, dash or underscore, up to 40 characters).', $('tn-name'));
    if (!r.relay || !r.foreign) return fail('Select both a Relay server and a Foreign server.', $('tn-relay'));
    if (!portList.test(r.service_ports)) return fail('Enter the Foreign Inbound Port(s), separated by commas.', $('tn-service'));
    if (r.user_ports && !portList.test(r.user_ports)) return fail('Enter the Relay User Listen Port(s) separated by commas, or leave empty to match Inbound Port(s).', $('tn-users'));
    if (r.user_ports && r.user_ports.split(',').length !== r.service_ports.split(',').length) {
      return fail('The number of User Listen Ports must match the number of Inbound Ports.', $('tn-users'));
    }
    if (!(r.link_port >= 1 && r.link_port <= 65535)) return fail('Tunnel Bridge Port must be between 1 and 65535.', $('tn-linkport'));
    if (['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(r.link) && !r.domain) return fail('Enter your CDN domain.', $('tn-domain'));
    if (!r.shared && !(r.pool >= 1 && r.pool <= 10000)) return fail('Connection Pool Size must be between 1 and 10000.', $('tn-pool'));
    if (r.shared && !(r.shared_links >= 1 && r.shared_links <= 16)) return fail('Number of shared Mux connections must be between 1 and 16.', $('tn-links-n'));
    if (!(r.max_conn >= 1 && r.max_conn <= 100000)) return fail('Max Concurrent User Sessions must be between 1 and 100000.', $('tn-max-conn'));
    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const res = await api('POST', '/api/tunnels', r);
      followTunnelJob(res.job, r.name);
    } catch (e) {
      fail(e.message);
    } finally {
      btn.disabled = false;
    }
  });

  function followTunnelJob(id, name) {
    $('tunnel-form').hidden = true;
    $('tn-progress').hidden = false;
    $('tn-log').replaceChildren();
    $('tn-result').textContent = 'Configuring tunnel on both servers...';
    $('tn-result').className = '';
    $('tn-back').hidden = true;
    $('tn-progress-title').focus();
    let seen = 0;
    const poll = async () => {
      let job;
      try {
        job = await api('GET', '/api/jobs/' + encodeURIComponent(id));
      } catch (e) {
        if (e.status === 401) return;
        $('tn-result').textContent = e.message;
        $('tn-result').className = 'bad';
        return;
      }
      const lines = job.lines || [];
      for (; seen < lines.length; seen++) $('tn-log').append(h('li', null, lines[seen]));
      $('tn-log').scrollTop = $('tn-log').scrollHeight;
      if (!job.done) {
        setTimeout(poll, 1000);
        return;
      }
      if (job.error) {
        $('tn-result').textContent = 'Tunnel creation failed. ' + sentence(job.error);
        $('tn-result').className = 'bad';
        $('tn-back').hidden = false;
      } else {
        $('tn-result').textContent = `Success: tunnel "${name}" is active on both servers.`;
        $('tn-result').className = 'good';
        $('tn-name').value = '';
      }
      lastTunnels = lastServers = '';
      refresh();
    };
    poll();
  }

  // ---------------------------------------------------------------- updates

  async function loadUpdates() {
    try {
      updatesCache = await api('GET', '/api/updates');
    } catch (e) {
      if (e.status === 401) throw e;
      return;
    }
    renderUpdates();
  }

  function renderUpdates() {
    const u = updatesCache;
    if (!u) return;
    let text = '';
    if (u.panel_older) {
      text = `PortBridge ${u.latest} is available (this panel is on ${u.panel}`;
      text += u.older ? `, and ${plural(u.older, 'server is', 'servers are')} on an older release).` : ').';
    } else if (u.older) {
      text = `${plural(u.older, 'server is', 'servers are')} running an older PortBridge version than this panel (${u.panel}).`;
    }
    if (u.note) text = sentence(u.note) + (text ? ' ' + text : '');
    $('update-banner').hidden = !text && !u.running;
    $('update-text').textContent = u.running ? 'A software update is currently in progress.' : text;
    for (const b of document.querySelectorAll('.update-all')) b.hidden = u.running || (!u.panel_older && !u.older);
    for (const b of document.querySelectorAll('.update-progress')) b.hidden = !u.job;

    const rows = [];
    const row = (k, v) => rows.push(h('dt', null, k), h('dd', null, v));
    row('Panel Version', u.panel);
    row('Latest Release', u.latest ? u.latest + (u.checked ? ` (checked ${ago(u.checked)})` : '') : (u.check_error ? sentence(u.check_error) : 'Not checked yet'));
    for (const s of u.servers || []) {
      const words = { current: 'Up to date', older: 'Update available', newer: 'Newer than panel', unknown: 'Unknown' }[s.state] || s.state;
      row(s.name, `${s.version || '—'} — ${words}${s.needs_ssh ? ' (needs one-time SSH upgrade)' : ''}`);
    }
    $('update-info').replaceChildren(...rows);
  }

  for (const b of document.querySelectorAll('.update-all')) {
    b.addEventListener('click', () => {
      const u = updatesCache || {};
      const self = u.panel_older
        ? ` After the other servers are updated, this panel host will also update to ${u.latest} and restart briefly without logging you out.`
        : '';
      openConfirm('Update all servers?',
        `Each server will be updated one by one while you stay in the panel, and its tunnels will restart for a few seconds.${self}`,
        'Update All Servers',
        async () => {
          const res = await api('POST', '/api/updates');
          $('confirm-dialog').close();
          followJob(res.job, 'Updating Servers', 'Done: all servers are up to date.', 'Some servers could not be updated.');
        });
    });
  }
  for (const b of document.querySelectorAll('.update-progress')) {
    b.addEventListener('click', () => {
      if (updatesCache && updatesCache.job) followJob(updatesCache.job, 'Updating Servers', 'Done: all servers are up to date.', 'Some servers could not be updated.');
    });
  }
  $('update-check').addEventListener('click', async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    try {
      updatesCache = await api('POST', '/api/updates/check');
      renderUpdates();
    } catch (e) {
      setStatus(e.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  // ------------------------------------------------------- backup & restore

  let pendingBackupJSON = '';

  async function downloadBackup(ev) {
    const btn = ev ? ev.currentTarget : $('backup-download-btn');
    const origLabel = btn ? btn.textContent : 'Download Full Backup (.json)';
    if (btn) {
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.textContent = 'Creating Backup…';
    }
    if ($('backup-loading-wrap')) $('backup-loading-wrap').hidden = false;
    if ($('backup-msg')) {
      $('backup-msg').textContent = '';
      $('backup-msg').className = '';
    }
    if ($('backup-err')) $('backup-err').textContent = '';
    try {
      const passphrase = $('backup-pass') ? $('backup-pass').value.trim() : '';
      const res = await api('POST', '/api/backup/create', { passphrase });
      const text = JSON.stringify(res.backup, null, 2) + '\n';
      const blob = new Blob([text], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = res.filename || 'portbridge-backup.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      const note = passphrase
        ? `Encrypted backup downloaded (${res.filename}). Keep your backup password safe.`
        : `Full panel backup downloaded (${res.filename}).`;
      if ($('backup-msg')) {
        $('backup-msg').textContent = note;
        $('backup-msg').className = 'good';
      }
      setStatus(note);
    } catch (e) {
      if ($('backup-err')) $('backup-err').textContent = e.message;
      setStatus(e.message, true);
    } finally {
      if ($('backup-loading-wrap')) $('backup-loading-wrap').hidden = true;
      if (btn) {
        btn.classList.remove('is-loading');
        btn.disabled = false;
        btn.textContent = origLabel;
      }
    }
  }

  if ($('backup-download-btn')) $('backup-download-btn').addEventListener('click', downloadBackup);

  function openRestoreDialog() {
    pendingBackupJSON = '';
    if ($('restore-file')) $('restore-file').value = '';
    if ($('restore-pass')) $('restore-pass').value = '';
    if ($('restore-pass-wrap')) $('restore-pass-wrap').hidden = true;
    if ($('restore-preview-wrap')) $('restore-preview-wrap').hidden = true;
    if ($('restore-loading-wrap')) $('restore-loading-wrap').hidden = true;
    if ($('restore-result-wrap')) {
      $('restore-result-wrap').hidden = true;
      $('restore-result-wrap').replaceChildren();
    }
    if ($('restore-error')) $('restore-error').textContent = '';
    if ($('restore-submit')) {
      $('restore-submit').classList.remove('is-loading');
      $('restore-submit').disabled = true;
      $('restore-submit').hidden = false;
      $('restore-submit').textContent = 'Restore Backup Now';
    }
    if ($('restore-close')) $('restore-close').disabled = false;
    setRadio('restore-mode', 'merge');
    if ($('restore-redeploy-remote')) $('restore-redeploy-remote').checked = true;
    if ($('restore-panel-identity')) $('restore-panel-identity').checked = true;
    if ($('restore-credentials')) $('restore-credentials').checked = false;
    syncChoiceCards($('restore-dialog'));
    $('restore-dialog').showModal();
  }

  if ($('backup-open-restore-btn')) $('backup-open-restore-btn').addEventListener('click', openRestoreDialog);
  if ($('restore-close')) $('restore-close').addEventListener('click', () => $('restore-dialog').close());

  async function inspectCurrentBackup() {
    if (!pendingBackupJSON) return;
    if ($('restore-error')) $('restore-error').textContent = '';
    if ($('restore-result-wrap')) $('restore-result-wrap').hidden = true;
    if ($('restore-loading-text')) $('restore-loading-text').textContent = 'Reading and inspecting backup file…';
    if ($('restore-loading-wrap')) $('restore-loading-wrap').hidden = false;
    const unlockBtn = $('restore-unlock-btn');
    if (unlockBtn) {
      unlockBtn.disabled = true;
      unlockBtn.classList.add('is-loading');
    }
    const passphrase = $('restore-pass') ? $('restore-pass').value.trim() : '';
    try {
      const rep = await api('POST', '/api/backup/inspect', {
        backup_json: pendingBackupJSON,
        passphrase,
      });
      if (rep.needs_passphrase) {
        $('restore-pass-wrap').hidden = false;
        $('restore-preview-wrap').hidden = true;
        $('restore-submit').disabled = true;
        $('restore-pass').focus();
        return;
      }
      $('restore-pass-wrap').hidden = !rep.encrypted;
      renderRestorePreview(rep);
    } catch (e) {
      $('restore-preview-wrap').hidden = true;
      $('restore-submit').disabled = true;
      $('restore-error').textContent = e.message;
    } finally {
      if ($('restore-loading-wrap')) $('restore-loading-wrap').hidden = true;
      if (unlockBtn) {
        unlockBtn.classList.remove('is-loading');
        unlockBtn.disabled = false;
      }
    }
  }

  function renderRestorePreview(rep) {
    const sum = $('restore-summary');
    sum.replaceChildren();

    const hostBadge = rep.same_server
      ? h('span', { class: 'state ok' }, 'Same Server')
      : h('span', { class: 'state warn' }, 'Different Server (Migration)');
    const srcIPs = (rep.source_ipv4 || []).concat(rep.source_ipv6 || []).join(', ') || '—';
    const curIPs = (rep.current_ipv4 || []).concat(rep.current_ipv6 || []).join(', ') || '—';

    sum.append(
      h('div', { class: 'diag-item' },
        h('div', { class: 'diag-top' }, h('strong', null, 'Backup Source Panel'), hostBadge),
        h('p', { class: 'muted small' }, `Source: ${rep.source_name || 'Panel'} (${srcIPs})${rep.source_group ? ' · Role: ' + rep.source_group.toUpperCase() : ''}`),
        h('p', { class: 'muted small' }, `This server: ${curIPs} · Created: ${rep.created_at ? rep.created_at.replace('T', ' ').replace('Z', ' UTC') : '—'}`)),
      h('div', { class: 'diag-item' },
        h('div', { class: 'diag-top' },
          h('strong', null, 'Servers & Tunnels in Backup'),
          h('span', { class: 'state ok' }, `${rep.server_count} server(s) · ${rep.paired_tunnel_count} tunnel(s)`)),
        h('p', { class: 'muted small' }, rep.server_names && rep.server_names.length
          ? `Managed servers: ${rep.server_names.join(', ')}`
          : 'No remote servers in backup (only this panel server).'),
        h('p', { class: 'muted small' }, rep.paired_tunnel_names && rep.paired_tunnel_names.length
          ? `Tunnels: ${rep.paired_tunnel_names.join(', ')} (${rep.local_tunnel_count} hosted locally on panel server)`
          : 'No tunnels recorded in backup.'),
        h('p', { class: 'muted small' }, `Cloudflare tokens: ${rep.cf_account_count} · Auto-Heal rules: ${rep.auto_heal_count}`))
    );

    const notesBox = $('restore-notes');
    notesBox.replaceChildren();
    if (rep.migration_notes && rep.migration_notes.length) {
      notesBox.hidden = false;
      const ul = h('ul', { class: 'mig-notes-list' });
      for (const n of rep.migration_notes) {
        ul.append(h('li', null, n));
      }
      notesBox.append(h('strong', null, rep.same_server ? 'Restore Check:' : 'Important Server Migration Guidance:'), ul);
    } else {
      notesBox.hidden = true;
    }

    const localBox = $('restore-local-box');
    if (rep.local_tunnel_count > 0) {
      localBox.hidden = false;
      $('restore-local-lead').textContent =
        `This backup includes ${rep.local_tunnel_count} tunnel(s) (${(rep.local_tunnel_names || []).join(', ')}) that were running directly on the panel server itself:`;
      $('restore-local-restore-card').hidden = !rep.same_server;
      $('restore-local-migrate-card').hidden = rep.same_server;
      setRadio('restore-local-action', rep.same_server ? 'restore' : 'skip');
    } else {
      localBox.hidden = true;
    }

    $('restore-preview-wrap').hidden = false;
    $('restore-submit').disabled = false;
    syncChoiceCards($('restore-dialog'));
  }

  if ($('restore-file')) {
    $('restore-file').addEventListener('change', async (ev) => {
      const f = ev.target.files && ev.target.files[0];
      if (!f) return;
      try {
        pendingBackupJSON = await f.text();
        await inspectCurrentBackup();
      } catch (e) {
        $('restore-error').textContent = 'Could not read backup file.';
      }
    });
  }

  if ($('restore-unlock-btn')) {
    $('restore-unlock-btn').addEventListener('click', inspectCurrentBackup);
  }

  if ($('restore-form')) {
    $('restore-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (!pendingBackupJSON) return;
      const btn = $('restore-submit');
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.textContent = 'Restoring Backup…';
      if ($('restore-close')) $('restore-close').disabled = true;
      $('restore-error').textContent = '';
      if ($('restore-result-wrap')) $('restore-result-wrap').hidden = true;
      if ($('restore-loading-text')) {
        $('restore-loading-text').textContent = 'Restoring servers, tokens, Auto-Heal rules, re-seeding agent connections, and verifying tunnels… Please wait.';
      }
      if ($('restore-loading-wrap')) {
        $('restore-loading-wrap').hidden = false;
      }
      try {
        const options = {
          passphrase: $('restore-pass') ? $('restore-pass').value.trim() : '',
          mode: radio('restore-mode') || 'merge',
          restore_credentials: $('restore-credentials') ? $('restore-credentials').checked : false,
          restore_panel_identity: $('restore-panel-identity') ? $('restore-panel-identity').checked : true,
          local_tunnels_action: !$('restore-local-box').hidden ? (radio('restore-local-action') || 'skip') : '',
          redeploy_remote_tunnels: $('restore-redeploy-remote') ? $('restore-redeploy-remote').checked : false,
        };
        const resp = await api('POST', '/api/backup/restore', {
          backup_json: pendingBackupJSON,
          options,
        });
        if (resp.csrf) {
          csrf = resp.csrf;
        }
        if (resp.user && $('acc-user')) {
          $('acc-user').value = resp.user;
        }
        const r = resp.result || {};
        const wrap = $('restore-result-wrap');
        wrap.replaceChildren();
        wrap.hidden = false;
        wrap.append(
          h('p', { class: 'good' },
            `Restore complete: ${r.servers_restored || 0} server(s), ${r.cf_accounts_restored || 0} Cloudflare token(s), ${r.auto_heal_restored || 0} Auto-Heal rule(s), ${r.local_tunnels_restored || 0} local tunnel(s), and ${r.remote_tunnels_joined || 0} remote tunnel endpoint(s) restored${r.remote_peers_updated ? ` (${r.remote_peers_updated} remote peer(s) updated to this server's IP)` : ''}.`)
        );
        if (r.actions_needed && r.actions_needed.length) {
          const ul = h('ul', { class: 'mig-notes-list' });
          for (const a of r.actions_needed) ul.append(h('li', null, a));
          wrap.append(h('strong', null, 'Next Steps for Your Setup:'), ul);
        }
        if (r.warnings && r.warnings.length) {
          const ul = h('ul', { class: 'mig-notes-list' });
          for (const w of r.warnings) ul.append(h('li', null, w));
          wrap.append(h('strong', null, 'Warnings:'), ul);
        }
        if ($('restore-loading-wrap')) $('restore-loading-wrap').hidden = true;
        lastServers = lastTunnels = '';
        await refresh();
        await loadSettings();
        setStatus('Backup restored successfully.');
      } catch (e) {
        $('restore-error').textContent = e.message;
      } finally {
        if ($('restore-loading-wrap')) $('restore-loading-wrap').hidden = true;
        if ($('restore-close')) $('restore-close').disabled = false;
        btn.classList.remove('is-loading');
        btn.disabled = false;
        btn.textContent = 'Restore Backup Now';
      }
    });
  }

  for (const el of document.querySelectorAll('#restore-dialog input[type="radio"]')) {
    el.addEventListener('change', () => syncChoiceCards($('restore-dialog')));
  }

  // --------------------------------------------------------- website bridges

  const DEFAULT_IRAN_DOMAINS = '.ir, shaparak.ir, zarinpal.com, kavenegar.com, melipayamak.com, sms.ir, farazsms.com, ippanel.com, payping.ir, zibal.ir, idpay.ir, nextpay.org, vandar.io, jibit.ir, asanpardakht.com, sadadpsp.ir, behpardakht.com, sep.ir, pep.co.ir, sizpay.ir, parsiangp.com';
  const DEFAULT_BYPASS_DOMAINS = 'telegram.org, api.telegram.org, t.me, wordpress.org, api.wordpress.org, github.com, googleapis.com, gstatic.com, cloudflare.com, stripe.com, paypal.com';

  let wbMode = 'create';
  let editingWebsiteBridge = null;
  let activeOutboundTestTarget = null;

  function renderWebsiteBridges(list) {
    const box = $('website-list');
    if (!box) return;
    if (!list.length) {
      box.replaceChildren(
        h('div', { class: 'card empty-card' },
          h('h3', null, 'No Website Bridges Configured Yet'),
          h('p', { class: 'muted' },
            'Host WordPress, WooCommerce, CyberPanel, LiteSpeed Enterprise, or Nginx websites on a fast Foreign VPS while giving visitors and Iranian payment/SMS gateways a public Iran VPS IP — without blocking Telegram or international APIs.'),
          h('div', { class: 'actions left' },
            h('button', { type: 'button', class: 'primary', onclick: () => openNewWebsiteBridge() }, '+ New Website Bridge'))));
      return;
    }
    box.replaceChildren(...list.map(websiteCard));
  }

  function websiteCard(t) {
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const any = ei || oi || {};
    const reverse = any.mode === 'reverse';
    const shortLink = shortLinkLabel(any);
    const linkPort = (ei && ei.link_port) || (oi && oi.link_port) || 0;
    const userPorts = ei && ei.user_ports && ei.user_ports.length ? ei.user_ports : (oi ? oi.service_ports : [80, 443]);
    const servicePorts = (oi && oi.service_ports && oi.service_ports.length) ? oi.service_ports : userPorts;
    const live = (ei && ei.live) || (oi && oi.live) || null;

    let overall = ['ok', 'Running'];
    const halves = [e, o].filter(Boolean);
    if (halves.some((x) => !x.info.running)) overall = ['bad', 'Stopped'];
    else if (live && live.path_state === 'blocked') overall = ['bad', 'Blocked'];
    else if (halves.some((x) => x.info.problem)) overall = ['warn', 'Warning'];
    else if (live && live.path_state === 'degraded') overall = ['warn', 'Degraded'];
    else if (!e || !o) overall = ['unknown', 'Unpaired'];

    const relayName = e ? (e.server_name || e.address) : (oi && oi.peer_ip ? oi.peer_ip : 'Not in panel');
    const foreignName = o ? (o.server_name || o.address) : (ei && ei.peer_ip ? ei.peer_ip : 'Not in panel');
    const relayAddr = e && e.address ? e.address : (oi && oi.peer_ip ? oi.peer_ip : '—');
    const foreignAddr = o && o.address ? o.address : (ei && ei.peer_ip ? ei.peer_ip : '—');
    const mainPort = ports(userPorts || servicePorts) || '80, 443';
    const domains = (ei && ei.website_domains) || (oi && oi.website_domains) || '';
    const outboundOn = !!((ei && ei.outbound_proxy) || (oi && oi.outbound_proxy));
    const outboundPort = (oi && oi.outbound_proxy_port) || (ei && ei.outbound_proxy_port) || 18080;
    const outboundMode = (oi && oi.outbound_proxy_mode) || (ei && ei.outbound_proxy_mode) || 'split';
    const pp = (ei && ei.proxy_protocol) || (oi && oi.proxy_protocol) || 'off';

    const edgeLive = ei && ei.live ? ei.live : null;
    const uniqueUsers = (edgeLive && typeof edgeLive.active_users === 'number')
      ? (Number(edgeLive.active_users) || 0)
      : (live && typeof live.active_users === 'number' ? (Number(live.active_users) || 0) : 0);
    const activeConns = live ? (Number(live.active_sessions) || 0) : 0;
    const visitorBadgeText = `${uniqueUsers} ${uniqueUsers === 1 ? 'visitor' : 'visitors'} · ${activeConns} ${activeConns === 1 ? 'req' : 'reqs'}`;

    const tunKey = `wb:${t.name}:${e ? e.server_id : ''}:${o ? o.server_id : ''}`;
    const headingId = 'wb-head-' + t.name + (e ? e.server_id : '') + (o ? o.server_id : '');
    const isOpen = expandedTunnels.has(tunKey);

    const proxySummary = outboundOn
      ? `127.0.0.1:${outboundPort} (${outboundMode === 'all' ? 'All via Iran' : 'Smart Split'})`
      : 'Disabled';

    const detailsGrid = h('div', { class: 'tunnel-details-grid' },
      h('div', { class: 'detail-item detail-relay' },
        h('span', { class: 'detail-label' }, 'Iran Entry Server (Public Website IP)'),
        h('span', { class: 'detail-primary' }, `${relayName} (${relayAddr})`),
        h('span', { class: 'detail-sub mono' }, `Visitors & Bank Callbacks → :${mainPort}`)),
      h('div', { class: 'detail-item detail-foreign' },
        h('span', { class: 'detail-label' }, 'Foreign Hosting Server (LiteSpeed / WordPress)'),
        h('span', { class: 'detail-primary' }, `${foreignName} (${foreignAddr})`),
        h('span', { class: 'detail-sub mono' }, `Web Server :${ports(servicePorts) || '80, 443'} · Real Visitor IP: ${pp !== 'off' ? 'PROXY ' + pp : 'Off'}`)),
      h('div', { class: 'detail-item' },
        h('span', { class: 'detail-label' }, 'Smart Outbound Proxy (Banks / SMS / Telegram)'),
        h('span', { class: 'detail-primary mono' }, proxySummary),
        h('span', { class: 'detail-sub' }, outboundOn
          ? (outboundMode === 'all'
              ? 'All proxy requests exit via Iran IP except Direct Bypass list (Telegram)'
              : '.ir & Iranian Banks/SMS → Iran IP · Telegram & International → Direct Foreign IP')
          : 'Enable in Edit to route Iranian bank/SMS calls via Iran IP')),
      h('div', { class: 'detail-item' },
        h('span', { class: 'detail-label' }, 'Website Domains & Multiplexed Link'),
        h('span', { class: 'detail-primary' }, domains || 'All SNI / Host domains on web ports'),
        h('span', { class: 'detail-sub' }, `${reverse ? 'Reverse' : 'Direct'} · ${shortLink} (:${linkPort}) · ${live ? `${live.links || 0}/${live.link_target || any.mux_links || 8} Mux trunks` : 'Shared Mux'}`)));

    const problems = halves.filter((x) => x.info.problem).map((x) => `${x.server_name}: ${sentence(x.info.problem)}`);
    if (live && live.path_note && live.path_state !== 'ok') problems.push(sentence(live.path_note));

    const bodyEl = h('div', { class: 'tunnel-body', hidden: !isOpen },
      detailsGrid,
      problems.map((p) => h('p', { class: 'problem' }, p)),
      t.stale ? h('p', { class: 'muted small' }, 'One of the servers cannot be reached right now, so these stats may be cached.') : null,
      websiteActions(t, halves));

    const ah = t.auto_heal || {};
    let ahBadge = null;
    if (ah.state === 'probing' || ah.state === 'switching') {
      ahBadge = h('span', { class: 'badge badge-autoheal is-healing' }, 'Auto-Healing…');
    } else if (ah.enabled) {
      ahBadge = h('span', { class: 'badge badge-autoheal is-on' }, 'Auto-Heal: ON');
    }

    const toggleBtn = h('button', {
      type: 'button',
      class: 'tunnel-summary',
      'aria-expanded': String(isOpen),
      'data-focus': `wb-toggle-${tunKey}`,
    },
      h('div', { class: 'tunnel-summary-left' },
        h('span', { class: 'state ' + overall[0] }, overall[1]),
        h('span', { class: 'tunnel-summary-name', id: headingId }, t.name),
        domains ? h('span', { class: 'badge badge-transport' }, domains) : null,
        h('span', { class: 'tunnel-summary-route' },
          `${relayName} ↔ ${foreignName}`,
          h('span', { class: 'tunnel-summary-port mono' }, `:${mainPort}`))),
      h('div', { class: 'tunnel-summary-right' },
        ahBadge,
        outboundOn ? h('span', { class: 'badge badge-transport mono' }, `Proxy 127.0.0.1:${outboundPort}`) : null,
        live ? h('span', { class: 'badge badge-users' }, visitorBadgeText) : null,
        h('span', { class: 'tunnel-chevron', 'aria-hidden': 'true' }, '▾')));

    const card = h('article', { class: 'card tunnel' + (isOpen ? ' is-open' : ''), 'aria-labelledby': headingId },
      toggleBtn,
      bodyEl);

    toggleBtn.addEventListener('click', () => {
      const nowOpen = !expandedTunnels.has(tunKey);
      if (nowOpen) expandedTunnels.add(tunKey);
      else expandedTunnels.delete(tunKey);
      card.classList.toggle('is-open', nowOpen);
      toggleBtn.setAttribute('aria-expanded', String(nowOpen));
      bodyEl.hidden = !nowOpen;
    });

    return card;
  }

  function websiteActions(t, halves) {
    const target = { name: t.name, edge: t.edge ? t.edge.server_id : '', origin: t.origin ? t.origin.server_id : '' };
    const key = `wb-${t.name}-${target.edge}-${target.origin}`;
    const allRunning = halves.length > 0 && halves.every((x) => x.info.running);
    const service = (action, doing) => async (ev) => {
      const btn = ev.currentTarget;
      const orig = btn.textContent;
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.textContent = `${doing}…`;
      setStatus(`${doing} ${t.name}...`);
      try {
        const res = await api('POST', '/api/tunnels/service', { ...target, action });
        const bad = (res.results || []).filter((r) => !r.ok);
        setStatus(bad.length ? '' : `${t.name}: done.`);
        if (bad.length) showResults(`${t.name}: action incomplete`, res.results);
        lastTunnels = '';
        await refresh();
      } catch (e) {
        setStatus(e.message, true);
      } finally {
        btn.classList.remove('is-loading');
        btn.textContent = orig;
        btn.disabled = false;
      }
    };
    const ahOn = !!(t.auto_heal && t.auto_heal.enabled);
    return h('div', { class: 'actions left tunnel-actions' },
      h('button', {
        type: 'button',
        class: 'primary',
        'data-focus': key + '-wpsetup',
        onclick: () => openWPSetupDialog(t)
      }, 'WordPress & LiteSpeed Setup'),
      target.origin
        ? h('button', {
            type: 'button',
            'data-focus': key + '-outtest',
            onclick: () => openOutboundTestDialog(t, target)
          }, 'Test Outbound Routing')
        : null,
      target.edge && target.origin
        ? h('button', {
            type: 'button',
            class: ahOn ? 'btn-autoheal is-on' : 'btn-autoheal',
            'data-focus': key + '-autoheal',
            onclick: () => openTunnelAutoHeal(t)
          }, ahOn ? 'Auto-Heal (ON)' : 'Auto-Heal & Failover')
        : null,
      target.edge ? h('button', { type: 'button', 'data-focus': key + '-edit', onclick: () => openEditWebsiteBridge(t) }, 'Edit') : null,
      h('button', { type: 'button', 'data-focus': key + '-diag', onclick: () => openTunnelDiag(t, target) }, 'Diagnose & Speed Test'),
      h('button', { type: 'button', 'data-focus': key + '-logs', onclick: () => openTunnelLogs(t, target) }, 'Logs'),
      h('button', { type: 'button', 'data-focus': key + '-restart', onclick: service('restart', 'Restarting') }, 'Restart'),
      allRunning
        ? h('button', { type: 'button', 'data-focus': key + '-stop', onclick: service('stop', 'Stopping') }, 'Stop')
        : h('button', { type: 'button', 'data-focus': key + '-start', onclick: service('start', 'Starting') }, 'Start'),
      h('button', { type: 'button', class: 'danger-text', 'data-focus': key + '-delete', onclick: () => confirmDeleteTunnel(t, target) }, 'Delete'));
  }

  function syncWebsiteDialogUI() {
    const outOn = $('wb-outbound') ? $('wb-outbound').checked : true;
    if ($('wb-outbound-box')) $('wb-outbound-box').hidden = !outOn;
    if ($('wb-port-preview') && $('wb-proxy-port')) {
      $('wb-port-preview').textContent = $('wb-proxy-port').value || '18080';
    }
    syncChoiceCards($('website-dialog'));
  }

  if ($('wb-outbound')) $('wb-outbound').addEventListener('change', syncWebsiteDialogUI);
  if ($('wb-proxy-port')) $('wb-proxy-port').addEventListener('input', syncWebsiteDialogUI);

  async function openNewWebsiteBridge() {
    if (!serversCache.length) {
      try { await loadServers(); } catch (_) {}
    }
    const relays = serversCache.filter((s) => s.group === 'relay');
    const foreigns = serversCache.filter((s) => s.group === 'foreign');
    if (!relays.length || !foreigns.length) {
      setStatus('Add at least one Relay (Iran) server and one Foreign server before creating a Website Bridge.', true);
      selectTab('servers', false);
      return;
    }
    wbMode = 'create';
    editingWebsiteBridge = null;
    $('wb-title').textContent = 'New Website Bridge';
    $('wb-sub').textContent = 'Forward visitors from an Iran VPS IP to your Foreign web server (LiteSpeed / CyberPanel / WordPress / Nginx), and give WordPress a smart local outbound proxy for Iranian banks & SMS gateways while keeping Telegram direct.';
    $('wb-submit').textContent = 'Create Website Bridge';
    if ($('wb-step1-title')) $('wb-step1-title').textContent = 'Servers, Bridge Name & Website Domains';
    if ($('wb-step4-title')) $('wb-step4-title').textContent = 'Inter-Server Link & Multiplexed Web Capacity';

    $('wb-relay').replaceChildren(...relays.map(serverOption));
    $('wb-foreign').replaceChildren(...foreigns.map(serverOption));
    $('wb-create-servers').hidden = false;
    $('wb-name-wrap').hidden = false;
    $('wb-create-transport').hidden = false;
    $('wb-autoheal-wrap').hidden = false;

    $('wb-name').value = '';
    $('wb-domains').value = '';
    $('wb-ports').value = '80,443';
    $('wb-linkport').value = '8443';
    setRadio('wb-proxy', 'v1');
    $('wb-outbound').checked = true;
    $('wb-proxy-port').value = '18080';
    setRadio('wb-proxy-mode', 'split');
    $('wb-iran-domains').value = DEFAULT_IRAN_DOMAINS;
    $('wb-bypass-domains').value = DEFAULT_BYPASS_DOMAINS;
    setRadio('wb-mode', 'direct');
    $('wb-link').value = 'website';
    $('wb-sni').value = 'www.bing.com';
    if ($('wb-ipv6')) $('wb-ipv6').checked = false;
    $('wb-mux-links').value = '8';
    $('wb-max-conn').value = '4000';
    $('wb-autoheal').checked = true;
    $('wb-error').textContent = '';
    $('wb-ports-result').replaceChildren();

    syncWebsiteDialogUI();
    openDialog($('website-dialog'));
    $('wb-name').focus();
  }

  function openEditWebsiteBridge(t) {
    wbMode = 'edit';
    editingWebsiteBridge = t;
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const any = ei || oi || {};
    const servicePorts = (oi && oi.service_ports && oi.service_ports.length) ? oi.service_ports : (ei && ei.user_ports ? ei.user_ports : [80, 443]);
    const linkPort = (ei && ei.link_port) || (oi && oi.link_port) || 8443;
    const pp = (ei && ei.proxy_protocol) || (oi && oi.proxy_protocol) || 'v1';
    const outOn = !!((ei && ei.outbound_proxy) || (oi && oi.outbound_proxy));
    const outPort = (oi && oi.outbound_proxy_port) || (ei && ei.outbound_proxy_port) || 18080;
    const outMode = (oi && oi.outbound_proxy_mode) || (ei && ei.outbound_proxy_mode) || 'split';
    const iranDoms = (oi && oi.outbound_iran_domains) || (ei && ei.outbound_iran_domains) || DEFAULT_IRAN_DOMAINS;
    const bypassDoms = (oi && oi.outbound_bypass_domains) || (ei && ei.outbound_bypass_domains) || DEFAULT_BYPASS_DOMAINS;
    const muxVal = (ei && ei.mux_links) || (oi && oi.mux_links) || 8;
    const maxConnVal = (ei && ei.max_conn) || (oi && oi.max_conn) || 4000;

    $('wb-title').textContent = `Edit Website Bridge: ${t.name}`;
    const where = [e && e.server_name, o && o.server_name].filter(Boolean).join(' ↔ ');
    $('wb-sub').textContent = `Update web ports, visitor IP forwarding, or Smart Outbound Proxy domains across ${where}.`;
    $('wb-submit').textContent = 'Save & Apply Website Bridge';
    if ($('wb-step1-title')) $('wb-step1-title').textContent = 'Website Domains';
    if ($('wb-step4-title')) $('wb-step4-title').textContent = 'Multiplexed Web Capacity';

    $('wb-create-servers').hidden = true;
    $('wb-name-wrap').hidden = true;
    $('wb-create-transport').hidden = true;
    $('wb-autoheal-wrap').hidden = true;

    $('wb-name').value = t.name;
    $('wb-domains').value = (ei && ei.website_domains) || (oi && oi.website_domains) || '';
    $('wb-ports').value = (servicePorts || [80, 443]).join(',');
    $('wb-linkport').value = String(linkPort);
    setRadio('wb-proxy', ['off', 'v1', 'v2'].includes(pp) ? pp : 'v1');
    $('wb-outbound').checked = outOn;
    $('wb-proxy-port').value = String(outPort);
    setRadio('wb-proxy-mode', outMode === 'all' ? 'all' : 'split');
    $('wb-iran-domains').value = iranDoms;
    $('wb-bypass-domains').value = bypassDoms;
    $('wb-mux-links').value = String(muxVal);
    $('wb-max-conn').value = String(maxConnVal);
    $('wb-error').textContent = '';
    $('wb-ports-result').replaceChildren();

    syncWebsiteDialogUI();
    openDialog($('website-dialog'));
    $('wb-domains').focus();
  }

  if ($('new-website-btn')) {
    $('new-website-btn').addEventListener('click', () => openNewWebsiteBridge());
  }
  if ($('wb-cancel')) {
    $('wb-cancel').addEventListener('click', () => $('website-dialog').close());
  }

  if ($('wb-check-ports')) {
    $('wb-check-ports').addEventListener('click', async () => {
      const webPorts = $('wb-ports').value.trim();
      const linkPort = Number($('wb-linkport').value || 0);
      const outOn = $('wb-outbound').checked;
      const outPort = Number($('wb-proxy-port').value || 18080);
      const out = $('wb-ports-result');
      if (!portList.test(webPorts) || !linkPort) {
        out.replaceChildren(h('li', { class: 'bad' }, 'Enter valid Web Ports (e.g. 80,443) and Internal Tunnel Bridge Port first.'));
        return;
      }
      let relayId = '', foreignId = '', mode = 'direct', ownTag = '';
      if (wbMode === 'edit' && editingWebsiteBridge) {
        const t = editingWebsiteBridge;
        relayId = t.edge ? t.edge.server_id : '';
        foreignId = t.origin ? t.origin.server_id : '';
        const any = (t.edge && t.edge.info) || (t.origin && t.origin.info) || {};
        mode = any.mode || 'direct';
        ownTag = `PortBridge tunnel "${t.name}"`;
      } else {
        relayId = $('wb-relay').value;
        foreignId = $('wb-foreign').value;
        mode = radio('wb-mode') || 'direct';
      }
      out.replaceChildren(h('li', null, 'Checking web & proxy ports on both servers...'));
      const relayPorts = webPorts + (mode === 'reverse' ? ',' + linkPort : '');
      const foreignPorts = webPorts + (mode === 'direct' ? ',' + linkPort : '') + (outOn && outPort ? ',' + outPort : '');
      const checkOne = async (srvId, list, role) => {
        if (!srvId) return [];
        const srv = serverById(srvId);
        const sName = (srv && (srv.name || srv.address)) || srvId;
        try {
          const res = await api('POST', '/api/ports', { server: srvId, ports: list });
          return (res.ports || []).map((p) => {
            const isSelf = ownTag && p.by === ownTag;
            const by = p.by ? ` (${p.by.replace(/^PortBridge /, '')})` : '';
            if (role === 'foreign' && outOn && p.port === outPort) {
              const ok = p.state === 'free' || isSelf;
              return h('li', { class: ok ? 'good' : 'bad' },
                `${sName} — Local Outbound Proxy 127.0.0.1:${p.port}: ${ok ? 'available' : 'already in use' + by}`);
            }
            if (p.port === linkPort && ((role === 'relay' && mode === 'reverse') || (role === 'foreign' && mode === 'direct'))) {
              const ok = p.state === 'free' || isSelf;
              return h('li', { class: ok ? 'good' : 'bad' },
                `${sName} — Bridge Port ${p.port}: ${ok ? 'available' : 'already in use' + by}`);
            }
            if (role === 'foreign') {
              const ok = p.state !== 'free';
              return h('li', { class: ok ? 'good' : 'warn' },
                `${sName} — Web Server Port ${p.port}: ${ok ? 'web server listening' + by + ' (ready)' : 'nothing listening on port ' + p.port + ' yet (make sure LiteSpeed / Nginx is running)'}`);
            }
            const ok = p.state === 'free' || isSelf;
            return h('li', { class: ok ? 'good' : 'bad' },
              `${sName} — Public Web Port ${p.port}: ${ok ? 'available on Iran server' : 'already in use' + by}`);
          });
        } catch (e) {
          return [h('li', { class: 'warn' }, `${sName}: could not check ports (${e.message})`)];
        }
      };
      const [a, b] = await Promise.all([checkOne(relayId, relayPorts, 'relay'), checkOne(foreignId, foreignPorts, 'foreign')]);
      out.replaceChildren(...a, ...b);
    });
  }

  if ($('website-form')) {
    $('website-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const err = $('wb-error');
      err.textContent = '';
      const fail = (msg, el) => { err.textContent = msg; if (el) el.focus(); };

      const webPorts = $('wb-ports').value.trim();
      const linkPort = Number($('wb-linkport').value || 0);
      const domains = $('wb-domains').value.trim();
      const proxyProto = radio('wb-proxy') || 'v1';
      const outOn = $('wb-outbound').checked;
      const outPort = Number($('wb-proxy-port').value || 18080);
      const outMode = radio('wb-proxy-mode') || 'split';
      const iranDoms = $('wb-iran-domains').value.trim();
      const bypassDoms = $('wb-bypass-domains').value.trim();
      const muxLinks = Number($('wb-mux-links').value || 8);
      const maxConn = Number($('wb-max-conn').value || 4000);

      if (!portList.test(webPorts)) return fail('Enter valid Web Ports separated by commas (e.g. 80,443).', $('wb-ports'));
      if (!(linkPort >= 1 && linkPort <= 65535)) return fail('Internal Tunnel Bridge Port must be between 1 and 65535.', $('wb-linkport'));
      const webPortNums = webPorts.split(',').map((x) => Number(x.trim()));
      if (webPortNums.includes(linkPort)) {
        return fail(`Internal Tunnel Bridge Port (${linkPort}) cannot be one of the Web Ports (${webPorts}). Use e.g. 8443.`, $('wb-linkport'));
      }
      if (outOn) {
        if (!(outPort >= 1024 && outPort <= 65535)) return fail('Local Outbound Proxy Port must be between 1024 and 65535.', $('wb-proxy-port'));
        if (webPortNums.includes(outPort) || outPort === linkPort) {
          return fail('Local Outbound Proxy Port must be different from the Web Ports and Bridge Port.', $('wb-proxy-port'));
        }
      }
      if (!(muxLinks >= 1 && muxLinks <= 16)) return fail('Parallel Multiplexed Trunks must be between 1 and 16.', $('wb-mux-links'));
      if (!(maxConn >= 10 && maxConn <= 100000)) return fail('Max Concurrent HTTP/HTTPS Requests must be between 10 and 100000.', $('wb-max-conn'));

      const btn = $('wb-submit');
      btn.disabled = true;
      try {
        if (wbMode === 'edit' && editingWebsiteBridge) {
          const t = editingWebsiteBridge;
          const res = await api('POST', '/api/tunnels/edit', {
            name: t.name,
            edge: t.edge ? t.edge.server_id : '',
            origin: t.origin ? t.origin.server_id : '',
            service_ports: webPorts,
            user_ports: webPorts,
            link_port: linkPort,
            proxy_protocol: proxyProto,
            mux: 'on',
            mux_links: muxLinks,
            max_conn: maxConn,
            website_domains: domains,
            outbound_proxy: outOn ? 'on' : 'off',
            outbound_proxy_port: outPort,
            outbound_proxy_mode: outMode,
            outbound_iran_domains: iranDoms,
            outbound_bypass_domains: bypassDoms,
          });
          $('website-dialog').close();
          followJob(res.job, `Updating Website Bridge "${t.name}"`,
            `Website Bridge "${t.name}" has been updated and restarted on both servers.`,
            'Could not update Website Bridge.');
        } else {
          const name = $('wb-name').value.trim();
          if (!/^[A-Za-z0-9_-]{1,40}$/.test(name)) {
            btn.disabled = false;
            return fail('Enter a Bridge Name using letters, numbers, dashes, or underscores (e.g. uk-wordpress).', $('wb-name'));
          }
          const relay = $('wb-relay').value;
          const foreign = $('wb-foreign').value;
          if (!relay || !foreign || relay === foreign) {
            btn.disabled = false;
            return fail('Choose an Iran Entry Server and a Foreign Hosting Server.');
          }
          const link = $('wb-link').value || 'website';
          const sni = $('wb-sni').value.trim() || 'www.bing.com';
          const res = await api('POST', '/api/tunnels', {
            name,
            relay,
            foreign,
            mode: radio('wb-mode') || 'direct',
            link,
            server_name: sni,
            spoof_sni: link === 'sni-spoof' ? sni : '',
            stealth: true,
            real_site: true,
            shared: true,
            shared_links: muxLinks,
            max_conn: maxConn,
            service_ports: webPorts,
            user_ports: webPorts,
            link_port: linkPort,
            proxy_protocol: proxyProto,
            ipv6: !!($('wb-ipv6') && $('wb-ipv6').checked),
            auto_heal: $('wb-autoheal').checked,
            website_bridge: true,
            website_domains: domains,
            outbound_proxy: outOn,
            outbound_proxy_port: outPort,
            outbound_proxy_mode: outMode,
            outbound_iran_domains: iranDoms,
            outbound_bypass_domains: bypassDoms,
          });
          $('website-dialog').close();
          selectTab('websites', false);
          followJob(res.job, `Creating Website Bridge "${name}"`,
            `Website Bridge "${name}" is active! Click "WordPress & LiteSpeed Setup" on its card for your wp-config.php snippet.`,
            'Could not create Website Bridge.');
        }
      } catch (e) {
        fail(e.message);
      } finally {
        btn.disabled = false;
      }
    });
  }

  function openWPSetupDialog(t) {
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const relayAddr = (e && e.address) || (ei && ei.local_ip) || (oi && oi.peer_ip) || '<Iran-Server-IP>';
    const foreignAddr = (o && o.address) || (oi && oi.local_ip) || '<Foreign-Server-IP>';
    const outPort = (oi && oi.outbound_proxy_port) || (ei && ei.outbound_proxy_port) || 18080;
    const domains = (ei && ei.website_domains) || (oi && oi.website_domains) || 'yourdomain.ir';
    const bypassRaw = (oi && oi.outbound_bypass_domains) || (ei && ei.outbound_bypass_domains) || DEFAULT_BYPASS_DOMAINS;
    const wpBypassList = ['localhost', '127.0.0.1', '*.telegram.org', 'api.telegram.org', 't.me', '*.wordpress.org', 'api.wordpress.org'];
    for (const part of bypassRaw.split(',')) {
      const d = part.trim();
      if (d && !wpBypassList.includes(d)) wpBypassList.push(d);
    }

    $('wp-setup-title').textContent = `WordPress, CyberPanel & LiteSpeed Setup — ${t.name}`;
    $('wp-dns-desc').textContent = `Point your domain(s) (${domains}) to your Iran Entry Server IP so visitors and Iranian bank callbacks connect through Iran:`;
    $('wp-dns-box').replaceChildren(
      h('p', null,
        h('strong', null, 'DNS A Record: '),
        `Point `,
        h('code', null, domains),
        ` (and `,
        h('code', null, 'www'),
        `) → `,
        h('code', null, relayAddr),
        ` (with Cloudflare Proxy OFF / Grey Cloud for `,
        h('code', null, '.ir'),
        ` bank callbacks, or keep your SSL certs on CyberPanel/LiteSpeed on ${foreignAddr}).`));

    const wpConfigCode = [
      `/* === PortBridge Smart Outbound Proxy (${t.name}) ===`,
      ` * Routes Iranian banks, Shaparak & SMS gateways through Iran IP (${relayAddr})`,
      ` * while Telegram & international APIs connect directly from Foreign VPS (${foreignAddr}).`,
      ` */`,
      `define( 'WP_PROXY_HOST', '127.0.0.1' );`,
      `define( 'WP_PROXY_PORT', '${outPort}' );`,
      `define( 'WP_PROXY_BYPASS_HOSTS', '${wpBypassList.slice(0, 12).join(', ')}' );`,
    ].join('\n');

    const muPluginCode = [
      `<?php`,
      `/**`,
      ` * Plugin Name: PortBridge Smart Iran/Direct Outbound Proxy`,
      ` * Description: Routes Iranian bank & SMS gateway cURL calls via PortBridge (127.0.0.1:${outPort}) while keeping Telegram direct.`,
      ` * Save as: wp-content/mu-plugins/portbridge-proxy.php`,
      ` */`,
      `add_action( 'http_api_curl', function( $handle, $r, $url ) {`,
      `    $host = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );`,
      `    if ( ! $host || $host === 'localhost' || $host === '127.0.0.1' ) {`,
      `        return;`,
      `    }`,
      `    // Telegram and international bypass hosts connect directly from Foreign VPS:`,
      `    if ( str_ends_with( $host, 'telegram.org' ) || $host === 't.me' ) {`,
      `        curl_setopt( $handle, CURLOPT_PROXY, '' );`,
      `        return;`,
      `    }`,
      `    // All other requests go through PortBridge Smart Splitter on 127.0.0.1:${outPort}:`,
      `    curl_setopt( $handle, CURLOPT_PROXY, '127.0.0.1:${outPort}' );`,
      `    curl_setopt( $handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP );`,
      `}, 10, 3 );`,
    ].join('\n');

    $('wp-config-snippet').textContent = wpConfigCode;
    $('wp-muplugin-snippet').textContent = muPluginCode;

    $('wp-litespeed-steps').replaceChildren(
      h('li', null,
        'Open your CyberPanel / LiteSpeed WebAdmin Console at ',
        h('code', null, `https://${foreignAddr}:7080`),
        '.'),
      h('li', null,
        'Go to ',
        h('strong', null, 'Configuration → Server → General'),
        ' and set ',
        h('strong', null, 'Use Client IP in Header'),
        ' to ',
        h('code', null, 'Trusted IP Only'),
        '.'),
      h('li', null,
        'Go to ',
        h('strong', null, 'Configuration → Server → Security → Access Control'),
        ' and in ',
        h('strong', null, 'Allowed List'),
        ', add ',
        h('code', null, `127.0.0.1T, ${relayAddr}T`),
        ' (with the trailing ',
        h('code', null, 'T'),
        ' for Trusted Proxy), then click ',
        h('strong', null, 'Graceful Restart'),
        '.'));

    openDialog($('wp-setup-dialog'));
  }

  if ($('wp-copy-config')) {
    $('wp-copy-config').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('wp-config-snippet').textContent);
        setStatus('Copied wp-config.php snippet to clipboard.');
      } catch (_) {}
    });
  }
  if ($('wp-copy-muplugin')) {
    $('wp-copy-muplugin').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('wp-muplugin-snippet').textContent);
        setStatus('Copied mu-plugin PHP code to clipboard.');
      } catch (_) {}
    });
  }
  if ($('wp-setup-close')) {
    $('wp-setup-close').addEventListener('click', () => $('wp-setup-dialog').close());
  }

  async function runOutboundTest(customHost) {
    if (!activeOutboundTestTarget) return;
    $('obt-loading').hidden = false;
    $('obt-error').textContent = '';
    $('obt-rerun').disabled = true;
    $('obt-test-custom').disabled = true;
    try {
      const res = await api('POST', '/api/tunnels/test-outbound', {
        ...activeOutboundTestTarget,
        custom_host: customHost || '',
      });
      const r = res.result || {};
      const probes = r.probes || [];
      const cards = probes.map((p, idx) => {
        const ok = !!p.ok;
        const routeCode = p.actual_route || p.expected_route || '';
        const routeBadge = routeCode === 'iran'
          ? 'Routed via Iran VPS IP'
          : (routeCode === 'direct' ? 'Routed Directly via Foreign VPS IP' : (routeCode || '—'));
        return h('div', { class: 'diag-card' },
          h('div', { class: 'diag-head' },
            h('strong', null, `${idx + 1}. ${p.label || p.target}`),
            h('span', { class: 'state ' + (ok ? 'ok' : 'bad') }, ok ? 'Verified' : 'Failed')),
          h('p', { class: 'muted small mono' }, `Target: ${p.target} · Proxy: ${r.proxy_addr || '127.0.0.1:18080'} (${r.proxy_mode || 'split'})`),
          h('ul', { class: 'diag-list' },
            h('li', { class: ok ? 'good' : 'bad' },
              h('strong', null, 'Route Taken: '),
              routeBadge),
            p.exit_ip
              ? h('li', { class: 'good' },
                  h('strong', null, routeCode === 'iran' ? 'Verified Iran Exit IP: ' : 'Verified Foreign Exit IP: '),
                  h('code', null, p.exit_ip))
              : null,
            typeof p.latency_ms === 'number'
              ? h('li', null,
                  h('strong', null, 'Round-Trip Latency: '),
                  `${p.latency_ms} ms`)
              : null,
            p.error
              ? h('li', { class: 'bad' },
                  h('strong', null, 'Error: '),
                  p.error)
              : null));
      });
      $('obt-results').replaceChildren(...cards);
    } catch (e) {
      $('obt-error').textContent = e.message;
    } finally {
      $('obt-loading').hidden = true;
      $('obt-rerun').disabled = false;
      $('obt-test-custom').disabled = false;
    }
  }

  function openOutboundTestDialog(t, target) {
    activeOutboundTestTarget = target;
    $('obt-title').textContent = `Test Smart Outbound Proxy — ${t.name}`;
    $('obt-custom-host').value = '';
    $('obt-results').replaceChildren();
    $('obt-error').textContent = '';
    openDialog($('outbound-test-dialog'));
    runOutboundTest('');
  }

  if ($('obt-rerun')) {
    $('obt-rerun').addEventListener('click', () => runOutboundTest($('obt-custom-host').value.trim()));
  }
  if ($('obt-test-custom')) {
    $('obt-test-custom').addEventListener('click', () => runOutboundTest($('obt-custom-host').value.trim()));
  }
  if ($('obt-close')) {
    $('obt-close').addEventListener('click', () => $('outbound-test-dialog').close());
  }

  // ------------------------------------------------------------------- start

  (async () => {
    syncChoiceCards();
    try {
      enter(await api('GET', '/api/me'));
    } catch (e) {
      if (e.status !== 401) showLogin(e.message);
    }
  })();
})();
