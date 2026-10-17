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

  function enter(me) {
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

  const TABS = ['servers', 'tunnels', 'dns', 'settings'];
  let cfLoadedOnce = false;

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

    const totalTunnels = tunnelsCache.length;
    let runningTunnels = 0;
    let activeUsers = 0;
    for (const t of tunnelsCache) {
      const e = t.edge, o = t.origin;
      const halves = [e, o].filter(Boolean);
      if (halves.length && halves.every((x) => x.info && x.info.running)) runningTunnels++;
      const live = (e && e.info && e.info.live) || (o && o.info && o.info.live) || null;
      if (live && live.active_sessions) activeUsers += Number(live.active_sessions) || 0;
    }

    if ($('sum-tunnels')) {
      $('sum-tunnels').textContent = String(totalTunnels);
      $('sum-tunnels-sub').textContent = totalTunnels ? `${runningTunnels} running now` : 'No tunnels configured';
    }
    if ($('sum-users')) {
      $('sum-users').textContent = String(activeUsers);
      $('sum-users-sub').textContent = activeUsers === 1 ? '1 active session' : `${activeUsers} active sessions`;
    }

    const ct = $('count-tunnels');
    if (ct) {
      ct.textContent = String(totalTunnels);
      ct.hidden = totalTunnels === 0;
    }
  }

  async function refresh() {
    if ($('shell').hidden) return;
    try {
      if (currentTab === 'servers') {
        await Promise.all([loadServers(), loadTunnels()]);
      } else if (currentTab === 'tunnels') {
        await Promise.all([loadTunnels(), loadServers()]);
      } else if (currentTab === 'dns') {
        await Promise.all([loadServers(), loadCloudflare(false)]);
      } else {
        await loadSettings();
      }
      if (statusIsProblem) setStatus('');
    } catch (e) {
      if (e.status !== 401) setStatus(e.message, true);
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
        const detail = [t.mode === 'reverse' ? 'Reverse' : 'Direct', shortLinkLabel(t)].filter(Boolean).join(' · ');
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
    $('confirm-error').textContent = '';
    confirmAction = action;
    openDialog($('confirm-dialog'));
    $('confirm-no').focus();
  }

  $('confirm-no').addEventListener('click', () => $('confirm-dialog').close());
  $('confirm-yes').addEventListener('click', async () => {
    const btn = $('confirm-yes');
    btn.disabled = true;
    try {
      await confirmAction();
      $('confirm-dialog').close();
    } catch (e) {
      $('confirm-error').textContent = e.message;
    } finally {
      btn.disabled = false;
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
    syncChoiceCards($('add-dialog'));
  }
  for (const r of document.querySelectorAll('input[name="auth"]')) r.addEventListener('change', showAuth);

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
  $('add-close').addEventListener('click', () => $('add-dialog').close());
  $('add-back').addEventListener('click', () => {
    $('add-progress').hidden = true;
    $('add-form').hidden = false;
    $('add-error').textContent = 'Please enter the SSH password or key again (it is never stored).';
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
    if (kind === 'key' && !body.private_key.trim()) { err.textContent = 'Paste the SSH private key.'; $('add-key').focus(); return; }
    if (kind === 'file' && !body.private_key.trim()) { err.textContent = 'Select the SSH private key file.'; $('add-file').focus(); return; }

    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const path = updating ? `/api/servers/${encodeURIComponent(addMode.server.id)}/ssh-update` : '/api/servers';
      const res = await api('POST', path, body);
      clearSecrets();
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
        $('add-result').textContent = (updating ? 'Upgrade failed. ' : 'Could not add server. ') + sentence(job.error);
        $('add-result').className = 'bad';
        $('add-back').hidden = false;
      } else {
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
    const poll = async () => {
      let job;
      try {
        job = await api('GET', '/api/jobs/' + encodeURIComponent(id));
      } catch (e) {
        if (e.status === 401) return;
        $('job-result').textContent = e.status === 0 || e.status === 404
          ? 'The panel is restarting on the new version. Please sign in again in a moment to view the results.'
          : e.message;
        $('job-note').hidden = true;
        setTimeout(waitForPanel, 5000);
        return;
      }
      const lines = job.lines || [];
      for (; seen < lines.length; seen++) $('job-log').append(h('li', null, lines[seen]));
      $('job-log').scrollTop = $('job-log').scrollHeight;
      if (!job.done) {
        setTimeout(poll, 1500);
        return;
      }
      $('job-note').hidden = true;
      $('job-result').textContent = job.error ? `${failText} ${sentence(job.error)}` : okText;
      $('job-result').className = job.error ? 'bad' : 'good';
      lastServers = lastTunnels = '';
      refresh();
    };
    poll();
  }

  async function waitForPanel() {
    try {
      await api('GET', '/api/me');
    } catch (e) {
      if (e.status === 0) setTimeout(waitForPanel, 5000);
    }
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
    const box = $('tunnel-list');
    if (!list.length) {
      box.replaceChildren(h('p', { class: 'empty' },
        'No tunnels yet. Click "+ New Tunnel", or drag a Relay server onto a Foreign server on the Servers tab.'));
      return;
    }
    box.replaceChildren(...list.map(tunnelCard));
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
    const raw = String(any.link || any.transport || '');
    const m = raw.match(/\(([^(),]+)\)/);
    const host = m ? m[1] : '';
    if (/CDN backup/i.test(raw)) return host ? `HTTPS (${host}) + CDN` : 'HTTPS + CDN Backup';
    if (/gRPC through a CDN/i.test(raw)) return host ? `gRPC + CDN (${host})` : 'gRPC + CDN';
    if (/through a CDN/i.test(raw)) return host ? `CDN (${host})` : 'CDN (WebSocket)';
    if (/gRPC/i.test(raw)) return host ? `gRPC (${host})` : 'gRPC';
    if (/HTTPS site/i.test(raw) || any.transport === 'tls' || any.transport === 'tlsmux') {
      return host ? `HTTPS (${host})` : 'HTTPS';
    }
    if (/KCP/i.test(raw) || any.transport === 'kcp') return 'KCP (UDP)';
    if (/website header/i.test(raw)) return host ? `TCP + HTTP (${host})` : 'TCP + HTTP Header';
    if (/plain/i.test(raw) || any.transport === 'tcp' || any.transport === 'tcpmux') return 'Plain TCP';
    return raw.length > 28 ? raw.slice(0, 28) + '…' : (raw || 'TCP');
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
    const activeCount = live ? (Number(live.active_sessions) || 0) : 0;

    const tunKey = `${t.name}:${e ? e.server_id : ''}:${o ? o.server_id : ''}`;
    const headingId = 'tun-' + t.name + (e ? e.server_id : '') + (o ? o.server_id : '');
    const isOpen = expandedTunnels.has(tunKey);

    // Essential details inside expanded view
    const relayAddr = e && e.address ? e.address : (oi && oi.peer_ip ? oi.peer_ip : '—');
    const foreignAddr = o && o.address ? o.address : (ei && ei.peer_ip ? ei.peer_ip : '—');
    const modeLabel = reverse ? 'Reverse (Foreign → Relay)' : 'Direct (Relay → Foreign)';
    const extraTags = [];
    if (any.real_site) extraTags.push('Real-Site Cover');
    if (any.cdn && !/CDN/i.test(shortLink)) extraTags.push('CDN Ready');
    if (any.proxy_protocol && any.proxy_protocol !== 'off') extraTags.push(`PROXY ${any.proxy_protocol}`);
    if (live && live.on_backup_route) extraTags.push('On Backup Route');

    let healthParts = [];
    if (live) {
      const pw = PATH_WORDS[live.path_state] || PATH_WORDS.unknown;
      healthParts.push(pw[1]);
      healthParts.push(`${activeCount} active ${activeCount === 1 ? 'user' : 'users'}`);
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

    const detailsGrid = h('div', { class: 'tunnel-details-grid' },
      h('div', { class: 'detail-item detail-relay' },
        h('span', { class: 'detail-label' }, 'Relay (Iran) · Entry'),
        h('span', { class: 'detail-primary' }, relayName),
        h('span', { class: 'detail-sub mono' }, `${relayAddr} · Listen :${ports(userPorts) || '—'}`)),
      h('div', { class: 'detail-item detail-foreign' },
        h('span', { class: 'detail-label' }, 'Foreign · Exit'),
        h('span', { class: 'detail-primary' }, foreignName),
        h('span', { class: 'detail-sub mono' }, `${foreignAddr} · Inbound :${ports(servicePorts) || '—'}`)),
      h('div', { class: 'detail-item' },
        h('span', { class: 'detail-label' }, 'Bridge & Transport'),
        h('span', { class: 'detail-primary' }, `${shortLink}${linkPort ? ' · :' + linkPort : ''}`),
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
        h('span', { class: 'badge badge-transport' }, `${reverse ? 'Reverse' : 'Direct'} · ${shortLink}`),
        live ? h('span', { class: 'badge badge-users' }, `${activeCount} active`) : null,
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
      btn.disabled = true;
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
        btn.disabled = false;
      }
    };
    return h('div', { class: 'actions left tunnel-actions' },
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

  function openEditTunnel(t) {
    editingTunnel = t;
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const any = ei || oi || {};
    const servicePorts = (oi && oi.service_ports && oi.service_ports.length) ? oi.service_ports : (ei ? ei.service_ports : []);
    const userPorts = (ei && ei.user_ports && ei.user_ports.length) ? ei.user_ports : servicePorts;
    const linkPort = (ei && ei.link_port) || (oi && oi.link_port) || 443;
    const isMux = !!any.mux;

    $('et-title').textContent = `Edit Tunnel: ${t.name}`;
    const where = [e && e.server_name, o && o.server_name].filter(Boolean).join(' ↔ ');
    $('et-sub').textContent = where
      ? `Update ports, capacity, or firewall settings across ${where}. Both servers will restart automatically.`
      : 'Update ports, capacity, or firewall settings for this tunnel.';

    $('et-service').value = (servicePorts || []).join(',');
    $('et-users').value = (userPorts || []).join(',') === (servicePorts || []).join(',') ? '' : (userPorts || []).join(',');
    $('et-linkport').value = String(linkPort);

    $('et-pool-wrap').hidden = isMux;
    $('et-mux-wrap').hidden = !isMux;
    $('et-pool').value = String((ei && ei.pool_size) || (oi && oi.pool_size) || 25);
    $('et-mux-links').value = String((ei && ei.mux_links) || (oi && oi.mux_links) || 4);
    $('et-max-conn').value = String((ei && ei.max_conn) || (oi && oi.max_conn) || 2000);

    const pp = (ei && ei.proxy_protocol) || (oi && oi.proxy_protocol) || 'off';
    setRadio('et-proxy', ['off', 'v1', 'v2'].includes(pp) ? pp : 'off');

    const fw = ei && typeof ei.firewall === 'boolean' ? ei.firewall : true;
    $('et-firewall').checked = fw;

    if ($('et-peer-ip')) $('et-peer-ip').value = (ei && ei.peer_ip) || (oi && oi.peer_ip) || '';
    if ($('et-peer-wrap')) $('et-peer-wrap').hidden = !!any.gre;
    if ($('et-spare-ttl-wrap')) $('et-spare-ttl-wrap').hidden = isMux;
    if ($('et-spare-ttl')) $('et-spare-ttl').value = (ei && ei.spare_ttl) || (oi && oi.spare_ttl) || '1m0s';
    if ($('et-drain')) $('et-drain').value = (ei && ei.drain) || (oi && oi.drain) || '10s';
    if ($('et-advanced')) $('et-advanced').open = false;

    $('et-error').textContent = '';
    $('et-ports-result').replaceChildren();
    $('edit-tunnel-form').hidden = false;
    $('et-progress').hidden = true;
    openDialog($('edit-tunnel-dialog'));
    $('et-service').focus();
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
    const poolSize = Number($('et-pool').value || 0);
    const muxLinks = Number($('et-mux-links').value || 0);
    const maxConn = Number($('et-max-conn').value || 0);
    const proxyProto = radio('et-proxy') || 'off';
    const firewall = $('et-firewall').checked ? 'on' : 'off';
    const peerIP = $('et-peer-ip') ? $('et-peer-ip').value.trim() : '';
    const spareTTL = ($('et-spare-ttl') && !$('et-spare-ttl-wrap').hidden) ? $('et-spare-ttl').value.trim() : '';
    const drain = $('et-drain') ? $('et-drain').value.trim() : '';

    if (!portList.test(servicePorts)) return fail('Enter the Foreign Inbound Port(s), separated by commas.', $('et-service'));
    if (userPorts && !portList.test(userPorts)) return fail('Enter the Relay User Listen Port(s) separated by commas, or leave empty to match Inbound Port(s).', $('et-users'));
    if (userPorts && userPorts.split(',').length !== servicePorts.split(',').length) {
      return fail('The number of User Listen Ports must match the number of Inbound Ports.', $('et-users'));
    }
    if (!(linkPort >= 1 && linkPort <= 65535)) return fail('Tunnel Bridge Port must be between 1 and 65535.', $('et-linkport'));

    const body = {
      name: t.name,
      edge: t.edge ? t.edge.server_id : '',
      origin: t.origin ? t.origin.server_id : '',
      service_ports: servicePorts,
      user_ports: userPorts || servicePorts,
      link_port: linkPort,
      pool: !$('et-pool-wrap').hidden ? poolSize : 0,
      mux_links: !$('et-mux-wrap').hidden ? muxLinks : 0,
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
    $('tn-opt-claim').hidden = !['website', 'website-cdn-backup', 'grpc'].includes(link);
    const needDomain = ['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(link);
    $('tn-opt-domain').hidden = !needDomain;
    if (needDomain) ensureTunnelCFHelper();
    $('tn-opt-clean').hidden = !['cdn', 'grpc-cdn'].includes(link);
    $('tn-opt-stealth').hidden = !['website', 'grpc'].includes(link);
    if (link === 'grpc' && $('tn-claim').value === 'www.bing.com') $('tn-claim').value = 'www.google.com';
    if (link !== 'grpc' && $('tn-claim').value === 'www.google.com') $('tn-claim').value = 'www.bing.com';
    const v6ok = !gre && ['plain', 'website', 'grpc', 'kcp'].includes(link) &&
      hasIPv6(serverById($('tn-relay').value)) && hasIPv6(serverById($('tn-foreign').value));
    $('tn-ipv6-row').hidden = !v6ok;
    if (!v6ok) $('tn-ipv6').checked = false;
    if (!sharingTouched) setRadio('tn-shared', ['kcp', 'cdn', 'website-cdn-backup', 'grpc', 'grpc-cdn'].includes(link) ? 'shared' : 'one');
    $('tn-opt-links').hidden = radio('tn-shared') !== 'shared';
    syncChoiceCards($('tunnel-dialog'));
  }

  for (const el of document.querySelectorAll('#tunnel-form input[name="tn-mode"], #tunnel-form input[name="tn-link"], #tn-gre, #tn-webheader, #tn-relay, #tn-foreign')) {
    el.addEventListener('change', showTunnelOptions);
  }
  for (const el of document.querySelectorAll('input[name="tn-shared"]')) {
    el.addEventListener('change', () => { sharingTouched = true; showTunnelOptions(); });
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
    setRadio('tn-link', cand.link || 'website');
    $('tn-stealth').checked = !!cand.stealth;
    $('tn-webheader').checked = !!cand.web_header;
    $('tn-ipv6').checked = !!cand.ipv6;
    if (cand.server_name && ['website', 'website-cdn-backup', 'grpc'].includes(cand.link)) {
      $('tn-claim').value = cand.server_name;
    }
    if (cand.domain) {
      $('tn-domain').value = cand.domain;
    }
    sharingTouched = true;
    setRadio('tn-shared', cand.shared ? 'shared' : 'one');
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
          h('span', { class: 'probe-row-sub' }, 'Running handshake, ping & payload burst...')),
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
    return h('div', { class: 'probe-row' },
      h('div', { class: 'probe-row-label' },
        r.label,
        r.error && r.status !== 'ok' ? h('span', { class: 'probe-row-sub' }, r.error) : null),
      h('span', { class: 'state ' + st[0] }, st[1]),
      h('span', { class: 'probe-metric' }, r.successes > 0 ? `${Math.round(r.rtt_ms)} ms` : '—'),
      h('span', { class: 'probe-metric' }, r.successes > 0 ? `${r.avg_mbps.toFixed(1)} Mbps` : '—'),
      isLive
        ? h('span', { class: 'muted small' }, r.status === 'ok' ? 'Done' : '—')
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
          setProbeProgress(`Testing ${i + 1} of ${cands.length}: ${spec.label}…`, pct);
          renderProbeResults({ results: liveState, notes: sess.notes }, true, i);

          const isTCPDirect = !spec.cdn && spec.transport !== 'kcp' && spec.target_addr;
          if (isTCPDirect && (deadTCP[spec.target_addr] || 0) >= 2) {
            const skipped = Object.assign({}, spec, {
              status: 'blocked',
              attempts: 1,
              successes: 0,
              error: 'connection timed out',
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
          if (isTCPDirect && stepRes.successes === 0 && (stepRes.error === 'connection timed out' || stepRes.error === 'connection refused')) {
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
    const shared = radio('tn-shared') === 'shared';
    return {
      name: $('tn-name').value.trim(),
      relay: $('tn-relay').value,
      foreign: $('tn-foreign').value,
      mode: radio('tn-mode'),
      link: gre ? 'plain' : radio('tn-link'),
      server_name: $('tn-claim').value.trim(),
      domain: $('tn-domain').value.trim(),
      clean_ips: $('tn-cleanips').value.replace(/\s+/g, ''),
      stealth: $('tn-stealth').checked,
      web_header: !gre && $('tn-webheader').checked,
      web_host: $('tn-webhost').value.trim(),
      real_site: $('tn-realsite').checked,
      gre,
      ipv6: $('tn-ipv6').checked,
      shared,
      shared_links: shared ? Number($('tn-links-n').value || 4) : 0,
      service_ports: $('tn-service').value.trim(),
      user_ports: $('tn-users').value.trim(),
      link_port: Number($('tn-linkport').value || 0),
      proxy_protocol: radio('tn-proxy'),
      relay_ip: $('tn-relayip').value.trim(),
    };
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
    if (r.shared && !(r.shared_links >= 1 && r.shared_links <= 16)) return fail('Number of shared Mux connections must be between 1 and 16.', $('tn-links-n'));
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
        ? ` The panel host will update to ${u.latest} first and restart briefly, then automatically update the remaining servers.`
        : '';
      openConfirm('Update all servers?',
        `Each server will be updated one by one, and its tunnels will restart for a few seconds.${self}`,
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
