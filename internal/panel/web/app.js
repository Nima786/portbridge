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
      showLogin(csrf ? 'You were logged out. Please log in again.' : '');
      throw new ApiError(401, (data && data.error) || 'Please log in.');
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
    return (list.length === 1 ? 'port ' : 'ports ') + list.join(', ');
  }

  function setStatus(msg, bad) {
    const el = $('status-line');
    el.textContent = msg || '';
    el.classList.toggle('bad', !!bad);
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

  // ------------------------------------------------------------------- tabs

  const TABS = ['servers', 'tunnels', 'settings'];

  function selectTab(name, focus) {
    currentTab = name;
    for (const t of TABS) {
      const on = t === name;
      const tab = $('tab-' + t);
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      $('view-' + t).hidden = !on;
    }
    if (focus) $('tab-' + name).focus();
    refresh();
  }

  for (const t of TABS) {
    const tab = $('tab-' + t);
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

  async function refresh() {
    if ($('shell').hidden) return;
    try {
      if (currentTab === 'servers') await loadServers();
      else if (currentTab === 'tunnels') await loadTunnels();
      else await loadSettings();
      setStatus('');
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
    const data = await api('GET', '/api/servers');
    const text = JSON.stringify(data.servers || []);
    if (text === lastServers) return;
    lastServers = text;
    keepFocus(() => renderServers(data.servers || []));
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
      : [h('p', { class: 'empty' }, 'No relay servers yet. Add one with "Add server".')]));
    $('col-foreign').replaceChildren(...(foreign.length ? foreign
      : [h('p', { class: 'empty' }, 'No foreign servers yet. Add one with "Add server".')]));
  }

  function serverState(s) {
    if (s.online) return h('span', { class: 'state ok' }, 'Online');
    if (s.problem === 'not checked yet') return h('span', { class: 'state unknown' }, 'Checking');
    return h('span', { class: 'state bad' }, 'Cannot be reached');
  }

  function serverCard(s) {
    const ov = s.overview;
    const tunnels = (ov && ov.tunnels) || [];
    const running = tunnels.filter((t) => t.running).length;
    const name = s.name || s.address || 'Server';
    const headingId = 'srv-' + s.id;

    const meta = [];
    if (s.address) meta.push(s.address);
    if (ov && ov.version) meta.push('PortBridge ' + ov.version);
    meta.push(tunnels.length ? `${plural(tunnels.length, 'tunnel')}, ${running} running` : 'no tunnels');

    const badges = [];
    if (s.this) badges.push(h('span', { class: 'badge' }, 'This server: runs the panel'));
    if (s.calls_panel) {
      badges.push(h('span', { class: 'badge', title: 'The panel cannot reach this server, so the server calls the panel instead.' },
        'Calls the panel'));
    }

    let problem = null;
    if (!s.online && s.problem && s.problem !== 'not checked yet') {
      let text = sentence(s.problem);
      if (s.last_seen) text += ` Last heard from ${ago(s.last_seen)}.`;
      problem = h('p', { class: 'problem' }, text);
    }

    const mini = tunnels.length ? h('ul', { class: 'mini', 'aria-label': `Tunnels on ${name}` },
      tunnels.map((t) => h('li', null,
        h('span', { class: 'state ' + (t.running ? 'ok' : 'bad') }, t.running ? 'Running' : 'Stopped'),
        ' ', t.name))) : null;

    return h('article', { class: 'card server', 'aria-labelledby': headingId },
      h('div', { class: 'head' }, h('h4', { id: headingId }, name), serverState(s)),
      h('p', { class: 'meta' }, meta.join(' · ')),
      badges.length ? h('div', { class: 'badges' }, badges) : null,
      problem,
      mini,
      h('div', { class: 'actions' },
        h('button', { type: 'button', 'data-focus': `srv-${s.id}-edit`, 'aria-label': `Rename or move ${name}`, onclick: () => openEdit(s) },
          'Rename or move'),
        s.this ? null : h('button', { type: 'button', 'data-focus': `srv-${s.id}-remove`, 'aria-label': `Remove ${name} from the panel`, onclick: () => confirmRemove(s) },
          'Remove')));
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

  // Renaming and moving

  let editing = null;

  function openEdit(s) {
    editing = s;
    $('edit-title').textContent = s.this ? 'This server' : (s.name || s.address);
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
      $('edit-error').textContent = 'Choose a group.';
      return;
    }
    if (!name && !editing.this) {
      $('edit-error').textContent = 'Give it a name.';
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
      'PortBridge and its tunnels stay on that server and keep working. Only the panel forgets it, and you can add it again later.',
      'Remove from the panel',
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
      $('add-error').textContent = 'That file is too big to be a private key.';
      $('add-file').value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => { keyFromFile = String(reader.result || ''); };
    reader.onerror = () => { $('add-error').textContent = 'That file could not be read.'; };
    reader.readAsText(f);
  });

  $('add-server').addEventListener('click', () => {
    $('add-form').hidden = false;
    $('add-progress').hidden = true;
    $('add-error').textContent = '';
    showAuth();
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
    $('add-error').textContent = 'Enter the password or key again: it is not kept.';
    $('add-address').focus();
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

    if (!body.group) { err.textContent = 'Choose whether it is a relay (Iran) or a foreign server.'; return; }
    if (!address) { err.textContent = "Enter the server's address."; $('add-address').focus(); return; }
    if (!Number.isInteger(port) || port < 1 || port > 65535) { err.textContent = 'The SSH port must be from 1 to 65535.'; return; }
    if (kind === 'password' && !body.password) { err.textContent = "Enter the server's password."; $('add-password').focus(); return; }
    if (kind === 'key' && !body.private_key.trim()) { err.textContent = 'Paste the private key.'; $('add-key').focus(); return; }
    if (kind === 'file' && !body.private_key.trim()) { err.textContent = 'Choose the private key file.'; $('add-file').focus(); return; }

    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const res = await api('POST', '/api/servers', body);
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
    $('add-result').textContent = 'Working...';
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
      if (job.error) {
        $('add-result').textContent = 'The server was not added. ' + sentence(job.error);
        $('add-result').className = 'bad';
        $('add-back').hidden = false;
      } else {
        $('add-result').textContent = 'Done: the server is in the panel.';
        $('add-result').className = 'good';
        $('add-address').value = '';
        $('add-name').value = '';
      }
      lastServers = '';
      refresh();
    };
    poll();
  }

  // ---------------------------------------------------------------- tunnels

  async function loadTunnels() {
    const data = await api('GET', '/api/tunnels');
    const text = JSON.stringify(data.tunnels || []);
    if (text === lastTunnels) return;
    lastTunnels = text;
    keepFocus(() => renderTunnels(data.tunnels || []));
  }

  function renderTunnels(list) {
    const box = $('tunnel-list');
    if (!list.length) {
      box.replaceChildren(h('p', { class: 'empty' },
        'No tunnels yet. Create one with the menu on your relay (Iran) server: portbridge-menu, then "Create a tunnel".'));
      return;
    }
    box.replaceChildren(...list.map(tunnelCard));
  }

  const PATH_WORDS = {
    ok: ['ok', 'Data gets through'],
    degraded: ['warn', 'Data gets through, but poorly'],
    blocked: ['bad', 'Data is not getting through'],
    unknown: ['unknown', 'Not measured yet'],
  };

  function halfState(half) {
    if (!half) return null;
    const i = half.info;
    if (i.problem) return h('span', { class: 'state warn' }, 'Has a problem');
    if (!i.running) return h('span', { class: 'state bad' }, 'Stopped');
    return h('span', { class: 'state ok' }, 'Running');
  }

  function node(role, half, missingText) {
    if (!half) {
      return h('div', { class: 'node missing' },
        h('div', { class: 'role' }, role),
        h('div', { class: 'name' }, 'Not in the panel'),
        missingText ? h('div', { class: 'addr' }, missingText) : null);
    }
    return h('div', { class: 'node' },
      h('div', { class: 'role' }, role),
      h('div', { class: 'name' }, half.server_name || half.address),
      half.address ? h('div', { class: 'addr' }, half.address) : null,
      halfState(half));
  }

  function wire(text, label) {
    return h('div', { class: 'wire' }, h('span', { class: 'arrow', 'aria-hidden': 'true' }, text),
      label ? h('span', { class: 'visually-hidden' }, label) : null);
  }

  function tunnelCard(t) {
    const e = t.edge, o = t.origin;
    const ei = e ? e.info : null, oi = o ? o.info : null;
    const any = ei || oi;
    const reverse = any.mode === 'reverse';
    const link = any.link || any.transport || '';
    const linkPort = (ei && ei.link_port) || (oi && oi.link_port) || 0;
    const userPorts = ei ? ei.user_ports : null;
    const servicePorts = (oi && oi.service_ports && oi.service_ports.length) ? oi.service_ports : (ei ? ei.service_ports : null);
    const live = (ei && ei.live) || (oi && oi.live) || null;

    // One word for the whole tunnel, from the worst of its parts.
    let overall = ['ok', 'Running'];
    const halves = [e, o].filter(Boolean);
    if (halves.some((x) => !x.info.running)) overall = ['bad', 'Stopped'];
    else if (live && live.path_state === 'blocked') overall = ['bad', 'Not getting through'];
    else if (halves.some((x) => x.info.problem)) overall = ['warn', 'Has a problem'];
    else if (live && live.path_state === 'degraded') overall = ['warn', 'Poor connection'];
    else if (!e || !o) overall = ['unknown', 'One end not in the panel'];

    const kind = [reverse ? 'Reverse' : 'Direct', link].filter(Boolean).join(' · ');
    const dir = reverse ? 'The foreign server connects to the relay' : 'The relay connects to the foreign server';

    const diagram = h('div', { class: 'diagram' },
      h('div', { class: 'node end' }, h('div', { class: 'role' }, 'Users'), h('div', { class: 'addr' }, ports(userPorts) || '—')),
      wire('→', 'connect to'),
      node('Relay (Iran)', e, oi && oi.peer_ip ? `at ${oi.peer_ip}` : ''),
      h('div', { class: 'wire link' },
        h('span', { class: 'arrow', 'aria-hidden': 'true' }, reverse ? '←' : '→'),
        h('span', null, link + (linkPort ? `, port ${linkPort}` : '')),
        h('span', null, reverse ? 'foreign connects' : 'relay connects'),
        h('span', { class: 'visually-hidden' }, dir + '.')),
      node('Foreign', o, ei && ei.peer_ip ? `at ${ei.peer_ip}` : ''),
      wire('→', 'which passes them to'),
      h('div', { class: 'node end' }, h('div', { class: 'role' }, 'Service'), h('div', { class: 'addr' }, ports(servicePorts) || '—')));

    const facts = [];
    const fact = (k, v) => facts.push(h('div', null, h('dt', null, k + ':'), h('dd', null, v)));
    if (live) {
      fact('Users now', String(live.active_sessions || 0));
      if (any.mux) fact('Links', `${live.links || 0} of ${live.link_target || any.mux_links || 0} up`);
      else fact('Spare connections', `${live.parked_spares || 0} of ${live.pool_target || any.pool_size || 0} ready`);
      const pw = PATH_WORDS[live.path_state] || PATH_WORDS.unknown;
      fact('Data', h('span', { class: 'state ' + pw[0] }, pw[1]));
      if (live.on_backup_route) fact('Route', 'on its backup route' + (live.route_in_use ? ` (${live.route_in_use})` : ''));
      fact('Up for', duration(live.uptime_seconds));
    } else if (halves.some((x) => x.info.running)) {
      fact('Live status', 'not reported yet');
    }
    fact('Real visitor address', any.proxy_protocol && any.proxy_protocol !== 'off' ? `passed on (PROXY ${any.proxy_protocol})` : 'not passed on');
    const extras = [];
    if (any.cdn) extras.push('can go through a CDN');
    if (any.gre) extras.push('GRE');
    if (any.real_site && !/real (web)?site/i.test(link)) extras.push('looks like a real website');
    if (extras.length) fact('Also', extras.join(', '));

    const problems = halves.filter((x) => x.info.problem).map((x) => `${x.server_name}: ${sentence(x.info.problem)}`);
    if (live && live.path_note && live.path_state !== 'ok') problems.push(sentence(live.path_note));

    return h('article', { class: 'card tunnel', 'aria-labelledby': 'tun-' + t.name + (e ? e.server_id : '') + (o ? o.server_id : '') },
      h('header', null,
        h('h3', { id: 'tun-' + t.name + (e ? e.server_id : '') + (o ? o.server_id : '') }, t.name),
        h('span', { class: 'state ' + overall[0] }, overall[1]),
        h('span', { class: 'kind' }, kind)),
      diagram,
      h('dl', { class: 'facts' }, facts),
      problems.map((p) => h('p', { class: 'problem' }, p)),
      t.stale ? h('p', { class: 'muted small' }, 'One of its servers cannot be reached right now, so this may be out of date.') : null);
  }

  // --------------------------------------------------------------- settings

  async function loadSettings() {
    const info = await api('GET', '/api/panel');
    const rows = [];
    const row = (k, v) => rows.push(h('dt', null, k), h('dd', null, v));
    row('Version', info.version || '');
    row('Open it at', (info.addresses || []).length
      ? h('span', null, ...info.addresses.map((a, i) => [i ? h('br') : null, a])) : '—');
    const c = info.certificate || {};
    if (c.real) {
      const until = c.until ? new Date(c.until).toLocaleDateString() : '';
      row('Certificate', `A real one for ${c.domain}, from ${c.issuer || 'Let\'s Encrypt'}, valid until ${until}. It renews itself.`);
    } else {
      row('Certificate', c.domain
        ? `The panel's own for now. A real one for ${c.domain}: ${sentence(c.note)}`
        : 'The panel\'s own, so the browser warns about it. Set a domain name in the menu on this server to get a real one.');
    }
    row('Its own certificate', h('span', { class: 'mono' }, info.fingerprint || ''));
    row('Servers call it at', info.public_url || 'not known: set it in the menu on this server');
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
    if (!user) return fail('The username cannot be empty.', $('acc-user'));
    if (pw && pw.length < 10) return fail('The new password must be at least 10 characters.', $('acc-new'));
    if (pw !== again) return fail('The two new passwords are not the same.', $('acc-again'));
    const btn = ev.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const res = await api('POST', '/api/account', { current_password: current, new_user: user, new_password: pw });
      csrf = res.csrf;
      currentUser = res.user;
      $('acc-current').value = $('acc-new').value = $('acc-again').value = '';
      msg.className = 'okay';
      msg.textContent = 'Saved. Use the new login from now on.';
    } catch (e) {
      fail(e.message);
    } finally {
      btn.disabled = false;
    }
  });

  // ------------------------------------------------------------------- start

  (async () => {
    try {
      enter(await api('GET', '/api/me'));
    } catch (e) {
      if (e.status !== 401) showLogin(e.message);
    }
  })();
})();
