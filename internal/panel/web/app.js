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

  let serversCache = [];
  let updatesCache = null;

  async function loadServers() {
    const [data] = await Promise.all([api('GET', '/api/servers'), loadUpdates()]);
    serversCache = data.servers || [];
    const text = JSON.stringify(serversCache) + JSON.stringify(updatesCache && updatesCache.servers);
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

    const upd = updatesCache && (updatesCache.servers || []).find((u) => u.id === s.id);
    const sshUpdate = upd && upd.needs_ssh ? h('p', { class: 'problem' },
      `Its PortBridge (${upd.version}) is older than the panel's, and from before one-click updates. `,
      h('button', { type: 'button', class: 'link', 'data-focus': `srv-${s.id}-ssh`, onclick: () => openSSHUpdate(s) },
        'Update it with its SSH login')) : null;

    const card = h('article', { class: 'card server', 'aria-labelledby': headingId },
      h('div', { class: 'head' }, h('h4', { id: headingId }, name), serverState(s)),
      h('p', { class: 'meta' }, meta.join(' · ')),
      badges.length ? h('div', { class: 'badges' }, badges) : null,
      problem,
      sshUpdate,
      mini,
      h('div', { class: 'actions' },
        (s.group === 'relay' || s.group === 'foreign')
          ? h('button', { type: 'button', 'data-focus': `srv-${s.id}-tunnel`, 'aria-label': `New tunnel with ${name}`, onclick: () => openNewTunnel(s.group === 'relay' ? s.id : '', s.group === 'foreign' ? s.id : '') }, 'New tunnel')
          : null,
        h('button', { type: 'button', 'data-focus': `srv-${s.id}-edit`, 'aria-label': `Rename or move ${name}`, onclick: () => openEdit(s) },
          'Rename or move'),
        s.this ? null : h('button', { type: 'button', 'data-focus': `srv-${s.id}-remove`, 'aria-label': `Remove ${name} from the panel`, onclick: () => confirmRemove(s) },
          'Remove')));
    makeDraggable(card, s);
    return card;
  }

  // Dragging a relay server onto a foreign one (or the other way round) starts
  // a new tunnel between them. "New tunnel" on each card does the same from the
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

  // The same form adds a server, or updates one too old to be updated with one
  // click, with its SSH login, once.
  let addMode = { kind: 'add' };

  function setAddMode(mode) {
    addMode = mode;
    const add = mode.kind === 'add';
    $('add-only').hidden = !add;
    $('add-only-name').hidden = !add;
    $('add-update-row').hidden = !add;
    $('add-title').textContent = add ? 'Add a server' : `Update ${mode.server.name} with its SSH login`;
    $('add-intro').textContent = add
      ? 'The panel logs in to it over SSH once, installs PortBridge there if needed, and from then on talks to it without SSH. The password or key is used only for this, and is never saved.'
      : 'Its PortBridge is from before one-click updates, so the panel logs in over SSH once to update it. Its tunnels restart for a few seconds. From then on it updates with one click. The password or key is used only for this, and is never saved.';
    $('add-submit').textContent = add ? 'Add server' : 'Update it';
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
    $('add-error').textContent = 'Enter the password or key again: it is not kept.';
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
    if (!updating && !body.group) { err.textContent = 'Choose whether it is a relay (Iran) or a foreign server.'; return; }
    if (!updating && !address) { err.textContent = "Enter the server's address."; $('add-address').focus(); return; }
    if (!Number.isInteger(port) || port < 1 || port > 65535) { err.textContent = 'The SSH port must be from 1 to 65535.'; return; }
    if (kind === 'password' && !body.password) { err.textContent = "Enter the server's password."; $('add-password').focus(); return; }
    if (kind === 'key' && !body.private_key.trim()) { err.textContent = 'Paste the private key.'; $('add-key').focus(); return; }
    if (kind === 'file' && !body.private_key.trim()) { err.textContent = 'Choose the private key file.'; $('add-file').focus(); return; }

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
      const updating = addMode.kind === 'ssh-update';
      if (job.error) {
        $('add-result').textContent = (updating ? 'It was not updated. ' : 'The server was not added. ') + sentence(job.error);
        $('add-result').className = 'bad';
        $('add-back').hidden = false;
      } else {
        $('add-result').textContent = updating ? 'Done: it is up to date, and updates with one click from now on.'
          : 'Done: the server is in the panel.';
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

  // followJob shows a job's progress in the job dialog until it is done.
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
        // The panel may be restarting on a new version.
        $('job-result').textContent = e.status === 0 || e.status === 404
          ? 'The panel is restarting. This page logs you out; log in again in a minute to see how the update went.'
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

  // waitForPanel waits for a restarting panel to answer again, then asks for a
  // fresh login.
  async function waitForPanel() {
    try {
      await api('GET', '/api/me');
    } catch (e) {
      if (e.status === 0) setTimeout(waitForPanel, 5000);
    }
  }
  $('job-close').addEventListener('click', () => $('job-dialog').close());

  // A list of what happened on each server, with what to do by hand.
  function showResults(title, results) {
    $('msg-title').textContent = title;
    $('msg-list').replaceChildren(...(results || []).map((r) => h('li', { class: r.ok ? 'good' : 'bad' },
      h('strong', null, r.server + ': '), r.ok ? 'done.' : sentence(r.error),
      r.manual ? h('p', { class: 'manual' }, 'To do it by hand: ' + r.manual) : null)));
    openDialog($('msg-dialog'));
    $('msg-close').focus();
  }
  $('msg-close').addEventListener('click', () => $('msg-dialog').close());

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
        'No tunnels yet. Make one with "New tunnel", or drag a relay server onto a foreign server on the Servers page.'));
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
      t.stale ? h('p', { class: 'muted small' }, 'One of its servers cannot be reached right now, so this may be out of date.') : null,
      tunnelActions(t, halves));
  }

  // tunnelActions are the buttons for one tunnel: both of its halves at once.
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
        if (bad.length) showResults(`${t.name}: not everything worked`, res.results);
        lastTunnels = '';
        await refresh();
      } catch (e) {
        setStatus(e.message, true);
      } finally {
        btn.disabled = false;
      }
    };
    return h('div', { class: 'actions left tunnel-actions' },
      h('button', { type: 'button', 'data-focus': key + '-restart', onclick: service('restart', 'Restarting') }, 'Restart'),
      allRunning
        ? h('button', { type: 'button', 'data-focus': key + '-stop', onclick: service('stop', 'Stopping') }, 'Stop')
        : h('button', { type: 'button', 'data-focus': key + '-start', onclick: service('start', 'Starting') }, 'Start'),
      target.edge ? h('button', { type: 'button', 'data-focus': key + '-code', onclick: () => showCode(target) }, 'Show its code') : null,
      h('button', { type: 'button', class: 'danger-text', 'data-focus': key + '-delete', onclick: () => confirmDeleteTunnel(t, target) }, 'Delete'));
  }

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
      $('code-msg').textContent = 'Copied.';
    } catch (e) {
      $('code-text').select();
      $('code-msg').textContent = 'Press Ctrl+C (or Cmd+C) to copy the selected code.';
    }
  });

  function confirmDeleteTunnel(t, target) {
    const where = [t.edge && t.edge.server_name, t.origin && t.origin.server_name].filter(Boolean).join(' and ');
    openConfirm(`Delete ${t.name}?`,
      `It is stopped and removed from ${where}. Users of it lose their connection. This cannot be undone.`,
      'Delete the tunnel',
      async () => {
        const res = await api('POST', '/api/tunnels/delete', target);
        lastTunnels = lastServers = '';
        await refresh();
        const bad = (res.results || []).filter((r) => !r.ok);
        if (bad.length) {
          $('confirm-dialog').close();
          showResults(`${t.name} was not removed everywhere`, res.results);
        } else {
          setStatus(`${t.name} was deleted from ${where}.`);
        }
      });
  }

  // --------------------------------------------------------------- settings

  async function loadSettings() {
    const [info] = await Promise.all([api('GET', '/api/panel'), loadUpdates()]);
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
    return h('option', { value: s.id }, `${s.name || s.address}${s.address ? ' (' + s.address + ')' : ''}${s.online ? '' : ' — cannot be reached'}`);
  }

  function serverById(id) {
    return serversCache.find((s) => s.id === id);
  }

  function hasIPv6(s) {
    const ov = s && s.overview;
    return !!(ov && ov.ipv6 && ov.ipv6.length);
  }

  // showTunnelOptions shows the questions that apply to what is chosen so far,
  // as the menu asks only those.
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
    $('tn-opt-domain').hidden = !['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(link);
    $('tn-opt-clean').hidden = !['cdn', 'grpc-cdn'].includes(link);
    $('tn-opt-stealth').hidden = !['website', 'grpc'].includes(link);
    if (link === 'grpc' && $('tn-claim').value === 'www.bing.com') $('tn-claim').value = 'www.google.com';
    if (link !== 'grpc' && $('tn-claim').value === 'www.google.com') $('tn-claim').value = 'www.bing.com';
    // IPv6 is offered as the menu offers it: both servers need an address, and
    // not with GRE, a CDN or the web-socket link.
    const v6ok = !gre && ['plain', 'website', 'grpc', 'kcp'].includes(link) &&
      hasIPv6(serverById($('tn-relay').value)) && hasIPv6(serverById($('tn-foreign').value));
    $('tn-ipv6-row').hidden = !v6ok;
    if (!v6ok) $('tn-ipv6').checked = false;
    // Shared connections suit the links that carry a lot per connection.
    if (!sharingTouched) setRadio('tn-shared', ['kcp', 'cdn', 'website-cdn-backup', 'grpc', 'grpc-cdn'].includes(link) ? 'shared' : 'one');
    $('tn-opt-links').hidden = radio('tn-shared') !== 'shared';
  }

  for (const el of document.querySelectorAll('#tunnel-form input[name="tn-mode"], #tunnel-form input[name="tn-link"], #tn-gre, #tn-webheader, #tn-relay, #tn-foreign')) {
    el.addEventListener('change', showTunnelOptions);
  }
  for (const el of document.querySelectorAll('input[name="tn-shared"]')) {
    el.addEventListener('change', () => { sharingTouched = true; showTunnelOptions(); });
  }

  async function openNewTunnel(relayID, foreignID) {
    if (!serversCache.length) {
      try { serversCache = (await api('GET', '/api/servers')).servers || []; } catch (e) { setStatus(e.message, true); return; }
    }
    const relays = serversCache.filter((s) => s.group === 'relay');
    const foreigns = serversCache.filter((s) => s.group === 'foreign');
    if (!relays.length || !foreigns.length) {
      setStatus('A tunnel joins a relay (Iran) server and a foreign server. Add one of each first, or move this server into its group.', true);
      return;
    }
    $('tn-relay').replaceChildren(...relays.map(serverOption));
    $('tn-foreign').replaceChildren(...foreigns.map(serverOption));
    if (relayID) $('tn-relay').value = relayID;
    if (foreignID) $('tn-foreign').value = foreignID;
    $('tn-error').textContent = '';
    $('tn-ports-result').replaceChildren();
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

  $('tn-check').addEventListener('click', async () => {
    const r = tunnelRequest();
    const out = $('tn-ports-result');
    const users = r.user_ports || r.service_ports;
    if (!portList.test(r.service_ports) || !portList.test(users) || !r.link_port) {
      out.replaceChildren(h('li', { class: 'bad' }, 'Fill in the ports first.'));
      return;
    }
    out.replaceChildren(h('li', null, 'Asking both servers...'));
    const relayPorts = users + (r.mode === 'reverse' ? ',' + r.link_port : '');
    const foreignPorts = r.service_ports + (r.mode === 'direct' ? ',' + r.link_port : '');
    const describe = async (server, list, role) => {
      const s = serverById(server);
      try {
        const res = await api('POST', '/api/ports', { server, ports: list });
        return res.ports.map((p) => {
          let what = 'users\' port';
          if (p.port === r.link_port && ((role === 'relay' && r.mode === 'reverse') || (role === 'foreign' && r.mode === 'direct'))) what = 'port between the servers';
          else if (role === 'foreign') what = 'service port';
          const by = p.by ? ` (${p.by.replace(/^PortBridge /, '')})` : '';
          let cls = 'good', text;
          if (what === 'service port') {
            text = p.state === 'free' ? 'nothing is listening there yet; is your service running?' : `something is listening${by}, as it should`;
            if (p.state === 'free') cls = 'warn';
            if (/^PortBridge tunnel/.test(p.by || '')) { cls = 'bad'; text = `used by ${p.by.replace(/^PortBridge /, '')}`; }
          } else {
            text = p.state === 'free' ? 'free' : `${p.state}${by}`;
            if (p.state !== 'free') cls = 'bad';
          }
          return h('li', { class: cls }, `${s ? s.name : server}, ${what} ${p.port}: ${text}`);
        });
      } catch (e) {
        return [h('li', { class: 'warn' }, `${s ? s.name : server}: could not be asked (${e.message})`)];
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
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(r.name)) return fail('Give it a short name: letters, digits, dash and underscore, up to 40 characters.', $('tn-name'));
    if (!r.relay || !r.foreign) return fail('Choose both servers.', $('tn-relay'));
    if (!portList.test(r.service_ports)) return fail('Give the service port or ports, separated by commas.', $('tn-service'));
    if (r.user_ports && !portList.test(r.user_ports)) return fail("Give your users' port or ports, separated by commas, or leave it empty.", $('tn-users'));
    if (r.user_ports && r.user_ports.split(',').length !== r.service_ports.split(',').length) {
      return fail("Each users' port leads to one service port, in order, so give the same number of each.", $('tn-users'));
    }
    if (!(r.link_port >= 1 && r.link_port <= 65535)) return fail('The port between the servers must be from 1 to 65535.', $('tn-linkport'));
    if (['cdn', 'website-cdn-backup', 'grpc-cdn'].includes(r.link) && !r.domain) return fail('Give your domain for the CDN.', $('tn-domain'));
    if (r.shared && !(r.shared_links >= 1 && r.shared_links <= 16)) return fail('The number of shared connections must be from 1 to 16.', $('tn-links-n'));
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
    $('tn-result').textContent = 'Working...';
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
        $('tn-result').textContent = 'The tunnel was not made. ' + sentence(job.error);
        $('tn-result').className = 'bad';
        $('tn-back').hidden = false;
      } else {
        $('tn-result').textContent = `Done: ${name} is running on both servers.`;
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
      text = `PortBridge ${u.latest} is available. This panel has ${u.panel}`;
      text += u.older ? `, and ${plural(u.older, 'server has', 'servers have')} older versions than that.` : '.';
    } else if (u.older) {
      text = `${plural(u.older, 'server has', 'servers have')} an older PortBridge than the panel's ${u.panel}.`;
    }
    if (u.note) text = sentence(u.note) + (text ? ' ' + text : '');
    $('update-banner').hidden = !text && !u.running;
    $('update-text').textContent = u.running ? 'An update is running.' : text;
    for (const b of document.querySelectorAll('.update-all')) b.hidden = u.running || (!u.panel_older && !u.older);
    for (const b of document.querySelectorAll('.update-progress')) b.hidden = !u.job;

    const rows = [];
    const row = (k, v) => rows.push(h('dt', null, k), h('dd', null, v));
    row('This panel', u.panel);
    row('Newest release', u.latest ? u.latest + (u.checked ? ` (checked ${ago(u.checked)})` : '') : (u.check_error ? sentence(u.check_error) : 'not checked yet'));
    for (const s of u.servers || []) {
      const words = { current: 'up to date', older: 'older', newer: 'newer than the panel', unknown: 'not known' }[s.state] || s.state;
      row(s.name, `${s.version || '—'}, ${words}${s.needs_ssh ? '; needs its SSH login once to update' : ''}`);
    }
    $('update-info').replaceChildren(...rows);
  }

  for (const b of document.querySelectorAll('.update-all')) {
    b.addEventListener('click', () => {
      const u = updatesCache || {};
      const self = u.panel_older
        ? ` This panel's own server is updated first, to ${u.latest}: the panel restarts and you log in again, and it then updates the other servers by itself.`
        : '';
      openConfirm('Update everything?',
        `Each server is updated in turn, and its tunnels restart for a few seconds while it does.${self}`,
        'Update everything',
        async () => {
          const res = await api('POST', '/api/updates');
          $('confirm-dialog').close();
          followJob(res.job, 'Updating', 'Done: everything is up to date.', 'Not everything was updated.');
        });
    });
  }
  for (const b of document.querySelectorAll('.update-progress')) {
    b.addEventListener('click', () => {
      if (updatesCache && updatesCache.job) followJob(updatesCache.job, 'Updating', 'Done: everything is up to date.', 'Not everything was updated.');
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
    try {
      enter(await api('GET', '/api/me'));
    } catch (e) {
      if (e.status !== 401) showLogin(e.message);
    }
  })();
})();
