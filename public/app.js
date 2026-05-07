const State = {
  token: null,
  me: null,
  privateKey: null,       
  publicKeyObj: null,     
  contacts: new Map(),    
  groups: new Map(),      
  current: null,          
  messagesByConv: new Map(), 
  socket: null,
  online: new Set(),
  composerTtl: 0,
  ttlTimers: new Map(),
  contactRequests: { incoming: [], outgoing: [] },
  pendingAttachment: null
};
const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];
function toast(msg, type = 'ok', ms = 2500) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (type === 'error' ? ' error' : '');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.className = 'toast'; }, ms);
}
function confirmDialog(opts = {}) {
  return new Promise((resolve) => {
    const modal = $('#confirm-modal');
    const titleEl = $('#confirm-title');
    const msgEl = $('#confirm-message');
    const inputWrap = $('#confirm-input-wrap');
    const inputEl = $('#confirm-input');
    const inputLabel = $('#confirm-input-label');
    const okBtn = $('#confirm-ok');
    const cancelBtn = $('#confirm-cancel');
    const xBtn = $('#confirm-x');
    const modalInner = modal.querySelector('.modal');
    titleEl.textContent = opts.title || 'confirm';
    msgEl.textContent = opts.message || '';
    okBtn.textContent = `[ ${opts.okLabel || 'confirm'} ]`;
    cancelBtn.textContent = `[ ${opts.cancelLabel || 'cancel'} ]`;
    if (opts.danger) modalInner.classList.add('danger');
    else modalInner.classList.remove('danger');
    const isPasswordPrompt = !!opts.password;
    const usesTypeMatchInput = typeof opts.input === 'string';
    const usesAnyInput = isPasswordPrompt || usesTypeMatchInput;
    if (usesAnyInput) {
      inputWrap.classList.remove('hidden');
      inputEl.value = '';
      inputEl.type = isPasswordPrompt ? 'password' : 'text';
      inputEl.placeholder = isPasswordPrompt ? '' : (opts.input || '');
      inputLabel.textContent = opts.inputLabel ||
        (isPasswordPrompt ? 'password' : `type "${opts.input}" to confirm`);
      okBtn.disabled = isPasswordPrompt ? false : true;
    } else {
      inputWrap.classList.add('hidden');
      okBtn.disabled = false;
    }
    function cleanup() {
      modal.classList.remove('open');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      xBtn.removeEventListener('click', onCancel);
      modal.removeEventListener('click', onBackdrop);
      document.removeEventListener('keydown', onKey);
      inputEl.removeEventListener('input', onTyping);
      inputEl.removeEventListener('keydown', onInputKey);
    }
    function onOk() {
      if (usesTypeMatchInput && inputEl.value !== opts.input) return;
      cleanup();
      if (isPasswordPrompt) resolve(inputEl.value);
      else resolve(true);
    }
    function onCancel() {
      cleanup();
      if (isPasswordPrompt) resolve(null);
      else resolve(false);
    }
    function onBackdrop(e) {
      if (e.target === modal) onCancel();
    }
    function onKey(e) {
      if (e.key === 'Escape') onCancel();
      else if (e.key === 'Enter' && !usesAnyInput && document.activeElement !== inputEl) onOk();
    }
    function onInputKey(e) {
      if (e.key === 'Enter' && !okBtn.disabled) { e.preventDefault(); onOk(); }
    }
    function onTyping() {
      if (usesTypeMatchInput) okBtn.disabled = inputEl.value !== opts.input;
    }
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    xBtn.addEventListener('click', onCancel);
    modal.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKey);
    if (usesAnyInput) {
      inputEl.addEventListener('input', onTyping);
      inputEl.addEventListener('keydown', onInputKey);
    }
    modal.classList.add('open');
    setTimeout(() => {
      if (usesAnyInput) inputEl.focus();
      else okBtn.focus();
    }, 100);
  });
}
$$('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    $$('.tab').forEach(t => t.classList.toggle('active', t === tab));
    const target = tab.dataset.tab;
    $$('.auth-form').forEach(f => f.classList.toggle('active', f.id === `${target}-form`));
    $('#login-error').textContent = '';
    $('#register-error').textContent = '';
  });
});
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (State.token) headers.Authorization = `Bearer ${State.token}`;
  const res = await fetch(path, { ...opts, headers });
  let body = null;
  try { body = await res.json(); } catch {}
  if (!res.ok) throw new Error(body?.error || `HTTP ${res.status}`);
  return body;
}
$('#register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  const err = $('#register-error');
  const prog = $('#register-progress');
  err.textContent = '';
  const fd = new FormData(e.target);
  const username = fd.get('username').trim();
  const password = fd.get('password');
  const confirm = fd.get('confirm');
  if (password !== confirm) { err.textContent = 'passwords do not match.'; return; }
  if (password.length < 8)  { err.textContent = 'password must be 8+ chars.'; return; }
  btn.classList.add('loading');
  btn.disabled = true;
  prog.textContent = '> generating curve25519 keypair...';
  try {
    await window.sodiumReady;  
    await new Promise(r => setTimeout(r, 50));
    const { privateKey, publicKey } = await PGP.generateKeypair(username, password);
    prog.textContent = '> registering...';
    const data = await api('/api/register', {
      method: 'POST',
      body: JSON.stringify({ username, password, publicKey })
    });
    prog.textContent = '> unlocking key...';
    await completeLogin(data, password, privateKey);
  } catch (e) {
    console.error('[register] error:', e);
    err.textContent = e.message.toLowerCase();
    prog.textContent = '';
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
});
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  const err = $('#login-error');
  err.textContent = '';
  const fd = new FormData(e.target);
  const username = fd.get('username').trim();
  const password = fd.get('password');
  btn.classList.add('loading');
  btn.disabled = true;
  try {
    await window.sodiumReady;
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    await completeLogin(data, password, null);
  } catch (e) {
    err.textContent = e.message.toLowerCase();
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
});
async function completeLogin(data, password, encryptedSeedBlob) {
  await window.sodiumReady;
  let storedBlob = encryptedSeedBlob;
  if (!storedBlob) {
    const stored = (() => { try { return JSON.parse(localStorage.getItem('niix.user')); } catch { return null; } })();
    storedBlob = stored?.privateKeyEncrypted;
  }
  let keypair;
  if (storedBlob) {
    // Fast path: unlock from locally cached encrypted seed blob
    try {
      keypair = await PGP.unlockPrivateKey(storedBlob, password);
    } catch {
      throw new Error('failed to unlock private key (wrong password?)');
    }
  } else {
    // New device: deterministically re-derive the keypair from credentials.
    // Produces the same keypair as registration so the public key matches the server record.
    try {
      keypair = await PGP.deriveKeypairFromCredentials(data.username, password);
      // Verify derived public key matches what the server has — catches wrong password
      // and accounts created before this feature (random seed, can't be re-derived)
      const derivedPub = PGP.packPublicKey(keypair.signPublicKey, keypair.kxPublicKey);
      if (derivedPub !== data.publicKey) {
        throw new Error('key mismatch — wrong password, or this account was created before cross-device login was supported and must be re-registered');
      }
      // Cache encrypted seed locally so future logins on this device are fast
      const { privateKey: freshBlob } = await PGP.generateKeypair(data.username, password);
      storedBlob = freshBlob;
    } catch (e) {
      throw new Error(e.message || 'failed to derive keypair from credentials');
    }
  }
  const pubObj = await PGP.readPublicKey(data.publicKey);
  State.token      = data.token;
  State.me         = { id: data.id, username: data.username, publicKey: data.publicKey };
  State.privateKey = keypair;
  State.publicKeyObj = pubObj;
  window._myKeypair = keypair;
  localStorage.setItem('niix.token', data.token);
  localStorage.setItem('niix.user', JSON.stringify({
    id: data.id, username: data.username,
    publicKey: data.publicKey,
    privateKeyEncrypted: storedBlob   
  }));
  enterChat();
}
async function tryResumeSession() {
  const userJSON = localStorage.getItem('niix.user');
  if (userJSON) {
    try {
      const stored = JSON.parse(userJSON);
      const usernameInput = $('#login-form input[name="username"]');
      if (usernameInput && stored.username) usernameInput.value = stored.username;
    } catch {}
  }
  return false;
}
$('#logout-btn').addEventListener('click', async () => {
  const ok = await confirmDialog({
    title: 'logout',
    message: 'logout? your decrypted key will be wiped from memory.\n\nyou can log back in with your password.',
    okLabel: 'logout'
  });
  if (!ok) return;
  hardLogout();
});
function hardLogout() {
  if (State.token) {
    fetch('/api/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${State.token}` }
    }).catch(() => {}); 
  }
  if (State.socket) State.socket.disconnect();
  localStorage.removeItem('niix.token');
  for (const t of State.ttlTimers.values()) clearTimeout(t);
  State.ttlTimers.clear();
  State.token = null;
  State.me = null;
  State.privateKey = null;
  State.publicKeyObj = null;
  State.contacts.clear();
  State.groups.clear();
  State.messagesByConv.clear();
  State.current = null;
  State.online.clear();
  for (const url of attachmentCache.values()) URL.revokeObjectURL(url);
  attachmentCache.clear();
  location.reload();
}
async function enterChat() {
  $('#auth-view').classList.add('hidden');
  $('#chat-view').classList.remove('hidden');
  $('#me-name').textContent = State.me.username;
  $('#me-fingerprint').textContent = await PGP.shortId(State.publicKeyObj);
  $('#me-fingerprint').addEventListener('click', async () => {
    const fp = await PGP.fingerprint(State.publicKeyObj);
    navigator.clipboard?.writeText(fp);
    toast('fingerprint copied');
  }, { once: true });
  document.addEventListener('click', (e) => {
    const t = e.target;
    if (!t) return;
    if (t.id === 'header-menu-btn' ||
        t.dataset?.role === 'menu' ||
        t.closest?.('[data-role="menu"]')) {
      toggleSidebar(true);
    }
  });
  $('#sidebar-overlay')?.addEventListener('click', () => toggleSidebar(false));
  await Promise.all([loadContacts(), loadGroups(), loadContactRequests()]);
  connectSocket();
}
function toggleSidebar(open) {
  const sb = $('#sidebar');
  const ov = $('#sidebar-overlay');
  if (!sb || !ov) return;
  if (open) {
    sb.classList.add('open');
    ov.classList.add('open');
  } else {
    sb.classList.remove('open');
    ov.classList.remove('open');
  }
}
async function loadContacts(query = '') {
  const list = await api('/api/users' + (query ? `?q=${encodeURIComponent(query)}` : ''));
  const fresh = new Map();
  for (const u of list) {
    const existing = State.contacts.get(u.id);
    fresh.set(u.id, {
      id: u.id,
      username: u.username,
      publicKey: u.publicKey,
      publicKeyObj: existing?.publicKeyObj || await PGP.readPublicKey(u.publicKey),
      online: State.online.has(u.id)
    });
  }
  State.contacts = fresh;
  renderContacts();
}
function renderContacts() {
  const c = $('#contacts');
  c.innerHTML = '';
  if (State.contacts.size === 0) {
    c.innerHTML = '<div class="no-contacts">// no other users yet</div>';
    return;
  }
  for (const u of State.contacts.values()) {
    const conv = `u:${u.id}`;
    const div = document.createElement('div');
    div.className = 'contact' + (State.current === conv ? ' active' : '');
    div.innerHTML = `
      <div class="contact-avatar">${u.username.slice(0, 2).toUpperCase()}</div>
      <div class="contact-name">${escapeHtml(u.username)}</div>
      <div class="contact-status${u.online ? ' online' : ''}" title="${u.online ? 'online' : 'offline'}"></div>
    `;
    div.addEventListener('click', () => openConversation(conv));
    div.addEventListener('contextmenu', (e) => { e.preventDefault(); showContactMenu(e, u.id); });
    let pressTimer;
    div.addEventListener('touchstart', (e) => {
      pressTimer = setTimeout(() => showContactMenu(e.touches[0], u.id), 500);
    });
    div.addEventListener('touchend', () => clearTimeout(pressTimer));
    div.addEventListener('touchmove', () => clearTimeout(pressTimer));
    c.appendChild(div);
  }
}
$('#user-search').addEventListener('input', debounce(async (e) => {
  await loadContacts(e.target.value.trim());
}, 250));
let pendingContactId = null;
function showContactMenu(evt, contactId) {
  pendingContactId = contactId;
  const menu = $('#contact-menu');
  const x = (evt.clientX != null ? evt.clientX : evt.pageX) || 100;
  const y = (evt.clientY != null ? evt.clientY : evt.pageY) || 100;
  menu.style.left = Math.min(x, window.innerWidth - 220) + 'px';
  menu.style.top = Math.min(y, window.innerHeight - 200) + 'px';
  menu.classList.remove('hidden');
}
$('#contact-menu')?.addEventListener('click', async (e) => {
  const item = e.target.closest('.popup-item');
  if (!item || pendingContactId == null) return;
  const action = item.dataset.action;
  const cid = pendingContactId;
  $('#contact-menu').classList.add('hidden');
  const peer = State.contacts.get(cid);
  const peerName = peer?.username || 'this user';
  try {
    if (action === 'clear') {
      const ok = await confirmDialog({
        title: 'clear chat',
        message: `clear chat history with ${peerName} just for you?\n\nthe other party still has their copy.`,
        okLabel: 'clear'
      });
      if (!ok) return;
      const r = await api(`/api/messages/dm/${cid}?mode=for-me`, { method: 'DELETE' });
      State.messagesByConv.delete(`u:${cid}`);
      if (State.current === `u:${cid}`) renderMessages();
      toast(`hidden ${r.hidden} message(s) from your view`);
    } else if (action === 'delete-everywhere') {
      const ok = await confirmDialog({
        title: 'delete for everyone',
        message: `delete YOUR messages to ${peerName} for everyone?\n\nthis only deletes messages YOU sent — they keep their own messages.\nthis cannot be undone.`,
        okLabel: 'delete',
        danger: true
      });
      if (!ok) return;
      const r = await api(`/api/messages/dm/${cid}?mode=for-everyone`, { method: 'DELETE' });
      State.messagesByConv.delete(`u:${cid}`);
      if (State.current === `u:${cid}`) renderMessages();
      toast(`deleted ${r.deleted} message(s)`);
    } else if (action === 'remove') {
      const ok = await confirmDialog({
        title: 'remove contact',
        message: `remove ${peerName} from your contacts?\n\nyou will no longer see them unless you share a group.`,
        okLabel: 'remove',
        danger: true
      });
      if (!ok) return;
      await api(`/api/contacts/${cid}`, { method: 'DELETE' });
      State.contacts.delete(cid);
      State.messagesByConv.delete(`u:${cid}`);
      if (State.current === `u:${cid}`) {
        State.current = null;
        renderChatHeader();
        renderMessages();
        $('#send-form').classList.add('hidden');
      }
      renderContacts();
      toast(`removed ${peerName}`);
    } else if (action === 'fingerprint') {
      navigator.clipboard?.writeText(await PGP.fingerprint(peer.publicKeyObj));
      toast('fingerprint copied');
    }
  } catch (e) {
    toast(e.message, 'error');
  }
});
document.addEventListener('click', (e) => {
  if (!e.target.closest('#contact-menu')) $('#contact-menu')?.classList.add('hidden');
  if (!e.target.closest('#group-menu')) $('#group-menu')?.classList.add('hidden');
}, true);
let pendingGroupId = null;
function showGroupMenu(evt, groupId) {
  pendingGroupId = groupId;
  const g = State.groups.get(groupId);
  if (!g) return;
  const isCreator = g.creatorId === State.me.id;
  const menu = $('#group-menu');
  menu.querySelector('[data-action="delete"]').style.display = isCreator ? '' : 'none';
  menu.querySelector('.popup-title').textContent = g.name;
  const x = (evt.clientX != null ? evt.clientX : evt.pageX) || 100;
  const y = (evt.clientY != null ? evt.clientY : evt.pageY) || 100;
  menu.style.left = Math.min(x, window.innerWidth - 220) + 'px';
  menu.style.top = Math.min(y, window.innerHeight - 200) + 'px';
  menu.classList.remove('hidden');
}
$('#group-menu')?.addEventListener('click', async (e) => {
  const item = e.target.closest('.popup-item');
  if (!item || pendingGroupId == null) return;
  const action = item.dataset.action;
  const gid = pendingGroupId;
  $('#group-menu').classList.add('hidden');
  const g = State.groups.get(gid);
  if (!g) return;
  try {
    if (action === 'manage') {
      openManageGroup(gid);
    } else if (action === 'leave') {
      const ok = await confirmDialog({
        title: 'leave group',
        message: `leave group "${g.name}"?\n\nyou will lose access to past messages.`,
        okLabel: 'leave',
        cancelLabel: 'cancel',
        danger: true
      });
      if (!ok) return;
      await api(`/api/groups/${gid}/members/${State.me.id}`, { method: 'DELETE' });
      toast(`left ${g.name}`);
    } else if (action === 'delete') {
      const ok = await confirmDialog({
        title: 'delete group',
        message: `delete group "${g.name}"?\n\nthis wipes the group and all its messages for everyone.\nthis cannot be undone.`,
        okLabel: 'delete group',
        cancelLabel: 'cancel',
        danger: true
      });
      if (!ok) return;
      await api(`/api/groups/${gid}`, { method: 'DELETE' });
    }
  } catch (e) {
    toast(e.message, 'error');
  }
});
const addContactModal = $('#addcontact-modal');
$('#add-contact-btn')?.addEventListener('click', () => {
  $('#fp-input').value = '';
  $('#fp-result').innerHTML = '';
  addContactModal.classList.add('open');
});
$('#addcontact-close')?.addEventListener('click', () => addContactModal.classList.remove('open'));
addContactModal?.addEventListener('click', (e) => {
  if (e.target === addContactModal) addContactModal.classList.remove('open');
});
$('#fp-search-btn')?.addEventListener('click', async () => {
  const raw = $('#fp-input').value.trim();
  const normalized = raw.toUpperCase().replace(/[\s:]/g, '');
  if (!/^[0-9A-F]{64}$/.test(normalized)) {
    $('#fp-result').innerHTML = '<div class="hint" style="margin:0"><span class="warn-title">⚠ invalid fingerprint</span>must be 64 hex chars (with or without spaces)</div>';
    return;
  }
  $('#fp-result').innerHTML = '<div class="dim" style="font-size: 0.75rem; padding: 0.5rem;">// looking up...</div>';
  try {
    const u = await api(`/api/users/by-fingerprint?fp=${encodeURIComponent(normalized)}`);
    const grouped = u.fingerprint.match(/.{1,4}/g).join(' ');
    $('#fp-result').innerHTML = `
      <div class="lookup-card">
        <div class="lookup-name">${escapeHtml(u.username)}</div>
        <div class="lookup-fp">${grouped}</div>
        <button class="btn primary" id="fp-send-request" data-id="${u.id}">[ send contact request ]</button>
      </div>
    `;
    $('#fp-send-request').addEventListener('click', async () => {
      const btn = $('#fp-send-request');
      btn.disabled = true;
      try {
        const r = await api('/api/contacts/requests', {
          method: 'POST', body: JSON.stringify({ userId: u.id })
        });
        if (r.accepted) {
          toast(`added · they had also requested you`);
        } else {
          toast(`request sent to ${u.username}`);
        }
        addContactModal.classList.remove('open');
      } catch (e) {
        toast(e.message, 'error');
        btn.disabled = false;
      }
    });
  } catch (e) {
    $('#fp-result').innerHTML = `<div class="hint" style="margin:0"><span class="warn-title">✗ not found</span>${escapeHtml(e.message)}</div>`;
  }
});
async function loadContactRequests() {
  try {
    State.contactRequests = await api('/api/contacts/requests');
  } catch { State.contactRequests = { incoming: [], outgoing: [] }; }
  renderRequestsBadge();
}
function renderRequestsBadge() {
  const n = State.contactRequests.incoming.length;
  const badge = $('#requests-badge');
  if (!badge) return;
  if (n > 0) {
    badge.textContent = n;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}
const requestsModal = $('#requests-modal');
$('#requests-btn')?.addEventListener('click', () => {
  renderRequestsList();
  requestsModal.classList.add('open');
});
$('#requests-close')?.addEventListener('click', () => requestsModal.classList.remove('open'));
requestsModal?.addEventListener('click', (e) => {
  if (e.target === requestsModal) requestsModal.classList.remove('open');
});
function renderRequestsList() {
  const inc = $('#requests-incoming');
  const out = $('#requests-outgoing');
  inc.innerHTML = '';
  out.innerHTML = '';
  if (State.contactRequests.incoming.length === 0) {
    inc.innerHTML = '<div class="dim" style="font-size:0.75rem; padding:0.5rem">// no pending incoming requests</div>';
  } else {
    for (const r of State.contactRequests.incoming) {
      const row = document.createElement('div');
      row.className = 'manage-row';
      row.innerHTML = `
        <div class="manage-row-name">${escapeHtml(r.from?.username || 'unknown')}</div>
        <div class="manage-row-actions">
          <button class="row-action" data-act="accept" data-id="${r.id}">accept</button>
          <button class="row-action danger" data-act="reject" data-id="${r.id}">reject</button>
        </div>
      `;
      inc.appendChild(row);
    }
  }
  if (State.contactRequests.outgoing.length === 0) {
    out.innerHTML = '<div class="dim" style="font-size:0.75rem; padding:0.5rem">// no outgoing requests</div>';
  } else {
    for (const r of State.contactRequests.outgoing) {
      const row = document.createElement('div');
      row.className = 'manage-row';
      row.innerHTML = `
        <div class="manage-row-name">${escapeHtml(r.to?.username || 'unknown')}</div>
        <div class="manage-row-actions">
          <button class="row-action danger" data-act="cancel" data-id="${r.id}">cancel</button>
        </div>
      `;
      out.appendChild(row);
    }
  }
}
document.querySelector('#requests-modal')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('.row-action');
  if (!btn) return;
  const rid = parseInt(btn.dataset.id, 10);
  const act = btn.dataset.act;
  btn.disabled = true;
  try {
    if (act === 'accept') {
      await api(`/api/contacts/requests/${rid}/accept`, { method: 'POST' });
      toast('accepted');
    } else if (act === 'reject' || act === 'cancel') {
      await api(`/api/contacts/requests/${rid}/reject`, { method: 'POST' });
      toast(act === 'cancel' ? 'cancelled' : 'rejected');
    }
    State.contactRequests.incoming = State.contactRequests.incoming.filter(r => r.id !== rid);
    State.contactRequests.outgoing = State.contactRequests.outgoing.filter(r => r.id !== rid);
    renderRequestsList();
    renderRequestsBadge();
  } catch (e) {
    toast(e.message, 'error');
    btn.disabled = false;
  }
});
const accountModal = $('#account-modal');
async function openAccountModal() {
  $('#account-name').textContent = State.me.username;
  $('#account-fp').textContent = await PGP.fingerprint(State.publicKeyObj);
  accountModal.classList.add('open');
}
$('#me-name')?.addEventListener('click', openAccountModal);
$('#account-btn')?.addEventListener('click', openAccountModal);
$('#account-close')?.addEventListener('click', () => accountModal.classList.remove('open'));
accountModal?.addEventListener('click', (e) => {
  if (e.target === accountModal) accountModal.classList.remove('open');
});
$('#account-copy-fp')?.addEventListener('click', async () => {
  navigator.clipboard?.writeText(await PGP.fingerprint(State.publicKeyObj));
  toast('your fingerprint copied');
});
$('#account-delete')?.addEventListener('click', async () => {
  const ok = await confirmDialog({
    title: 'delete account',
    message: 'this permanently wipes:\n\n· your account & login\n· all messages you sent\n· you from all groups\n· your contacts\n\nthis cannot be undone.',
    okLabel: 'delete account',
    cancelLabel: 'cancel',
    danger: true
  });
  if (!ok) return;
  try {
    await api('/api/account', { method: 'DELETE' });
    toast('account deleted');
    setTimeout(hardLogout, 800);
  } catch (e) {
    toast(e.message, 'error');
  }
});
async function loadGroups() {
  const list = await api('/api/groups');
  const fresh = new Map();
  for (const g of list) {
    const members = [];
    for (const m of g.members) {
      members.push({
        ...m,
        publicKeyObj: await PGP.readPublicKey(m.publicKey)
      });
    }
    fresh.set(g.id, {
      id: g.id, name: g.name, creatorId: g.creatorId,
      members, createdAt: g.createdAt
    });
  }
  State.groups = fresh;
  renderGroups();
}
function renderGroups() {
  const c = $('#groups-list');
  c.innerHTML = '';
  if (State.groups.size === 0) {
    c.innerHTML = '<div class="no-contacts">// no groups yet<br>tap + to create</div>';
    return;
  }
  for (const g of State.groups.values()) {
    const conv = `g:${g.id}`;
    const div = document.createElement('div');
    div.className = 'contact group' + (State.current === conv ? ' active' : '');
    div.innerHTML = `
      <div class="contact-avatar">▦</div>
      <div style="flex:1;min-width:0">
        <div class="contact-name">${escapeHtml(g.name)}</div>
        <div class="contact-meta">${g.members.length} members</div>
      </div>
    `;
    div.addEventListener('click', () => openConversation(conv));
    div.addEventListener('contextmenu', (e) => { e.preventDefault(); showGroupMenu(e, g.id); });
    let pressTimer;
    div.addEventListener('touchstart', (e) => {
      pressTimer = setTimeout(() => showGroupMenu(e.touches[0], g.id), 500);
    });
    div.addEventListener('touchend', () => clearTimeout(pressTimer));
    div.addEventListener('touchmove', () => clearTimeout(pressTimer));
    c.appendChild(div);
  }
}
const groupModal = $('#group-modal');
let groupSelected = new Set();  
$('#new-group-btn').addEventListener('click', () => {
  groupSelected.clear();
  $('#group-name-input').value = '';
  $('#group-member-search').value = '';
  renderMemberPicker('');
  renderSelectedMembers();
  groupModal.classList.add('open');
});
$('#group-modal-close').addEventListener('click', () => groupModal.classList.remove('open'));
$('#group-cancel').addEventListener('click', () => groupModal.classList.remove('open'));
groupModal.addEventListener('click', (e) => {
  if (e.target === groupModal) groupModal.classList.remove('open');
});
$('#group-member-search').addEventListener('input', (e) => {
  renderMemberPicker(e.target.value.toLowerCase());
});
function renderMemberPicker(query) {
  const wrap = $('#member-picker');
  wrap.innerHTML = '';
  const list = [...State.contacts.values()]
    .filter(u => !query || u.username.toLowerCase().includes(query));
  for (const u of list) {
    const row = document.createElement('div');
    const sel = groupSelected.has(u.id);
    row.className = 'member-row' + (sel ? ' selected' : '');
    row.innerHTML = `
      <div class="checkbox">${sel ? '✓' : ''}</div>
      <div style="flex:1">${escapeHtml(u.username)}</div>
    `;
    row.addEventListener('click', () => {
      if (groupSelected.has(u.id)) groupSelected.delete(u.id);
      else groupSelected.add(u.id);
      renderMemberPicker(query);
      renderSelectedMembers();
    });
    wrap.appendChild(row);
  }
}
function renderSelectedMembers() {
  const wrap = $('#selected-members');
  wrap.innerHTML = '';
  for (const uid of groupSelected) {
    const u = State.contacts.get(uid);
    if (!u) continue;
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.innerHTML = `${escapeHtml(u.username)} <span class="x">×</span>`;
    chip.addEventListener('click', () => {
      groupSelected.delete(uid);
      renderMemberPicker($('#group-member-search').value.toLowerCase());
      renderSelectedMembers();
    });
    wrap.appendChild(chip);
  }
}
$('#group-create').addEventListener('click', async () => {
  const btn = $('#group-create');
  const name = $('#group-name-input').value.trim();
  if (!name) { toast('group needs a name', 'error'); return; }
  if (groupSelected.size < 1) { toast('select at least 1 member', 'error'); return; }
  btn.classList.add('loading');
  btn.disabled = true;
  try {
    const g = await api('/api/groups', {
      method: 'POST',
      body: JSON.stringify({ name, memberIds: [...groupSelected] })
    });
    if (!State.groups.has(g.id)) {
      const members = [];
      for (const m of g.members) {
        members.push({ ...m, publicKeyObj: await PGP.readPublicKey(m.publicKey) });
      }
      State.groups.set(g.id, { ...g, members });
      renderGroups();
    }
    groupModal.classList.remove('open');
    openConversation(`g:${g.id}`);
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
});
const manageModal = $('#manage-modal');
let manageGroupId = null;
let manageAddSelected = new Set();
function openManageGroup(groupId) {
  manageGroupId = groupId;
  manageAddSelected.clear();
  $('#manage-add-search').value = '';
  renderManagePanel();
  manageModal.classList.add('open');
}
$('#manage-close')?.addEventListener('click', () => manageModal.classList.remove('open'));
$('#manage-done')?.addEventListener('click', () => manageModal.classList.remove('open'));
manageModal.addEventListener('click', (e) => {
  if (e.target === manageModal) manageModal.classList.remove('open');
});
$('#manage-add-search')?.addEventListener('input', (e) => {
  renderManageAddPicker(e.target.value.toLowerCase());
});
function renderManagePanel() {
  const g = State.groups.get(manageGroupId);
  if (!g) { manageModal.classList.remove('open'); return; }
  const meId = State.me.id;
  const isCreator = g.creatorId === meId;
  const isAdmin = isCreator || (g.adminIds || []).includes(meId);
  $('#manage-group-name').textContent = g.name;
  $('#manage-meta').textContent = `${g.members.length} members${isCreator ? ' · you are the creator' : isAdmin ? ' · you are an admin' : ''}`;
  const list = $('#manage-members-list');
  list.innerHTML = '';
  const sorted = [...g.members].sort((a, b) => {
    const ar = a.id === g.creatorId ? 0 : (g.adminIds || []).includes(a.id) ? 1 : 2;
    const br = b.id === g.creatorId ? 0 : (g.adminIds || []).includes(b.id) ? 1 : 2;
    if (ar !== br) return ar - br;
    return a.username.localeCompare(b.username);
  });
  for (const m of sorted) {
    const isThemCreator = m.id === g.creatorId;
    const isThemAdmin = (g.adminIds || []).includes(m.id);
    const isThemMe = m.id === meId;
    const row = document.createElement('div');
    row.className = 'manage-row';
    let roleBadge = '';
    if (isThemCreator) roleBadge = '<span class="role-badge creator">creator</span>';
    else if (isThemAdmin) roleBadge = '<span class="role-badge admin">admin</span>';
    let actions = '';
    if (isCreator && !isThemCreator) {
      if (isThemAdmin) {
        actions += `<button class="row-action" data-action="demote" data-id="${m.id}">demote</button>`;
      } else {
        actions += `<button class="row-action" data-action="promote" data-id="${m.id}">promote</button>`;
      }
    }
    if (isThemMe && !isThemCreator) {
      actions += `<button class="row-action danger" data-action="leave" data-id="${m.id}">leave</button>`;
    } else if (!isThemCreator && !isThemMe) {
      const canRemove = isCreator || (isAdmin && !isThemAdmin);
      if (canRemove) {
        actions += `<button class="row-action danger" data-action="remove" data-id="${m.id}">remove</button>`;
      }
    }
    row.innerHTML = `
      <div class="manage-row-name">
        ${escapeHtml(m.username)}${isThemMe ? ' <span class="dim">· you</span>' : ''}
        ${roleBadge}
      </div>
      <div class="manage-row-actions">${actions}</div>
    `;
    list.appendChild(row);
  }
  list.onclick = async (e) => {
    const btn = e.target.closest('.row-action');
    if (!btn) return;
    const action = btn.dataset.action;
    const targetId = parseInt(btn.dataset.id, 10);
    const username = sorted.find(m => m.id === targetId)?.username || '';
    btn.disabled = true;
    try {
      if (action === 'promote') {
        await api(`/api/groups/${manageGroupId}/admins`, {
          method: 'POST', body: JSON.stringify({ userId: targetId })
        });
        toast(`promoted ${username}`);
      } else if (action === 'demote') {
        await api(`/api/groups/${manageGroupId}/admins/${targetId}`, { method: 'DELETE' });
        toast(`demoted ${username}`);
      } else if (action === 'remove') {
        const ok = await confirmDialog({
          title: 'remove member',
          message: `remove ${username} from the group?`,
          okLabel: 'remove',
          danger: true
        });
        if (!ok) { btn.disabled = false; return; }
        await api(`/api/groups/${manageGroupId}/members/${targetId}`, { method: 'DELETE' });
        toast(`removed ${username}`);
      } else if (action === 'leave') {
        const ok = await confirmDialog({
          title: 'leave group',
          message: 'leave this group? you will lose access to past messages.',
          okLabel: 'leave',
          danger: true
        });
        if (!ok) { btn.disabled = false; return; }
        await api(`/api/groups/${manageGroupId}/members/${targetId}`, { method: 'DELETE' });
        toast('left the group');
        manageModal.classList.remove('open');
        return;
      }
      renderManagePanel();
    } catch (e) {
      toast(e.message, 'error');
      btn.disabled = false;
    }
  };
  const addSection = $('#manage-add-section');
  if (isAdmin) {
    addSection.classList.remove('hidden');
    renderManageAddPicker('');
  } else {
    addSection.classList.add('hidden');
  }
  const dangerSection = $('#manage-danger-section');
  if (isCreator) {
    dangerSection.classList.remove('hidden');
  } else {
    dangerSection.classList.add('hidden');
  }
}
function renderManageAddPicker(query) {
  const g = State.groups.get(manageGroupId);
  if (!g) return;
  const memberIdSet = new Set(g.members.map(m => m.id));
  const wrap = $('#manage-add-picker');
  wrap.innerHTML = '';
  const candidates = [...State.contacts.values()]
    .filter(u => !memberIdSet.has(u.id))
    .filter(u => !query || u.username.toLowerCase().includes(query));
  for (const u of candidates) {
    const sel = manageAddSelected.has(u.id);
    const row = document.createElement('div');
    row.className = 'member-row' + (sel ? ' selected' : '');
    row.innerHTML = `
      <div class="checkbox">${sel ? '✓' : ''}</div>
      <div style="flex:1">${escapeHtml(u.username)}</div>
    `;
    row.addEventListener('click', () => {
      if (manageAddSelected.has(u.id)) manageAddSelected.delete(u.id);
      else manageAddSelected.add(u.id);
      renderManageAddPicker(query);
    });
    wrap.appendChild(row);
  }
}
$('#manage-add-btn')?.addEventListener('click', async () => {
  const btn = $('#manage-add-btn');
  if (manageAddSelected.size === 0) { toast('select someone first', 'error'); return; }
  btn.classList.add('loading');
  btn.disabled = true;
  try {
    await api(`/api/groups/${manageGroupId}/members`, {
      method: 'POST',
      body: JSON.stringify({ memberIds: [...manageAddSelected] })
    });
    toast(`added ${manageAddSelected.size} member(s)`);
    manageAddSelected.clear();
    setTimeout(renderManagePanel, 100);
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
});
$('#manage-delete-group')?.addEventListener('click', async () => {
  const g = State.groups.get(manageGroupId);
  if (!g) return;
  const ok = await confirmDialog({
    title: 'delete group',
    message: `delete group "${g.name}"?\n\nthis wipes the group and all its messages for everyone.\nthis cannot be undone.`,
    okLabel: 'delete group',
    cancelLabel: 'cancel',
    danger: true
  });
  if (!ok) return;
  try {
    await api(`/api/groups/${manageGroupId}`, { method: 'DELETE' });
    toast('group deleted');
    manageModal.classList.remove('open');
  } catch (e) {
    toast(e.message, 'error');
  }
});
async function renderChatHeader() {
  const conv = State.current;
  if (!conv) {
    $('#chat-header').innerHTML = `
      <button class="header-back-btn" data-role="menu" title="open contacts">☰</button>
      <div class="empty-header">// select a contact or group</div>
    `;
    return;
  }
  const isGroup = conv.startsWith('g:');
  const id = parseInt(conv.slice(2), 10);
  if (isGroup) {
    const g = State.groups.get(id);
    if (!g) return;
    const meId = State.me.id;
    const isAdmin = g.creatorId === meId || (g.adminIds || []).includes(meId);
    $('#chat-header').innerHTML = `
      <button class="header-back-btn" data-role="menu" title="open contacts">☰</button>
      <div style="flex:1; min-width:0">
        <div class="peer-name"><span class="diamond">◈</span>${escapeHtml(g.name)}</div>
        <div class="meta-line">${g.members.length} members${isAdmin ? ' · you can manage' : ''}</div>
      </div>
      <button class="header-action-btn" id="manage-group-btn" title="group settings">⚙</button>
    `;
    $('#manage-group-btn').addEventListener('click', () => openManageGroup(id));
  } else {
    const peer = State.contacts.get(id);
    if (!peer) return;
    $('#chat-header').innerHTML = `
      <button class="header-back-btn" data-role="menu" title="open contacts">☰</button>
      <div class="peer-name">${escapeHtml(peer.username)}</div>
      <div class="peer-fp" title="click for full fingerprint"></div>
    `;
    PGP.shortId(peer.publicKeyObj).then(id => {
      const el = $('#chat-header .peer-fp');
      if (el) el.textContent = id;
    });
    $('#chat-header .peer-fp').addEventListener('click', async () => {
      navigator.clipboard?.writeText(await PGP.fingerprint(peer.publicKeyObj));
      toast('fingerprint copied');
    });
  }
}
async function backfillCurrentConversation() {
  const conv = State.current;
  if (!conv) return;
  const isGroup = conv.startsWith('g:');
  const id = parseInt(conv.slice(2), 10);
  const path = isGroup ? `/api/messages/group/${id}` : `/api/messages/dm/${id}`;
  let raw;
  try { raw = await api(path); }
  catch (e) { console.warn('[backfill] fetch fail', e); return; }
  const existing = State.messagesByConv.get(conv) || [];
  const existingIds = new Set(existing.map(m => m.id));
  let added = 0;
  for (const m of raw) {
    if (existingIds.has(m.id)) continue;
    let plaintext, failed = false;
    try {
      const senderPubObj = getSenderPublicKeyObj(m.senderId);
      if (!senderPubObj) throw new Error('unknown sender');
      plaintext = await PGP.decrypt(m.ciphertext, State.privateKey, senderPubObj);
    }
    catch { plaintext = '⚠ undecryptable'; failed = true; }
    existing.push({
      id: m.id, senderId: m.senderId,
      plaintext, createdAt: m.createdAt,
      deleteAt: m.deleteAt, failed,
      attachment: m.attachment || null
    });
    added++;
  }
  if (added > 0) {
    existing.sort((a, b) => a.createdAt - b.createdAt || a.id - b.id);
    State.messagesByConv.set(conv, existing);
    renderMessages({ forceScrollToBottom: true });
    console.log(`[backfill] added ${added} message(s)`);
  }
}
async function openConversation(conv) {
  State.current = conv;
  renderContacts();
  renderGroups();
  const isGroup = conv.startsWith('g:');
  const id = parseInt(conv.slice(2), 10);
  if (isGroup) {
    if (!State.groups.get(id)) return;
  } else {
    if (!State.contacts.get(id)) return;
  }
  renderChatHeader();
  if (window.innerWidth <= 720) toggleSidebar(false);
  $('#send-form').classList.remove('hidden');
  if (!State.messagesByConv.has(conv)) {
    const path = isGroup ? `/api/messages/group/${id}` : `/api/messages/dm/${id}`;
    const raw = await api(path);
    const decrypted = [];
    for (const m of raw) {
      try {
        const senderPubObj = getSenderPublicKeyObj(m.senderId);
        if (!senderPubObj) throw new Error('unknown sender');
        const text = await PGP.decrypt(m.ciphertext, State.privateKey, senderPubObj);
        decrypted.push({
          id: m.id, senderId: m.senderId,
          plaintext: text, createdAt: m.createdAt,
          deleteAt: m.deleteAt,
          attachment: m.attachment || null
        });
        scheduleClientTtl(m.id, m.deleteAt);
      } catch {
        decrypted.push({
          id: m.id, senderId: m.senderId,
          plaintext: '⚠ undecryptable', createdAt: m.createdAt,
          deleteAt: m.deleteAt, failed: true,
          attachment: m.attachment || null
        });
      }
    }
    State.messagesByConv.set(conv, decrypted);
  }
  renderMessages({ forceScrollToBottom: true });
}
function renderAttachmentSlot(m) {
  const a = m.attachment;
  if (a.expired) {
    return `
      <div class="attach-slot expired">
        <div class="attach-slot-icon">⌛</div>
        <div class="attach-slot-info">
          <div class="attach-slot-name">${escapeHtml(a.filename)}</div>
          <div class="attach-slot-meta">attachment expired · ${escapeHtml(a.mime)} · ${formatBytes(a.size)}</div>
        </div>
      </div>
    `;
  }
  const icon = iconForMime(a.mime);
  const sizeLabel = formatBytes(a.size);
  const autoload = (a.mime || '').startsWith('image/') || (a.mime || '').startsWith('audio/');
  const expiryHint = formatExpiryHint(a);
  return `
    <div class="attach-slot${autoload ? ' autoload' : ''}" data-message-id="${m.id}" data-loaded="0" data-mime="${escapeHtml(a.mime || '')}">
      <div class="attach-slot-icon">${icon}</div>
      <div class="attach-slot-info">
        <div class="attach-slot-name">${escapeHtml(a.filename)}</div>
        <div class="attach-slot-meta">${escapeHtml(a.mime)} · ${sizeLabel}${expiryHint ? ' · ' + expiryHint : ''}${autoload ? '' : ' · tap to load'}</div>
      </div>
    </div>
  `;
}
function formatExpiryHint(a) {
  if (!a.expiresAt) return '';
  const left = a.expiresAt - Math.floor(Date.now()/1000);
  if (left <= 0) return 'expiring';
  if (left < 3600) return `expires in ${Math.round(left/60)}m`;
  if (left < 86400) return `expires in ${Math.round(left/3600)}h`;
  return `expires in ${Math.round(left/86400)}d`;
}
const attachmentCache = new Map();
let autoloadObserver = null;
const autoloadTargets = new WeakMap(); 
function observeForAutoload(slot, message) {
  autoloadTargets.set(slot, message);
  if (!autoloadObserver) {
    autoloadObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const target = entry.target;
        const msg = autoloadTargets.get(target);
        if (!msg) continue;
        if (target.dataset.loaded === '1') continue;
        loadAndShowAttachment(msg, target);
        autoloadObserver.unobserve(target);
      }
    }, {
      rootMargin: '200px 0px',
      threshold: 0.01
    });
  }
  autoloadObserver.observe(slot);
  setTimeout(() => {
    if (slot.dataset.loaded === '1') return;
    if (!slot.isConnected) return;
    const r = slot.getBoundingClientRect();
    const inView = r.bottom > -200 && r.top < (window.innerHeight + 200);
    if (inView) {
      loadAndShowAttachment(message, slot);
      autoloadObserver?.unobserve(slot);
    }
  }, 50);
}
async function loadAndShowAttachment(m, slot) {
  if (slot.dataset.loaded === '1') return;
  const a = m.attachment;
  if (!a) return;
  const cached = attachmentCache.get(a.attachmentId);
  if (cached) {
    renderAttachmentInline(slot, cached, a);
    slot.dataset.loaded = '1';
    return;
  }
  console.log('[attach] loading', a.filename, a.mime, a.size, 'bytes');
  slot.querySelector('.attach-slot-meta').textContent = 'fetching...';
  try {
    const senderPubObj = getSenderPublicKeyObj(m.senderId);
    if (!senderPubObj) throw new Error('sender public key not found');
    const rawKey = await PGP.unwrapKey(a.keyCiphertext, State.privateKey, senderPubObj);
    const r = await fetch(`/api/attachments/${a.attachmentId}`, {
      headers: { 'Authorization': `Bearer ${State.token}` }
    });
    if (!r.ok) throw new Error(`server ${r.status}`);
    const encrypted = new Uint8Array(await r.arrayBuffer());
    slot.querySelector('.attach-slot-meta').textContent = 'decrypting...';
    const plaintext = await PGP.decryptFile(encrypted, rawKey);
    const blob = new Blob([plaintext], { type: a.mime });
    const url = URL.createObjectURL(blob);
    attachmentCache.set(a.attachmentId, url);
    console.log('[attach] decrypted', a.filename, '→', url);
    renderAttachmentInline(slot, url, a);
    slot.dataset.loaded = '1';
  } catch (e) {
    console.warn('[attach] load failed:', e);
    slot.querySelector('.attach-slot-meta').textContent = '⚠ failed: ' + e.message;
  }
}
function renderAttachmentInline(slot, url, a) {
  const mime = a.mime || '';
  let inner;
  if (mime.startsWith('image/')) {
    inner = `<img src="${url}" alt="${escapeHtml(a.filename)}" class="attach-image" />`;
  } else if (mime.startsWith('video/')) {
    inner = `<video src="${url}" controls class="attach-video"></video>`;
  } else if (mime.startsWith('audio/')) {
    inner = `<audio src="${url}" controls class="attach-audio"></audio>`;
  } else {
    inner = `
      <div class="attach-slot-icon">${iconForMime(mime)}</div>
      <div class="attach-slot-info">
        <div class="attach-slot-name">${escapeHtml(a.filename)}</div>
        <div class="attach-slot-meta">${escapeHtml(mime)} · ${formatBytes(a.size)}</div>
      </div>
      <a href="${url}" download="${escapeHtml(a.filename)}" class="attach-download">[ download ]</a>
    `;
  }
  slot.innerHTML = inner;
  if (mime.startsWith('image/') || mime.startsWith('video/') || mime.startsWith('audio/')) {
    const mediaEl = slot.querySelector('img, video, audio');
    if (mediaEl) {
      mediaEl.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const msgId = slot.dataset.messageId ? parseInt(slot.dataset.messageId, 10) : null;
        showMessageMenu(e, msgId, { url, filename: a.filename });
      });
      mediaEl.title = 'Right-click for options';
    }
  }
  slot.classList.add('loaded');
}
function buildMessageDiv(m, isGroup) {
  const div = document.createElement('div');
  const mine = m.senderId === State.me.id;
  const expiring = m.deleteAt && m.deleteAt > 0;
  div.className = 'msg ' + (mine ? 'mine' : 'theirs') +
                  (m.failed ? ' failed' : '') +
                  (expiring ? ' expiring' : '');
  div.dataset.messageId = m.id;
  const senderName = (!mine && isGroup) ? senderUsername(m.senderId) : null;
  const ttlLabel = expiring ? formatTtl(m.deleteAt) : '';
  const captionText = (m.plaintext === '[attachment]') ? '' : m.plaintext;
  const rendered = captionText
    ? renderTextWithLinks(captionText)
    : { html: '', embeds: [] };
  const embedsHtml = rendered.embeds.map(renderEmbedShell).join('');
  div.innerHTML = `
    ${senderName ? `<span class="msg-sender">${escapeHtml(senderName)}</span>` : ''}
    ${m.attachment ? renderAttachmentSlot(m) : ''}
    ${rendered.html ? `<div class="msg-text">${rendered.html}</div>` : ''}
    ${embedsHtml}
    <span class="msg-meta">${formatTime(m.createdAt)}${ttlLabel ? `<span class="msg-ttl">${ttlLabel}</span>` : ''}</span>
  `;
  if (m.attachment && !m.attachment.expired) {
    const slot = div.querySelector('.attach-slot');
    if (slot) {
      slot.addEventListener('click', () => loadAndShowAttachment(m, slot));
      if (slot.classList.contains('autoload')) observeForAutoload(slot, m);
    }
  }
  for (const ytWrap of div.querySelectorAll('.yt-embed[data-video-id]')) {
    const videoId = ytWrap.dataset.videoId;
    const start = ytWrap.dataset.start;
    ytWrap.addEventListener('click', (e) => {
      if (e.target.closest('.yt-fallback-link')) return;
      if (ytWrap.dataset.loaded === '1') return;
      ytWrap.dataset.loaded = '1';
      ytWrap.innerHTML = renderYouTubeIframe(videoId, start);
    });
  }
  div.addEventListener('click', (e) => {
    if (e.target.closest('a')) e.stopPropagation();
  });
  if (mine && !m.failed) {
    div.addEventListener('contextmenu', (e) => {
      if (e.target.closest('a')) return;
      e.preventDefault();
      showMessageMenu(e, m.id);
    });
    let pressTimer;
    div.addEventListener('touchstart', (e) => {
      if (e.target.closest('a, .yt-embed')) return;
      pressTimer = setTimeout(() => showMessageMenu(e.touches[0], m.id), 500);
    });
    div.addEventListener('touchend', () => clearTimeout(pressTimer));
    div.addEventListener('touchmove', () => clearTimeout(pressTimer));
  }
  return div;
}
const URL_RE = /\bhttps?:\/\/[^\s<>"]+/gi;
const YT_RE = /^https?:\/\/(?:www\.|m\.|music\.)?(?:youtube\.com\/(?:watch\?(?:[^#]*&)?v=|shorts\/|embed\/|v\/|live\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/i;
function trimUrlPunct(url) {
  return url.replace(/[.,;:!?]+$/, '');
}
function parseYouTubeStart(t) {
  if (!t) return null;
  if (/^\d+$/.test(t)) return parseInt(t, 10);
  let total = 0;
  const h = t.match(/(\d+)\s*h/i); if (h) total += parseInt(h[1], 10) * 3600;
  const mm = t.match(/(\d+)\s*m/i); if (mm) total += parseInt(mm[1], 10) * 60;
  const s = t.match(/(\d+)\s*s/i); if (s) total += parseInt(s[1], 10);
  return total > 0 ? total : null;
}
const SAFE_URL_SCHEMES = /^https?:\/\//i;
function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return SAFE_URL_SCHEMES.test(parsed.href);
  } catch { return false; }
}
function renderTextWithLinks(text) {
  const parts = [];
  const embeds = [];
  const seenVideos = new Set();
  let lastIdx = 0;
  let m;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) {
    if (m.index > lastIdx) parts.push({ kind: 'text', value: text.slice(lastIdx, m.index) });
    const url = trimUrlPunct(m[0]);
    if (isSafeUrl(url)) {
      parts.push({ kind: 'link', url });
      const yt = url.match(YT_RE);
      if (yt) {
        const videoId = yt[1];
        let start = null;
        try {
          const u = new URL(url);
          start = parseYouTubeStart(u.searchParams.get('t') || u.searchParams.get('start'));
        } catch {  }
        if (!seenVideos.has(videoId)) {
          seenVideos.add(videoId);
          embeds.push({ kind: 'youtube', videoId, start, url });
        }
      }
    } else {
      parts.push({ kind: 'text', value: url });
    }
    lastIdx = m.index + url.length;
    URL_RE.lastIndex = lastIdx;
  }
  if (lastIdx < text.length) parts.push({ kind: 'text', value: text.slice(lastIdx) });
  const html = parts.map(p => {
    if (p.kind === 'text') return escapeHtml(p.value);
    return `<a href="${escapeHtml(p.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(p.url)}</a>`;
  }).join('');
  return { html, embeds };
}
function renderEmbedShell(embed) {
  if (embed.kind !== 'youtube') return '';
  const id = embed.videoId;
  const thumb = `https://i.ytimg.com/vi/${encodeURIComponent(id)}/hqdefault.jpg`;
  const startAttr = embed.start ? ` data-start="${embed.start}"` : '';
  return `
    <div class="yt-embed" data-video-id="${escapeHtml(id)}"${startAttr} role="button" tabindex="0" title="play on youtube-nocookie.com">
      <div class="yt-thumb-wrap">
        <img class="yt-thumb" src="${thumb}" alt="YouTube thumbnail" loading="lazy" referrerpolicy="no-referrer" />
        <div class="yt-play-btn" aria-hidden="true">▶</div>
      </div>
      <div class="yt-meta">
        <span class="yt-badge">YouTube</span>
        <a class="yt-fallback-link" href="${escapeHtml(embed.url)}" target="_blank" rel="noopener noreferrer">open ↗</a>
      </div>
    </div>
  `;
}
function renderYouTubeIframe(videoId, start) {
  const id = encodeURIComponent(videoId);
  const params = new URLSearchParams({ autoplay: '1', rel: '0' });
  if (start) params.set('start', String(parseInt(start, 10) || 0));
  try { if (window.location?.origin) params.set('origin', window.location.origin); } catch {}
  const src = `https://www.youtube-nocookie.com/embed/${id}?${params.toString()}`;
  return `
    <div class="yt-iframe-wrap">
      <iframe
        src="${src}"
        title="YouTube video player"
        loading="lazy"
        referrerpolicy="strict-origin-when-cross-origin"
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
        allowfullscreen></iframe>
    </div>
  `;
}
function renderMessages({ forceScrollToBottom = false } = {}) {
  const wrap = $('#messages');
  const wasAtBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 60;
  const list = State.messagesByConv.get(State.current) || [];
  const isGroup = State.current ? State.current.startsWith('g:') : false;
  const rendered = new Map(); 
  for (const child of wrap.children) {
    const id = child.dataset.messageId;
    if (id) rendered.set(parseInt(id, 10), child);
  }
  const wantIds = new Set(list.map(m => m.id));
  for (const [id, div] of rendered) {
    if (!wantIds.has(id)) div.remove();
  }
  if (list.length === 0) {
    wrap.innerHTML = '';
    const p = document.createElement('div');
    p.className = 'placeholder';
    p.innerHTML = '<span class="diamond">◈</span><p>no messages yet · say something encrypted</p>';
    wrap.appendChild(p);
    return;
  } else {
    wrap.querySelector('.placeholder')?.remove();
  }
  let refNode = null; 
  for (let i = list.length - 1; i >= 0; i--) {
    const m = list[i];
    let div = rendered.get(m.id);
    if (!div) {
      div = buildMessageDiv(m, isGroup);
    }
    const expiring = m.deleteAt && m.deleteAt > 0;
    const ttlSpan = div.querySelector('.msg-ttl');
    if (expiring && ttlSpan) ttlSpan.textContent = formatTtl(m.deleteAt);
    if (div !== (refNode ? refNode.previousSibling : wrap.lastChild)) {
      wrap.insertBefore(div, refNode);
    }
    refNode = div;
  }
  if (forceScrollToBottom || wasAtBottom) {
    wrap.scrollTop = wrap.scrollHeight;
  }
}
function senderUsername(id) {
  if (id === State.me.id) return State.me.username;
  const c = State.contacts.get(id);
  if (c) return c.username;
  for (const g of State.groups.values()) {
    const m = g.members.find(x => x.id === id);
    if (m) return m.username;
  }
  return `user#${id}`;
}
const msgMenu = $('#msg-menu');
const msgMenuDownloadBtn = msgMenu?.querySelector('[data-action="download"]');
let pendingDeleteId = null;
let pendingAttachment = null; 
function showMessageMenu(evt, messageId, attachment = null) {
  pendingDeleteId = messageId;
  pendingAttachment = attachment || null;
  if (msgMenuDownloadBtn) {
    msgMenuDownloadBtn.style.display = attachment ? '' : 'none';
  }
  const x = (evt.clientX != null ? evt.clientX : evt.pageX) || 100;
  const y = (evt.clientY != null ? evt.clientY : evt.pageY) || 100;
  msgMenu.style.left = Math.min(x, window.innerWidth - 200) + 'px';
  msgMenu.style.top = Math.min(y, window.innerHeight - 100) + 'px';
  msgMenu.classList.remove('hidden');
}
msgMenu.addEventListener('click', async (e) => {
  const action = e.target.closest('.popup-item')?.dataset.action;
  if (!action) return;
  msgMenu.classList.add('hidden');
  if (action === 'delete' && pendingDeleteId != null) {
    const ok = await confirmDialog({
      title: 'delete message',
      message: 'delete this message for everyone?',
      okLabel: 'delete',
      danger: true
    });
    if (!ok) return;
    State.socket.emit('delete-message', { messageId: pendingDeleteId }, (ack) => {
      if (!ack?.ok) toast(ack?.error || 'delete failed', 'error');
    });
  } else if (action === 'delete-me' && pendingDeleteId != null) {
    const ok = await confirmDialog({
      title: 'delete message',
      message: 'delete this message just for you?',
      okLabel: 'delete',
      danger: true
    });
    if (!ok) return;
    const list = State.messagesByConv.get(State.current) || [];
    const idx = list.findIndex(m => m.id === pendingDeleteId);
    if (idx !== -1) {
      list.splice(idx, 1);
      renderMessages();
    }
  } else if (action === 'download' && pendingAttachment) {
    const a = document.createElement('a');
    a.href = pendingAttachment.url;
    a.download = pendingAttachment.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
  pendingAttachment = null;
});
document.addEventListener('click', (e) => {
  if (!msgMenu.contains(e.target)) msgMenu.classList.add('hidden');
}, true);
const timerMenu = $('#timer-menu');
const timerBtn = $('#timer-btn');
const timerLabel = $('#timer-label');
timerBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  const r = timerBtn.getBoundingClientRect();
  timerMenu.style.left = r.left + 'px';
  timerMenu.style.bottom = (window.innerHeight - r.top + 6) + 'px';
  timerMenu.style.top = 'auto';
  timerMenu.classList.toggle('hidden');
  $$('.popup-item', timerMenu).forEach(i => {
    i.classList.toggle('active', parseInt(i.dataset.seconds, 10) === State.composerTtl);
  });
});
timerMenu.addEventListener('click', (e) => {
  const item = e.target.closest('.popup-item');
  if (!item) return;
  State.composerTtl = parseInt(item.dataset.seconds, 10) || 0;
  if (State.composerTtl > 0) {
    timerLabel.textContent = '⏱ ' + ttlShortLabel(State.composerTtl);
    timerBtn.classList.add('active');
  } else {
    timerLabel.textContent = '⏱';
    timerBtn.classList.remove('active');
  }
  timerMenu.classList.add('hidden');
});
document.addEventListener('click', (e) => {
  if (!timerMenu.contains(e.target) && e.target !== timerBtn && !timerBtn.contains(e.target)) {
    timerMenu.classList.add('hidden');
  }
}, true);
function ttlShortLabel(secs) {
  if (secs < 3600) return Math.round(secs/60) + 'm';
  if (secs < 86400) return Math.round(secs/3600) + 'h';
  if (secs < 604800) return Math.round(secs/86400) + 'd';
  return Math.round(secs/604800) + 'w';
}
const attachBtn = $('#attach-btn');
const attachInput = $('#attach-input');
const attachPreview = $('#attach-preview');
attachBtn?.addEventListener('click', () => attachInput.click());
attachInput?.addEventListener('change', async (e) => {
  const file = e.target.files?.[0];
  attachInput.value = ''; 
  if (!file) return;
  if (file.size > 100 * 1024 * 1024) {
    toast('file too big · 100 MB max', 'error');
    return;
  }
  await stagePendingAttachment(file);
});
async function stagePendingAttachment(file) {
  if (State.pendingAttachment) clearPendingAttachment();
  attachPreview.classList.remove('hidden');
  $('#attach-preview-icon').textContent = iconForMime(file.type);
  $('#attach-preview-name').textContent = file.name;
  $('#attach-preview-meta').textContent = `${formatBytes(file.size)} · preparing...`;
  attachBtn.classList.add('active');
  attachBtn.disabled = true;
  try {
    let prepared = file;
    if (canStripMetadata(file)) {
      $('#attach-preview-meta').textContent = `${formatBytes(file.size)} · cleaning metadata...`;
      try {
        prepared = await stripImageMetadata(file);
        if (prepared !== file) {
          $('#attach-preview-name').textContent = prepared.name;
          $('#attach-preview-icon').textContent = iconForMime(prepared.type);
        }
      } catch (e) {
        throw new Error('could not clean metadata — file not uploaded');
      }
    }
    const fileBytes = new Uint8Array(await prepared.arrayBuffer());
    const rawKey = await PGP.generateFileKey();
    $('#attach-preview-meta').textContent = `${formatBytes(prepared.size)} · encrypting...`;
    const encrypted = await PGP.encryptFile(fileBytes, rawKey);
    $('#attach-preview-meta').textContent = `${formatBytes(prepared.size)} · uploading...`;
    const fp = await fetch(
      `/api/attachments?filename=${encodeURIComponent(prepared.name)}&mime=${encodeURIComponent(prepared.type || 'application/octet-stream')}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'Authorization': `Bearer ${State.token}`
        },
        body: encrypted
      }
    );
    if (!fp.ok) {
      const err = await fp.json().catch(() => ({}));
      throw new Error(err.error || `upload ${fp.status}`);
    }
    const { id } = await fp.json();
    State.pendingAttachment = {
      rawKey, attachmentId: id,
      filename: prepared.name,
      mime: prepared.type || 'application/octet-stream',
      size: prepared.size
    };
    $('#attach-preview-meta').textContent = `${formatBytes(prepared.size)} · ready · type a caption (optional)`;
  } catch (e) {
    toast('attachment failed: ' + e.message, 'error');
    clearPendingAttachment();
  } finally {
    attachBtn.disabled = false;
  }
}
function canStripMetadata(file) {
  if (!file || !file.type) return false;
  switch (file.type) {
    case 'image/jpeg':
    case 'image/jpg':
    case 'image/png':
    case 'image/webp':
    case 'image/bmp':
    case 'image/tiff':
      return true;
    default:
      return false;
  }
}
async function stripImageMetadata(file) {
  let bitmap;
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
  } catch {
    bitmap = await createImageBitmap(file);
  }
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close?.();
  const keepFormat = (file.type === 'image/png' || file.type === 'image/webp');
  const outMime = keepFormat ? file.type : 'image/jpeg';
  const quality = (outMime === 'image/jpeg' || outMime === 'image/webp') ? 0.92 : undefined;
  const blob = await new Promise((resolve, reject) => {
    canvas.toBlob(
      (b) => b ? resolve(b) : reject(new Error('canvas.toBlob returned null')),
      outMime,
      quality
    );
  });
  let outName = file.name;
  if (outMime !== file.type) {
    const ext = outMime === 'image/jpeg' ? 'jpg'
              : outMime === 'image/png'  ? 'png'
              : outMime === 'image/webp' ? 'webp'
              : 'bin';
    outName = file.name.replace(/\.[^.]+$/, '') + '.' + ext;
  }
  return new File([blob], outName, { type: outMime });
}
function clearPendingAttachment() {
  State.pendingAttachment = null;
  attachPreview.classList.add('hidden');
  attachBtn.classList.remove('active');
}
$('#attach-preview-remove')?.addEventListener('click', clearPendingAttachment);
function iconForMime(mime) {
  if (!mime) return '📄';
  if (mime.startsWith('image/')) return '🖼️';
  if (mime.startsWith('video/')) return '🎬';
  if (mime.startsWith('audio/')) return '🎵';
  if (mime === 'application/pdf') return '📕';
  if (mime.startsWith('text/')) return '📝';
  return '📄';
}
function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
function formatTtl(deleteAt) {
  const left = deleteAt - Math.floor(Date.now()/1000);
  if (left <= 0) return 'expiring...';
  return '⏱ ' + ttlShortLabel(left);
}
$('#send-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await sendCurrentMessage();
});
$('#message-input').addEventListener('keydown', (e) => {
  const isTouch = matchMedia('(pointer: coarse)').matches;
  if (e.key === 'Enter' && !e.shiftKey && !isTouch) {
    e.preventDefault();
    sendCurrentMessage();
    return;
  }
  setTimeout(() => {
    const ta = e.target;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 140) + 'px';
  });
});
function getSenderPublicKeyObj(senderId) {
  if (senderId === State.me?.id) return State.publicKeyObj;
  const contact = State.contacts.get(senderId);
  if (contact?.publicKeyObj) return contact.publicKeyObj;
  for (const g of State.groups.values()) {
    const member = g.members.find(m => m.id === senderId);
    if (member?.publicKeyObj) return member.publicKeyObj;
  }
  return null;
}
async function ingestIncomingMessage(m) {
  let plaintext, failed = false;
  try {
    const senderPubObj = getSenderPublicKeyObj(m.senderId);
    if (!senderPubObj) throw new Error('unknown sender');
    plaintext = await PGP.decrypt(m.ciphertext, State.privateKey, senderPubObj);
  } catch (e) { console.warn('[ingest] decrypt fail', e); plaintext = '⚠ undecryptable'; failed = true; }
  const conv = m.conv;
  let myConv = conv;
  if (conv.startsWith('u:')) {
    const partyInConv = parseInt(conv.slice(2), 10);
    if (m.senderId !== State.me.id) {
      myConv = `u:${m.senderId}`;
    }
    const otherId = m.senderId === State.me.id ? partyInConv : m.senderId;
    if (!State.contacts.has(otherId)) await loadContacts();
  }
  const arr = State.messagesByConv.get(myConv) || [];
  if (arr.some(x => x.id === m.id)) {
    return;
  }
  arr.push({
    id: m.id, senderId: m.senderId,
    plaintext, createdAt: m.createdAt,
    deleteAt: m.deleteAt, failed,
    attachment: m.attachment || null
  });
  State.messagesByConv.set(myConv, arr);
  scheduleClientTtl(m.id, m.deleteAt);
  if (State.current === myConv) {
    renderMessages({ forceScrollToBottom: true });
  } else if (m.senderId !== State.me.id) {
    const sender = senderUsername(m.senderId);
    toast(`new msg from ${sender}`);
  }
}
async function sendCurrentMessage() {
  const input = $('#message-input');
  const text = input.value.trim();
  if (!text && !State.pendingAttachment) return;
  if (State.current == null) return;
  const conv = State.current;
  const isGroup = conv.startsWith('g:');
  const id = parseInt(conv.slice(2), 10);
  let recipients;
  if (isGroup) {
    const g = State.groups.get(id);
    if (!g) return;
    recipients = g.members.map(m => ({ id: m.id, publicKeyObj: m.publicKeyObj }));
  } else {
    const peer = State.contacts.get(id);
    if (!peer) return;
    recipients = [
      { id: peer.id, publicKeyObj: peer.publicKeyObj },
      { id: State.me.id, publicKeyObj: State.publicKeyObj }
    ];
  }
  input.value = '';
  input.style.height = 'auto';
  const pendingAtt = State.pendingAttachment;
  if (pendingAtt) clearPendingAttachment();
  try {
    const messageText = text || '[attachment]';
    const ciphertexts = await PGP.encryptForEach(messageText, recipients);
    const deleteAt = State.composerTtl > 0
      ? Math.floor(Date.now()/1000) + State.composerTtl
      : null;
    let attachmentField = null;
    if (pendingAtt) {
      const keyCiphertexts = await PGP.wrapKeyForEach(pendingAtt.rawKey, recipients);
      attachmentField = {
        attachmentId: pendingAtt.attachmentId,
        keyCiphertexts
      };
    }
    State.socket.emit('send-message', { conv, ciphertexts, deleteAt, attachment: attachmentField }, async (ack) => {
      if (!ack?.ok) {
        toast(ack?.error || 'send failed', 'error');
        return;
      }
      if (ack.message) {
        await ingestIncomingMessage(ack.message);
      }
    });
  } catch (e) {
    toast('encryption failed: ' + e.message, 'error');
  }
}
function scheduleClientTtl(messageId, deleteAt) {
  if (!deleteAt) return;
  const ms = (deleteAt - Math.floor(Date.now()/1000)) * 1000;
  if (ms <= 0) {
    locallyRemoveMessage(messageId);
    return;
  }
  if (ms > 2_147_000_000) return; 
  const t = setTimeout(() => locallyRemoveMessage(messageId), ms);
  State.ttlTimers.set(messageId, t);
}
function locallyRemoveMessage(messageId) {
  for (const [conv, list] of State.messagesByConv.entries()) {
    const idx = list.findIndex(m => m.id === messageId);
    if (idx >= 0) {
      list.splice(idx, 1);
      if (State.current === conv) renderMessages();
    }
  }
  State.ttlTimers.delete(messageId);
}
setInterval(() => {
  if (State.current && State.messagesByConv.has(State.current)) {
    const list = State.messagesByConv.get(State.current);
    if (list.some(m => m.deleteAt)) renderMessages();
  }
}, 30_000);
function connectSocket() {
  State.socket = io({
    auth: { token: State.token },
    transports: ['polling', 'websocket'],
    upgrade: true,
    rememberUpgrade: false,
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 20000
  });
  State.socket.on('connect', () => {
    console.log('[socket] connected via', State.socket.io.engine.transport.name);
    if (State.current && State.messagesByConv.has(State.current)) {
      backfillCurrentConversation().catch(e => console.warn('[backfill] fail', e));
    }
  });
  State.socket.on('connect_error', (err) => {
    console.warn('[socket] connect_error:', err.message);
    if (err.message.includes('token')) hardLogout();
  });
  State.socket.on('disconnect', (reason) => {
    console.warn('[socket] disconnected:', reason);
  });
  State.socket.on('presence-list', (list) => {
    State.online = new Set(list);
    for (const u of State.contacts.values()) u.online = State.online.has(u.id);
    renderContacts();
  });
  State.socket.on('presence', ({ userId, online }) => {
    if (online) State.online.add(userId);
    else State.online.delete(userId);
    const c = State.contacts.get(userId);
    if (c) { c.online = online; renderContacts(); }
    if (online && !c) loadContacts();
  });
  State.socket.on('contact-request', (req) => {
    State.contactRequests.incoming.push(req);
    renderRequestsBadge();
    toast(`contact request from ${req.from.username}`);
  });
  State.socket.on('contact-added', async (u) => {
    if (State.contacts.has(u.id)) return;
    try {
      const publicKeyObj = await PGP.readPublicKey(u.publicKey);
      State.contacts.set(u.id, {
        id: u.id, username: u.username, publicKey: u.publicKey,
        publicKeyObj, online: State.online.has(u.id)
      });
      State.contactRequests.incoming = State.contactRequests.incoming.filter(r => r.from?.id !== u.id);
      State.contactRequests.outgoing = State.contactRequests.outgoing.filter(r => r.to?.id !== u.id);
      renderContacts();
      renderRequestsBadge();
      toast(`now in contacts · ${u.username}`);
    } catch (e) { console.warn('contact-added failed:', e); }
  });
  State.socket.on('contact-removed', ({ userId }) => {
    const stillBoundByGroup = [...State.groups.values()].some(g =>
      g.members.some(m => m.id === userId)
    );
    if (!stillBoundByGroup) {
      State.contacts.delete(userId);
      State.messagesByConv.delete(`u:${userId}`);
      if (State.current === `u:${userId}`) {
        State.current = null;
        renderChatHeader();
        renderMessages();
        $('#send-form').classList.add('hidden');
      }
    }
    renderContacts();
  });
  State.socket.on('group-deleted', ({ groupId }) => {
    State.groups.delete(groupId);
    State.messagesByConv.delete(`g:${groupId}`);
    if (State.current === `g:${groupId}`) {
      State.current = null;
      renderChatHeader();
      renderMessages();
      $('#send-form').classList.add('hidden');
    }
    renderGroups();
    toast('group deleted');
  });
  State.socket.on('messages-deleted-bulk', ({ messageIds, conv }) => {
    const idSet = new Set(messageIds);
    let myConv = conv;
    if (conv?.startsWith('u:')) {
      const otherId = parseInt(conv.slice(2), 10);
      if (otherId === State.me.id) {
        for (const [c, list] of State.messagesByConv.entries()) {
          State.messagesByConv.set(c, list.filter(m => !idSet.has(m.id)));
        }
        if (State.current) renderMessages();
        return;
      }
    }
    const list = State.messagesByConv.get(myConv);
    if (list) {
      State.messagesByConv.set(myConv, list.filter(m => !idSet.has(m.id)));
      if (State.current === myConv) renderMessages();
    }
  });
  State.socket.on('messages-hidden', ({ conv, messageIds }) => {
    const idSet = new Set(messageIds);
    const list = State.messagesByConv.get(conv);
    if (list) {
      State.messagesByConv.set(conv, list.filter(m => !idSet.has(m.id)));
      if (State.current === conv) renderMessages();
    }
  });
  State.socket.on('account-deleted', ({ userId }) => {
    State.contacts.delete(userId);
    State.messagesByConv.delete(`u:${userId}`);
    if (State.current === `u:${userId}`) {
      State.current = null;
      renderChatHeader();
      renderMessages();
      $('#send-form').classList.add('hidden');
    }
    for (const g of State.groups.values()) {
      g.members = g.members.filter(m => m.id !== userId);
    }
    renderContacts();
    renderGroups();
    if (State.current?.startsWith('g:')) renderChatHeader();
  });
  State.socket.on('group-created', async (g) => {
    if (State.groups.has(g.id)) return;
    const members = [];
    for (const m of g.members) {
      members.push({ ...m, publicKeyObj: await PGP.readPublicKey(m.publicKey) });
    }
    State.groups.set(g.id, { ...g, members });
    renderGroups();
    if (g.creatorId !== State.me.id) {
      toast(`added to group · ${g.name}`);
    }
  });
  State.socket.on('group-updated', async (g) => {
    const stillMember = g.members.some(m => m.id === State.me.id);
    if (!stillMember) {
      const wasOpen = State.current === `g:${g.id}`;
      State.groups.delete(g.id);
      State.messagesByConv.delete(`g:${g.id}`);
      renderGroups();
      if (wasOpen) {
        State.current = null;
        $('#chat-header').innerHTML = `
          <button class="header-back-btn" data-role="menu" title="open contacts">☰</button>
          <div class="empty-header">// removed from group</div>
        `;
        $('#messages').innerHTML = '<div class="placeholder"><span class="diamond">◈</span><p>you are no longer in this group.</p></div>';
        $('#send-form').classList.add('hidden');
      }
      toast(`removed from · ${g.name}`);
      return;
    }
    const members = [];
    for (const m of g.members) {
      const existing = State.groups.get(g.id)?.members.find(x => x.id === m.id);
      members.push({
        ...m,
        publicKeyObj: existing?.publicKeyObj || await PGP.readPublicKey(m.publicKey)
      });
    }
    State.groups.set(g.id, { ...g, members });
    renderGroups();
    if (State.current === `g:${g.id}`) {
      renderChatHeader();
    }
  });
  State.socket.on('new-message', async (m) => {
    await ingestIncomingMessage(m);
  });
  State.socket.on('message-deleted', ({ messageId, conv, expired }) => {
    locallyRemoveMessage(messageId);
    if (!expired && State.current && (
      conv === State.current ||
      true
    )) {
    }
  });
  State.socket.on('attachment-expired', ({ messageId, attachmentId }) => {
    const cached = attachmentCache.get(attachmentId);
    if (cached) {
      URL.revokeObjectURL(cached);
      attachmentCache.delete(attachmentId);
    }
    let touched = false;
    for (const list of State.messagesByConv.values()) {
      for (const m of list) {
        if (m.id === messageId && m.attachment) {
          m.attachment = {
            attachmentId: m.attachment.attachmentId,
            filename: m.attachment.filename,
            mime: m.attachment.mime,
            size: m.attachment.size,
            expired: true
          };
          touched = true;
        }
      }
    }
    if (touched) renderMessages();
  });
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
function formatTime(unix) {
  const d = new Date(unix * 1000);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) return d.toTimeString().slice(0, 5);
  return d.toLocaleDateString() + ' ' + d.toTimeString().slice(0, 5);
}
function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}
(function setupMobileViewport() {
  if (!window.visualViewport) return;
  function syncHeight() {
    if (window.innerWidth > 720) {
      document.documentElement.style.removeProperty('--mobile-vh');
      return;
    }
    document.documentElement.style.setProperty(
      '--mobile-vh',
      window.visualViewport.height + 'px'
    );
  }
  window.visualViewport.addEventListener('resize', syncHeight);
  window.visualViewport.addEventListener('scroll', syncHeight);
  window.addEventListener('resize', syncHeight);
  syncHeight();
})();
document.addEventListener('focusin', (e) => {
  if (e.target?.id !== 'message-input') return;
  if (window.innerWidth > 720) return;
  setTimeout(() => {
    e.target.scrollIntoView({ block: 'end', behavior: 'smooth' });
  }, 200);
});
(async () => { await tryResumeSession(); })();
undefined