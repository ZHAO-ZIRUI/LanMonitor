'use strict';

const $ = id => document.getElementById(id);
const hosts = new Map();
const cells = new Map();
const pendingChanges = new Map();
const prefix = '192.168.100.';
let revision = null;
let selected = null;
let serverOffset = 0;
let onlineWindow = 90;
let scanner = {};
let connected = false;
let actionBusy = false;
let noteEditorMac = null;
let noteDirty = false;
let toastTimer;
let returnFocus;
let settingsRevision = 0;
let settingsBusy = false;
let pollTimer;
let pollInFlight = false;
let fullPollRequired = null;
let serverInstance = null;
let instanceGeneration = {};
let requestSequence = 0n;
let lastScannerSequence = 0n;
const responseSequences = new WeakMap();
let historyConfirmation = null;
let settings = {
  scan_enabled: true, ping_enabled: true, probe_rate: 4, passive_interval: 12,
  name_lookup: true, name_interval: 12, arp_enabled: true,
  online_window: 90, dhcp_start: 5, dhcp_end: 99, refresh_interval: 2, show_hostnames: true,
  auto_cleanup_old_addresses: true,
};
const settingsInputs = [...$('settings-form').querySelectorAll('input[name], select[name]')];
const settingsButtons = [...$('settings-form').querySelectorAll('button')];

for (let n = 0; n <= 255; n++) {
  const host = { octet: n, ip: prefix + n, dhcp: n >= 5 && n <= 99, special: n === 0 ? '网络地址' : n === 255 ? '广播地址' : null };
  hosts.set(n, host);
  const button = document.createElement('button');
  button.className = 'ip-cell';
  button.dataset.octet = String(n);
  const number = document.createElement('span');
  number.className = 'cell-number';
  number.textContent = String(n);
  const hostname = document.createElement('span');
  hostname.className = 'cell-hostname';
  button.append(number, hostname);
  button.addEventListener('click', () => openDrawer(n));
  $('grid').append(button);
  cells.set(n, button);
}

function currentTime() { return Date.now() / 1000 + serverOffset; }
function applySettings(values, version = 0) {
  if (values && version >= settingsRevision) {
    settings = { ...settings, ...values };
    settingsRevision = version;
  }
  onlineWindow = settings.online_window;
  document.querySelector('.workspace').classList.toggle('hide-hostnames', !settings.show_hostnames);
  hosts.forEach(host => { host.dhcp = !host.special && host.octet >= settings.dhcp_start && host.octet <= settings.dhcp_end; });
  $('history-dhcp-range').textContent = `已保存范围 .${settings.dhcp_start}–.${settings.dhcp_end} 的设备记录与标记`;
}
function isOnline(host) {
  const age = currentTime() - host.last_seen;
  return !!host.last_seen && age >= 0 && age <= onlineWindow;
}
function statusOf(host) { return host.special ? 'special' : isOnline(host) ? 'online' : host.first_recorded ? 'seen' : 'unknown'; }
function statusText(host) { return host.special || (isOnline(host) ? '在线' : host.first_recorded ? '出现过 · 暂未确认在线' : '尚未观测到'); }
function timeText(timestamp) {
  if (!timestamp || !Number.isFinite(timestamp) || Math.abs(timestamp) > 8640000000000) return '—';
  return new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date(timestamp * 1000));
}
function relativeTime(timestamp) {
  if (!timestamp) return '';
  const seconds = Math.max(0, Math.floor(currentTime() - timestamp));
  if (seconds < 10) return '刚刚';
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

function drawCell(host) {
  const cell = cells.get(host.octet);
  const state = statusOf(host);
  cell.className = ['ip-cell', state, host.dhcp && 'dhcp', host.infrastructure && 'infrastructure', host.reserved && 'reserved', selected === host.octet && 'selected'].filter(Boolean).join(' ');
  const label = cell.querySelector('.cell-hostname');
  label.textContent = host.special || (host.note ? host.note.replace(/\s+/g, ' ') : host.hostname ? host.hostname.replace(/\.local\.?$/i, '') : '');
  label.classList.toggle('device-note', !!host.note);
  const flags = [!host.special && (host.dhcp ? 'DHCP 池内' : 'DHCP 池外'), host.infrastructure && '基础设施', host.reserved && '已预留'].filter(Boolean);
  const description = [host.ip, statusText(host), host.note, host.hostname, ...flags].filter(Boolean).join(' · ');
  cell.title = description;
  cell.setAttribute('aria-label', description);
  cell.setAttribute('aria-pressed', String(selected === host.octet));
}

function updateCounts() {
  const values = [...hosts.values()].filter(host => !host.special);
  $('count-online').textContent = values.filter(isOnline).length;
  $('count-seen').textContent = values.filter(host => host.first_recorded && !isOnline(host)).length;
  $('count-infra').textContent = values.filter(host => host.infrastructure).length;
  $('count-reserved').textContent = values.filter(host => host.reserved).length;
}

function updateConnection() {
  $('connection').className = 'connection ' + (connected ? 'connected' : 'error');
  $('connection').querySelector('span').textContent = !connected ? '连接中断' : !settings.scan_enabled ? '监测已暂停' : scanner.error ? '采集异常' : '实时监测';
  $('connection').title = connected ? scanner.error || '' : '暂时无法取得最新状态';
}

function renderAll() {
  hosts.forEach(drawCell);
  updateCounts();
  updateConnection();
  if (selected !== null) renderDrawer();
}

function detailRows(target, rows) {
  const fragment = document.createDocumentFragment();
  for (const [label, value, note] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value || '—';
    if (note) dd.className = 'note';
    fragment.append(dt, dd);
  }
  $(target).replaceChildren(fragment);
}

function renderDrawer() {
  const host = hosts.get(selected);
  $('drawer-ip').textContent = host.ip;
  $('drawer-status').textContent = statusText(host);
  $('drawer-status').className = 'status-badge ' + statusOf(host);
  $('drawer-hostname').textContent = host.hostname || (host.special ? '子网保留地址' : '主机名未知');
  const tags = [];
  function tag(text, kind = '') {
    const element = document.createElement('span');
    element.className = 'tag ' + kind;
    element.textContent = text;
    tags.push(element);
  }
  tag(host.dhcp ? 'DHCP 地址池' : host.special ? '特殊地址' : 'DHCP 池外', host.special ? 'special' : host.dhcp ? 'dhcp' : '');
  if (host.infrastructure) tag('基础设施', 'infra');
  if (host.reserved) tag('已预留', 'reserved');
  $('drawer-tags').replaceChildren(...tags);
  renderNoteEditor(host);
  detailRows('device-details', [
    ['MAC 地址', host.mac],
    ['名称来源', host.hostname_source, true],
    ['名称更新', timeText(host.hostname_updated_at)],
    ['地址范围', host.dhcp ? `.${settings.dhcp_start}–.${settings.dhcp_end} / DHCP 动态池` : host.special || '池外 / 分配方式待确认', true],
  ]);
  detailRows('observation-details', [
    ['首次记录', timeText(host.first_recorded)],
    ['首次确认在线', timeText(host.first_seen)],
    ['最后出现', host.last_seen ? `${timeText(host.last_seen)} · ${relativeTime(host.last_seen)}` : host.first_recorded ? '仅有历史缓存，尚未确认' : '—', !host.last_seen],
    ['出现依据', host.last_seen_source || host.cache_source, true],
    ['最后 Ping 成功', timeText(host.last_ping_success)],
    ['响应延迟', host.last_ping_ms !== null && host.last_ping_ms !== undefined ? `${host.last_ping_ms.toFixed(2)} ms` : '—'],
    ['最后 Ping 检查', timeText(host.last_checked)],
    ['检查结果', host.last_ping_ok === true ? '收到回应' : host.last_ping_ok === false ? '未收到回应' : '尚未检查', true],
  ]);
  $('drawer-operations').hidden = !!host.special;
  $('special-note').hidden = !host.special;
  $('infra-label').textContent = host.infrastructure ? '撤销基础设施标记' : '标记为基础设施';
  $('reserve-label').textContent = host.reserved ? '取消预留' : '预留此地址';
  $('infra-switch').classList.toggle('on', !!host.infrastructure);
  $('reserve-switch').classList.toggle('on', !!host.reserved);
  $('infra-action').setAttribute('aria-pressed', String(!!host.infrastructure));
  $('reserve-action').setAttribute('aria-pressed', String(!!host.reserved));
  for (const id of ['infra-action', 'reserve-action', 'delete-action']) $(id).disabled = actionBusy || !connected;
}

function openDrawer(octet) {
  returnFocus = document.activeElement;
  noteDirty = false;
  $('device-note-message').textContent = '';
  selected = octet;
  $('drawer').hidden = false;
  $('drawer-backdrop').hidden = false;
  $('grid').inert = true;
  renderAll();
  $('drawer-close').focus();
}

function closeDrawer() {
  selected = null;
  $('drawer').hidden = true;
  $('drawer-backdrop').hidden = true;
  $('grid').inert = false;
  hosts.forEach(drawCell);
  if (returnFocus) returnFocus.focus();
}

function renderNoteEditor(host) {
  $('device-note-section').hidden = !!host.special;
  if (!noteDirty) {
    noteEditorMac = host.mac || null;
    $('device-note-input').value = host.note || '';
  }
  const changedDevice = noteDirty && host.mac !== noteEditorMac;
  const canEdit = !!noteEditorMac && !host.special && !changedDevice && connected && !actionBusy;
  $('device-note-input').disabled = !canEdit;
  $('device-note-save').disabled = !canEdit || !noteDirty;
  $('device-note-clear').disabled = !canEdit || !host.note;
  $('device-note-cancel').disabled = actionBusy || !noteDirty;
  $('device-note-hint').textContent = changedDevice ? '该地址的 MAC 已变化，取消修改后可编辑当前设备的备注。' : noteEditorMac ? `关联 MAC ${noteEditorMac} · ${$('device-note-input').value.length}/200` : '尚未识别到 MAC，暂时无法添加设备备注。';
}

async function saveDeviceNote(value = $('device-note-input').value) {
  const host = hosts.get(selected);
  if (!host || actionBusy || !connected || !noteEditorMac || host.mac !== noteEditorMac) return;
  const octet = selected, mac = noteEditorMac;
  actionBusy = true;
  $('device-note-message').textContent = '正在保存…';
  $('device-note-message').classList.remove('error');
  renderDrawer();
  try {
    const data = await requestJSON(`/api/devices/${mac}/note`, 'PATCH', { note: value });
    mergeHosts(data.hosts, data.revision, true);
    if (selected === octet && noteEditorMac === mac) {
      noteDirty = false;
      $('device-note-message').textContent = data.note ? '备注已保存' : '备注已清除';
    }
    renderAll();
  } catch (error) {
    if (selected === octet && noteEditorMac === mac) {
      $('device-note-message').textContent = error.name === 'AbortError' ? '保存超时，请稍后重试' : error.message;
      $('device-note-message').classList.add('error');
    }
  } finally {
    actionBusy = false;
    if (selected !== null) renderDrawer();
  }
}

function toast(message, error = false) {
  clearTimeout(toastTimer);
  $('toast').textContent = message;
  $('toast').classList.toggle('error', error);
  $('toast').hidden = false;
  toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3500);
}

function setSettingsBusy(busy) {
  settingsBusy = busy;
  for (const control of settingsInputs) control.disabled = busy;
  for (const button of settingsButtons) button.disabled = busy;
  $('settings-close').disabled = busy;
  $('history-confirm-cancel').disabled = busy;
  $('history-confirm-clear').disabled = busy;
}

function fillSettingsForm(values) {
  for (const input of settingsInputs) {
    if (input.type === 'checkbox') input.checked = values[input.name];
    else input.value = values[input.name];
  }
}

// Every response belongs to one server lifetime. A delayed response from an
// earlier lifetime must never replace data after another request saw a restart.
function acceptInstance(data, generation, sequence, legacyMutation = false) {
  const instance = data.instance ?? data.scanner?.started_at;
  if (generation !== instanceGeneration && (instance === undefined || instance === null || instance !== serverInstance)) {
    const error = new Error('服务已重启，请重试');
    error.name = 'StaleResponseError';
    throw error;
  }
  if (instance === undefined || instance === null) {
    if (!legacyMutation || serverInstance === null) throw new Error('服务响应格式无效');
    // An older running backend may serve this newer static file. Keep revision
    // guards for its mutation result and confirm the lifetime with a full poll.
    fullPollRequired = {};
    return;
  }
  if (instance !== serverInstance) {
    serverInstance = instance;
    fullPollRequired = null;
    instanceGeneration = {};
    revision = null;
    settingsRevision = 0;
    pendingChanges.clear();
    scanner = { started_at: instance };
    lastScannerSequence = sequence;
  }
}

function applyScanner(data) {
  const sequence = responseSequences.get(data) || 0n;
  if (data.scanner && sequence >= lastScannerSequence) {
    scanner = data.scanner;
    lastScannerSequence = sequence;
  }
}

function mergeHosts(values, version, mutation = false) {
  if (revision !== null && version < revision) return false;
  for (const host of values) {
    if (version >= (pendingChanges.get(host.octet) || 0)) {
      hosts.set(host.octet, host);
      if (mutation) pendingChanges.set(host.octet, version);
      else pendingChanges.delete(host.octet);
    }
  }
  return true;
}

function schedulePoll() {
  clearTimeout(pollTimer);
  if (!pollInFlight) {
    const interval = settings.refresh_interval * 1000;
    pollTimer = setTimeout(poll, connected ? interval : Math.max(4000, interval));
  }
}

async function requestJSON(path, method = 'GET', values) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  const generation = instanceGeneration;
  const sequence = ++requestSequence;
  try {
    const response = await fetch(path, {
      method, signal: controller.signal, cache: 'no-store',
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-LanMonitor': '1' },
      body: values === undefined ? undefined : JSON.stringify(values),
    });
    // Keep the deadline active until the entire response body has arrived.
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || '请求失败');
    const legacyMutation = ((method === 'PATCH' || method === 'DELETE') && /^\/api\/hosts\/\d{1,3}$/.test(path))
      || (method === 'POST' && path === '/api/history/clear');
    acceptInstance(result, generation, sequence, legacyMutation);
    responseSequences.set(result, sequence);
    return result;
  } finally { clearTimeout(timeout); }
}

async function openSettings() {
  if (settingsBusy) return;
  if (selected !== null) closeDrawer();
  $('settings-modal').showModal();
  cancelHistoryConfirmation();
  fillSettingsForm(settings);
  $('settings-message').textContent = '正在读取设置…';
  $('settings-message').classList.remove('error');
  setSettingsBusy(true);
  try {
    const data = await requestJSON('/api/settings');
    applySettings(data.settings, data.settings_revision);
    applyScanner(data);
    fillSettingsForm(settings);
    $('settings-service-host').textContent = data.service.host;
    $('settings-service-port').textContent = data.service.port;
    $('settings-subnet').textContent = data.service.subnet;
    $('settings-message').textContent = '';
    renderAll();
  } catch (error) {
    $('settings-message').textContent = error.name === 'AbortError' ? '读取超时，请稍后重新打开设置' : error.message;
    $('settings-message').classList.add('error');
    $('settings-save').disabled = true;
  } finally {
    setSettingsBusy(false);
    if ($('settings-message').classList.contains('error')) {
      for (const id of ['settings-save', 'history-clear-dhcp', 'history-clear-all']) $(id).disabled = true;
    }
    $('settings-close').focus();
  }
}

function closeSettings() {
  if (settingsBusy || $('history-confirm').open) return;
  $('settings-modal').close();
  $('settings-open').focus();
}

async function saveSettings(event) {
  event.preventDefault();
  if (settingsBusy || !$('settings-form').reportValidity()) return;
  const values = Object.fromEntries(settingsInputs.map(input => [input.name, input.type === 'checkbox' ? input.checked : Number(input.value)]));
  setSettingsBusy(true);
  $('settings-message').textContent = '正在保存…';
  $('settings-message').classList.remove('error');
  try {
    const data = await requestJSON('/api/settings', 'PATCH', values);
    applySettings(data.settings, data.settings_revision);
    applyScanner(data);
    renderAll();
    schedulePoll();
    setSettingsBusy(false);
    closeSettings();
    toast('设置已保存');
  } catch (error) {
    $('settings-message').textContent = error.name === 'AbortError' ? '保存请求超时，请重新打开设置确认结果' : error.message;
    $('settings-message').classList.add('error');
  } finally { setSettingsBusy(false); }
}

function cancelHistoryConfirmation() {
  const scope = historyConfirmation?.scope;
  historyConfirmation = null;
  if ($('history-confirm').open) $('history-confirm').close();
  if (scope && !settingsBusy) $(scope === 'dhcp' ? 'history-clear-dhcp' : 'history-clear-all').focus();
}

function confirmHistoryScope(scope) {
  if (settingsBusy) return;
  historyConfirmation = scope === 'dhcp' ? { scope, dhcp_start: settings.dhcp_start, dhcp_end: settings.dhcp_end } : { scope };
  $('history-confirm-title').textContent = scope === 'dhcp' ? '清空 DHCP 历史？' : '重置全部设备记录？';
  const range = scope === 'dhcp' ? `.${settings.dhcp_start}–.${settings.dhcp_end} 范围内` : '全部地址';
  const notes = scope === 'dhcp' ? '设备备注保留。' : '全部设备备注也会清除。';
  $('history-confirm-description').textContent = `清除${range}的设备历史、主机名及地址标记。${notes}在线设备会在后续探测中重新记录。`;
  $('history-confirm-message').textContent = '';
  $('history-confirm-message').classList.remove('error');
  $('history-confirm').showModal();
  $('history-confirm-cancel').focus();
}

async function clearHistory() {
  if (settingsBusy || !historyConfirmation) return;
  const scope = historyConfirmation.scope;
  setSettingsBusy(true);
  $('history-confirm-clear').textContent = '正在清空…';
  $('history-confirm-message').textContent = '正在清空历史记录…';
  $('history-confirm-message').classList.remove('error');
  $('settings-message').textContent = '';
  $('settings-message').classList.remove('error');
  try {
    const data = await requestJSON('/api/history/clear', 'POST', historyConfirmation);
    if (mergeHosts(data.state.hosts, data.state.revision)) revision = data.state.revision;
    applySettings();
    renderAll();
    cancelHistoryConfirmation();
    $('settings-message').textContent = data.scope === 'dhcp' ? `已清空 .${data.range[0]}–.${data.range[1]} 的历史记录` : '全部历史记录已重置';
  } catch (error) {
    $('history-confirm-message').textContent = error.name === 'AbortError' ? '请求超时，请刷新后确认清空结果' : error.message;
    $('history-confirm-message').classList.add('error');
  } finally {
    setSettingsBusy(false);
    $('history-confirm-clear').textContent = '确认清空';
    if (!historyConfirmation) $(scope === 'dhcp' ? 'history-clear-dhcp' : 'history-clear-all').focus();
  }
}

async function mutate(method, values) {
  if (selected === null || actionBusy) return;
  const octet = selected;
  actionBusy = true;
  renderDrawer();
  try {
    const data = await requestJSON(`/api/hosts/${octet}`, method, values);
    mergeHosts([data.host], data.revision, true);
    // Do not advance the polling cursor: another host may have changed during this request.
    renderAll();
    toast(method === 'DELETE' ? '记录已删除，设备再次出现时会重新记录' : '标记已保存');
  } catch (error) { toast(error.name === 'AbortError' ? '操作超时，请刷新后确认结果' : error.message, true); }
  finally { actionBusy = false; if (selected !== null) renderDrawer(); }
}

async function poll() {
  if (pollInFlight) return;
  pollInFlight = true;
  clearTimeout(pollTimer);
  try {
    const fullPollToken = fullPollRequired;
    const requestedFull = revision === null || fullPollToken !== null;
    const query = requestedFull ? '' : `?since=${revision}&instance=${encodeURIComponent(serverInstance)}`;
    const state = await requestJSON('/api/state' + query);
    // A response captured before a mutation/clear cannot restore older data.
    if (!mergeHosts(state.hosts, state.revision)) {
      connected = true;
      updateConnection();
      return;
    }
    if (requestedFull && state.full && fullPollToken === fullPollRequired) fullPollRequired = null;
    serverOffset = state.now - Date.now() / 1000;
    applyScanner(state);
    applySettings(state.settings, state.settings_revision);
    revision = state.revision;
    connected = true;
    renderAll();
  } catch (error) {
    if (error.name !== 'StaleResponseError') {
      connected = false;
      renderAll();
    }
  } finally {
    pollInFlight = false;
    schedulePoll();
  }
}

$('settings-open').addEventListener('click', openSettings);
$('settings-close').addEventListener('click', closeSettings);
$('settings-cancel').addEventListener('click', closeSettings);
$('settings-form').addEventListener('submit', saveSettings);
$('history-clear-dhcp').addEventListener('click', () => confirmHistoryScope('dhcp'));
$('history-clear-all').addEventListener('click', () => confirmHistoryScope('all'));
$('history-confirm-cancel').addEventListener('click', () => { if (!settingsBusy) cancelHistoryConfirmation(); });
$('history-confirm-clear').addEventListener('click', clearHistory);
$('history-confirm').addEventListener('cancel', event => {
  event.preventDefault();
  if (!settingsBusy) cancelHistoryConfirmation();
});
$('history-confirm').addEventListener('click', event => {
  if (settingsBusy || event.target !== $('history-confirm')) return;
  const bounds = $('history-confirm').getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) cancelHistoryConfirmation();
});
$('settings-modal').addEventListener('cancel', event => { if (settingsBusy) event.preventDefault(); });
$('settings-modal').addEventListener('click', event => {
  if (event.target !== $('settings-modal')) return;
  const bounds = $('settings-modal').getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) closeSettings();
});
$('drawer-close').addEventListener('click', closeDrawer);
$('drawer-backdrop').addEventListener('click', closeDrawer);
$('device-note-input').addEventListener('input', () => {
  noteDirty = $('device-note-input').value !== (hosts.get(selected)?.note || '');
  $('device-note-message').textContent = '';
  renderNoteEditor(hosts.get(selected));
});
$('device-note-form').addEventListener('submit', event => { event.preventDefault(); saveDeviceNote(); });
$('device-note-clear').addEventListener('click', () => saveDeviceNote(''));
$('device-note-cancel').addEventListener('click', () => {
  noteDirty = false;
  $('device-note-message').textContent = '';
  renderDrawer();
});
$('infra-action').addEventListener('click', () => mutate('PATCH', { infrastructure: !hosts.get(selected).infrastructure }));
$('reserve-action').addEventListener('click', () => mutate('PATCH', { reserved: !hosts.get(selected).reserved }));
$('delete-action').addEventListener('click', () => mutate('DELETE'));
$('fullscreen').addEventListener('click', async () => {
  try {
    if (document.fullscreenElement) await document.exitFullscreen();
    else await document.documentElement.requestFullscreen();
  } catch (_) { toast('当前浏览器不支持全屏，可使用系统全屏快捷键'); }
});
document.addEventListener('fullscreenchange', () => {
  const label = document.fullscreenElement ? '退出全屏' : '进入全屏';
  $('fullscreen').setAttribute('aria-label', label);
  $('fullscreen').title = label;
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && selected !== null) {
    closeDrawer();
  } else if (event.key === 'Tab' && selected !== null) {
    const focusable = [...$('drawer').querySelectorAll('button:not(:disabled), textarea:not(:disabled)')].filter(control => control.offsetParent !== null);
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});
renderAll();
setInterval(renderAll, 1000);
poll();
