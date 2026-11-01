const DEFAULT_AUDIT_LIMIT = 20;
const state = { apiBaseUrl: "", csrfToken: null, user: null, usersSerial: 0, ownDevicesSerial: 0, deviceSerial: 0, deviceAccountsSerial: 0, deviceAccounts: [], selectedDeviceAccount: null, auditCursors: [null], auditIndex: 0, auditSerial: 0, requestIds: new Map() };

const $ = (selector) => document.querySelector(selector);
const elements = {
  loginView: $("#login-view"), appView: $("#app-view"), loginForm: $("#login-form"), loginSubmit: $("#login-submit"),
  loginError: $("#login-error"), serviceState: $("#service-state"), notice: $("#notice"), signedInUser: $("#signed-in-user"),
  logout: $("#logout-button"), profileState: $("#profile-state"), profileContent: $("#profile-content"), networkList: $("#network-list"),
  usersState: $("#users-state"), usersContent: $("#users-content"), usersBody: $("#users-body"), auditState: $("#audit-state"),
  auditContent: $("#audit-content"), auditBody: $("#audit-body"), auditPrev: $("#audit-prev"), auditNext: $("#audit-next"), auditPageLabel: $("#audit-page-label"),
  ownDevicesState: $("#own-devices-state"), ownDevicesContent: $("#own-devices-content"), ownDevicesBody: $("#own-devices-body"), devicesState: $("#devices-state"), devicesContent: $("#devices-content"), devicesBody: $("#devices-body"), deviceLimit: $("#device-limit"), deviceAccountSelect: $("#device-account-select"), openAddDevice: $("#open-add-device"),
  userDialog: $("#user-dialog"), userForm: $("#user-form"), userFormError: $("#user-form-error"), managedUsername: $("#managed-username"),
  managedPassword: $("#managed-password"), editingUsername: $("#editing-username"), passwordHint: $("#password-hint"), userDialogTitle: $("#user-dialog-title"), saveUser: $("#save-user"),
  deviceDialog: $("#device-dialog"), deviceForm: $("#device-form"), deviceFormError: $("#device-form-error"), deviceAccountNote: $("#device-account-note"), registeredDeviceId: $("#registered-device-id"), saveDevice: $("#save-device")
};

function showNotice(message) { elements.notice.textContent = message; elements.notice.hidden = false; window.setTimeout(() => { elements.notice.hidden = true; }, 4500); }
function showError(element, message) { element.textContent = message; element.hidden = false; }
function clearError(element) { element.textContent = ""; element.hidden = true; }
function setPanel(element, kind, message) { element.className = `state-panel${kind ? ` ${kind}` : ""}`; element.textContent = message; element.hidden = false; }
function setBusy(button, busy, busyText) { if (!button.dataset.label) button.dataset.label = button.textContent; button.disabled = busy; button.textContent = busy ? busyText : button.dataset.label; }
function roleText(role) { return role === "admin" ? "管理员" : "普通用户"; }
function networkText(network) { return network === "home" ? "家庭" : "工作"; }
function deviceStateText(value) { return ({ registered: "已登记", removed: "已移除" })[value] || value; }
function humanError(error) {
  return error.message;
}
function isSessionError(error) { return error?.status === 401 && error?.code === "authentication_required"; }
function protocolError(name) { return new Error(`服务返回的${name}格式不正确。`); }
function expectArray(value, name) { if (!Array.isArray(value)) throw protocolError(name); return value; }
function statusBadge(value, type = "active") { const span = document.createElement("span"); span.className = `status ${type}`; span.textContent = value; return span; }
function apiUrl(path) { return `${state.apiBaseUrl}${path}`; }

async function loadConfig() {
  try {
    const response = await fetch("config.json", { cache: "no-store" });
    if (!response.ok) throw new Error("配置文件不可读取");
    const config = await response.json();
    if (typeof config.apiBaseUrl !== "string") throw new Error("apiBaseUrl 必须为字符串");
    // 空值代表同源 API；部署不需要也不应为了同源而填写伪造地址。
    if (config.apiBaseUrl) {
      const configuredUrl = new URL(config.apiBaseUrl, window.location.href);
      if (configuredUrl.protocol !== "https:") throw new Error("服务地址必须使用 HTTPS");
      if (configuredUrl.origin !== window.location.origin || configuredUrl.username || configuredUrl.password) throw new Error("当前部署只支持同源 HTTPS API，配置中不得包含凭据");
      if (configuredUrl.pathname !== "/" || configuredUrl.search || configuredUrl.hash) throw new Error("apiBaseUrl 只能是 API 主机的根 HTTPS 地址");
      state.apiBaseUrl = configuredUrl.origin;
    }
  } catch (error) {
    setServiceUnavailable("无法读取服务配置。请检查 config.json。");
    return false;
  }
  elements.serviceState.textContent = "正在检查服务状态…";
  try {
    await apiRequest("/health", { method: "GET" });
    elements.serviceState.textContent = "服务可用。请输入账户名和密码。";
    return true;
  } catch (error) {
    setServiceUnavailable(`无法连接管理服务：${error.message}`);
    return false;
  }
}

function setServiceUnavailable(message) { elements.serviceState.className = "service-state error"; elements.serviceState.textContent = message; elements.loginSubmit.disabled = true; }

async function apiRequest(path, options = {}) {
  const controller = new AbortController();
  const old = state.requestIds.get(path);
  if (old) old.abort();
  state.requestIds.set(path, controller);
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.mutation && state.csrfToken) headers.set("X-CSRF-Token", state.csrfToken);
  let response;
  try {
    response = await fetch(apiUrl(path), { method: options.method || "GET", credentials: "include", headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), signal: controller.signal });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error("网络请求失败，请检查服务地址和网络连接。");
  } finally { if (state.requestIds.get(path) === controller) state.requestIds.delete(path); }
  let body = null;
  try { body = await response.json(); } catch { /* 非 JSON 错误响应由下方统一处理。 */ }
  if (!response.ok) {
    const detail = body?.error;
    const error = new Error(detail?.message || `请求失败（HTTP ${response.status}）`);
    error.status = response.status; error.code = detail?.code; throw error;
  }
  return body;
}

function renderProfile(user) {
  state.user = user;
  $("#profile-username").textContent = user.username;
  $("#profile-role").textContent = roleText(user.role);
  const status = $("#profile-status"); status.replaceChildren(statusBadge(user.active ? "启用" : "已停用", user.active ? "active" : "inactive"));
  elements.networkList.replaceChildren(...user.networks.map((network) => { const tag = document.createElement("span"); tag.className = "network-tag"; tag.textContent = networkText(network); return tag; }));
  elements.signedInUser.textContent = `${user.username} · ${roleText(user.role)}`;
  document.querySelectorAll(".admin-only").forEach((item) => { item.hidden = user.role !== "admin"; });
  loadOwnDevices();
  elements.profileContent.hidden = false; elements.profileState.hidden = true;
}

function showLogin() {
  // 会话切换必须使仍在飞行的旧账户读取结果过期，避免其覆盖新账户页面。
  state.usersSerial += 1; state.ownDevicesSerial += 1; state.deviceSerial += 1; state.deviceAccountsSerial += 1; state.auditSerial += 1;
  state.deviceAccounts = []; state.selectedDeviceAccount = null; state.auditCursors = [null]; state.auditIndex = 0;
  state.requestIds.forEach((controller) => controller.abort()); state.requestIds.clear();
  state.user = null; state.csrfToken = null;
  if (elements.userDialog.open) elements.userDialog.close();
  if (elements.deviceDialog.open) elements.deviceDialog.close();
  elements.userForm.reset(); elements.deviceForm.reset();
  elements.appView.hidden = true; elements.loginView.hidden = false; elements.loginForm.reset(); clearError(elements.loginError); $("#username").focus();
}
function showApp(user) { elements.loginForm.reset(); renderProfile(user); elements.loginView.hidden = true; elements.appView.hidden = false; showPage("overview"); }

function acceptCurrentSession(response) {
  if (!response || typeof response.csrf_token !== "string") throw new Error("服务返回的会话信息不完整。");
  const { csrf_token: csrfToken, ...user } = response;
  state.csrfToken = csrfToken;
  showApp(user);
}

async function restoreSession() {
  try {
    // 仅 POST refresh 可轮换 CSRF；GET /me 是无副作用的只读资料接口。
    acceptCurrentSession(await apiRequest("/api/auth/refresh", { method: "POST" }));
  } catch (error) {
    showLogin();
    if (isSessionError(error)) {
      elements.serviceState.className = "service-state";
      elements.serviceState.textContent = "请输入账户名和密码。";
      return;
    }
    elements.serviceState.className = "service-state error";
    elements.serviceState.textContent = `无法恢复登录状态：${humanError(error)}`;
  }
}

async function submitLogin(event) {
  event.preventDefault(); clearError(elements.loginError);
  if (!elements.loginForm.reportValidity()) return;
  setBusy(elements.loginSubmit, true, "正在登录…");
  try {
    const response = await apiRequest("/api/auth/login", { method: "POST", body: { username: $("#username").value.trim(), password: $("#password").value } });
    if (!response?.user || typeof response.csrf_token !== "string") throw new Error("服务返回的登录信息不完整。");
    // 登录已提供新 CSRF；不再借由 GET 请求轮换它。
    state.csrfToken = response.csrf_token; showApp(response.user); showNotice("登录成功。");
  } catch (error) { showError(elements.loginError, humanError(error)); } finally { setBusy(elements.loginSubmit, false, ""); }
}

function showPage(page) {
  if (page !== "overview" && state.user?.role !== "admin") return;
  document.querySelectorAll(".page").forEach((item) => { item.hidden = item.id !== `${page}-page`; });
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
  $("#main-content").focus();
  if (page === "users") loadUsers(); if (page === "devices") loadDeviceAccounts(state.selectedDeviceAccount); if (page === "audit") loadAudit();
}

async function loadUsers() {
  elements.usersContent.hidden = true; setPanel(elements.usersState, "", "正在读取账户列表…");
  const serial = ++state.usersSerial;
  try { const users = expectArray(await apiRequest("/api/admin/users"), "账户列表"); if (serial !== state.usersSerial) return; renderUsers(users); elements.usersState.hidden = true; elements.usersContent.hidden = false; }
  catch (error) { if (serial === state.usersSerial && error.name !== "AbortError") { if (isSessionError(error)) return showLogin(); setPanel(elements.usersState, "error", `无法读取账户列表：${humanError(error)}`); } }
}
function renderUsers(users) {
  elements.usersBody.replaceChildren();
  if (!Array.isArray(users) || users.length === 0) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 5; cell.textContent = "没有账户记录。"; row.append(cell); elements.usersBody.append(row); return; }
  users.forEach((user) => { const row = document.createElement("tr"); const cells = [user.username, roleText(user.role), user.networks.map(networkText).join("、")]; cells.forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); }); const status = document.createElement("td"); status.append(statusBadge(user.active ? "启用" : "已停用", user.active ? "active" : "inactive")); row.append(status); const actions = document.createElement("td"); actions.className = "table-actions"; const devices = document.createElement("button"); devices.className = "link-button"; devices.type = "button"; devices.textContent = "设备"; devices.addEventListener("click", () => openDevicesFor(user.username)); actions.append(devices); const edit = document.createElement("button"); edit.className = "link-button"; edit.type = "button"; edit.textContent = "编辑"; edit.addEventListener("click", () => openUserDialog(user)); actions.append(edit); if (user.active) { const disable = document.createElement("button"); disable.className = "link-button"; disable.type = "button"; disable.textContent = "停用"; disable.addEventListener("click", () => deactivateUser(user, disable)); actions.append(disable); } row.append(actions); elements.usersBody.append(row); });
}

function openUserDialog(user = null) {
  elements.userForm.reset(); clearError(elements.userFormError); elements.editingUsername.value = user?.username || ""; elements.managedUsername.disabled = Boolean(user); elements.managedUsername.value = user?.username || ""; elements.managedPassword.required = !user; elements.passwordHint.textContent = user ? "（留空则不修改）" : "（至少 10 位）"; elements.userDialogTitle.textContent = user ? `编辑账户：${user.username}` : "新建账户"; elements.saveUser.dataset.label = user ? "保存修改" : "创建账户"; elements.saveUser.textContent = elements.saveUser.dataset.label; if (user) { document.querySelector(`input[name="managed-role"][value="${user.role}"]`).checked = true; $("#network-home").checked = user.networks.includes("home"); $("#network-work").checked = user.networks.includes("work"); }
  elements.userDialog.showModal(); elements.managedUsername.focus();
}
function selectedNetworks() { return ["home", "work"].filter((network) => $(`#network-${network}`).checked); }
async function submitUser(event) {
  event.preventDefault(); clearError(elements.userFormError); const isEdit = Boolean(elements.editingUsername.value); const networks = selectedNetworks();
  if (!elements.userForm.reportValidity()) return; if (networks.length === 0) { showError(elements.userFormError, "至少选择一个授权网络。"); return; }
  const role = document.querySelector("input[name='managed-role']:checked").value; const password = elements.managedPassword.value; const payload = { role, networks };
  if (password) payload.password = password;
  if (!isEdit) { payload.username = elements.managedUsername.value.trim(); if (!password) { showError(elements.userFormError, "新建账户必须设置密码。"); return; } }
  setBusy(elements.saveUser, true, isEdit ? "正在保存…" : "正在创建…");
  try { await apiRequest(isEdit ? `/api/admin/users/${encodeURIComponent(elements.editingUsername.value)}` : "/api/admin/users", { method: isEdit ? "PATCH" : "POST", body: payload, mutation: true }); elements.userDialog.close(); showNotice(isEdit ? "账户已更新。" : "账户已创建。"); await loadUsers(); }
  catch (error) { showError(elements.userFormError, humanError(error)); } finally { setBusy(elements.saveUser, false, ""); }
}
async function deactivateUser(user, button) {
  if (!window.confirm(`确定停用账户“${user.username}”吗？该操作将撤销其会话。`)) return;
  setBusy(button, true, "停用中…");
  try { await apiRequest(`/api/admin/users/${encodeURIComponent(user.username)}/deactivate`, { method: "POST", body: {}, mutation: true }); showNotice("账户已停用。"); await loadUsers(); }
  catch (error) { showNotice(`无法停用账户：${humanError(error)}`); } finally { setBusy(button, false, ""); }
}

async function loadOwnDevices() {
  elements.ownDevicesContent.hidden = true;
  setPanel(elements.ownDevicesState, "", "正在读取我的设备记录…");
  const serial = ++state.ownDevicesSerial;
  try {
    const devices = expectArray(await apiRequest("/api/devices"), "我的设备列表");
    if (serial !== state.ownDevicesSerial) return;
    renderOwnDevices(Array.isArray(devices) ? devices : []);
    elements.ownDevicesState.hidden = true;
    elements.ownDevicesContent.hidden = false;
  } catch (error) {
    if (serial !== state.ownDevicesSerial || error.name === "AbortError") return;
    if (isSessionError(error)) { showLogin(); return; }
    const message = error.code === "authentication_required"
      ? "登录已失效，请重新登录。"
      : `无法读取我的设备记录：${humanError(error)}`;
    setPanel(elements.ownDevicesState, "error", message);
  }
}
function renderOwnDevices(devices) {
  elements.ownDevicesBody.replaceChildren();
  if (devices.length === 0) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 3; cell.textContent = "没有设备登记记录。请联系管理员维护名单。"; row.append(cell); elements.ownDevicesBody.append(row); return; }
  devices.forEach((device) => { const row = document.createElement("tr"); const id = document.createElement("td"); id.textContent = device.device_id; row.append(id); const stateCell = document.createElement("td"); stateCell.append(statusBadge(deviceStateText(device.state), device.state === "registered" ? "active" : "inactive")); row.append(stateCell); const updated = document.createElement("td"); updated.textContent = deviceTime(device.updated_at); row.append(updated); elements.ownDevicesBody.append(row); });
}

function deviceLimitReached(devices) { return devices.filter((device) => device.state === "registered").length >= 10; }
function deviceTime(value) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN", { hour12: false }); }
async function loadDeviceAccounts(selectedAccount = state.selectedDeviceAccount) {
  elements.devicesContent.hidden = true;
  elements.deviceAccountSelect.disabled = true;
  elements.openAddDevice.disabled = true;
  setPanel(elements.devicesState, "", "正在读取可管理账户…");
  const serial = ++state.deviceAccountsSerial;
  try {
    const users = expectArray(await apiRequest("/api/admin/users"), "可管理账户列表");
    if (serial !== state.deviceAccountsSerial) return;
    state.deviceAccounts = users;
    elements.deviceAccountSelect.replaceChildren();
    state.deviceAccounts.forEach((user) => { const option = document.createElement("option"); option.value = user.username; option.textContent = `${user.username} · ${roleText(user.role)}`; elements.deviceAccountSelect.append(option); });
    elements.deviceAccountSelect.disabled = state.deviceAccounts.length === 0;
    if (state.deviceAccounts.length === 0) { setPanel(elements.devicesState, "empty", "没有可管理账户。"); elements.openAddDevice.disabled = true; return; }
    const account = selectedAccount && state.deviceAccounts.some((user) => user.username === selectedAccount) ? selectedAccount : (elements.deviceAccountSelect.value || state.user.username);
    state.selectedDeviceAccount = account;
    elements.deviceAccountSelect.value = account;
    await loadDevices(account);
  } catch (error) { if (serial !== state.deviceAccountsSerial || error.name === "AbortError") return; if (isSessionError(error)) return showLogin(); setPanel(elements.devicesState, "error", `无法读取可管理账户：${humanError(error)}`); }
}
function openDevicesFor(account) { state.selectedDeviceAccount = account; showPage("devices"); }
async function loadDevices(account = elements.deviceAccountSelect.value) {
  if (!account) return;
  elements.devicesContent.hidden = true;
  elements.openAddDevice.disabled = true;
  setPanel(elements.devicesState, "", "正在读取设备记录…");
  const serial = ++state.deviceSerial;
  try {
    const devices = expectArray(await apiRequest(`/api/admin/users/${encodeURIComponent(account)}/devices`), "设备列表");
    if (serial !== state.deviceSerial) return;
    renderDevices(Array.isArray(devices) ? devices : [], account);
    elements.devicesState.hidden = true;
    elements.devicesContent.hidden = false;
  } catch (error) { if (serial === state.deviceSerial && error.name !== "AbortError") { if (isSessionError(error)) return showLogin(); setPanel(elements.devicesState, "error", `无法读取设备记录：${humanError(error)}`); } }
}
function renderDevices(devices, account) {
  elements.devicesBody.replaceChildren();
  const limitReached = deviceLimitReached(devices);
  const registeredCount = devices.filter((device) => device.state === "registered").length;
  elements.deviceLimit.textContent = `已登记设备记录：${registeredCount}/10。已移除记录不计入上限。设备名单不构成账户密码登录或 VPN 准入控制。`;
  elements.openAddDevice.disabled = limitReached;
  elements.openAddDevice.title = limitReached ? "该账户已达到 10 条已登记设备记录上限。" : "";
  if (devices.length === 0) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 4; cell.textContent = "没有设备登记记录。"; row.append(cell); elements.devicesBody.append(row); }
  devices.forEach((device) => { const row = document.createElement("tr"); const id = document.createElement("td"); id.textContent = device.device_id; row.append(id); const stateCell = document.createElement("td"); stateCell.append(statusBadge(deviceStateText(device.state), device.state === "registered" ? "active" : "inactive")); row.append(stateCell); const updated = document.createElement("td"); updated.textContent = deviceTime(device.updated_at); row.append(updated); const actions = document.createElement("td"); actions.className = "table-actions"; if (device.state === "registered") { const remove = document.createElement("button"); remove.className = "link-button"; remove.type = "button"; remove.textContent = "移除记录"; remove.addEventListener("click", () => removeDevice(account, device, remove)); actions.append(remove); } else { actions.textContent = "—"; } row.append(actions); elements.devicesBody.append(row); });
}
function openDeviceDialog() {
  const account = elements.deviceAccountSelect.value;
  if (!account) return;
  elements.deviceForm.reset(); clearError(elements.deviceFormError);
  elements.deviceAccountNote.textContent = `账户：${account}。最多可保留 10 条已登记设备记录。`;
  elements.deviceDialog.showModal(); elements.registeredDeviceId.focus();
}
async function submitDeviceRegistration(event) {
  event.preventDefault(); clearError(elements.deviceFormError);
  if (!elements.deviceForm.reportValidity()) return;
  const account = elements.deviceAccountSelect.value;
  if (!account) return;
  setBusy(elements.saveDevice, true, "正在登记…");
  try {
    await apiRequest(`/api/admin/users/${encodeURIComponent(account)}/devices`, { method: "POST", body: { device_id: elements.registeredDeviceId.value.trim() }, mutation: true });
    elements.deviceDialog.close(); showNotice("设备登记记录已保存；该记录不验证或限制设备登录，也不表示 VPN 已可用。"); await loadDevices(account);
  } catch (error) { showError(elements.deviceFormError, humanError(error)); } finally { setBusy(elements.saveDevice, false, ""); }
}
async function removeDevice(account, device, button) {
  if (!window.confirm(`确定移除设备“${device.device_id}”的登记记录吗？这不会阻止持有账户密码的设备登录或连接 VPN。`)) return;
  setBusy(button, true, "移除中…");
  try { await apiRequest(`/api/admin/users/${encodeURIComponent(account)}/devices/${encodeURIComponent(device.device_id)}/remove`, { method: "POST", mutation: true }); showNotice("设备登记记录已移除；该操作不影响账户密码登录或 VPN 准入。"); await loadDevices(account); }
  catch (error) { showNotice(`无法移除设备记录：${humanError(error)}`); } finally { setBusy(button, false, ""); }
}

async function loadAudit() {
  elements.auditContent.hidden = true; setPanel(elements.auditState, "", "正在读取审计记录…"); const cursor = state.auditCursors[state.auditIndex];
  const serial = ++state.auditSerial;
  try { const page = await apiRequest(`/api/admin/audit?limit=${DEFAULT_AUDIT_LIMIT}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`); if (!Array.isArray(page?.items)) throw protocolError("审计记录"); if (serial !== state.auditSerial) return; renderAudit(page); elements.auditState.hidden = true; elements.auditContent.hidden = false; }
  catch (error) { if (serial === state.auditSerial) { if (isSessionError(error)) return showLogin(); setPanel(elements.auditState, "error", `无法读取审计记录：${humanError(error)}`); } }
}
function renderAudit(page) {
  elements.auditBody.replaceChildren(); const items = Array.isArray(page?.items) ? page.items : [];
  if (items.length === 0) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 5; cell.textContent = "没有符合条件的审计记录。"; row.append(cell); elements.auditBody.append(row); }
  items.forEach((item) => { const row = document.createElement("tr"); const date = new Date(item.occurred_at); const values = [Number.isNaN(date.valueOf()) ? item.occurred_at : date.toLocaleString("zh-CN", { hour12: false }), item.actor || "—", item.action]; values.forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); }); const outcomeCell = document.createElement("td"); const outcomeText = item.outcome === "success" ? "成功" : item.outcome === "failure" ? "失败" : "拒绝"; outcomeCell.append(statusBadge(outcomeText, item.outcome)); row.append(outcomeCell); const sourceCell = document.createElement("td"); sourceCell.textContent = item.source_ip || "—"; row.append(sourceCell); elements.auditBody.append(row); });
  const next = page?.next_cursor ?? null; if (next !== null) state.auditCursors[state.auditIndex + 1] = next; else state.auditCursors.length = state.auditIndex + 1;
  elements.auditPrev.disabled = state.auditIndex === 0; elements.auditNext.disabled = next === null; elements.auditPageLabel.textContent = `第 ${state.auditIndex + 1} 页`;
}

async function logout() {
  setBusy(elements.logout, true, "退出中…");
  try {
    await apiRequest("/api/auth/logout", { method: "POST", body: {}, mutation: true });
    showLogin();
  } catch (error) {
    if (isSessionError(error)) { showLogin(); return; }
    // 网络失败时不能假装会话已注销，用户可重试或等待服务恢复。
    showNotice(`退出请求未完成；当前会话状态未知：${humanError(error)}`);
  } finally { setBusy(elements.logout, false, ""); }
}

elements.loginForm.addEventListener("submit", submitLogin); elements.logout.addEventListener("click", logout); document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => showPage(item.dataset.page))); $("#open-create-user").addEventListener("click", () => openUserDialog()); $("#close-user-dialog").addEventListener("click", () => elements.userDialog.close()); $("#cancel-user").addEventListener("click", () => elements.userDialog.close()); elements.userForm.addEventListener("submit", submitUser); elements.openAddDevice.addEventListener("click", openDeviceDialog); $("#close-device-dialog").addEventListener("click", () => elements.deviceDialog.close()); $("#cancel-device").addEventListener("click", () => elements.deviceDialog.close()); elements.deviceForm.addEventListener("submit", submitDeviceRegistration); elements.deviceAccountSelect.addEventListener("change", () => { state.selectedDeviceAccount = elements.deviceAccountSelect.value; loadDevices(); }); elements.auditPrev.addEventListener("click", () => { if (state.auditIndex > 0) { state.auditIndex -= 1; loadAudit(); } }); elements.auditNext.addEventListener("click", () => { if (state.auditCursors[state.auditIndex + 1] != null) { state.auditIndex += 1; loadAudit(); } });

if (await loadConfig()) await restoreSession();
