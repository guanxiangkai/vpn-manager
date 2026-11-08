const DEFAULT_AUDIT_LIMIT = 20;
const state = { apiBaseUrl: "", sessionTransport: "cookie", sessionToken: null, csrfToken: null, user: null, users: [], usersSerial: 0, auditCursors: [null], auditIndex: 0, auditSerial: 0, networks: [], networkNames: new Map(), networksSerial: 0, editingNetwork: null, userDialogSerial: 0, requestIds: new Map() };

const $ = (selector) => document.querySelector(selector);
const elements = {
  loginView: $("#login-view"), appView: $("#app-view"), loginForm: $("#login-form"), loginSubmit: $("#login-submit"),
  loginError: $("#login-error"), serviceState: $("#service-state"), notice: $("#notice"), signedInUser: $("#signed-in-user"),
  logout: $("#logout-button"), profileState: $("#profile-state"), profileContent: $("#profile-content"), networkList: $("#network-list"),
  usersState: $("#users-state"), usersContent: $("#users-content"), usersBody: $("#users-body"), auditState: $("#audit-state"),
  auditContent: $("#audit-content"), auditBody: $("#audit-body"), auditPrev: $("#audit-prev"), auditNext: $("#audit-next"), auditPageLabel: $("#audit-page-label"),
  userDialog: $("#user-dialog"), userForm: $("#user-form"), userFormError: $("#user-form-error"), managedUsername: $("#managed-username"),
  managedPassword: $("#managed-password"), editingUsername: $("#editing-username"), passwordHint: $("#password-hint"), userDialogTitle: $("#user-dialog-title"), saveUser: $("#save-user")
};

function showNotice(message) { elements.notice.textContent = message; elements.notice.hidden = false; window.setTimeout(() => { elements.notice.hidden = true; }, 4500); }
function showError(element, message) { element.textContent = message; element.hidden = false; }
function clearError(element) { element.textContent = ""; element.hidden = true; }
function setPanel(element, kind, message) { element.className = `state-panel${kind ? ` ${kind}` : ""}`; element.textContent = message; element.hidden = false; }
function setBusy(button, busy, busyText) { if (!button.dataset.label) button.dataset.label = button.textContent; button.disabled = busy; button.textContent = busy ? busyText : button.dataset.label; }
function roleText(role, protectedAccount = false) { return protectedAccount ? "超级管理员" : role === "admin" ? "管理员" : "普通用户"; }
function networkInfo(network) { return state.networkNames.get(network); }
function networkText(network) { return networkInfo(network)?.name || network; }
function networkIcon(network) { return ["home", "work"].includes(network) ? network : "network"; }
function humanError(error) {
  return error.message;
}
function isSessionError(error) { return error?.status === 401 && error?.code === "authentication_required"; }
function protocolError(name) { return new Error(`服务返回的${name}格式不正确。`); }
function expectArray(value, name) { if (!Array.isArray(value)) throw protocolError(name); return value; }
function statusBadge(value, type = "active") { const span = document.createElement("span"); span.className = `status ${type}`; span.textContent = value; return span; }
function apiUrl(path) { return `${state.apiBaseUrl}${path}`; }

// 页面中的动态资料只通过 textContent 写入；图标引用来自本地固定符号集。
function textElement(tag, text, className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(svg.namespaceURI, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}
function emptyRow(body, columns, title, detail = "") {
  const row = document.createElement("tr");
  const cell = textElement("td", "", "empty-cell");
  cell.colSpan = columns;
  cell.append(textElement("strong", title));
  if (detail) cell.append(textElement("span", detail));
  row.append(cell);
  body.append(row);
}
function networkTag(network) {
  const tag = textElement("span", "", `network-tag ${networkIcon(network)}`);
  tag.append(icon(networkIcon(network)), document.createTextNode(networkText(network)));
  return tag;
}

async function loadConfig() {
  try {
    const response = await fetch("config.json", { cache: "no-store" });
    if (!response.ok) throw new Error("配置文件不可读取");
    const config = await response.json();
    if (typeof config.apiBaseUrl !== "string") throw new Error("apiBaseUrl 必须为字符串");
    const transport = config.sessionTransport ?? "cookie";
    if (!["cookie", "bearer"].includes(transport)) throw new Error("会话传输方式无效");
    // 空值代表同源 API；部署不需要也不应为了同源而填写伪造地址。
    if (config.apiBaseUrl) {
      const configuredUrl = new URL(config.apiBaseUrl, window.location.href);
      if (configuredUrl.protocol !== "https:") throw new Error("服务地址必须使用 HTTPS");
      if (configuredUrl.username || configuredUrl.password) throw new Error("配置中不得包含凭据");
      if (configuredUrl.origin !== window.location.origin && transport !== "bearer") throw new Error("跨站 API 必须使用内存会话");
      if (configuredUrl.pathname !== "/" || configuredUrl.search || configuredUrl.hash) throw new Error("apiBaseUrl 只能是 API 主机的根 HTTPS 地址");
      state.apiBaseUrl = configuredUrl.origin;
    }
    state.sessionTransport = transport;
  } catch (error) {
    setServiceUnavailable("无法读取服务配置。请检查 config.json。");
    return false;
  }
  elements.serviceState.textContent = "正在检查服务状态…";
  try {
    await apiRequest("/health", { method: "GET" });
    elements.serviceState.textContent = transportHint();
    return true;
  } catch (error) {
    setServiceUnavailable(`无法连接管理服务：${error.message}`);
    return false;
  }
}

function setServiceUnavailable(message) { elements.serviceState.className = "service-state error"; elements.serviceState.textContent = message; elements.loginSubmit.disabled = true; }
function transportHint() { return state.sessionTransport === "bearer" ? "服务可用。请输入账户名和密码；刷新或关闭页面后需重新登录。" : "服务可用。请输入账户名和密码。"; }

async function apiRequest(path, options = {}) {
  const controller = new AbortController();
  const old = state.requestIds.get(path);
  if (old) old.abort();
  state.requestIds.set(path, controller);
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.mutation && state.csrfToken) headers.set("X-CSRF-Token", state.csrfToken);
  if (state.sessionTransport === "bearer" && state.sessionToken) headers.set("Authorization", `Bearer ${state.sessionToken}`);
  let response;
  try {
    response = await fetch(apiUrl(path), { method: options.method || "GET", credentials: state.sessionTransport === "bearer" ? "omit" : "include", cache: "no-store", redirect: "error", headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), signal: controller.signal });
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
  $("#profile-role").textContent = roleText(user.role, user.protected);
  const status = $("#profile-status"); status.replaceChildren(statusBadge(user.active ? "启用" : "已停用", user.active ? "active" : "inactive"));
  $("#network-count").textContent = `${user.networks.length} 个网络`;
  renderAuthorizedNetworks(user);
  loadNetworkMetadata(user);
  $("#user-avatar").textContent = user.username.slice(0, 1).toUpperCase();
  elements.signedInUser.replaceChildren(document.createTextNode(user.username), textElement("small", roleText(user.role, user.protected)));
  document.querySelectorAll(".admin-only").forEach((item) => { item.hidden = user.role !== "admin"; });
  loadVpnStatus(user);
  elements.profileContent.hidden = false; elements.profileState.hidden = true;
}

function renderAuthorizedNetworks(user) {
  elements.networkList.replaceChildren(...user.networks.map((network) => {
    const card = textElement("article", "", "network-card");
    const main = textElement("div", "", "network-card-main");
    const image = textElement("span", "", `network-icon ${networkIcon(network)}`);
    image.append(icon(networkIcon(network)));
    const copy = textElement("div", "", "network-card-copy");
    copy.append(textElement("h3", networkText(network)), textElement("p", networkInfo(network)?.description || "此账户已获授权的网络"));
    main.append(image, copy, statusBadge("已授权"));
    const footer = textElement("div", "", "network-card-footer");
    footer.append(textElement("span", "权限已分配 · 连接状态以系统为准"), icon("shield"));
    card.append(main, footer);
    return card;
  }));
  if (user.networks.length === 0) elements.networkList.append(textElement("p", "当前没有已授权网络，请联系管理员。", "state-panel"));
}

function rememberNetworks(networks) {
  networks.forEach((network) => {
    const current = state.networkNames.get(network.id);
    if (!current || network.version >= current.version) state.networkNames.set(network.id, network);
  });
  if (state.users.length) renderUsers();
}

async function loadNetworkMetadata(user) {
  try {
    const networks = expectArray(await apiRequest("/api/networks"), "网络资料");
    if (state.user !== user) return;
    rememberNetworks(networks); renderAuthorizedNetworks(user);
  } catch (error) {
    if (state.user !== user || error.name === "AbortError") return;
    if (isSessionError(error)) { showLogin(); return; }
    // 名称读取失败时保留 API 已授权的稳定标识，不猜测其他网络名称。
    elements.networkList.append(textElement("p", "网络名称暂时读取失败，可刷新页面重试；授权标识如上所示。", "context-note"));
  }
}

async function loadVpnStatus(user) {
  const panel = $("#vpn-integration-state");
  panel.parentElement.classList.remove("applied");
  panel.textContent = "正在核对 VPN 接入状态…";
  try {
    const result = await apiRequest("/api/vpn/status");
    if (state.user !== user) return;
    panel.parentElement.classList.toggle("applied", result.state === "applied");
    panel.textContent = result.state === "applied" ? "VPN 账户权限已同步；连接状态请以系统 VPN 设置为准。" : "VPN 账户权限尚未同步完成，请继续使用现有连接方式。";
  } catch (error) {
    if (state.user !== user || error.name === "AbortError") return;
    if (isSessionError(error)) { showLogin(); return; }
    panel.textContent = error.code === "gateway_unavailable" ? "VPN 接入尚未切换：此处显示账户授权，现有 VPN 继续使用原方式；当前无法通过本页面撤销原 VPN 连接。" : "暂时无法核对 VPN 接入状态，请勿将账户资料视为连接已生效。";
  }
}

function showLogin() {
  document.title = "登录 · VPN 管理器";
  // 会话切换必须使仍在飞行的旧账户读取结果过期，避免其覆盖新账户页面。
  state.usersSerial += 1; state.auditSerial += 1; state.networksSerial += 1; state.userDialogSerial += 1;
  state.users = []; state.auditCursors = [null]; state.auditIndex = 0;
  $("#user-search").value = ""; $("#user-status-filter").value = "all";
  state.networks = []; state.networkNames.clear(); state.editingNetwork = null; $("#network-search").value = "";
  state.requestIds.forEach((controller) => controller.abort()); state.requestIds.clear();
  state.user = null; state.csrfToken = null; state.sessionToken = null;
  if (elements.userDialog.open) elements.userDialog.close();
  if ($("#network-dialog").open) $("#network-dialog").close();
  elements.userForm.reset();
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
  // OSS 与 API 跨站时不依赖第三方 Cookie，也不从磁盘恢复会话。
  if (state.sessionTransport === "bearer") { showLogin(); return; }
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
    if (state.sessionTransport === "bearer") {
      if (typeof response.session_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(response.session_token)) throw new Error("服务未启用跨站会话，请联系管理员。");
      state.sessionToken = response.session_token;
    }
    // 登录已提供新 CSRF；不再借由 GET 请求轮换它。
    state.csrfToken = response.csrf_token; showApp(response.user); showNotice("登录成功。");
  } catch (error) { showError(elements.loginError, humanError(error)); } finally { setBusy(elements.loginSubmit, false, ""); }
}

function showPage(page) {
  if (page !== "overview" && state.user?.role !== "admin") return;
  document.querySelectorAll(".page").forEach((item) => { item.hidden = item.id !== `${page}-page`; });
  document.querySelectorAll(".nav-item").forEach((item) => {
    const current = item.dataset.page === page;
    item.classList.toggle("active", current);
    if (current) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current");
  });
  const title = ({ overview: "访问概览", networks: "网络环境", users: "账户与授权", audit: "登录审计" })[page];
  $("#current-page-name").textContent = title;
  document.title = `${title} · VPN 管理器`;
  $("#main-content").focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "instant" });
  if (page === "users") loadUsers(); if (page === "audit") loadAudit();
  if (page === "networks") loadNetworks();
}

async function readNetworkCatalog() {
  const user = state.user;
  const networks = expectArray(await apiRequest("/api/admin/networks"), "网络目录");
  if (state.user !== user) throw new DOMException("会话已切换", "AbortError");
  state.networks = networks; rememberNetworks(networks);
  return networks;
}

async function loadNetworks() {
  const serial = ++state.networksSerial;
  $("#networks-content").hidden = true; $("#network-search").disabled = true;
  $("#networks-total").textContent = "—"; $("#networks-result-count").textContent = "";
  setPanel($("#networks-state"), "", "正在读取网络目录…");
  try {
    await readNetworkCatalog();
    if (serial !== state.networksSerial) return;
    renderNetworks(); $("#networks-state").hidden = true; $("#networks-content").hidden = false; $("#network-search").disabled = false;
    if (state.user) renderAuthorizedNetworks(state.user);
  } catch (error) {
    if (serial !== state.networksSerial || error.name === "AbortError") return;
    if (isSessionError(error)) { showLogin(); return; }
    setPanel($("#networks-state"), "error", `无法读取网络目录：${humanError(error)} 请点击右上角刷新重试。`);
  }
}

function renderNetworks() {
  const query = $("#network-search").value.trim().toLocaleLowerCase();
  const networks = state.networks.filter((network) => `${network.name} ${network.description}`.toLocaleLowerCase().includes(query));
  const body = $("#networks-body"); body.replaceChildren();
  $("#networks-total").textContent = String(state.networks.length);
  $("#networks-result-count").textContent = `显示 ${networks.length} / ${state.networks.length} 个网络`;
  if (networks.length === 0) emptyRow(body, 4, query ? "没有匹配的网络" : "暂无网络", query ? "试试其他名称或说明。" : "通过右上角新增网络草稿。");
  networks.forEach((network) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    identity.append(textElement("strong", network.name, "network-name"), textElement("span", network.description || "暂无说明", "network-description"));
    const status = document.createElement("td"); status.append(statusBadge(network.state === "draft" ? "草稿 · 待接通" : "现有网络", network.state === "draft" ? "inactive" : "active"));
    const date = new Date(network.updated_at);
    const updated = textElement("td", Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString("zh-CN", { hour12: false }), "network-updated");
    const actions = textElement("td", "", "table-actions"); const edit = textElement("button", "编辑", "link-button"); edit.type = "button";
    edit.setAttribute("aria-label", `编辑网络 ${network.name}`); edit.addEventListener("click", () => openNetworkDialog(network)); actions.append(edit);
    row.append(identity, status, updated, actions); body.append(row);
  });
}

function openNetworkDialog(network = null) {
  state.editingNetwork = network;
  $("#network-form").reset(); clearError($("#network-form-error"));
  $("#network-dialog-title").textContent = network ? "编辑网络资料" : "新增网络";
  $("#network-name").value = network?.name || ""; $("#network-description").value = network?.description || "";
  $("#network-form-note").textContent = network ? "名称与说明修改后会同步显示在授权页面，不改变现有 VPN 或账户权限。" : "新增网络先保存为草稿，不改变现有 VPN 或账户权限。";
  const save = $("#save-network"); save.dataset.label = network ? "保存修改" : "保存草稿"; save.textContent = save.dataset.label; save.disabled = false;
  $("#network-dialog").showModal(); $("#network-name").focus();
}

async function submitNetwork(event) {
  event.preventDefault(); clearError($("#network-form-error"));
  if (!$("#network-form").reportValidity()) return;
  const name = $("#network-name").value.trim();
  if (!name) { showError($("#network-form-error"), "请输入网络名称。"); return; }
  const network = state.editingNetwork;
  const payload = { name, description: $("#network-description").value.trim() };
  if (network) payload.version = network.version;
  setBusy($("#save-network"), true, "正在保存…");
  try {
    const saved = await apiRequest(network ? `/api/admin/networks/${encodeURIComponent(network.id)}` : "/api/admin/networks", { method: network ? "PATCH" : "POST", body: payload, mutation: true });
    rememberNetworks([saved]); $("#network-dialog").close();
    showNotice(network ? "网络资料已更新，原有权限保持不变。" : "网络草稿已保存，完成接通验证后才能授权。");
    await loadNetworks();
  } catch (error) {
    if (isSessionError(error)) { showLogin(); return; }
    if (error.name !== "AbortError") showError($("#network-form-error"), humanError(error));
  } finally { setBusy($("#save-network"), false, ""); }
}

async function loadUsers() {
  elements.usersContent.hidden = true; setPanel(elements.usersState, "", "正在读取账户列表…");
  state.users = [];
  $("#users-total").textContent = "—";
  $("#users-summary").textContent = "";
  $("#users-result-count").textContent = "";
  $("#user-search").disabled = true;
  $("#user-status-filter").disabled = true;
  const serial = ++state.usersSerial;
  try {
    const users = expectArray(await apiRequest("/api/admin/users"), "账户列表");
    if (serial !== state.usersSerial) return;
    state.users = users;
    $("#user-search").disabled = false;
    $("#user-status-filter").disabled = false;
    renderUsers();
    elements.usersState.hidden = true; elements.usersContent.hidden = false;
  }
  catch (error) { if (serial === state.usersSerial && error.name !== "AbortError") { if (isSessionError(error)) return showLogin(); setPanel(elements.usersState, "error", `无法读取账户列表：${humanError(error)}`); } }
}
function renderUsers() {
  const query = $("#user-search").value.trim().toLowerCase();
  const filter = $("#user-status-filter").value;
  const users = state.users.filter((user) => user.username.toLowerCase().includes(query) && (filter === "all" || user.active === (filter === "active")));
  $("#users-total").textContent = state.users.length;
  $("#users-summary").textContent = `启用 ${state.users.filter((user) => user.active).length} · 管理员 ${state.users.filter((user) => user.role === "admin").length}`;
  $("#users-result-count").textContent = `显示 ${users.length} 个账户，共 ${state.users.length} 个`;
  elements.usersBody.replaceChildren();
  if (users.length === 0) {
    emptyRow(elements.usersBody, 5, state.users.length ? "没有匹配的账户" : "暂无账户记录", state.users.length ? "试试其他账户名，或切换账户状态。" : "新建账户后，可为其分配角色与网络权限。");
    return;
  }
  users.forEach((user) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    const name = textElement("div", "", "account-cell");
    const avatar = textElement("span", user.username.slice(0, 1).toUpperCase(), "avatar");
    avatar.setAttribute("aria-hidden", "true");
    name.append(avatar, document.createTextNode(user.username)); identity.append(name);
    const role = document.createElement("td");
    const roleLabel = textElement("span", "", `role-label ${user.role === "admin" ? "admin" : ""}`);
    if (user.role === "admin") roleLabel.append(icon("shield"));
    roleLabel.append(document.createTextNode(roleText(user.role, user.protected))); role.append(roleLabel);
    const networks = document.createElement("td");
    const tags = textElement("div", "", "permission-tags");
    tags.append(...user.networks.map(networkTag)); networks.append(tags);
    const status = document.createElement("td");
    status.append(statusBadge(user.active ? "启用" : "已停用", user.active ? "active" : "inactive"));
    const actions = textElement("td", "", "table-actions");
    const edit = textElement("button", "编辑", "link-button");
    edit.type = "button"; edit.setAttribute("aria-label", `编辑账户 ${user.username}`);
    edit.addEventListener("click", () => openUserDialog(user));
    const grant = textElement("button", "网络授权", "link-button");
    grant.type = "button"; grant.setAttribute("aria-label", `修改 ${user.username} 的网络授权`);
    grant.addEventListener("click", () => openUserDialog(user, true));
    actions.append(edit, grant);
    if (user.active) {
      const disable = textElement("button", "停用", "link-button danger");
      disable.type = "button"; disable.setAttribute("aria-label", `停用账户 ${user.username}`);
      disable.disabled = Boolean(user.protected);
      if (user.protected) disable.title = "系统管理员不能停用";
      disable.addEventListener("click", () => deactivateUser(user, disable)); actions.append(disable);
    }
    row.append(identity, role, networks, status, actions); elements.usersBody.append(row);
  });
}

async function openUserDialog(user = null, focusNetworks = false) {
  const serial = ++state.userDialogSerial;
  elements.userForm.reset(); clearError(elements.userFormError);
  elements.editingUsername.value = user?.username || ""; elements.managedUsername.disabled = Boolean(user); elements.managedUsername.value = user?.username || "";
  elements.managedPassword.required = !user; elements.passwordHint.textContent = user ? "（留空则不修改）" : "（至少 10 位）";
  elements.userDialogTitle.textContent = user ? `编辑账户：${user.username}` : "新建账户";
  elements.saveUser.dataset.label = user ? "保存修改" : "创建账户"; elements.saveUser.textContent = elements.saveUser.dataset.label;
  if (user) document.querySelector(`input[name="managed-role"][value="${user.role}"]`).checked = true;
  document.querySelectorAll("input[name='managed-role']").forEach((input) => { input.disabled = Boolean(user?.protected); });
  $("#protected-account-note").hidden = !user?.protected;
  $("#network-choices").replaceChildren(textElement("p", "正在读取可授权网络…", "muted")); elements.saveUser.disabled = true;
  elements.userDialog.showModal();
  (user ? elements.managedPassword : elements.managedUsername).focus();
  try {
    const networks = await readNetworkCatalog();
    if (!elements.userDialog.open || serial !== state.userDialogSerial) return;
    $("#network-choices").replaceChildren(...networks.filter((network) => network.state === "existing").map((network) => {
      const label = textElement("label", "", "choice"); const input = document.createElement("input"); input.type = "checkbox"; input.value = network.id;
      input.checked = user?.networks.includes(network.id) || false;
      label.append(input, icon(networkIcon(network.id)), textElement("span", network.name)); return label;
    }));
    syncNetworkChoices(); elements.saveUser.disabled = false;
    if (focusNetworks) $("#network-choices input:not(:disabled)")?.focus();
  } catch (error) {
    if (isSessionError(error)) { showLogin(); return; }
    if (serial === state.userDialogSerial && error.name !== "AbortError" && elements.userDialog.open) showError(elements.userFormError, `无法读取可授权网络，请关闭后重试：${humanError(error)}`);
  }
}
function syncNetworkChoices() {
  const member = document.querySelector("input[name='managed-role']:checked").value === "user";
  $("#network-choices").querySelectorAll("input").forEach((input) => {
    input.disabled = member;
    if (member) input.checked = input.value === "work";
  });
  $("#network-choices-hint").textContent = member ? `普通用户仅可授权「${networkText("work")}」；草稿不能授权。` : "仅分配该账户需要访问的网络，草稿不能授权。";
}
function selectedNetworks() { return [...$("#network-choices").querySelectorAll("input:checked")].map((input) => input.value); }
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
  if (user.protected) return;
  if (!window.confirm(`确定停用账户“${user.username}”吗？该操作将撤销其会话。`)) return;
  setBusy(button, true, "停用中…");
  try { await apiRequest(`/api/admin/users/${encodeURIComponent(user.username)}/deactivate`, { method: "POST", body: {}, mutation: true }); showNotice("账户已停用。"); await loadUsers(); }
  catch (error) { showNotice(`无法停用账户：${humanError(error)}`); } finally { setBusy(button, false, ""); }
}

async function loadAudit() {
  elements.auditContent.hidden = true; setPanel(elements.auditState, "", "正在读取审计记录…"); const cursor = state.auditCursors[state.auditIndex];
  const serial = ++state.auditSerial;
  try { const page = await apiRequest(`/api/admin/audit?limit=${DEFAULT_AUDIT_LIMIT}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`); if (!Array.isArray(page?.items)) throw protocolError("审计记录"); if (serial !== state.auditSerial) return; renderAudit(page); elements.auditState.hidden = true; elements.auditContent.hidden = false; }
  catch (error) { if (serial === state.auditSerial) { if (isSessionError(error)) return showLogin(); setPanel(elements.auditState, "error", `无法读取审计记录：${humanError(error)}`); } }
}
function renderAudit(page) {
  elements.auditBody.replaceChildren(); const items = Array.isArray(page?.items) ? page.items : [];
  if (items.length === 0) emptyRow(elements.auditBody, 5, "暂无审计记录", "登录和管理操作的记录会显示在这里。");
  // 保留服务端动作值作为提示，未知动作仍显示原值，避免丢失审计含义。
  const actionLabels = { login: "账户登录", logout: "退出登录", login_rate_limited: "登录频率限制", admin_access: "管理操作鉴权", user_create: "创建账户", user_update: "更新账户", user_deactivate: "停用账户", device_record_add: "登记设备", device_record_remove: "移除设备记录", gateway_sync_queued: "权限同步排队", gateway_sync_retry: "重试权限同步", gateway_sync_applied: "权限同步完成", gateway_sync_failed: "权限同步失败", authentication_schema_upgrade: "认证数据升级", gateway_schema_upgrade: "网关数据升级", user_network_policy_upgrade: "网络授权规则升级", network_catalog_upgrade: "网络目录升级", network_create: "新增网络草稿", network_update: "修改网络资料" };
  items.forEach((item) => {
    const row = document.createElement("tr");
    const date = new Date(item.occurred_at);
    const time = textElement("td", Number.isNaN(date.valueOf()) ? item.occurred_at : date.toLocaleString("zh-CN", { hour12: false }));
    const actor = textElement("td", item.actor || "—");
    const action = textElement("td", actionLabels[item.action] || item.action);
    action.title = item.action;
    if (item.target && item.target !== item.actor) action.append(textElement("small", item.target, "audit-target"));
    const outcome = document.createElement("td");
    const outcomeText = item.outcome === "success" ? "成功" : item.outcome === "failure" ? "失败" : "拒绝";
    outcome.append(statusBadge(outcomeText, item.outcome));
    row.append(time, actor, action, outcome, textElement("td", item.source_ip || "—"));
    elements.auditBody.append(row);
  });
  $("#audit-result-count").textContent = `本页 ${items.length} 条记录`;
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

elements.loginForm.addEventListener("submit", submitLogin);
elements.logout.addEventListener("click", logout);
document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => showPage(item.dataset.page)));
$("#user-search").addEventListener("input", renderUsers);
$("#user-status-filter").addEventListener("change", renderUsers);
$("#refresh-users").addEventListener("click", loadUsers);
$("#refresh-networks").addEventListener("click", loadNetworks);
$("#network-search").addEventListener("input", renderNetworks);
$("#open-create-network").addEventListener("click", () => openNetworkDialog());
$("#close-network-dialog").addEventListener("click", () => $("#network-dialog").close());
$("#cancel-network").addEventListener("click", () => $("#network-dialog").close());
$("#network-form").addEventListener("submit", submitNetwork);
document.querySelectorAll("input[name='managed-role']").forEach((input) => input.addEventListener("change", syncNetworkChoices));
$("#refresh-audit").addEventListener("click", () => { state.auditCursors = [null]; state.auditIndex = 0; loadAudit(); });
$("#open-create-user").addEventListener("click", () => openUserDialog());
$("#close-user-dialog").addEventListener("click", () => elements.userDialog.close());
$("#cancel-user").addEventListener("click", () => elements.userDialog.close());
elements.userDialog.addEventListener("close", () => { state.userDialogSerial += 1; });
elements.userForm.addEventListener("submit", submitUser);
elements.auditPrev.addEventListener("click", () => { if (state.auditIndex > 0) { state.auditIndex -= 1; loadAudit(); } });
elements.auditNext.addEventListener("click", () => { if (state.auditCursors[state.auditIndex + 1] != null) { state.auditIndex += 1; loadAudit(); } });

if (await loadConfig()) await restoreSession();
