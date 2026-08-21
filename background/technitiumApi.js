// background/technitiumApi.js
// This module wraps all API requests to the Technitium DNS Server.

async function getConfig() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["baseUrl", "apiKey"], (data) => resolve(data));
  });
}

async function technitiumRequest(path) {
  const { baseUrl, apiKey } = await getConfig();

  if (!baseUrl || !apiKey) {
    throw new Error("Technitium is not configured");
  }

  const cleanBaseUrl = String(baseUrl).replace(/\/$/, "");
  const hasQuery = path.includes("?");
  const url = `${cleanBaseUrl}/api${path}${hasQuery ? "&" : "?"}token=${encodeURIComponent(apiKey)}`;

  let response;
  try {
    response = await fetch(url, { method: "GET" });
  } catch (err) {
    throw new Error("Technitium API is unreachable");
  }

  if (!response.ok) {
    throw new Error(`API HTTP error (${response.status})`);
  }

  const data = await response.json();

  if (data.status && data.status !== "ok") {
    // Technitium may return e.g. { status: "error", errorMessage: "..." }.
    throw new Error(data.errorMessage || "Technitium API error");
  }

  return data;
}

function withNode(path, node) {
  if (!node) return path;
  return `${path}${path.includes("?") ? "&" : "?"}node=${encodeURIComponent(node)}`;
}

// ===== Settings / blocking status =====

// Fetches general DNS settings.
// GET /api/settings/get?token=...
export async function getDnsSettings() {
  return technitiumRequest(`/settings/get`);
}

// Enables or disables ad blocking through the settings/set endpoint.
export async function setEnableBlocking(enable) {
  // /api/settings/set?enableBlocking=true|false
  return technitiumRequest(
    `/settings/set?enableBlocking=${enable ? "true" : "false"}`,
  );
}

// Disables blocking temporarily for the requested number of minutes.
// GET /api/settings/temporaryDisableBlocking?minutes=5
export async function temporaryDisableBlocking(minutes) {
  const m = Math.max(1, Math.floor(minutes || 5));
  return technitiumRequest(`/settings/temporaryDisableBlocking?minutes=${m}`);
}

// ===== Cluster =====

// Returns the current session including server/cluster information. This
// endpoint includes clusterInitialized and clusterNodes for API tokens without
// requiring Administration/View permission.
// GET /api/user/session/get
export async function getSessionInfo() {
  return technitiumRequest(`/user/session/get`);
}

// ===== DNS apps =====

// Lists all installed DNS apps.
// GET /api/apps/list
export async function listApps() {
  return technitiumRequest(`/apps/list`);
}

// ===== Query logs =====
// The Query Logs endpoint is /api/logs/query, not an /api/apps/* endpoint.
export async function queryLogs(params) {
  const {
    name,
    classPath,
    pageNumber = 1,
    entriesPerPage = 50,
    descendingOrder = true,
    startIso,
    endIso,
    clientIpAddress,
    responseType,
    qname,
    qtype,
    node,
  } = params || {};

  const qs = new URLSearchParams();
  if (name) qs.set("name", name);
  if (classPath) qs.set("classPath", classPath);
  qs.set("pageNumber", String(pageNumber));
  qs.set("entriesPerPage", String(entriesPerPage));
  qs.set("descendingOrder", descendingOrder ? "true" : "false");
  if (startIso) qs.set("start", startIso);
  if (endIso) qs.set("end", endIso);
  if (clientIpAddress) qs.set("clientIpAddress", clientIpAddress);
  if (responseType) qs.set("responseType", responseType);
  if (qname) qs.set("qname", qname);
  if (qtype) qs.set("qtype", qtype);
  if (node) qs.set("node", node);

  return technitiumRequest(`/logs/query?${qs.toString()}`);
}

// ===== Allowed zones =====

// Adds a domain to the allow list.
// GET /api/allowed/add?domain=...
export async function allowZone(domain) {
  return technitiumRequest(`/allowed/add?domain=${encodeURIComponent(domain)}`);
}

// Removes a domain from the allow list.
// GET /api/allowed/delete?domain=...
export async function deleteAllowedZone(domain) {
  return technitiumRequest(
    `/allowed/delete?domain=${encodeURIComponent(domain)}`,
  );
}

// Lists entries in Allowed Zones.
// GET /api/allowed/list?domain=...
export async function listAllowed(domain, node) {
  const d = domain ? encodeURIComponent(domain) : "";
  return technitiumRequest(withNode(`/allowed/list?domain=${d}`, node));
}

// ===== Cache =====

// Deletes a domain from the DNS cache.
// GET /api/cache/delete?domain=...
export async function deleteCachedZone(domain, node) {
  return technitiumRequest(
    withNode(`/cache/delete?domain=${encodeURIComponent(domain)}`, node),
  );
}
