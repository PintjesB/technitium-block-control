import {
  getSessionInfo,
  listApps,
  queryLogs,
} from "../background/technitiumApi.js";
import {
  diagnosePageCorrelation,
  formatDiagnosticReport,
  sanitizeDiagnosticUrl,
  sanitizeDiagnosticValue,
} from "../background/diagnostics.js";

const CLIENT_LOCATION_CACHE_KEY = "clientLocation";
const CLIENT_IP_CACHE_TS_KEY = "clientIpDetectedAt";
const QUERY_LOGS_CACHE_KEY = "queryLogsApp";
const FAILED_NAVIGATION_PREFIX = "failedNavigation::";
const CLIENT_IP_TTL_MS = 24 * 60 * 60 * 1000;
const FAILED_NAVIGATION_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LOG_WINDOW_MS = 120 * 1000;
const PROBE_TIMEOUT_MS = 5000;
const RETRY_INTERVAL_MS = 250;

const runButton = document.getElementById("runDiagnostics");
const copyButton = document.getElementById("copyDiagnostics");
const output = document.getElementById("diagnosticsOutput");
const sinceLoadToggle = document.getElementById("toggleSinceLoad");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createCorrelationId() {
  return `diag-${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 8)}`;
}

function diagnosticLog(correlationId, stage, payload) {
  console.info(
    `[TAC diagnostics ${correlationId}] ${stage}`,
    sanitizeDiagnosticValue(payload),
  );
}

function errorMessage(error) {
  return sanitizeDiagnosticValue(error?.message || String(error || "Unknown error"));
}

function normalizeDomain(value) {
  if (!value) return null;
  return String(value).trim().toLowerCase().replace(/\.$/, "");
}

function hostnameFromUrl(value) {
  if (typeof value !== "string" || !value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return normalizeDomain(url.hostname);
  } catch {
    return null;
  }
}

function isHttpUrl(value) {
  return !!hostnameFromUrl(value);
}

function hostMatchesBlocked(host, blockedDomain) {
  const h = normalizeDomain(host);
  const d = normalizeDomain(blockedDomain);
  if (!h || !d) return false;
  return h === d || h.endsWith(`.${d}`);
}

function isBlockedEntry(entry) {
  const responseType = String(entry?.responseType || "").toLowerCase();
  const rcode = String(entry?.rcode || entry?.RCODE || "").toLowerCase();
  return responseType.includes("blocked") || rcode.includes("nxdomain");
}

function mapEntry(entry) {
  return {
    qname: normalizeDomain(entry?.qname),
    clientIpAddress: entry?.clientIpAddress || null,
    timestamp: entry?.timestamp || null,
    responseType: entry?.responseType ?? null,
    rcode: entry?.rcode ?? entry?.RCODE ?? null,
    blocked: isBlockedEntry(entry),
  };
}

function selectQueryLogsApp(apps) {
  for (const app of apps || []) {
    for (const dnsApp of app?.dnsApps || []) {
      if (dnsApp?.isQueryLogs && dnsApp?.classPath) {
        return { name: app.name, classPath: dnsApp.classPath };
      }
    }
  }
  return null;
}

function clusterFromSession(sessionInfo) {
  const info = sessionInfo?.info || {};
  if (!info.clusterInitialized) {
    return {
      initialized: false,
      primaryNode: null,
      nodes: [{ name: null, type: "Standalone", state: "Self" }],
    };
  }

  const nodes = (Array.isArray(info.clusterNodes) ? info.clusterNodes : [])
    .filter((node) => node?.name)
    .map((node) => ({
      name: node.name,
      type: node.type || null,
      state: node.state || null,
    }));

  return {
    initialized: true,
    primaryNode:
      nodes.find((node) => String(node.type).toLowerCase() === "primary")?.name ||
      null,
    nodes: nodes.length > 0 ? nodes : [{ name: null, type: null, state: null }],
  };
}

function nodeNames(cluster) {
  return cluster.nodes.map((node) => node.name);
}

function clientCacheValidity(location, detectedAt, cluster, now = Date.now()) {
  if (!location?.clientIpAddress || !Number.isFinite(detectedAt)) return false;
  if (now - detectedAt > CLIENT_IP_TTL_MS) return false;
  if (!cluster.initialized) return location.node == null;
  return (
    typeof location.node === "string" &&
    cluster.nodes.some((node) => node.name === location.node)
  );
}

function resolvePageContext(tab, failedNavigation, now = Date.now()) {
  if (isHttpUrl(tab?.pendingUrl)) {
    return { url: tab.pendingUrl, source: "pendingUrl", navigationFailedAt: null };
  }

  const failedAt = Number(failedNavigation?.timeStamp);
  const failedIsFresh =
    isHttpUrl(failedNavigation?.url) &&
    Number.isFinite(failedAt) &&
    failedAt <= now + 60_000 &&
    now - failedAt <= FAILED_NAVIGATION_TTL_MS;

  if (failedIsFresh) {
    return {
      url: failedNavigation.url,
      source: "failedNavigation",
      navigationFailedAt: failedAt,
    };
  }

  return {
    url: typeof tab?.url === "string" ? tab.url : "",
    source: "tabUrl",
    navigationFailedAt: null,
  };
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs?.[0] || null;
}

async function getFailedNavigation(tabId) {
  if (!Number.isInteger(tabId)) return null;
  const key = `${FAILED_NAVIGATION_PREFIX}${tabId}`;
  const storage = chrome.storage.session || chrome.storage.local;
  const data = await storage.get(key);
  return data[key] || null;
}

async function collectPageSnapshot(tabId) {
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const hostTypes = new Map();
        for (const entry of performance.getEntriesByType("resource")) {
          try {
            const url = new URL(entry.name, location.href);
            const host = url.hostname.toLowerCase();
            if (!host) continue;
            let types = hostTypes.get(host);
            if (!types) {
              types = new Set();
              hostTypes.set(host, types);
            }
            types.add(String(entry.initiatorType || "other").toLowerCase());
          } catch {}
        }

        return {
          pageHost: location.hostname.toLowerCase(),
          pageStartEpoch: Date.now() - performance.now(),
          resourceHosts: Array.from(hostTypes.keys()),
        };
      },
    });

    return { ok: true, ...result };
  } catch (error) {
    return { ok: false, error: errorMessage(error) };
  }
}

async function queryOneNode(params, node) {
  try {
    const response = await queryLogs({
      ...params,
      node: node || undefined,
    });
    return {
      node: node || "local",
      ok: true,
      entries: (response.response?.entries || []).map(mapEntry),
    };
  } catch (error) {
    return {
      node: node || "local",
      ok: false,
      error: errorMessage(error),
      entries: [],
    };
  }
}

async function queryEveryNode(nodes, params) {
  return Promise.all(nodes.map((node) => queryOneNode(params, node)));
}

async function freshClientProbe(nodes, queryApp, correlationId) {
  if (!queryApp) {
    return { ok: false, error: "No queryable Query Logs app was detected." };
  }

  const qname = `ttdiag-${Date.now()}-${Math.random().toString(16).slice(2)}.example.com`;
  try {
    await fetch(`https://${qname}/`, { mode: "no-cors" });
  } catch {}

  const startedAt = Date.now();
  let attempts = 0;
  let lastResults = [];

  while (Date.now() - startedAt <= PROBE_TIMEOUT_MS) {
    attempts += 1;
    const now = Date.now();
    lastResults = await queryEveryNode(nodes, {
      name: queryApp.name,
      classPath: queryApp.classPath,
      entriesPerPage: 10,
      descendingOrder: true,
      startIso: new Date(now - 30_000).toISOString(),
      endIso: new Date(now).toISOString(),
      qname,
    });

    for (const result of lastResults) {
      const match = result.entries.find(
        (entry) => entry.qname === normalizeDomain(qname) && entry.clientIpAddress,
      );
      if (match) {
        const probe = {
          ok: true,
          attempts,
          qname,
          location: {
            clientIpAddress: match.clientIpAddress,
            node: result.node === "local" ? null : result.node,
          },
        };
        diagnosticLog(correlationId, "fresh-client-probe", probe);
        return probe;
      }
    }

    if (lastResults.length > 0 && lastResults.every((result) => !result.ok)) {
      return {
        ok: false,
        attempts,
        error: "Every cluster node failed the fresh client probe.",
        perNode: lastResults,
      };
    }

    await sleep(RETRY_INTERVAL_MS);
  }

  return {
    ok: false,
    attempts,
    error: "Fresh client probe produced no matching query-log entry within 5 seconds.",
    perNode: lastResults,
  };
}

async function queryExactWithRetry({
  nodes,
  params,
  timeoutMs,
  correlationId,
}) {
  const startedAt = Date.now();
  let attempts = 0;
  let results = [];

  while (true) {
    attempts += 1;
    results = await queryEveryNode(nodes, params);
    const hasBlocked = results.some((result) =>
      result.entries.some((entry) => entry.blocked),
    );
    if (hasBlocked) break;

    const elapsed = Date.now() - startedAt;
    if (elapsed >= timeoutMs) break;
    await sleep(Math.min(200, Math.max(0, timeoutMs - elapsed)));
  }

  const summary = { attempts, results };
  diagnosticLog(correlationId, "exact-page-query", summary);
  return summary;
}

function compactNodeResults(results, limitPerNode = 20) {
  return results.map((result) => ({
    node: result.node,
    ok: result.ok,
    error: result.error || null,
    entryCount: result.entries.length,
    entries: result.entries.slice(0, limitPerNode),
  }));
}

async function collectDiagnostics() {
  const correlationId = createCorrelationId();
  const generatedAt = new Date().toISOString();
  const report = {
    meta: {
      correlationId,
      generatedAt,
      extensionVersion: chrome.runtime.getManifest?.().version || null,
    },
  };

  diagnosticLog(correlationId, "start", report.meta);

  const tab = await getActiveTab();
  report.browser = {
    tabId: tab?.id ?? null,
    status: tab?.status || null,
    tabUrl: sanitizeDiagnosticUrl(tab?.url || ""),
    pendingUrl: sanitizeDiagnosticUrl(tab?.pendingUrl || ""),
  };
  diagnosticLog(correlationId, "browser", report.browser);

  if (!tab || !Number.isInteger(tab.id)) {
    report.decision = {
      code: "no-active-tab",
      detail: "No active browser tab was available to diagnose.",
    };
    return formatDiagnosticReport(report);
  }

  const failedNavigation = await getFailedNavigation(tab.id);
  report.navigation = {
    failedNavigation: failedNavigation
      ? {
          url: sanitizeDiagnosticUrl(failedNavigation.url),
          timeStamp: failedNavigation.timeStamp || null,
          ageMs: Number.isFinite(failedNavigation.timeStamp)
            ? Date.now() - failedNavigation.timeStamp
            : null,
        }
      : null,
  };

  const pageContext = resolvePageContext(tab, failedNavigation);
  const pageHost = hostnameFromUrl(pageContext.url);
  report.page = {
    resolvedSource: pageContext.source,
    resolvedUrl: sanitizeDiagnosticUrl(pageContext.url),
    resolvedHost: pageHost,
    navigationFailedAt: pageContext.navigationFailedAt,
  };
  diagnosticLog(correlationId, "page-context", {
    navigation: report.navigation,
    page: report.page,
  });

  const snapshot = await collectPageSnapshot(tab.id);
  report.page.snapshot = snapshot.ok
    ? {
        ok: true,
        pageHost: snapshot.pageHost || null,
        pageStartEpoch: snapshot.pageStartEpoch || null,
        resourceHostCount: snapshot.resourceHosts?.length || 0,
        resourceHosts: (snapshot.resourceHosts || []).slice(0, 50),
      }
    : snapshot;
  diagnosticLog(correlationId, "page-snapshot", report.page.snapshot);

  let cluster = {
    initialized: false,
    primaryNode: null,
    nodes: [{ name: null, type: "Unknown", state: "Unknown" }],
  };
  try {
    const session = await getSessionInfo();
    cluster = clusterFromSession(session);
    report.technitium = { cluster };
  } catch (error) {
    report.technitium = {
      cluster: {
        ...cluster,
        discoveryError: errorMessage(error),
      },
    };
  }
  diagnosticLog(correlationId, "cluster", report.technitium.cluster);

  const nodes = nodeNames(cluster);

  const cacheData = await chrome.storage.local.get([
    QUERY_LOGS_CACHE_KEY,
    CLIENT_LOCATION_CACHE_KEY,
    CLIENT_IP_CACHE_TS_KEY,
  ]);

  let discoveredQueryApp = null;
  let appsError = null;
  try {
    const apps = await listApps();
    discoveredQueryApp = selectQueryLogsApp(apps.response?.apps || []);
  } catch (error) {
    appsError = errorMessage(error);
  }

  const cachedQueryApp = cacheData[QUERY_LOGS_CACHE_KEY] || null;
  const queryApp = cachedQueryApp?.name && cachedQueryApp?.classPath
    ? cachedQueryApp
    : discoveredQueryApp;

  report.technitium.queryLogsApp = {
    cached: cachedQueryApp,
    discovered: discoveredQueryApp,
    effective: queryApp,
    discoveryError: appsError,
  };
  diagnosticLog(correlationId, "query-logs-app", report.technitium.queryLogsApp);

  const cachedLocation = cacheData[CLIENT_LOCATION_CACHE_KEY] || null;
  const detectedAt = cacheData[CLIENT_IP_CACHE_TS_KEY];
  const cachedValid = clientCacheValidity(cachedLocation, detectedAt, cluster);
  const freshProbe = await freshClientProbe(nodes, queryApp, correlationId);
  const effectiveLocation = cachedValid
    ? cachedLocation
    : freshProbe.ok
      ? freshProbe.location
      : null;

  report.technitium.client = {
    cached: {
      location: cachedLocation,
      detectedAt: Number.isFinite(detectedAt) ? detectedAt : null,
      ageMs: Number.isFinite(detectedAt) ? Date.now() - detectedAt : null,
      valid: cachedValid,
    },
    freshProbe,
    effectiveLocation,
  };
  diagnosticLog(correlationId, "client", report.technitium.client);

  const now = Date.now();
  const sinceLoad = !!sinceLoadToggle?.checked;
  const generalStart =
    sinceLoad && snapshot.ok && Number.isFinite(snapshot.pageStartEpoch)
      ? snapshot.pageStartEpoch - 2000
      : now - DEFAULT_LOG_WINDOW_MS;
  const generalWindow = {
    startIso: new Date(Math.max(0, generalStart)).toISOString(),
    endIso: new Date(now).toISOString(),
    source: sinceLoad && snapshot.ok ? "pageStart" : "last120Seconds",
  };

  let generalResults = [];
  if (queryApp && effectiveLocation?.clientIpAddress) {
    generalResults = await queryEveryNode(nodes, {
      name: queryApp.name,
      classPath: queryApp.classPath,
      entriesPerPage: 300,
      descendingOrder: true,
      startIso: generalWindow.startIso,
      endIso: generalWindow.endIso,
      clientIpAddress: effectiveLocation.clientIpAddress,
    });
  }

  const generalEntries = generalResults.flatMap((result) => result.entries);
  const blockedGeneralEntries = generalEntries.filter((entry) => entry.blocked);
  const generalPageMatches = blockedGeneralEntries.filter((entry) =>
    hostMatchesBlocked(pageHost, entry.qname),
  );

  report.technitium.generalQuery = {
    window: generalWindow,
    perNode: compactNodeResults(generalResults, 10),
    totalEntries: generalEntries.length,
    blockedEntries: blockedGeneralEntries.length,
    pageMatchCount: generalPageMatches.length,
    pageMatches: generalPageMatches.slice(0, 20),
  };
  diagnosticLog(correlationId, "general-query", report.technitium.generalQuery);

  let exactResults = [];
  let exactAttempts = 0;
  let exactWindow = null;

  if (queryApp && effectiveLocation?.clientIpAddress && pageHost) {
    const failedAt = Number(pageContext.navigationFailedAt);
    const exactStart = Number.isFinite(failedAt)
      ? Math.max(0, failedAt - 30_000)
      : generalStart;
    const retryMs =
      Number.isFinite(failedAt) && now - failedAt <= 10_000 ? 1500 : 0;

    exactWindow = {
      startIso: new Date(exactStart).toISOString(),
      endIso: new Date(now).toISOString(),
      retryMs,
      source: Number.isFinite(failedAt) ? "failedNavigation" : generalWindow.source,
    };

    const exact = await queryExactWithRetry({
      nodes,
      params: {
        name: queryApp.name,
        classPath: queryApp.classPath,
        entriesPerPage: 200,
        descendingOrder: true,
        startIso: exactWindow.startIso,
        endIso: exactWindow.endIso,
        clientIpAddress: effectiveLocation.clientIpAddress,
        qname: pageHost,
      },
      timeoutMs: retryMs,
      correlationId,
    });
    exactAttempts = exact.attempts;
    exactResults = exact.results;
  }

  report.technitium.exactPageQuery = {
    qname: pageHost,
    window: exactWindow,
    attempts: exactAttempts,
    perNode: compactNodeResults(exactResults, 30),
    totalEntries: exactResults.reduce(
      (sum, result) => sum + result.entries.length,
      0,
    ),
    blockedEntries: exactResults.reduce(
      (sum, result) =>
        sum + result.entries.filter((entry) => entry.blocked).length,
      0,
    ),
  };

  report.decision = diagnosePageCorrelation({
    pageHost,
    exactNodeResults: exactResults,
    matchedInGeneralList: generalPageMatches.length > 0,
  });
  diagnosticLog(correlationId, "decision", report.decision);

  return formatDiagnosticReport(report);
}

async function runAndRenderDiagnostics() {
  if (!runButton || !output) return;

  runButton.disabled = true;
  if (copyButton) copyButton.hidden = true;
  output.hidden = false;
  output.textContent = "Running diagnostics... This may take up to 5 seconds.";

  try {
    output.textContent = await collectDiagnostics();
    if (copyButton) copyButton.hidden = false;
  } catch (error) {
    output.textContent = formatDiagnosticReport({
      meta: {
        correlationId: createCorrelationId(),
        generatedAt: new Date().toISOString(),
      },
      fatalError: errorMessage(error),
    });
    if (copyButton) copyButton.hidden = false;
  } finally {
    runButton.disabled = false;
  }
}

runButton?.addEventListener("click", runAndRenderDiagnostics);

copyButton?.addEventListener("click", async () => {
  if (!output?.textContent) return;
  try {
    await navigator.clipboard.writeText(output.textContent);
    const original = copyButton.textContent;
    copyButton.textContent = "Copied";
    setTimeout(() => {
      copyButton.textContent = original;
    }, 1200);
  } catch {
    output.focus?.();
  }
});
