// background/serviceWorker.js
// This service worker runs in the background and controls the extension's core logic.

import {
  getDnsSettings,
  setEnableBlocking,
  temporaryDisableBlocking,
  getSessionInfo,
  listApps,
  queryLogs,
  allowZone,
  deleteAllowedZone,
  deleteCachedZone,
  listAllowed,
} from "./technitiumApi.js";

const TIMER_ALARM = "reEnableBlocking";

const CLIENT_LOCATION_CACHE_KEY = "clientLocation";
const LEGACY_CLIENT_IP_CACHE_KEY = "clientIpAddress";
const CLIENT_IP_CACHE_TS_KEY = "clientIpDetectedAt";
const QUERY_LOGS_CACHE_KEY = "queryLogsApp";
const LEGACY_QUERY_LOGGER_CACHE_KEY = "queryLoggerApp";
const CLIENT_IP_TTL_MS = 24 * 60 * 60 * 1000;
const CLIENT_DETECTION_TIMEOUT_MS = 5000;
const CLIENT_DETECTION_RETRY_MS = 250;

const FAILED_NAVIGATION_PREFIX = "failedNavigation::";
const FAILED_NAVIGATION_TTL_MS = 24 * 60 * 60 * 1000;
const PAGE_DOMAIN_LOOKUP_RETRY_MS = 200;

const TEMP_ALLOW_MINUTES_KEY = "tempAllowMinutes";
const LOG_WINDOW_SECONDS_KEY = "logWindowSeconds";

const TEMP_ALLOW_PREFIX = "tempAllow::";
const TEMP_ALLOW_STATE_KEY = "tempAllowState";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isHttpUrl(value) {
  if (typeof value !== "string" || !value) return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function navigationStorage() {
  return chrome.storage.session || chrome.storage.local;
}

function failedNavigationKey(tabId) {
  return `${FAILED_NAVIGATION_PREFIX}${tabId}`;
}

async function getFailedNavigation(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  const key = failedNavigationKey(tabId);
  const data = await navigationStorage().get(key);
  return data[key] || null;
}

async function setFailedNavigation(tabId, details) {
  if (!Number.isInteger(tabId) || tabId < 0 || !isHttpUrl(details?.url)) return;
  const key = failedNavigationKey(tabId);
  const timeStamp = Number.isFinite(details?.timeStamp)
    ? details.timeStamp
    : Date.now();
  await navigationStorage().set({
    [key]: { url: details.url, timeStamp },
  });
}

async function clearFailedNavigation(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  await navigationStorage().remove(failedNavigationKey(tabId));
}

export function resolvePageContext({
  tabUrl,
  pendingUrl,
  failedNavigation,
  now = Date.now(),
}) {
  if (isHttpUrl(pendingUrl)) {
    return { url: pendingUrl, navigationFailedAt: null };
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
      navigationFailedAt: failedAt,
    };
  }

  return {
    url: typeof tabUrl === "string" ? tabUrl : "",
    navigationFailedAt: null,
  };
}

if (chrome.webNavigation?.onErrorOccurred?.addListener) {
  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (details.frameId !== 0) return;
    setFailedNavigation(details.tabId, details).catch((error) =>
      console.warn("[Technitium] Failed to remember navigation error:", error),
    );
  });
}

if (chrome.webNavigation?.onCommitted?.addListener) {
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    if (String(details.url || "").toLowerCase().startsWith("chrome-error://")) {
      return;
    }
    clearFailedNavigation(details.tabId).catch((error) =>
      console.warn("[Technitium] Failed to clear navigation error:", error),
    );
  });
}

if (chrome.tabs?.onRemoved?.addListener) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearFailedNavigation(tabId).catch((error) =>
      console.warn("[Technitium] Failed to clear closed-tab navigation state:", error),
    );
  });
}

export function getClusterTopology(sessionInfo) {
  const info = sessionInfo?.info || {};
  if (!info.clusterInitialized) {
    return { clusterInitialized: false, nodes: [null], primaryNode: null };
  }

  const clusterNodes = Array.isArray(info.clusterNodes) ? info.clusterNodes : [];
  const nodes = clusterNodes.filter((node) => node?.name).map((node) => node.name);
  const primaryNode =
    clusterNodes.find((node) => String(node?.type).toLowerCase() === "primary")?.name ||
    null;

  return {
    clusterInitialized: true,
    nodes: nodes.length > 0 ? Array.from(new Set(nodes)) : [null],
    primaryNode,
  };
}

async function loadClusterTopology() {
  try {
    return getClusterTopology(await getSessionInfo());
  } catch (e) {
    console.warn(
      "[Technitium] Cluster topology discovery failed; using local node:",
      e,
    );
    return { clusterInitialized: false, nodes: [null], primaryNode: null };
  }
}

export function isClientLocationCacheValid(
  location,
  detectedAt,
  topology,
  now = Date.now(),
) {
  if (!location?.clientIpAddress || !Number.isFinite(detectedAt)) return false;
  if (now - detectedAt > CLIENT_IP_TTL_MS) return false;

  if (!topology?.clusterInitialized) return location.node == null;
  return (
    typeof location.node === "string" &&
    Array.isArray(topology.nodes) &&
    topology.nodes.includes(location.node)
  );
}

async function getCachedClientLocation(topology) {
  const data = await chrome.storage.local.get([
    CLIENT_LOCATION_CACHE_KEY,
    LEGACY_CLIENT_IP_CACHE_KEY,
    CLIENT_IP_CACHE_TS_KEY,
  ]);

  const detectedAt = data[CLIENT_IP_CACHE_TS_KEY];
  const location = data[CLIENT_LOCATION_CACHE_KEY];

  if (isClientLocationCacheValid(location, detectedAt, topology)) {
    if (data[LEGACY_CLIENT_IP_CACHE_KEY]) {
      await chrome.storage.local.remove(LEGACY_CLIENT_IP_CACHE_KEY);
    }
    return location;
  }

  const legacyIp = data[LEGACY_CLIENT_IP_CACHE_KEY];
  if (
    !topology.clusterInitialized &&
    typeof legacyIp === "string" &&
    legacyIp &&
    Number.isFinite(detectedAt) &&
    Date.now() - detectedAt <= CLIENT_IP_TTL_MS
  ) {
    const migrated = { clientIpAddress: legacyIp, node: null };
    await chrome.storage.local.set({ [CLIENT_LOCATION_CACHE_KEY]: migrated });
    await chrome.storage.local.remove(LEGACY_CLIENT_IP_CACHE_KEY);
    return migrated;
  }

  await chrome.storage.local.remove([
    CLIENT_LOCATION_CACHE_KEY,
    LEGACY_CLIENT_IP_CACHE_KEY,
    CLIENT_IP_CACHE_TS_KEY,
  ]);
  return null;
}

async function setCachedClientLocation(location) {
  await chrome.storage.local.set({
    [CLIENT_LOCATION_CACHE_KEY]: location,
    [CLIENT_IP_CACHE_TS_KEY]: Date.now(),
  });
  await chrome.storage.local.remove(LEGACY_CLIENT_IP_CACHE_KEY);
}

async function clearCachedClientLocation() {
  await chrome.storage.local.remove([
    CLIENT_LOCATION_CACHE_KEY,
    LEGACY_CLIENT_IP_CACHE_KEY,
    CLIENT_IP_CACHE_TS_KEY,
  ]);
}

export async function pollForClientLocation({
  qname,
  nodes,
  queryLogger,
  queryLogsFn = queryLogs,
  now = Date.now,
  sleepFn = sleep,
  timeoutMs = CLIENT_DETECTION_TIMEOUT_MS,
  intervalMs = CLIENT_DETECTION_RETRY_MS,
}) {
  const target = String(qname || "").toLowerCase();
  const queryNodes = Array.isArray(nodes) && nodes.length > 0 ? nodes : [null];
  const startedAt = now();

  while (true) {
    const queryTime = now();
    const endIso = new Date(queryTime).toISOString();
    const startIso = new Date(queryTime - 30 * 1000).toISOString();

    const results = await Promise.all(
      queryNodes.map(async (node) => {
        try {
          const res = await queryLogsFn({
            name: queryLogger.name,
            classPath: queryLogger.classPath,
            entriesPerPage: 10,
            descendingOrder: true,
            startIso,
            endIso,
            qname,
            node: node || undefined,
          });
          const entries = res.response?.entries || [];
          const entry = entries.find(
            (item) =>
              String(item?.qname || "").toLowerCase() === target &&
              item?.clientIpAddress,
          );
          return {
            ok: true,
            location: entry
              ? { clientIpAddress: entry.clientIpAddress, node: node || null }
              : null,
          };
        } catch (error) {
          return { ok: false, error };
        }
      }),
    );

    const match = results.find((result) => result.ok && result.location)?.location;
    if (match) return match;

    const successfulQueries = results.filter((result) => result.ok);
    if (successfulQueries.length === 0 && results.length > 0) {
      throw results[0].error;
    }

    const elapsed = now() - startedAt;
    if (elapsed >= timeoutMs) return null;

    await sleepFn(Math.min(intervalMs, Math.max(0, timeoutMs - elapsed)));
  }
}

export async function queryClientEntriesWithFailover({
  location,
  clusterInitialized,
  queryParams,
  queryLogsFn = queryLogs,
  redetectFn,
}) {
  const queryAtLocation = async (currentLocation) => {
    const res = await queryLogsFn({
      ...queryParams,
      clientIpAddress: currentLocation.clientIpAddress,
      node: currentLocation.node || undefined,
    });
    return res.response?.entries || [];
  };

  let firstEntries;
  let firstError = null;
  try {
    firstEntries = await queryAtLocation(location);
  } catch (e) {
    firstError = e;
  }

  if (!clusterInitialized) {
    if (firstError) throw firstError;
    return { location, entries: firstEntries };
  }

  if (!firstError && firstEntries.length > 0) {
    return { location, entries: firstEntries };
  }

  const redetected = await redetectFn();
  const sameLocation =
    redetected?.clientIpAddress === location?.clientIpAddress &&
    redetected?.node === location?.node;

  if (sameLocation && !firstError) {
    return { location: redetected, entries: firstEntries };
  }

  return {
    location: redetected,
    entries: await queryAtLocation(redetected),
  };
}

async function queryEntriesAcrossNodes(topology, params) {
  const results = await Promise.all(
    topology.nodes.map(async (node) => {
      try {
        const res = await queryLogs({ ...params, node: node || undefined });
        return { ok: true, entries: res.response?.entries || [] };
      } catch (error) {
        return { ok: false, error };
      }
    }),
  );

  const successes = results.filter((result) => result.ok);
  if (successes.length === 0 && results.length > 0) {
    throw results[0].error;
  }

  return successes.flatMap((result) => result.entries);
}

async function deleteCachedZoneEverywhere(domain) {
  const topology = await loadClusterTopology();
  await Promise.allSettled(
    topology.nodes.map((node) => deleteCachedZone(domain, node || undefined)),
  );
}

async function restoreScheduledState() {
  const now = Date.now();
  const { blockingTempUntil } =
    await chrome.storage.local.get("blockingTempUntil");

  await chrome.alarms.clear(TIMER_ALARM);
  if (blockingTempUntil && Number.isFinite(blockingTempUntil)) {
    if (blockingTempUntil > now) {
      await chrome.alarms.create(TIMER_ALARM, { when: blockingTempUntil });
    } else {
      await clearTimerState();
    }
  }

  const state = await getTempAllowState();
  const entries = Object.entries(state);
  if (entries.length === 0) return;

  for (const [domain, expiresTs] of entries) {
    const when = Number(expiresTs);
    if (!Number.isFinite(when)) {
      delete state[domain];
      continue;
    }

    const alarmName = `${TEMP_ALLOW_PREFIX}${domain}`;
    await chrome.alarms.clear(alarmName);

    if (when <= now) {
      try {
        await removeTempAllow(domain);
        delete state[domain];
      } catch (e) {
        console.warn(
          "[Technitium] Temp allow cleanup (startup) failed:",
          domain,
          e,
        );
      }
      continue;
    }

    await chrome.alarms.create(alarmName, { when });
  }

  await setTempAllowState(state);
}

async function setTimerState(untilTs) {
  await chrome.storage.local.set({ blockingTempUntil: untilTs });
}

async function clearTimerState() {
  await chrome.storage.local.remove(["blockingTempUntil"]);
}

async function getTempAllowState() {
  const data = await chrome.storage.local.get(TEMP_ALLOW_STATE_KEY);
  return data[TEMP_ALLOW_STATE_KEY] || {};
}

async function setTempAllowState(state) {
  await chrome.storage.local.set({ [TEMP_ALLOW_STATE_KEY]: state });
}

async function removeTempAllow(domain) {
  await deleteAllowedZone(domain);
  await deleteCachedZoneEverywhere(domain);

  const state = await getTempAllowState();
  delete state[domain];
  await setTempAllowState(state);
}

chrome.runtime.onInstalled.addListener(() => {
  restoreScheduledState().catch((e) =>
    console.warn("[Technitium] restoreScheduledState (onInstalled) failed:", e),
  );
});

chrome.runtime.onStartup.addListener(() => {
  restoreScheduledState().catch((e) =>
    console.warn("[Technitium] restoreScheduledState (onStartup) failed:", e),
  );
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === TIMER_ALARM) {
    try {
      await setEnableBlocking(true);
    } catch (e) {
      console.error("[Technitium] Re-enable after timer failed:", e);
    } finally {
      await clearTimerState();
    }
    return;
  }

  if (alarm.name.startsWith(TEMP_ALLOW_PREFIX)) {
    const domain = alarm.name.slice(TEMP_ALLOW_PREFIX.length);
    try {
      await removeTempAllow(domain);
    } catch (e) {
      console.error("[Technitium] Temp allow cleanup failed:", domain, e);
    }
  }
});

async function getOptionNumber(key, defaultValue) {
  const data = await chrome.storage.local.get(key);
  const v = data[key];
  if (typeof v === "number" && Number.isFinite(v)) return v;
  return defaultValue;
}

async function getOptionBool(key, defaultValue = false) {
  const data = await chrome.storage.local.get(key);
  const v = data[key];
  if (typeof v === "boolean") return v;
  return defaultValue;
}

async function getCachedQueryLogsApp() {
  const data = await chrome.storage.local.get(QUERY_LOGS_CACHE_KEY);
  const q = data[QUERY_LOGS_CACHE_KEY];
  if (q?.name && q?.classPath) return q;
  return null;
}

async function setCachedQueryLogsApp(app) {
  await chrome.storage.local.set({ [QUERY_LOGS_CACHE_KEY]: app });
  await chrome.storage.local.remove(LEGACY_QUERY_LOGGER_CACHE_KEY);
}

export function selectQueryLogsApp(apps) {
  for (const app of apps || []) {
    for (const dnsApp of app?.dnsApps || []) {
      if (dnsApp?.isQueryLogs && dnsApp?.classPath) {
        return { name: app.name, classPath: dnsApp.classPath };
      }
    }
  }
  return null;
}

async function detectQueryLogsApp() {
  const cached = await getCachedQueryLogsApp();
  if (cached) return cached;

  const res = await listApps();
  const found = selectQueryLogsApp(res.response?.apps || []);
  if (!found) {
    throw new Error(
      "No DNS app with query-log search support was found (apps/list).",
    );
  }

  await setCachedQueryLogsApp(found);
  return found;
}

async function inferClientLocationFromLogs({ force = false } = {}) {
  const topology = await loadClusterTopology();
  if (!force) {
    const cached = await getCachedClientLocation(topology);
    if (cached) return { location: cached, topology };
  }

  const qname = `ttip-${Date.now()}-${Math.random().toString(16).slice(2)}.example.com`;

  try {
    await fetch(`https://${qname}/`, { mode: "no-cors" });
  } catch (_) {}

  const ql = await detectQueryLogsApp();
  const location = await pollForClientLocation({
    qname,
    nodes: topology.nodes,
    queryLogger: ql,
  });

  if (!location) {
    throw new Error(
      "Client IP could not be detected (no matching query-log entry found).",
    );
  }

  await setCachedClientLocation(location);
  return { location, topology };
}

function normalizeDomain(qname) {
  if (!qname) return null;
  return String(qname).trim().toLowerCase().replace(/\.$/, "");
}

function isBlockedLogEntry(e) {
  const rtRaw = e.responseType;
  const rt =
    typeof rtRaw === "string" ? rtRaw.toLowerCase() : String(rtRaw || "");
  const rcRaw = e.rcode || e.RCODE;
  const rc =
    typeof rcRaw === "string" ? rcRaw.toLowerCase() : String(rcRaw || "");

  if (rt.includes("blocked")) return true;
  if (rc.includes("nxdomain")) return true;
  return false;
}

function summarizeBlockedDomain(domain, entries) {
  const dNorm = normalizeDomain(domain);
  let count = 0;
  let lastSeen = null;

  for (const entry of entries || []) {
    if (normalizeDomain(entry?.qname) !== dNorm) continue;
    if (!isBlockedLogEntry(entry)) continue;
    count += 1;
    const ts = entry.timestamp || null;
    if (ts && (!lastSeen || ts > lastSeen)) lastSeen = ts;
  }

  if (count === 0) return null;
  return { domain: dNorm, count, lastSeen };
}

export async function pollForBlockedDomain({
  domain,
  clientIpAddress,
  nodes,
  queryLogger,
  startIso,
  endIso,
  queryLogsFn = queryLogs,
  now = Date.now,
  sleepFn = sleep,
  timeoutMs = 0,
  intervalMs = PAGE_DOMAIN_LOOKUP_RETRY_MS,
}) {
  const dNorm = normalizeDomain(domain);
  if (!dNorm) return null;

  const queryNodes = Array.isArray(nodes) && nodes.length > 0 ? nodes : [null];
  const startedAt = now();

  while (true) {
    const results = await Promise.all(
      queryNodes.map(async (node) => {
        try {
          const response = await queryLogsFn({
            name: queryLogger.name,
            classPath: queryLogger.classPath,
            entriesPerPage: 200,
            descendingOrder: true,
            startIso,
            endIso,
            clientIpAddress,
            qname: dNorm,
            node: node || undefined,
          });
          return { ok: true, entries: response.response?.entries || [] };
        } catch (error) {
          return { ok: false, error };
        }
      }),
    );

    const successes = results.filter((result) => result.ok);
    if (successes.length === 0 && results.length > 0) {
      throw results[0].error;
    }

    const item = summarizeBlockedDomain(
      dNorm,
      successes.flatMap((result) => result.entries),
    );
    if (item) return item;

    const elapsed = now() - startedAt;
    if (elapsed >= timeoutMs) return null;

    await sleepFn(Math.min(intervalMs, Math.max(0, timeoutMs - elapsed)));
  }
}

function aggregateBlocked(entries) {
  const map = new Map();
  for (const e of entries) {
    if (!isBlockedLogEntry(e)) continue;

    const d = normalizeDomain(e.qname);
    if (!d) continue;

    const ts = e.timestamp || null;
    const prev = map.get(d);
    if (!prev) {
      map.set(d, { domain: d, count: 1, lastSeen: ts });
    } else {
      prev.count += 1;
      if (ts && (!prev.lastSeen || ts > prev.lastSeen)) prev.lastSeen = ts;
    }
  }

  return Array.from(map.values()).sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.domain.localeCompare(b.domain);
  });
}

async function findBlockedForDomain(domain, options = {}) {
  const dNorm = normalizeDomain(domain);
  if (!dNorm) return null;

  const ql = await detectQueryLogsApp();
  const detected = await inferClientLocationFromLogs();

  let startIso;
  let endIso;

  if (options.startIso && options.endIso) {
    startIso = options.startIso;
    endIso = options.endIso;
  } else {
    const secondsDefault = await getOptionNumber(LOG_WINDOW_SECONDS_KEY, 120);
    const seconds = Math.max(10, Math.floor(options.seconds || secondsDefault));
    endIso = new Date().toISOString();
    startIso = new Date(Date.now() - seconds * 1000).toISOString();
  }

  return pollForBlockedDomain({
    domain: dNorm,
    clientIpAddress: detected.location.clientIpAddress,
    nodes: detected.topology.nodes,
    queryLogger: ql,
    startIso,
    endIso,
    timeoutMs: Math.max(0, Math.floor(options.retryMs || 0)),
  });
}

async function isDomainAllowed(domain, primaryNode) {
  const d = normalizeDomain(domain);
  if (!d) return false;

  const res = await listAllowed(d, primaryNode || undefined);
  const r = res.response || {};
  const records = Array.isArray(r.records) ? r.records : [];
  const zones = Array.isArray(r.zones) ? r.zones : [];

  if (
    (records.length > 0 || zones.length > 0) &&
    String(r.domain || "")
      .toLowerCase()
      .includes(d)
  ) {
    return true;
  }

  return records.length > 0 || zones.length > 0;
}

async function allowedStatusBatch(domains) {
  const list = (domains || []).map(normalizeDomain).filter(Boolean);
  const unique = Array.from(new Set(list));
  const topology = await loadClusterTopology();

  const allowed = {};
  const concurrency = 5;
  let idx = 0;

  async function worker() {
    while (idx < unique.length) {
      const i = idx++;
      const d = unique[i];
      try {
        allowed[d] = await isDomainAllowed(d, topology.primaryNode);
      } catch (_) {
        allowed[d] = false;
      }
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, unique.length) },
    () => worker(),
  );
  await Promise.all(workers);

  return { enabled: true, allowed };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.action === "pageContext") {
        const failedNavigation = await getFailedNavigation(msg.tabId);
        const context = resolvePageContext({
          tabUrl: msg.tabUrl,
          pendingUrl: msg.pendingUrl,
          failedNavigation,
        });
        sendResponse({ ok: true, ...context });
        return;
      }

      if (msg.action === "status") {
        const settings = await getDnsSettings();
        const enableBlocking = !!settings.response?.enableBlocking;
        const { blockingTempUntil } =
          await chrome.storage.local.get("blockingTempUntil");
        sendResponse({
          ok: true,
          enableBlocking,
          tempUntil: blockingTempUntil || null,
        });
        return;
      }

      if (msg.action === "enable") {
        await setEnableBlocking(true);
        await clearTimerState();
        await chrome.alarms.clear(TIMER_ALARM);
        sendResponse({ ok: true });
        return;
      }

      if (msg.action === "disable") {
        await setEnableBlocking(false);
        await clearTimerState();
        await chrome.alarms.clear(TIMER_ALARM);
        sendResponse({ ok: true });
        return;
      }

      if (msg.action === "tempDisable") {
        const minutes = Math.max(1, Math.floor(msg.minutes || 5));
        await temporaryDisableBlocking(minutes);
        const untilTs = Date.now() + minutes * 60 * 1000;
        await setTimerState(untilTs);
        await chrome.alarms.clear(TIMER_ALARM);
        await chrome.alarms.create(TIMER_ALARM, { when: untilTs });
        sendResponse({ ok: true, tempUntil: untilTs });
        return;
      }

      if (msg.action === "blockedList") {
        let detected = await inferClientLocationFromLogs();
        const ql = await detectQueryLogsApp();

        let startIso, endIso;
        if (msg.startIso && msg.endIso) {
          startIso = msg.startIso;
          endIso = msg.endIso;
        } else {
          const secondsDefault = await getOptionNumber(
            LOG_WINDOW_SECONDS_KEY,
            120,
          );
          const seconds = Math.max(
            10,
            Math.floor(msg.seconds || secondsDefault),
          );
          endIso = new Date().toISOString();
          startIso = new Date(Date.now() - seconds * 1000).toISOString();
        }

        const result = await queryClientEntriesWithFailover({
          location: detected.location,
          clusterInitialized: detected.topology.clusterInitialized,
          queryParams: {
            name: ql.name,
            classPath: ql.classPath,
            entriesPerPage: 300,
            descendingOrder: true,
            startIso,
            endIso,
          },
          redetectFn: async () => {
            await clearCachedClientLocation();
            detected = await inferClientLocationFromLogs({ force: true });
            return detected.location;
          },
        });

        const items = aggregateBlocked(result.entries);
        sendResponse({ ok: true, items });
        return;
      }

      if (msg.action === "blockedForDomain") {
        const domain = normalizeDomain(msg.domain);
        if (!domain) {
          sendResponse({ ok: true, item: null });
          return;
        }

        const item = await findBlockedForDomain(domain, {
          startIso: msg.startIso,
          endIso: msg.endIso,
          seconds: msg.seconds,
          retryMs: msg.retryMs,
        });
        sendResponse({ ok: true, item });
        return;
      }

      if (msg.action === "allowDomain") {
        const domain = normalizeDomain(msg.domain);
        if (!domain) {
          sendResponse({ error: "Invalid domain" });
          return;
        }

        await allowZone(domain);
        await deleteCachedZoneEverywhere(domain);
        sendResponse({ ok: true });
        return;
      }

      if (msg.action === "removeAllowDomain") {
        const domain = normalizeDomain(msg.domain);
        if (!domain) {
          sendResponse({ error: "Invalid domain" });
          return;
        }

        await deleteAllowedZone(domain);
        await deleteCachedZoneEverywhere(domain);
        sendResponse({ ok: true });
        return;
      }

      if (msg.action === "tempAllowDomain") {
        const domain = normalizeDomain(msg.domain);
        if (!domain) {
          sendResponse({ error: "Invalid domain" });
          return;
        }

        const minutesDefault = await getOptionNumber(
          TEMP_ALLOW_MINUTES_KEY,
          30,
        );
        const minutes = Math.max(1, Math.floor(msg.minutes || minutesDefault));

        await allowZone(domain);
        await deleteCachedZoneEverywhere(domain);

        const expiresTs = Date.now() + minutes * 60 * 1000;
        const state = await getTempAllowState();
        state[domain] = expiresTs;
        await setTempAllowState(state);

        const alarmName = `${TEMP_ALLOW_PREFIX}${domain}`;
        await chrome.alarms.clear(alarmName);
        await chrome.alarms.create(alarmName, { when: expiresTs });
        sendResponse({ ok: true, expiresTs });
        return;
      }

      if (msg.action === "allowedStatusBatch") {
        const domains = Array.isArray(msg.domains) ? msg.domains : [];
        const res = await allowedStatusBatch(domains);
        sendResponse({ ok: true, ...res });
        return;
      }

      sendResponse({ error: "Unknown action" });
    } catch (e) {
      sendResponse({ error: e.message || "Error" });
    }
  })();

  return true;
});
