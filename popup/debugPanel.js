import { resolveDns } from "../background/technitiumApi.js";
import {
  formatDiagnosticReport,
  needsDnsOriginTrace,
  sanitizeDiagnosticValue,
} from "../background/diagnostics.js";
import {
  buildDebugViewModel,
  buildDeepDnsPlan,
  formatShortDebugSummary,
  summarizeDnsClientResponse,
} from "../background/debugView.js";
import { navigationErrorKey } from "../background/navigationDebug.js";

const runButton = document.getElementById("runDiagnostics");
const deepDnsButton = document.getElementById("deepDnsTest");
const clearCacheButton = document.getElementById("clearDebugCache");
const copySummaryButton = document.getElementById("copyDebugSummary");
const copyFullButton = document.getElementById("copyDiagnostics");
const rawDetails = document.getElementById("rawDebugDetails");
const output = document.getElementById("diagnosticsOutput");

const visualState = document.getElementById("debugVisualState");
const summaryEl = document.getElementById("debugSummary");
const stagesEl = document.getElementById("debugStages");
const dnsSection = document.getElementById("debugDnsSection");
const dnsRecordsEl = document.getElementById("debugDnsRecords");
const environmentSection = document.getElementById("debugEnvironmentSection");
const environmentEl = document.getElementById("debugEnvironment");
const evidenceSection = document.getElementById("debugEvidenceSection");
const likelyCauseEl = document.getElementById("debugLikelyCause");
const evidenceEl = document.getElementById("debugEvidence");
const deepDnsSection = document.getElementById("deepDnsSection");
const deepDnsResultsEl = document.getElementById("deepDnsResults");
const reportActions = document.getElementById("debugReportActions");

const DETECTION_CACHE_KEYS = [
  "clientLocation",
  "clientIpAddress",
  "clientIpDetectedAt",
  "queryLogsApp",
  "queryLoggerApp",
];

let latestReport = null;
let latestView = null;
let runStartedAt = null;
let enrichingNavigation = false;
let deepDnsRunning = false;

function parseDiagnosticReport(text) {
  if (typeof text !== "string") return null;
  const jsonStart = text.indexOf("{");
  if (jsonStart < 0) return null;

  try {
    return JSON.parse(text.slice(jsonStart));
  } catch {
    return null;
  }
}

function clearElement(element) {
  if (element) element.replaceChildren();
}

function textNode(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text ?? "";
  return element;
}

function setHidden(element, hidden) {
  if (element) element.hidden = !!hidden;
}

function fmtDuration(ms) {
  if (!Number.isFinite(ms)) return null;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}

function fmtAge(ms) {
  if (!Number.isFinite(ms) || ms < 0) return null;
  if (ms < 1000) return "just now";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m ago`;
  return `${(ms / 3_600_000).toFixed(1)}h ago`;
}

function statusSymbol(status) {
  switch (status) {
    case "ok":
      return "✓";
    case "blocked":
      return "⊘";
    case "warning":
      return "!";
    case "error":
      return "×";
    default:
      return "•";
  }
}

function responseLabel(entry) {
  if (!entry) return "No result";
  const responseType = entry.responseType || "Unknown";
  const rcode = entry.rcode || entry.RCODE || "Unknown";
  return `${responseType}/${rcode}`;
}

function addEnvironmentRow(label, value) {
  if (!environmentEl) return;
  const row = document.createElement("div");
  row.className = "debugEnvRow";
  row.append(
    textNode("div", "debugEnvLabel", label),
    textNode("div", "debugEnvValue", value ?? "—"),
  );
  environmentEl.appendChild(row);
}

function renderDiagnosis(view, report, waitingForOrigin) {
  if (!summaryEl) return;
  clearElement(summaryEl);
  summaryEl.className = `debugDiagnosis status-${view.overall.status}`;

  const title = document.createElement("div");
  title.className = "debugDiagnosisTitle";
  title.append(
    textNode("span", "", statusSymbol(view.overall.status)),
    textNode("span", "", view.overall.title),
  );

  summaryEl.append(
    title,
    textNode("div", "debugDiagnosisDetail", view.overall.detail),
  );

  const meta = [];
  if (report?.meta?.correlationId) meta.push(report.meta.correlationId);
  if (Number.isFinite(report?.uiDebugRuntimeMs)) {
    meta.push(`debug runtime ${fmtDuration(report.uiDebugRuntimeMs)}`);
  }
  if (waitingForOrigin) meta.push("tracing DNS origin…");
  if (meta.length) summaryEl.append(textNode("div", "debugMetaLine", meta.join(" · ")));

  setHidden(summaryEl, false);
}

function renderStages(view) {
  if (!stagesEl) return;
  clearElement(stagesEl);

  for (const stage of view.stages || []) {
    const card = document.createElement("div");
    card.className = `debugStage status-${stage.status}`;

    const header = document.createElement("div");
    header.className = "debugStageHeader";

    const label = document.createElement("div");
    label.className = "debugStageLabel";
    label.append(
      textNode("span", "debugDot", ""),
      textNode("span", "", stage.label),
    );
    header.appendChild(label);

    const duration = fmtDuration(stage.durationMs);
    if (duration) header.append(textNode("span", "debugStageTime", duration));

    card.append(
      header,
      textNode("div", "debugStageValue", stage.value),
    );
    if (stage.detail) card.append(textNode("div", "debugStageDetail", stage.detail));
    stagesEl.appendChild(card);
  }

  setHidden(stagesEl, false);
}

function renderDnsRecords(view, waitingForOrigin) {
  if (!dnsRecordsEl || !dnsSection) return;
  clearElement(dnsRecordsEl);

  const records = view.dnsRecords || [];
  if (records.length === 0) {
    if (waitingForOrigin) {
      dnsRecordsEl.append(textNode("div", "debugPlaceholder", "Tracing the non-cached DNS origin…"));
      setHidden(dnsSection, false);
    } else {
      setHidden(dnsSection, true);
    }
    return;
  }

  for (const record of records) {
    const row = document.createElement("div");
    row.className = "debugDnsRecord";
    row.append(textNode("span", "debugQtype", record.qtype));

    const body = document.createElement("div");
    body.className = "debugDnsChain";

    const origin = responseLabel(record.origin);
    const current = responseLabel(record.current);
    let chain = current;
    if (record.origin && record.current && origin !== current) chain = `${origin} → ${current}`;
    else if (record.origin && !record.current) chain = origin;

    body.append(textNode("div", "", chain));

    const answer = record.current?.answer ?? record.origin?.answer;
    if (answer) body.append(textNode("div", "debugDnsAnswer", String(answer)));

    row.appendChild(body);
    dnsRecordsEl.appendChild(row);
  }

  setHidden(dnsSection, false);
}

function renderEnvironment(view, report) {
  if (!environmentEl || !environmentSection) return;
  clearElement(environmentEl);

  addEnvironmentRow("Page source", view.page.source || "Unknown");
  if (view.page.navigationError) addEnvironmentRow("Browser error", view.page.navigationError);
  const navAge = fmtAge(view.page.navigationAgeMs);
  if (navAge) addEnvironmentRow("Navigation failure", navAge);

  const effective = view.client.effective;
  if (effective?.clientIpAddress) {
    addEnvironmentRow(
      "Client",
      `${effective.clientIpAddress}${effective.node ? ` · ${effective.node}` : ""}`,
    );
  }

  if (view.client.cached) {
    const cacheBits = [view.client.cachedValid ? "valid" : "stale"];
    const age = fmtAge(view.client.cachedAgeMs);
    if (age) cacheBits.push(age);
    if (view.client.fresh) {
      cacheBits.push(view.client.cachedMatchesFresh ? "matches fresh probe" : "differs from fresh probe");
    }
    addEnvironmentRow("Client cache", cacheBits.join(" · "));
  }

  const freshProbe = report?.technitium?.client?.freshProbe;
  if (freshProbe) {
    addEnvironmentRow(
      "Fresh probe",
      freshProbe.ok
        ? `OK${freshProbe.attempts ? ` · ${freshProbe.attempts} attempt${freshProbe.attempts === 1 ? "" : "s"}` : ""}`
        : `Failed · ${freshProbe.error || "no matching log entry"}`,
    );
  }

  addEnvironmentRow(
    "Cluster",
    `${view.cluster.reachable}/${view.cluster.total} reachable${view.cluster.primaryNode ? ` · primary ${view.cluster.primaryNode}` : ""}`,
  );

  for (const node of view.cluster.nodes || []) {
    addEnvironmentRow(
      node?.name || "Local node",
      [node?.type, node?.state].filter(Boolean).join(" · ") || "Unknown state",
    );
  }

  const queryApp = view.queryLogs.app;
  addEnvironmentRow(
    "Query Logs",
    queryApp ? `${queryApp.name} · ${queryApp.classPath}` : "Unavailable",
  );

  for (const result of view.nodeResults || []) {
    const count = Number(result?.entryCount ?? result?.entries?.length ?? 0);
    addEnvironmentRow(
      `Exact query · ${result?.node || "local"}`,
      result?.ok ? `${count} entr${count === 1 ? "y" : "ies"}` : `Error · ${result?.error || "unknown"}`,
    );
  }

  if (Number.isFinite(report?.uiDebugRuntimeMs)) {
    addEnvironmentRow("Debug runtime", fmtDuration(report.uiDebugRuntimeMs));
  }

  setHidden(environmentSection, false);
}

function renderEvidence(view) {
  if (!evidenceSection || !likelyCauseEl || !evidenceEl) return;
  clearElement(likelyCauseEl);
  clearElement(evidenceEl);

  const cause = view.likelyCause;
  if (cause) {
    const heading = `${cause.label} · ${cause.kind}`;
    likelyCauseEl.append(
      textNode("strong", "", heading),
      textNode("div", "", cause.detail || ""),
    );
  }

  for (const line of view.evidence || []) {
    evidenceEl.append(textNode("li", "", line));
  }

  setHidden(evidenceSection, false);
}

function showLoading(message = "Running debug… This may take up to 5 seconds.") {
  if (!visualState) return;
  clearElement(visualState);
  visualState.append(textNode("div", "debugPlaceholder", message));
  setHidden(summaryEl, true);
  setHidden(stagesEl, true);
  setHidden(dnsSection, true);
  setHidden(environmentSection, true);
  setHidden(evidenceSection, true);
  setHidden(deepDnsSection, true);
  setHidden(reportActions, true);
  setHidden(rawDetails, true);
  if (deepDnsButton) deepDnsButton.disabled = true;
}

function renderReport(report) {
  latestReport = report;
  latestView = buildDebugViewModel(report);

  const perNode = report?.technitium?.exactPageQuery?.perNode || [];
  const waitingForOrigin = needsDnsOriginTrace(perNode) && !report?.technitium?.dnsOriginTrace;

  clearElement(visualState);
  renderDiagnosis(latestView, report, waitingForOrigin);
  renderStages(latestView);
  renderDnsRecords(latestView, waitingForOrigin);
  renderEnvironment(latestView, report);
  renderEvidence(latestView);

  setHidden(reportActions, false);
  setHidden(rawDetails, false);
  if (copyFullButton) copyFullButton.hidden = false;
  if (deepDnsButton) {
    deepDnsButton.disabled =
      waitingForOrigin ||
      deepDnsRunning ||
      !report?.page?.resolvedHost ||
      !report?.technitium?.client?.effectiveLocation;
  }
}

async function navigationErrorForReport(report) {
  const tabId = report?.browser?.tabId;
  if (!Number.isInteger(tabId)) return null;

  const storage = chrome.storage.session || chrome.storage.local;
  const key = navigationErrorKey(tabId);
  const data = await storage.get(key);
  const state = data[key] || null;
  if (!state?.error) return null;

  const failed = report?.navigation?.failedNavigation;
  if (!failed) return state;

  const storedHost = (() => {
    try {
      return new URL(state.url).hostname.toLowerCase();
    } catch {
      return null;
    }
  })();
  const reportHost = failed?.url?.host ? String(failed.url.host).toLowerCase() : null;

  if (storedHost && reportHost && storedHost !== reportHost) return null;
  if (
    Number.isFinite(state.timeStamp) &&
    Number.isFinite(failed.timeStamp) &&
    Math.abs(state.timeStamp - failed.timeStamp) > 5_000
  ) {
    return null;
  }

  return state;
}

async function enrichNavigationError(report) {
  if (enrichingNavigation || report?.navigation?.failedNavigation?.error) return false;

  const state = await navigationErrorForReport(report);
  if (!state?.error || !report?.navigation?.failedNavigation) return false;

  report.navigation.failedNavigation.error = state.error;
  enrichingNavigation = true;
  try {
    output.textContent = formatDiagnosticReport(report);
  } finally {
    enrichingNavigation = false;
  }
  return true;
}

async function handleRawReportChange() {
  if (!output?.textContent) return;
  const report = parseDiagnosticReport(output.textContent);
  if (!report) return;

  if (runStartedAt && !Number.isFinite(report.uiDebugRuntimeMs)) {
    report.uiDebugRuntimeMs = Date.now() - runStartedAt;
  }

  if (await enrichNavigationError(report)) return;
  renderReport(report);
}

async function copyText(button, text) {
  if (!text) return;
  const original = button?.textContent || "Copy";
  try {
    await navigator.clipboard.writeText(text);
    if (button) button.textContent = "Copied";
  } catch {
    if (output) output.focus?.();
  } finally {
    if (button) {
      setTimeout(() => {
        button.textContent = original;
      }, 1200);
    }
  }
}

function renderDeepDnsResults(results, plan) {
  if (!deepDnsResultsEl || !deepDnsSection) return;
  clearElement(deepDnsResultsEl);

  for (const qtype of plan.qtypes) {
    const box = document.createElement("div");
    box.className = "deepDnsQtype";
    box.append(textNode("div", "deepDnsQtypeTitle", qtype));

    const rows = document.createElement("div");
    rows.className = "deepDnsRows";

    for (const resolver of plan.resolvers) {
      const result = results.find(
        (item) => item.qtype === qtype && item.resolverId === resolver.id,
      );
      const row = document.createElement("div");
      const status = result?.ok ? "ok" : result?.error ? "error" : "warning";
      row.className = `deepDnsRow deepDnsStatus-${status}`;

      const answer = result?.answers?.length
        ? result.answers[0]
        : result?.error || result?.warning || "No answer";

      row.append(
        textNode(
          "div",
          "deepDnsResolver",
          `${resolver.label}${Number.isFinite(result?.durationMs) ? ` · ${fmtDuration(result.durationMs)}` : ""}`,
        ),
        textNode("div", "deepDnsRcode", result?.rcode || "Pending"),
        textNode("div", "deepDnsAnswer", answer),
      );
      rows.appendChild(row);
    }

    box.appendChild(rows);
    deepDnsResultsEl.appendChild(box);
  }

  setHidden(deepDnsSection, false);
}

async function runDeepDnsTest() {
  if (!latestReport || deepDnsRunning || !deepDnsButton) return;

  const plan = buildDeepDnsPlan(latestReport);
  if (!plan.domain) return;

  deepDnsRunning = true;
  deepDnsButton.disabled = true;
  deepDnsButton.textContent = "Running Deep DNS…";
  setHidden(deepDnsSection, false);
  clearElement(deepDnsResultsEl);
  deepDnsResultsEl?.append(
    textNode(
      "div",
      "debugPlaceholder",
      `Testing ${plan.qtypes.length} record type${plan.qtypes.length === 1 ? "" : "s"} across ${plan.resolvers.length} resolver paths…`,
    ),
  );

  const jobs = [];
  for (const qtype of plan.qtypes) {
    for (const resolver of plan.resolvers) {
      jobs.push(
        (async () => {
          const startedAt = performance.now();
          try {
            const response = await resolveDns({
              server: resolver.server,
              domain: plan.domain,
              type: qtype,
              protocol: resolver.protocol,
              dnssec: false,
              node: plan.node || undefined,
            });
            return {
              resolverId: resolver.id,
              resolverLabel: resolver.label,
              server: resolver.server,
              protocol: resolver.protocol,
              qtype,
              durationMs: performance.now() - startedAt,
              ...summarizeDnsClientResponse(response),
            };
          } catch (error) {
            return {
              resolverId: resolver.id,
              resolverLabel: resolver.label,
              server: resolver.server,
              protocol: resolver.protocol,
              qtype,
              durationMs: performance.now() - startedAt,
              ok: false,
              rcode: "Error",
              answerCount: 0,
              answers: [],
              warning: null,
              error: sanitizeDiagnosticValue(error?.message || String(error)),
            };
          }
        })(),
      );
    }
  }

  try {
    const results = await Promise.all(jobs);
    latestReport.technitium.deepDnsTest = {
      generatedAt: new Date().toISOString(),
      domain: plan.domain,
      node: plan.node,
      qtypes: plan.qtypes,
      resolvers: plan.resolvers.map(({ id, label, server, protocol }) => ({
        id,
        label,
        server,
        protocol,
      })),
      results,
    };

    output.textContent = formatDiagnosticReport(latestReport);
    renderDeepDnsResults(results, plan);
  } finally {
    deepDnsRunning = false;
    deepDnsButton.textContent = "Deep DNS test";
    deepDnsButton.disabled = false;
  }
}

runButton?.addEventListener("click", () => {
  runStartedAt = Date.now();
  latestReport = null;
  latestView = null;
  showLoading();
});

deepDnsButton?.addEventListener("click", () => {
  runDeepDnsTest().catch((error) => {
    setHidden(deepDnsSection, false);
    clearElement(deepDnsResultsEl);
    deepDnsResultsEl?.append(
      textNode("div", "debugPlaceholder", `Deep DNS test failed: ${error?.message || error}`),
    );
    deepDnsRunning = false;
    deepDnsButton.disabled = false;
    deepDnsButton.textContent = "Deep DNS test";
  });
});

clearCacheButton?.addEventListener("click", async () => {
  clearCacheButton.disabled = true;
  try {
    await chrome.storage.local.remove(DETECTION_CACHE_KEYS);
    runButton?.click();
  } finally {
    clearCacheButton.disabled = false;
  }
});

copySummaryButton?.addEventListener("click", () => {
  if (!latestView || !latestReport) return;
  copyText(copySummaryButton, formatShortDebugSummary(latestView, latestReport));
});

if (output) {
  const observer = new MutationObserver(() => {
    handleRawReportChange().catch((error) =>
      console.warn("[TAC debug] Failed to render debug report:", error),
    );
  });
  observer.observe(output, {
    childList: true,
    characterData: true,
    subtree: true,
  });
}
