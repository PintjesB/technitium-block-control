import { queryLogs } from "../background/technitiumApi.js";
import {
  cachedServerFailureQtypes,
  formatDiagnosticReport,
  needsDnsOriginTrace,
  sanitizeDiagnosticValue,
  traceNonCachedDnsOrigin,
} from "../background/diagnostics.js";

const TRACE_LOOKBACK_MS = 30 * 60 * 1000;
const TRACE_MAX_PAGES = 20;
const TRACE_ENTRIES_PER_PAGE = 200;

const output = document.getElementById("diagnosticsOutput");
const copyButton = document.getElementById("copyDiagnostics");

let tracing = false;

function normalizeDomain(value) {
  if (!value) return null;
  return String(value).trim().toLowerCase().replace(/\.$/, "");
}

function isBlockedEntry(entry) {
  const responseType = String(entry?.responseType || "").toLowerCase();
  const rcode = String(entry?.rcode || entry?.RCODE || "").toLowerCase();
  return responseType.includes("blocked") || rcode.includes("nxdomain");
}

function mapEntry(entry) {
  return {
    qname: normalizeDomain(entry?.qname),
    qtype: entry?.qtype ?? null,
    qclass: entry?.qclass ?? null,
    clientIpAddress: entry?.clientIpAddress || null,
    timestamp: entry?.timestamp || null,
    responseType: entry?.responseType ?? null,
    rcode: entry?.rcode ?? entry?.RCODE ?? null,
    answer: entry?.answer ?? null,
    blocked: isBlockedEntry(entry),
  };
}

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

function cachedServerFailureNodes(perNode = []) {
  return perNode
    .filter((result) =>
      (result?.entries || []).some((entry) => {
        const responseType = String(entry?.responseType || "").toLowerCase();
        const rcode = String(entry?.rcode || "").toLowerCase();
        return responseType === "cached" && rcode === "serverfailure";
      }),
    )
    .map((result) => result.node)
    .filter(Boolean);
}

async function queryNodePage({
  node,
  queryApp,
  qname,
  qtype,
  clientIpAddress,
  startIso,
  endIso,
  pageNumber,
}) {
  const response = await queryLogs({
    name: queryApp.name,
    classPath: queryApp.classPath,
    pageNumber,
    entriesPerPage: TRACE_ENTRIES_PER_PAGE,
    descendingOrder: true,
    startIso,
    endIso,
    clientIpAddress,
    qname,
    qtype: qtype || undefined,
    node: node === "local" ? undefined : node,
  });

  return (response.response?.entries || []).map(mapEntry);
}

async function traceNodeOrigin({
  node,
  queryApp,
  qname,
  clientIpAddress,
  startIso,
  endIso,
}) {
  try {
    const newestEntries = await queryNodePage({
      node,
      queryApp,
      qname,
      qtype: null,
      clientIpAddress,
      startIso,
      endIso,
      pageNumber: 1,
    });

    const qtypes = cachedServerFailureQtypes(newestEntries);
    if (qtypes.length === 0) {
      return {
        node,
        ok: true,
        qtypes: [],
        traces: [],
        note:
          "The earlier diagnostic report contained cached SERVFAILs, but the fresh history query no longer returned any cached SERVFAIL qtypes.",
      };
    }

    const traces = await Promise.all(
      qtypes.map(async (qtype) => {
        const trace = await traceNonCachedDnsOrigin({
          maxPages: TRACE_MAX_PAGES,
          fetchPage: (pageNumber) =>
            queryNodePage({
              node,
              queryApp,
              qname,
              qtype,
              clientIpAddress,
              startIso,
              endIso,
              pageNumber,
            }),
        });

        return {
          qtype,
          ...trace,
        };
      }),
    );

    return {
      node,
      ok: true,
      qtypes,
      traces,
    };
  } catch (error) {
    return {
      node,
      ok: false,
      error: sanitizeDiagnosticValue(error?.message || String(error)),
      qtypes: [],
      traces: [],
    };
  }
}

function traceSummary(results) {
  const outcomes = results.flatMap((result) =>
    (result.traces || [])
      .filter((trace) => trace.found)
      .map((trace) => ({
        node: result.node,
        qtype: trace.qtype,
        responseType: trace.entry?.responseType ?? null,
        rcode: trace.entry?.rcode ?? null,
        timestamp: trace.entry?.timestamp ?? null,
        answer: trace.entry?.answer ?? null,
      })),
  );

  if (outcomes.length === 0) {
    return {
      code: "origin-not-found",
      detail:
        "Cached SERVFAIL entries were found, but no earlier non-cached DNS outcome was found within the bounded trace window.",
    };
  }

  return {
    code: "origin-found",
    detail:
      "The nearest earlier non-cached DNS outcome was found per affected qtype. Inspect responseType, rcode, and answer to identify what originally populated each cache failure.",
    outcomes,
  };
}

async function appendOriginTrace(report) {
  const exactPageQuery = report?.technitium?.exactPageQuery;
  const perNode = exactPageQuery?.perNode || [];
  if (!needsDnsOriginTrace(perNode)) return report;
  if (report?.technitium?.dnsOriginTrace) return report;

  const queryApp = report?.technitium?.queryLogsApp?.effective;
  const clientIpAddress = report?.technitium?.client?.effectiveLocation?.clientIpAddress;
  const qname = exactPageQuery?.qname;

  if (!queryApp?.name || !queryApp?.classPath || !clientIpAddress || !qname) {
    report.technitium.dnsOriginTrace = {
      triggered: true,
      error:
        "Origin tracing could not start because query-app, client-IP, or qname context is missing.",
    };
    return report;
  }

  const navigationFailedAt = Number(report?.page?.navigationFailedAt);
  const generatedAt = Date.parse(report?.meta?.generatedAt || "");
  const anchor = Number.isFinite(navigationFailedAt)
    ? navigationFailedAt
    : Number.isFinite(generatedAt)
      ? generatedAt
      : Date.now();

  const startIso = new Date(Math.max(0, anchor - TRACE_LOOKBACK_MS)).toISOString();
  const endIso = exactPageQuery?.window?.endIso || new Date().toISOString();
  const nodes = cachedServerFailureNodes(perNode);

  const results = await Promise.all(
    nodes.map((node) =>
      traceNodeOrigin({
        node,
        queryApp,
        qname,
        clientIpAddress,
        startIso,
        endIso,
      }),
    ),
  );

  report.technitium.dnsOriginTrace = {
    triggered: true,
    trigger: "Cached / ServerFailure",
    qname,
    clientIpAddress,
    window: {
      startIso,
      endIso,
      lookbackMinutes: TRACE_LOOKBACK_MS / 60_000,
    },
    limits: {
      maxPagesPerQtypePerNode: TRACE_MAX_PAGES,
      entriesPerPage: TRACE_ENTRIES_PER_PAGE,
    },
    perNode: results,
    summary: traceSummary(results),
  };

  return report;
}

async function maybeTraceCurrentReport() {
  if (!output || tracing) return;

  const report = parseDiagnosticReport(output.textContent);
  if (!report || report?.technitium?.dnsOriginTrace) return;

  const perNode = report?.technitium?.exactPageQuery?.perNode || [];
  if (!needsDnsOriginTrace(perNode)) return;

  tracing = true;
  const originalCopyText = copyButton?.textContent || "Copy report";
  if (copyButton) {
    copyButton.disabled = true;
    copyButton.textContent = "Tracing DNS origin...";
  }

  try {
    const traced = await appendOriginTrace(report);
    output.textContent = formatDiagnosticReport(traced);

    const correlationId = traced?.meta?.correlationId || "unknown";
    console.info(
      `[TAC diagnostics ${correlationId}] dns-origin-trace`,
      sanitizeDiagnosticValue(traced?.technitium?.dnsOriginTrace),
    );
  } finally {
    if (copyButton) {
      copyButton.disabled = false;
      copyButton.textContent = originalCopyText;
    }
    tracing = false;
  }
}

if (output) {
  const observer = new MutationObserver(() => {
    maybeTraceCurrentReport().catch((error) =>
      console.warn("[TAC diagnostics] DNS origin trace failed:", error),
    );
  });

  observer.observe(output, {
    childList: true,
    characterData: true,
    subtree: true,
  });
}
