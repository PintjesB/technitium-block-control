function lower(value) {
  return String(value ?? "").toLowerCase();
}

function isBlocked(entry) {
  return entry?.blocked === true || lower(entry?.responseType).includes("blocked") || lower(entry?.rcode).includes("nxdomain");
}

function isServerFailure(entry) {
  return lower(entry?.rcode) === "serverfailure" || lower(entry?.rcode) === "servfail";
}

function sameLocation(a, b) {
  if (!a || !b) return false;
  return a.clientIpAddress === b.clientIpAddress && (a.node ?? null) === (b.node ?? null);
}

function reachableNode(node) {
  const state = lower(node?.state);
  return state === "self" || state === "connected" || state === "online";
}

function flattenExactEntries(report) {
  return (report?.technitium?.exactPageQuery?.perNode || []).flatMap((result) =>
    result?.ok ? result.entries || [] : [],
  );
}

function originOutcomes(report) {
  return report?.technitium?.dnsOriginTrace?.summary?.outcomes || [];
}

function uniqueQtypes(report) {
  const qtypes = [];
  const seen = new Set();
  const add = (qtype) => {
    const value = qtype ? String(qtype) : null;
    if (!value || seen.has(value)) return;
    seen.add(value);
    qtypes.push(value);
  };

  for (const entry of flattenExactEntries(report)) add(entry?.qtype);
  for (const entry of originOutcomes(report)) add(entry?.qtype);
  return qtypes;
}

function dnsRecords(report) {
  const currentEntries = flattenExactEntries(report);
  const origins = originOutcomes(report);

  return uniqueQtypes(report).map((qtype) => ({
    qtype,
    origin: origins.find((entry) => String(entry?.qtype) === qtype) || null,
    current: currentEntries.find((entry) => String(entry?.qtype) === qtype) || null,
  }));
}

function overallDiagnosis(report, records) {
  const technitium = report?.technitium || {};
  const queryApp = technitium?.queryLogsApp?.effective;
  const location = technitium?.client?.effectiveLocation;
  const exactResults = technitium?.exactPageQuery?.perNode || [];

  if (!report?.page?.resolvedHost) {
    return {
      status: "error",
      title: "Page could not be identified",
      detail: "The extension could not determine an HTTP(S) hostname for the current navigation.",
    };
  }

  if (!queryApp?.name || !queryApp?.classPath) {
    return {
      status: "error",
      title: "Query Logs unavailable",
      detail: "No queryable Technitium Query Logs application is available.",
    };
  }

  if (!location?.clientIpAddress) {
    return {
      status: "error",
      title: "Client detection failed",
      detail: "The extension could not determine the current client IP and Technitium node.",
    };
  }

  if (exactResults.length > 0 && exactResults.every((result) => !result?.ok)) {
    return {
      status: "error",
      title: "Query Logs request failed",
      detail: "Every Technitium node failed the exact page-domain query.",
    };
  }

  if (records.some((record) => isBlocked(record.current))) {
    return {
      status: "blocked",
      title: "Blocked by Technitium",
      detail: "Technitium returned a block-list response for the current page hostname.",
    };
  }

  if (
    records.some(
      (record) => isServerFailure(record.origin) || isServerFailure(record.current),
    )
  ) {
    return {
      status: "warning",
      title: "DNS resolution failure",
      detail: "Technitium received the page query, but recursive DNS resolution returned SERVFAIL.",
    };
  }

  const decision = report?.decision?.code;
  if (decision === "no-exact-query-log-entry") {
    return {
      status: "neutral",
      title: "No matching DNS query",
      detail: "No exact query-log entry was found for this page and client in the diagnostic window.",
    };
  }

  if (decision === "classification-mismatch") {
    return {
      status: "warning",
      title: "DNS response not classified",
      detail: "Technitium returned the page query, but it did not match a known block or resolution-failure state.",
    };
  }

  return {
    status: "ok",
    title: "DNS path looks healthy",
    detail: "No blocking or DNS-resolution failure was detected for the current page query.",
  };
}

function buildEvidence(report, records, overall) {
  const evidence = [];
  const host = report?.page?.resolvedHost;
  const client = report?.technitium?.client?.effectiveLocation;
  const exactEntries = flattenExactEntries(report);

  if (host) evidence.push(`Browser navigation resolved to ${host}.`);
  if (client?.clientIpAddress) {
    evidence.push(
      `Technitium client is ${client.clientIpAddress}${client.node ? ` on ${client.node}` : ""}.`,
    );
  }
  if (exactEntries.length > 0) {
    evidence.push(`Technitium returned ${exactEntries.length} exact page-domain query-log entr${exactEntries.length === 1 ? "y" : "ies"}.`);
  }

  if (overall.title === "DNS resolution failure") {
    evidence.push("Technitium did not report a block-list response for the failing page query.");
    for (const record of records) {
      if (isServerFailure(record.origin)) {
        evidence.push(`${record.qtype} originated as ${record.origin.responseType || "Unknown"} / ${record.origin.rcode || "Unknown"}.`);
      }
    }
  }

  if (overall.title === "Blocked by Technitium") {
    evidence.push("At least one exact page-domain entry was classified as blocked by Technitium.");
  }

  return evidence;
}

function likelyCause(overall) {
  switch (overall.title) {
    case "DNS resolution failure":
      return {
        kind: "inference",
        label: "DNS recursion/upstream failure",
        detail: "The query reached Technitium, but the resolver path failed before a usable DNS answer was produced.",
      };
    case "Blocked by Technitium":
      return {
        kind: "confirmed",
        label: "Technitium blocking",
        detail: "The query log contains a Technitium block-list response.",
      };
    case "Query Logs request failed":
      return {
        kind: "confirmed",
        label: "Technitium API/query-log failure",
        detail: "The extension could not query the relevant Technitium nodes.",
      };
    default:
      return {
        kind: "unknown",
        label: "No single cause identified",
        detail: "Use the stage details or Deep DNS test if the page still does not behave as expected.",
      };
  }
}

export function buildDebugViewModel(report = {}) {
  const cluster = report?.technitium?.cluster || {};
  const clusterNodes = Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const cachedLocation = report?.technitium?.client?.cached?.location || null;
  const freshLocation = report?.technitium?.client?.freshProbe?.location || null;
  const effectiveLocation = report?.technitium?.client?.effectiveLocation || null;
  const records = dnsRecords(report);
  const overall = overallDiagnosis(report, records);

  const model = {
    overall,
    page: {
      host: report?.page?.resolvedHost || null,
      source: report?.page?.resolvedSource || null,
      navigationError: report?.navigation?.failedNavigation?.error || null,
      navigationAgeMs: report?.navigation?.failedNavigation?.ageMs ?? null,
      snapshotOk: report?.page?.snapshot?.ok === true,
    },
    client: {
      effective: effectiveLocation,
      cached: cachedLocation,
      cachedValid: report?.technitium?.client?.cached?.valid === true,
      cachedAgeMs: report?.technitium?.client?.cached?.ageMs ?? null,
      fresh: freshLocation,
      freshOk: report?.technitium?.client?.freshProbe?.ok === true,
      cachedMatchesFresh: sameLocation(cachedLocation, freshLocation),
    },
    cluster: {
      initialized: cluster.initialized === true,
      primaryNode: cluster.primaryNode || null,
      total: clusterNodes.length,
      reachable: clusterNodes.filter(reachableNode).length,
      nodes: clusterNodes,
      discoveryError: cluster.discoveryError || null,
    },
    queryLogs: {
      app: report?.technitium?.queryLogsApp?.effective || null,
      discoveryError: report?.technitium?.queryLogsApp?.discoveryError || null,
    },
    dnsRecords: records,
    nodeResults: report?.technitium?.exactPageQuery?.perNode || [],
    timings: report?.timings || {},
    decision: report?.decision || null,
  };

  model.likelyCause = likelyCause(overall);
  model.evidence = buildEvidence(report, records, overall);

  model.stages = [
    {
      id: "page",
      label: "Page",
      status: model.page.host ? "ok" : "error",
      value: model.page.host || "Unknown",
      detail: model.page.navigationError || model.page.source || null,
      durationMs: model.timings.pageMs ?? null,
    },
    {
      id: "client",
      label: "Client",
      status: model.client.effective?.clientIpAddress ? (model.client.cachedMatchesFresh || !model.client.cached ? "ok" : "warning") : "error",
      value: model.client.effective?.clientIpAddress || "Not detected",
      detail: model.client.effective?.node || "Local node",
      durationMs: model.timings.clientProbeMs ?? null,
    },
    {
      id: "cluster",
      label: "Cluster",
      status: model.cluster.discoveryError ? "error" : model.cluster.reachable === model.cluster.total ? "ok" : "warning",
      value: `${model.cluster.reachable}/${model.cluster.total || 0} reachable`,
      detail: model.cluster.primaryNode ? `Primary: ${model.cluster.primaryNode}` : null,
      durationMs: model.timings.clusterMs ?? null,
    },
    {
      id: "queryLogs",
      label: "Query Logs",
      status: model.queryLogs.app ? "ok" : "error",
      value: model.queryLogs.app?.name || "Unavailable",
      detail: model.queryLogs.discoveryError || null,
      durationMs: model.timings.queryLogsAppMs ?? null,
    },
    {
      id: "dns",
      label: "DNS result",
      status: overall.status,
      value: overall.title,
      detail: records.length ? records.map((record) => `${record.qtype}: ${record.current?.rcode || record.origin?.rcode || "Unknown"}`).join(" · ") : null,
      durationMs: model.timings.exactQueryMs ?? null,
    },
  ];

  return model;
}

function recordChain(record) {
  const part = (entry) => entry ? `${entry.responseType || "Unknown"}/${entry.rcode || "Unknown"}` : null;
  const origin = part(record.origin);
  const current = part(record.current);
  if (origin && current && origin !== current) return `${origin} -> ${current}`;
  return current || origin || "No result";
}

export function formatShortDebugSummary(view, report = {}) {
  const lines = [
    "Technitium Adblock Control Debug",
    `Diagnosis: ${view?.overall?.title || "Unknown"}`,
    `Page: ${view?.page?.host || "Unknown"}`,
  ];

  if (view?.page?.navigationError) lines.push(`Navigation: ${view.page.navigationError}`);
  if (view?.client?.effective?.clientIpAddress) lines.push(`Client: ${view.client.effective.clientIpAddress}`);
  if (view?.client?.effective?.node) lines.push(`Node: ${view.client.effective.node}`);
  lines.push(`Cluster: ${view?.cluster?.reachable ?? 0}/${view?.cluster?.total ?? 0} reachable`);
  if (view?.queryLogs?.app?.name) lines.push(`Query Logs: ${view.queryLogs.app.name}`);

  if (view?.dnsRecords?.length) {
    lines.push("DNS:");
    for (const record of view.dnsRecords) lines.push(`- ${record.qtype}: ${recordChain(record)}`);
  }

  if (view?.likelyCause?.label) {
    lines.push(`Likely cause (${view.likelyCause.kind}): ${view.likelyCause.label}`);
  }
  if (report?.meta?.correlationId) lines.push(`Correlation: ${report.meta.correlationId}`);
  return lines.join("\n");
}

export function buildDeepDnsPlan(report = {}) {
  const qtypes = uniqueQtypes(report);
  const selectedQtypes = (qtypes.length ? qtypes : ["A"]).slice(0, 3);

  return {
    domain: report?.page?.resolvedHost || null,
    node: report?.technitium?.client?.effectiveLocation?.node || null,
    qtypes: selectedQtypes,
    resolvers: [
      { id: "this-server", label: "This Technitium server", server: "this-server", protocol: "UDP" },
      { id: "cloudflare-udp", label: "Cloudflare UDP", server: "1.1.1.1", protocol: "UDP" },
      { id: "cloudflare-doh", label: "Cloudflare DoH", server: "https://cloudflare-dns.com/dns-query", protocol: "HTTPS" },
      { id: "google-doh", label: "Google DoH", server: "https://dns.google/dns-query", protocol: "HTTPS" },
    ],
  };
}

function getRcode(result) {
  return (
    result?.RCODE ??
    result?.rcode ??
    result?.Header?.RCODE ??
    result?.Header?.rcode ??
    result?.header?.RCODE ??
    result?.header?.rcode ??
    null
  );
}

function getAnswers(result) {
  const answers = result?.Answer ?? result?.answer ?? [];
  return Array.isArray(answers) ? answers : [];
}

function recordName(record) {
  return record?.Name ?? record?.name ?? "";
}

function recordType(record) {
  return record?.Type ?? record?.type ?? "";
}

function rdataText(value) {
  if (value == null) return "";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (typeof value !== "object") return String(value);

  const preferred = ["IPAddress", "ipAddress", "Domain", "domain", "NameServer", "nameServer", "Target", "target", "Value", "value"];
  for (const key of preferred) {
    if (value[key] != null) return String(value[key]);
  }

  const primitiveValues = Object.values(value).filter(
    (item) => typeof item === "string" || typeof item === "number",
  );
  return primitiveValues.slice(0, 3).join(" ");
}

function formatAnswer(record) {
  return [recordName(record), recordType(record), rdataText(record?.RDATA ?? record?.rdata)]
    .filter(Boolean)
    .join(" ");
}

export function summarizeDnsClientResponse(response = {}) {
  const payload = response?.response || response;
  const result = payload?.result || payload?.Result || payload;
  const rcode = getRcode(result);
  const answers = getAnswers(result).map(formatAnswer).filter(Boolean).slice(0, 10);
  const warning = payload?.warningMessage ?? payload?.WarningMessage ?? null;

  return {
    ok: lower(rcode) === "noerror",
    rcode: rcode ?? "Unknown",
    answerCount: getAnswers(result).length,
    answers,
    warning,
  };
}
