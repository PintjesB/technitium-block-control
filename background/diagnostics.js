const SENSITIVE_KEY_RE = /(api.?key|token|authorization|password|secret|credential)/i;

function sanitizeDiagnosticString(value) {
  return String(value)
    .replace(
      /([?&](?:token|api(?:_|-)?key)=)[^&#\s]*/gi,
      "$1[REDACTED]",
    )
    .replace(
      /(Authorization\s*:\s*Bearer\s+)[^\s,;]+/gi,
      "$1[REDACTED]",
    )
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]");
}

export function sanitizeDiagnosticUrl(value) {
  if (typeof value !== "string" || !value) return null;

  try {
    const url = new URL(value);
    return {
      scheme: url.protocol.replace(/:$/, ""),
      host: url.hostname || null,
      hasQuery: url.search.length > 0,
      hasFragment: url.hash.length > 0,
    };
  } catch {
    return {
      scheme: null,
      host: null,
      hasQuery: false,
      hasFragment: false,
      rawType: sanitizeDiagnosticString(value).slice(0, 120),
    };
  }
}

export function sanitizeDiagnosticValue(value, key = "") {
  if (SENSITIVE_KEY_RE.test(String(key))) return "[REDACTED]";

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeDiagnosticValue(item));
  }

  if (value && typeof value === "object") {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      output[childKey] = sanitizeDiagnosticValue(childValue, childKey);
    }
    return output;
  }

  if (typeof value === "string") return sanitizeDiagnosticString(value);
  return value;
}

export function formatDiagnosticReport(report) {
  const sanitized = sanitizeDiagnosticValue(report || {});
  return [
    "Technitium Adblock Control Diagnostics",
    "Paste this complete report into the GitHub issue/chat used for debugging.",
    "Secrets are redacted and browser URLs are reduced by the collector.",
    "",
    JSON.stringify(sanitized, null, 2),
  ].join("\n");
}

export function diagnosePageCorrelation({
  pageHost,
  exactNodeResults = [],
  matchedInGeneralList = false,
}) {
  if (!pageHost) {
    return {
      code: "no-page-host",
      detail:
        "The extension could not resolve an HTTP(S) hostname for the active page/navigation.",
    };
  }

  const successful = exactNodeResults.filter((result) => result?.ok);
  if (exactNodeResults.length > 0 && successful.length === 0) {
    return {
      code: "exact-query-failed",
      detail:
        "Every Technitium node failed the exact page-domain query. Inspect the per-node errors.",
    };
  }

  const entries = successful.flatMap((result) => result.entries || []);
  if (entries.some((entry) => entry?.blocked === true)) {
    return {
      code: "backend-match",
      detail:
        "The exact page query returned a blocked entry. If the top list is empty, the remaining fault is in popup correlation/rendering.",
    };
  }

  if (entries.length > 0) {
    return {
      code: "classification-mismatch",
      detail:
        "Technitium returned exact page-domain entries, but none matched the extension's blocked-entry classification. Inspect responseType and rcode.",
    };
  }

  if (matchedInGeneralList) {
    return {
      code: "general-list-match-only",
      detail:
        "The page hostname matches the general blocked list, but the exact page-domain query returned no entries.",
    };
  }

  return {
    code: "no-exact-query-log-entry",
    detail:
      "Technitium returned no exact page-domain entry for the detected client and diagnostic time window.",
  };
}
