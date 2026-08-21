import test from "node:test";
import assert from "node:assert/strict";

import {
  sanitizeDiagnosticUrl,
  sanitizeDiagnosticValue,
  formatDiagnosticReport,
  diagnosePageCorrelation,
  traceNonCachedDnsOrigin,
  needsDnsOriginTrace,
  cachedServerFailureQtypes,
} from "../background/diagnostics.js";

test("diagnostic URL sanitization keeps routing context but removes query and fragment values", () => {
  assert.deepEqual(
    sanitizeDiagnosticUrl(
      "https://blocked.example/path?token=super-secret&next=/private#fragment",
    ),
    {
      scheme: "https",
      host: "blocked.example",
      hasQuery: true,
      hasFragment: true,
    },
  );
});

test("diagnostic sanitization redacts credentials recursively", () => {
  const sanitized = sanitizeDiagnosticValue({
    apiKey: "secret-api-key",
    nested: {
      token: "secret-token",
      authorization: "Bearer secret-bearer",
      message:
        "request failed: https://dns.example/api/logs/query?token=abc123&node=dns-01 Authorization: Bearer xyz",
    },
    harmless: "keep-me",
  });

  assert.equal(sanitized.apiKey, "[REDACTED]");
  assert.equal(sanitized.nested.token, "[REDACTED]");
  assert.equal(sanitized.nested.authorization, "[REDACTED]");
  assert.match(sanitized.nested.message, /token=\[REDACTED\]/);
  assert.match(sanitized.nested.message, /Bearer \[REDACTED\]/);
  assert.doesNotMatch(JSON.stringify(sanitized), /abc123|secret-api-key|secret-token|xyz/);
  assert.equal(sanitized.harmless, "keep-me");
});

test("formatted report is pasteable and cannot expose injected secrets", () => {
  const report = formatDiagnosticReport({
    meta: {
      correlationId: "diag-abc123",
      generatedAt: "2026-08-21T15:00:00.000Z",
    },
    browser: {
      tabUrl: "https://blocked.example/?token=url-secret",
    },
    injected: {
      apiKey: "api-secret",
      token: "token-secret",
    },
  });

  assert.match(report, /^Technitium Adblock Control Diagnostics/m);
  assert.match(report, /diag-abc123/);
  assert.match(report, /blocked\.example/);
  assert.doesNotMatch(report, /url-secret|api-secret|token-secret/);
});

test("diagnostic decision identifies a backend match", () => {
  assert.deepEqual(
    diagnosePageCorrelation({
      pageHost: "blocked.example",
      exactNodeResults: [
        {
          node: "dns-02",
          ok: true,
          entries: [
            {
              qname: "blocked.example",
              responseType: "Blocked",
              rcode: "NoError",
              blocked: true,
            },
          ],
        },
      ],
      matchedInGeneralList: false,
    }),
    {
      code: "backend-match",
      detail:
        "The exact page query returned a blocked entry. If the top list is empty, the remaining fault is in popup correlation/rendering.",
    },
  );
});

test("diagnostic decision distinguishes missing entries from classification mismatches", () => {
  assert.equal(
    diagnosePageCorrelation({
      pageHost: "blocked.example",
      exactNodeResults: [
        {
          node: "dns-01",
          ok: true,
          entries: [],
        },
      ],
      matchedInGeneralList: false,
    }).code,
    "no-exact-query-log-entry",
  );

  assert.equal(
    diagnosePageCorrelation({
      pageHost: "blocked.example",
      exactNodeResults: [
        {
          node: "dns-01",
          ok: true,
          entries: [
            {
              qname: "blocked.example",
              responseType: "Resolved",
              rcode: "Refused",
              blocked: false,
            },
          ],
        },
      ],
      matchedInGeneralList: false,
    }).code,
    "classification-mismatch",
  );
});

test("diagnostic decision reports when every exact-node query failed", () => {
  assert.equal(
    diagnosePageCorrelation({
      pageHost: "blocked.example",
      exactNodeResults: [
        { node: "dns-01", ok: false, error: "unreachable" },
        { node: "dns-02", ok: false, error: "forbidden" },
      ],
      matchedInGeneralList: false,
    }).code,
    "exact-query-failed",
  );
});

test("SERVFAIL origin trace skips cached pages and returns the nearest non-cached entry", async () => {
  const pages = [
    [
      { timestamp: "2026-08-21T16:33:36Z", responseType: "Cached", rcode: "ServerFailure" },
      { timestamp: "2026-08-21T16:33:35Z", responseType: "Cached", rcode: "ServerFailure" },
    ],
    [
      { timestamp: "2026-08-21T16:33:34Z", responseType: "Cached", rcode: "ServerFailure" },
      { timestamp: "2026-08-21T16:33:33Z", responseType: "Recursive", rcode: "ServerFailure" },
      { timestamp: "2026-08-21T16:33:32Z", responseType: "Recursive", rcode: "NoError" },
    ],
  ];
  const requestedPages = [];

  const result = await traceNonCachedDnsOrigin({
    fetchPage: async (pageNumber) => {
      requestedPages.push(pageNumber);
      return pages[pageNumber - 1] || [];
    },
    maxPages: 20,
  });

  assert.deepEqual(requestedPages, [1, 2]);
  assert.equal(result.found, true);
  assert.equal(result.pagesScanned, 2);
  assert.equal(result.cachedEntriesSkipped, 3);
  assert.deepEqual(result.entry, {
    timestamp: "2026-08-21T16:33:33Z",
    responseType: "Recursive",
    rcode: "ServerFailure",
  });
});

test("SERVFAIL origin trace stops when history is exhausted without a non-cached entry", async () => {
  const requestedPages = [];
  const result = await traceNonCachedDnsOrigin({
    fetchPage: async (pageNumber) => {
      requestedPages.push(pageNumber);
      if (pageNumber === 1) {
        return [{ responseType: "Cached", rcode: "ServerFailure" }];
      }
      return [];
    },
    maxPages: 20,
  });

  assert.deepEqual(requestedPages, [1, 2]);
  assert.deepEqual(result, {
    found: false,
    pagesScanned: 2,
    cachedEntriesSkipped: 1,
    exhausted: true,
    entry: null,
  });
});

test("origin tracing is limited to cached ServerFailure results", () => {
  assert.equal(
    needsDnsOriginTrace([
      {
        ok: true,
        entries: [{ responseType: "Cached", rcode: "ServerFailure" }],
      },
    ]),
    true,
  );

  assert.equal(
    needsDnsOriginTrace([
      {
        ok: true,
        entries: [{ responseType: "Cached", rcode: "NoError" }],
      },
    ]),
    false,
  );

  assert.equal(
    needsDnsOriginTrace([
      {
        ok: true,
        entries: [{ responseType: "Recursive", rcode: "ServerFailure" }],
      },
    ]),
    false,
  );
});

test("cached SERVFAIL qtypes are deduplicated and exclude unrelated outcomes", () => {
  assert.deepEqual(
    cachedServerFailureQtypes([
      { responseType: "Cached", rcode: "ServerFailure", qtype: "AAAA" },
      { responseType: "Cached", rcode: "ServerFailure", qtype: "A" },
      { responseType: "Cached", rcode: "ServerFailure", qtype: "AAAA" },
      { responseType: "Cached", rcode: "NoError", qtype: "HTTPS" },
      { responseType: "Recursive", rcode: "ServerFailure", qtype: "A" },
    ]),
    ["AAAA", "A"],
  );
});
