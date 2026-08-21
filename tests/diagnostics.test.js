import test from "node:test";
import assert from "node:assert/strict";

import {
  sanitizeDiagnosticUrl,
  sanitizeDiagnosticValue,
  formatDiagnosticReport,
  diagnosePageCorrelation,
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
