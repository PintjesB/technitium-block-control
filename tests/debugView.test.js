import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDebugViewModel,
  buildDeepDnsPlan,
  formatShortDebugSummary,
  summarizeDnsClientResponse,
} from "../background/debugView.js";

function baseReport() {
  return {
    meta: {
      correlationId: "diag-test",
      generatedAt: "2026-08-21T20:53:31.953Z",
      extensionVersion: "0.3.2",
    },
    navigation: {
      failedNavigation: {
        url: { scheme: "https", host: "fitgirl-repacks.site" },
        timeStamp: 1_000,
        ageMs: 6_000,
        error: "net::ERR_NAME_NOT_RESOLVED",
      },
    },
    page: {
      resolvedSource: "failedNavigation",
      resolvedHost: "fitgirl-repacks.site",
      snapshot: { ok: false, error: "Frame with ID 0 is showing error page" },
    },
    technitium: {
      cluster: {
        initialized: true,
        primaryNode: "technitium-01.home",
        nodes: [
          { name: "technitium-01.home", type: "Primary", state: "Self" },
          { name: "technitium-02.home", type: "Secondary", state: "Connected" },
        ],
      },
      queryLogsApp: {
        effective: { name: "Query Logs (Sqlite)", classPath: "QueryLogsSqlite.App" },
        discoveryError: null,
      },
      client: {
        cached: {
          location: { clientIpAddress: "192.168.100.158", node: "technitium-01.home" },
          valid: true,
          ageMs: 20_000,
        },
        freshProbe: {
          ok: true,
          location: { clientIpAddress: "192.168.100.158", node: "technitium-01.home" },
        },
        effectiveLocation: {
          clientIpAddress: "192.168.100.158",
          node: "technitium-01.home",
        },
      },
      exactPageQuery: {
        qname: "fitgirl-repacks.site",
        perNode: [
          {
            node: "technitium-01.home",
            ok: true,
            entries: [
              {
                qname: "fitgirl-repacks.site",
                qtype: "A",
                responseType: "Cached",
                rcode: "ServerFailure",
                blocked: false,
              },
              {
                qname: "fitgirl-repacks.site",
                qtype: "HTTPS",
                responseType: "Cached",
                rcode: "ServerFailure",
                blocked: false,
              },
            ],
          },
          { node: "technitium-02.home", ok: true, entries: [] },
        ],
      },
      dnsOriginTrace: {
        summary: {
          code: "origin-found",
          outcomes: [
            {
              node: "technitium-01.home",
              qtype: "A",
              responseType: "Recursive",
              rcode: "ServerFailure",
              answer: null,
            },
            {
              node: "technitium-01.home",
              qtype: "HTTPS",
              responseType: "Recursive",
              rcode: "ServerFailure",
              answer: null,
            },
          ],
        },
      },
    },
    timings: {
      clusterMs: 12,
      clientProbeMs: 155,
      exactQueryMs: 44,
      totalMs: 302,
    },
    decision: {
      code: "classification-mismatch",
      detail: "Exact entries exist but are not classified as blocked.",
    },
  };
}

test("visual debug model identifies recursive SERVFAIL as a DNS resolution failure", () => {
  const view = buildDebugViewModel(baseReport());

  assert.deepEqual(view.overall, {
    status: "warning",
    title: "DNS resolution failure",
    detail: "Technitium received the page query, but recursive DNS resolution returned SERVFAIL.",
  });

  assert.equal(view.page.host, "fitgirl-repacks.site");
  assert.equal(view.page.navigationError, "net::ERR_NAME_NOT_RESOLVED");
  assert.equal(view.client.cachedMatchesFresh, true);
  assert.equal(view.cluster.reachable, 2);
  assert.equal(view.cluster.total, 2);

  assert.deepEqual(
    view.dnsRecords.map((record) => ({
      qtype: record.qtype,
      origin: record.origin && `${record.origin.responseType}/${record.origin.rcode}`,
      current: record.current && `${record.current.responseType}/${record.current.rcode}`,
    })),
    [
      { qtype: "A", origin: "Recursive/ServerFailure", current: "Cached/ServerFailure" },
      { qtype: "HTTPS", origin: "Recursive/ServerFailure", current: "Cached/ServerFailure" },
    ],
  );

  assert.equal(view.likelyCause.label, "DNS recursion/upstream failure");
  assert.equal(view.likelyCause.kind, "inference");
  assert.ok(view.evidence.some((line) => /not report a block-list response/i.test(line)));
});

test("visual debug model identifies a real Technitium block", () => {
  const report = baseReport();
  report.page.resolvedHost = "ads.example";
  report.technitium.exactPageQuery.qname = "ads.example";
  report.technitium.exactPageQuery.perNode[0].entries = [
    {
      qname: "ads.example",
      qtype: "A",
      responseType: "Blocked",
      rcode: "NxDomain",
      blocked: true,
    },
  ];
  delete report.technitium.dnsOriginTrace;
  report.decision = { code: "backend-match", detail: "blocked" };

  const view = buildDebugViewModel(report);
  assert.equal(view.overall.status, "blocked");
  assert.equal(view.overall.title, "Blocked by Technitium");
  assert.equal(view.dnsRecords[0].current.responseType, "Blocked");
});

test("short debug summary contains the diagnosis and essential routing context", () => {
  const report = baseReport();
  const summary = formatShortDebugSummary(buildDebugViewModel(report), report);

  assert.match(summary, /DNS resolution failure/);
  assert.match(summary, /fitgirl-repacks\.site/);
  assert.match(summary, /192\.168\.100\.158/);
  assert.match(summary, /technitium-01\.home/);
  assert.match(summary, /A: Recursive\/ServerFailure -> Cached\/ServerFailure/);
  assert.match(summary, /HTTPS: Recursive\/ServerFailure -> Cached\/ServerFailure/);
  assert.doesNotMatch(summary, /apiKey|token=/i);
});

test("deep DNS plan tests the current server plus plaintext and encrypted external resolvers", () => {
  const plan = buildDeepDnsPlan(baseReport());

  assert.deepEqual(plan.qtypes, ["A", "HTTPS"]);
  assert.equal(plan.node, "technitium-01.home");
  assert.deepEqual(
    plan.resolvers.map(({ id, server, protocol }) => ({ id, server, protocol })),
    [
      { id: "this-server", server: "this-server", protocol: "UDP" },
      { id: "cloudflare-udp", server: "1.1.1.1", protocol: "UDP" },
      { id: "cloudflare-doh", server: "https://cloudflare-dns.com/dns-query", protocol: "HTTPS" },
      { id: "google-doh", server: "https://dns.google/dns-query", protocol: "HTTPS" },
    ],
  );
});

test("DNS client response summary extracts RCODE and answer data from Technitium result", () => {
  assert.deepEqual(
    summarizeDnsClientResponse({
      response: {
        result: {
          RCODE: "NoError",
          Answer: [
            { Name: "example.com", Type: "A", RDATA: { IPAddress: "192.0.2.10" } },
          ],
        },
      },
    }),
    {
      ok: true,
      rcode: "NoError",
      answerCount: 1,
      answers: ["example.com A 192.0.2.10"],
      warning: null,
    },
  );
});
