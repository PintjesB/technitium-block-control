import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDebugViewModel,
  buildDeepDnsPlan,
  formatShortDebugSummary,
  summarizeDeepDnsDiagnosis,
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
        url: { scheme: "https", host: "servfail.example.test" },
        timeStamp: 1_000,
        ageMs: 6_000,
        error: "net::ERR_NAME_NOT_RESOLVED",
      },
    },
    page: {
      resolvedSource: "failedNavigation",
      resolvedHost: "servfail.example.test",
      snapshot: { ok: false, error: "Frame with ID 0 is showing error page" },
    },
    technitium: {
      cluster: {
        initialized: true,
        primaryNode: "dns-primary.example.test",
        nodes: [
          { name: "dns-primary.example.test", type: "Primary", state: "Self" },
          { name: "dns-secondary.example.test", type: "Secondary", state: "Connected" },
        ],
      },
      queryLogsApp: {
        effective: { name: "Query Logs (Sqlite)", classPath: "QueryLogsSqlite.App" },
        discoveryError: null,
      },
      client: {
        cached: {
          location: { clientIpAddress: "192.0.2.44", node: "dns-primary.example.test" },
          valid: true,
          ageMs: 20_000,
        },
        freshProbe: {
          ok: true,
          location: { clientIpAddress: "192.0.2.44", node: "dns-primary.example.test" },
        },
        effectiveLocation: {
          clientIpAddress: "192.0.2.44",
          node: "dns-primary.example.test",
        },
      },
      exactPageQuery: {
        qname: "servfail.example.test",
        perNode: [
          {
            node: "dns-primary.example.test",
            ok: true,
            entries: [
              {
                qname: "servfail.example.test",
                responseType: "Cached",
                rcode: "ServerFailure",
                blocked: false,
              },
              {
                qname: "servfail.example.test",
                responseType: "Cached",
                rcode: "ServerFailure",
                blocked: false,
              },
            ],
          },
          { node: "dns-secondary.example.test", ok: true, entries: [] },
        ],
      },
      dnsOriginTrace: {
        summary: {
          code: "origin-found",
          outcomes: [
            {
              node: "dns-primary.example.test",
              qtype: "A",
              responseType: "Recursive",
              rcode: "ServerFailure",
              answer: null,
            },
            {
              node: "dns-primary.example.test",
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

function dnssecFailureDnsClientResponse() {
  const signatureExpired = {
    Code: "EXTENDED_DNS_ERROR",
    Data: {
      InfoCode: "SignatureExpired",
      ExtraText: "dnssec-broken.example.test DNSKEY IN",
    },
  };
  const noAuthority = {
    Code: "EXTENDED_DNS_ERROR",
    Data: {
      InfoCode: "NoReachableAuthority",
      ExtraText: "https://resolver.example/dns-query returned RCODE=ServerFailure for ns1.example.test. A IN",
    },
  };

  return {
    response: {
      result: {
        RCODE: "ServerFailure",
        Answer: [],
        EDNS: {
          ExtendedRCODE: "ServerFailure",
          Options: [signatureExpired, noAuthority],
        },
        DnsClientExtendedErrors: [
          {
            InfoCode: "SignatureExpired",
            ExtraText: "dnssec-broken.example.test DNSKEY IN",
          },
        ],
        Additional: [
          {
            Type: "OPT",
            RDATA: {
              Options: [signatureExpired, noAuthority],
            },
          },
        ],
      },
    },
  };
}

test("visual debug model reconstructs qtype chains from current raw diagnostics", () => {
  const view = buildDebugViewModel(baseReport());

  assert.deepEqual(view.overall, {
    status: "warning",
    title: "DNS resolution failure",
    detail: "Technitium received the page query, but recursive DNS resolution returned SERVFAIL.",
  });

  assert.equal(view.page.host, "servfail.example.test");
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

test("visual debug model identifies a real Technitium block without qtype metadata", () => {
  const report = baseReport();
  report.page.resolvedHost = "ads.example";
  report.technitium.exactPageQuery.qname = "ads.example";
  report.technitium.exactPageQuery.perNode[0].entries = [
    {
      qname: "ads.example",
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
  assert.equal(view.dnsRecords[0].qtype, "DNS");
  assert.equal(view.dnsRecords[0].current.responseType, "Blocked");
});

test("short debug summary contains the diagnosis and essential routing context", () => {
  const report = baseReport();
  const summary = formatShortDebugSummary(buildDebugViewModel(report), report);

  assert.match(summary, /DNS resolution failure/);
  assert.match(summary, /servfail\.example\.test/);
  assert.match(summary, /192\.0\.2\.44/);
  assert.match(summary, /dns-primary\.example\.test/);
  assert.match(summary, /A: Recursive\/ServerFailure -> Cached\/ServerFailure/);
  assert.match(summary, /HTTPS: Recursive\/ServerFailure -> Cached\/ServerFailure/);
  assert.doesNotMatch(summary, /apiKey|token=/i);
});

test("deep DNS plan tests the current server plus plaintext and encrypted external resolvers", () => {
  const plan = buildDeepDnsPlan(baseReport());

  assert.deepEqual(plan.qtypes, ["A", "HTTPS"]);
  assert.equal(plan.node, "dns-primary.example.test");
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
      extendedErrors: [],
    },
  );
});

test("DNS client response summary extracts and deduplicates Technitium EDEs", () => {
  const summary = summarizeDnsClientResponse(dnssecFailureDnsClientResponse());

  assert.equal(summary.ok, false);
  assert.equal(summary.rcode, "ServerFailure");
  assert.deepEqual(summary.extendedErrors, [
    {
      code: "SignatureExpired",
      label: "Signature Expired",
      text: "dnssec-broken.example.test DNSKEY IN",
      source: "response",
    },
    {
      code: "NoReachableAuthority",
      label: "No Reachable Authority",
      text: "https://resolver.example/dns-query returned RCODE=ServerFailure for ns1.example.test. A IN",
      source: "response",
    },
  ]);
});

test("deep DNS diagnosis promotes SignatureExpired above generic SERVFAIL", () => {
  const response = summarizeDnsClientResponse(dnssecFailureDnsClientResponse());
  const diagnosis = summarizeDeepDnsDiagnosis([
    {
      resolverId: "this-server",
      resolverLabel: "This Technitium server",
      qtype: "A",
      ...response,
    },
  ]);

  assert.deepEqual(diagnosis, {
    status: "error",
    title: "DNSSEC validation failure",
    detail: "Signature Expired — dnssec-broken.example.test DNSKEY IN",
    kind: "confirmed",
  });
});

test("short summary includes precise Deep DNS EDE diagnosis", () => {
  const report = baseReport();
  const response = summarizeDnsClientResponse(dnssecFailureDnsClientResponse());
  report.technitium.deepDnsTest = {
    results: [
      {
        resolverId: "this-server",
        resolverLabel: "This Technitium server",
        qtype: "A",
        ...response,
      },
    ],
  };

  const summary = formatShortDebugSummary(buildDebugViewModel(report), report);
  assert.match(summary, /Deep DNS: DNSSEC validation failure/);
  assert.match(summary, /Signature Expired — dnssec-broken\.example\.test DNSKEY IN/);
});
