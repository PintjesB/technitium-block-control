import test from "node:test";
import assert from "node:assert/strict";

const requests = [];

globalThis.chrome = {
  storage: {
    local: {
      get(_keys, callback) {
        callback({
          baseUrl: "https://dns.example.test:5380",
          apiKey: "secret-token",
        });
      },
    },
  },
};

globalThis.fetch = async (url, options) => {
  requests.push({ url: String(url), options });
  return {
    ok: true,
    async json() {
      return { status: "ok", response: {} };
    },
  };
};

const api = await import("../background/technitiumApi.js");

test.beforeEach(() => {
  requests.length = 0;
});

test("queryLogs routes the request to the requested cluster node", async () => {
  await api.queryLogs({
    name: "Query Logs (Sqlite)",
    classPath: "QueryLogger",
    node: "dns-02.example.test",
  });

  assert.equal(requests.length, 1);
  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/api/logs/query");
  assert.equal(url.searchParams.get("node"), "dns-02.example.test");
});

test("queryLogs preserves standalone behavior when node is omitted", async () => {
  await api.queryLogs({
    name: "Query Logs (Sqlite)",
    classPath: "QueryLogger",
  });

  const url = new URL(requests[0].url);
  assert.equal(url.searchParams.has("node"), false);
});

test("queryLogs can filter a DNS record type", async () => {
  await api.queryLogs({
    name: "Query Logs (Sqlite)",
    classPath: "QueryLogger",
    qname: "fitgirl-repacks.site",
    qtype: "AAAA",
  });

  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/api/logs/query");
  assert.equal(url.searchParams.get("qname"), "fitgirl-repacks.site");
  assert.equal(url.searchParams.get("qtype"), "AAAA");
});

test("DNS client resolve routes a deep-debug query through a selected node", async () => {
  assert.equal(typeof api.resolveDns, "function");

  await api.resolveDns({
    server: "https://cloudflare-dns.com/dns-query",
    domain: "fitgirl-repacks.site",
    type: "A",
    protocol: "HTTPS",
    dnssec: false,
    node: "dns-02.example.test",
  });

  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/api/dnsClient/resolve");
  assert.equal(url.searchParams.get("server"), "https://cloudflare-dns.com/dns-query");
  assert.equal(url.searchParams.get("domain"), "fitgirl-repacks.site");
  assert.equal(url.searchParams.get("type"), "A");
  assert.equal(url.searchParams.get("protocol"), "HTTPS");
  assert.equal(url.searchParams.get("dnssec"), "false");
  assert.equal(url.searchParams.get("node"), "dns-02.example.test");
});

test("getSessionInfo reads cluster metadata without admin-only APIs", async () => {
  assert.equal(typeof api.getSessionInfo, "function");

  await api.getSessionInfo();

  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/api/user/session/get");
  assert.equal(url.searchParams.has("node"), false);
});

test("cache deletion can target a specific cluster node", async () => {
  await api.deleteCachedZone("ads.example", "dns-02.example.test");

  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/api/cache/delete");
  assert.equal(url.searchParams.get("domain"), "ads.example");
  assert.equal(url.searchParams.get("node"), "dns-02.example.test");
});

test("allowed-zone reads can target the primary node", async () => {
  await api.listAllowed("ads.example", "dns-primary.example.test");

  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/api/allowed/list");
  assert.equal(url.searchParams.get("domain"), "ads.example");
  assert.equal(url.searchParams.get("node"), "dns-primary.example.test");
});
