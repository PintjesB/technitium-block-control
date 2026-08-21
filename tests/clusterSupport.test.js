// Regression coverage for cluster-aware query-log behavior.
import test from "node:test";
import assert from "node:assert/strict";

const noopListener = { addListener() {} };

globalThis.chrome = {
  runtime: {
    onInstalled: noopListener,
    onStartup: noopListener,
    onMessage: noopListener,
  },
  alarms: {
    onAlarm: noopListener,
    async clear() {},
    async create() {},
  },
  tabs: {
    onRemoved: noopListener,
  },
  webNavigation: {
    onErrorOccurred: noopListener,
    onCommitted: noopListener,
  },
  storage: {
    local: {
      async get() {
        return {};
      },
      async set() {},
      async remove() {},
    },
    session: {
      async get() {
        return {};
      },
      async set() {},
      async remove() {},
    },
  },
};

globalThis.fetch = async () => ({
  ok: true,
  async json() {
    return { status: "ok", response: {} };
  },
});

const worker = await import("../background/serviceWorker.js");

test("cluster topology retains every named node and the primary", () => {
  assert.equal(typeof worker.getClusterTopology, "function");

  const topology = worker.getClusterTopology({
    info: {
      clusterInitialized: true,
      clusterNodes: [
        { name: "dns-01", type: "Primary", state: "Self" },
        { name: "dns-02", type: "Secondary", state: "Connected" },
        { name: "dns-03", type: "Secondary", state: "Unreachable" },
      ],
    },
  });

  assert.deepEqual(topology.nodes, ["dns-01", "dns-02", "dns-03"]);
  assert.equal(topology.primaryNode, "dns-01");
  assert.equal(topology.clusterInitialized, true);
});

test("standalone topology keeps node routing disabled", () => {
  assert.equal(typeof worker.getClusterTopology, "function");
  assert.deepEqual(worker.getClusterTopology({ info: { clusterInitialized: false } }), {
    clusterInitialized: false,
    nodes: [null],
    primaryNode: null,
  });
});

test("query-log app selection skips logger-only apps", () => {
  assert.equal(typeof worker.selectQueryLogsApp, "function");

  const selected = worker.selectQueryLogsApp([
    {
      name: "Log Exporter",
      dnsApps: [
        {
          classPath: "LogExporter.App",
          isQueryLogger: true,
          isQueryLogs: false,
        },
      ],
    },
    {
      name: "Query Logs (Sqlite)",
      dnsApps: [
        {
          classPath: "QueryLogsSqlite.App",
          isQueryLogger: true,
          isQueryLogs: true,
        },
      ],
    },
  ]);

  assert.deepEqual(selected, {
    name: "Query Logs (Sqlite)",
    classPath: "QueryLogsSqlite.App",
  });
});

test("failed main-frame navigation overrides the previous committed tab URL", () => {
  assert.equal(typeof worker.resolvePageContext, "function");

  const failedAt = 10_000;
  const context = worker.resolvePageContext({
    tabUrl: "https://previous.example/",
    pendingUrl: undefined,
    failedNavigation: {
      url: "https://blocked.example/path",
      timeStamp: failedAt,
    },
    now: failedAt + 1_000,
  });

  assert.deepEqual(context, {
    url: "https://blocked.example/path",
    navigationFailedAt: failedAt,
  });
});

test("pending navigation takes precedence over an older failed navigation", () => {
  assert.equal(typeof worker.resolvePageContext, "function");

  const context = worker.resolvePageContext({
    tabUrl: "https://previous.example/",
    pendingUrl: "https://new.example/loading",
    failedNavigation: {
      url: "https://blocked.example/",
      timeStamp: 10_000,
    },
    now: 11_000,
  });

  assert.deepEqual(context, {
    url: "https://new.example/loading",
    navigationFailedAt: null,
  });
});

test("stale failed navigation does not override the current tab URL", () => {
  assert.equal(typeof worker.resolvePageContext, "function");

  const context = worker.resolvePageContext({
    tabUrl: "https://current.example/",
    failedNavigation: {
      url: "https://blocked.example/",
      timeStamp: 1_000,
    },
    now: 1_000 + 24 * 60 * 60 * 1000 + 1,
  });

  assert.deepEqual(context, {
    url: "https://current.example/",
    navigationFailedAt: null,
  });
});

test("blocked-domain lookup retries while the query logger flushes asynchronously", async () => {
  assert.equal(typeof worker.pollForBlockedDomain, "function");

  let clock = 0;
  let round = 0;
  const item = await worker.pollForBlockedDomain({
    domain: "blocked.example",
    nodes: ["dns-01", "dns-02"],
    queryLogger: { name: "Query Logs (Sqlite)", classPath: "QueryLogsSqlite.App" },
    startIso: new Date(0).toISOString(),
    endIso: new Date(60_000).toISOString(),
    now: () => clock,
    sleepFn: async (ms) => {
      clock += ms;
      round += 1;
    },
    timeoutMs: 1000,
    intervalMs: 200,
    queryLogsFn: async ({ node }) => {
      if (round >= 2 && node === "dns-02") {
        return {
          response: {
            entries: [
              {
                qname: "blocked.example",
                responseType: "Blocked",
                rcode: "NoError",
                timestamp: "2026-08-21T15:00:00Z",
              },
            ],
          },
        };
      }
      return { response: { entries: [] } };
    },
  });

  assert.deepEqual(item, {
    domain: "blocked.example",
    count: 1,
    lastSeen: "2026-08-21T15:00:00Z",
  });
  assert.equal(round, 2);
});

test("client detection surfaces an API error when every node query fails", async () => {
  assert.equal(typeof worker.pollForClientLocation, "function");

  await assert.rejects(
    () =>
      worker.pollForClientLocation({
        qname: "probe.example.com",
        nodes: ["dns-01", "dns-02"],
        queryLogger: { name: "Log Exporter", classPath: "LogExporter.App" },
        timeoutMs: 0,
        queryLogsFn: async () => {
          throw new Error(
            "DNS application 'LogExporter.App' class path was not found: Log Exporter",
          );
        },
      }),
    /class path was not found/,
  );
});

test("client detection searches every node and retries until the probe is logged", async () => {
  assert.equal(typeof worker.pollForClientLocation, "function");

  let clock = 0;
  let round = 0;
  const calls = [];

  const location = await worker.pollForClientLocation({
    qname: "probe.example.com",
    nodes: ["dns-01", "dns-02"],
    queryLogger: { name: "Query Logs", classPath: "Logger" },
    now: () => clock,
    sleepFn: async (ms) => {
      clock += ms;
      round += 1;
    },
    timeoutMs: 5000,
    intervalMs: 250,
    queryLogsFn: async ({ node }) => {
      calls.push({ round, node });
      if (round >= 2 && node === "dns-02") {
        return {
          response: {
            entries: [
              { qname: "probe.example.com", clientIpAddress: "192.0.2.10" },
            ],
          },
        };
      }
      return { response: { entries: [] } };
    },
  });

  assert.deepEqual(location, {
    clientIpAddress: "192.0.2.10",
    node: "dns-02",
  });
  assert.deepEqual(calls.slice(0, 4), [
    { round: 0, node: "dns-01" },
    { round: 0, node: "dns-02" },
    { round: 1, node: "dns-01" },
    { round: 1, node: "dns-02" },
  ]);
  assert.ok(clock < 5000);
});

test("client detection tolerates an unreachable cluster node", async () => {
  assert.equal(typeof worker.pollForClientLocation, "function");

  const location = await worker.pollForClientLocation({
    qname: "probe.example.com",
    nodes: ["dns-01", "dns-02"],
    queryLogger: { name: "Query Logs", classPath: "Logger" },
    timeoutMs: 0,
    queryLogsFn: async ({ node }) => {
      if (node === "dns-01") throw new Error("node unavailable");
      return {
        response: {
          entries: [
            { qname: "probe.example.com", clientIpAddress: "2001:db8::10" },
          ],
        },
      };
    },
  });

  assert.deepEqual(location, {
    clientIpAddress: "2001:db8::10",
    node: "dns-02",
  });
});

test("cached client location is invalid after its node leaves the topology", () => {
  assert.equal(typeof worker.isClientLocationCacheValid, "function");

  const location = { clientIpAddress: "192.0.2.10", node: "dns-01" };
  const detectedAt = 1_000;

  assert.equal(
    worker.isClientLocationCacheValid(
      location,
      detectedAt,
      { clusterInitialized: true, nodes: ["dns-01", "dns-02"] },
      2_000,
    ),
    true,
  );

  assert.equal(
    worker.isClientLocationCacheValid(
      location,
      detectedAt,
      { clusterInitialized: true, nodes: ["dns-02"] },
      2_000,
    ),
    false,
  );
});

test("client location cache expires after 24 hours", () => {
  assert.equal(typeof worker.isClientLocationCacheValid, "function");

  const location = { clientIpAddress: "192.0.2.10", node: null };
  const detectedAt = 1_000;
  const ttl = 24 * 60 * 60 * 1000;

  assert.equal(
    worker.isClientLocationCacheValid(
      location,
      detectedAt,
      { clusterInitialized: false, nodes: [null] },
      detectedAt + ttl + 1,
    ),
    false,
  );
});

test("failover redetects the client node when cached-node log queries stop matching", async () => {
  assert.equal(typeof worker.queryClientEntriesWithFailover, "function");

  const queryNodes = [];
  const detectionCalls = [];

  const result = await worker.queryClientEntriesWithFailover({
    location: { clientIpAddress: "192.0.2.10", node: "dns-01" },
    clusterInitialized: true,
    queryParams: { name: "Query Logs", classPath: "Logger" },
    queryLogsFn: async ({ node }) => {
      queryNodes.push(node);
      if (node === "dns-02") {
        return { response: { entries: [{ qname: "blocked.example" }] } };
      }
      return { response: { entries: [] } };
    },
    redetectFn: async () => {
      detectionCalls.push(true);
      return { clientIpAddress: "192.0.2.10", node: "dns-02" };
    },
  });

  assert.deepEqual(queryNodes, ["dns-01", "dns-02"]);
  assert.equal(detectionCalls.length, 1);
  assert.deepEqual(result.location, {
    clientIpAddress: "192.0.2.10",
    node: "dns-02",
  });
  assert.equal(result.entries.length, 1);
});
