import test from "node:test";
import assert from "node:assert/strict";

globalThis.chrome = {
  runtime: {
    onInstalled: { addListener() {} },
    onStartup: { addListener() {} },
    onMessage: { addListener() {} },
  },
  alarms: {
    onAlarm: { addListener() {} },
    async clear() {},
    async create() {},
  },
  storage: {
    local: {
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

test("cluster topology selects queryable nodes and the primary", () => {
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

  assert.deepEqual(topology.nodes, ["dns-01", "dns-02"]);
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

test("cached client location is invalid after its node leaves the queryable topology", () => {
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
