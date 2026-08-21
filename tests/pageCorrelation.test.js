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
  tabs: { onRemoved: noopListener },
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

test("exact blocked-page lookup stays scoped to the detected client IP", async () => {
  const calls = [];

  const item = await worker.pollForBlockedDomain({
    domain: "blocked.example",
    clientIpAddress: "192.0.2.10",
    nodes: ["dns-01", "dns-02"],
    queryLogger: { name: "Query Logs (Sqlite)", classPath: "QueryLogsSqlite.App" },
    startIso: "2026-08-21T15:00:00.000Z",
    endIso: "2026-08-21T15:01:00.000Z",
    timeoutMs: 0,
    queryLogsFn: async (params) => {
      calls.push(params);
      return { response: { entries: [] } };
    },
  });

  assert.equal(item, null);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].clientIpAddress, "192.0.2.10");
  assert.equal(calls[1].clientIpAddress, "192.0.2.10");
});
