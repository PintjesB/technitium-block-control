import test from "node:test";
import assert from "node:assert/strict";

import { latestDnsQueryInfo } from "../background/debugTime.js";

test("latest DNS query info returns newest exact-query timestamp and age", () => {
  const report = {
    technitium: {
      exactPageQuery: {
        perNode: [
          {
            ok: true,
            entries: [
              { timestamp: "2026-08-21T20:53:20.000Z" },
              { timestamp: "2026-08-21T20:53:24.700Z" },
            ],
          },
          {
            ok: true,
            entries: [{ timestamp: "2026-08-21T20:53:22.000Z" }],
          },
        ],
      },
    },
  };

  assert.deepEqual(
    latestDnsQueryInfo(report, Date.parse("2026-08-21T20:53:31.000Z")),
    {
      timestamp: "2026-08-21T20:53:24.700Z",
      ageMs: 6300,
    },
  );
});

test("latest DNS query info ignores invalid or missing timestamps", () => {
  assert.equal(
    latestDnsQueryInfo(
      {
        technitium: {
          exactPageQuery: {
            perNode: [{ ok: true, entries: [{ timestamp: "not-a-date" }] }],
          },
        },
      },
      Date.now(),
    ),
    null,
  );
});
