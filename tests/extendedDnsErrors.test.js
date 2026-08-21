import test from "node:test";
import assert from "node:assert/strict";

import { summarizeDnsClientResponse } from "../background/debugView.js";

test("generic Technitium EDE is surfaced when no DNSSEC-specific error exists", () => {
  const summary = summarizeDnsClientResponse({
    response: {
      result: {
        RCODE: "ServerFailure",
        Answer: [],
        EDNS: {
          Options: [
            {
              Code: "EXTENDED_DNS_ERROR",
              Data: {
                InfoCode: "NoReachableAuthority",
                ExtraText: "No valid response from name servers for example.test. A IN",
              },
            },
          ],
        },
      },
    },
  });

  assert.equal(
    summary.warning,
    "EDE: No Reachable Authority — No valid response from name servers for example.test. A IN",
  );
});
