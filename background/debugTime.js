export function latestDnsQueryInfo(report, now = Date.now()) {
  const entries = (report?.technitium?.exactPageQuery?.perNode || []).flatMap(
    (result) => (result?.ok ? result.entries || [] : []),
  );

  let latest = null;
  let latestMs = -Infinity;

  for (const entry of entries) {
    if (!entry?.timestamp) continue;
    const parsed = Date.parse(entry.timestamp);
    if (!Number.isFinite(parsed) || parsed <= latestMs) continue;
    latestMs = parsed;
    latest = entry.timestamp;
  }

  if (!latest || !Number.isFinite(latestMs)) return null;

  return {
    timestamp: latest,
    ageMs: Math.max(0, now - latestMs),
  };
}
