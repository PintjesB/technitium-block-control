export const NAVIGATION_ERROR_PREFIX = "failedNavigationError::";

function isHttpUrl(value) {
  if (typeof value !== "string" || !value) return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function createNavigationErrorState(details, now = Date.now()) {
  if (!isHttpUrl(details?.url)) return null;

  return {
    url: details.url,
    timeStamp: Number.isFinite(details?.timeStamp) ? details.timeStamp : now,
    error: details?.error ? String(details.error) : null,
  };
}

export function navigationErrorKey(tabId) {
  return `${NAVIGATION_ERROR_PREFIX}${tabId}`;
}
