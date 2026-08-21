import "./serviceWorker.js";
import {
  createNavigationErrorState,
  navigationErrorKey,
} from "./navigationDebug.js";

function storageArea() {
  return chrome.storage.session || chrome.storage.local;
}

async function storeNavigationError(details) {
  if (details?.frameId !== 0 || !Number.isInteger(details?.tabId)) return;
  const state = createNavigationErrorState(details);
  if (!state) return;
  await storageArea().set({ [navigationErrorKey(details.tabId)]: state });
}

async function clearNavigationError(tabId) {
  if (!Number.isInteger(tabId)) return;
  await storageArea().remove(navigationErrorKey(tabId));
}

if (chrome.webNavigation?.onErrorOccurred?.addListener) {
  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    storeNavigationError(details).catch((error) =>
      console.warn("[Technitium] Failed to store navigation debug metadata:", error),
    );
  });
}

if (chrome.webNavigation?.onCommitted?.addListener) {
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    if (String(details.url || "").toLowerCase().startsWith("chrome-error://")) {
      return;
    }
    clearNavigationError(details.tabId).catch((error) =>
      console.warn("[Technitium] Failed to clear navigation debug metadata:", error),
    );
  });
}

if (chrome.tabs?.onRemoved?.addListener) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearNavigationError(tabId).catch((error) =>
      console.warn("[Technitium] Failed to clear closed-tab debug metadata:", error),
    );
  });
}
