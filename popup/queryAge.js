import { latestDnsQueryInfo } from "../background/debugTime.js";

const output = document.getElementById("diagnosticsOutput");
const environment = document.getElementById("debugEnvironment");
let updateTimer = null;

function parseDiagnosticReport(text) {
  if (typeof text !== "string") return null;
  const jsonStart = text.indexOf("{");
  if (jsonStart < 0) return null;
  try {
    return JSON.parse(text.slice(jsonStart));
  } catch {
    return null;
  }
}

function formatAge(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "unknown age";
  if (ms < 1000) return "just now";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m ago`;
  return `${(ms / 3_600_000).toFixed(1)}h ago`;
}

function formatTime(timestamp) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return timestamp;
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function renderLatestQuery() {
  if (!output || !environment) return;
  const report = parseDiagnosticReport(output.textContent);
  if (!report) return;

  environment.querySelector("#debugLatestQueryRow")?.remove();
  const info = latestDnsQueryInfo(report);
  if (!info) return;

  const row = document.createElement("div");
  row.id = "debugLatestQueryRow";
  row.className = "debugEnvRow";

  const label = document.createElement("div");
  label.className = "debugEnvLabel";
  label.textContent = "Latest DNS query";

  const value = document.createElement("div");
  value.className = "debugEnvValue";
  value.textContent = `${formatTime(info.timestamp)} · ${formatAge(info.ageMs)}`;

  row.append(label, value);
  environment.appendChild(row);
}

function scheduleRender() {
  if (updateTimer !== null) clearTimeout(updateTimer);
  updateTimer = setTimeout(() => {
    updateTimer = null;
    renderLatestQuery();
  }, 0);
}

if (output) {
  const observer = new MutationObserver(scheduleRender);
  observer.observe(output, {
    childList: true,
    characterData: true,
    subtree: true,
  });
}
