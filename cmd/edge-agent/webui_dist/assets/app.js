(function () {
var COMPACT_THRESHOLD = 12;
var COLLAPSE_LIMIT = 12;
var MAX_ANIMATION_DELAY = 600;
var state = {
pollTimer: null,
loading: false,
connectPending: false,
latestAgent: null,
prevCounts: {},
expandedGroups: {},
};
var sourceLabels = {
local_runtime: "Local runtime",
discovery: "Discovery only",
historical: "Historical",
};
var groupTitles = {
available: "Available",
busy: "Busy",
error: "Error",
recently_disconnected: "Recently disconnected",
};
var controlLabels = {
connected: "Connected",
not_connected: "Not connected",
renew_key: "Renew key",
};
var groupBorderClass = {
available: "compact-row-available",
busy: "compact-row-busy",
error: "compact-row-error",
recently_disconnected: "compact-row-disconnected",
};
var dom = {
banner: document.getElementById("status-banner"),
availableCount: document.getElementById("available-count"),
busyCount: document.getElementById("busy-count"),
errorCount: document.getElementById("error-count"),
disconnectedCount: document.getElementById("disconnected-count"),
agentMeta: document.getElementById("agent-meta"),
scanMeta: document.getElementById("scan-meta"),
heroText: document.getElementById("hero-text"),
connectionChip: document.getElementById("connection-chip"),
connectionChipLabel: document.getElementById("connection-chip-label"),
scanChip: document.getElementById("scan-chip"),
scanChipLabel: document.getElementById("scan-chip-label"),
refreshButton: document.getElementById("refresh-button"),
connectPanel: document.getElementById("connect-panel"),
connectTitle: document.getElementById("connect-title"),
connectText: document.getElementById("connect-text"),
connectForm: document.getElementById("connect-form"),
connectInput: document.getElementById("api-key-input"),
connectButton: document.getElementById("connect-button"),
connectError: document.getElementById("connect-error"),
summaryGrid: document.getElementById("summary-grid"),
skeletonSummary: document.getElementById("skeleton-summary"),
board: document.getElementById("board"),
grids: {
available: document.getElementById("available-grid"),
busy: document.getElementById("busy-grid"),
error: document.getElementById("error-grid"),
recently_disconnected: document.getElementById("disconnected-grid"),
},
empties: {
available: document.getElementById("available-empty"),
busy: document.getElementById("busy-empty"),
error: document.getElementById("error-empty"),
recently_disconnected: document.getElementById("disconnected-empty"),
},
template: document.getElementById("printer-card-template"),
};
function init() {
dom.refreshButton.addEventListener("click", triggerScan);
dom.connectForm.addEventListener("submit", submitAPIKey);
loadObservations();
state.pollTimer = window.setInterval(loadObservations, 5000);
}
async function loadObservations() {
if (state.loading) {
return;
}
state.loading = true;
try {
var response = await fetch("/api/local/observations", { cache: "no-store" });
if (!response.ok) {
throw new Error("Observation request failed with status " + response.status);
}
var payload = await response.json();
state.latestAgent = payload.agent || null;
render(payload);
} catch (error) {
renderError(error);
} finally {
state.loading = false;
}
}
async function triggerScan() {
dom.refreshButton.disabled = true;
dom.refreshButton.classList.add("spinning");
try {
var response = await fetch("/api/local/observations/scan", {
method: "POST",
headers: {
"Content-Type": "application/json",
},
body: "{}",
});
if (!response.ok) {
throw new Error("Scan request failed with status " + response.status);
}
var payload = await response.json();
if (payload.status === "started" || payload.status === "in_progress") {
window.setTimeout(loadObservations, 350);
}
} catch (error) {
renderError(error);
} finally {
window.setTimeout(function () {
dom.refreshButton.disabled = false;
dom.refreshButton.classList.remove("spinning");
}, 600);
}
}
async function submitAPIKey(event) {
event.preventDefault();
if (state.connectPending) {
return;
}
var apiKey = dom.connectInput.value.trim();
var agent = state.latestAgent || {};
if (!apiKey) {
showConnectError("Paste a valid API key.");
return;
}
if (!agent.control_plane_url) {
showConnectError("Control plane URL is not configured for this edge-agent.");
return;
}
state.connectPending = true;
dom.connectButton.disabled = true;
hideConnectError();
try {
var response = await fetch("/api/local/control-plane/connect", {
method: "POST",
headers: {
"Content-Type": "application/json",
},
body: JSON.stringify({
saas_api_key: apiKey,
}),
});
if (!response.ok) {
var message = await response.text();
throw new Error(message || "Failed to connect edge-agent to SaaS.");
}
dom.connectInput.value = "";
await loadObservations();
} catch (error) {
showConnectError(error instanceof Error ? error.message : "Failed to connect edge-agent to SaaS.");
} finally {
state.connectPending = false;
dom.connectButton.disabled = false;
}
}
function hideSkeleton() {
if (!dom.skeletonSummary.classList.contains("hidden")) {
dom.skeletonSummary.classList.add("hidden");
}
}
function updateCount(el, newValue, key) {
var str = String(newValue);
if (el.textContent === str) {
return;
}
var prev = state.prevCounts[key];
el.textContent = str;
state.prevCounts[key] = newValue;
if (prev !== undefined && prev !== newValue) {
el.classList.add("count-flash");
window.setTimeout(function () {
el.classList.remove("count-flash");
}, 600);
}
if (key === "error" && newValue > 0) {
el.classList.add("error-pulse");
} else if (key === "error") {
el.classList.remove("error-pulse");
}
}
function render(payload) {
hideSkeleton();
var agent = payload.agent || {};
var summary = payload.summary || {};
var printers = Array.isArray(payload.printers) ? payload.printers : [];
var connected = agent.control_plane_status === "connected";
updateCount(dom.availableCount, summary.available_count || 0, "available");
updateCount(dom.busyCount, summary.busy_count || 0, "busy");
updateCount(dom.errorCount, summary.error_count || 0, "error");
updateCount(dom.disconnectedCount, summary.recently_disconnected_count || 0, "disconnected");
dom.agentMeta.textContent = connected ? "Connected edge-agent" : "Awaiting SaaS connection";
dom.scanMeta.textContent = describeScan(agent.scan);
renderControlState(agent);
renderScanChip(agent.scan, connected);
state.latestPrinters = printers;
renderGroups(printers);
dom.summaryGrid.classList.toggle("hidden", !connected);
dom.board.classList.toggle("hidden", !connected);
dom.connectPanel.classList.toggle("hidden", connected);
}
function renderError(error) {
hideSkeleton();
dom.banner.textContent = error instanceof Error ? error.message : "Unable to load local observations.";
dom.banner.className = "banner banner-error";
dom.banner.classList.remove("hidden");
dom.summaryGrid.classList.add("hidden");
dom.board.classList.add("hidden");
dom.connectPanel.classList.remove("hidden");
dom.connectPanel.dataset.status = "not_connected";
dom.connectionChip.dataset.status = "not_connected";
dom.connectionChipLabel.textContent = controlLabels.not_connected;
dom.heroText.textContent = "The local dashboard could not load agent state.";
dom.connectTitle.textContent = "Reconnect edge-agent";
dom.connectText.textContent = "Paste a valid API key to continue.";
dom.scanMeta.textContent = "Observation feed unavailable";
dom.scanChip.classList.add("hidden");
dom.refreshButton.classList.add("hidden");
}
function renderControlState(agent) {
var status = agent.control_plane_status || "not_connected";
dom.connectionChip.dataset.status = status;
dom.connectionChipLabel.textContent = controlLabels[status] || status;
if (status === "connected") {
dom.banner.className = "banner hidden";
dom.banner.textContent = "";
dom.heroText.textContent = "A clean read-only view of what this edge-agent can currently see on your network.";
hideConnectError();
return;
}
dom.banner.textContent = agent.control_plane_message || "Paste a valid API key to continue.";
dom.banner.className = "banner banner-" + status;
dom.banner.classList.remove("hidden");
if (status === "renew_key") {
dom.heroText.textContent = "The current API key was rejected. Renew the key to restore the printer dashboard.";
dom.connectPanel.dataset.status = "renew_key";
dom.connectTitle.textContent = "Renew edge-agent API key";
dom.connectText.textContent = agent.control_plane_message || "Paste a new API key to reconnect edge-agent to PrintFarmHQ SaaS.";
} else {
dom.heroText.textContent = "Edge-agent is not connected to PrintFarmHQ SaaS yet. Paste a valid API key to unlock the dashboard.";
dom.connectPanel.dataset.status = "not_connected";
dom.connectTitle.textContent = "Connect edge-agent to PrintFarmHQ SaaS";
dom.connectText.textContent = agent.control_plane_message || "Paste a valid API key to continue.";
}
}
function renderScanChip(scan, connected) {
var running = Boolean(scan && scan.running);
dom.scanChip.dataset.running = running ? "true" : "false";
dom.scanChipLabel.textContent = running ? "Scanning local network" : describeScan(scan);
dom.refreshButton.disabled = running;
dom.scanChip.classList.toggle("hidden", !connected);
dom.refreshButton.classList.toggle("hidden", !connected);
}
// --- Keyed diffing helpers ---
function printerKey(printer) {
return (printer.adapter_family || "") + "|" + (printer.endpoint_url || "");
}
function setText(parent, selector, value) {
var el = parent.querySelector(selector);
if (el && el.textContent !== value) {
el.textContent = value;
}
}
// --- Card rendering with DOM diffing ---
function updateCardInPlace(cardEl, printer) {
cardEl.dataset.group = printer.group || "";
var iconUse = cardEl.querySelector(".printer-icon use");
if (iconUse) {
var isBambu = printer.adapter_family && printer.adapter_family.toLowerCase() === "bambu";
var href = isBambu ? "#icon-printer-bambu" : "#icon-printer";
if (iconUse.getAttribute("href") !== href) {
iconUse.setAttribute("href", href);
}
}
setText(cardEl, ".printer-kicker", buildKicker(printer));
setText(cardEl, ".printer-name", printer.display_name || printer.endpoint_url);
var statusPill = cardEl.querySelector(".status-pill");
var statusText = groupTitles[printer.group] || "Observed";
if (statusPill.textContent !== statusText) {
statusPill.textContent = statusText;
}
statusPill.className = "status-pill status-" + printer.group;
setText(cardEl, ".printer-detail", buildDetail(printer));
setText(cardEl, ".badge-source", sourceLabels[printer.observation_source] || printer.observation_source || "Observed");
setText(cardEl, ".badge-host", printer.observed_host || "");
setText(cardEl, ".meta-last-seen", formatRelative(printer.last_seen_at));
setText(cardEl, ".meta-state", buildStateText(printer));
}
function renderCardGroup(grid, items) {
// Build a map of existing cards by key
var existingCards = {};
var childCards = grid.querySelectorAll(".printer-card[data-printer-key]");
for (var i = 0; i < childCards.length; i++) {
existingCards[childCards[i].dataset.printerKey] = childCards[i];
}
// Track which keys are still present
var activeKeys = {};
var newIndex = 0;
items.forEach(function (printer) {
var key = printerKey(printer);
activeKeys[key] = true;
var existing = existingCards[key];
if (existing) {
// Update in place — no animation reset
updateCardInPlace(existing, printer);
// Ensure order: move to end if needed
grid.appendChild(existing);
} else {
// New card — build and animate
var fragment = buildCard(printer);
var card = fragment.querySelector(".printer-card");
card.dataset.printerKey = key;
var delay = Math.min(newIndex * 50, MAX_ANIMATION_DELAY);
card.style.animationDelay = delay + "ms";
grid.appendChild(fragment);
newIndex++;
}
});
// Remove cards no longer in the list
for (var k in existingCards) {
if (!activeKeys[k]) {
existingCards[k].remove();
}
}
// Also remove any compact table that might have been here before
var oldTable = grid.querySelector(".compact-table");
if (oldTable) {
oldTable.remove();
}
grid.classList.remove("compact-grid");
grid.classList.add("card-grid");
}
// --- Compact table rendering with DOM diffing ---
function buildCompactRow(printer, groupName) {
var tr = document.createElement("tr");
tr.dataset.printerKey = printerKey(printer);
tr.className = groupBorderClass[groupName] || "";
var cells = [
{ cls: "compact-name", text: printer.display_name || printer.endpoint_url },
{ cls: "compact-type", text: buildKicker(printer) },
{ cls: "", text: groupTitles[printer.group] || "Observed", pill: true },
{ cls: "compact-col-state", text: buildStateText(printer) },
{ cls: "compact-col-source", text: sourceLabels[printer.observation_source] || printer.observation_source || "Observed" },
{ cls: "compact-col-lastseen", text: formatRelative(printer.last_seen_at) },
];
cells.forEach(function (c) {
var td = document.createElement("td");
if (c.pill) {
var span = document.createElement("span");
span.className = "status-pill status-" + printer.group;
span.textContent = c.text;
td.appendChild(span);
} else {
if (c.cls) {
td.className = c.cls;
}
td.textContent = c.text;
}
tr.appendChild(td);
});
return tr;
}
function updateRowInPlace(row, printer, groupName) {
var cells = row.children;
var values = [
printer.display_name || printer.endpoint_url,
buildKicker(printer),
groupTitles[printer.group] || "Observed",
buildStateText(printer),
sourceLabels[printer.observation_source] || printer.observation_source || "Observed",
formatRelative(printer.last_seen_at),
];
row.className = groupBorderClass[groupName] || "";
for (var i = 0; i < cells.length && i < values.length; i++) {
if (i === 2) {
// Status pill cell
var pill = cells[i].querySelector(".status-pill");
if (pill) {
if (pill.textContent !== values[i]) {
pill.textContent = values[i];
}
pill.className = "status-pill status-" + printer.group;
}
} else {
if (cells[i].textContent !== values[i]) {
cells[i].textContent = values[i];
}
}
}
}
function renderCompactGroup(grid, groupName, items) {
// Remove any existing cards (switching from card mode)
var existingCards = grid.querySelectorAll(".printer-card");
for (var c = 0; c < existingCards.length; c++) {
existingCards[c].remove();
}
grid.classList.remove("card-grid");
grid.classList.add("compact-grid");
var table = grid.querySelector(".compact-table");
var tbody;
if (!table) {
table = document.createElement("table");
table.className = "compact-table";
var thead = document.createElement("thead");
var headerRow = document.createElement("tr");
var headers = ["Printer", "Type", "Status", "State", "Source", "Last seen"];
headers.forEach(function (h, idx) {
var th = document.createElement("th");
th.textContent = h;
if (idx === 3) th.className = "compact-col-state";
if (idx === 4) th.className = "compact-col-source";
if (idx === 5) th.className = "compact-col-lastseen";
headerRow.appendChild(th);
});
thead.appendChild(headerRow);
table.appendChild(thead);
tbody = document.createElement("tbody");
table.appendChild(tbody);
grid.appendChild(table);
} else {
tbody = table.querySelector("tbody");
}
// Build map of existing rows
var existingRows = {};
var rows = tbody.querySelectorAll("tr[data-printer-key]");
for (var i = 0; i < rows.length; i++) {
existingRows[rows[i].dataset.printerKey] = rows[i];
}
var activeKeys = {};
items.forEach(function (printer) {
var key = printerKey(printer);
activeKeys[key] = true;
var existing = existingRows[key];
if (existing) {
updateRowInPlace(existing, printer, groupName);
tbody.appendChild(existing);
} else {
var row = buildCompactRow(printer, groupName);
tbody.appendChild(row);
}
});
// Remove rows no longer present
for (var k in existingRows) {
if (!activeKeys[k]) {
existingRows[k].remove();
}
}
}
// --- Toggle button ---
function renderToggleButton(grid, groupName, totalCount, isExpanded) {
var section = grid.parentElement;
var btn = section.querySelector(".group-toggle");
if (!btn) {
btn = document.createElement("button");
btn.className = "group-toggle";
btn.type = "button";
btn.addEventListener("click", function () {
state.expandedGroups[groupName] = !state.expandedGroups[groupName];
// Re-render will happen on next poll, but let's force immediate update
if (state.latestPrinters) {
renderGroups(state.latestPrinters);
}
});
section.appendChild(btn);
}
if (isExpanded) {
btn.textContent = "Show first " + COLLAPSE_LIMIT;
} else {
btn.textContent = "Show all " + totalCount;
}
}
function removeToggle(grid) {
var section = grid.parentElement;
var btn = section.querySelector(".group-toggle");
if (btn) {
btn.remove();
}
}
// --- Main group rendering ---
function renderGroups(printers) {
var groups = {
available: [],
busy: [],
error: [],
recently_disconnected: [],
};
printers.forEach(function (printer) {
if (groups[printer.group]) {
groups[printer.group].push(printer);
}
});
Object.keys(groups).forEach(function (groupName) {
var grid = dom.grids[groupName];
var empty = dom.empties[groupName];
var items = groups[groupName];
var total = items.length;
if (total === 0) {
empty.classList.remove("hidden");
grid.textContent = "";
grid.classList.remove("compact-grid");
grid.classList.add("card-grid");
removeToggle(grid);
return;
}
empty.classList.add("hidden");
// Determine compact threshold: error group gets double threshold
var threshold = groupName === "error" ? COMPACT_THRESHOLD * 2 : COMPACT_THRESHOLD;
var useCompact = total > threshold;
// Determine collapse
var isExpanded = Boolean(state.expandedGroups[groupName]);
var needsCollapse = total > COLLAPSE_LIMIT;
var visibleItems = needsCollapse && !isExpanded ? items.slice(0, COLLAPSE_LIMIT) : items;
if (useCompact) {
renderCompactGroup(grid, groupName, visibleItems);
} else {
renderCardGroup(grid, visibleItems);
}
if (needsCollapse) {
renderToggleButton(grid, groupName, total, isExpanded);
} else {
removeToggle(grid);
}
});
}
function buildCard(printer) {
var fragment = dom.template.content.cloneNode(true);
var card = fragment.querySelector(".printer-card");
card.dataset.group = printer.group || "";
var iconUse = fragment.querySelector(".printer-icon use");
if (iconUse) {
var isBambu = printer.adapter_family && printer.adapter_family.toLowerCase() === "bambu";
iconUse.setAttribute("href", isBambu ? "#icon-printer-bambu" : "#icon-printer");
}
var kicker = fragment.querySelector(".printer-kicker");
kicker.textContent = buildKicker(printer);
fragment.querySelector(".printer-name").textContent = printer.display_name || printer.endpoint_url;
var statusPill = fragment.querySelector(".status-pill");
statusPill.textContent = groupTitles[printer.group] || "Observed";
statusPill.classList.add("status-" + printer.group);
fragment.querySelector(".printer-detail").textContent = buildDetail(printer);
fragment.querySelector(".badge-source").textContent =
sourceLabels[printer.observation_source] || printer.observation_source || "Observed";
fragment.querySelector(".badge-host").textContent = printer.observed_host || "";
fragment.querySelector(".meta-last-seen").textContent = formatRelative(printer.last_seen_at);
fragment.querySelector(".meta-state").textContent = buildStateText(printer);
return fragment;
}
function buildKicker(printer) {
var parts = [];
if (printer.adapter_family) {
parts.push(printer.adapter_family.toUpperCase());
}
if (printer.model_hint) {
parts.push(printer.model_hint);
}
return parts.join(" / ") || "Observed";
}
function buildDetail(printer) {
if (printer.group === "recently_disconnected") {
return printer.last_error_message ||
printer.connectivity_error ||
"This printer was seen recently but is not reachable right now.";
}
if (printer.current_printer_state || printer.current_job_state) {
return buildStateText(printer);
}
if (printer.status_detail_level === "discovery_basic") {
return "Visible on the local network. Detailed runtime telemetry is not available yet.";
}
return "Visible on the local network.";
}
function buildStateText(printer) {
if (printer.group === "recently_disconnected") {
var lastReachable = printer.last_reachable_at ? formatRelative(printer.last_reachable_at) : "recently";
return "Disconnected, last reachable " + lastReachable;
}
var parts = [];
if (printer.current_printer_state) {
parts.push(printer.current_printer_state);
}
if (printer.current_job_state) {
parts.push(printer.current_job_state);
}
if (parts.length > 0) {
return parts.join(" / ");
}
return "Visibility only";
}
function describeScan(scan) {
if (!scan) {
return "No scan data yet";
}
if (scan.running) {
return "Scanning local network";
}
if (scan.last_finished_at) {
return "Last scan " + formatRelative(scan.last_finished_at);
}
if (scan.last_started_at) {
return "Scan started " + formatRelative(scan.last_started_at);
}
return "No scan data yet";
}
function showConnectError(message) {
dom.connectError.textContent = message;
dom.connectError.classList.remove("hidden");
}
function hideConnectError() {
dom.connectError.textContent = "";
dom.connectError.classList.add("hidden");
}
function formatRelative(raw) {
if (!raw) {
return "Unknown";
}
var value = new Date(raw);
if (Number.isNaN(value.getTime())) {
return "Unknown";
}
var diffSeconds = Math.round((Date.now() - value.getTime()) / 1000);
var absSeconds = Math.abs(diffSeconds);
if (absSeconds < 60) {
return diffSeconds <= 0 ? "just now" : diffSeconds + "s ago";
}
if (absSeconds < 3600) {
return Math.round(diffSeconds / 60) + "m ago";
}
if (absSeconds < 86400) {
return Math.round(diffSeconds / 3600) + "h ago";
}
return new Intl.DateTimeFormat(undefined, {
month: "short",
day: "numeric",
hour: "2-digit",
minute: "2-digit",
}).format(value);
}
if (document.readyState === "loading") {
document.addEventListener("DOMContentLoaded", init);
} else {
init();
}
})();
