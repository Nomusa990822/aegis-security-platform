
const API = {
    health: "/api/v1/health",
    alerts: "/api/v1/alerts",
    events: "/api/v1/events",
    rules: "/api/v1/detection/rules"
};

const state = {
    alerts: [],
    events: [],
    rules: [],
    selectedAlert: null,
    currentView: "overview"
};

const $ = (id) => document.getElementById(id);

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return escapeHTML(value);
    return date.toLocaleString([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
    });
}

function showToast(message, isError = false) {
    const toast = $("toast");
    toast.textContent = message;
    toast.className = `toast show${isError ? " error" : ""}`;

    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => {
        toast.className = "toast";
    }, 3500);
}

async function fetchJSON(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            "Accept": "application/json",
            ...(options.body ? { "Content-Type": "application/json" } : {}),
            ...options.headers
        }
    });

    if (!response.ok) {
        const detail = await response.text();
        throw new Error(`HTTP ${response.status}: ${detail.slice(0, 180)}`);
    }

    return response.json();
}

function setConnection(online) {
    $("connection-dot").className = `status-dot ${online ? "online" : "offline"}`;
    $("connection-text").textContent = online ? "Connected" : "Disconnected";
}

function setHealthIndicator(dotId, textId, online, label) {
    $(dotId).className = `health-indicator ${online ? "online" : "offline"}`;
    $(textId).textContent = label;
    $(textId).style.color = online ? "var(--green)" : "var(--red)";
}

function normaliseList(payload, possibleKeys) {
    if (Array.isArray(payload)) return payload;

    for (const key of possibleKeys) {
        if (Array.isArray(payload?.[key])) return payload[key];
    }

    return [];
}

async function loadHealth() {
    try {
        const data = await fetchJSON(API.health);

        const healthy = String(data.status ?? "").toLowerCase();
        const apiOnline = !["unhealthy", "error", "offline"].includes(healthy);

        setHealthIndicator("api-health-dot", "api-health", apiOnline,
            apiOnline ? "Operational" : "Unavailable");

        // The existing health endpoint is the source of truth for API health.
        // SQLite status is not independently tested by this frontend.
        setHealthIndicator("db-health-dot", "db-health", apiOnline,
            apiOnline ? "API connected" : "Unknown");

        $("health-label").textContent = apiOnline ? "Operational" : "Attention";
        $("health-label").style.color = apiOnline ? "var(--green)" : "var(--red)";
        setConnection(apiOnline);
    } catch (error) {
        setConnection(false);
        setHealthIndicator("api-health-dot", "api-health", false, "Unavailable");
        setHealthIndicator("db-health-dot", "db-health", false, "Unknown");
        $("health-label").textContent = "Unavailable";
        $("health-label").style.color = "var(--red)";
    }
}

async function loadAlerts() {
    const payload = await fetchJSON(API.alerts);
    state.alerts = normaliseList(payload, ["alerts", "items", "results"]);
    renderMetrics();
    renderRecentAlerts();
    renderAlertsTable();
}

async function loadEvents() {
    const payload = await fetchJSON(`${API.events}?limit=100`);
    state.events = normaliseList(payload, ["events", "items", "results"]);
    renderMetrics();
    renderRecentEvents();
    renderEventsTable();
}

async function loadRules() {
    try {
        const payload = await fetchJSON(API.rules);
        state.rules = normaliseList(payload, ["rules", "items", "results"]);
        renderRules();
    } catch (error) {
        $("rules-table").innerHTML =
            `<tr><td colspan="5" class="empty-state">Could not load detection rules: ${escapeHTML(error.message)}</td></tr>`;
    }
}

async function refreshDashboard() {
    $("refresh-button").classList.add("refreshing");

    const results = await Promise.allSettled([
        loadHealth(),
        loadAlerts(),
        loadEvents(),
        loadRules()
    ]);

    const alertsFailed = results[1].status === "rejected";
    const eventsFailed = results[2].status === "rejected";

    if (alertsFailed) {
        $("alerts-table").innerHTML =
            `<tr><td colspan="7" class="empty-state">Unable to retrieve alerts. Check the backend.</td></tr>`;
        $("recent-alerts").innerHTML =
            `<div class="empty-state">Unable to retrieve alerts.</div>`;
    }

    if (eventsFailed) {
        $("events-table").innerHTML =
            `<tr><td colspan="6" class="empty-state">Unable to retrieve events. Check the backend.</td></tr>`;
        $("recent-events").innerHTML =
            `<tr><td colspan="5" class="empty-state">Unable to retrieve events.</td></tr>`;
    }

    $("last-updated").textContent = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });

    $("refresh-button").classList.remove("refreshing");
}

function renderMetrics() {
    const count = (status) =>
        state.alerts.filter(alert =>
            String(alert.status).toLowerCase() === status
        ).length;

    $("metric-events").textContent = state.events.length;
    $("metric-open").textContent = count("open");
    $("metric-investigating").textContent = count("investigating");
    $("metric-resolved").textContent = count("resolved");
    $("sidebar-alert-count").textContent = count("open");
}

function severityClass(value) {
    const severity = String(value ?? "low").toLowerCase();
    return ["critical", "high", "medium", "low"].includes(severity)
        ? severity
        : "low";
}

function statusPill(value) {
    const status = String(value ?? "open").toLowerCase();
    const safeStatus = ["open", "investigating", "resolved"].includes(status)
        ? status
        : "open";

    return `<span class="status-pill ${safeStatus}">${escapeHTML(safeStatus)}</span>`;
}

function renderRecentAlerts() {
    const alerts = [...state.alerts]
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .slice(0, 5);

    if (!alerts.length) {
        $("recent-alerts").innerHTML = `<div class="empty-state">No alerts recorded.</div>`;
        return;
    }

    $("recent-alerts").innerHTML = alerts.map(alert => `
        <div class="alert-item" data-alert-id="${Number(alert.id)}">
            <span class="alert-severity-mark ${severityClass(alert.severity)}"></span>
            <div class="alert-main">
                <div class="alert-title">${escapeHTML(alert.title)}</div>
                <div class="alert-meta">${escapeHTML(alert.source_ip)} · ${escapeHTML(alert.detection_rule)}</div>
            </div>
            <div>
                ${statusPill(alert.status)}
                <div class="alert-time">${formatTime(alert.created_at)}</div>
            </div>
        </div>
    `).join("");

    document.querySelectorAll(".alert-item").forEach(item => {
        item.addEventListener("click", () => {
            openAlert(Number(item.dataset.alertId));
        });
    });
}

function renderRecentEvents() {
    const events = [...state.events]
        .sort((a, b) => new Date(b.received_at || b.occurred_at) -
                        new Date(a.received_at || a.occurred_at))
        .slice(0, 5);

    if (!events.length) {
        $("recent-events").innerHTML =
            `<tr><td colspan="5" class="empty-state">No security events recorded.</td></tr>`;
        return;
    }

    $("recent-events").innerHTML = events.map(event => `
        <tr>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.source_ip)}</td>
            <td>${escapeHTML(event.username)}</td>
            <td class="outcome ${String(event.outcome).toLowerCase() === "failure" ? "failed" : ""}">
                ${escapeHTML(event.outcome)}
            </td>
            <td>${formatDate(event.occurred_at || event.received_at)}</td>
        </tr>
    `).join("");
}

function renderAlertsTable() {
    const search = $("alert-search").value.toLowerCase();
    const status = $("alert-status-filter").value;
    const severity = $("alert-severity-filter").value;

    const filtered = state.alerts.filter(alert => {
        const searchable = [
            alert.title, alert.description, alert.source_ip,
            alert.detection_rule, alert.severity, alert.status
        ].join(" ").toLowerCase();

        return searchable.includes(search) &&
            (status === "all" || String(alert.status).toLowerCase() === status) &&
            (severity === "all" || String(alert.severity).toLowerCase() === severity);
    });

    if (!filtered.length) {
        $("alerts-table").innerHTML =
            `<tr><td colspan="7" class="empty-state">No alerts match these filters.</td></tr>`;
        return;
    }

    $("alerts-table").innerHTML = filtered.map(alert => `
        <tr>
            <td><strong>${escapeHTML(alert.title)}</strong></td>
            <td><span class="severity ${severityClass(alert.severity)}">${escapeHTML(alert.severity)}</span></td>
            <td>${escapeHTML(alert.source_ip)}</td>
            <td>${escapeHTML(alert.detection_rule)}</td>
            <td>${statusPill(alert.status)}</td>
            <td>${formatDate(alert.created_at)}</td>
            <td><button class="action-button" data-open-alert="${Number(alert.id)}">Inspect</button></td>
        </tr>
    `).join("");

    document.querySelectorAll("[data-open-alert]").forEach(button => {
        button.addEventListener("click", () => {
            openAlert(Number(button.dataset.openAlert));
        });
    });
}

async function openAlert(id) {
    try {
        const payload = await fetchJSON(`${API.alerts}/${id}`);
        state.selectedAlert = payload.alert ?? payload;

        const alert = state.selectedAlert;
        $("detail-title").textContent = alert.title ?? "Alert details";

        $("detail-content").innerHTML = `
            <div class="detail-grid">
                <div class="detail-field"><small>Alert ID</small><strong>#${Number(alert.id)}</strong></div>
                <div class="detail-field"><small>Severity</small><strong><span class="severity ${severityClass(alert.severity)}">${escapeHTML(alert.severity)}</span></strong></div>
                <div class="detail-field"><small>Source IP</small><strong>${escapeHTML(alert.source_ip)}</strong></div>
                <div class="detail-field"><small>Detection rule</small><strong>${escapeHTML(alert.detection_rule)}</strong></div>
                <div class="detail-field"><small>Created</small><strong>${formatDate(alert.created_at)}</strong></div>
                <div class="detail-field"><small>Current status</small><strong>${statusPill(alert.status)}</strong></div>
            </div>
            <p class="detail-description">${escapeHTML(alert.description)}</p>
            <div class="detail-actions">
                <label for="status-update">Update status</label>
                <select id="status-update">
                    <option value="open" ${alert.status === "open" ? "selected" : ""}>Open</option>
                    <option value="investigating" ${alert.status === "investigating" ? "selected" : ""}>Investigating</option>
                    <option value="resolved" ${alert.status === "resolved" ? "selected" : ""}>Resolved</option>
                </select>
                <button class="action-button" id="save-status">Save status</button>
            </div>
        `;

        $("alert-detail").classList.remove("hidden");
        $("save-status").addEventListener("click", updateSelectedAlertStatus);
        $("alert-detail").scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
        showToast(`Could not load alert: ${error.message}`, true);
    }
}

async function updateSelectedAlertStatus() {
    if (!state.selectedAlert) return;

    const id = Number(state.selectedAlert.id);
    const status = $("status-update").value;
    const button = $("save-status");

    button.disabled = true;
    button.textContent = "Saving...";

    try {
        await fetchJSON(`${API.alerts}/${id}/status`, {
            method: "PATCH",
            body: JSON.stringify({ status })
        });

        showToast(`Alert #${id} updated to ${status}.`);
        await loadAlerts();
        await openAlert(id);
    } catch (error) {
        showToast(`Status update failed: ${error.message}`, true);
    } finally {
        const refreshedButton = $("save-status");
        if (refreshedButton) {
            refreshedButton.disabled = false;
            refreshedButton.textContent = "Save status";
        }
    }
}

function renderEventsTable() {
    const search = $("event-search").value.toLowerCase();

    const filtered = state.events.filter(event => {
        const searchable = [
            event.event_type, event.source_ip, event.username,
            event.outcome, event.description
        ].join(" ").toLowerCase();

        return searchable.includes(search);
    });

    if (!filtered.length) {
        $("events-table").innerHTML =
            `<tr><td colspan="6" class="empty-state">No matching events found.</td></tr>`;
        return;
    }

    $("events-table").innerHTML = filtered.map(event => `
        <tr>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.source_ip)}</td>
            <td>${escapeHTML(event.username)}</td>
            <td class="outcome ${String(event.outcome).toLowerCase() === "failure" ? "failed" : ""}">${escapeHTML(event.outcome)}</td>
            <td>${escapeHTML(event.description)}</td>
            <td>${formatDate(event.occurred_at || event.received_at)}</td>
        </tr>
    `).join("");
}

function renderRules() {
    if (!state.rules.length) {
        $("rules-table").innerHTML =
            `<tr><td colspan="5" class="empty-state">No detection rules returned by the API.</td></tr>`;
        return;
    }

    $("rules-table").innerHTML = state.rules.map(rule => `
        <tr>
            <td>${escapeHTML(rule.rule_id)}</td>
            <td><strong>${escapeHTML(rule.name)}</strong><br><span class="alert-meta">${escapeHTML(rule.description)}</span></td>
            <td><span class="severity ${severityClass(rule.severity)}">${escapeHTML(rule.severity)}</span></td>
            <td>${escapeHTML(rule.mitre_technique)} · ${escapeHTML(rule.mitre_name)}</td>
            <td>${rule.enabled ? '<span class="status-pill resolved">Enabled</span>' : '<span class="status-pill open">Disabled</span>'}</td>
        </tr>
    `).join("");
}

function switchView(view) {
    state.currentView = view;

    document.querySelectorAll(".view").forEach(section => {
        section.classList.toggle("active", section.id === `view-${view}`);
    });

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle("active", button.dataset.view === view);
    });

    const names = {
        overview: "Overview",
        alerts: "Alerts",
        events: "Security Events",
        rules: "Detection Rules"
    };

    $("breadcrumb-current").textContent = names[view] || "Overview";
    $("page-heading").textContent = names[view] || "Overview";

    if (view === "alerts") renderAlertsTable();
    if (view === "events") renderEventsTable();
}

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => switchView(button.dataset.view));
});

document.querySelectorAll("[data-open-view]").forEach(button => {
    button.addEventListener("click", () => switchView(button.dataset.openView));
});

$("refresh-button").addEventListener("click", refreshDashboard);
$("alert-search").addEventListener("input", renderAlertsTable);
$("alert-status-filter").addEventListener("change", renderAlertsTable);
$("alert-severity-filter").addEventListener("change", renderAlertsTable);
$("event-search").addEventListener("input", renderEventsTable);

$("close-detail").addEventListener("click", () => {
    $("alert-detail").classList.add("hidden");
});

refreshDashboard();
window.setInterval(refreshDashboard, 15000);
