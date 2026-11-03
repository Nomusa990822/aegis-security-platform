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
    investigation: null,
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
        throw new Error(`HTTP ${response.status}: ${detail.slice(0, 250)}`);
    }

    return response.json();
}

function normaliseList(payload, possibleKeys) {
    if (Array.isArray(payload)) return payload;

    for (const key of possibleKeys) {
        if (Array.isArray(payload?.[key])) return payload[key];
    }

    return [];
}

function setConnection(online) {
    $("connection-dot").className =
        `status-dot ${online ? "online" : "offline"}`;

    $("connection-text").textContent =
        online ? "Connected" : "Disconnected";
}

function setHealthIndicator(dotId, textId, online, label) {
    $(dotId).className =
        `health-indicator ${online ? "online" : "offline"}`;

    $(textId).textContent = label;
    $(textId).style.color = online ? "var(--green)" : "var(--red)";
}

async function loadHealth() {
    try {
        const data = await fetchJSON(API.health);
        const healthy = String(data.status ?? "").toLowerCase();

        const apiOnline =
            !["unhealthy", "error", "offline"].includes(healthy);

        setHealthIndicator(
            "api-health-dot",
            "api-health",
            apiOnline,
            apiOnline ? "Operational" : "Unavailable"
        );

        // The current health endpoint does not independently verify SQLite.
        setHealthIndicator(
            "db-health-dot",
            "db-health",
            apiOnline,
            apiOnline ? "API connected" : "Unknown"
        );

        $("health-label").textContent =
            apiOnline ? "Operational" : "Attention";

        $("health-label").style.color =
            apiOnline ? "var(--green)" : "var(--red)";

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
        $("rules-table").innerHTML = `
            <tr><td colspan="5" class="empty-state">
                Could not load detection rules: ${escapeHTML(error.message)}
            </td></tr>`;
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

    if (results[1].status === "rejected") {
        $("alerts-table").innerHTML = `
            <tr><td colspan="7" class="empty-state">
                Unable to retrieve alerts. Check the backend.
            </td></tr>`;

        $("recent-alerts").innerHTML =
            `<div class="empty-state">Unable to retrieve alerts.</div>`;
    }

    if (results[2].status === "rejected") {
        $("events-table").innerHTML = `
            <tr><td colspan="6" class="empty-state">
                Unable to retrieve events. Check the backend.
            </td></tr>`;

        $("recent-events").innerHTML = `
            <tr><td colspan="5" class="empty-state">
                Unable to retrieve events.
            </td></tr>`;
    }

    $("last-updated").textContent = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });

    $("refresh-button").classList.remove("refreshing");

    // Keep the evidence selector current when the investigation is open.
    if (state.currentView === "investigation") {
        renderEvidenceEventOptions();
    }
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

    const safeStatus =
        ["open", "investigating", "resolved"].includes(status)
            ? status
            : "open";

    return `
        <span class="status-pill ${safeStatus}">
            ${escapeHTML(safeStatus)}
        </span>`;
}

function renderRecentAlerts() {
    const alerts = [...state.alerts]
        .sort((a, b) =>
            new Date(b.created_at) - new Date(a.created_at)
        )
        .slice(0, 5);

    if (!alerts.length) {
        $("recent-alerts").innerHTML =
            `<div class="empty-state">No alerts recorded.</div>`;
        return;
    }

    $("recent-alerts").innerHTML = alerts.map(alert => `
        <div class="alert-item" data-alert-id="${Number(alert.id)}">
            <span class="alert-severity-mark ${severityClass(alert.severity)}"></span>
            <div class="alert-main">
                <div class="alert-title">${escapeHTML(alert.title)}</div>
                <div class="alert-meta">
                    ${escapeHTML(alert.source_ip)} ·
                    ${escapeHTML(alert.detection_rule)}
                </div>
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
        .sort((a, b) =>
            new Date(b.received_at || b.occurred_at) -
            new Date(a.received_at || a.occurred_at)
        )
        .slice(0, 5);

    if (!events.length) {
        $("recent-events").innerHTML = `
            <tr><td colspan="5" class="empty-state">
                No security events recorded.
            </td></tr>`;
        return;
    }

    $("recent-events").innerHTML = events.map(event => `
        <tr>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.source_ip)}</td>
            <td>${escapeHTML(event.username)}</td>
            <td class="outcome ${
                String(event.outcome).toLowerCase() === "failure" ? "failed" : ""
            }">${escapeHTML(event.outcome)}</td>
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
            alert.title,
            alert.description,
            alert.source_ip,
            alert.detection_rule,
            alert.severity,
            alert.status
        ].join(" ").toLowerCase();

        return searchable.includes(search) &&
            (status === "all" ||
                String(alert.status).toLowerCase() === status) &&
            (severity === "all" ||
                String(alert.severity).toLowerCase() === severity);
    });

    if (!filtered.length) {
        $("alerts-table").innerHTML = `
            <tr><td colspan="7" class="empty-state">
                No alerts match these filters.
            </td></tr>`;
        return;
    }

    $("alerts-table").innerHTML = filtered.map(alert => `
        <tr>
            <td><strong>${escapeHTML(alert.title)}</strong></td>
            <td>
                <span class="severity ${severityClass(alert.severity)}">
                    ${escapeHTML(alert.severity)}
                </span>
            </td>
            <td>${escapeHTML(alert.source_ip)}</td>
            <td>${escapeHTML(alert.detection_rule)}</td>
            <td>${statusPill(alert.status)}</td>
            <td>${formatDate(alert.created_at)}</td>
            <td>
                <button class="action-button"
                    data-open-alert="${Number(alert.id)}">
                    Investigate
                </button>
            </td>
        </tr>
    `).join("");

    document.querySelectorAll("[data-open-alert]").forEach(button => {
        button.addEventListener("click", () => {
            openAlert(Number(button.dataset.openAlert));
        });
    });
}

/* -------------------------------------------------------
   INCIDENT INVESTIGATION WORKSPACE
------------------------------------------------------- */

async function openAlert(id) {
    try {
        state.selectedAlert = null;
        state.investigation = null;

        $("investigation-empty").classList.add("hidden");
        $("investigation-content").classList.remove("hidden");

        $("incident-title").textContent = "Loading incident...";
        $("notes-list").innerHTML =
            `<div class="empty-state">Loading investigation notes...</div>`;
        $("evidence-list").innerHTML =
            `<div class="empty-state">Loading linked evidence...</div>`;
        $("timeline-list").innerHTML =
            `<div class="empty-state">Loading timeline...</div>`;

        switchView("investigation");

        const payload = await fetchJSON(
            `${API.alerts}/${id}/investigation`
        );

        if (!payload.alert) {
            throw new Error("The investigation response did not contain an alert.");
        }

        state.investigation = payload;
        state.selectedAlert = payload.alert;

        renderInvestigation(payload);
    } catch (error) {
        $("investigation-content").classList.add("hidden");
        $("investigation-empty").classList.remove("hidden");

        $("investigation-empty").textContent =
            `Unable to load this investigation: ${error.message}`;

        showToast("Could not load investigation.", true);
    }
}

function renderInvestigation(data) {
    const alert = data.alert;
    const notes = data.notes ?? [];
    const evidence = data.evidence ?? [];
    const timeline = data.timeline ?? [];
    const audit = data.audit_log ?? [];

    $("incident-reference").textContent =
        `INC-${String(alert.id).padStart(6, "0")} · ALERT #${alert.id}`;

    $("incident-title").textContent = alert.title ?? "Untitled incident";
    $("incident-created").textContent =
        `Created ${formatDate(alert.created_at)}`;

    $("incident-status").innerHTML = statusPill(alert.status);

    $("incident-severity").innerHTML = `
        <span class="severity ${severityClass(alert.severity)}">
            ${escapeHTML(alert.severity)}
        </span>`;

    $("incident-source-ip").textContent = alert.source_ip ?? "—";
    $("incident-rule").textContent = alert.detection_rule ?? "—";
    $("incident-description").textContent = alert.description ?? "No description provided.";

    const mitreMatch = String(alert.description ?? "").match(/T\d{4}(?:\.\d{3})?/);
    const technique = mitreMatch ? mitreMatch[0] : "Not specified";

    $("incident-mitre").innerHTML =
        technique === "Not specified"
            ? escapeHTML(technique)
            : `<a class="mitre-link" href="https://attack.mitre.org/techniques/${encodeURIComponent(technique)}/" target="_blank" rel="noopener noreferrer">${escapeHTML(technique)} ↗</a>`;

    $("investigation-status").value =
        ["open", "investigating", "resolved"].includes(alert.status)
            ? alert.status
            : "open";

    $("status-feedback").textContent = "";

    $("investigation-note-count").textContent = notes.length;
    $("investigation-evidence-count").textContent = evidence.length;
    $("investigation-timeline-count").textContent = timeline.length;
    $("investigation-audit-count").textContent = audit.length;

    $("notes-counter").textContent = notes.length;
    $("evidence-counter").textContent = evidence.length;
    $("timeline-counter").textContent = timeline.length;
    $("audit-counter").textContent = audit.length;

    renderNotes(notes);
    renderEvidence(evidence);
    renderTimeline(timeline);
    renderAuditLog(audit);
    renderEvidenceEventOptions();

    $("investigation-empty").classList.add("hidden");
    $("investigation-content").classList.remove("hidden");
}

function renderNotes(notes) {
    if (!notes.length) {
        $("notes-list").innerHTML =
            `<div class="empty-state">No investigation notes have been added.</div>`;
        return;
    }

    $("notes-list").innerHTML = [...notes]
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .map(note => `
            <article class="record-card">
                <div class="record-card-header">
                    <strong>${escapeHTML(note.author || "analyst")}</strong>
                    <time>${formatDate(note.created_at)}</time>
                </div>
                <p>${escapeHTML(note.content)}</p>
                <span class="record-id">NOTE #${Number(note.id)}</span>
            </article>
        `).join("");
}

function renderEvidence(evidence) {
    if (!evidence.length) {
        $("evidence-list").innerHTML =
            `<div class="empty-state">No evidence has been linked to this incident.</div>`;
        return;
    }

    $("evidence-list").innerHTML = evidence.map(item => `
        <article class="record-card evidence-card">
            <div class="record-card-header">
                <strong>Security event #${Number(item.event_id)}</strong>
                <span class="evidence-outcome ${
                    String(item.outcome).toLowerCase() === "failure" ? "failed" : ""
                }">${escapeHTML(item.outcome || "unknown")}</span>
            </div>

            <div class="evidence-details">
                <span><small>TYPE</small>${escapeHTML(item.event_type)}</span>
                <span><small>SOURCE IP</small>${escapeHTML(item.source_ip)}</span>
                <span><small>USERNAME</small>${escapeHTML(item.username)}</span>
                <span><small>OCCURRED</small>${formatDate(item.occurred_at)}</span>
            </div>

            <p class="evidence-description">${escapeHTML(item.description)}</p>

            ${
                item.analyst_note
                    ? `<p class="evidence-annotation">${escapeHTML(item.analyst_note)}</p>`
                    : ""
            }

            <span class="record-id">
                EVIDENCE #${Number(item.evidence_id ?? item.id)}
                · Linked ${formatDate(item.linked_at)}
            </span>
        </article>
    `).join("");
}

function renderTimeline(timeline) {
    if (!timeline.length) {
        $("timeline-list").innerHTML =
            `<div class="empty-state">No timeline activity recorded.</div>`;
        return;
    }

    const sorted = [...timeline].sort((a, b) =>
        new Date(a.created_at) - new Date(b.created_at)
    );

    $("timeline-list").innerHTML = sorted.map(item => `
        <article class="timeline-item">
            <span class="timeline-marker"></span>
            <div class="timeline-content">
                <div class="timeline-header">
                    <strong>${escapeHTML(item.summary)}</strong>
                    <time>${formatDate(item.created_at)}</time>
                </div>
                ${
                    item.details
                        ? `<p>${escapeHTML(item.details)}</p>`
                        : ""
                }
                <span class="record-id">
                    ${escapeHTML(item.actor || "system")}
                    · ${escapeHTML(item.action)}
                </span>
            </div>
        </article>
    `).join("");
}

function renderAuditLog(audit) {
    if (!audit.length) {
        $("audit-table").innerHTML = `
            <tr><td colspan="6" class="empty-state">
                No audit records available.
            </td></tr>`;
        return;
    }

    $("audit-table").innerHTML = audit.map(item => `
        <tr>
            <td>${formatDate(item.created_at)}</td>
            <td>${escapeHTML(item.action)}</td>
            <td>${escapeHTML(item.actor)}</td>
            <td>${escapeHTML(item.previous_value ?? "—")}</td>
            <td>${escapeHTML(item.new_value ?? "—")}</td>
            <td>${escapeHTML(item.details ?? "—")}</td>
        </tr>
    `).join("");
}

function renderEvidenceEventOptions() {
    const select = $("evidence-event-id");
    if (!select) return;

    const currentValue = select.value;

    const options = state.events.map(event => `
        <option value="${Number(event.id)}">
            #${Number(event.id)} · ${escapeHTML(event.event_type)}
            · ${escapeHTML(event.source_ip)}
            · ${escapeHTML(event.outcome)}
        </option>
    `).join("");

    select.innerHTML =
        `<option value="">Choose a security event...</option>${options}`;

    if (currentValue &&
        state.events.some(event => String(event.id) === currentValue)) {
        select.value = currentValue;
    }
}

async function submitInvestigationNote(event) {
    event.preventDefault();

    if (!state.selectedAlert) return;

    const content = $("note-content").value.trim();

    if (!content) {
        showToast("Enter a note before submitting.", true);
        return;
    }

    const button = $("add-note-button");
    button.disabled = true;
    button.textContent = "Saving...";

    try {
        const id = Number(state.selectedAlert.id);

        await fetchJSON(`${API.alerts}/${id}/notes`, {
            method: "POST",
            body: JSON.stringify({ content })
        });

        $("note-content").value = "";

        await openAlert(id);
        showToast("Investigation note saved.");
    } catch (error) {
        showToast(`Could not save note: ${error.message}`, true);
    } finally {
        button.disabled = false;
        button.textContent = "Add note";
    }
}

async function submitEvidence(event) {
    event.preventDefault();

    if (!state.selectedAlert) return;

    const eventId = Number($("evidence-event-id").value);
    const analystNote = $("evidence-note").value.trim();

    if (!eventId) {
        showToast("Select a security event to link.", true);
        return;
    }

    const button = $("link-evidence-button");
    button.disabled = true;
    button.textContent = "Linking...";

    const body = {
        event_id: eventId,
        analyst_note: analystNote || null
    };

    try {
        const id = Number(state.selectedAlert.id);

        await fetchJSON(`${API.alerts}/${id}/evidence`, {
            method: "POST",
            body: JSON.stringify(body)
        });

        $("evidence-note").value = "";

        await openAlert(id);
        showToast(`Security event #${eventId} linked as evidence.`);
    } catch (error) {
        showToast(`Could not link evidence: ${error.message}`, true);
    } finally {
        button.disabled = false;
        button.textContent = "Link evidence";
    }
}

async function updateInvestigationStatus() {
    if (!state.selectedAlert) return;

    const id = Number(state.selectedAlert.id);
    const status = $("investigation-status").value;
    const button = $("save-investigation-status");

    button.disabled = true;
    button.textContent = "Updating...";
    $("status-feedback").textContent = "";

    try {
        const result = await fetchJSON(`${API.alerts}/${id}/status`, {
            method: "PATCH",
            body: JSON.stringify({ status })
        });

        await loadAlerts();
        await openAlert(id);

        $("status-feedback").textContent =
            result.message || "Status updated.";

        showToast(`Incident status updated to ${status}.`);
    } catch (error) {
        showToast(`Status update failed: ${error.message}`, true);
        $("status-feedback").textContent = "Update failed.";
    } finally {
        button.disabled = false;
        button.textContent = "Update status";
    }
}

/* -------------------------------------------------------
   SECURITY EVENTS
------------------------------------------------------- */

function renderEventsTable() {
    const search = $("event-search").value.toLowerCase();

    const filtered = state.events.filter(event => {
        const searchable = [
            event.event_type,
            event.source_ip,
            event.username,
            event.outcome,
            event.description
        ].join(" ").toLowerCase();

        return searchable.includes(search);
    });

    if (!filtered.length) {
        $("events-table").innerHTML = `
            <tr><td colspan="6" class="empty-state">
                No matching events found.
            </td></tr>`;
        return;
    }

    $("events-table").innerHTML = filtered.map(event => `
        <tr>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.source_ip)}</td>
            <td>${escapeHTML(event.username)}</td>
            <td class="outcome ${
                String(event.outcome).toLowerCase() === "failure" ? "failed" : ""
            }">${escapeHTML(event.outcome)}</td>
            <td>${escapeHTML(event.description)}</td>
            <td>${formatDate(event.occurred_at || event.received_at)}</td>
        </tr>
    `).join("");
}

function renderRules() {
    if (!state.rules.length) {
        $("rules-table").innerHTML = `
            <tr><td colspan="5" class="empty-state">
                No detection rules returned by the API.
            </td></tr>`;
        return;
    }

    $("rules-table").innerHTML = state.rules.map(rule => `
        <tr>
            <td>${escapeHTML(rule.rule_id)}</td>
            <td>
                <strong>${escapeHTML(rule.name)}</strong><br>
                <span class="alert-meta">${escapeHTML(rule.description)}</span>
            </td>
            <td>
                <span class="severity ${severityClass(rule.severity)}">
                    ${escapeHTML(rule.severity)}
                </span>
            </td>
            <td>
                ${escapeHTML(rule.mitre_technique)}
                · ${escapeHTML(rule.mitre_name)}
            </td>
            <td>
                ${
                    rule.enabled
                        ? '<span class="status-pill resolved">Enabled</span>'
                        : '<span class="status-pill open">Disabled</span>'
                }
            </td>
        </tr>
    `).join("");
}

/* -------------------------------------------------------
   NAVIGATION AND EVENT LISTENERS
------------------------------------------------------- */

function switchView(view) {
    const validViews = [
        "overview",
        "alerts",
        "events",
        "rules",
        "investigation"
    ];

    if (!validViews.includes(view)) return;

    state.currentView = view;

    document.querySelectorAll(".view").forEach(section => {
        section.classList.toggle(
            "active",
            section.id === `view-${view}`
        );
    });

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.view === view
        );
    });

    const names = {
        overview: "Overview",
        alerts: "Alerts",
        events: "Security Events",
        rules: "Detection Rules",
        investigation: "Investigation"
    };

    $("breadcrumb-current").textContent = names[view];
    $("page-heading").textContent = names[view];

    if (view === "alerts") renderAlertsTable();
    if (view === "events") renderEventsTable();
    if (view === "investigation") renderEvidenceEventOptions();
}

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
        const view = button.dataset.view;

        if (view === "investigation" && !state.selectedAlert) {
            switchView("investigation");
            $("investigation-content").classList.add("hidden");
            $("investigation-empty").classList.remove("hidden");
            return;
        }

        switchView(view);
    });
});

document.querySelectorAll("[data-open-view]").forEach(button => {
    button.addEventListener("click", () => {
        switchView(button.dataset.openView);
    });
});

$("back-to-alerts").addEventListener("click", () => {
    switchView("alerts");
});

$("refresh-button").addEventListener("click", refreshDashboard);

$("alert-search").addEventListener("input", renderAlertsTable);
$("alert-status-filter").addEventListener("change", renderAlertsTable);
$("alert-severity-filter").addEventListener("change", renderAlertsTable);
$("event-search").addEventListener("input", renderEventsTable);

$("note-form").addEventListener("submit", submitInvestigationNote);
$("evidence-form").addEventListener("submit", submitEvidence);

$("save-investigation-status").addEventListener(
    "click",
    updateInvestigationStatus
);

refreshDashboard();
window.setInterval(refreshDashboard, 15000);
