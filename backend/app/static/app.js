/* =========================================================
   AEGIS — AUTONOMOUS THREAT DETECTION AND RESPONSE PLATFORM
   Correlation Investigation Dashboard
========================================================= */

const API = {
    health: "/api/v1/health",
    alerts: "/api/v1/alerts",
    events: "/api/v1/events",
    rules: "/api/v1/detection/rules",
    correlations: "/api/v1/correlations",
    mitre: "/api/v1/mitre"
};

const state = {
    alerts: [],
    events: [],
    rules: [],
    cases: [],
    mitreTechniques: [],
    mitreMappings: [],
    selectedMitreTechnique: null,
    selectedCase: null,
    selectedAlert: null,
    alertInvestigation: null,
    currentView: "overview",
    loadingCase: false,
    loadingAlert: false,
    alertRequestId: 0
};

const $ = (id) => document.getElementById(id);

/* =========================================================
   GENERAL HELPERS
========================================================= */

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

    if (Number.isNaN(date.getTime())) {
        return escapeHTML(value);
    }

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

    if (!toast) return;

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
            ...(options.body
                ? { "Content-Type": "application/json" }
                : {}),
            ...(sessionStorage.getItem("aegis_access_token")
                ? {
                    "Authorization": `Bearer ${sessionStorage.getItem("aegis_access_token")}`
                }
                : {}),
            ...options.headers
        }
    });

    if (!response.ok) {
        const detail = await response.text();

        throw new Error(
            `HTTP ${response.status}: ${detail.slice(0, 250)}`
        );
    }

    return response.json();
}

function normaliseList(payload, possibleKeys) {
    if (Array.isArray(payload)) return payload;

    for (const key of possibleKeys) {
        if (Array.isArray(payload?.[key])) {
            return payload[key];
        }
    }

    return [];
}

function setText(id, value) {
    const element = $(id);

    if (element) {
        element.textContent = value ?? "—";
    }
}

function setHTML(id, value) {
    const element = $(id);

    if (element) {
        element.innerHTML = value;
    }
}

function setConnection(online) {
    const dot = $("connection-dot");
    const text = $("connection-text");

    if (dot) {
        dot.className = `status-dot ${online ? "online" : "offline"}`;
    }

    if (text) {
        text.textContent = online ? "Connected" : "Disconnected";
    }
}

function setHealthIndicator(dotId, textId, online, label) {
    const dot = $(dotId);
    const text = $(textId);

    if (dot) {
        dot.className =
            `health-indicator ${online ? "online" : "offline"}`;
    }

    if (text) {
        text.textContent = label;
        text.style.color = online
            ? "var(--green)"
            : "var(--red)";
    }
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
        </span>
    `;
}

function severityPill(value) {
    return `
        <span class="severity ${severityClass(value)}">
            ${escapeHTML(value ?? "low")}
        </span>
    `;
}

function emptyRow(columns, message) {
    return `
        <tr>
            <td colspan="${columns}" class="empty-state">
                ${escapeHTML(message)}
            </td>
        </tr>
    `;
}

/* =========================================================
   HEALTH AND DATA LOADING
========================================================= */

async function loadHealth() {
    try {
        const data = await fetchJSON(API.health);

        const status = String(data.status ?? "").toLowerCase();

        const online = ![
            "unhealthy",
            "error",
            "offline"
        ].includes(status);

        setHealthIndicator(
            "api-health-dot",
            "api-health",
            online,
            online ? "Operational" : "Unavailable"
        );

        // The current health endpoint does not independently
        // verify the SQLite database.

        setHealthIndicator(
            "db-health-dot",
            "db-health",
            online,
            online ? "API connected" : "Unknown"
        );

        setText(
            "health-label",
            online ? "Operational" : "Attention"
        );

        const label = $("health-label");

        if (label) {
            label.style.color = online
                ? "var(--green)"
                : "var(--red)";
        }

        setConnection(online);

    } catch (error) {
        setConnection(false);

        setHealthIndicator(
            "api-health-dot",
            "api-health",
            false,
            "Unavailable"
        );

        setHealthIndicator(
            "db-health-dot",
            "db-health",
            false,
            "Unknown"
        );

        setText("health-label", "Unavailable");

        const label = $("health-label");

        if (label) {
            label.style.color = "var(--red)";
        }
    }
}

async function loadAlerts() {
    const payload = await fetchJSON(API.alerts);

    state.alerts = normaliseList(
        payload,
        ["alerts", "items", "results"]
    );

    renderMetrics();
    renderAlertsTable();
}

async function loadEvents() {
    const payload = await fetchJSON(
        `${API.events}?limit=100`
    );

    state.events = normaliseList(
        payload,
        ["events", "items", "results"]
    );

    renderMetrics();
    renderRecentEvents();
    renderEventsTable();
}

async function loadRules() {
    try {
        const payload = await fetchJSON(API.rules);

        state.rules = normaliseList(
            payload,
            ["rules", "items", "results"]
        );

        renderRules();

    } catch (error) {
        setHTML(
            "rules-table",
            emptyRow(
                5,
                `Could not load detection rules: ${error.message}`
            )
        );
    }
}

async function loadCases() {
    const payload = await fetchJSON(API.correlations);

    state.cases = normaliseList(
        payload,
        ["correlations", "cases", "items", "results"]
    );

    renderMetrics();
    renderRecentCases();
    renderCasesTable();
}

async function refreshDashboard() {
    const refreshButton = $("refresh-button");

    if (refreshButton) {
        refreshButton.classList.add("refreshing");
    }

    const results = await Promise.allSettled([
       loadHealth(),
       loadAlerts(),
       loadEvents(),
       loadRules(),
       loadCases(),
       loadMitreData()
    ]);

    if (results[1].status === "rejected") {
        setHTML(
            "alerts-table",
            emptyRow(7, "Unable to retrieve alerts. Check the backend.")
        );
    }

    if (results[2].status === "rejected") {
        setHTML(
            "events-table",
            emptyRow(6, "Unable to retrieve security events.")
        );

        setHTML(
            "recent-events",
            emptyRow(5, "Unable to retrieve security events.")
        );
    }

    if (results[4].status === "rejected") {
        setHTML(
            "cases-table",
            emptyRow(7, "Unable to retrieve correlation cases.")
        );

        setHTML(
            "recent-cases",
            `<div class="empty-state">
                Unable to retrieve correlation cases.
            </div>`
        );
    }

    setText(
        "last-updated",
        new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        })
    );

    if (refreshButton) {
        refreshButton.classList.remove("refreshing");
    }

    // Refresh the currently open case without losing its view.
    if (
        state.currentView === "case" &&
        state.selectedCase?.id &&
        !state.loadingCase
    ) {
        await loadCaseDetails(state.selectedCase.id, false);
    }

    // Refresh the currently open alert investigation.
    if (
        state.currentView === "alert" &&
        state.selectedAlert &&
        !state.loadingAlert
    ) {
        await loadAlertInvestigation(state.selectedAlert);
    }
}

/* =========================================================
   OVERVIEW METRICS
========================================================= */

function renderMetrics() {
    const openAlerts = state.alerts.filter(alert =>
        String(alert.status).toLowerCase() === "open"
    ).length;

    const activeCases = state.cases.filter(item =>
        ["open", "investigating"].includes(
            String(item.status).toLowerCase()
        )
    ).length;

    const criticalCases = state.cases.filter(item =>
        String(item.severity).toLowerCase() === "critical"
    ).length;

    setText("metric-events", state.events.length);
    setText("metric-open-alerts", openAlerts);
    setText("metric-active-cases", activeCases);
    setText("metric-critical", criticalCases);

    // Sidebar counters
    setText("sidebar-alert-count", openAlerts);
    setText("sidebar-case-count", activeCases);
}

/* =========================================================
   RECENT CASES
========================================================= */

function renderRecentCases() {
    const container = $("recent-cases");

    if (!container) return;

    const recent = [...state.cases]
        .sort((a, b) =>
            new Date(b.created_at) - new Date(a.created_at)
        )
        .slice(0, 5);

    if (!recent.length) {
        container.innerHTML = `
            <div class="empty-state">
                No correlation cases recorded.
            </div>
        `;
        return;
    }

    container.innerHTML = recent.map(item => `
        <div class="alert-item"
             data-open-case="${Number(item.id)}">

            <span class="alert-severity-mark ${severityClass(item.severity)}">
            </span>

            <div class="alert-main">
                <div class="alert-title">
                    ${escapeHTML(item.title)}
                </div>

                <div class="alert-meta">
                    CASE #${Number(item.id)}
                    · ${escapeHTML(item.source_ip ?? "Unknown source")}
                </div>
            </div>

            <div>
                ${statusPill(item.status)}
                <div class="alert-time">
                    ${formatTime(item.created_at)}
                </div>
            </div>
        </div>
    `).join("");

    container.querySelectorAll("[data-open-case]").forEach(element => {
        element.addEventListener("click", () => {
            openCase(Number(element.dataset.openCase));
        });
    });
}

/* =========================================================
   RECENT SECURITY EVENTS
========================================================= */

function renderRecentEvents() {
    const container = $("recent-events");

    if (!container) return;

    const recent = [...state.events]
        .sort((a, b) =>
            new Date(b.received_at || b.occurred_at) -
            new Date(a.received_at || a.occurred_at)
        )
        .slice(0, 5);

    if (!recent.length) {
        container.innerHTML = emptyRow(
            5,
            "No security events recorded."
        );
        return;
    }

    container.innerHTML = recent.map(event => `
        <tr>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.source_ip)}</td>
            <td>${escapeHTML(event.username)}</td>

            <td class="outcome ${
                String(event.outcome).toLowerCase() === "failure"
                    ? "failed"
                    : ""
            }">
                ${escapeHTML(event.outcome)}
            </td>

            <td>
                ${formatDate(event.occurred_at || event.received_at)}
            </td>
        </tr>
    `).join("");
}

/* =========================================================
   ALERT REGISTER
========================================================= */

function renderAlertsTable() {
    const search = ($("alert-search")?.value ?? "").toLowerCase();
    const status = $("alert-status-filter")?.value ?? "all";
    const severity = $("alert-severity-filter")?.value ?? "all";

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
        setHTML(
            "alerts-table",
            emptyRow(7, "No alerts match these filters.")
        );
        return;
    }

    setHTML(
        "alerts-table",
        filtered.map(alert => `
            <tr>
                <td>
                    <strong>${escapeHTML(alert.title)}</strong>
                </td>

                <td>${severityPill(alert.severity)}</td>

                <td>${escapeHTML(alert.source_ip)}</td>

                <td>${escapeHTML(alert.detection_rule)}</td>

                <td>${statusPill(alert.status)}</td>

                <td>${formatDate(alert.created_at)}</td>

                <td>
                    <button class="action-button"
                        data-open-alert="${Number(alert.id)}">
                        View
                    </button>
                </td>
            </tr>
        `).join("")
    );

   document.querySelectorAll("[data-open-alert]").forEach(button => {
       button.addEventListener("click", () => {
           const alertId = Number(button.dataset.openAlert);
           openAlert(alertId);
       });
   });
}

/* =========================================================
   SECURITY EVENTS REGISTER
========================================================= */


function renderEventsTable() {
    const search = ($("event-search")?.value ?? "").toLowerCase();

    const filtered = state.events.filter(event => {
        const searchable = [
            event.id,
            event.event_type,
            event.source_ip,
            event.username,
            event.outcome,
            event.description
        ].join(" ").toLowerCase();

        return searchable.includes(search);
    });

    if (!filtered.length) {
        setHTML(
            "events-table",
            emptyRow(7, "No matching events found.")
        );
        return;
    }

    setHTML(
        "events-table",
        filtered.map(event => `
            <tr>
                <td>${escapeHTML(event.id)}</td>
                <td>${escapeHTML(event.event_type)}</td>
                <td>${escapeHTML(event.source_ip)}</td>
                <td>${escapeHTML(event.username ?? "—")}</td>

                <td class="outcome ${
                    String(event.outcome).toLowerCase() === "failure"
                        ? "failed"
                        : ""
                }">
                    ${escapeHTML(event.outcome)}
                </td>

                <td>${escapeHTML(event.description)}</td>

                <td>
                    ${formatDate(event.occurred_at || event.received_at)}
                </td>
            </tr>
        `).join("")
    );
}


/* =========================================================
   DETECTION RULES
========================================================= */

function renderRules() {
    if (!state.rules.length) {
        setHTML(
            "rules-table",
            emptyRow(5, "No detection rules returned by the API.")
        );
        return;
    }

    setHTML(
        "rules-table",
        state.rules.map(rule => `
            <tr>
                <td>${escapeHTML(rule.rule_id)}</td>

                <td>
                    <strong>${escapeHTML(rule.name)}</strong><br>
                    <span class="alert-meta">
                        ${escapeHTML(rule.description)}
                    </span>
                </td>

                <td>${severityPill(rule.severity)}</td>

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
        `).join("")
    );
}

/* =========================================================
   CORRELATION CASE REGISTER
========================================================= */

function renderCasesTable() {
    const search = ($("case-search")?.value ?? "").toLowerCase();
    const status = $("case-status-filter")?.value ?? "all";
    const severity = $("case-severity-filter")?.value ?? "all";

    const filtered = state.cases.filter(item => {
        const searchable = [
            item.id,
            item.title,
            item.source_ip,
            item.status,
            item.severity,
            item.assigned_to
        ].join(" ").toLowerCase();

        return searchable.includes(search) &&
            (status === "all" ||
                String(item.status).toLowerCase() === status) &&
            (severity === "all" ||
                String(item.severity).toLowerCase() === severity);
    });

    setText("case-total", filtered.length);

    if (!filtered.length) {
        setHTML(
            "cases-table",
            emptyRow(7, "No correlation cases match these filters.")
        );
        return;
    }

    setHTML(
        "cases-table",
        filtered.map(item => `
            <tr>
                <td>
                    <strong>CASE #${Number(item.id)}</strong>
                </td>

                <td>
                    <strong>${escapeHTML(item.title)}</strong>
                </td>

                <td>${severityPill(item.severity)}</td>

                <td>${escapeHTML(item.source_ip ?? "—")}</td>

                <td>${Number(item.alert_count ?? 0)}</td>

                <td>${statusPill(item.status)}</td>

                <td>
                    <button class="action-button"
                        data-open-case="${Number(item.id)}">
                        Investigate
                    </button>
                </td>
            </tr>
        `).join("")
    );

    document.querySelectorAll("#cases-table [data-open-case]")
        .forEach(button => {
            button.addEventListener("click", () => {
                openCase(Number(button.dataset.openCase));
            });
        });
}



/* =========================================================
   INDIVIDUAL ALERT INVESTIGATION WORKSPACE
========================================================= */

async function openAlert(id) {
    if (!Number.isInteger(id) || id < 1) {
        showToast("Invalid alert identifier.", true);
        return;
    }

    state.selectedAlert = id;
    state.alertInvestigation = null;

    switchView("alert");

    $("alert-workspace-empty")?.classList.add("hidden");

   const workspaceContent = $("alert-workspace-content");

   if (workspaceContent) {
       workspaceContent.hidden = false;
       workspaceContent.classList.remove("hidden");
   }

    setText("investigation-alert-title", "Loading alert...");
    setText(
        "investigation-alert-reference",
        `ALERT-${String(id).padStart(6, "0")}`
    );

    setText(
        "investigation-alert-description",
        "Retrieving alert details and investigation history..."
    );

    setHTML(
        "alert-notes-list",
        `<div class="empty-state">Loading investigation notes...</div>`
    );

    setHTML(
        "alert-evidence-list",
        `<div class="empty-state">Loading linked evidence...</div>`
    );

    setHTML(
        "alert-timeline-list",
        `<div class="empty-state">Loading activity timeline...</div>`
    );

    setHTML(
        "alert-audit-table",
        emptyRow(6, "Loading audit history...")
    );

    await loadAlertInvestigation(id);
}

async function loadAlertInvestigation(id) {
    const requestId = ++state.alertRequestId;
    state.loadingAlert = true;

    try {
        const data = await fetchJSON(
            `${API.alerts}/${id}/investigation`
        );

        // Ignore responses belonging to an older selection.
        if (
            requestId !== state.alertRequestId ||
            state.selectedAlert !== id
        ) {
            return;
        }

        if (!data.alert) {
            throw new Error(
                "The API response did not contain an alert."
            );
        }

        state.alertInvestigation = data;

        renderAlertWorkspace(data);

    } catch (error) {
        // Only display errors for the currently selected alert.
        if (
            requestId === state.alertRequestId &&
            state.selectedAlert === id
        ) {
            const workspaceContent = $("alert-workspace-content");

            if (workspaceContent) {
                workspaceContent.hidden = true;
                workspaceContent.classList.add("hidden");
            }

            $("alert-workspace-empty")?.classList.remove("hidden");

            setText(
                "alert-workspace-empty",
                `Unable to load alert investigation: ${error.message}`
            );

            showToast(
                `Could not load alert investigation: ${error.message}`,
                true
            );
        }

    } finally {
        if (requestId === state.alertRequestId) {
            state.loadingAlert = false;
        }
    }
}


function renderAlertWorkspace(data) {
    const alert = data.alert;
    const notes = data.notes ?? [];
    const evidence = data.evidence ?? [];
    const timeline = data.timeline ?? [];
    const audit = data.audit_log ?? [];

    $("alert-workspace-empty")?.classList.add("hidden");

    const workspaceContent = $("alert-workspace-content");

    if (workspaceContent) {
        workspaceContent.hidden = false;
        workspaceContent.classList.remove("hidden");
    }

    setText(
        "investigation-alert-title",
        alert.title ?? "Untitled alert"
    );

    setText(
        "investigation-alert-reference",
        `ALERT-${String(alert.id).padStart(6, "0")}`
    );

    setHTML(
        "investigation-alert-severity",
        severityPill(alert.severity)
    );

    setText(
        "investigation-alert-description",
        alert.description ?? "No description provided."
    );

    setHTML(
        "investigation-alert-status",
        statusPill(alert.status)
    );

    setText(
        "investigation-alert-source",
        alert.source_ip ?? "—"
    );

    setText(
        "investigation-alert-rule",
        alert.detection_rule ?? "—"
    );

    setText(
        "investigation-alert-created",
        formatDate(alert.created_at)
    );

    const statusSelect = $("investigation-status-select");

    if (statusSelect) {
        statusSelect.value = alert.status ?? "open";
    }

    setText("alert-status-feedback", "");

    setText("alert-note-counter", notes.length);
    setText("alert-evidence-counter", evidence.length);
    setText("alert-timeline-counter", timeline.length);
    setText("alert-audit-counter", audit.length);

    renderAlertNotes(notes);
    renderAlertEvidence(evidence);
    renderAlertTimeline(timeline);
    renderAlertAudit(audit);
    renderAlertMitre(data.mitre);
}


/* =========================================================
   ALERT INVESTIGATION NOTES
========================================================= */

function renderAlertNotes(notes) {
    if (!notes.length) {
        setHTML(
            "alert-notes-list",
            `<div class="empty-state">
                No investigation notes have been added.
            </div>`
        );
        return;
    }

    setHTML(
        "alert-notes-list",
        notes.map(note => `
            <article class="record-card">
                <div class="record-card-header">
                    <strong>
                        ${escapeHTML(note.author ?? "Analyst")}
                    </strong>

                    <time>${formatDate(note.created_at)}</time>
                </div>

                <p>${escapeHTML(note.content)}</p>

                <span class="record-id">
                    NOTE #${Number(note.id)}
                </span>
            </article>
        `).join("")
    );
}


async function submitAlertNote(event) {
    event.preventDefault();

    const id = state.selectedAlert;

    if (!id) {
        showToast("Open an alert before adding a note.", true);
        return;
    }

    const content = $("alert-note-content")?.value.trim();

    if (!content) {
        showToast("Enter an investigation note.", true);
        return;
    }

    const button = $("add-alert-note");

    if (button) {
        button.disabled = true;
        button.textContent = "Saving...";
    }

    try {
        await fetchJSON(
            `${API.alerts}/${id}/notes`,
            {
                method: "POST",
                body: JSON.stringify({ content })
            }
        );

        $("alert-note-content").value = "";

        await loadAlertInvestigation(id);
        await loadAlerts();

        showToast("Investigation note saved.");

    } catch (error) {
        showToast(
            `Could not save investigation note: ${error.message}`,
            true
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Add investigation note";
        }
    }
}


/* =========================================================
   ALERT EVIDENCE MANAGEMENT
========================================================= */

function renderAlertEvidence(evidence) {
    if (!evidence.length) {
        setHTML(
            "alert-evidence-list",
            `<div class="empty-state">
                No security events have been linked to this alert.
            </div>`
        );
        return;
    }

    setHTML(
        "alert-evidence-list",
        evidence.map(item => `
            <article class="record-card">
                <div class="record-card-header">
                    <strong>
                        EVENT #${Number(item.event_id)}
                        · ${escapeHTML(item.event_type ?? "Security event")}
                    </strong>

                    <span class="record-id">
                        ${escapeHTML(item.outcome ?? "Unknown outcome")}
                    </span>
                </div>

                <p>
                    ${escapeHTML(
                        item.description ?? "No event description available."
                    )}
                </p>

                <div class="evidence-details">
                    <span>
                        <small>SOURCE IP</small>
                        ${escapeHTML(item.source_ip ?? "—")}
                    </span>

                    <span>
                        <small>USERNAME</small>
                        ${escapeHTML(item.username ?? "—")}
                    </span>

                    <span>
                        <small>LINKED BY</small>
                        ${escapeHTML(item.linked_by ?? "—")}
                    </span>

                    <span>
                        <small>LINKED AT</small>
                        ${formatDate(item.linked_at)}
                    </span>
                </div>

                ${
                    item.analyst_note
                        ? `<p class="muted">
                            <strong>Analyst justification:</strong>
                            ${escapeHTML(item.analyst_note)}
                        </p>`
                        : ""
                }
            </article>
        `).join("")
    );
}


async function submitAlertEvidence(event) {
    event.preventDefault();

    const id = state.selectedAlert;

    if (!id) {
        showToast("Open an alert before linking evidence.", true);
        return;
    }

    const eventId = Number($("alert-evidence-event-id")?.value);
    const analystNote = $("alert-evidence-note")?.value.trim();

    if (!Number.isInteger(eventId) || eventId < 1) {
        showToast("Enter a valid security event ID.", true);
        return;
    }

    const button = $("link-alert-evidence");

    if (button) {
        button.disabled = true;
        button.textContent = "Linking...";
    }

    try {
        await fetchJSON(
            `${API.alerts}/${id}/evidence`,
            {
                method: "POST",
                body: JSON.stringify({
                    event_id: eventId,
                    analyst_note: analystNote || null
                })
            }
        );

        $("alert-evidence-event-id").value = "";
        $("alert-evidence-note").value = "";

        await loadAlertInvestigation(id);

        showToast("Security event linked as evidence.");

    } catch (error) {
        showToast(
            `Could not link evidence: ${error.message}`,
            true
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Link event as evidence";
        }
    }
}


/* =========================================================
   ALERT INVESTIGATION TIMELINE
========================================================= */

function renderAlertTimeline(timeline) {
    if (!timeline.length) {
        setHTML(
            "alert-timeline-list",
            `<div class="empty-state">
                No investigation activity recorded.
            </div>`
        );
        return;
    }

    const sorted = [...timeline].sort((a, b) =>
        new Date(a.created_at) - new Date(b.created_at)
    );

    setHTML(
        "alert-timeline-list",
        sorted.map(item => `
            <article class="timeline-item">
                <span class="timeline-marker"></span>

                <div class="timeline-content">
                    <div class="timeline-header">
                        <strong>
                            ${escapeHTML(item.summary ?? item.action ?? "Activity")}
                        </strong>

                        <time>${formatDate(item.created_at)}</time>
                    </div>

                    ${
                        item.details
                            ? `<p>${escapeHTML(item.details)}</p>`
                            : ""
                    }

                    <span class="record-id">
                        ${escapeHTML(item.actor ?? "system")}
                        · ${escapeHTML(item.action ?? "activity")}
                    </span>
                </div>
            </article>
        `).join("")
    );
}


/* =========================================================
   ALERT AUDIT HISTORY
========================================================= */

function renderAlertAudit(audit) {
    if (!audit.length) {
        setHTML(
            "alert-audit-table",
            emptyRow(6, "No audit records available.")
        );
        return;
    }

    setHTML(
        "alert-audit-table",
        audit.map(item => `
            <tr>
                <td>${formatDate(item.created_at)}</td>

                <td>${escapeHTML(item.action ?? "—")}</td>

                <td>${escapeHTML(item.actor ?? "—")}</td>

                <td>
                    ${escapeHTML(item.previous_value ?? "—")}
                </td>

                <td>
                    ${escapeHTML(item.new_value ?? "—")}
                </td>

                <td>
                    ${escapeHTML(item.details ?? "—")}
                </td>
            </tr>
        `).join("")
    );
}


/* =========================================================
   ALERT STATUS MANAGEMENT
========================================================= */

async function updateAlertStatus() {
    const id = state.selectedAlert;

    if (!id) {
        showToast("No alert is currently selected.", true);
        return;
    }

    const status = $("investigation-status-select")?.value;

    if (!["open", "investigating", "resolved"].includes(status)) {
        showToast("Select a valid alert status.", true);
        return;
    }

    const button = $("save-alert-status");

    if (button) {
        button.disabled = true;
        button.textContent = "Updating...";
    }

    setText("alert-status-feedback", "");

    try {
        const result = await fetchJSON(
            `${API.alerts}/${id}/status`,
            {
                method: "PATCH",
                body: JSON.stringify({ status })
            }
        );

        await loadAlertInvestigation(id);
        await loadAlerts();

        setText(
            "alert-status-feedback",
            result.message ?? "Alert status updated."
        );

        showToast(`Alert status updated to ${status}.`);

    } catch (error) {
        showToast(
            `Alert status update failed: ${error.message}`,
            true
        );

        setText("alert-status-feedback", "Update failed.");

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Save status";
        }
    }
}


/* =========================================================
   CASE WORKSPACE
========================================================= */

async function openCase(id) {
    if (!Number.isInteger(id) || id < 1) {
        showToast("Invalid case identifier.", true);
        return;
    }

    switchView("case");

    setHTML(
        "linked-alerts",
        `<div class="empty-state">Loading linked alerts...</div>`
    );

    setHTML(
        "notes-list",
        `<div class="empty-state">Loading investigation notes...</div>`
    );

    setHTML(
        "timeline-list",
        `<div class="empty-state">Loading case timeline...</div>`
    );

    setHTML(
        "audit-table",
        emptyRow(6, "Loading audit history...")
    );

    await loadCaseDetails(id, true);
}

async function loadCaseDetails(id, showLoading = true) {
    if (state.loadingCase) return;

    state.loadingCase = true;

    if (showLoading) {
        $("case-empty")?.classList.add("hidden");
        $("case-content")?.classList.remove("hidden");
        setText("case-title", "Loading case...");
    }

    try {
        const [detail, timelineData, auditData] = await Promise.all([
            fetchJSON(`${API.correlations}/${id}`),
            fetchJSON(`${API.correlations}/${id}/timeline`),
            fetchJSON(`${API.correlations}/${id}/audit`)
        ]);

        if (!detail.correlation) {
            throw new Error(
                "The API response did not contain a correlation case."
            );
        }

        state.selectedCase = detail.correlation;

        renderCaseWorkspace(
            detail,
            timelineData,
            auditData
        );

    } catch (error) {
        if (showLoading) {
            $("case-content")?.classList.add("hidden");
            $("case-empty")?.classList.remove("hidden");

            setText(
                "case-empty",
                `Unable to load case: ${error.message}`
            );
        }

        showToast(
            `Could not load case: ${error.message}`,
            true
        );

    } finally {
        state.loadingCase = false;
    }
}

function renderCaseWorkspace(detail, timelineData, auditData) {
    const item = detail.correlation;
    const alerts = detail.alerts ?? [];
    const notes = detail.notes ?? [];
    const timeline = timelineData.timeline ?? [];
    const audit = auditData.audit_history ?? [];

    state.selectedCase = item;

    $("case-empty")?.classList.add("hidden");
    $("case-content")?.classList.remove("hidden");

    setText(
        "case-reference",
        `CASE-${String(item.id).padStart(6, "0")}`
    );

    setText("case-title", item.title ?? "Untitled case");

    setText(
        "case-created",
        `Created ${formatDate(item.created_at)}`
    );

    setHTML(
        "case-status-display",
        statusPill(item.status)
    );

    setHTML(
        "case-severity",
        severityPill(item.severity)
    );

    setText("case-source-ip", item.source_ip ?? "—");
    setText("case-alert-count", alerts.length);
    setText("case-assigned", item.assigned_to ?? "Unassigned");

    const statusSelect = $("case-status-select");

    if (statusSelect) {
        statusSelect.value = item.status ?? "open";
    }

    const assigneeInput = $("case-assignee");

    if (assigneeInput) {
        assigneeInput.value = item.assigned_to ?? "";
    }

    setText("case-feedback", "");

    setText("stat-alerts", alerts.length);
    setText("stat-notes", notes.length);
    setText("stat-timeline", timeline.length);
    setText("stat-audit", audit.length);

    setText("linked-alert-counter", alerts.length);
    setText("notes-counter", notes.length);
    setText("timeline-counter", timeline.length);
    setText("audit-counter", audit.length);

    renderLinkedAlerts(alerts);
    renderCaseNotes(notes);
    renderCaseTimeline(timeline);
    renderCaseAudit(audit);
}

function renderLinkedAlerts(alerts) {
    if (!alerts.length) {
        setHTML(
            "linked-alerts",
            `<div class="empty-state">
                No alerts are linked to this case.
            </div>`
        );
        return;
    }

    setHTML(
        "linked-alerts",
        alerts.map(alert => `
            <article class="record-card">
                <div class="record-card-header">
                    <strong>
                        ALERT #${Number(alert.id)}
                        · ${escapeHTML(alert.title)}
                    </strong>

                    ${severityPill(alert.severity)}
                </div>

                <p>
                    ${escapeHTML(
                        alert.description ?? "No description provided."
                    )}
                </p>

                <div class="evidence-details">
                    <span>
                        <small>SOURCE IP</small>
                        ${escapeHTML(alert.source_ip)}
                    </span>

                    <span>
                        <small>DETECTION RULE</small>
                        ${escapeHTML(alert.detection_rule)}
                    </span>

                    <span>
                        <small>STATUS</small>
                        ${escapeHTML(alert.status)}
                    </span>

                    <span>
                        <small>CREATED</small>
                        ${formatDate(alert.created_at)}
                    </span>
                </div>
            </article>
        `).join("")
    );
}

/* =========================================================
   INVESTIGATION NOTES
========================================================= */

function renderCaseNotes(notes) {
    if (!notes.length) {
        setHTML(
            "notes-list",
            `<div class="empty-state">
                No investigation notes have been added.
            </div>`
        );
        return;
    }

    const sorted = [...notes].sort((a, b) =>
        new Date(b.created_at) - new Date(a.created_at)
    );

    setHTML(
        "notes-list",
        sorted.map(note => `
            <article class="record-card">
                <div class="record-card-header">
                    <strong>
                        ${escapeHTML(note.author || "analyst")}
                    </strong>

                    <time>${formatDate(note.created_at)}</time>
                </div>

                <p>${escapeHTML(note.content)}</p>

                <span class="record-id">
                    NOTE #${Number(note.id)}
                </span>
            </article>
        `).join("")
    );
}

async function submitCaseNote(event) {
    event.preventDefault();

    if (!state.selectedCase) {
        showToast("Open a case before adding a note.", true);
        return;
    }

    const content = $("note-content")?.value.trim();

    if (!content) {
        showToast("Enter a note before submitting.", true);
        return;
    }

    const button = $("add-note-button");

    if (button) {
        button.disabled = true;
        button.textContent = "Saving...";
    }

    try {
        const id = Number(state.selectedCase.id);

        await fetchJSON(
            `${API.correlations}/${id}/notes`,
            {
                method: "POST",
                body: JSON.stringify({
                    content
                })
            }
        );

        $("note-content").value = "";

        await loadCaseDetails(id, false);
        await loadCases();

        showToast("Investigation note saved.");

    } catch (error) {
        showToast(
            `Could not save note: ${error.message}`,
            true
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Add note";
        }
    }
}

/* =========================================================
   CASE STATUS MANAGEMENT
========================================================= */

async function updateCaseStatus() {
    if (!state.selectedCase) return;

    const id = Number(state.selectedCase.id);
    const status = $("case-status-select")?.value;

    const button = $("save-case-status");

    if (!["open", "investigating", "resolved"].includes(status)) {
        showToast("Select a valid case status.", true);
        return;
    }

    if (button) {
        button.disabled = true;
        button.textContent = "Updating...";
    }

    setText("case-feedback", "");

    try {
        const result = await fetchJSON(
            `${API.correlations}/${id}/status`,
            {
                method: "PATCH",
                body: JSON.stringify({
                    status,
                    details: "Case status updated through the AEGIS dashboard."
                })
            }
        );

        await loadCases();
        await loadCaseDetails(id, false);

        setText(
            "case-feedback",
            result.message ?? "Case status updated."
        );

        showToast(`Case status updated to ${status}.`);

    } catch (error) {
        showToast(
            `Status update failed: ${error.message}`,
            true
        );

        setText("case-feedback", "Update failed.");

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Save status";
        }
    }
}

/* =========================================================
   CASE ASSIGNMENT MANAGEMENT
========================================================= */

async function updateCaseAssignment(assignedTo) {
    if (!state.selectedCase) return;

    const id = Number(state.selectedCase.id);
    const button = $("save-case-assignment");

    if (button) {
        button.disabled = true;
        button.textContent = "Saving...";
    }

    try {
        const result = await fetchJSON(
            `${API.correlations}/${id}/assignment`,
            {
                method: "PATCH",
                body: JSON.stringify({
                    assigned_to: assignedTo || null,
                })
            }
        );

        await loadCases();
        await loadCaseDetails(id, false);

        showToast(
            assignedTo
                ? `Case assigned to ${assignedTo}.`
                : "Case assignment removed."
        );

        return result;

    } catch (error) {
        showToast(
            `Assignment update failed: ${error.message}`,
            true
        );

        return null;

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Save assignment";
        }
    }
}

async function saveCaseAssignment() {
    const assignedTo = $("case-assignee")?.value.trim();

    if (!assignedTo) {
        showToast(
            "Enter an analyst identifier or use Clear assignment.",
            true
        );
        return;
    }

    await updateCaseAssignment(assignedTo);
}

async function clearCaseAssignment() {
    await updateCaseAssignment(null);
}

/* =========================================================
   CASE TIMELINE
========================================================= */

function renderCaseTimeline(timeline) {
    if (!timeline.length) {
        setHTML(
            "timeline-list",
            `<div class="empty-state">
                No timeline activity recorded.
            </div>`
        );
        return;
    }

    const sorted = [...timeline].sort((a, b) =>
        new Date(a.created_at) - new Date(b.created_at)
    );

    setHTML(
        "timeline-list",
        sorted.map(item => `
            <article class="timeline-item">
                <span class="timeline-marker"></span>

                <div class="timeline-content">
                    <div class="timeline-header">
                        <strong>
                            ${escapeHTML(item.summary)}
                        </strong>

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
        `).join("")
    );
}

/* =========================================================
   CASE AUDIT HISTORY
========================================================= */

function renderCaseAudit(audit) {
    if (!audit.length) {
        setHTML(
            "audit-table",
            emptyRow(6, "No audit records available.")
        );
        return;
    }

    setHTML(
        "audit-table",
        audit.map(item => `
            <tr>
                <td>${formatDate(item.created_at)}</td>

                <td>${escapeHTML(item.action)}</td>

                <td>${escapeHTML(item.actor)}</td>

                <td>
                    ${escapeHTML(item.previous_value ?? "—")}
                </td>

                <td>
                    ${escapeHTML(item.new_value ?? "—")}
                </td>

                <td>
                    ${escapeHTML(item.details ?? "—")}
                </td>
            </tr>
        `).join("")
    );
}


/* =========================================================
   MITRE ATT&CK INTELLIGENCE WORKSPACE
========================================================= */

function techniqueById(techniqueId) {
    return state.mitreTechniques.find(
        technique => technique.technique_id === techniqueId
    );
}

function confidenceClass(value) {
    const confidence = String(value ?? "").toLowerCase();

    if (confidence === "high") return "high";
    if (confidence === "moderate" || confidence === "medium") {
        return "medium";
    }
    if (confidence === "low") return "low";

    return "unknown";
}

function confidencePill(value) {
    const confidence = String(value ?? "unknown").toLowerCase();

    return `
        <span class="mitre-confidence ${confidenceClass(confidence)}">
            ${escapeHTML(confidence)}
        </span>
    `;
}

function getMitreTactics() {
    return [
        ...new Set(
            state.mitreTechniques
                .map(item => item.tactic)
                .filter(Boolean)
        )
    ].sort();
}

async function loadMitreTechniques() {
    const payload = await fetchJSON(`${API.mitre}/techniques`);

    state.mitreTechniques = normaliseList(
        payload,
        ["techniques", "items", "results"]
    );

    renderMitreMetrics();
    renderMitreTacticFilter();
    renderMitreTechniques();
}

async function loadMitreMappings() {
    const payload = await fetchJSON(`${API.mitre}/mappings`);

    const ruleMappings = normaliseList(
        payload,
        ["mappings", "items", "results"]
    );

    state.mitreMappings = ruleMappings.flatMap(rule => {
        const mappings = Array.isArray(rule.mappings)
            ? rule.mappings
            : [];

        return mappings.map(mapping => ({
            ...mapping,
            rule_id: mapping.rule_id || rule.rule_id
        }));
    });

    renderMitreMetrics();
    renderMitreMappings();
}

async function loadMitreData() {
    const results = await Promise.allSettled([
        loadMitreTechniques(),
        loadMitreMappings()
    ]);

    if (results[0].status === "rejected") {
        setHTML(
            "mitre-techniques",
            `<div class="empty-state">
                Could not load ATT&CK techniques:
                ${escapeHTML(
                    results[0].reason?.message ?? "Unknown error"
                )}
            </div>`
        );
    }

    if (results[1].status === "rejected") {
        setHTML(
            "mitre-mappings-table",
            emptyRow(
                5,
                `Could not load rule mappings: ${
                    results[1].reason?.message ?? "Unknown error"
                }`
            )
        );
    }

    renderMitreMetrics();
    renderMitreTechniques();
    renderMitreMappings();
}

function renderMitreMetrics() {
    const techniques = state.mitreTechniques;
    const mappings = state.mitreMappings;
    const registeredRules = state.rules;

    const mappedRules = new Set(
        mappings.map(item => item.rule_id).filter(Boolean)
    );

    const unmappedCount = registeredRules.filter(
        rule => !mappedRules.has(rule.rule_id)
    ).length;

    setText("mitre-technique-count", techniques.length);
    setText("mitre-mapping-count", mappings.length);
    setText("mitre-mapped-rule-count", mappedRules.size);
    setText("mitre-tactic-count", getMitreTactics().length);
    setText("mitre-rule-counter", mappings.length);
    setText("mitre-total-rule-count", registeredRules.length);
    setText("mitre-unmapped-rule-count", unmappedCount);
    setText("mitre-coverage-counter", registeredRules.length);
    renderMitreRuleCoverage();
}

function renderMitreRuleCoverage() {
    const rules = state.rules;
    const mappingsByRule = new Map();

    state.mitreMappings.forEach(mapping => {
        if (!mapping.rule_id) return;

        if (!mappingsByRule.has(mapping.rule_id)) {
            mappingsByRule.set(mapping.rule_id, []);
        }

        mappingsByRule.get(mapping.rule_id).push(mapping);
    });

    if (!rules.length) {
        setHTML(
            "mitre-rule-coverage-table",
            emptyRow(5, "No registered detection rules are available. Check the detection-rules API.")
        );
        return;
    }

    const sortedRules = [...rules].sort(
        (a, b) => String(a.rule_id).localeCompare(String(b.rule_id))
    );

    setHTML(
        "mitre-rule-coverage-table",
        sortedRules.map(rule => {
            const mappings = mappingsByRule.get(rule.rule_id) ?? [];
            const techniques = mappings.map(mapping => {
                const technique = mapping.technique || techniqueById(mapping.technique_id);
                const name = technique?.name ?? mapping.technique_id;

                return `
                    <button
                        type="button"
                        class="mitre-table-link"
                        data-mitre-technique="${escapeHTML(mapping.technique_id)}"
                    >${escapeHTML(mapping.technique_id)} · ${escapeHTML(name)}</button>
                `;
            }).join("<br>");

            return `
                <tr>
                    <td><strong>${escapeHTML(rule.rule_id)}</strong></td>
                    <td>
                        <strong>${escapeHTML(rule.name)}</strong>
                        <span class="mitre-rule-description">${escapeHTML(rule.description ?? "")}</span>
                    </td>
                    <td>${severityPill(rule.severity)}</td>
                    <td>
                        ${mappings.length
                            ? '<span class="mitre-coverage-status mapped">Mapped</span>'
                            : '<span class="mitre-coverage-status unmapped">Unmapped</span>'}
                    </td>
                    <td>${techniques || '<span class="muted">No ATT&CK technique associated</span>'}</td>
                </tr>
            `;
        }).join("")
    );

    document.querySelectorAll(
        "#mitre-rule-coverage-table [data-mitre-technique]"
    ).forEach(button => {
        button.addEventListener("click", () => {
            selectMitreTechnique(button.dataset.mitreTechnique);
            $("mitre-detail-panel")?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        });
    });
}

function renderMitreTacticFilter() {
    const select = $("mitre-tactic-filter");

    if (!select) return;

    const currentValue = select.value || "all";

    select.innerHTML = `
        <option value="all">All tactics</option>
        ${getMitreTactics().map(tactic => `
            <option value="${escapeHTML(tactic)}">
                ${escapeHTML(tactic)}
            </option>
        `).join("")}
    `;

    select.value = getMitreTactics().includes(currentValue)
        ? currentValue
        : "all";
}

function renderMitreTechniques() {
    const search = (
        $("mitre-search")?.value ?? ""
    ).trim().toLowerCase();

    const tactic = $("mitre-tactic-filter")?.value ?? "all";

    const filtered = state.mitreTechniques.filter(technique => {
        const searchable = [
            technique.technique_id,
            technique.name,
            technique.tactic,
            technique.tactic_id,
            technique.description
        ].join(" ").toLowerCase();

        return searchable.includes(search) &&
            (tactic === "all" || technique.tactic === tactic);
    });

    setText("mitre-results-count", filtered.length);

    if (!filtered.length) {
        setHTML(
            "mitre-techniques",
            `<div class="empty-state">
                No techniques match your search.
            </div>`
        );
        return;
    }

    setHTML(
        "mitre-techniques",
        filtered.map(technique => `
            <button
                type="button"
                class="mitre-technique-card ${
                    state.selectedMitreTechnique === technique.technique_id
                        ? "selected"
                        : ""
                }"
                data-mitre-technique="${escapeHTML(technique.technique_id)}"
            >
                <div class="mitre-card-top">
                    <span class="mitre-technique-id">
                        ${escapeHTML(technique.technique_id)}
                    </span>
                    <span class="mitre-tactic">
                        ${escapeHTML(technique.tactic ?? "Unclassified")}
                    </span>
                </div>

                <strong>${escapeHTML(technique.name)}</strong>

                <p>
                    ${escapeHTML(
                        technique.description || "No description available."
                    )}
                </p>

                <span class="mitre-card-action">View technique details →</span>
            </button>
        `).join("")
    );

    document.querySelectorAll("[data-mitre-technique]")
        .forEach(button => {
            button.addEventListener("click", () => {
                selectMitreTechnique(
                    button.dataset.mitreTechnique
                );
            });
        });
}

function selectMitreTechnique(techniqueId) {
    const technique = techniqueById(techniqueId);

    if (!technique) {
        showToast("Technique not found in the local catalogue.", true);
        return;
    }

    state.selectedMitreTechnique = techniqueId;

    renderMitreTechniques();
    renderMitreTechniqueDetail(technique);
}

function renderMitreTechniqueDetail(technique) {
    const parentId = technique.parent_technique_id;
    const parent = parentId ? techniqueById(parentId) : null;

    const relatedMappings = state.mitreMappings.filter(
        mapping => mapping.technique_id === technique.technique_id
    );

    const reference = technique.url ||
        `https://attack.mitre.org/techniques/${encodeURIComponent(
            technique.technique_id.replace(".", "/")
        )}/`;

    setHTML(
        "mitre-technique-detail",
        `
            <div class="mitre-detail-header">
                <div>
                    <span class="mitre-technique-id">
                        ${escapeHTML(technique.technique_id)}
                    </span>
                    <h3>${escapeHTML(technique.name)}</h3>
                    <span class="mitre-tactic">
                        ${escapeHTML(technique.tactic ?? "Unclassified")}
                    </span>
                </div>

                <a
                    class="mitre-link"
                    href="${escapeHTML(reference)}"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    Open ATT&CK reference ↗
                </a>
            </div>

            <div class="mitre-detail-grid">
                <div class="detail-field">
                    <small>TECHNIQUE ID</small>
                    <strong>${escapeHTML(technique.technique_id)}</strong>
                </div>

                <div class="detail-field">
                    <small>TACTIC</small>
                    <strong>${escapeHTML(technique.tactic ?? "—")}</strong>
                </div>

                <div class="detail-field">
                    <small>TACTIC ID</small>
                    <strong>${escapeHTML(technique.tactic_id ?? "—")}</strong>
                </div>

                <div class="detail-field">
                    <small>PARENT TECHNIQUE</small>
                    <strong>
                        ${parent
                            ? `${escapeHTML(parent.technique_id)} · ${escapeHTML(parent.name)}`
                            : escapeHTML(parentId ?? "None")}
                    </strong>
                </div>
            </div>

            <div class="mitre-description">
                <h4>Description</h4>
                <p>${escapeHTML(
                    technique.description || "No description available."
                )}</p>
            </div>

            <div class="mitre-description">
                <h4>AEGIS detection coverage</h4>
                ${
                    relatedMappings.length
                        ? relatedMappings.map(mapping => `
                            <article class="record-card">
                                <div class="record-card-header">
                                    <strong>
                                        ${escapeHTML(mapping.rule_id)}
                                    </strong>
                                    ${confidencePill(mapping.confidence)}
                                </div>

                                <p>${escapeHTML(
                                    mapping.rationale ?? "No mapping rationale supplied."
                                )}</p>

                                <span class="record-id">
                                    ${escapeHTML(mapping.mapping_type ?? "Mapping type unspecified")}
                                </span>
                            </article>
                        `).join("")
                        : `<div class="empty-state">
                            No AEGIS detection rule is currently mapped to this technique.
                        </div>`
                }
            </div>
        `
    );
}

function renderMitreMappings() {
    const mappings = state.mitreMappings;

    if (!mappings.length) {
        setHTML(
            "mitre-mappings-table",
            emptyRow(6, "No detection rule mappings are available.")
        );
        return;
    }

    setHTML(
        "mitre-mappings-table",
        mappings.map(mapping => {
            const technique =
                mapping.technique ||
                techniqueById(mapping.technique_id);

            return `
                <tr>
                    <td>
                        <strong>${escapeHTML(mapping.rule_id)}</strong>
                    </td>
                    <td>
                        <button
                            type="button"
                            class="mitre-table-link"
                            data-mitre-technique="${escapeHTML(mapping.technique_id)}"
                        >
                            ${escapeHTML(mapping.technique_id)} -
                            ${escapeHTML(
                                technique?.name ?? "Unknown technique"
                            )}
                        </button>
                    </td>
                    <td>${escapeHTML(technique?.tactic ?? "-")}</td>
                    <td>${confidencePill(mapping.confidence)}</td>
                    <td>${escapeHTML(mapping.mapping_type ?? "-")}</td>
                    <td>
                        <span class="mitre-rationale">${escapeHTML(mapping.rationale ?? "No mapping rationale supplied.")}</span>
                        ${mapping.evidence_requirements
                            ? `<span class="mitre-evidence-note"><strong>Evidence:</strong> ${escapeHTML(Array.isArray(mapping.evidence_requirements) ? mapping.evidence_requirements.join(" ") : mapping.evidence_requirements)}</span>`
                            : ""}
                    </td>
                </tr>`;
        }).join("")
    );

    document.querySelectorAll(
        "#mitre-mappings-table [data-mitre-technique]"
    ).forEach(button => {
        button.addEventListener("click", () => {
            selectMitreTechnique(button.dataset.mitreTechnique);

            $("mitre-detail-panel")?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        });
    });
}

function renderAlertMitre(mitre) {
    const container = $("alert-mitre-mapping");

    if (!container) return;

    const mappings = mitre?.mappings ?? [];

    setText("alert-mitre-count", mappings.length);

    if (!mitre || !mitre.mapped || !mappings.length) {
        setHTML(
            "alert-mitre-mapping",
            `<div class="empty-state">
                No ATT&CK technique mapping is currently associated
                with this detection rule.
            </div>`
        );
        return;
    }

    setHTML(
        "alert-mitre-mapping",
        mappings.map(mapping => {
            const technique =
                mapping.technique ||
                techniqueById(mapping.technique_id);

            const reference = technique?.url ||
                `https://attack.mitre.org/techniques/${encodeURIComponent(
                    mapping.technique_id.replace(".", "/")
                )}/`;

            return `
                <article class="record-card mitre-alert-card">
                    <div class="record-card-header">
                        <strong>
                            <a
                                class="mitre-link"
                                href="${escapeHTML(reference)}"
                                target="_blank"
                                rel="noopener noreferrer"
                            >
                                ${escapeHTML(mapping.technique_id)} -
                                ${escapeHTML(
                                    technique?.name ?? mapping.technique_id
                                )}
                            </a>
                        </strong>

                        ${confidencePill(mapping.confidence)}
                    </div>

                    <div class="evidence-details">
                        <span>
                            <small>TACTIC</small>
                            <strong>${escapeHTML(technique?.tactic ?? "-")}</strong>
                        </span>

                        <span>
                            <small>MAPPING TYPE</small>
                            <strong>${escapeHTML(mapping.mapping_type ?? "-")}</strong>
                        </span>
                    </div>

                    <p>
                        ${escapeHTML(
                            mapping.rationale ?? "No mapping rationale supplied."
                        )}
                    </p>

                    ${
                        mapping.evidence_requirements
                            ? `<p class="muted">
                                <strong>Evidence Considerations:</strong>
                                ${escapeHTML(
                                    Array.isArray(mapping.evidence_requirements)
                                        ? mapping.evidence_requirements.join(". ")
                                        : mapping.evidence_requirements
                                )}
                              </p>`
                            : ""
                    }
                </article>`;
        }).join("")
    );
}

/* =========================================================
   NAVIGATION
========================================================= */

function switchView(view) {
    const validViews = [
        "overview",
        "alerts",
        "events",
        "investigations",
        "case",
        "alert",
        "rules",
        "mitre"
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
        investigations: "Investigations",
        case: "Case Workspace",
        alert: "Alert Investigation",
        rules: "Detection Rules",
        mitre: "MITRE ATT&CK"
    };

    setText("breadcrumb-current", names[view]);
    setText("page-heading", names[view]);

    if (view === "alerts") {
        renderAlertsTable();
    }

    if (view === "events") {
        renderEventsTable();
    }

    if (view === "investigations") {
        renderCasesTable();
    }

    if (view === "mitre") {
        loadMitreData();
    }
}

/* =========================================================
   EVENT LISTENERS
========================================================= */

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
        const view = button.dataset.view;

        if (view === "case" && !state.selectedCase) {
            switchView("investigations");
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

$("back-to-cases")?.addEventListener("click", () => {
    switchView("investigations");
});

$("back-to-alerts")?.addEventListener("click", () => {
    switchView("alerts");
});

$("alert-note-form")?.addEventListener(
    "submit",
    submitAlertNote
);

$("alert-evidence-form")?.addEventListener(
    "submit",
    submitAlertEvidence
);

$("save-alert-status")?.addEventListener(
    "click",
    updateAlertStatus
);

$("refresh-button")?.addEventListener(
    "click",
    refreshDashboard
);

$("alert-search")?.addEventListener(
    "input",
    renderAlertsTable
);

$("alert-status-filter")?.addEventListener(
    "change",
    renderAlertsTable
);

$("alert-severity-filter")?.addEventListener(
    "change",
    renderAlertsTable
);

$("event-search")?.addEventListener(
    "input",
    renderEventsTable
);

$("case-search")?.addEventListener(
    "input",
    renderCasesTable
);

$("case-status-filter")?.addEventListener(
    "change",
    renderCasesTable
);

$("case-severity-filter")?.addEventListener(
    "change",
    renderCasesTable
);

$("note-form")?.addEventListener(
    "submit",
    submitCaseNote
);

$("save-case-status")?.addEventListener(
    "click",
    updateCaseStatus
);

$("save-case-assignment")?.addEventListener(
    "click",
    saveCaseAssignment
);

$("clear-case-assignment")?.addEventListener(
    "click",
    clearCaseAssignment
);

$("mitre-search")?.addEventListener(
    "input",
    renderMitreTechniques
);

$("mitre-tactic-filter")?.addEventListener(
    "change",
    renderMitreTechniques
);

/* =========================================================
   INITIALISE DASHBOARD
========================================================= */

async function startDashboardSession(token) {
    const gate = $("auth-gate");
    const error = $("auth-error");

    if (!token) {
        if (gate) gate.hidden = false;
        return;
    }

    sessionStorage.setItem("aegis_access_token", token);

    try {
        const session = await fetchJSON("/api/v1/auth/me");

        if (gate) gate.hidden = true;
        if ($("auth-identity")) {
            $("auth-identity").textContent =
                `${session.actor_id} · ${session.role}`;
        }

        await refreshDashboard();
    } catch (requestError) {
        sessionStorage.removeItem("aegis_access_token");
        if (gate) gate.hidden = false;
        if (error) {
            error.textContent =
                "Authentication failed. Check the token and try again.";
        }
    }
}

$("auth-form")?.addEventListener("submit", async event => {
    event.preventDefault();

    const token = $("auth-token")?.value.trim();

    if (!token) {
        if ($("auth-error")) {
            $("auth-error").textContent = "Enter an access token.";
        }
        return;
    }

    if ($("auth-error")) $("auth-error").textContent = "";
    await startDashboardSession(token);
});

$("logout-button")?.addEventListener("click", () => {
    sessionStorage.removeItem("aegis_access_token");
    window.location.reload();
});

startDashboardSession(
    sessionStorage.getItem("aegis_access_token")
);

window.setInterval(() => {
    if (sessionStorage.getItem("aegis_access_token")) {
        refreshDashboard();
    }
}, 15000);
