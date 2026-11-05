
/* =========================================================
   AEGIS CONTROLLED RESPONSE INTERFACE
   Dry-run only. No real containment is performed.
========================================================= */

(() => {
    "use strict";

    const RESPONSE_API = "/api/v1/response";

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

        if (Number.isNaN(date.getTime())) {
            return "—";
        }

        return date.toLocaleString();
    }

    function selectedAlertId() {
        const reference = $("investigation-alert-reference")
            ?.textContent
            ?.trim();

        const match = reference?.match(/^ALERT-(\d+)$/);

        return match ? Number(match[1]) : null;
    }

    function sourceIP() {
        return $("investigation-alert-source")
            ?.textContent
            ?.trim() || "";
    }

    function setFeedback(message, isError = false) {
        const element = $("response-feedback");

        if (!element) return;

        element.textContent = message;
        element.classList.toggle("error", isError);
    }

    async function requestJSON(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            headers: {
                "Accept": "application/json",
                ...(options.body
                    ? { "Content-Type": "application/json" }
                    : {}),
                ...options.headers
            }
        });

        const payload = await response.json().catch(() => ({}));

        if (!response.ok) {
            const detail = payload.detail
                ? JSON.stringify(payload.detail)
                : `HTTP ${response.status}`;

            throw new Error(detail);
        }

        return payload;
    }

    function renderResult(payload) {
        const container = $("response-result");
        const result = payload.result;

        if (!container || !result) return;

        const reasons = Array.isArray(result.reasons)
            ? result.reasons
            : [];

        container.innerHTML = `
            <div class="response-result-header">
                <strong>Response evaluation</strong>
                <span class="response-status ${escapeHTML(result.status)}">
                    ${escapeHTML(result.status)}
                </span>
            </div>

            <div class="response-result-grid">
                <div class="response-result-item">
                    <small>Response ID</small>
                    <strong>#${escapeHTML(payload.response_id)}</strong>
                </div>

                <div class="response-result-item">
                    <small>Action</small>
                    <strong>${escapeHTML(result.action)}</strong>
                </div>

                <div class="response-result-item">
                    <small>Target</small>
                    <strong>${escapeHTML(result.target)}</strong>
                </div>

                <div class="response-result-item">
                    <small>Policy allowed</small>
                    <strong>${result.policy_allowed ? "Yes" : "No"}</strong>
                </div>

                <div class="response-result-item">
                    <small>Approval required</small>
                    <strong>${result.approval_required ? "Yes" : "No"}</strong>
                </div>

                <div class="response-result-item">
                    <small>Real execution</small>
                    <strong>${result.executed ? "Yes" : "No"}</strong>
                </div>
            </div>

            <ul class="response-reasons">
                ${reasons.map(reason =>
                    `<li>${escapeHTML(reason)}</li>`
                ).join("")}
            </ul>
        `;

        container.classList.add("visible");
    }

    function renderHistory(records) {
        const table = $("response-history-table");

        if (!table) return;

        const alertId = selectedAlertId();

        const filtered = records.filter(
            record => record.alert_id === alertId
        );

        if (!filtered.length) {
            table.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        No response previews recorded for this alert.
                    </td>
                </tr>
            `;
            return;
        }

        table.innerHTML = filtered.map(record => `
            <tr>
                <td class="response-id">#${escapeHTML(record.id)}</td>
                <td>${escapeHTML(record.action)}</td>
                <td>${escapeHTML(record.target)}</td>
                <td>
                    <span class="response-status ${escapeHTML(record.status)}">
                        ${escapeHTML(record.status)}
                    </span>
                </td>
                <td>
                    <span class="response-boolean">
                        ${record.executed ? "YES" : "NO"}
                    </span>
                </td>
                <td>${escapeHTML(record.requested_by)}</td>
                <td>${escapeHTML(formatDate(record.created_at))}</td>
            </tr>
        `).join("");
    }

    async function loadResponseHistory() {
        const button = $("refresh-response-history");

        if (button) button.disabled = true;

        try {
            setFeedback("Retrieving response history...");

            const payload = await requestJSON(
                `${RESPONSE_API}/history?limit=100`
            );

            renderHistory(payload.responses ?? []);

            setFeedback(
                `Loaded ${payload.count ?? 0} recorded response entries.`
            );

        } catch (error) {
            setFeedback(
                `Unable to load response history: ${error.message}`,
                true
            );

        } finally {
            if (button) button.disabled = false;
        }
    }

    async function submitPreview() {
        const button = $("submit-response-preview");
        const targetInput = $("response-target");
        const alertId = selectedAlertId();

        if (!alertId) {
            setFeedback(
                "Open an alert investigation before creating a preview.",
                true
            );
            return;
        }

        const target = targetInput?.value?.trim();

        if (!target) {
            setFeedback("Enter a target IP address.", true);
            return;
        }

        if (button) button.disabled = true;

        setFeedback("Evaluating response policy...");

        try {
            const payload = await requestJSON(
                `${RESPONSE_API}/preview`,
                {
                    method: "POST",
                    body: JSON.stringify({
                        alert_id: alertId,
                        action: "block_ip",
                        target,
                        requested_by: "analyst-01"
                    })
                }
            );

            renderResult(payload);

            setFeedback(
                `Preview #${payload.response_id} saved successfully.`
            );

            await loadResponseHistory();

        } catch (error) {
            setFeedback(
                `Response preview failed: ${error.message}`,
                true
            );

        } finally {
            if (button) button.disabled = false;
        }
    }

    function useAlertSourceIP() {
        const input = $("response-target");
        const ip = sourceIP();

        if (!input || !ip || ip === "—") {
            setFeedback(
                "This alert does not have a usable source IP.",
                true
            );
            return;
        }

        input.value = ip;
        setFeedback("Alert source IP copied into the response target.");
    }

    function initialise() {
        $("response-target")?.addEventListener(
            "input",
            () => {
                $("response-result")?.classList.remove("visible");
            }
        );

        $("use-alert-source-ip")?.addEventListener(
            "click",
            useAlertSourceIP
        );

        $("submit-response-preview")?.addEventListener(
            "click",
            submitPreview
        );

        $("refresh-response-history")?.addEventListener(
            "click",
            loadResponseHistory
        );

        const sourceElement = $("investigation-alert-source");

        if (sourceElement) {
            const observer = new MutationObserver(() => {
                const input = $("response-target");

                if (input && !input.value.trim()) {
                    const ip = sourceIP();

                    if (ip && ip !== "—") {
                        input.value = ip;
                    }
                }
            });

            observer.observe(sourceElement, {
                childList: true,
                characterData: true,
                subtree: true
            });
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialise);
    } else {
        initialise();
    }
})();
