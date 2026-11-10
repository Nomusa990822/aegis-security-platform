
/* =========================================================
   AEGIS — ADAPTIVE THEME MANAGER
   System / Light / Dark
========================================================= */

(() => {
    "use strict";

    const STORAGE_KEY = "aegis_theme_preference";
    const VALID_THEMES = ["system", "light", "dark"];

    const root = document.documentElement;
    const colourScheme = window.matchMedia(
        "(prefers-color-scheme: dark)"
    );

    let preference = "system";

    try {
        const saved = localStorage.getItem(STORAGE_KEY);

        if (VALID_THEMES.includes(saved)) {
            preference = saved;
        }
    } catch {
        preference = "system";
    }

    function resolveTheme() {
        if (preference === "system") {
            return colourScheme.matches ? "dark" : "light";
        }

        return preference;
    }

    function applyTheme() {
        const resolved = resolveTheme();

        root.dataset.theme = resolved;
        root.dataset.themePreference = preference;

        const logo = document.getElementById("brand-logo");

        if (logo) {
            logo.src =
                `/dashboard/assets/aegis-sentinel-${resolved}.svg`;
        }

        const selector = document.getElementById("theme-select");

        if (selector && selector.value !== preference) {
            selector.value = preference;
        }

        const themeMeta = document.querySelector(
            'meta[name="theme-color"]'
        );

        if (themeMeta) {
            themeMeta.content = resolved === "dark"
                ? "#090d16"
                : "#F4F7FB";
        }
    }

    function savePreference(nextPreference) {
        if (!VALID_THEMES.includes(nextPreference)) {
            return;
        }

        preference = nextPreference;

        try {
            localStorage.setItem(STORAGE_KEY, preference);
        } catch {
            // The current selection still applies for this session.
        }

        applyTheme();
    }

    // Apply the saved preference before the dashboard is displayed.
    applyTheme();

    document.addEventListener("DOMContentLoaded", () => {
        const selector = document.getElementById("theme-select");

        if (selector) {
            selector.value = preference;

            selector.addEventListener("change", event => {
                savePreference(event.target.value);
            });
        }

        // Reapply the theme when the operating-system preference changes.
        // This only affects the application when System is selected.
        applyTheme();
    });

    colourScheme.addEventListener("change", () => {
        if (preference === "system") {
            applyTheme();
        }
    });
})();
