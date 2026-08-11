/* =============================================================================
   NGINX Management, front end.

   Plain JavaScript.  No framework, no build step, no packages.  For a tool that
   has to work on an isolated network while something is on fire, a page that
   renders from the HTML the server sent beats one that needs a bundle to load
   first.

   Three jobs in here:
     1. Talk to the API and always send the CSRF token
     2. Show the help popups
     3. Small bits of page behaviour
   ============================================================================= */

(function () {
    "use strict";

    // ------------------------------------------------------------- path prefix
    // Empty in the normal case, something like /test when a proxy in front puts
    // us on a sub path.  Everything the page fetches goes through this, so both
    // cases work with no other change.
    function basePath() {
        const meta = document.querySelector('meta[name="nfm-base"]');
        return meta ? meta.getAttribute("content") || "" : "";
    }

    // ------------------------------------------------------------------ CSRF
    // The token is in a cookie our own script can read.  We copy it into a
    // header on every write.  A form posted from another site carries the
    // cookie, because browsers do that, but it cannot read that cookie to set
    // the header, so it fails.  That is the double submit pattern.
    function csrfToken() {
        const match = document.cookie.match(/(?:^|;\s*)nfm_csrf=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    // ------------------------------------------------------------------- API
    async function api(path, options) {
        options = options || {};
        const method = options.method || "GET";

        const headers = { "Accept": "application/json" };
        if (options.body !== undefined) {
            headers["Content-Type"] = "application/json";
        }
        if (method !== "GET" && method !== "HEAD") {
            headers["X-CSRF-Token"] = csrfToken();
        }

        let response;
        try {
            response = await fetch(basePath() + "/api" + path, {
                method: method,
                headers: headers,
                body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
                credentials: "same-origin"
            });
        } catch (err) {
            throw new Error("Could not reach the manager.  Is it still running?");
        }

        // A 401 means the session went away, usually because it timed out.
        // Send them to the login page rather than showing a confusing error.
        if (response.status === 401) {
            window.location.href = basePath() + "/login";
            throw new Error("signed out");
        }

        let data = null;
        const text = await response.text();
        if (text) {
            try { data = JSON.parse(text); } catch (e) { data = { detail: text }; }
        }

        if (!response.ok) {
            const detail = data && data.detail;
            throw new Error(formatError(detail) || ("request failed with " + response.status));
        }

        return data;
    }

    // The apply endpoint hands back a structured object when a node refuses,
    // because knowing which node said no and what nginx told it is the whole
    // point.  Flatten it into something readable.
    function formatError(detail) {
        if (!detail) return null;
        if (typeof detail === "string") return detail;

        if (detail.error) {
            let message = detail.error;
            if (detail.failed && detail.failed.length) {
                message += "\n\n" + detail.failed.map(function (f) {
                    return f.node + ": " + (f.error || "").split("\n").slice(0, 3).join("\n");
                }).join("\n\n");
            }
            if (detail.node) message += "\n\nnode: " + detail.node;
            return message;
        }
        return JSON.stringify(detail);
    }

    // ---------------------------------------------------------------- toasts
    function toast(message, kind) {
        let holder = document.getElementById("toasts");
        if (!holder) {
            holder = document.createElement("div");
            holder.id = "toasts";
            document.body.appendChild(holder);
        }

        const box = document.createElement("div");
        box.className = "toast " + (kind || "");
        box.textContent = message;
        holder.appendChild(box);

        // Errors stay long enough to actually read, since they often contain
        // several lines of nginx output.
        setTimeout(function () { box.remove(); }, kind === "bad" ? 12000 : 4500);
    }

    // ----------------------------------------------------------- help popups
    // The content comes from the same catalog the forms and the config renderer
    // read, so the help can never end up describing something the tool does not
    // actually do.
    let catalogCache = null;

    async function loadCatalog(context) {
        if (catalogCache) return catalogCache;
        catalogCache = await api("/catalog?context=" + encodeURIComponent(context || "server"));
        return catalogCache;
    }

    function buildHelpModal(feature) {
        const help = feature.help || {};
        const parts = [];

        parts.push('<div class="help-section"><p>' + escapeHtml(help.summary || "") + "</p></div>");

        if (help.detail) {
            parts.push('<div class="help-section"><h4>What it does</h4><p>' +
                escapeHtml(help.detail) + "</p></div>");
        }

        if (help.warning) {
            parts.push('<div class="notice warn">' + icon("warn") +
                "<div>" + escapeHtml(help.warning) + "</div></div>");
        }

        if (help.use_cases && help.use_cases.length) {
            parts.push('<div class="help-section"><h4>When you would use it</h4><ul>' +
                help.use_cases.map(function (u) {
                    return "<li>" + escapeHtml(u) + "</li>";
                }).join("") + "</ul></div>");
        }

        if (help.example) {
            parts.push('<div class="help-section"><h4>Suggested value</h4><p>' +
                escapeHtml(help.example) + "</p></div>");
        }

        if (help.example_config) {
            parts.push('<div class="help-section"><h4>What it looks like in the config</h4><pre>' +
                escapeHtml(help.example_config) + "</pre></div>");
        }

        if (!feature.available) {
            parts.push('<div class="notice bad">' + icon("warn") +
                "<div>This nginx was not built with the <code>" +
                escapeHtml(feature.module) +
                "</code> module, so this setting is not available on this box.  " +
                "Add it to the module list in the installer script and rebuild.</div></div>");
        }

        if (help.docs_url) {
            parts.push('<div class="help-section"><h4>Reference</h4><p><a href="' +
                escapeHtml(help.docs_url) + '" target="_blank" rel="noopener noreferrer">' +
                escapeHtml(help.docs_url) + "</a></p></div>");
        }

        return parts.join("");
    }

    function openModal(title, subtitle, bodyHtml, wide) {
        closeModal();

        const backdrop = document.createElement("div");
        backdrop.className = "modal-backdrop";
        backdrop.id = "active-modal";

        backdrop.innerHTML =
            '<div class="modal' + (wide ? " wide" : "") + '" role="dialog" aria-modal="true">' +
            '<div class="modal-head"><div><h3>' + escapeHtml(title) + "</h3>" +
            (subtitle ? '<div class="directive">' + escapeHtml(subtitle) + "</div>" : "") +
            '</div><button class="modal-close" aria-label="Close">&times;</button></div>' +
            '<div class="modal-body">' + bodyHtml + "</div>" +
            '<div class="modal-foot"><button class="btn" data-close>Close</button></div>' +
            "</div>";

        document.body.appendChild(backdrop);

        // Click outside to close, but only on the backdrop itself.  Without the
        // target check, a click that starts inside the modal and drifts out
        // closes it, which is maddening when you are selecting text.
        backdrop.addEventListener("click", function (e) {
            if (e.target === backdrop || e.target.hasAttribute("data-close") ||
                e.target.classList.contains("modal-close")) {
                closeModal();
            }
        });

        document.addEventListener("keydown", escClose);
    }

    function escClose(e) {
        if (e.key === "Escape") closeModal();
    }

    function closeModal() {
        const existing = document.getElementById("active-modal");
        if (existing) existing.remove();
        document.removeEventListener("keydown", escClose);
    }

    // ------------------------------------------------------------------ icons
    // Drawn by hand as inline SVG.  No image files, no icon font, nothing
    // fetched from anywhere.  Keeps the content security policy tight and means
    // the whole GUI works with no outside network at all.
    const ICONS = {
        warn: '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5 15 14H1L8 1.5zm0 4a.7.7 0 0 0-.7.8l.25 3.2a.45.45 0 0 0 .9 0l.25-3.2A.7.7 0 0 0 8 5.5zm0 5.4a.8.8 0 1 0 0 1.6.8.8 0 0 0 0-1.6z"/></svg>',
        info: '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm0 3a.9.9 0 1 1 0 1.8A.9.9 0 0 1 8 4zm1.2 8H6.8v-.9h.7V7.9h-.7V7h2.1v4.1h.3V12z"/></svg>',
        check: '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M13.5 4.5 6 12 2.5 8.5l1-1L6 10l6.5-6.5 1 1z"/></svg>'
    };

    function icon(name) {
        return ICONS[name] || "";
    }

    // ------------------------------------------------------------- utilities
    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text === null || text === undefined ? "" : String(text);
        return div.innerHTML;
    }

    async function confirmThen(message, action) {
        if (!window.confirm(message)) return;
        try {
            await action();
        } catch (err) {
            toast(err.message, "bad");
        }
    }

    // --------------------------------------------------------------- wiring
    document.addEventListener("DOMContentLoaded", function () {

        // Any element with data-help="setting_key" gets a working ? button.
        document.body.addEventListener("click", async function (e) {
            const trigger = e.target.closest("[data-help]");
            if (!trigger) return;

            e.preventDefault();
            const key = trigger.getAttribute("data-help");
            const context = trigger.getAttribute("data-help-context") || "server";

            try {
                const catalog = await loadCatalog(context);
                const feature = catalog.features.find(function (f) { return f.key === key; });
                if (!feature) {
                    toast("No help written for " + key + " yet", "bad");
                    return;
                }
                openModal(
                    feature.label,
                    feature.directive ? feature.directive : "",
                    buildHelpModal(feature)
                );
            } catch (err) {
                toast(err.message, "bad");
            }
        });

        // Static help, where the text is written into the page rather than
        // coming from the catalog.  Used for things that are not nginx
        // directives, like the cluster and certificate pages.
        document.body.addEventListener("click", function (e) {
            const trigger = e.target.closest("[data-help-static]");
            if (!trigger) return;
            e.preventDefault();

            const source = document.getElementById(trigger.getAttribute("data-help-static"));
            if (!source) return;

            openModal(
                trigger.getAttribute("data-help-title") || "Help",
                trigger.getAttribute("data-help-sub") || "",
                source.innerHTML,
                trigger.hasAttribute("data-help-wide")
            );
        });

        // Apply button, on every page that has one.
        const applyBtn = document.getElementById("apply-config");
        if (applyBtn) {
            applyBtn.addEventListener("click", async function () {
                applyBtn.disabled = true;
                const original = applyBtn.textContent;
                applyBtn.textContent = "Applying...";

                try {
                    const result = await api("/apply", {
                        method: "POST",
                        body: { summary: "applied from the web GUI" }
                    });

                    if (result.unchanged) {
                        toast("Nothing had changed, so nothing was reloaded");
                    } else {
                        let message = "Applied version " + result.version +
                            " to " + result.applied_to.join(", ");
                        if (result.queued_for && result.queued_for.length) {
                            message += ".  Queued for " + result.queued_for.join(", ") +
                                ", they will catch up when they are back.";
                        }
                        toast(message, "ok");
                        setTimeout(function () { window.location.reload(); }, 1200);
                    }
                } catch (err) {
                    toast(err.message, "bad");
                } finally {
                    applyBtn.disabled = false;
                    applyBtn.textContent = original;
                }
            });
        }

        // Sidebar toggle on narrow screens.
        const toggle = document.querySelector(".menu-toggle");
        if (toggle) {
            toggle.addEventListener("click", function () {
                document.querySelector(".sidebar").classList.toggle("open");
            });
        }
    });

    // Let the pages use these.
    window.NFM = {
        api: api,
        toast: toast,
        openModal: openModal,
        closeModal: closeModal,
        confirmThen: confirmThen,
        escapeHtml: escapeHtml,
        icon: icon
    };
})();
