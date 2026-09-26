/* =============================================================================
   Failover LB, front end.

   Plain JavaScript. No framework, no build step, no packages. It has to work
   on an isolated network during an outage, so pages render from the server's
   HTML without a bundle.

   Three jobs in here:
     1. Talk to the API and always send the CSRF token
     2. Show the help popups
     3. Small bits of page behavior
   ============================================================================= */

(function () {
    "use strict";

    // ------------------------------------------------------------- path prefix
    // Empty normally, something like /test when a proxy puts us on a sub path.
    // Everything the page fetches goes through this.
    function basePath() {
        const meta = document.querySelector('meta[name="nfm-base"]');
        return meta ? meta.getAttribute("content") || "" : "";
    }

    // ------------------------------------------------------------------ CSRF
    // The token is in a cookie our script can read, copied into a header on
    // every write. A cross site form carries the cookie but cannot read it to
    // set the header, so it fails. Double submit pattern.
    function csrfToken() {
        const match = document.cookie.match(/(?:^|;\s*)nfm_csrf=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    // ------------------------------------------------------------------- API
    // Set once the pending banner is wired up, so api() can nudge it after a
    // write without knowing about the banner.
    let pendingRefresh = null;

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

        // A 401 means the session ended, usually a timeout. Go to the login
        // page rather than showing a confusing error.
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

        // Is this page still the one the server is serving?
        //
        // Open tabs are never refetched, and most of the JavaScript is inline
        // in templates. So a tab left open across an upgrade runs old script,
        // and the failures look like feature bugs: a missing form field, a
        // button calling an endpoint that moved.
        //
        // Checked here because every page uses the API, so it is one header
        // comparison with no timer or extra request.
        checkBuild(response.headers.get("X-NFM-Build"));

        // A write may have made saved config differ from running, so recheck
        // now instead of waiting for the timer. Skipped for the status call
        // itself to avoid a loop.
        if (method !== "GET" && method !== "HEAD" && pendingRefresh) {
            pendingRefresh();
        }

        return data;
    }

    // When a node refuses, apply returns a structured object saying which node
    // and what nginx said. Flatten it into something readable.
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
    // ------------------------------------------------------- the page is old
    //
    // Shown once and left up, not as a toast, so it is not missed. It does not
    // reload on its own, since that could throw away a half filled form.
    let buildWarned = false;

    function checkBuild(serverBuild) {
        if (!serverBuild || buildWarned) { return; }
        const meta = document.querySelector('meta[name="nfm-build"]');
        const mine = meta ? meta.getAttribute("content") : "";
        if (!mine || mine === serverBuild) { return; }

        buildWarned = true;
        const bar = document.createElement("div");
        bar.className = "stale-bar";
        bar.innerHTML =
            "<div><strong>This page is out of date.</strong> " +
            "The manager has been upgraded since you opened it, so what you " +
            "are looking at is running the old version and may be missing " +
            "things or calling endpoints that have moved.</div>" +
            '<button type="button" class="btn sm">Reload</button>';
        bar.querySelector("button").addEventListener("click", function () {
            window.location.reload();
        });
        document.body.appendChild(bar);
    }

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

        // Errors stay long enough to read, since they often contain several
        // lines of nginx output.
        setTimeout(function () { box.remove(); }, kind === "bad" ? 12000 : 4500);
    }

    // ----------------------------------------------------------- help popups
    // Content comes from the same catalog as the forms and config renderer, so
    // help cannot describe something the tool does not do.
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
            let why = escapeHtml(feature.unavailable_reason || "not available on this build");
            let fix = feature.min_version
                ? "Upgrade the oldest node, or leave this setting alone until you do."
                : "Add it to the module list at the top of nginx-installer.sh and run " +
                  "the install again on the nodes that are missing it.";
            parts.push('<div class="notice bad">' + icon("warn") +
                "<div><strong>Not available: </strong>" + why + "<br>" + fix + "</div></div>");
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

        // A modal holding a form does not close on a backdrop click.
        //
        // Click anywhere to dismiss suits help popups, where nothing is lost.
        // On a form one stray click would throw away everything typed.
        //
        // So forms close on the X, the Close button, or Escape, and Escape asks
        // first if anything has been filled in.
        const hasForm = backdrop.querySelector("input, select, textarea") !== null;

        backdrop.addEventListener("click", function (e) {
            const wantsClose = e.target.hasAttribute("data-close") ||
                               e.target.classList.contains("modal-close");

            if (wantsClose) {
                if (hasForm && modalHasContent(backdrop) &&
                    !window.confirm("Close this and lose what you have typed?")) {
                    return;
                }
                closeModal();
                return;
            }

            // The backdrop itself. Only dismisses when there is nothing to
            // lose. The target check also stops a click that starts inside
            // the box and drifts out, which would break text selection.
            if (e.target === backdrop && !hasForm) {
                closeModal();
            }
        });

        document.addEventListener("keydown", escClose);
    }

    function escClose(e) {
        if (e.key !== "Escape") return;

        const backdrop = document.getElementById("active-modal");
        if (backdrop && backdrop.querySelector("input, select, textarea") &&
            modalHasContent(backdrop) &&
            !window.confirm("Close this and lose what you have typed?")) {
            return;
        }
        closeModal();
    }

    // Has anything been entered in this form? If not, skip the confirm.
    function modalHasContent(backdrop) {
        const fields = backdrop.querySelectorAll("input, select, textarea");
        for (const field of fields) {
            if (field.type === "checkbox" || field.type === "radio") {
                if (field.checked !== field.defaultChecked) return true;
            } else if (field.type === "hidden") {
                continue;
            } else if ((field.value || "").trim() !== (field.defaultValue || "").trim()) {
                return true;
            }
        }
        return false;
    }

    function closeModal() {
        const existing = document.getElementById("active-modal");
        if (existing) existing.remove();
        document.removeEventListener("keydown", escClose);
    }

    // ------------------------------------------------------------------ icons
    // Inline SVG, drawn by hand. Nothing fetched, which keeps the CSP tight and
    // works with no outside network.
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

        // Static help written into the page rather than from the catalog, for
        // things that are not nginx directives (cluster, certificates).
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

        // Apply, shared by the page button and the pending banner. Both get
        // the real handler; forwarding clicks put the feedback on the wrong
        // button and made the banner look dead.
        async function doApply(btn) {
            btn.disabled = true;
            const original = btn.textContent;
            btn.textContent = "Applying...";

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
                btn.disabled = false;
                btn.textContent = original;
            }
        }

        ["apply-config", "pending-config-apply"].forEach(function (id) {
            const btn = document.getElementById(id);
            if (btn) {
                btn.addEventListener("click", function () { doApply(btn); });
            }
        });

        // Show what applying would change, without having to apply it to
        // find out.
        const showBtn = document.getElementById("pending-config-show");
        if (showBtn) {
            showBtn.addEventListener("click", async function () {
                showBtn.disabled = true;
                try {
                    const r = await api("/config/pending");
                    let html = "";
                    if (!r.changed_files) {
                        html = '<div class="help-section"><p>Nothing differs from the '
                             + 'config that is live.</p></div>';
                    } else {
                        html = '<div class="help-section"><p>'
                             + r.changed_files + ' file'
                             + (r.changed_files === 1 ? "" : "s")
                             + ' would change'
                             + (r.never_applied ? ", and nothing has ever been applied"
                                                : ", against version " + r.applied_version)
                             + ".</p></div>";
                        r.changes.forEach(function (c) {
                            html += '<div class="help-section"><h4>'
                                 + escapeHtml(c.path) + " <span class=\"faint\">"
                                 + c.kind + "</span></h4><pre>"
                                 + escapeHtml(c.diff.join("\n"))
                                 + (c.truncated ? "\n... trimmed" : "")
                                 + "</pre></div>";
                        });
                    }
                    openModal("Waiting to be applied", "", html, true);
                } catch (err) {
                    toast(err.message, "bad");
                } finally {
                    showBtn.disabled = false;
                }
            });
        }

        // Saved is not live. Check on load, then poll, because the editors
        // save over the API without a reload and the banner would go stale.
        const banner = document.getElementById("pending-config");
        if (banner) {
            async function refreshPending() {
                try {
                    const st = await api("/status");
                    const cfg = (st && st.config) || {};
                    banner.hidden = !cfg.dirty;
                    if (cfg.dirty) {
                        const title = document.getElementById("pending-config-title");
                        const detail = document.getElementById("pending-config-detail");
                        if (cfg.never_applied) {
                            title.textContent = "Nothing has been applied yet";
                            detail.textContent = "This config has never been sent to nginx.  "
                                + "Apply it to make it live.";
                        } else {
                            title.textContent = "Saved, but not live yet";
                            detail.textContent = "These changes are stored.  nginx is still "
                                + "running version " + cfg.applied_version + ".";
                        }
                    }
                } catch (err) {
                    // Lost session or network is reported elsewhere. No
                    // banner for it here.
                }
            }
            pendingRefresh = refreshPending;
            refreshPending();
            setInterval(refreshPending, 15000);
        }

        // Filter boxes.
        //
        // data-filter="<selector>" filters the matching elements on their
        // data-search text. Built once here so every list page behaves the
        // same.
        //
        // Client side on purpose: these lists are tens to hundreds of rows,
        // and filtering locally is instant. At thousands this would become a
        // query without changing the markup.
        document.querySelectorAll("[data-filter]").forEach(function (box) {
            const targets = Array.from(document.querySelectorAll(box.getAttribute("data-filter")));
            const empty = document.getElementById(box.getAttribute("data-filter-empty"));
            const count = document.getElementById(box.getAttribute("data-filter-count"));

            function apply() {
                const needle = box.value.trim().toLowerCase();
                let shown = 0;

                targets.forEach(function (el) {
                    // Fall back to the row's own text, so a page missing
                    // data-search still filters sensibly.
                    const hay = (el.getAttribute("data-search") || el.textContent || "").toLowerCase();
                    const match = !needle || hay.indexOf(needle) !== -1;
                    el.hidden = !match;
                    if (match) shown += 1;
                });

                if (empty) empty.hidden = !needle || shown > 0;
                if (count) {
                    count.textContent = needle
                        ? shown + " of " + targets.length
                        : targets.length + (targets.length === 1 ? " total" : " total");
                }
            }

            box.addEventListener("input", apply);
            // Escape clears, which is what people try before reaching for the mouse.
            box.addEventListener("keydown", function (e) {
                if (e.key === "Escape") { box.value = ""; apply(); }
            });
            apply();
        });

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
        icon: icon,
        csrfToken: csrfToken
    };
})();
