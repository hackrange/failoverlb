/* =============================================================================
   Failover LB, front end.

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
    // Set once the pending banner is wired up.  Kept at this level so api()
    // can nudge it after a write without knowing anything about the banner.
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

        // Is this page still the page the server is serving.
        //
        // A tab already open is never re-fetched, however good the cache
        // headers are, and most of this GUI's JavaScript is inline in the
        // template.  So a tab left open across an upgrade keeps running the
        // old script, and the failures look like bugs in the feature rather
        // than an old page: a form missing a field that shipped, a button
        // calling an endpoint that moved.  Both of those were reported as
        // faults before this existed.
        //
        // Checked here because every page talks to the API, so it costs one
        // header comparison and needs no timer, no extra request, and nothing
        // to remember to wire up on a new page.
        checkBuild(response.headers.get("X-NFM-Build"));

        // Anything that changed something may have made the saved config differ
        // from the running one, so ask again rather than waiting for the timer.
        // Skipped for the status call itself, which would loop forever.
        if (method !== "GET" && method !== "HEAD" && pendingRefresh) {
            pendingRefresh();
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
    // ------------------------------------------------------- the page is old
    //
    // Said once, and left up.  A toast disappears, and the whole problem here
    // is that somebody carries on for another ten minutes wondering why a
    // feature is missing.  It does not reload on its own either: the page may
    // have half filled a form, and taking that away to fix a problem they have
    // not noticed yet is a worse trade than a line at the top of the screen.
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

        // A modal holding a form does not close when you click the backdrop.
        //
        // For a help popup, click anywhere to dismiss is what everybody expects
        // and there is nothing to lose.  For a form it is the opposite: you
        // have typed a hostname, a port and three settings, your mouse clips
        // the edge of the box, and it is all gone with no undo.  That is a
        // horrible thing to do to somebody and it is entirely avoidable.
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

            // The backdrop itself.  Only dismisses when there is nothing to
            // lose.  The target check also stops a click that begins inside the
            // box and drifts out from closing it, which otherwise ruins
            // selecting text.
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

    // Has anybody actually put anything in this form?  Nothing typed means
    // nothing to warn about, and a confirm box on an untouched form is just
    // noise.
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

        // Applying, shared by the page button and the one in the pending
        // banner.  Both get the real handler rather than one forwarding clicks
        // to the other, because forwarding put every bit of feedback on the
        // wrong button and the banner looked dead when it was working fine.
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

        // Show what applying would actually change.  "Something is pending" is
        // half an answer, and the other half should not require applying it to
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

        // Saved is not live.  Check on load, then keep an eye on it, because
        // the editors save over the API without reloading the page and the
        // banner would otherwise stay wrong until you navigated.
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
                    // Losing the session or the network is its own alarm
                    // elsewhere.  Do not flash a banner about it.
                }
            }
            pendingRefresh = refreshPending;
            refreshPending();
            setInterval(refreshPending, 15000);
        }

        // Filter boxes.
        //
        // Anything with data-filter="<selector>" filters the things that
        // selector matches, on the text in their data-search attribute.  Built
        // once here rather than per page, so sites, pools and certificates
        // behave the same and there is one place to fix.
        //
        // Client side on purpose.  These lists are tens to hundreds of rows and
        // filtering them in the browser is instant, where a round trip per
        // keystroke is not.  If somebody turns up with thousands, this becomes
        // a query and the markup does not have to change.
        document.querySelectorAll("[data-filter]").forEach(function (box) {
            const targets = Array.from(document.querySelectorAll(box.getAttribute("data-filter")));
            const empty = document.getElementById(box.getAttribute("data-filter-empty"));
            const count = document.getElementById(box.getAttribute("data-filter-count"));

            function apply() {
                const needle = box.value.trim().toLowerCase();
                let shown = 0;

                targets.forEach(function (el) {
                    // Fall back to the row's own text, so a page that forgets
                    // data-search still filters on something sensible rather
                    // than hiding everything.
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
