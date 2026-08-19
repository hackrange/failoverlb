"""
Break the thing on purpose, and see whether its check notices.

The only honest way to ask "would this check still pass if the behaviour it
tests were removed".  A check that passes against a broken product is not a
check, it is a comment, and this project has shipped three of those: a CSRF
cookie that was never sent so every role check was proving the wrong guard, a
`deny all` that every site config already contains so "the site denies
everything" was true of a site that denied nobody, and a WAF suite whose idea
of ordinary traffic was four tidy GETs.

Each mutation is a small surgical edit to a copy of `app/` or `host-agent/`.
Nothing live is touched.  A mutation that does not apply is reported as such,
because a mutation that quietly did nothing would look exactly like a check
that caught nothing.

    python3 tools/mutation/mutate.py            # every mutation
    python3 tools/mutation/mutate.py access     # ones whose name matches
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IMAGE = "nginx-fleet-manager:1.0.0"

# (name, check to run, file, find, replace)
MUTATIONS = [
    ("acl reaches http", "access_lists", "app/core/render.py",
     "lines.extend(self._render_body(host, cfg, tls=False, acl=acl,",
     "lines.extend(self._render_body(host, cfg, tls=False,"),

    ("acme stays open under a deny", "access_lists", "app/core/render.py",
     '        lines.append("        allow all;")\n        lines.append("        try_files $uri =404;")',
     '        lines.append("        try_files $uri =404;")'),

    ("block known drops the policy rules", "waf", "app/core/render.py",
     "        ] + self._block_known_lines(mode)",
     "        ] + []  # mutation: block known malicious enforces everything"),

    ("the waf gate asks for loaded", "waf", "app/core/capabilities.py",
     "        if answered and not all(answered):",
     "        if False:"),

    ("waf_module travels in a snapshot", "waf", "app/core/settings_store.py",
     'SNAPSHOT_KEYS = FLEET_KEYS + INTERNAL_FLEET_KEYS',
     'SNAPSHOT_KEYS = FLEET_KEYS'),

    ("a second default site is refused", "default_site", "app/web/routes_api.py",
     "    if blocked:\n        raise HTTPException(",
     "    if False:\n        raise HTTPException("),

    ("a viewer cannot write", "authz_sweep", "app/auth/service.py",
     '    UserRole.VIEWER: {\n        "view",\n    },',
     '    UserRole.VIEWER: {\n        "view", "edit_sites", "edit_pools",\n    },'),

    ("values cannot become config", "render_safety", "app/core/render.py",
     "def esc(value) -> str:",
     "def esc(value) -> str:\n    return str(value)  # mutation: no quoting"),

    ("a setting that does nothing is caught", "wiring", "app/catalog/features.py",
     'key="waf_mode"',
     'key="waf_mode_typo_nothing_reads"'),

    ("you cannot change your own role", "users_page", "app/web/routes_account.py",
     '    if target.id == actor.id:\n        return _users_back("you cannot change your own role")',
     '    if False:\n        return _users_back("you cannot change your own role")'),

    ("you cannot disable your own account", "users_page", "app/web/routes_account.py",
     "    if not turning_on and target.id == actor.id:",
     "    if False and target.id == actor.id:"),

    ("the second default refusal", "default_site", "app/web/routes_api.py",
     "    if other:\n        raise HTTPException(",
     "    if False:\n        raise HTTPException("),

    ("the standby message tells the truth", "standby_message", "app/core/cluster.py",
     "            if me is not None and me.role == NodeRole.STANDBY:",
     "            if True:"),

    # ---- the second batch, security and correctness -----------------------

    ("secrets are compared in constant time", "trust", "app/core/crypto.py",
     "    return hmac.compare_digest(a.encode(), b.encode())",
     "    return a == b  # mutation: leaks how much matched"),

    ("a peer signature is verified", "trust", "app/core/crypto.py",
     "    expected = sign_payload(hmac_key, node_name, timestamp, nonce, body)\n"
     "    return hmac.compare_digest(expected, signature)",
     "    return True  # mutation: any signature will do"),

    ("blocking a country writes the rules", "geo_blocking", "app/core/render.py",
     "        codes = [str(c).strip().upper() for c in (cfg.get(\"geoip2_country_block\") or [])\n"
     "                 if str(c).strip()]",
     "        codes = []  # mutation: block nothing"),

    ("a password spray is detected", "login_watch", "app/core/login_watch.py",
     "        loud = [a for a in addresses if a[\"count\"] >= watch.brute_threshold]",
     "        loud = []  # mutation: never loud"),

    ("a backend that keeps failing is marked down", "health_checks",
     "app/core/health.py",
     "            if old_state != MemberState.DOWN and member.consecutive_fail >= (pool.health_check_fall or 3):",
     "            if False:"),

    ("a backend that recovers is marked up", "health_checks",
     "app/core/health.py",
     "            if old_state != MemberState.UP and member.consecutive_ok >= (pool.health_check_rise or 2):",
     "            if False:"),

    ("weights move one step at a time", "adaptive_weights", "app/core/health.py",
     "            if ideal > m.weight:\n                new = min(ideal, m.weight + 1)",
     "            if ideal > m.weight:\n                new = ideal  # mutation: jump straight there"),

    ("a hopeless backend keeps a floor", "adaptive_weights", "app/core/health.py",
     "            ideal = max(min_w, min(max_w, round(ideal)))",
     "            ideal = round(ideal)  # mutation: no floor, no ceiling"),

    ("uniformly slow is left alone", "adaptive_weights", "app/core/health.py",
     "        if fastest > float(cfg.get(\"adaptive_floor_ms\", 1000)):",
     "        if False:"),

    ("the allow list is not wide open", "accepted_risks", "app/config.py",
     '    admin_allowlist: str = Field(default="")',
     '    admin_allowlist: str = Field(default="0.0.0.0/0")'),

    # ---- the third batch, the checks with no mutation yet -----------------

    ("local passwords can really be turned off", "auth_modes",
     "app/core/settings_store.py",
     '    return auth_mode() != "oidc"',
     "    return True  # mutation: a password always gets you in"),

    ("the provider is only offered when the mode allows", "auth_modes",
     "app/core/settings_store.py",
     '    return auth_mode() in ("both", "oidc")',
     "    return True  # mutation: always offer it"),

    ("a backend path keeps its trailing slash", "backend_path",
     "app/core/render.py",
     '        if not value.endswith("/"):',
     "        if False:  # mutation: no trailing slash, so paths glue together"),

    ("a catalog default is written rather than left to nginx", "catalog_sweep",
     "app/core/render.py",
     "        feature = get_feature(key)\n        if not feature or not self.supports(key):\n            return None\n        return feature.default",
     "        return None  # mutation: never fall back to the catalog"),

    ("the comparison totals add up", "comparison", "app/catalog/comparison.py",
     "def product_totals():",
     "def product_totals():\n    return []  # mutation: no totals at all"),

    ("stopping the dns listener waits for its threads", "gslb_listener",
     "app/core/gslb.py",
     "        for thread in self._threads:\n            if thread is threading.current_thread():\n                continue\n            thread.join(timeout=STOP_TIMEOUT_SECONDS)",
     "        pass  # mutation: close underneath the threads, as it used to"),

    ("a quoted string is one token", "parser", "app/core/nginx_parser.py",
     '        if ch in "\\"\'":',
     "        if False:  # mutation: quotes are not special"),

    ("a rewrite steps around the certificate challenge", "rewrite_guards",
     "app/core/render.py",
     '            lines.append(f"{pad}if ($request_uri ~ ^/\\\\.well-known/acme-challenge/) {{")',
     '            lines.append(f"{pad}if ($request_uri ~ ^/__never_matches__) {{")'),

    ("the settings put replaces rather than merges", "settings_merge",
     "app/web/routes_api.py",
     '        host.settings = json.dumps(_validate_settings(payload["settings"], "server"))',
     '        _merged = dict(host.setting_map()); _merged.update(payload["settings"])\n'
     '        host.settings = json.dumps(_validate_settings(_merged, "server"))'),

    ("an unknown setting is dropped rather than stored", "settings_merge",
     "app/web/routes_api.py",
     "        feature = get_feature(key)\n        if not feature:\n            problems.append(f\"there is no setting called {key}\")\n            continue",
     "        feature = get_feature(key)\n        if not feature:\n            cleaned[key] = value  # mutation: keep unknown keys\n            continue"),

    ("a page that raises is noticed", "page_sweep", "app/web/routes_pages.py",
     "async def waf_profiles_page(request: Request, db: DBSession = Depends(get_db)):",
     "async def waf_profiles_page(request: Request, db: DBSession = Depends(get_db)):\n    raise RuntimeError('mutation: this page is broken')"),

    ("a template with an unclosed block is noticed", "templates",
     "app/web/templates/waf_profiles.html",
     "{% if not profiles %}",
     "{% if not profiles %}{% if True %}"),

    ("a template with an unclosed named block is noticed", "templates",
     "app/web/templates/waf_profiles.html",
     "{% block content %}",
     "{% block content %}{% block stray %}"),

    ("a page that never reaches the layout is noticed", "templates",
     "app/web/templates/waf_profiles.html",
     "{% block content %}",
     "{% block not_a_real_block %}"),

    ("an address is not handed out twice", "tunnel_addresses",
     "app/core/tunnel.py",
     "    taken |= addresses_pools_point_at(session, network)",
     "    pass  # mutation: forget what pools still point at"),

    ("a missing column is added on upgrade", "upgrade_migration", "app/db.py",
     "                parts = [f'ALTER TABLE {table.name} ADD COLUMN \"{column.name}\" {ddl_type}']",
     "                continue  # mutation: never add the column"),

    ("an empty pool costs one site, not the fleet", "regressions",
     "app/core/render.py",
     "            if not self._pool_has_servers(pool):",
     "            if False:  # mutation: write an empty upstream block, which nginx refuses"),

    ("the bill of materials matches the build", "sbom",
     "sbom/sbom.spdx.json",
     '"name": "failover-lb',
     '"name": "not-the-same-build-at-all'),

    ("a rollback that fails puts it back", "rollback", "host-agent/nginx-mgr-agent.py",
     "        previous = MANAGED_DIR.parent / (MANAGED_DIR.name + \".before-rollback\")",
     "        previous = None if True else MANAGED_DIR.parent / 'x'"),
]


# Checks that run against the repository or the host rather than in the
# container.  `rollback` reads the deployed agent by path; `sbom` regenerates
# the bill of materials from files in the tree and compares.
HOST_CHECKS = {"rollback", "sbom"}


def run(check_name, tree):
    """Run one check with app/ and host-agent/ taken from a mutated tree."""
    if check_name == "sbom":
        # From inside the mutated tree, so it reads that tree's sbom/ and
        # installer rather than the real ones.
        proc = subprocess.run([sys.executable, str(tree / "checks" / "sbom.py")],
                              cwd=str(tree), capture_output=True, text=True,
                              timeout=600)
        return proc.returncode, proc.stdout + proc.stderr

    if check_name == "rollback":
        # A host check, not a container one.  It reads the deployed agent by
        # path, so point it at the mutated copy instead.
        script = (tree / "checks" / "rollback.py").read_text().replace(
            'AGENT = Path("/opt/nginx-fleet-manager/nginx-mgr-agent.py")',
            f'AGENT = Path("{tree}/host-agent/nginx-mgr-agent.py")')
        tmp = tree / "checks" / "_mutated_rollback.py"
        tmp.write_text(script)
        proc = subprocess.run([sys.executable, str(tmp)],
                              capture_output=True, text=True, timeout=600)
        return proc.returncode, proc.stdout + proc.stderr

    # A copy of the database, not the live one.
    #
    # A mutation that turns a refusal into a success does not just make the
    # check pass, it makes the write **happen**.  The first run of this
    # harness gave a viewer edit_pools and left a real pool and a real site in
    # the fleet's database, which then turned up in the next check's output.
    # A tool for finding checks that lie must not leave litter of its own.
    #
    # sqlite keeps recent writes in a write ahead log, so the backup API is
    # used rather than a file copy: a copy of the .db alone is the database as
    # of some earlier moment.
    data = tree / "data"
    data.mkdir(exist_ok=True)
    subprocess.run(
        ["docker", "run", "--rm", "-v", "nginx-gui-mgmt_nfm-data:/live",
         "-v", f"{data}:/copy", IMAGE, "python", "-c",
         "import sqlite3, shutil, os, glob;"
         "src=sqlite3.connect('/live/fleet.db');dst=sqlite3.connect('/copy/fleet.db');"
         "src.backup(dst);src.close();dst.close();"
         "[shutil.copy(f, '/copy') for f in glob.glob('/live/*') "
         " if not os.path.basename(f).startswith('fleet.db')]"],
        capture_output=True, timeout=300)

    cmd = [
        "docker", "run", "--rm", "-i", "--network", "container:nginx-fleet-manager",
        "-v", f"{tree}/app:/app/app:ro",
        "-v", f"{tree}/checks:/app/checks:ro",
        "-v", "/run/nginxmgr:/run/nginxmgr",
        "-v", f"{data}:/data",
        "-v", "/etc/nginx:/host/etc/nginx:ro",
        "-v", "/etc/letsencrypt:/host/etc/letsencrypt:ro",
        "-w", "/app", IMAGE, "python",
    ]
    with (tree / "checks" / f"{check_name}.py").open() as fh:
        proc = subprocess.run(cmd, stdin=fh, capture_output=True, text=True,
                              timeout=900)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else ""
    caught, blind, broken = [], [], []

    for name, check_name, rel, find, replace in MUTATIONS:
        if want and want not in name and want not in check_name:
            continue
        tree = Path(tempfile.mkdtemp(prefix="mutation-"))
        try:
            # `extra` and not `name`: the loop variable of the mutation
            # itself is called name, and reusing it here renamed the mutation
            # in the report to whichever file was copied last.  The harness
            # reported a real result under the wrong heading, which is the
            # exact failure it exists to find.
            for extra in ("nginx-installer.sh", "requirements.txt",
                          "docker-compose.yml", "Dockerfile"):
                if (REPO / extra).is_file():
                    shutil.copy(REPO / extra, tree / extra)
            for folder in ("app", "checks", "host-agent", "sbom", "tools"):
                if not (REPO / folder).is_dir():
                    continue
                shutil.copytree(REPO / folder, tree / folder,
                                ignore=shutil.ignore_patterns("__pycache__"))
            target = tree / rel
            text = target.read_text()
            if text.count(find) != 1:
                broken.append((name, check_name,
                               f"the mutation matched {text.count(find)} times, not once"))
                print(f"  ????  {name:38} [{check_name}] mutation did not apply")
                continue
            target.write_text(text.replace(find, replace))

            code, output = run(check_name, tree)
            if code == 0:
                blind.append((name, check_name, output))
                print(f"  BLIND {name:38} [{check_name}] passed against broken code")
            else:
                caught.append((name, check_name))
                print(f"  caught {name:37} [{check_name}]")
        except Exception as exc:
            broken.append((name, check_name, str(exc)))
            print(f"  ????  {name:38} [{check_name}] {exc}")
        finally:
            shutil.rmtree(tree, ignore_errors=True)

    print(f"\n  caught {len(caught)}, blind {len(blind)}, "
          f"could not run {len(broken)}")
    if blind:
        print("\n  checks that passed against broken code:")
        for name, check_name, _out in blind:
            print(f"    {check_name:20} does not notice: {name}")
    return 1 if blind else 0


if __name__ == "__main__":
    sys.exit(main())
