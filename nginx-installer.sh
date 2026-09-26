#!/usr/bin/env bash
#
# Nginx from source installer.
#
# Builds nginx against a current OpenSSL for post quantum key exchange, hides
# the nginx name in the Server header, adds our usual modules, sets up certbot
# and keeps a backup so a bad build can be reverted with one command.
#
# Certbot runs in webroot mode.  Do not install python3-certbot-nginx: it
# pulls in Ubuntu's nginx package (see protect_from_apt).
#
# Everyday use:
#   sudo ./nginx-installer.sh install          # build and install nginx
#   sudo ./nginx-installer.sh revert           # go back to the last build
#   sudo ./nginx-installer.sh cert example.com you@example.com
#   sudo ./nginx-installer.sh renew            # renew every cert
#   sudo ./nginx-installer.sh status           # quick health check
#
# To upgrade, change NGINX_VERSION below and run install again.  The old
# build is backed up first, so revert always has something to go back to.

# -E lets the ERR trap fire inside functions too, so a failure always reports
# where it happened.
set -Eeuo pipefail


# =============================================================================
# Versions
# =============================================================================

# Pinned versions.  Bump and rerun install to upgrade.  Each can also be set
# from the environment (handy for Ansible or Terraform).
NGINX_VERSION="${NGINX_VERSION:-1.30.4}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
HEADERS_MORE_VERSION="${HEADERS_MORE_VERSION:-0.40}"

# The WAF engine, built from source.  Ubuntu 24.04 ships libmodsecurity3
# 3.0.12, which predates two CVE fixes in 3.0.15 (an integer underflow in the
# verify operators and a buffer overflow in hex_decode).
MODSECURITY_VERSION="${MODSECURITY_VERSION:-3.0.16}"


# =============================================================================
# Included modules
# =============================================================================
#
# Add or drop modules here.  There are four lists:
#
#   BUILTIN_MODULES      nginx's own modules, enabled by configure flag.
#   THIRD_PARTY_MODULES  outside modules downloaded and compiled in.
#   DYNAMIC_MODULES      outside modules built as .so, loaded on demand.
#   EXTRA_BUILD_DEPS     apt packages those modules need to build.
#
# Comment out a line to drop a module, add a line and rerun install to add
# one.  Order matters in THIRD_PARTY_MODULES: the devel kit must come before
# lua, which depends on it.

# nginx's built in modules.  These are just flags, no downloads needed.
BUILTIN_MODULES=(
  --with-compat
  --with-threads
  --with-file-aio
  --with-http_ssl_module
  --with-http_v2_module
  # HTTP/3.  Needs a TLS library with the QUIC API, which OpenSSL has had
  # since 3.5.  QUIC is also where post quantum key exchange matters most,
  # since its handshake carries data from the first flight.
  --with-http_v3_module
  --with-http_realip_module
  --with-http_stub_status_module
  --with-http_gzip_static_module
  --with-http_sub_module
  --with-http_dav_module              # base for the dav-ext module
  --with-http_addition_module
  --with-http_auth_request_module
  --with-http_secure_link_module
  --with-http_slice_module
  --with-http_geoip_module            # legacy geoip, needs libgeoip-dev
  --with-http_image_filter_module     # needs libgd-dev
  --with-http_perl_module             # needs libperl-dev
  --with-http_xslt_module             # needs libxml2-dev and libxslt1-dev
  --with-mail
  --with-mail_ssl_module
  --with-stream
  --with-stream_ssl_module
  --with-stream_realip_module
  --with-stream_ssl_preread_module
  --with-stream_geoip_module
  --with-pcre-jit
)

# Outside modules, as "folder|git-url|git-ref".  The ref can be a tag or a
# branch.
THIRD_PARTY_MODULES=(
  "ngx_devel_kit|https://github.com/vision5/ngx_devel_kit|master"
  "lua-nginx-module|https://github.com/openresty/lua-nginx-module|v0.10.28"
  "echo-nginx-module|https://github.com/openresty/echo-nginx-module|v0.63"
  "headers-more-nginx-module|https://github.com/openresty/headers-more-nginx-module|v${HEADERS_MORE_VERSION}"
  "ngx-fancyindex|https://github.com/aperezdc/ngx-fancyindex|v0.5.2"
  "ngx_cache_purge|https://github.com/nginx-modules/ngx_cache_purge|master"
  "nginx-dav-ext-module|https://github.com/arut/nginx-dav-ext-module|v3.0.0"
  "subs-filter|https://github.com/yaoweibin/ngx_http_substitutions_filter_module|master"
  "upload-progress|https://github.com/masterzen/nginx-upload-progress-module|master"
  "auth-pam|https://github.com/sto/ngx_http_auth_pam_module|master"
  "geoip2|https://github.com/leev/ngx_http_geoip2_module|master"
  "upstream-fair|https://github.com/itoffshore/nginx-upstream-fair|master"
)

# nchan was removed on August 25, 2026.  Nothing here used it, but compiled
# in it grabbed a 128 MB shared memory zone on every node.  Twice, after a
# reload, workers aborted inside it holding that zone's lock, and since a
# reload reuses the zone, nginx kept accepting connections without answering
# any until a full restart.  If pub/sub is ever needed, add it to
# DYNAMIC_MODULES so it only loads where a config asks for it.

# Modules built as loadable .so files, same format as above.  ModSecurity
# links against libmodsecurity.so; compiled in, a missing or mismatched
# library would stop nginx from starting at all.  As a .so it is only loaded
# on nodes whose sites have the WAF on.  Needs --with-compat (set above).
#
# The WAF is off by default since it adds a couple of minutes to every build.
# Turning it on in the GUI rebuilds with WITH_MODSECURITY=1, or by hand:
#
#   sudo WITH_MODSECURITY=1 ./nginx-installer.sh install
#
WITH_MODSECURITY="${WITH_MODSECURITY:-0}"

DYNAMIC_MODULES=()
if [[ "$WITH_MODSECURITY" == "1" ]]; then
  DYNAMIC_MODULES+=(
    "modsecurity-nginx|https://github.com/owasp-modsecurity/ModSecurity-nginx|v1.0.4"
  )
fi

# Extra apt packages the modules above need at build time.
EXTRA_BUILD_DEPS=(
  libpam0g-dev        # auth-pam
  libmaxminddb-dev    # geoip2
  libgeoip-dev        # legacy geoip
  libgd-dev           # image-filter
  libxml2-dev         # xslt and dav-ext
  libxslt1-dev        # xslt
  libperl-dev         # perl
)

# Build deps for libmodsecurity, only when the WAF is built: autotools, yajl
# for the JSON audit log, lmdb for CRS counters, curl for remote rules.
if [[ "$WITH_MODSECURITY" == "1" ]]; then
  EXTRA_BUILD_DEPS+=(
    automake
    autoconf
    libtool
    pkg-config
    libcurl4-openssl-dev
    libyajl-dev
    liblmdb-dev
    libssl-dev
  )
fi
# The lua module needs OpenResty's LuaJIT, not Ubuntu's.  build_lua_support
# builds it from source.


# =============================================================================
# Other settings
# =============================================================================

# Shown in the Server header instead of nginx.  Leave blank to drop the
# header.
FAKE_SERVER_NAME="server"

# Where things live.  You probably do not need to touch these.
PREFIX="/etc/nginx"
SBIN="/usr/sbin/nginx"
BUILD_ROOT="/usr/local/src/nginx-build"
BACKUP_ROOT="/var/backups/nginx-installer"

# Source tarball cache.  BUILD_ROOT is wiped on every build, so this saves
# downloading nginx and OpenSSL each time.
CACHE_DIR="/var/cache/nginx-installer"
WEBROOT="/var/www/html"
ACME_WEBROOT="/var/www/certbot"
RUN_USER="www-data"


# =============================================================================
# Little helpers
# =============================================================================

# Colored log output.
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Report the line for anything that fails without going through die(), so a
# command with its output sent to /dev/null does not stop the script silently.
trap 'rc=$?; printf "\033[1;31m[x]\033[0m Stopped at line %s (exit %s), command: %s\n" "$LINENO" "$rc" "$BASH_COMMAND" >&2; exit $rc' ERR

# Most commands touch system paths and services, so they need root.
require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "Please run this with sudo or as root."
  fi
}

# True when systemd is actually pid 1.  Containers and chroots can have
# systemctl installed without it.
have_systemd() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

# Tested on Ubuntu 24.04 and 26.04.  Anything else gets a warning but still
# runs.
check_ubuntu() {
  local id ver
  id="$(. /etc/os-release && echo "${ID:-}")"
  ver="$(. /etc/os-release && echo "${VERSION_ID:-}")"
  if [[ "$id" != "ubuntu" ]]; then
    warn "This is built for Ubuntu.  Found '$id', trying anyway."
    return
  fi
  case "$ver" in
    24.04|26.04) log "Ubuntu $ver looks good." ;;
    *) warn "Tested on Ubuntu 24.04 and 26.04.  Found $ver, trying anyway." ;;
  esac
}

# Download a tarball, caching it for the next build.  A cached copy is only
# used if it still unpacks, so a half written file from an interrupted build
# is fetched again instead of failing every build after it.  Retries are
# generous because several nodes behind one address may pull the same file
# within minutes.
fetch() {
  local url="$1" out="$2" name cached
  name="$(basename "$out")"
  cached="${CACHE_DIR}/${name}"

  if [[ -s "$cached" ]] && tar tzf "$cached" >/dev/null 2>&1; then
    log "Using the cached ${name}, no download needed."
    cp -a "$cached" "$out"
    return
  fi

  log "Downloading $url"
  wget --https-only --tries=5 --waitretry=15 --timeout=60 -qO "$out" "$url" \
    || die "Could not download $url"

  # Cache it, but never let a caching problem fail the build.
  if tar tzf "$out" >/dev/null 2>&1; then
    mkdir -p "$CACHE_DIR"
    cp -a "$out" "${cached}.part" 2>/dev/null && mv "${cached}.part" "$cached" 2>/dev/null || true
  fi
}


# =============================================================================
# Dependencies
# =============================================================================

# Build dependencies.  pcre2 and zlib come from the distro; only OpenSSL is
# built from source, for post quantum support.  Module deps come from
# EXTRA_BUILD_DEPS.
install_deps() {
  log "Installing build dependencies."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    wget \
    curl \
    git \
    tar \
    perl \
    libpcre2-dev \
    zlib1g-dev \
    certbot \
    "${EXTRA_BUILD_DEPS[@]}"
}


# =============================================================================
# Keep apt away from our binary
# =============================================================================

# Installing anything that depends on the nginx package (usually
# python3-certbot-nginx) makes apt pull in Ubuntu's nginx, which overwrites
# our /usr/sbin/nginx with a binary lacking our modules.  The next config
# test then fails with something like:
#
#   unknown directive "more_set_headers" in /etc/nginx/nginx.conf
#
# and apt is left half configured.  Three guards: a stand in package so the
# dependency is met, holds on the real packages, and a dpkg diversion so even
# a forced install lands on nginx.distrib.
protect_from_apt() {
  log "Setting up apt guards so nothing overwrites our nginx."

  # Warn if the real packages are installed, but do not remove them;
  # removing nginx-common can take the config with it.  dpkg-query exits 1
  # when none are found (the normal case), hence the "|| true".  Our own stand
  # in is also named nginx, so skip epoch 9.
  local installed
  installed="$(dpkg-query -W -f='${Package} ${Status} ${Version}\n' nginx nginx-core nginx-common 2>/dev/null \
    | awk '$4 == "installed" && $5 !~ /^9:/ { printf "%s ", $1 }' || true)"
  if [[ -n "${installed// /}" ]]; then
    warn "Ubuntu's nginx packages are already installed: ${installed}"
    warn "Clear them out with: apt-get remove ${installed}"
    warn "Use remove, not purge.  Purge deletes the config in ${PREFIX}."
  fi

  # Hold the real packages so an upgrade does not bring them back.
  local pkg
  for pkg in nginx nginx-common nginx-core nginx-full; do
    apt-mark hold "$pkg" >/dev/null 2>&1 || true
  done
  log "Held: nginx nginx-common nginx-core nginx-full"

  # Divert any packaged binary to ${SBIN}.distrib.  No --rename, so dpkg
  # never moves our own binary.
  if ! dpkg-divert --list "$SBIN" 2>/dev/null | grep -q .; then
    dpkg-divert --local --divert "${SBIN}.distrib" --add "$SBIN" >/dev/null
    log "Diverted any packaged nginx to ${SBIN}.distrib"
  fi
}


# Register the stand in package.  Runs after the build and takes the version
# from the installed binary, so a failed build never leaves dpkg (and any
# inventory or vulnerability scan reading it) reporting an upgrade that did
# not happen.
register_stand_in_package() {
  local installed
  installed="$(dpkg-query -W -f='${Package} ${Status} ${Version}\n' nginx nginx-core nginx-common 2>/dev/null \
    | awk '$4 == "installed" && $5 !~ /^9:/ { printf "%s ", $1 }' || true)"

  # An empty package named nginx satisfies anything that depends on nginx.
  # Epoch 9 keeps it newer than anything Ubuntu ships.
  local stub ver built
  built="$("$SBIN" -v 2>&1 | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p')"
  if [[ -z "$built" ]]; then
    warn "Could not read a version out of ${SBIN}, leaving the stand in package alone."
    return
  fi
  ver="9:${built}-source"
  stub="$(mktemp -d)"
  mkdir -p "${stub}/nginx/DEBIAN"
  cat > "${stub}/nginx/DEBIAN/control" <<EOF
Package: nginx
Version: ${ver}
Architecture: all
Maintainer: nginx-installer <root@localhost>
Section: httpd
Priority: optional
Provides: nginx-core (= ${ver}), nginx-common (= ${ver}), nginx-full (= ${ver}), httpd
Description: Stand in for the nginx built from source
 This box runs nginx built from source by nginx-installer.sh.  This package
 ships no files.  It exists so apt counts the nginx dependency as met and
 leaves the real binary at ${SBIN} alone.
EOF

  if [[ -n "${installed// /}" ]]; then
    warn "Skipping the stand in package while the real ones are still here."
  else
    log "Installing a stand in nginx package at version ${ver}."
    dpkg-deb --build --root-owner-group "${stub}/nginx" "${stub}/nginx.deb" >/dev/null
    dpkg -i "${stub}/nginx.deb" >/dev/null
  fi
  rm -rf "$stub"
}


# =============================================================================
# Fetch and unpack the sources
# =============================================================================

fetch_sources() {
  rm -rf "$BUILD_ROOT"
  mkdir -p "${BUILD_ROOT}/modules"
  cd "$BUILD_ROOT"

  fetch "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" nginx.tar.gz
  fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" openssl.tar.gz

  log "Unpacking nginx and OpenSSL."
  tar xf nginx.tar.gz
  tar xf openssl.tar.gz

  # Static and dynamic modules are cloned to the same place; only the
  # configure flag differs.
  local entry name url ref
  for entry in "${THIRD_PARTY_MODULES[@]}" "${DYNAMIC_MODULES[@]}"; do
    IFS='|' read -r name url ref <<< "$entry"
    log "Fetching module $name ($ref)"
    git clone --depth 1 --branch "$ref" "$url" "modules/${name}" \
      || die "Could not fetch module $name from $url"
  done
}

# True when the WAF module is in the build.
wants_modsecurity() {
  printf '%s\n' "${DYNAMIC_MODULES[@]}" | grep -q "modsecurity-nginx"
}


# =============================================================================
# Back up whatever is already installed
# =============================================================================

# Snapshot the current binary, config and service file.  This is what
# revert restores.
backup_current() {
  local stamp dir
  stamp="$(date +%Y%m%d-%H%M%S)"
  dir="${BACKUP_ROOT}/${stamp}"
  mkdir -p "$dir"

  if [[ -x "$SBIN" ]]; then
    log "Backing up the current nginx to $dir"
    cp -a "$SBIN" "${dir}/nginx.bin"
    # Remember what version this binary was so revert can tell you.
    "$SBIN" -v 2>"${dir}/version.txt" || true
  else
    log "No nginx installed yet, this is a first run."
  fi

  if [[ -d "$PREFIX" ]]; then
    tar czf "${dir}/etc-nginx.tar.gz" -C "$(dirname "$PREFIX")" "$(basename "$PREFIX")"
  fi

  if [[ -f /etc/systemd/system/nginx.service ]]; then
    cp -a /etc/systemd/system/nginx.service "${dir}/nginx.service"
  fi

  # Point "latest" at this snapshot so revert knows which one to grab.
  ln -sfn "$dir" "${BACKUP_ROOT}/latest"
}


# =============================================================================
# Lua support
# =============================================================================

# The lua module needs OpenResty's LuaJIT plus lua-resty-core, or nginx will
# not start.  Skipped when lua is not in the module list.
build_lua_support() {
  printf '%s\n' "${THIRD_PARTY_MODULES[@]}" | grep -q "lua-nginx-module" || return 0

  log "Building OpenResty LuaJIT for the lua module."
  git clone --depth 1 https://github.com/openresty/luajit2 "${BUILD_ROOT}/luajit2"
  make -C "${BUILD_ROOT}/luajit2" -j"$(nproc)"
  make -C "${BUILD_ROOT}/luajit2" install
  # Make sure the loader can find the new library at runtime.
  ldconfig

  # These must match the lua-nginx-module version (OpenResty ships them as a
  # set).  Bump them together.
  log "Installing lua-resty-core and lua-resty-lrucache."
  git clone --depth 1 --branch v0.1.31 https://github.com/openresty/lua-resty-core "${BUILD_ROOT}/lua-resty-core"
  make -C "${BUILD_ROOT}/lua-resty-core" install LUA_LIB_DIR=/usr/local/share/lua/5.1
  git clone --depth 1 --branch v0.15 https://github.com/openresty/lua-resty-lrucache "${BUILD_ROOT}/lua-resty-lrucache"
  make -C "${BUILD_ROOT}/lua-resty-lrucache" install LUA_LIB_DIR=/usr/local/share/lua/5.1
}


# =============================================================================
# The WAF engine
# =============================================================================

# libmodsecurity, the engine behind the ModSecurity-nginx connector.  Slow
# to build, so it only runs when the WAF is enabled.
build_modsecurity() {
  wants_modsecurity || return 0

  # Skip when this version is already built; bump MODSECURITY_VERSION to
  # force a rebuild.  The connector is still rebuilt every time, since it is
  # tied to the exact nginx it was compiled against.
  local stamp="/usr/local/lib/.modsecurity-version"
  if [[ -f "$stamp" && -f /usr/local/lib/libmodsecurity.so ]] \
     && [[ "$(cat "$stamp" 2>/dev/null)" == "$MODSECURITY_VERSION" ]]; then
    log "libmodsecurity ${MODSECURITY_VERSION} is already built, skipping it."
    # In case ld.so.cache was rebuilt without it.
    ldconfig
    return 0
  fi

  log "Building libmodsecurity ${MODSECURITY_VERSION}.  This one takes a while."
  git clone --depth 1 --branch "v${MODSECURITY_VERSION}" \
    https://github.com/owasp-modsecurity/ModSecurity "${BUILD_ROOT}/ModSecurity" \
    || die "Could not fetch libmodsecurity ${MODSECURITY_VERSION}."

  # libinjection (SQLi and XSS detection) is a git submodule.
  git -C "${BUILD_ROOT}/ModSecurity" submodule update --init --recursive --depth 1 \
    || die "Could not fetch the libmodsecurity submodules."

  cd "${BUILD_ROOT}/ModSecurity"
  ./build.sh
  # The default prefix is /usr/local/modsecurity, which is off the loader
  # path; nginx would then fail to load libmodsecurity.so.3.  /usr/local is
  # where ldconfig already looks.
  #
  # Docs and examples are skipped to save build time.  yajl and lmdb are
  # required explicitly so a missing package fails here instead of producing
  # an engine that cannot write the JSON audit log.
  ./configure \
    --prefix=/usr/local \
    --with-yajl \
    --with-lmdb \
    --disable-doxygen-doc \
    --disable-doxygen-html \
    --disable-examples
  make -j"$(nproc)"
  make install

  # Otherwise nginx fails at startup on a missing libmodsecurity.so.3.
  ldconfig

  # Stamp only after a complete build, so a failed run is retried.
  printf '%s\n' "$MODSECURITY_VERSION" > "$stamp"
}


# =============================================================================
# The actual build
# =============================================================================

build_nginx() {
  cd "${BUILD_ROOT}/nginx-${NGINX_VERSION}"

  # Turn the module list into --add-module flags, keeping the same order.
  local addmods=() entry name
  for entry in "${THIRD_PARTY_MODULES[@]}"; do
    name="${entry%%|*}"
    addmods+=( "--add-module=${BUILD_ROOT}/modules/${name}" )
  done

  # Dynamic modules are built as .so files under --modules-path and only
  # loaded by a load_module line.
  for entry in "${DYNAMIC_MODULES[@]}"; do
    name="${entry%%|*}"
    addmods+=( "--add-dynamic-module=${BUILD_ROOT}/modules/${name}" )
  done

  # Point the connector at our libmodsecurity.  Otherwise it falls back to
  # pkg-config, which may find Ubuntu's older 3.0.12 package.
  if wants_modsecurity; then
    export MODSECURITY_INC="/usr/local/include"
    export MODSECURITY_LIB="/usr/local/lib"
    log "Using libmodsecurity from $MODSECURITY_LIB"
  fi

  # Point the lua module at the OpenResty LuaJIT we built in build_lua_support.
  if printf '%s\n' "${THIRD_PARTY_MODULES[@]}" | grep -q "lua-nginx-module"; then
    export LUAJIT_LIB="/usr/local/lib"
    export LUAJIT_INC="/usr/local/include/luajit-2.1"
    log "Using OpenResty LuaJIT from $LUAJIT_INC"
  fi

  # -Wno-error: newer GCC (Ubuntu 26.04) turns some warnings into errors that
  # older modules trip.
  #
  # Perl modules go under /etc/nginx, which is backed up on every install, so
  # a revert keeps them in step with the binary.
  log "Configuring nginx.  This bakes OpenSSL ${OPENSSL_VERSION} right in."
  ./configure \
    --prefix="$PREFIX" \
    --sbin-path="$SBIN" \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path="${PREFIX}/nginx.conf" \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/run/nginx.pid \
    --lock-path=/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user="$RUN_USER" \
    --group="$RUN_USER" \
    --with-cc-opt="-Wno-error" \
    --with-perl_modules_path="${PREFIX}/perl" \
    "${BUILTIN_MODULES[@]}" \
    --with-openssl="${BUILD_ROOT}/openssl-${OPENSSL_VERSION}" \
    "${addmods[@]}"

  log "Compiling.  Grab a coffee, this is the slow part."
  make -j"$(nproc)"

  log "Installing the new nginx."
  make install
}


# =============================================================================
# Config files
# =============================================================================

# Directories nginx expects, plus the site and certbot challenge webroots.
make_dirs() {
  mkdir -p \
    /var/cache/nginx \
    /var/log/nginx \
    /usr/lib/nginx/modules \
    "${PREFIX}/modules-enabled" \
    "${PREFIX}/conf.d" \
    "${PREFIX}/sites-available" \
    "${PREFIX}/sites-enabled" \
    "${PREFIX}/snippets" \
    "$WEBROOT" \
    "$ACME_WEBROOT"
  chown -R "${RUN_USER}:${RUN_USER}" /var/cache/nginx /var/log/nginx "$WEBROOT" "$ACME_WEBROOT"
}

# Main config, written only on first install so upgrades keep local edits.
# Server blocks belong in sites-enabled.
write_main_conf() {
  if [[ -f "${PREFIX}/nginx.conf" ]] && grep -q "installer-managed" "${PREFIX}/nginx.conf" 2>/dev/null; then
    log "Keeping your existing nginx.conf."
    return
  fi
  # Only add the lua paths when lua is built, or the config will not load.
  local lua_conf=""
  if printf '%s\n' "${THIRD_PARTY_MODULES[@]}" | grep -q "lua-nginx-module"; then
    lua_conf='
    # Let the lua module find its resty core files.
    lua_package_path "/usr/local/share/lua/5.1/?.lua;;";
    lua_package_cpath "/usr/local/lib/lua/5.1/?.so;;";'
  fi

  log "Writing a fresh nginx.conf."
  cat > "${PREFIX}/nginx.conf" <<EOF
# installer-managed base config.  Put your sites in sites-available instead.
user ${RUN_USER};
worker_processes auto;
pid /run/nginx.pid;

# Loadable modules.  This has to be up here in the main context, which is why
# it is an include rather than a load_module line the manager could write into
# conf.d.  The folder is normally empty: a module only gets a file here when
# something is switched on that needs it, and dropping the file unloads it.
include ${PREFIX}/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    tcp_nopush      on;
    keepalive_timeout 65;

    # We load a lot of modules, so give the variable hash some extra room.
    variables_hash_max_size 2048;
    variables_hash_bucket_size 128;

    # Hide the nginx name and version from anyone poking at the headers.
    server_tokens off;
    more_set_headers "Server: ${FAKE_SERVER_NAME}";
    more_clear_headers "X-Powered-By";
${lua_conf}

    gzip on;

    include ${PREFIX}/conf.d/*.conf;
    include ${PREFIX}/sites-enabled/*;
}
EOF
}

# Add the modules-enabled include to an nginx.conf that predates it.
# Without it, files the manager writes to modules-enabled are never read and
# the WAF looks enabled while doing nothing.  Only edits a config this
# installer wrote; a hand written nginx.conf gets a warning instead.
ensure_modules_include() {
  local conf="${PREFIX}/nginx.conf"
  [[ -f "$conf" ]] || return 0

  if grep -q "modules-enabled" "$conf"; then
    return 0
  fi

  if ! grep -q "installer-managed" "$conf"; then
    warn "Your nginx.conf is not one of ours, so the modules-enabled include"
    warn "was not added.  Loadable modules will not work until you add this"
    warn "line in the main context, above the events block:"
    warn "    include ${PREFIX}/modules-enabled/*.conf;"
    return 0
  fi

  log "Adding the modules-enabled include to your existing nginx.conf."
  cp -a "$conf" "${conf}.bak-modules"

  # Insert above the events block, which keeps it in the main context where
  # load_module is allowed.
  if ! grep -qE '^[[:space:]]*events[[:space:]]*\{' "$conf"; then
    warn "No events block found in ${conf}, so the include was not added."
    return 0
  fi

  awk -v line="include ${PREFIX}/modules-enabled/*.conf;" '
    !done && /^[[:space:]]*events[[:space:]]*\{/ {
      print "# Loadable modules.  Added on upgrade; see modules-enabled."
      print line
      print ""
      done = 1
    }
    { print }
  ' "$conf" > "${conf}.new" || die "Could not rewrite ${conf}."

  mv -f "${conf}.new" "$conf"

  # Test now so a failure points at this change.
  if ! "$SBIN" -t -c "$conf" >/dev/null 2>&1; then
    warn "nginx would not accept the include, putting your nginx.conf back."
    mv -f "${conf}.bak-modules" "$conf"
    return 0
  fi
}

# Shared TLS snippet with sane defaults and the post quantum key exchange
# groups from OpenSSL 3.5.
write_ssl_snippet() {
  log "Writing the TLS hardening snippet."
  cat > "${PREFIX}/snippets/ssl-hardening.conf" <<'EOF'
# installer-managed TLS settings.  Include this from any https server block.
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# Ask for a post quantum hybrid first, then fall back to classic curves.
# X25519MLKEM768 is the hybrid that ships in OpenSSL 3.5.
ssl_conf_command Groups X25519MLKEM768:X25519:secp256r1:secp384r1;

add_header Strict-Transport-Security "max-age=63072000" always;
EOF
}

# Open UDP for QUIC on an active ufw or firewalld.  Without it HTTP/3 fails
# silently: clients just stay on HTTP/2 with no error anywhere.  A box with
# no running firewall is left alone.
open_quic_port() {
  local port="${1:-443}"

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ufw status 2>/dev/null | grep -qE "^${port}/udp .*ALLOW"; then
      log "ufw already allows ${port}/udp, which is what HTTP/3 needs."
    else
      log "ufw is active, allowing ${port}/udp so HTTP/3 can connect."
      ufw allow "${port}/udp" >/dev/null 2>&1 \
        || warn "could not add the ufw rule, so HTTP/3 will not connect until ${port}/udp is open"
    fi
    return 0
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    log "firewalld is active, allowing ${port}/udp so HTTP/3 can connect."
    firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 \
      && firewall-cmd --reload >/dev/null 2>&1 \
      || warn "could not add the firewalld rule, so HTTP/3 will not connect until ${port}/udp is open"
    return 0
  fi

  # No managed firewall.  Log it, since upstream filtering may still apply.
  log "No ufw or firewalld running, so nothing is filtering ${port}/udp here."
  log "Anything in front of this box still has to allow UDP ${port} for HTTP/3."
}

# A plain http site so a fresh box serves something and certbot has a place
# for challenge files.
write_default_site() {
  if [[ -e "${PREFIX}/sites-available/default.conf" ]]; then
    log "Keeping your existing default site."
  else
    log "Writing a default http site."
    cat > "${PREFIX}/sites-available/default.conf" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root ${WEBROOT};
    index index.html;

    include ${PREFIX}/snippets/acme-challenge.conf;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    ln -sfn "${PREFIX}/sites-available/default.conf" "${PREFIX}/sites-enabled/default.conf"
  fi

  if [[ ! -f "${WEBROOT}/index.html" ]]; then
    echo "<h1>It works</h1>" > "${WEBROOT}/index.html"
  fi
}

# systemd unit for nginx.
write_service() {
  log "Writing the systemd service."

  # Remove first: a masked unit is a symlink to /dev/null, and writing
  # through it silently discards the file.
  rm -f /etc/systemd/system/nginx.service

  cat > /etc/systemd/system/nginx.service <<EOF
[Unit]
Description=nginx web server
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=${SBIN} -t -q -g 'daemon on; master_process on;'
ExecStart=${SBIN} -g 'daemon on; master_process on;'
ExecReload=${SBIN} -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
  # No systemd is fine, but a failed daemon-reload is fatal, or it shows up
  # later as "Unit nginx.service not found".
  if have_systemd; then
    systemctl daemon-reload || die "systemctl daemon-reload failed, systemd never saw the new unit."
  else
    warn "No systemd here, skipping the service.  Start nginx yourself with ${SBIN}."
  fi
}


# =============================================================================
# Our stand in for the certbot nginx plugin
# =============================================================================
#
# python3-certbot-nginx cannot be installed (it wants Ubuntu's nginx), so
# this covers what it does using webroot auth: find the served domains, make
# the ACME challenge answerable, wire the cert into the server block, and
# optionally redirect http to https.
#
# Every edit backs up the site file, runs a config test, and restores the
# backup if the test fails.

# The challenge location, kept in one snippet so every site shares it.
write_acme_snippet() {
  cat > "${PREFIX}/snippets/acme-challenge.conf" <<EOF
# installer-managed.  Include this in any port 80 server block so certbot can
# answer the http-01 challenge from ${ACME_WEBROOT}.
location ^~ /.well-known/acme-challenge/ {
    root ${ACME_WEBROOT};
    default_type "text/plain";
    try_files \$uri =404;
}
EOF
}

# Print every served server_name, one per line.  Skips the catch all and
# wildcard or regex names, which http-01 cannot validate.
discover_domains() {
  local f
  for f in "${PREFIX}"/sites-enabled/* "${PREFIX}"/conf.d/*.conf; do
    [[ -f "$f" ]] || continue
    sed 's/#.*//' "$f" | tr -s ' \t' ' ' \
      | grep -oE '(^| )server_name [^;]+;' \
      | sed 's/.*server_name //; s/;$//'
  done | tr ' ' '\n' | grep -vE '^\s*$|^_$|^\*|^~|^\.' | sort -u
}

# Find the site file serving a domain, via sites-enabled so disabled sites
# are never touched.
site_file_for_domain() {
  local domain="$1" link target
  for link in "${PREFIX}"/sites-enabled/*; do
    [[ -e "$link" ]] || continue
    target="$(readlink -f "$link")"
    if sed 's/#.*//' "$target" | grep -qE "(^| )server_name([ ]+[^;]*)? ${domain}( |;)"; then
      echo "$target"
      return 0
    fi
  done
  return 1
}

# Site file rewriter, stdin to stdout.
#
# In the domain's http block: add the challenge include and, with redirect
# on, replace "location /" with a 301.  In its https block: point the cert
# lines at the new cert and include the TLS snippet.  With no https block,
# append one.  Only top level server blocks are touched; braces are counted
# with comments stripped.
rewrite_site() {
  local domain="$1" redirect="$2"
  awk -v domain="$domain" -v redirect="$redirect" -v prefix="$PREFIX" -v webroot="$WEBROOT" '
    function stripped(s) { sub(/#.*/, "", s); return s }

    { line[NR] = $0 }

    END {
      # Dots in a domain are regex wildcards, so escape them before matching.
      dom = domain
      gsub(/\./, "\\.", dom)

      # Pass one, mark where each top level server block starts and ends.
      depth = 0; nb = 0
      for (i = 1; i <= NR; i++) {
        t = stripped(line[i])
        if (depth == 0 && t ~ /(^|[ \t;}])server[ \t]*\{/) { nb++; bs[nb] = i; be[nb] = 0 }
        o = gsub(/\{/, "", t); c = gsub(/\}/, "", t)
        depth += o - c
        if (nb > 0 && be[nb] == 0 && depth == 0) be[nb] = i
      }

      # Pass two, work out what each block is and which one we care about.
      # We also note what is already in there so a second run does not add the
      # same lines twice.  autocert calls this twice on purpose.
      for (b = 1; b <= nb; b++) {
        issl[b] = 0; mine[b] = 0; added[b] = 0; hashard[b] = 0; hascert[b] = 0
        for (i = bs[b]; i <= be[b]; i++) {
          t = stripped(line[i])
          if (t ~ /listen[^;]*(ssl|443)/ || t ~ /ssl_certificate[ \t]/) issl[b] = 1
          if (t ~ /(^|[ \t])server_name[ \t]/ && t ~ ("[ \t]" dom "[ \t;]")) mine[b] = 1
          if (t ~ /acme-challenge/) added[b] = 1
          if (t ~ /ssl-hardening/) hashard[b] = 1
          if (t ~ /(^|[ \t])ssl_certificate[ \t]/) hascert[b] = 1
        }
        if (mine[b]) anymine = 1
        if (mine[b] && issl[b]) havessl = 1
      }

      # Pass three, print it back out with the edits folded in.
      for (i = 1; i <= NR; i++) {
        b = 0
        for (k = 1; k <= nb; k++) if (i >= bs[k] && i <= be[k]) b = k

        if (b == 0 || !mine[b]) { print line[i]; continue }

        t = stripped(line[i])

        # Plain http block for our domain.
        if (!issl[b]) {
          # Skip over the old "location /" body when we are replacing it.
          if (skiploc) {
            u = t
            o = gsub(/\{/, "", u); c = gsub(/\}/, "", u)
            skipdepth += o - c
            if (skipdepth <= 0) skiploc = 0
            continue
          }
          if (redirect == "1" && !redone[b] && t ~ /(^|[ \t])location[ \t]+\/[ \t]*\{/) {
            print "    location / {"
            print "        return 301 https://$host$request_uri;"
            print "    }"
            redone[b] = 1
            # The old location may open and close on the same line, so count
            # its braces instead of assuming we have more lines to skip.
            u = t
            o = gsub(/\{/, "", u); c = gsub(/\}/, "", u)
            skipdepth = o - c
            if (skipdepth > 0) skiploc = 1
            continue
          }
          print line[i]
          # Drop the challenge include right after server_name, once.
          if (!added[b] && t ~ /(^|[ \t])server_name[ \t]/) {
            print "    include " prefix "/snippets/acme-challenge.conf;"
            added[b] = 1
          }
          continue
        }

        # Https block for our domain.  Point it at the fresh cert.
        if (t ~ /(^|[ \t])ssl_certificate_key[ \t]/) {
          print "    ssl_certificate_key /etc/letsencrypt/live/" domain "/privkey.pem;"
          if (!hashard[b]) {
            print "    include " prefix "/snippets/ssl-hardening.conf;"
            hashard[b] = 1
          }
          continue
        }
        if (t ~ /(^|[ \t])ssl_certificate[ \t]/) {
          print "    ssl_certificate     /etc/letsencrypt/live/" domain "/fullchain.pem;"
          continue
        }
        print line[i]
        # An https block with no cert lines at all still needs them.
        if (!hascert[b] && t ~ /(^|[ \t])server_name[ \t]/) {
          print "    ssl_certificate     /etc/letsencrypt/live/" domain "/fullchain.pem;"
          print "    ssl_certificate_key /etc/letsencrypt/live/" domain "/privkey.pem;"
          hascert[b] = 1
          if (!hashard[b]) {
            print "    include " prefix "/snippets/ssl-hardening.conf;"
            hashard[b] = 1
          }
        }
      }

      # We matched the domain but it had no https block, so write a whole one.
      # If nothing in this file matched we leave it exactly as we found it.
      if (anymine && !havessl) {
        print ""
        print "server {"
        print "    listen 443 ssl;"
        print "    listen [::]:443 ssl;"
        print "    http2 on;"
        print "    server_name " domain ";"
        print ""
        print "    ssl_certificate     /etc/letsencrypt/live/" domain "/fullchain.pem;"
        print "    ssl_certificate_key /etc/letsencrypt/live/" domain "/privkey.pem;"
        print "    include " prefix "/snippets/ssl-hardening.conf;"
        print ""
        print "    root " webroot ";"
        print "    index index.html;"
        print ""
        print "    location / {"
        print "        try_files $uri $uri/ =404;"
        print "    }"
        print "}"
      }
    }
  '
}

# Rewrite a site file in place, restoring it if the config test fails.
apply_site_edit() {
  local file="$1" domain="$2" redirect="$3" backup tmp
  backup="${file}.bak-$(date +%Y%m%d-%H%M%S)"
  tmp="$(mktemp)"

  cp -a "$file" "$backup"
  rewrite_site "$domain" "$redirect" < "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"

  if "$SBIN" -t >/dev/null 2>&1; then
    log "Updated $(basename "$file") for ${domain}.  Backup at $(basename "$backup")"
    return 0
  fi

  warn "That edit did not pass a config test, putting the old file back."
  cat "$backup" > "$file"
  "$SBIN" -t 2>&1 | sed 's/^/    /' || true
  return 1
}

# Deploy hook so nginx picks up renewed certs.
write_renewal_hook() {
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<EOF
#!/usr/bin/env bash
# installer-managed.  Reload nginx after a cert renews.
# Nothing to do if nginx is not up.
systemctl is-active --quiet nginx || exit 0
# Test first, a reload on a broken config would take the site down.
${SBIN} -t && systemctl reload nginx
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
}

# Check the challenge path works before asking Let's Encrypt, by fetching a
# test token over port 80 the way the ACME server will.
check_acme_path() {
  local domain="$1" token="installer-check-$$" got
  mkdir -p "${ACME_WEBROOT}/.well-known/acme-challenge"
  echo "$token" > "${ACME_WEBROOT}/.well-known/acme-challenge/${token}"
  chown -R "${RUN_USER}:${RUN_USER}" "${ACME_WEBROOT}/.well-known"

  got="$(curl -fsS --max-time 10 "http://${domain}/.well-known/acme-challenge/${token}" 2>/dev/null || true)"
  rm -f "${ACME_WEBROOT}/.well-known/acme-challenge/${token}"

  if [[ "$got" == "$token" ]]; then
    log "The challenge path answers over http://${domain}, good to go."
    return 0
  fi
  warn "Could not fetch the challenge over http://${domain}."
  warn "Check DNS, port 80, and the firewall before you blame certbot."
  return 1
}

# Ask for the cert itself.  Always webroot, never a plugin.
request_cert() {
  local domain="$1" email="$2"
  if [[ -d "/etc/letsencrypt/live/${domain}" ]]; then
    log "Already have a cert for ${domain}, leaving it alone."
    return 0
  fi
  log "Asking Let's Encrypt for a cert for ${domain}."
  certbot certonly \
    --webroot -w "$ACME_WEBROOT" \
    -d "$domain" \
    --agree-tos \
    -m "$email" \
    --non-interactive
}


# =============================================================================
# Commands
# =============================================================================

cmd_install() {
  require_root
  check_ubuntu
  install_deps
  protect_from_apt
  fetch_sources
  backup_current
  build_lua_support
  build_modsecurity
  build_nginx

  # Now that ${SBIN} really is the new build, tell dpkg so.  Before this point
  # the box has not changed version and must not claim to have.
  register_stand_in_package

  make_dirs
  write_main_conf
  ensure_modules_include
  write_ssl_snippet
  write_acme_snippet
  write_default_site
  open_quic_port 443

  # Test before stopping anything.  If the new binary cannot load the live
  # config (say a module it uses was dropped), the old nginx keeps serving
  # until someone runs revert, instead of the node going down.
  log "Testing the config before we stop anything."
  "$SBIN" -t

  # Stop any apt nginx before writing our unit, so we never disable our own.
  if have_systemd; then
    systemctl disable --now nginx 2>/dev/null || true
  fi

  write_service
  write_renewal_hook

  if have_systemd; then
    # Make sure the unit really landed.
    [[ -s /etc/systemd/system/nginx.service ]] \
      || die "The service file is missing or empty, so systemctl will not find nginx."

    systemctl enable nginx || die "Could not enable nginx.service."

    # Show the real error rather than failing quietly.
    if ! systemctl restart nginx; then
      systemctl status nginx --no-pager -l || true
      die "nginx would not start, see the status above."
    fi
  fi

  log "Done.  Here is what got installed:"
  "$SBIN" -V 2>&1 | sed 's/^/    /'

  if have_systemd; then
    log "nginx is running.  Check it with: curl -I http://localhost"
  else
    log "Built and installed.  No systemd here, so start it with: ${SBIN}"
  fi
}

# Restore the binary, config and service file from the last snapshot, then
# restart nginx.
cmd_revert() {
  require_root
  local dir="${BACKUP_ROOT}/latest"
  [[ -d "$dir" ]] || die "No backup found, nothing to revert to."

  log "Reverting from $(readlink -f "$dir")"

  if [[ -f "${dir}/nginx.bin" ]]; then
    # Copying over a running binary fails with "Text file busy".  Renaming
    # it is fine (the process keeps its inode), which is also what nginx's
    # make install does.
    if [[ -f "$SBIN" ]]; then
      mv -f "$SBIN" "${SBIN}.old" \
        || die "Could not move the running nginx aside, so the revert stopped here."
    fi

    cp -a "${dir}/nginx.bin" "$SBIN"
    log "Restored the old nginx binary."
  else
    warn "That snapshot had no binary, this was likely your first install."
    warn "Stopping nginx instead."
    systemctl stop nginx 2>/dev/null || true
  fi

  if [[ -f "${dir}/etc-nginx.tar.gz" ]]; then
    # Empty and refill ${PREFIX} rather than replacing it.  The agent sees it
    # through a systemd ReadWritePaths bind mount tied to the original inode;
    # a new directory would leave the agent's writes failing as read only
    # until it was restarted.
    local staged
    staged="$(mktemp -d)"
    tar xzf "${dir}/etc-nginx.tar.gz" -C "$staged"

    if [[ -d "${staged}/$(basename "$PREFIX")" ]]; then
      mkdir -p "$PREFIX"
      find "$PREFIX" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
      # The trailing dot copies the contents, not the folder itself.
      cp -a "${staged}/$(basename "$PREFIX")/." "$PREFIX/"
      log "Restored the old config."
    else
      warn "That snapshot did not hold a $(basename "$PREFIX") folder, leaving the config alone."
    fi
    rm -rf "$staged"
  fi

  if [[ -f "${dir}/nginx.service" ]]; then
    cp -a "${dir}/nginx.service" /etc/systemd/system/nginx.service
    systemctl daemon-reload 2>/dev/null || true
  fi

  if [[ -x "$SBIN" ]]; then
    "$SBIN" -t && systemctl restart nginx 2>/dev/null || true
    log "Reverted and running:"
    "$SBIN" -v 2>&1 | sed 's/^/    /'
  fi
}

# Get a cert for a domain with no server block yet and write an https site
# for it.  For an existing server block, use autocert instead.
# Usage: cmd_cert domain email
cmd_cert() {
  require_root
  local domain="${1:-}" email="${2:-}"
  [[ -n "$domain" ]] || die "Usage: $0 cert <domain> <email>"
  [[ -n "$email"  ]] || die "Usage: $0 cert <domain> <email>"
  command -v certbot >/dev/null || die "certbot is missing.  Run: $0 install"

  if site_file_for_domain "$domain" >/dev/null 2>&1; then
    warn "${domain} already has a server block."
    warn "Use: $0 autocert ${email} ${domain}"
    die "Stopping so we do not write a duplicate site."
  fi

  write_acme_snippet
  make_dirs

  local site="${PREFIX}/sites-available/${domain}.conf"
  log "Writing a plain http site for ${domain} so the challenge can be served."
  cat > "$site" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    include ${PREFIX}/snippets/acme-challenge.conf;

    root ${WEBROOT};
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
  ln -sfn "$site" "${PREFIX}/sites-enabled/${domain}.conf"

  "$SBIN" -t || die "The config does not pass a test, fix that before we go on."
  systemctl reload nginx 2>/dev/null || systemctl start nginx 2>/dev/null || true

  check_acme_path "$domain" || warn "Trying the cert anyway."
  request_cert "$domain" "$email"

  # Now fold the cert in and turn http into a redirect.
  apply_site_edit "$site" "$domain" 1 || die "Could not write the https block."
  write_renewal_hook
  systemctl reload nginx 2>/dev/null || true
  log "Done.  ${domain} is on https now."
}

# Our version of "certbot --nginx".  With no domains given, does every
# served server_name.  For each: make the challenge answerable, get the cert,
# then edit the existing server block in place.
# Usage: cmd_autocert email [domain ...]
cmd_autocert() {
  require_root
  local email="${1:-}"
  [[ -n "$email" ]] || die "Usage: $0 autocert <email> [domain ...]"
  shift
  command -v certbot >/dev/null || die "certbot is missing.  Run: $0 install"

  local domains=("$@")
  if [[ ${#domains[@]} -eq 0 ]]; then
    log "No domains given, reading them out of your config."
    mapfile -t domains < <(discover_domains)
    [[ ${#domains[@]} -gt 0 ]] || die "Found no real server_name to work with."
    log "Found: ${domains[*]}"
  fi

  write_acme_snippet
  make_dirs
  write_renewal_hook

  local domain site failed=()
  for domain in "${domains[@]}"; do
    log "----- ${domain} -----"

    if ! site="$(site_file_for_domain "$domain")"; then
      warn "No enabled server block serves ${domain}, skipping."
      warn "Give it one first with: $0 cert ${domain} ${email}"
      failed+=("$domain")
      continue
    fi

    # Step one, add the challenge location.  No redirect yet, since https
    # has no cert to load.
    if ! apply_site_edit "$site" "$domain" 0; then
      failed+=("$domain"); continue
    fi
    systemctl reload nginx 2>/dev/null || systemctl start nginx 2>/dev/null || true

    # Step two, prove it works, then get the cert.
    check_acme_path "$domain" || warn "Trying the cert anyway."
    if ! request_cert "$domain" "$email"; then
      warn "Certbot could not get a cert for ${domain}."
      failed+=("$domain"); continue
    fi

    # Step three, wire in the cert and add the redirect.
    if ! apply_site_edit "$site" "$domain" 1; then
      failed+=("$domain"); continue
    fi
    systemctl reload nginx 2>/dev/null || true
    log "${domain} is on https."
  done

  if [[ ${#failed[@]} -gt 0 ]]; then
    warn "These did not finish: ${failed[*]}"
    return 1
  fi
  log "All done."
}

# List the domains autocert would work on.
cmd_domains() {
  local d found=0
  while read -r d; do
    [[ -n "$d" ]] || continue
    found=1
    if [[ -d "/etc/letsencrypt/live/${d}" ]]; then
      printf '    %-40s has a cert\n' "$d"
    else
      printf '    %-40s no cert yet\n' "$d"
    fi
  done < <(discover_domains)
  [[ "$found" -eq 1 ]] || warn "No server_name found in ${PREFIX}/sites-enabled."
}

# Renew certs by hand.  certbot's timer does this anyway, and the deploy hook
# handles the reload.
cmd_renew() {
  require_root
  write_renewal_hook
  log "Renewing certs."
  certbot renew
  log "Done."
}

# A fast look at what is going on.
cmd_status() {
  if [[ -x "$SBIN" ]]; then
    "$SBIN" -v 2>&1 | sed 's/^/    /'
  else
    warn "nginx is not installed."
  fi
  # A missing unit is reported separately from a stopped service.
  if ! have_systemd; then
    warn "No systemd on this box, nothing to report on the service."
  elif [[ ! -s /etc/systemd/system/nginx.service ]]; then
    warn "No service file at /etc/systemd/system/nginx.service.  Rerun install."
  elif systemctl is-active nginx >/dev/null 2>&1; then
    log "Service is running."
  else
    warn "Service is not running."
  fi
}

usage() {
  cat <<EOF
Nginx from source installer.

Usage: $0 <command> [args]

Commands:
  install                    Build and install nginx ${NGINX_VERSION} with OpenSSL ${OPENSSL_VERSION}.
  revert                     Roll back to the build from before the last install.
  domains                    List the domains in your config and which have certs.
  autocert <email> [domain]  Cert every domain in your config and wire it in.
  cert <domain> <email>      New domain with no server block yet, set it all up.
  renew                      Renew all certs now.
  status                     Show the version and whether nginx is running.

autocert is our stand in for "certbot --nginx".  It reads your server blocks,
gets certs over webroot, then edits those blocks in place.  Every edit is
tested and rolled back if nginx does not like it.

Do not install python3-certbot-nginx.  It depends on Ubuntu's nginx package,
and installing that drops a stock binary on top of this build.  You lose every
module and the config stops loading.  install sets up guards against that.

To upgrade, edit NGINX_VERSION at the top of this file, then run install again.
EOF
}


# =============================================================================
# Dispatch
# =============================================================================

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    install)  cmd_install  "$@" ;;
    revert)   cmd_revert   "$@" ;;
    domains)  cmd_domains  "$@" ;;
    autocert) cmd_autocert "$@" ;;
    cert)     cmd_cert     "$@" ;;
    renew)    cmd_renew    "$@" ;;
    status)   cmd_status   "$@" ;;
    ""|-h|--help|help) usage ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
