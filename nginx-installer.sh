#!/usr/bin/env bash
#
# Nginx from source installer.
#
# This builds nginx against a fresh OpenSSL so you get post quantum crypto.
# It hides the nginx name from the Server header, loads the modules we like,
# sets up certbot, and keeps a backup so you can roll back with one command.
#
# Certbot runs in webroot mode here.  Do not install python3-certbot-nginx and
# expect it to help, that plugin edits your server blocks for you and it drags
# in Ubuntu's nginx package.  See protect_from_apt below for why that hurts.
#
# Everyday use:
#   sudo ./nginx-installer.sh install          # build and install nginx
#   sudo ./nginx-installer.sh revert           # go back to the last build
#   sudo ./nginx-installer.sh cert example.com you@example.com
#   sudo ./nginx-installer.sh renew            # renew every cert
#   sudo ./nginx-installer.sh status           # quick health check
#
# To move to a newer nginx just change NGINX_VERSION below and run install again.
# The old build gets backed up first so revert always has somewhere to go.

# The -E matters.  It lets the ERR trap below fire from inside a function, so a
# command that quits early always tells you where it happened.
set -Eeuo pipefail


# ==============================================================================
# Versions
# ==============================================================================

# Pin the versions here.  Bump these when a new release comes out, then rerun
# install.  Keeping them at the top is the whole point, one edit and you upgrade.
# You can also set these as env vars, which is handy for Ansible and Terraform.
NGINX_VERSION="${NGINX_VERSION:-1.30.4}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
HEADERS_MORE_VERSION="${HEADERS_MORE_VERSION:-0.40}"

# The WAF engine, built from source rather than taken from apt.  Ubuntu 24.04
# ships libmodsecurity3 at 3.0.12, which is older than the two CVEs fixed in
# 3.0.15 (an integer underflow in the verify operators, and a buffer overflow
# in hex_decode).  A WAF running a knowingly vulnerable engine is worse than no
# WAF, so we pin a current one the same way we pin nginx and OpenSSL.
MODSECURITY_VERSION="${MODSECURITY_VERSION:-3.0.16}"


# ==============================================================================
# Included modules
# ==============================================================================
#
# This is the one place to add or drop modules.  There are four lists.
#
#   BUILTIN_MODULES      nginx's own modules, switched on with a configure flag.
#   THIRD_PARTY_MODULES  outside modules we download and compile in.
#   DYNAMIC_MODULES      outside modules built as .so and loaded only when used.
#   EXTRA_BUILD_DEPS     apt packages that some of those modules need to build.
#
# To drop a module, comment out its line.  To add one, put a new line in the
# right list and rerun install.  Order matters in THIRD_PARTY_MODULES, the devel
# kit has to come before lua since lua leans on it.

# nginx's built in modules.  These are just flags, no downloads needed.
BUILTIN_MODULES=(
  --with-compat
  --with-threads
  --with-file-aio
  --with-http_ssl_module
  --with-http_v2_module
  # HTTP/3.  Needs a TLS library with the QUIC API, which is why this was left
  # out for years: it wanted BoringSSL or quictls and we bake OpenSSL.  OpenSSL
  # 3.5 has the API and the nginx we build knows how to use it, so the reason
  # is gone.  Worth having beyond the version number, because QUIC is where the
  # post quantum key exchange matters most: a handshake somebody captures today
  # is decrypted whenever a quantum computer turns up, and QUIC handshakes are
  # the ones carrying everything from the first flight.
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

# Outside modules.  Format is "folder|git-url|git-ref".  We clone each one and
# add it to the build.  The ref can be a tag or a branch.
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

# nchan was here and was taken out on 25 August 2026.  Please do not put it
# back without reading this.
#
# It is a publish and subscribe server built into nginx: an application posts a
# message to a channel and every browser holding a connection open gets it, over
# websockets, server sent events or long polling.  A good module, and nothing
# here has ever used it.  The manager generates no nchan directive of any kind,
# and the GUI's live pages poll on a timer rather than being pushed to.
#
# It cost two outages.  On 17 August and again on 24 August, seconds after an
# nginx reload, every worker aborted inside it and died holding the lock on its
# shared memory zone.  A zone left locked by a dead process stays locked, and
# nginx builds those zones once at startup, so a reload hands the same poisoned
# zone straight back to the replacement workers and they block on it too.  The
# master keeps the listening sockets throughout, so the machine goes on
# accepting connections and answering none of them.  It looks alive from
# outside and from systemd, and the second time it took 72 minutes and a manual
# restart to clear.
#
# Being compiled in is what made it unavoidable.  It claimed a 128 MB shared
# memory zone on every node at startup purely because it was present, with no
# directive asking for it.  The note under the dynamic module list below makes
# this same argument about ModSecurity, and it applies here: a compiled in
# module is part of the binary whether anybody wants it or not.
#
# If push ever is wanted, add it to the dynamic list below instead, so it sits
# on disk doing nothing until a node's config actually asks for it.

# Modules built as loadable .so files instead of compiled in.  Same
# "folder|git-url|git-ref" format as the list above.
#
# Why these are not just in THIRD_PARTY_MODULES: a compiled in module is part
# of the binary whether anybody wants it or not.  ModSecurity links against
# libmodsecurity.so, and if that library is ever missing or a version out of
# step, a statically linked nginx will not exec at all.  That would take down
# every node in the fleet over a feature most of them are not using.  Built
# this way the .so sits on disk doing nothing until a load_module line asks for
# it, and that line is only written for a node whose sites have the WAF on.
#
# --with-compat is in BUILTIN_MODULES above, which is what these need.
#
# The WAF is off unless asked for.  Measured at about two minutes of the four
# a whole build takes on a sixteen core box, and a good deal more on a small
# one, and most installs will never switch it on, so a fresh box does not pay
# for it.
# Turning it on in the GUI rebuilds nginx with WITH_MODSECURITY=1, which is the
# same path the version upgrades already take, so nobody has to edit this file
# or compile anything by hand.
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

# What libmodsecurity needs to build, added only when the WAF is being built.
# autotools because that is how it builds, yajl for the JSON audit log the hits
# page reads, lmdb for the counters CRS keeps between requests, curl for rules
# that fetch.  None of this goes on a box that is not building a WAF.
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
# Note: the lua module needs OpenResty's own LuaJIT, not the stock Ubuntu one.
# We build that from source in build_lua_support, so it is not an apt package.


# ==============================================================================
# Other settings
# ==============================================================================

# This is the name we show in the Server header instead of nginx.  Set it to
# whatever you like, or leave it blank to drop the header completely.
FAKE_SERVER_NAME="server"

# Where things live.  You probably do not need to touch these.
PREFIX="/etc/nginx"
SBIN="/usr/sbin/nginx"
BUILD_ROOT="/usr/local/src/nginx-build"
BACKUP_ROOT="/var/backups/nginx-installer"

# Source tarballs live here between builds.  BUILD_ROOT gets cleared at the
# start of every build, so without this each one re-downloads nginx and the
# whole of openssl.
CACHE_DIR="/var/cache/nginx-installer"
WEBROOT="/var/www/html"
ACME_WEBROOT="/var/www/certbot"
RUN_USER="www-data"


# ==============================================================================
# Little helpers
# ==============================================================================

# Colored log lines so it is easy to see what happened.
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Catch anything that dies without going through die().  Before this was here a
# command could fail with its errors sent to /dev/null and the script would
# just stop, no message, halfway through the install.  Now you get the line.
trap 'rc=$?; printf "\033[1;31m[x]\033[0m Stopped at line %s (exit %s), command: %s\n" "$LINENO" "$rc" "$BASH_COMMAND" >&2; exit $rc' ERR

# Most of this needs root since we touch system paths and services.
require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "Please run this with sudo or as root."
  fi
}

# True when systemd is actually running the box.  A container or a chroot can
# have the systemctl binary sitting there without systemd as pid 1, and every
# call we make would fail for a reason that has nothing to do with our config.
have_systemd() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

# We only promise this works on the two Ubuntu LTS releases the user asked for.
# Anything else still tries, but we say so up front.
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

# Grab a file, keeping a copy so the next build does not go out to the network
# for the same fifty megabytes.
#
# Both callers pass a tarball.  The cached copy is only used if it still unpacks,
# which catches a half written file from an interrupted build; a corrupt cache
# that failed the build every time until somebody worked out to delete it would
# be a worse bug than the one this fixes.
#
# The retries got longer after a real failure.  Both boxes sit behind one
# address, so three builds in a row means three pulls of the same file from the
# same place in a few minutes, and the third came back empty.  Five tries with a
# wait between them costs nothing on a good day and saves a twenty minute build
# on a bad one.
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

  # Keep it, but never let a caching problem fail an otherwise good build.
  if tar tzf "$out" >/dev/null 2>&1; then
    mkdir -p "$CACHE_DIR"
    cp -a "$out" "${cached}.part" 2>/dev/null && mv "${cached}.part" "$cached" 2>/dev/null || true
  fi
}


# ==============================================================================
# Dependencies
# ==============================================================================

# Pull in everything the source build needs.  We lean on the distro for pcre2
# and zlib since those are stable, and we only build OpenSSL ourselves because
# that is where the post quantum support comes from.  The module deps get added
# on top from the EXTRA_BUILD_DEPS list.
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


# ==============================================================================
# Keep apt away from our binary
# ==============================================================================

# Here is the trap this saves you from.  Install anything that depends on the
# nginx package, and python3-certbot-nginx is the usual culprit, and apt pulls
# in Ubuntu's nginx.  Dpkg then unpacks its binary right on top of ours at
# /usr/sbin/nginx.  That binary has none of our modules compiled in, so the
# very next config test blows up with something like:
#
#   unknown directive "more_set_headers" in /etc/nginx/nginx.conf
#
# The nginx postinst runs that test, so it fails, and the whole apt run ends up
# half configured.  We block it three ways.  A stand in package so the nginx
# dependency is already met, a hold so apt will not swap that out, and a
# diversion so even a forced install lands on nginx.distrib instead of us.
protect_from_apt() {
  log "Setting up apt guards so nothing overwrites our nginx."

  # If the real packages are already here, say so.  We do not pull them out for
  # you, removing nginx-common can take your config down with it.
  # The "|| true" on the end matters.  On a clean box none of these packages
  # are installed, so dpkg-query exits 1, and with pipefail and set -e that
  # kills the whole install right here without printing a thing.  Not finding
  # them is the normal case, so it is not an error.
  # Our own stand in is named nginx too, so skip anything carrying our epoch of
  # 9.  Without this every rerun of install would tell you to remove the very
  # package we put there on the run before.
  local installed
  installed="$(dpkg-query -W -f='${Package} ${Status} ${Version}\n' nginx nginx-core nginx-common 2>/dev/null \
    | awk '$4 == "installed" && $5 !~ /^9:/ { printf "%s ", $1 }' || true)"
  if [[ -n "${installed// /}" ]]; then
    warn "Ubuntu's nginx packages are already installed: ${installed}"
    warn "Clear them out with: apt-get remove ${installed}"
    warn "Use remove, not purge.  Purge deletes the config in ${PREFIX}."
  fi

  # Hold the real names so apt will not quietly put them back on an upgrade.
  local pkg
  for pkg in nginx nginx-common nginx-core nginx-full; do
    apt-mark hold "$pkg" >/dev/null 2>&1 || true
  done
  log "Held: nginx nginx-common nginx-core nginx-full"

  # Last line of defense.  With this in place dpkg writes any nginx binary it
  # ships to ${SBIN}.distrib and ours stays put.  No --rename on purpose, we do
  # not want it moving the binary we just built.
  if ! dpkg-divert --list "$SBIN" 2>/dev/null | grep -q .; then
    dpkg-divert --local --divert "${SBIN}.distrib" --add "$SBIN" >/dev/null
    log "Diverted any packaged nginx to ${SBIN}.distrib"
  fi
}


# The stand in package, registered once the binary it describes actually exists.
#
# This used to run up front, alongside the holds above, and it recorded the
# version we were about to build rather than the one we had.  A build that then
# failed left the box telling dpkg it was running the new nginx while the old
# binary carried on serving.  That is worse than an ugly failure: anything that
# reads package versions, an inventory, a vulnerability scan, a person running
# dpkg -l, was told the upgrade had happened.  It found us on a box whose
# openssl download had timed out, which is a thing that will happen again.
#
# So it runs after the build, and it takes the version from the binary rather
# than from what we were aiming at, because those are only the same thing when
# everything worked.
register_stand_in_package() {
  local installed
  installed="$(dpkg-query -W -f='${Package} ${Status} ${Version}\n' nginx nginx-core nginx-common 2>/dev/null \
    | awk '$4 == "installed" && $5 !~ /^9:/ { printf "%s ", $1 }' || true)"

  # Build a tiny package named nginx that owns no files.  Apt sees the name as
  # installed, so a dependency on nginx is satisfied without the real thing.
  # The epoch of 9 keeps it sorted above anything Ubuntu will ever ship, so an
  # upgrade never decides ours is the older one.
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


# ==============================================================================
# Fetch and unpack the sources
# ==============================================================================

fetch_sources() {
  rm -rf "$BUILD_ROOT"
  mkdir -p "${BUILD_ROOT}/modules"
  cd "$BUILD_ROOT"

  fetch "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" nginx.tar.gz
  fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" openssl.tar.gz

  log "Unpacking nginx and OpenSSL."
  tar xf nginx.tar.gz
  tar xf openssl.tar.gz

  # Clone each outside module into its own folder.  Both lists land in the same
  # place, since the only difference between them is the configure flag.
  local entry name url ref
  for entry in "${THIRD_PARTY_MODULES[@]}" "${DYNAMIC_MODULES[@]}"; do
    IFS='|' read -r name url ref <<< "$entry"
    log "Fetching module $name ($ref)"
    git clone --depth 1 --branch "$ref" "$url" "modules/${name}" \
      || die "Could not fetch module $name from $url"
  done
}

# True when the WAF module is in the build.  Several steps below are skipped
# entirely without it, so a box that does not want a WAF does not spend any
# time compiling one.
wants_modsecurity() {
  printf '%s\n' "${DYNAMIC_MODULES[@]}" | grep -q "modsecurity-nginx"
}


# ==============================================================================
# Back up whatever is already installed
# ==============================================================================

# Before we overwrite anything we stash the current binary, the config, and the
# service file.  That snapshot is what revert restores, so every install leaves
# you a safe way back.
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


# ==============================================================================
# Lua support
# ==============================================================================

# The lua module is picky.  It needs OpenResty's own build of LuaJIT plus the
# resty.core lua files, or nginx will not even start.  Stock Ubuntu luajit does
# not cut it.  We only do any of this when lua is actually in the module list.
build_lua_support() {
  printf '%s\n' "${THIRD_PARTY_MODULES[@]}" | grep -q "lua-nginx-module" || return 0

  log "Building OpenResty LuaJIT for the lua module."
  git clone --depth 1 https://github.com/openresty/luajit2 "${BUILD_ROOT}/luajit2"
  make -C "${BUILD_ROOT}/luajit2" -j"$(nproc)"
  make -C "${BUILD_ROOT}/luajit2" install
  # Make sure the loader can find the new library at runtime.
  ldconfig

  # These two lua libs have to match the lua module version or nginx will not
  # start.  This trio is the set OpenResty ships together, so they play nice.
  # If you bump lua-nginx-module above, bump these to match.
  log "Installing lua-resty-core and lua-resty-lrucache."
  git clone --depth 1 --branch v0.1.31 https://github.com/openresty/lua-resty-core "${BUILD_ROOT}/lua-resty-core"
  make -C "${BUILD_ROOT}/lua-resty-core" install LUA_LIB_DIR=/usr/local/share/lua/5.1
  git clone --depth 1 --branch v0.15 https://github.com/openresty/lua-resty-lrucache "${BUILD_ROOT}/lua-resty-lrucache"
  make -C "${BUILD_ROOT}/lua-resty-lrucache" install LUA_LIB_DIR=/usr/local/share/lua/5.1
}


# ==============================================================================
# The WAF engine
# ==============================================================================

# libmodsecurity is the engine.  The nginx module in DYNAMIC_MODULES is only a
# connector and will not build without this, the same way the lua module will
# not build without LuaJIT.
#
# This is the slowest thing in the whole install after OpenSSL, so it only runs
# when the module is actually in the list.
build_modsecurity() {
  wants_modsecurity || return 0

  # Skip it when the right version is already here.
  #
  # This roughly halves a rebuild on a well specified box and saves far more on
  # a small one.  People rebuild nginx to pick up a new OpenSSL or to add a
  # module, and making all of them wait for a WAF engine that has not changed
  # since last time is how a maintained thing stops being maintained.  Bump
  # MODSECURITY_VERSION and it builds again; leave it alone and it does not.
  #
  # The connector in DYNAMIC_MODULES is rebuilt every time regardless, because
  # an nginx module is tied to the exact nginx it was compiled against.  That
  # part is quick.
  local stamp="/usr/local/lib/.modsecurity-version"
  if [[ -f "$stamp" && -f /usr/local/lib/libmodsecurity.so ]] \
     && [[ "$(cat "$stamp" 2>/dev/null)" == "$MODSECURITY_VERSION" ]]; then
    log "libmodsecurity ${MODSECURITY_VERSION} is already built, skipping it."
    # Still needs to be findable, in case ld.so.cache was rebuilt without it.
    ldconfig
    return 0
  fi

  log "Building libmodsecurity ${MODSECURITY_VERSION}.  This one takes a while."
  git clone --depth 1 --branch "v${MODSECURITY_VERSION}" \
    https://github.com/owasp-modsecurity/ModSecurity "${BUILD_ROOT}/ModSecurity" \
    || die "Could not fetch libmodsecurity ${MODSECURITY_VERSION}."

  # libinjection is a submodule, not vendored, and it is what does the SQL
  # injection and XSS detection.  Without this the build gets a long way in
  # before failing on a missing header.
  git -C "${BUILD_ROOT}/ModSecurity" submodule update --init --recursive --depth 1 \
    || die "Could not fetch the libmodsecurity submodules."

  cd "${BUILD_ROOT}/ModSecurity"
  ./build.sh
  # --prefix matters more than it looks.
  #
  # ModSecurity's configure defaults to /usr/local/modsecurity, not /usr/local,
  # which is unusual enough that it cost a whole build to find.  Two things go
  # wrong if it is left alone: the nginx connector cannot find the library, and
  # even pointed at it by hand the module would then fail at runtime, because
  # /usr/local/modsecurity/lib is not on the loader's search path and nginx
  # would start, load the module and die on a missing libmodsecurity.so.3.
  #
  # Installing into /usr/local instead puts it where ldconfig already looks, so
  # both problems go away rather than being papered over with an ld.so.conf.d
  # entry.
  #
  # The docs and examples are most of the build time and none of the value.
  # yajl and lmdb are asked for by name rather than left to autodetect, so a
  # missing package fails here with a clear reason instead of quietly producing
  # an engine that cannot write a JSON audit log, which is what the hits page
  # reads.
  ./configure \
    --prefix=/usr/local \
    --with-yajl \
    --with-lmdb \
    --disable-doxygen-doc \
    --disable-doxygen-html \
    --disable-examples
  make -j"$(nproc)"
  make install

  # Make sure the loader can find it, or nginx loads the module and dies on a
  # missing libmodsecurity.so.3 at startup.
  ldconfig

  # Only stamped once the build actually finished, so a run that died halfway
  # through builds again next time instead of being skipped forever.
  printf '%s\n' "$MODSECURITY_VERSION" > "$stamp"
}


# ==============================================================================
# The actual build
# ==============================================================================

build_nginx() {
  cd "${BUILD_ROOT}/nginx-${NGINX_VERSION}"

  # Turn the module list into --add-module flags, keeping the same order.
  local addmods=() entry name
  for entry in "${THIRD_PARTY_MODULES[@]}"; do
    name="${entry%%|*}"
    addmods+=( "--add-module=${BUILD_ROOT}/modules/${name}" )
  done

  # The dynamic ones get built into .so files under --modules-path instead of
  # into the binary.  Nothing loads them until a load_module line says to.
  for entry in "${DYNAMIC_MODULES[@]}"; do
    name="${entry%%|*}"
    addmods+=( "--add-dynamic-module=${BUILD_ROOT}/modules/${name}" )
  done

  # Point the connector at the libmodsecurity we just built.  Its config script
  # will fall back to pkg-config, which on Ubuntu can find the 3.0.12 package
  # instead and produce a module linked against an engine we did not choose.
  # Same reasoning as the LuaJIT variables below: say which one, do not guess.
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

  # Newer compilers like the GCC on Ubuntu 26.04 turn some warnings into hard
  # errors.  A few of the older modules trip those, so we tell the compiler to
  # keep warnings as warnings.  That way the build finishes on both releases.
  #
  # We also drop the perl module files inside /etc/nginx.  That folder gets
  # backed up on every install, so a revert brings the perl bits back in step
  # with the old binary instead of leaving a mismatched leftover behind.
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


# ==============================================================================
# Config files
# ==============================================================================

# Make all the folders nginx expects, plus the webroots for pages and for the
# certbot challenge files.
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

# The main config.  We only write this on a first install so an upgrade never
# stomps on your tweaks.  Your server blocks live in sites-enabled, not here.
write_main_conf() {
  if [[ -f "${PREFIX}/nginx.conf" ]] && grep -q "installer-managed" "${PREFIX}/nginx.conf" 2>/dev/null; then
    log "Keeping your existing nginx.conf."
    return
  fi
  # When lua is in the build we need to tell it where the resty files live.
  # If lua is dropped from the module list these lines are left out so the
  # config still loads.
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

# Put the modules-enabled include into an nginx.conf that predates it.
#
# write_main_conf above only writes on a first install, on purpose, so an
# upgrade never stomps on somebody's edits.  That leaves every box installed
# before dynamic modules existed with no way to load one: the manager would
# write a perfectly good file into modules-enabled and nothing would ever read
# it, and the WAF would look switched on while doing nothing at all.  That is
# the exact shape of bug this project keeps finding, so it gets handled here
# rather than discovered later.
#
# Only touches a config we wrote.  Somebody else's hand rolled nginx.conf is
# left alone and told about, because guessing where to put a directive in a
# file we do not understand is how an installer takes a node down.
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

  # Go in above the events block.  That is the first thing in every config this
  # installer has ever written, and anything before it is the main context,
  # which is the only place load_module is allowed.
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

  # Prove it before leaving it there.  A config test runs later anyway, but
  # failing here says which change did it.
  if ! "$SBIN" -t -c "$conf" >/dev/null 2>&1; then
    warn "nginx would not accept the include, putting your nginx.conf back."
    mv -f "${conf}.bak-modules" "$conf"
    return 0
  fi
}

# A shared TLS snippet.  Any site can include this to get solid settings plus
# the post quantum key exchange groups that OpenSSL 3.5 gives us.
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

# A plain http site so a fresh box actually serves something, and so certbot
# has a place to drop its challenge files.
# Let QUIC in, when there is a firewall here that would stop it.
#
# HTTP/3 is UDP, and this is the one place where a missing rule fails silently.
# A box allowing TCP 443 and nothing else serves every request perfectly over
# HTTP/2 while HTTP/3 never connects at all: no error, no log line, and the
# setting in the GUI looks on.  Somebody then spends an afternoon on the nginx
# config, which is correct.
#
# Only touches a firewall that is actually running, and says so when it does.
# Nothing is opened on a box with no firewall, because there is nothing to open
# and quietly starting one would be a much bigger change than this deserves.
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

  # No managed firewall here.  Say nothing loud, but leave the fact somewhere,
  # because "it is already open" and "nobody checked" look identical later.
  log "No ufw or firewalld running, so nothing is filtering ${port}/udp here."
  log "Anything in front of this box still has to allow UDP ${port} for HTTP/3."
}

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

# The systemd unit so nginx starts on boot and reloads cleanly.
write_service() {
  log "Writing the systemd service."

  # Clear the old file first.  If nginx.service was ever masked it is a symlink
  # pointing at /dev/null, and writing through that symlink throws our unit
  # away without a single error message.
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
  # No systemd on this box means no service to install, and that is fine.  But
  # if systemd is here and the reload fails, say so.  Hiding it is what leaves
  # you staring at "Unit nginx.service not found" later on.
  if have_systemd; then
    systemctl daemon-reload || die "systemctl daemon-reload failed, systemd never saw the new unit."
  else
    warn "No systemd here, skipping the service.  Start nginx yourself with ${SBIN}."
  fi
}


# ==============================================================================
# Our stand in for the certbot nginx plugin
# ==============================================================================
#
# python3-certbot-nginx does four handy things.  It reads your config to find
# which domains you serve, it makes sure the acme challenge can be answered, it
# writes the cert into the right server block, and it can flip plain http over
# to a redirect.  We cannot install it, it wants Ubuntu's nginx.  So we do the
# same four things here with our own code and plain webroot auth.
#
# The one rule everything below follows: back up the site file, make the edit,
# run a config test, and put the backup back if the test fails.  A bad edit
# never reaches a running server.

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

# Print every server_name we actually serve, one per line.  This is the part
# that replaces the plugin's domain picker.  We skip the catch all and any
# wildcard or regex name since Let's Encrypt will not take those over http-01.
discover_domains() {
  local f
  for f in "${PREFIX}"/sites-enabled/* "${PREFIX}"/conf.d/*.conf; do
    [[ -f "$f" ]] || continue
    sed 's/#.*//' "$f" | tr -s ' \t' ' ' \
      | grep -oE '(^| )server_name [^;]+;' \
      | sed 's/.*server_name //; s/;$//'
  done | tr ' ' '\n' | grep -vE '^\s*$|^_$|^\*|^~|^\.' | sort -u
}

# Find which file in sites-available holds a domain.  We look through the
# enabled links so we never touch a site that is turned off.
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

# The rewriter.  Reads a site file on stdin and writes the fixed one on stdout.
#
# For the matching plain http block it adds the challenge include, and if
# redirect is on it swaps the body of "location /" for a 301.  For the matching
# https block it points ssl_certificate at the new cert and pulls in our TLS
# snippet.  If there is no https block yet it appends one at the end.
#
# It walks the file counting braces so it only ever touches top level server
# blocks, and it strips comments before counting so a brace in a comment does
# not throw the depth off.
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

# Apply the rewrite to a real file, but only keep it if nginx still likes it.
# This is the safety net the plugin does not really give you.
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

# Certbot runs everything in this folder after a renewal.  Without it the new
# cert sits on disk while nginx keeps serving the old one until a restart.
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

# Before we ask Let's Encrypt for anything, prove the challenge path works.
# We drop a file where certbot will put its token and fetch it over port 80,
# the same way the acme server will.  Way easier to debug than a failed order.
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


# ==============================================================================
# Commands
# ==============================================================================

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

  # Test before stopping anything.
  #
  # This used to come after the disable below, and the order cost a node.  A
  # build that produced a working binary but one the live config would not load,
  # which is what you get when a module the config depends on drops out of the
  # build, went like this: nginx stopped, config test failed, installer died,
  # nginx never started again.  The box was left down, with a new binary that
  # could not serve the config it had.  On a standby you would not notice; on
  # the node taking traffic it is a full outage caused by the very step that was
  # meant to be safe.
  #
  # Testing first means a bad build leaves the old nginx running and serving.
  # The new binary is already in place at this point, so the way out is a revert,
  # but the site stays up while somebody does it.
  log "Testing the config before we stop anything."
  "$SBIN" -t

  # Get any old apt nginx out of the way before we drop our own unit in, so we
  # are never disabling the service we just wrote.
  if have_systemd; then
    systemctl disable --now nginx 2>/dev/null || true
  fi

  write_service
  write_renewal_hook

  if have_systemd; then
    # Prove the unit really landed before we tell anyone the install worked.
    [[ -s /etc/systemd/system/nginx.service ]] \
      || die "The service file is missing or empty, so systemctl will not find nginx."

    systemctl enable nginx || die "Could not enable nginx.service."

    # Let the real error through here.  A silent failure is how you end up
    # thinking the install worked when nothing is running.
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

# Roll back to the last snapshot we saved.  This swaps the binary, the config,
# and the service file back, then restarts nginx.
cmd_revert() {
  require_root
  local dir="${BACKUP_ROOT}/latest"
  [[ -d "$dir" ]] || die "No backup found, nothing to revert to."

  log "Reverting from $(readlink -f "$dir")"

  if [[ -f "${dir}/nginx.bin" ]]; then
    # You cannot write over a binary that is running.  The kernel says "Text
    # file busy" and the copy fails, which is exactly what this did for as long
    # as it existed: revert, the way out of a bad build, did not work at all,
    # and the one time you would ever reach for it is when something is already
    # broken.  It went unnoticed because nothing had reverted on a box where
    # nginx was up.
    #
    # Renaming a running binary is fine, the running process keeps the inode it
    # already has.  This is the same move nginx's own make install makes, which
    # is why building over a running nginx has always worked while this did not.
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
    # Emptied and refilled, not deleted and replaced.
    #
    # The agent reaches ${PREFIX} through a systemd ReadWritePaths bind mount,
    # and that mount is tied to the directory that existed when the agent
    # started.  Deleting the directory and untarring a new one in its place
    # leaves the agent holding a mount to an inode that no longer exists, so
    # every write it makes to nginx config comes back read only.  The node then
    # sits there looking healthy and quietly refusing to apply anything, until
    # somebody restarts the agent, and the one time you have just run a revert
    # is the one time you are least likely to guess that is what is wrong.
    #
    # Keeping the directory itself and swapping what is inside it keeps every
    # mount valid and needs nothing restarted.
    local staged
    staged="$(mktemp -d)"
    tar xzf "${dir}/etc-nginx.tar.gz" -C "$staged"

    if [[ -d "${staged}/$(basename "$PREFIX")" ]]; then
      mkdir -p "$PREFIX"
      find "$PREFIX" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
      # The dot matters, it copies what is inside rather than the folder itself.
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

# Grab a Let's Encrypt cert for a domain and write a fresh https site for it.
# Use this when the domain has no server block yet.  If it already has one,
# use autocert instead so we edit what is there rather than adding a second.
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

# This is our version of "certbot --nginx".  With no domains it reads your
# config, finds every server_name you serve, and does them all.  For each one
# it makes sure the challenge is answerable, gets the cert, then edits the
# existing server block in place instead of writing a whole new site.
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

    # Step one, make sure the challenge location is in the http block.  We ask
    # for no redirect yet, the cert does not exist so https would not load.
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

    # Step three, now that the cert is on disk, wire it in and add the redirect.
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

# Show what we would work on, same list autocert uses.
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

# Renew every cert and reload nginx.  The certbot package also does this on a
# timer, this is just for when you want to force it by hand.  The reload comes
# from the deploy hook we wrote, so there is nothing to pass here.
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
  # Call out a missing unit on its own.  "Service is not running" sends you
  # hunting through logs when the real problem is that systemd has no unit.
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


# ==============================================================================
# Dispatch
# ==============================================================================

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
