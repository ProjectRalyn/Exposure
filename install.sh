#!/usr/bin/env bash
set -euo pipefail

# Exposure Installer Script
# Supports installing the exposure musl binary, initializing node/control configs,
# and setting up hardened systemd services.

APP_NAME="exposure"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/exposure"
DATA_DIR="/var/lib/exposure"
SERVICE_USER="exposure"
USE_ROOT_USER=false

ROLE=""                 # node | control | binary-only
BIN_SRC=""              # local binary path
DOWNLOAD_URL=""         # remote HTTPS binary URL
DOWNLOAD_SHA256=""      # optional expected SHA-256 hex digest for --url
GITHUB_REPO="${EXPOSURE_GITHUB_REPO:-ProjectRalyn/Exposure}"
RELEASE_VERSION="${EXPOSURE_VERSION:-latest}"
NON_INTERACTIVE=false
FORCE_INIT=false
START_SERVICE=true
UNINSTALL=false
PURGE=false
TMP_BIN=""
TMP_SHA=""

# Node options
NODE_TAG=""
NODE_LISTEN=""
NODE_BOOTSTRAP=""
NODE_INGRESS=false
NODE_EGRESS=false
NODE_RELAY=false
NODE_MAINTAINER=false
CUSTOM_CONFIG=""
NODE_CONFIG=""
NODE_ROLES_EXPLICIT=false
NODE_PROMPT_DONE=false

# Control options
CONTROL_ID="control-1"
CONTROL_PANEL="127.0.0.1:8090"
CONTROL_SQLITE=""
ADMIN_USER="admin"
ADMIN_PASSWORD="${EXPOSURE_ADMIN_PASSWORD:-}"
BOOTSTRAP_TAG=""
BOOTSTRAP_ADDR=""
BOOTSTRAP_PASSPHRASE="${EXPOSURE_BOOTSTRAP_PASSPHRASE:-}"
CONTROL_CONFIG=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { printf '%b[INFO]%b %s\n' "$GREEN" "$NC" "$*"; }
log_warn()  { printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$*"; }
log_error() { printf '%b[ERROR]%b %s\n' "$RED" "$NC" "$*" >&2; }
die()       { log_error "$*"; exit 1; }

cleanup_tmp() {
    if [[ -n "${TMP_BIN:-}" && -f "$TMP_BIN" ]]; then
        rm -f -- "$TMP_BIN"
    fi
    if [[ -n "${TMP_SHA:-}" && -f "$TMP_SHA" ]]; then
        rm -f -- "$TMP_SHA"
    fi
}
trap cleanup_tmp EXIT

usage() {
    cat <<EOF
Exposure Installer

Usage:
  $0 [OPTIONS]

General Options:
  --role <node|control|binary-only>
                          Component role to install/configure (prompts if omitted on TTY)
  --bin <path>            Path to local exposure binary (skips GitHub Release download)
  --url <https-url>       Download HTTPS URL for exposure binary (if not using GitHub Release)
  --repo <owner/repo>     GitHub repository for release downloads (default: ProjectRalyn/Exposure)
  --version <tag|latest>  Release tag to download (default: latest)
  --sha256 <hex>          Expected 64-char SHA-256 hex digest for binary
  --bin-dir <dir>         Binary install directory (default: /usr/local/bin)
  --config-dir <dir>      Config directory (default: /etc/exposure)
  --data-dir <dir>        Data/state directory (default: /var/lib/exposure)
  --user <name>           System user for systemd service (default: exposure)
  --run-as-root           Run systemd service as root instead of dedicated user
  -y, --non-interactive   Disable interactive prompts (use CLI flags/defaults)
  --force-init            Overwrite existing config file if present
  --no-start              Install service without starting it immediately
  --uninstall             Uninstall exposure binary and systemd services
  --purge                 With --uninstall, also remove config and data directories
  -h, --help              Show this help message

Node Options (--role node):
  --tag <name>            Node tag (default: system hostname)
  --listen <addr>         Link listener address (e.g. 0.0.0.0:9443)
  --bootstrap <addr>      Bootstrap tunnel address
  --ingress               Enable ingress role
  --egress                Enable egress role
  --relay                 Enable relay role
  --maintainer            Enable maintainer role
  --config <path>         Node config path (default: <config-dir>/node.yaml)

Control Options (--role control):
  --id <id>               Control ID (default: control-1)
  --panel <addr>          Panel listen address (default: 127.0.0.1:8090)
  --sqlite <path>         SQLite DB path (default: <data-dir>/control.db)
  --admin-user <user>     Admin username (default: admin)
  --admin-password <pw>   Admin password (prefer EXPOSURE_ADMIN_PASSWORD env; auto-generated if omitted)
  --bootstrap-tag <tag>   Initial bootstrap node tag
  --bootstrap-addr <addr> Initial bootstrap node address
  --bootstrap-passphrase <phrase>
                          Initial bootstrap node passphrase (prefer EXPOSURE_BOOTSTRAP_PASSPHRASE env)
  --config <path>         Control config path (default: <config-dir>/control.yaml)

Examples:
  # Install binary only
  sudo $0 --bin ./exposure

  # Install and start an ingress+relay node
  sudo $0 --bin ./exposure --role node --tag ingress-hk --listen 0.0.0.0:9443 --ingress --relay

  # Install and start Control plane (recommended: pass secrets via environment)
  sudo EXPOSURE_ADMIN_PASSWORD='strong-secret-password' $0 --bin ./exposure --role control --panel 127.0.0.1:8090
EOF
}

require_arg() {
    local opt="$1"
    local argc="$2"
    if [[ "$argc" -lt 2 ]]; then
        die "Option ${opt} requires a value."
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role)                 require_arg "$1" "$#"; ROLE="$2"; shift 2 ;;
            --bin)                  require_arg "$1" "$#"; BIN_SRC="$2"; shift 2 ;;
            --url)                  require_arg "$1" "$#"; DOWNLOAD_URL="$2"; shift 2 ;;
            --repo)                 require_arg "$1" "$#"; GITHUB_REPO="$2"; shift 2 ;;
            --version)              require_arg "$1" "$#"; RELEASE_VERSION="$2"; shift 2 ;;
            --sha256)               require_arg "$1" "$#"; DOWNLOAD_SHA256="$2"; shift 2 ;;
            --bin-dir)              require_arg "$1" "$#"; BIN_DIR="$2"; shift 2 ;;
            --config-dir)           require_arg "$1" "$#"; CONFIG_DIR="$2"; shift 2 ;;
            --data-dir)             require_arg "$1" "$#"; DATA_DIR="$2"; shift 2 ;;
            --user)                 require_arg "$1" "$#"; SERVICE_USER="$2"; shift 2 ;;
            --run-as-root)          USE_ROOT_USER=true; shift ;;
            -y|--non-interactive)   NON_INTERACTIVE=true; shift ;;
            --force-init)           FORCE_INIT=true; shift ;;
            --no-start)             START_SERVICE=false; shift ;;
            --uninstall)            UNINSTALL=true; shift ;;
            --purge)                PURGE=true; shift ;;

            --tag)                  require_arg "$1" "$#"; NODE_TAG="$2"; shift 2 ;;
            --listen)               require_arg "$1" "$#"; NODE_LISTEN="$2"; shift 2 ;;
            --bootstrap)            require_arg "$1" "$#"; NODE_BOOTSTRAP="$2"; shift 2 ;;
            --ingress)              NODE_INGRESS=true; NODE_ROLES_EXPLICIT=true; shift ;;
            --egress)               NODE_EGRESS=true; NODE_ROLES_EXPLICIT=true; shift ;;
            --relay)                NODE_RELAY=true; NODE_ROLES_EXPLICIT=true; shift ;;
            --maintainer)           NODE_MAINTAINER=true; NODE_ROLES_EXPLICIT=true; shift ;;
            --config)               require_arg "$1" "$#"; CUSTOM_CONFIG="$2"; shift 2 ;;

            --id)                   require_arg "$1" "$#"; CONTROL_ID="$2"; shift 2 ;;
            --panel)                require_arg "$1" "$#"; CONTROL_PANEL="$2"; shift 2 ;;
            --sqlite)               require_arg "$1" "$#"; CONTROL_SQLITE="$2"; shift 2 ;;
            --admin-user)           require_arg "$1" "$#"; ADMIN_USER="$2"; shift 2 ;;
            --admin-password)       require_arg "$1" "$#"; ADMIN_PASSWORD="$2"; shift 2 ;;
            --bootstrap-tag)        require_arg "$1" "$#"; BOOTSTRAP_TAG="$2"; shift 2 ;;
            --bootstrap-addr)       require_arg "$1" "$#"; BOOTSTRAP_ADDR="$2"; shift 2 ;;
            --bootstrap-passphrase) require_arg "$1" "$#"; BOOTSTRAP_PASSPHRASE="$2"; shift 2 ;;

            -h|--help)              usage; exit 0 ;;
            *)                      die "Unknown option: $1 (use --help for usage)" ;;
        esac
    done

    if [[ -n "$CUSTOM_CONFIG" ]]; then
        if [[ "$ROLE" == "control" ]]; then
            CONTROL_CONFIG="$CUSTOM_CONFIG"
        else
            NODE_CONFIG="$CUSTOM_CONFIG"
        fi
    fi
}

validate_safe_path() {
    local label="$1"
    local p="$2"
    [[ -n "$p" ]] || die "${label} cannot be empty."
    if [[ "$p" =~ [[:space:][:cntrl:]] ]]; then
        die "${label} contains forbidden whitespace or control characters: $p"
    fi
    if [[ "$p" == *".."* ]]; then
        die "${label} cannot contain '..' path segments: $p"
    fi
}

validate_safe_dir() {
    local label="$1"
    local d="$2"
    local strict_purge="${3:-false}"
    validate_safe_path "$label" "$d"
    [[ "$d" == /* ]] || die "${label} must be an absolute path: $d"
    # Strip trailing slashes for comparison
    local norm="${d%/}"
    [[ -n "$norm" ]] || die "${label} cannot be '/'"

    case "$norm" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib)
            if [[ "$strict_purge" == "true" ]]; then
                die "${label} refuses dangerous system directory: $d"
            fi
            ;;
    esac
    if [[ "$strict_purge" == "true" && "$norm" == "/usr/local" ]]; then
        die "${label} refuses dangerous system directory: $d"
    fi
}

validate_service_user() {
    local u="$1"
    if [[ ! "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        die "Invalid --user name: $u"
    fi
}

validate_inputs() {
    validate_safe_dir "--bin-dir" "$BIN_DIR" "false"
    validate_safe_dir "--config-dir" "$CONFIG_DIR" "true"
    validate_safe_dir "--data-dir" "$DATA_DIR" "true"
    if [[ "$USE_ROOT_USER" == "false" ]]; then
        validate_service_user "$SERVICE_USER"
    fi
    [[ -z "$NODE_CONFIG" ]]    || validate_safe_path "--config" "$NODE_CONFIG"
    [[ -z "$CONTROL_CONFIG" ]] || validate_safe_path "--config" "$CONTROL_CONFIG"
    [[ -z "$CONTROL_SQLITE" ]] || validate_safe_path "--sqlite" "$CONTROL_SQLITE"
    if [[ -n "$DOWNLOAD_SHA256" && ! "$DOWNLOAD_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        die "Invalid --sha256 digest (expected 64 hex characters)."
    fi
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "This script must be run as root (or with sudo)."
    fi
}

has_systemd() {
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  printf '%s\n' "x86_64" ;;
        aarch64|arm64) printf '%s\n' "aarch64" ;;
        *)             die "Unsupported architecture: $arch" ;;
    esac
}

verify_sha256() {
    local file="$1"
    local expected="${2,,}"
    local actual=""
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print tolower($1)}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print tolower($1)}')"
    else
        die "Cannot verify --sha256: neither sha256sum nor shasum is installed."
    fi
    if [[ "$actual" != "$expected" ]]; then
        die "SHA-256 mismatch for downloaded binary (expected ${expected}, got ${actual})."
    fi
    log_info "Verified binary SHA-256: ${actual}"
}

download_https() {
    local url="$1"
    local out="$2"
    [[ "$url" == https://* ]] || die "Download URL must use https:// (refusing insecure transport): $url"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 "$url" -o "$out"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --secure-protocol=TLSv1_2 -qO "$out" "$url"
    else
        die "Neither curl nor wget is installed."
    fi
}

resolve_binary() {
    local arch="$1"

    if [[ -n "$BIN_SRC" ]]; then
        [[ -f "$BIN_SRC" ]] || die "Specified binary not found: $BIN_SRC"
        if [[ -n "$DOWNLOAD_SHA256" ]]; then
            verify_sha256 "$BIN_SRC" "$DOWNLOAD_SHA256"
        fi
        return 0
    fi

    local asset_name="exposure-linux-${arch}"
    local release_base=""
    if [[ -z "$DOWNLOAD_URL" ]]; then
        if [[ "$RELEASE_VERSION" == "latest" ]]; then
            release_base="https://github.com/${GITHUB_REPO}/releases/latest/download"
        else
            release_base="https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_VERSION}"
        fi
        DOWNLOAD_URL="${release_base}/${asset_name}"
        log_info "Using GitHub Release (${RELEASE_VERSION}) for ${GITHUB_REPO}: ${asset_name}"
    fi

    TMP_BIN="$(mktemp /tmp/exposure.XXXXXX)"
    chmod 0700 "$TMP_BIN"
    log_info "Downloading exposure binary from $DOWNLOAD_URL ..."
    download_https "$DOWNLOAD_URL" "$TMP_BIN" \
        || die "Failed to download binary from $DOWNLOAD_URL (pass --bin <path> to install a local binary)."

    if [[ -z "$DOWNLOAD_SHA256" && -n "$release_base" ]]; then
        TMP_SHA="$(mktemp /tmp/exposure-sha.XXXXXX)"
        if download_https "${release_base}/SHA256SUMS.txt" "$TMP_SHA" 2>/dev/null; then
            local sum_line
            sum_line="$(grep -E "[[:space:]]${asset_name}\$" "$TMP_SHA" | head -n1 || true)"
            if [[ -n "$sum_line" ]]; then
                DOWNLOAD_SHA256="${sum_line%% *}"
            fi
        fi
    fi

    if [[ -n "$DOWNLOAD_SHA256" ]]; then
        verify_sha256 "$TMP_BIN" "$DOWNLOAD_SHA256"
    else
        log_warn "No checksum available; downloaded binary integrity was not checksum-verified."
    fi

    BIN_SRC="$TMP_BIN"
    return 0
}

install_binary() {
    local arch="$1"
    resolve_binary "$arch"
    mkdir -p "$BIN_DIR"
    local dst="${BIN_DIR}/${APP_NAME}"
    install -m 0755 "$BIN_SRC" "$dst"
    log_info "Installed binary to $dst"
    "$dst" --version || die "Installed binary failed to execute."
}

ensure_user_and_dirs() {
    local run_user="root"
    local run_group="root"

    if [[ "$USE_ROOT_USER" == "false" ]]; then
        if ! id "$SERVICE_USER" >/dev/null 2>&1; then
            log_info "Creating system user: $SERVICE_USER"
            if command -v useradd >/dev/null 2>&1; then
                useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
                    || useradd -r -M -s /sbin/nologin "$SERVICE_USER"
            elif command -v adduser >/dev/null 2>&1; then
                adduser -S -D -H "$SERVICE_USER"
            else
                die "Cannot create user $SERVICE_USER: useradd/adduser not found."
            fi
        fi
        run_user="$SERVICE_USER"
        run_group="$(id -gn "$SERVICE_USER")"
    fi

    mkdir -p "$CONFIG_DIR" "$DATA_DIR"
    chown -R "${run_user}:${run_group}" "$CONFIG_DIR" "$DATA_DIR"
    chmod 0700 "$CONFIG_DIR" "$DATA_DIR"
}

needs_net_bind_cap() {
    local addr="$1"
    local port="${addr##*:}"
    if [[ "$port" =~ ^[0-9]+$ && "$port" -lt 1024 ]]; then
        return 0
    fi
    return 1
}

write_systemd_unit() {
    local unit_name="$1"
    local description="$2"
    local exec_cmd="$3"
    local grant_net_bind="$4"
    local extra_rw_paths="${5:-}"
    local run_user="root"
    [[ "$USE_ROOT_USER" == "false" ]] && run_user="$SERVICE_USER"

    local cap_lines=""
    if [[ "$grant_net_bind" == "true" ]]; then
        cap_lines=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
    else
        cap_lines=$'AmbientCapabilities=\nCapabilityBoundingSet='
    fi

    local rw_paths="${CONFIG_DIR} ${DATA_DIR}"
    if [[ -n "$extra_rw_paths" ]]; then
        rw_paths="${rw_paths} ${extra_rw_paths}"
    fi

    local unit_path="/etc/systemd/system/${unit_name}.service"
    cat > "$unit_path" <<EOF
[Unit]
Description=${description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${run_user}
WorkingDirectory=${DATA_DIR}
ExecStart=${exec_cmd}
Restart=always
RestartSec=3
LimitNOFILE=1048576
${cap_lines}
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
ReadWritePaths=${rw_paths}

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$unit_path"
    log_info "Wrote hardened systemd unit: $unit_path"

    if has_systemd; then
        systemctl daemon-reload
        systemctl enable "${unit_name}.service"
        if [[ "$START_SERVICE" == "true" ]]; then
            systemctl restart "${unit_name}.service"
            log_info "Started ${unit_name}.service"
        else
            log_info "Enabled ${unit_name}.service (not started due to --no-start)"
        fi
    else
        log_warn "systemd is not running; unit file created at $unit_path. Run manually:"
        printf '  %s\n' "$exec_cmd"
    fi
}

can_prompt() {
    [[ "$NON_INTERACTIVE" == "false" && -r /dev/tty && -w /dev/tty ]]
}

prompt_val() {
    local __var="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local reply=""
    if [[ -n "$default_val" ]]; then
        printf '%b?%b %s [%s]: ' "$CYAN" "$NC" "$prompt_text" "$default_val" >/dev/tty
    else
        printf '%b?%b %s: ' "$CYAN" "$NC" "$prompt_text" >/dev/tty
    fi
    IFS= read -r reply </dev/tty || reply=""
    if [[ -z "$reply" ]]; then
        reply="$default_val"
    fi
    printf -v "$__var" '%s' "$reply"
}

prompt_yn() {
    local __var="$1"
    local prompt_text="$2"
    local default_yn="${3:-n}"
    local hint="y/N"
    [[ "$default_yn" == "y" ]] && hint="Y/n"
    local reply=""
    printf '%b?%b %s [%s]: ' "$CYAN" "$NC" "$prompt_text" "$hint" >/dev/tty
    IFS= read -r reply </dev/tty || reply=""
    reply="${reply:-$default_yn}"
    case "${reply,,}" in
        y|yes|true|1) printf -v "$__var" '%s' "true" ;;
        *)            printf -v "$__var" '%s' "false" ;;
    esac
}

prompt_secret() {
    local __var="$1"
    local prompt_text="$2"
    local reply=""
    printf '%b?%b %s: ' "$CYAN" "$NC" "$prompt_text" >/dev/tty
    IFS= read -rs reply </dev/tty || reply=""
    printf '\n' >/dev/tty
    printf -v "$__var" '%s' "$reply"
}

detect_primary_ip() {
    local ip=""
    if command -v hostname >/dev/null 2>&1; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    if [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
    fi
    printf '%s' "${ip:-<this-host-ip>}"
}

prompt_role_if_needed() {
    if [[ -n "$ROLE" ]]; then
        return 0
    fi
    if ! can_prompt; then
        ROLE="binary-only"
        return 0
    fi
    printf '\n%bSelect Exposure component to install:%b\n' "$CYAN" "$NC" >/dev/tty
    printf '  1) node         (Mesh Node: Ingress / Egress / Relay / Maintainer)\n' >/dev/tty
    printf '  2) control      (Control Plane & Admin Web Panel)\n' >/dev/tty
    printf '  3) binary-only  (Install exposure binary only)\n' >/dev/tty
    local choice=""
    prompt_val choice "Enter choice (1-3)" "1"
    case "$choice" in
        1|node)        ROLE="node" ;;
        2|control)     ROLE="control" ;;
        3|binary-only) ROLE="binary-only" ;;
        *)             die "Invalid selection: $choice" ;;
    esac
}

prompt_node_init() {
    [[ "$NODE_PROMPT_DONE" == "true" ]] && return 0
    NODE_PROMPT_DONE=true
    can_prompt || return 0

    local default_tag="${NODE_TAG:-$(hostname -s 2>/dev/null || hostname)}"
    local default_listen="${NODE_LISTEN:-0.0.0.0:10802}"
    printf '\n%bConfigure Node Initialization:%b\n' "$CYAN" "$NC" >/dev/tty
    prompt_val NODE_TAG "Node Tag (--tag)" "$default_tag"
    prompt_val NODE_LISTEN "Link Listen Address (--listen, or 'none' to disable)" "$default_listen"
    if [[ "${NODE_LISTEN,,}" == "none" || "${NODE_LISTEN,,}" == "off" ]]; then
        NODE_LISTEN=""
    fi

    if [[ "$NODE_ROLES_EXPLICIT" == "false" ]]; then
        prompt_yn NODE_INGRESS "Enable Ingress role?" "n"
        prompt_yn NODE_EGRESS "Enable Egress role?" "y"
        prompt_yn NODE_RELAY "Enable Relay role?" "n"
        prompt_yn NODE_MAINTAINER "Enable Maintainer role?" "n"
    fi

    prompt_val NODE_BOOTSTRAP "Bootstrap Tunnel Address (optional, e.g. 1.2.3.4:10802)" "$NODE_BOOTSTRAP"
}

prompt_control_init() {
    can_prompt || return 0
    printf '\n%bConfigure Control Plane Initialization:%b\n' "$CYAN" "$NC" >/dev/tty
    prompt_val CONTROL_ID "Control ID (--id)" "$CONTROL_ID"
    prompt_val CONTROL_PANEL "Admin Panel Listen Address (--panel)" "$CONTROL_PANEL"
    prompt_val ADMIN_USER "Admin Username (--admin-user)" "$ADMIN_USER"
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        prompt_secret ADMIN_PASSWORD "Admin Password (leave blank to auto-generate)"
    fi
    prompt_val BOOTSTRAP_TAG "Initial Bootstrap Node Tag (optional)" "$BOOTSTRAP_TAG"
    if [[ -n "$BOOTSTRAP_TAG" ]]; then
        prompt_val BOOTSTRAP_ADDR "Initial Bootstrap Node Address (e.g. 1.2.3.4:10802)" "$BOOTSTRAP_ADDR"
        if [[ -z "$BOOTSTRAP_PASSPHRASE" ]]; then
            prompt_secret BOOTSTRAP_PASSPHRASE "Initial Bootstrap Node 5-Word Passphrase (optional)"
        fi
    fi
}

setup_node() {
    local cfg="${NODE_CONFIG:-${CONFIG_DIR}/node.yaml}"
    local cfg_dir
    cfg_dir="$(dirname "$cfg")"
    mkdir -p "$cfg_dir"
    local tag="${NODE_TAG:-$(hostname -s 2>/dev/null || hostname)}"
    local node_pubkey=""

    if [[ ! -f "$cfg" || "$FORCE_INIT" == "true" ]]; then
        prompt_node_init
        tag="${NODE_TAG:-$tag}"

        local args=(init-node --tag "$tag" --output "$cfg")
        [[ "$FORCE_INIT" == "true" ]]      && args+=(--force)
        [[ -n "$NODE_LISTEN" ]]            && args+=(--listen "$NODE_LISTEN")
        [[ -n "$NODE_BOOTSTRAP" ]]         && args+=(--bootstrap "$NODE_BOOTSTRAP")
        [[ "$NODE_INGRESS" == "true" ]]    && args+=(--ingress)
        [[ "$NODE_EGRESS" == "true" ]]     && args+=(--egress)
        [[ "$NODE_RELAY" == "true" ]]      && args+=(--relay)
        [[ "$NODE_MAINTAINER" == "true" ]] && args+=(--maintainer)

        log_info "Initializing Node config at $cfg ..."
        local init_out=""
        init_out="$(umask 0077; "${BIN_DIR}/${APP_NAME}" "${args[@]}")"
        printf '%s\n' "$init_out"
        node_pubkey="$(printf '%s\n' "$init_out" | awk -F': *' '/^Public Key:/ {print $2; exit}')"
        chmod 0600 "$cfg"
        if [[ "$USE_ROOT_USER" == "false" ]]; then
            chown "${SERVICE_USER}:$(id -gn "$SERVICE_USER")" "$cfg"
        fi
    else
        log_info "Using existing Node config: $cfg"
    fi

    local extra_rw=""
    if [[ "$cfg_dir" != "$CONFIG_DIR" && "$cfg_dir" != "$DATA_DIR" ]]; then
        extra_rw="$cfg_dir"
    fi

    local start_since
    start_since="$(date '+%Y-%m-%d %H:%M:%S')"

    write_systemd_unit \
        "exposure-node" \
        "Exposure Reverse Proxy & Mesh Node" \
        "${BIN_DIR}/${APP_NAME} node --config ${cfg}" \
        "true" \
        "$extra_rw"

    # Wait briefly for exposure-node to print its one-time 5-word onboarding passphrase
    local passphrase=""
    if [[ "$START_SERVICE" == "true" ]] && has_systemd && command -v journalctl >/dev/null 2>&1; then
        local i
        for i in 1 2 3 4 5; do
            sleep 1
            passphrase="$(journalctl -u exposure-node.service --since "$start_since" --no-pager -o cat 2>/dev/null \
                | awk '/ONE-TIME ONBOARDING PASSPHRASE/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}' || true)"
            if [[ -n "$passphrase" ]]; then
                break
            fi
        done
    fi

    local mode_label="Listening (mesh dials node)"
    local host_ip
    host_ip="$(detect_primary_ip)"
    local listen_port="${NODE_LISTEN##*:}"
    [[ -z "$NODE_LISTEN" || "$listen_port" == "$NODE_LISTEN" ]] && listen_port="10802"
    local listen_addr_hint="${host_ip}:${listen_port}"
    if [[ -n "$NODE_BOOTSTRAP" ]]; then
        mode_label="Active (node dials bootstrap tunnel)"
    fi

    printf '\n%b==================== Onboarding Info ====================%b\n' "$CYAN" "$NC"
    printf 'Use these values in Control Panel -> Onboarding:\n'
    printf '  Target Node Tag   : %s\n' "$tag"
    if [[ -n "$passphrase" ]]; then
        printf '  5-Word Passphrase : %s\n' "$passphrase"
    else
        printf '  5-Word Passphrase : (check logs: journalctl -u exposure-node -n 30 --no-pager)\n'
    fi
    printf '  Onboarding Mode   : %s\n' "$mode_label"
    if [[ -n "$NODE_BOOTSTRAP" ]]; then
        printf '  Bootstrap Tunnel  : %s\n' "$NODE_BOOTSTRAP"
    else
        printf '  Address (Listen)  : %s\n' "$listen_addr_hint"
    fi
    if [[ -n "$node_pubkey" ]]; then
        printf '  Node Public Key   : %s\n' "$node_pubkey"
    fi
    printf '  Config File       : %s\n' "$cfg"
    printf '%b=========================================================%b\n\n' "$CYAN" "$NC"
}

generate_random_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
    else
        dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'
        printf '\n'
    fi
}

setup_control() {
    local cfg="${CONTROL_CONFIG:-${CONFIG_DIR}/control.yaml}"
    local sqlite="${CONTROL_SQLITE:-${DATA_DIR}/control.db}"
    local cfg_dir sqlite_dir
    cfg_dir="$(dirname "$cfg")"
    sqlite_dir="$(dirname "$sqlite")"
    mkdir -p "$cfg_dir" "$sqlite_dir"

    local generated_pw=false
    local sign_pk=""
    local link_pk=""

    if [[ ! -f "$cfg" || "$FORCE_INIT" == "true" ]]; then
        prompt_control_init

        if [[ -z "$ADMIN_PASSWORD" ]]; then
            ADMIN_PASSWORD="$(generate_random_password)"
            generated_pw=true
        fi

        local args=(
            init-control
            --id "$CONTROL_ID"
            --output "$cfg"
            --panel "$CONTROL_PANEL"
            --sqlite "$sqlite"
            --admin-user "$ADMIN_USER"
        )
        [[ "$FORCE_INIT" == "true" ]] && args+=(--force)
        [[ -n "$BOOTSTRAP_TAG" ]]     && args+=(--bootstrap-tag "$BOOTSTRAP_TAG")
        [[ -n "$BOOTSTRAP_ADDR" ]]    && args+=(--bootstrap-addr "$BOOTSTRAP_ADDR")

        log_info "Initializing Control config at $cfg ..."
        local init_out=""
        init_out="$(
            umask 0077
            EXPOSURE_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
            EXPOSURE_BOOTSTRAP_PASSPHRASE="$BOOTSTRAP_PASSPHRASE" \
            "${BIN_DIR}/${APP_NAME}" "${args[@]}"
        )"
        printf '%s\n' "$init_out"
        sign_pk="$(printf '%s\n' "$init_out" | awk -F': *' '/^Signing Public Key:/ {print $2; exit}')"
        link_pk="$(printf '%s\n' "$init_out" | awk -F': *' '/^Link Public Key:/ {print $2; exit}')"
        chmod 0600 "$cfg"
        if [[ "$USE_ROOT_USER" == "false" ]]; then
            chown "${SERVICE_USER}:$(id -gn "$SERVICE_USER")" "$cfg"
        fi
    else
        log_info "Using existing Control config: $cfg"
    fi

    local grant_net_bind="false"
    if needs_net_bind_cap "$CONTROL_PANEL"; then
        grant_net_bind="true"
    fi

    local extra_rw=""
    if [[ "$cfg_dir" != "$CONFIG_DIR" && "$cfg_dir" != "$DATA_DIR" ]]; then
        extra_rw="${extra_rw} ${cfg_dir}"
    fi
    if [[ "$sqlite_dir" != "$CONFIG_DIR" && "$sqlite_dir" != "$DATA_DIR" && "$sqlite_dir" != "$cfg_dir" ]]; then
        extra_rw="${extra_rw} ${sqlite_dir}"
    fi

    write_systemd_unit \
        "exposure-control" \
        "Exposure Control Plane & Admin Panel" \
        "${BIN_DIR}/${APP_NAME} control --config ${cfg}" \
        "$grant_net_bind" \
        "${extra_rw# }"

    printf '\n%b================= Control Plane Info ====================%b\n' "$CYAN" "$NC"
    printf '  Control ID        : %s\n' "$CONTROL_ID"
    printf '  Admin Panel       : http://%s\n' "$CONTROL_PANEL"
    printf '  Admin Username    : %s\n' "$ADMIN_USER"
    if [[ "$generated_pw" == "true" ]]; then
        printf '  Admin Password    : %s\n' "$ADMIN_PASSWORD"
    fi
    if [[ -n "$sign_pk" ]]; then
        printf '  Signing PubKey    : %s\n' "$sign_pk"
    fi
    if [[ -n "$link_pk" ]]; then
        printf '  Link PubKey       : %s\n' "$link_pk"
    fi
    printf '  Config File       : %s\n' "$cfg"
    printf '%b=========================================================%b\n\n' "$CYAN" "$NC"
}

do_uninstall() {
    for svc in exposure-node exposure-control; do
        if has_systemd; then
            if systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
                systemctl stop "${svc}.service"
            fi
            if systemctl is-enabled --quiet "${svc}.service" 2>/dev/null; then
                systemctl disable "${svc}.service"
            fi
        fi
        if [[ -f "/etc/systemd/system/${svc}.service" ]]; then
            rm -f -- "/etc/systemd/system/${svc}.service"
            log_info "Removed /etc/systemd/system/${svc}.service"
        fi
    done

    if has_systemd; then
        systemctl daemon-reload
    fi

    if [[ -f "${BIN_DIR}/${APP_NAME}" ]]; then
        rm -f -- "${BIN_DIR}/${APP_NAME}"
        log_info "Removed ${BIN_DIR}/${APP_NAME}"
    fi

    if [[ "$PURGE" == "true" ]]; then
        rm -rf --one-file-system --preserve-root -- "$CONFIG_DIR" "$DATA_DIR"
        log_info "Purged $CONFIG_DIR and $DATA_DIR"
    else
        log_info "Kept $CONFIG_DIR and $DATA_DIR (pass --purge to remove)"
    fi
}

main() {
    parse_args "$@"
    validate_inputs
    require_root

    if [[ "$UNINSTALL" == "true" ]]; then
        do_uninstall
        exit 0
    fi

    local arch
    arch="$(detect_arch)"
    log_info "Detected architecture: $arch"

    prompt_role_if_needed

    case "$ROLE" in
        node|control|binary-only) ;;
        *) die "Invalid --role: $ROLE (expected: node, control, or binary-only)" ;;
    esac

    install_binary "$arch"

    if [[ "$ROLE" == "binary-only" ]]; then
        log_info "Binary-only installation complete."
        exit 0
    fi

    ensure_user_and_dirs

    case "$ROLE" in
        node)    setup_node ;;
        control) setup_control ;;
    esac

    log_info "Exposure installation complete."
}

main "$@"
