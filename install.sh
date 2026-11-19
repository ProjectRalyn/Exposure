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
FORCE_INIT=false
START_SERVICE=true
UNINSTALL=false
PURGE=false
TMP_BIN=""

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
}
trap cleanup_tmp EXIT

usage() {
    cat <<EOF
Exposure Installer

Usage:
  $0 [OPTIONS]

General Options:
  --role <node|control|binary-only>
                          Component role to install/configure (default: binary-only)
  --bin <path>            Path to local exposure binary (auto-detected if omitted)
  --url <https-url>       Download HTTPS URL for exposure binary (if not using --bin)
  --sha256 <hex>          Expected 64-char SHA-256 hex digest for --url binary
  --bin-dir <dir>         Binary install directory (default: /usr/local/bin)
  --config-dir <dir>      Config directory (default: /etc/exposure)
  --data-dir <dir>        Data/state directory (default: /var/lib/exposure)
  --user <name>           System user for systemd service (default: exposure)
  --run-as-root           Run systemd service as root instead of dedicated user
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
            --sha256)               require_arg "$1" "$#"; DOWNLOAD_SHA256="$2"; shift 2 ;;
            --bin-dir)              require_arg "$1" "$#"; BIN_DIR="$2"; shift 2 ;;
            --config-dir)           require_arg "$1" "$#"; CONFIG_DIR="$2"; shift 2 ;;
            --data-dir)             require_arg "$1" "$#"; DATA_DIR="$2"; shift 2 ;;
            --user)                 require_arg "$1" "$#"; SERVICE_USER="$2"; shift 2 ;;
            --run-as-root)          USE_ROOT_USER=true; shift ;;
            --force-init)           FORCE_INIT=true; shift ;;
            --no-start)             START_SERVICE=false; shift ;;
            --uninstall)            UNINSTALL=true; shift ;;
            --purge)                PURGE=true; shift ;;

            --tag)                  require_arg "$1" "$#"; NODE_TAG="$2"; shift 2 ;;
            --listen)               require_arg "$1" "$#"; NODE_LISTEN="$2"; shift 2 ;;
            --bootstrap)            require_arg "$1" "$#"; NODE_BOOTSTRAP="$2"; shift 2 ;;
            --ingress)              NODE_INGRESS=true; shift ;;
            --egress)               NODE_EGRESS=true; shift ;;
            --relay)                NODE_RELAY=true; shift ;;
            --maintainer)           NODE_MAINTAINER=true; shift ;;
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

resolve_binary() {
    local arch="$1"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -n "$BIN_SRC" ]]; then
        [[ -f "$BIN_SRC" ]] || die "Specified binary not found: $BIN_SRC"
        if [[ -n "$DOWNLOAD_SHA256" ]]; then
            verify_sha256 "$BIN_SRC" "$DOWNLOAD_SHA256"
        fi
        return 0
    fi

    if [[ -n "$DOWNLOAD_URL" ]]; then
        [[ "$DOWNLOAD_URL" == https://* ]] || die "--url must use https:// (refusing insecure transport)."
        TMP_BIN="$(mktemp /tmp/exposure.XXXXXX)"
        chmod 0700 "$TMP_BIN"
        log_info "Downloading exposure binary from $DOWNLOAD_URL ..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --proto '=https' --tlsv1.2 "$DOWNLOAD_URL" -o "$TMP_BIN"
        elif command -v wget >/dev/null 2>&1; then
            wget --https-only --secure-protocol=TLSv1_2 -qO "$TMP_BIN" "$DOWNLOAD_URL"
        else
            die "Neither curl nor wget is installed."
        fi
        if [[ -n "$DOWNLOAD_SHA256" ]]; then
            verify_sha256 "$TMP_BIN" "$DOWNLOAD_SHA256"
        else
            log_warn "No --sha256 provided; downloaded binary integrity was not checksum-verified."
        fi
        BIN_SRC="$TMP_BIN"
        return 0
    fi

    # Auto-detect local binary relative to the script directory (never untrusted CWD)
    local candidates=(
        "${script_dir}/${APP_NAME}"
        "${script_dir}/target/${arch}-unknown-linux-musl/release/${APP_NAME}"
        "${script_dir}/target/release/${APP_NAME}"
    )
    for c in "${candidates[@]}"; do
        if [[ -f "$c" && -x "$c" ]]; then
            BIN_SRC="$c"
            log_info "Auto-detected binary: $BIN_SRC"
            return 0
        fi
    done

    die "Could not find exposure binary. Pass --bin <path> or --url <https-url>."
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

setup_node() {
    local cfg="${NODE_CONFIG:-${CONFIG_DIR}/node.yaml}"
    local cfg_dir
    cfg_dir="$(dirname "$cfg")"
    mkdir -p "$cfg_dir"
    local tag="${NODE_TAG:-$(hostname -s 2>/dev/null || hostname)}"

    if [[ ! -f "$cfg" || "$FORCE_INIT" == "true" ]]; then
        local args=(init-node --tag "$tag" --output "$cfg")
        [[ "$FORCE_INIT" == "true" ]]      && args+=(--force)
        [[ -n "$NODE_LISTEN" ]]            && args+=(--listen "$NODE_LISTEN")
        [[ -n "$NODE_BOOTSTRAP" ]]         && args+=(--bootstrap "$NODE_BOOTSTRAP")
        [[ "$NODE_INGRESS" == "true" ]]    && args+=(--ingress)
        [[ "$NODE_EGRESS" == "true" ]]     && args+=(--egress)
        [[ "$NODE_RELAY" == "true" ]]      && args+=(--relay)
        [[ "$NODE_MAINTAINER" == "true" ]] && args+=(--maintainer)

        log_info "Initializing Node config at $cfg ..."
        (umask 0077; "${BIN_DIR}/${APP_NAME}" "${args[@]}")
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

    write_systemd_unit \
        "exposure-node" \
        "Exposure Reverse Proxy & Mesh Node" \
        "${BIN_DIR}/${APP_NAME} node --config ${cfg}" \
        "true" \
        "$extra_rw"
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

    if [[ ! -f "$cfg" || "$FORCE_INIT" == "true" ]]; then
        local generated_pw=false
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
        (
            umask 0077
            EXPOSURE_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
            EXPOSURE_BOOTSTRAP_PASSPHRASE="$BOOTSTRAP_PASSPHRASE" \
            "${BIN_DIR}/${APP_NAME}" "${args[@]}"
        )
        chmod 0600 "$cfg"
        if [[ "$USE_ROOT_USER" == "false" ]]; then
            chown "${SERVICE_USER}:$(id -gn "$SERVICE_USER")" "$cfg"
        fi

        if [[ "$generated_pw" == "true" ]]; then
            printf '\n%bGenerated Control Admin Credentials:%b\n' "$CYAN" "$NC"
            printf '  Username: %s\n' "$ADMIN_USER"
            printf '  Password: %s\n\n' "$ADMIN_PASSWORD"
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

    if [[ -z "$ROLE" ]]; then
        ROLE="binary-only"
    fi

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
