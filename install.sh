#!/usr/bin/env bash
set -euo pipefail

# Exposure Installer Script
# Supports installing the exposure musl binary, initializing node/control configs,
# and setting up systemd services.

APP_NAME="exposure"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/exposure"
DATA_DIR="/var/lib/exposure"
SERVICE_USER="exposure"
USE_ROOT_USER=false

ROLE=""                 # node | control | binary-only
BIN_SRC=""              # local binary path
DOWNLOAD_URL=""         # remote binary URL
FORCE_INIT=false
START_SERVICE=true
UNINSTALL=false
PURGE=false

# Node options
NODE_TAG=""
NODE_LISTEN=""
NODE_BOOTSTRAP=""
NODE_INGRESS=false
NODE_EGRESS=false
NODE_RELAY=false
NODE_MAINTAINER=false
NODE_CONFIG=""

# Control options
CONTROL_ID="control-1"
CONTROL_PANEL="127.0.0.1:8090"
CONTROL_SQLITE=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""
BOOTSTRAP_TAG=""
BOOTSTRAP_ADDR=""
BOOTSTRAP_PASSPHRASE=""
CONTROL_CONFIG=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()       { log_error "$*"; exit 1; }

usage() {
    cat <<EOF
Exposure Installer

Usage:
  $0 [OPTIONS]

General Options:
  --role <node|control|binary-only>
                          Component role to install/configure (default: binary-only)
  --bin <path>            Path to local exposure binary (auto-detected if omitted)
  --url <url>             Download URL for exposure binary (if not using --bin)
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
  --admin-password <pw>   Admin password (auto-generated if omitted)
  --bootstrap-tag <tag>   Initial bootstrap node tag
  --bootstrap-addr <addr> Initial bootstrap node address
  --bootstrap-passphrase <phrase>
                          Initial bootstrap node 5-word passphrase
  --config <path>         Control config path (default: <config-dir>/control.yaml)

Examples:
  # Install binary only
  sudo $0 --bin ./exposure

  # Install and start an ingress+relay node
  sudo $0 --bin ./exposure --role node --tag ingress-hk --listen 0.0.0.0:9443 --ingress --relay

  # Install and start Control plane
  sudo $0 --bin ./exposure --role control --panel 0.0.0.0:8090 --admin-password 'secret'
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role)               ROLE="${2:-}"; shift 2 ;;
            --bin)                BIN_SRC="${2:-}"; shift 2 ;;
            --url)                DOWNLOAD_URL="${2:-}"; shift 2 ;;
            --bin-dir)            BIN_DIR="${2:-}"; shift 2 ;;
            --config-dir)         CONFIG_DIR="${2:-}"; shift 2 ;;
            --data-dir)           DATA_DIR="${2:-}"; shift 2 ;;
            --user)               SERVICE_USER="${2:-}"; shift 2 ;;
            --run-as-root)        USE_ROOT_USER=true; shift ;;
            --force-init)         FORCE_INIT=true; shift ;;
            --no-start)           START_SERVICE=false; shift ;;
            --uninstall)          UNINSTALL=true; shift ;;
            --purge)              PURGE=true; shift ;;

            --tag)                NODE_TAG="${2:-}"; shift 2 ;;
            --listen)             NODE_LISTEN="${2:-}"; shift 2 ;;
            --bootstrap)          NODE_BOOTSTRAP="${2:-}"; shift 2 ;;
            --ingress)            NODE_INGRESS=true; shift ;;
            --egress)             NODE_EGRESS=true; shift ;;
            --relay)              NODE_RELAY=true; shift ;;
            --maintainer)         NODE_MAINTAINER=true; shift ;;
            --config)
                if [[ "$ROLE" == "control" ]]; then
                    CONTROL_CONFIG="${2:-}"
                else
                    NODE_CONFIG="${2:-}"
                fi
                shift 2
                ;;

            --id)                 CONTROL_ID="${2:-}"; shift 2 ;;
            --panel)              CONTROL_PANEL="${2:-}"; shift 2 ;;
            --sqlite)             CONTROL_SQLITE="${2:-}"; shift 2 ;;
            --admin-user)         ADMIN_USER="${2:-}"; shift 2 ;;
            --admin-password)     ADMIN_PASSWORD="${2:-}"; shift 2 ;;
            --bootstrap-tag)      BOOTSTRAP_TAG="${2:-}"; shift 2 ;;
            --bootstrap-addr)     BOOTSTRAP_ADDR="${2:-}"; shift 2 ;;
            --bootstrap-passphrase) BOOTSTRAP_PASSPHRASE="${2:-}"; shift 2 ;;

            -h|--help)            usage; exit 0 ;;
            *)                    die "Unknown option: $1 (use --help for usage)" ;;
        esac
    done
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
        x86_64|amd64)  echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)             die "Unsupported architecture: $arch" ;;
    esac
}

resolve_binary() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -n "$BIN_SRC" ]]; then
        [[ -f "$BIN_SRC" ]] || die "Specified binary not found: $BIN_SRC"
        return 0
    fi

    if [[ -n "$DOWNLOAD_URL" ]]; then
        local tmp_bin
        tmp_bin="$(mktemp /tmp/exposure.XXXXXX)"
        log_info "Downloading exposure binary from $DOWNLOAD_URL ..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$DOWNLOAD_URL" -o "$tmp_bin"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "$tmp_bin" "$DOWNLOAD_URL"
        else
            rm -f "$tmp_bin"
            die "Neither curl nor wget is installed."
        fi
        BIN_SRC="$tmp_bin"
        return 0
    fi

    # Auto-detect local binary
    local candidates=(
        "${script_dir}/${APP_NAME}"
        "./${APP_NAME}"
        "${script_dir}/target/x86_64-unknown-linux-musl/release/${APP_NAME}"
        "${script_dir}/target/release/${APP_NAME}"
    )
    for c in "${candidates[@]}"; do
        if [[ -f "$c" && -x "$c" ]]; then
            BIN_SRC="$c"
            log_info "Auto-detected binary: $BIN_SRC"
            return 0
        fi
    done

    die "Could not find exposure binary. Pass --bin <path> or --url <url>."
}

install_binary() {
    resolve_binary
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
    chmod 0750 "$CONFIG_DIR" "$DATA_DIR"
}

write_systemd_unit() {
    local unit_name="$1"
    local description="$2"
    local exec_cmd="$3"
    local run_user="root"
    [[ "$USE_ROOT_USER" == "false" ]] && run_user="$SERVICE_USER"

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
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$unit_path"
    log_info "Wrote systemd unit: $unit_path"

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
        echo "  $exec_cmd"
    fi
}

setup_node() {
    local cfg="${NODE_CONFIG:-${CONFIG_DIR}/node.yaml}"
    local tag="${NODE_TAG:-$(hostname -s 2>/dev/null || hostname)}"

    if [[ ! -f "$cfg" || "$FORCE_INIT" == "true" ]]; then
        local args=(init-node --tag "$tag" --output "$cfg")
        [[ -n "$NODE_LISTEN" ]]    && args+=(--listen "$NODE_LISTEN")
        [[ -n "$NODE_BOOTSTRAP" ]] && args+=(--bootstrap "$NODE_BOOTSTRAP")
        [[ "$NODE_INGRESS" == "true" ]]    && args+=(--ingress)
        [[ "$NODE_EGRESS" == "true" ]]     && args+=(--egress)
        [[ "$NODE_RELAY" == "true" ]]      && args+=(--relay)
        [[ "$NODE_MAINTAINER" == "true" ]] && args+=(--maintainer)

        log_info "Initializing Node config at $cfg ..."
        "${BIN_DIR}/${APP_NAME}" "${args[@]}"
        chmod 0640 "$cfg"
        if [[ "$USE_ROOT_USER" == "false" ]]; then
            chown "${SERVICE_USER}:$(id -gn "$SERVICE_USER")" "$cfg"
        fi
    else
        log_info "Using existing Node config: $cfg"
    fi

    write_systemd_unit \
        "exposure-node" \
        "Exposure Reverse Proxy & Mesh Node" \
        "${BIN_DIR}/${APP_NAME} node --config ${cfg}"
}

generate_random_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20
    else
        tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
    fi
}

setup_control() {
    local cfg="${CONTROL_CONFIG:-${CONFIG_DIR}/control.yaml}"
    local sqlite="${CONTROL_SQLITE:-${DATA_DIR}/control.db}"

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
            --admin-password "$ADMIN_PASSWORD"
        )
        [[ -n "$BOOTSTRAP_TAG" ]]        && args+=(--bootstrap-tag "$BOOTSTRAP_TAG")
        [[ -n "$BOOTSTRAP_ADDR" ]]       && args+=(--bootstrap-addr "$BOOTSTRAP_ADDR")
        [[ -n "$BOOTSTRAP_PASSPHRASE" ]] && args+=(--bootstrap-passphrase "$BOOTSTRAP_PASSPHRASE")

        log_info "Initializing Control config at $cfg ..."
        "${BIN_DIR}/${APP_NAME}" "${args[@]}"
        chmod 0640 "$cfg"
        if [[ "$USE_ROOT_USER" == "false" ]]; then
            chown "${SERVICE_USER}:$(id -gn "$SERVICE_USER")" "$cfg"
        fi

        if [[ "$generated_pw" == "true" ]]; then
            echo ""
            echo -e "${CYAN}Generated Control Admin Credentials:${NC}"
            echo "  Username: $ADMIN_USER"
            echo "  Password: $ADMIN_PASSWORD"
            echo ""
        fi
    else
        log_info "Using existing Control config: $cfg"
    fi

    write_systemd_unit \
        "exposure-control" \
        "Exposure Control Plane & Admin Panel" \
        "${BIN_DIR}/${APP_NAME} control --config ${cfg}"
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
            rm -f "/etc/systemd/system/${svc}.service"
            log_info "Removed /etc/systemd/system/${svc}.service"
        fi
    done

    if has_systemd; then
        systemctl daemon-reload
    fi

    if [[ -f "${BIN_DIR}/${APP_NAME}" ]]; then
        rm -f "${BIN_DIR}/${APP_NAME}"
        log_info "Removed ${BIN_DIR}/${APP_NAME}"
    fi

    if [[ "$PURGE" == "true" ]]; then
        rm -rf "$CONFIG_DIR" "$DATA_DIR"
        log_info "Purged $CONFIG_DIR and $DATA_DIR"
    else
        log_info "Kept $CONFIG_DIR and $DATA_DIR (pass --purge to remove)"
    fi
}

main() {
    parse_args "$@"
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

    install_binary

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
