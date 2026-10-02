#!/bin/bash
# ==============================================================================
# Xray Reality Automation Engine (Industrial Architecture Edition - V6.7 Verified)
# Architecture: VLESS + XTLS-Vision + Reality + Nginx Reverse Proxy + Hysteria2
# ==============================================================================

# ------------------------------------------------------------------------------
# LAYER 1: 运行时基座、全局上下文与安全底座 (Runtime Toolkit & Core Safety)
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ERROR] 权限不足：执行本脚本需要 Root 权限。\e[0m"
    echo -e "\e[33m请执行 'sudo -i' 或 'su -' 获取 Root 权限后重新运行。\e[0m"
    [[ "${BASH_SOURCE[0]}" != "${0}" ]] && return 1 2>/dev/null || exit 1
fi

readonly SCRIPT_VERSION="6.7-Industrial-Verified"
readonly LOG_FILE="/dev/null"
readonly LOCK_FILE="/var/run/xray_script.lock"
readonly SCRIPT_DIR="/usr/local/etc/xray-script"
readonly XRAY_CONF_DIR="/usr/local/etc/xray"
readonly XRAY_SHARE_DIR="/usr/local/share/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly XRAY_CONFIG="$XRAY_CONF_DIR/config.json"
readonly HY2_CONF_DIR="/etc/hysteria"
readonly HY2_CONFIG="$HY2_CONF_DIR/config.yaml"
readonly HY2_BIN="/usr/local/bin/hysteria"
readonly ACME_BIN="/root/.acme.sh/acme.sh"

readonly C_RED="\e[31m"
readonly C_GREEN="\e[32m"
readonly C_YELLOW="\e[33m"
readonly C_BLUE="\e[36m"
readonly C_RESET="\e[0m"
readonly C_BOLD="\e[1m"

export AUTO_UPGRADE='0'
export LE_NO_LOG=1
export LE_LOG_FILE='/dev/null'
export DEBUG=0
export DEBIAN_FRONTEND="noninteractive"
export APT_LISTCHANGES_FRONTEND="none"

declare -gA CTX=(
    [mode]="1"
    [domain]=""
    [public_sni]="www.apple.com"
    [dns_api]=""
    [cf_token]=""
    [cf_zone_id]=""
    [namesilo_key]=""
    [cert_mode]="--server letsencrypt"
    [port]="443"
    [hy2_pass]=""
    [ipv4]=""
    [ipv6]=""
    [uuid]=""
    [pub_key]=""
    [priv_key]=""
    [short_id]=""
    [arch]=""
)

CLEANUP_LIST=()

log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; safe_terminate 1; }

cleanup_resources() {
    rm -f "$LOCK_FILE" 2>/dev/null
    flock -u 9 2>/dev/null
    exec 9>&- 2>/dev/null
    [[ ${#CLEANUP_LIST[@]} -gt 0 ]] && rm -rf "${CLEANUP_LIST[@]}" 2>/dev/null
}

safe_terminate() {
    local code=${1:-0}
    cleanup_resources
    trap - EXIT SIGHUP SIGINT SIGTERM 2>/dev/null
    [[ "${BASH_SOURCE[0]}" != "${0}" ]] && return "$code" 2>/dev/null || exit "$code"
}

# 进程并发互斥锁（采用追加模式与绝对互斥判定，杜绝截断穿透）
exec 9>>"$LOCK_FILE"
if ! flock -n 9; then
    ACTIVE_PID=$(cat "$LOCK_FILE" 2>/dev/null)
    echo -e "${C_RED}[ERROR] 检测到已有安装程序正在运行 (PID: ${ACTIVE_PID:-未知})，请勿重复执行。${C_RESET}"
    safe_terminate 1
fi
echo $$ > "$LOCK_FILE"

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'cleanup_resources' EXIT
    trap 'cleanup_resources; echo -e "\n${C_YELLOW}用户已手动中断。${C_RESET}"; exit 130' INT
    trap 'cleanup_resources; exit 143' TERM
fi

fetch_asset() {
    local url="$1"
    local dest="$2"
    local timeout="${3:-120}"
    curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m "$timeout" -o "$dest" "$url"
}

get_domain_info() {
    local domain=$1
    local dot_count
    dot_count=$(echo "$domain" | tr -cd '.' | wc -c)
    if [[ "$domain" == www.* ]]; then
        local root_d="${domain#www.}"
        if getent ahostsv4 "$root_d" >/dev/null 2>&1 || getent ahostsv6 "$root_d" >/dev/null 2>&1; then
            echo "$root_d $domain" && return
        fi
    elif [[ "$dot_count" -eq 1 ]]; then
        local www_d="www.$domain"
        if getent ahostsv4 "$www_d" >/dev/null 2>&1 || getent ahostsv6 "$www_d" >/dev/null 2>&1; then
            echo "$domain $www_d" && return
        fi
    fi
    echo "$domain"
}

# ------------------------------------------------------------------------------
# LAYER 2: 基础设施策略 (Infrastructure Strategy)
# ------------------------------------------------------------------------------
unit_purge() {
    local units=("$@")
    [[ ${#units[@]} -eq 0 ]] && return 0
    systemctl stop "${units[@]}" >/dev/null 2>&1 || true
    systemctl disable "${units[@]}" >/dev/null 2>&1 || true
    for u in "${units[@]}"; do
        rm -f "/etc/systemd/system/$u" "/lib/systemd/system/$u"
        systemctl reset-failed "$u" >/dev/null 2>&1 || true
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
}

sys_setup_journald() {
    log_info "正在配置系统环境和日志策略..."
    mkdir -p /etc/systemd/journald.conf.d/
    cat > /etc/systemd/journald.conf.d/99-prophet.conf <<'EOF'
[Journal]
SystemMaxUse=100M
MaxRetentionSec=7day
ForwardToSyslog=no
EOF
    systemctl restart systemd-journald || true
}

sys_setup_bbr() {
    log_info "正在检查网络加速 (BBR) 状态..."
    local bbr_conf_file="/etc/sysctl.conf"
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        local major_version="${VERSION_ID%%.*}"
        if [[ "$ID" == "debian" && "$major_version" =~ ^[0-9]+$ && "$major_version" -ge 13 ]]; then
            bbr_conf_file="/etc/sysctl.d/99-custom.conf"
            mkdir -p /etc/sysctl.d
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
        fi
        log_info "当前系统信息: ${PRETTY_NAME:-Linux} | 目标配置路径: $bbr_conf_file"
    fi

    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        sed -i '/net.core.default_qdisc/d' "$bbr_conf_file" 2>/dev/null || true
        sed -i '/net.ipv4.tcp_congestion_control/d' "$bbr_conf_file" 2>/dev/null || true
        echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr" >> "$bbr_conf_file"
        [[ "$bbr_conf_file" == "/etc/sysctl.conf" ]] && sysctl -p >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1
        log_ok "BBR 网络加速已成功开启。"
    else
        log_ok "网络加速 (BBR) 已处于开启状态，跳过配置。"
    fi
}

sys_clean_apt_cache() {
    log_info "正在清理安装过程中产生的系统垃圾..."
    apt-get autoremove -yqq >/dev/null 2>&1
    apt-get clean -yqq >/dev/null 2>&1
    log_ok "系统垃圾清理完毕。"
}

# ------------------------------------------------------------------------------
# LAYER 3: 业务组件驱动 (Component Lifecycle Drivers)
# ------------------------------------------------------------------------------

# --- [Driver: ACME 证书管理] ---
driver_cert_install() {
    local domain="${CTX[domain]}"
    local api="${CTX[dns_api]}"
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local domains
    domains=$(get_domain_info "$domain")
    local primary_domain
    primary_domain=$(echo "$domains" | awk '{print $1}')
    local acme_args=""
    for d in $domains; do
        acme_args="$acme_args -d $d"
    done

    if [[ -s "$cert_file" ]]; then
        log_info "检测到服务器已存在有效证书，跳过申请步骤直接复用。"
        return 0
    fi

    log_info "正在向 Let's Encrypt 申请 TLS 证书 ($domain)..."
    local tmp_acme="/tmp/acme_$(date +%s)"
    CLEANUP_LIST+=("$tmp_acme")
    mkdir -p "$tmp_acme" && cd "$tmp_acme" || log_err "创建临时工作目录失败。"

    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 60 https://get.acme.sh | sh -s email="admin@${domain}" --nocron && [[ -s "$ACME_BIN" ]]; then
        log_ok "证书申请工具 (ACME) 安装成功。"
        "$ACME_BIN" --upgrade --auto-upgrade "$AUTO_UPGRADE" >/dev/null 2>&1
    else
        log_err "证书申请工具安装失败，请检查网络连接。"
    fi

    if [[ "$api" == "webroot" ]]; then
        local acme_temp_conf="/etc/nginx/sites-enabled/acme_temp"
        CLEANUP_LIST+=("$acme_temp_conf")
        rm -f /etc/nginx/sites-enabled/default
        cat > "$acme_temp_conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domains;
    location / { root /var/www/html; }
}
EOF
        systemctl restart nginx >/dev/null 2>&1 || systemctl start nginx >/dev/null 2>&1
        "$ACME_BIN" --issue $acme_args --webroot /var/www/html --keylength ec-256 ${CTX[cert_mode]}
        rm -f "$acme_temp_conf"
    else
        "$ACME_BIN" --issue --dns "$api" $acme_args --keylength ec-256 ${CTX[cert_mode]}
    fi

    mkdir -p /etc/nginx/ssl
    "$ACME_BIN" --install-cert -d "$primary_domain" --ecc \
        --key-file "/etc/nginx/ssl/${domain}_ecc.key" \
        --fullchain-file "$cert_file" \
        --reloadcmd "systemctl reload nginx || true"

    cd "$HOME" || true

    if [[ -s "$cert_file" ]]; then
        log_ok "TLS 证书申请成功并部署到 Nginx。"
        local acme_conf="/root/.acme.sh/account.conf"
        if [[ -f "$acme_conf" ]]; then
            grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
            grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
            grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
        fi
    else
        log_err "证书申请失败，请检查域名解析与服务商密钥。"
    fi
}

driver_cert_setup_timer() {
    cat > /etc/systemd/system/xray-acme.service <<EOF
[Unit]
Description=Acme.sh Certificate Renewal Daemon

[Service]
Type=oneshot
User=root
ExecStart=$ACME_BIN --cron --home /root/.acme.sh
LimitNOFILE=1048576
EOF

    cat > /etc/systemd/system/xray-acme.timer <<EOF
[Unit]
Description=Timer for Acme.sh Renewal (SGT)

[Timer]
OnCalendar=*-*-* 02:00:00 Asia/Singapore
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now xray-acme.timer >/dev/null 2>&1
}

driver_cert_purge() {
    log_info "正在彻底清理证书资产与自动续签任务..."
    unit_purge "xray-acme.timer" "xray-acme.service"
    rm -rf /root/.acme.sh /etc/nginx/ssl 2>/dev/null || true
    crontab -l 2>/dev/null | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
    sed -i '/\.acme\.sh/d' /root/.bashrc 2>/dev/null || true
    sed -i '/acme\.sh/d' /root/.bashrc 2>/dev/null || true
    log_ok "证书组件与续签任务清理完成。"
}

# --- [Driver: Nginx 伪装网关] ---
driver_nginx_install() {
    local domain="${CTX[domain]}"
    local domains
    domains=$(get_domain_info "$domain")

    if [[ ! -s "/etc/nginx/ssl/${domain}_ecc.cer" || ! -s "/etc/nginx/ssl/${domain}_ecc.key" ]]; then
        log_err "Nginx 关联的证书文件不存在 (/etc/nginx/ssl/${domain}_ecc.cer)，请检查证书申请步骤。"
    fi

    log_info "正在配置 Nginx 主程序..."
    cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log notice;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    access_log off;
    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    rm -f /etc/nginx/sites-enabled/default

    log_info "正在配置 Nginx 伪装网站和安全策略..."
    log_info "正在通过语法探针检测 Nginx 核心特性支持..."
    local has_reject=0
    local probe_conf="/tmp/ngx_probe.conf"
    cat > "$probe_conf" <<'EOF'
events {}
http { server { listen 127.0.0.1:8443 ssl; ssl_reject_handshake on; } }
EOF
    if nginx -t -c "$probe_conf" >/dev/null 2>&1; then
        has_reject=1
        log_ok "安全特性支持: [ssl_reject_handshake] 校验通过，已启用阻断。"
    else
        log_warn "当前 Nginx 版本较低，不支持 [ssl_reject_handshake] 特性。"
    fi

    local has_http2=0
    cat > "$probe_conf" <<'EOF'
events {}
http { server { http2 on; } }
EOF
    if nginx -t -c "$probe_conf" >/dev/null 2>&1; then
        has_http2=1
        log_ok "HTTP/2 特性模式: 采用现代独立 [http2 on] 语法 (server 作用域校验通过)。"
    else
        log_info "HTTP/2 特性模式: 降级采用兼容模式 [listen ... http2]。"
    fi
    rm -f "$probe_conf"

    local tmp_conf="/tmp/xray_nginx.conf"
    rm -f "$tmp_conf"

    if [[ $has_reject -eq 1 ]]; then
        cat >> "$tmp_conf" <<EOF
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOF
    fi

    local listen_directive
    if [[ $has_http2 -eq 1 ]]; then
        listen_directive="listen 127.0.0.1:8443 ssl;\n    http2 on;"
    else
        listen_directive="listen 127.0.0.1:8443 ssl http2;"
    fi

    cat >> "$tmp_conf" <<EOF
server {
    $(echo -e "$listen_directive")
    ssl_certificate /etc/nginx/ssl/${domain}_ecc.cer;
    ssl_certificate_key /etc/nginx/ssl/${domain}_ecc.key;
    server_name $domains;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header X-Frame-Options SAMEORIGIN always;

    location / {
        root /var/www/html;
        index index.html;
        try_files \$uri \$uri/ =404;
    }
}
EOF

    if [[ "${CTX[dns_api]}" == "webroot" ]]; then
        cat >> "$tmp_conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domains;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
    else
        cat >> "$tmp_conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domains;
    return 301 https://\$host\$request_uri;
}
EOF
    fi

    if [[ "${CTX[mode]}" == "3" ]]; then
        cat >> "$tmp_conf" <<EOF
server {
    listen 127.0.0.1:8444 default_server;
    server_name $domains;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header X-Frame-Options SAMEORIGIN always;

    location / {
        root /var/www/html;
        index index.html;
        try_files \$uri \$uri/ =404;
    }
}
EOF
    fi

    mv -f "$tmp_conf" /etc/nginx/sites-available/xray
    ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/

    local test_err
    if ! test_err=$(nginx -t 2>&1); then
        echo -e "${C_RED}=================== NGINX 语法校验错误详情 ===================${C_RESET}"
        echo -e "${test_err}"
        echo -e "${C_RED}==============================================================${C_RESET}"
        cat -n /etc/nginx/sites-available/xray
        rm -f /etc/nginx/sites-enabled/xray
        log_err "Nginx 配置文件校验失败，错误原因已详细打印在上方。"
    fi

    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    local zip_file="/tmp/web_template.zip"
    CLEANUP_LIST+=("$temp_extract" "$zip_file")
    mkdir -p "$target_dir"
    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* 2>/dev/null

    log_info "正在下载伪装网页文件..."
    echo -e "${C_BLUE}--- 解压伪装网页 ---${C_RESET}"
    if fetch_asset "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main" "$zip_file" 120 && [[ -s "$zip_file" ]]; then
        mkdir -p "$temp_extract"
        if unzip -qo "$zip_file" -d "$temp_extract"; then
            local inner_dir
            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
            [[ -n "$inner_dir" ]] && cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null
            log_ok "伪装网页部署成功。"
            echo "--------------------"
        fi
        rm -rf "$temp_extract" "$zip_file" 2>/dev/null || true
    fi

    if [[ ! -s "$target_dir/index.html" ]]; then
        cat > "$target_dir/index.html" <<'EOF'
<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>
EOF
    fi

    chmod -R 755 "$target_dir"
    chown -R www-data:www-data "$target_dir" 2>/dev/null || true

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx 服务重载失败。"
    log_ok "Nginx 服务启动成功。"
}

driver_nginx_clean_site() {
    log_info "正在清理 Nginx 业务站点与伪装网页..."
    systemctl stop nginx >/dev/null 2>&1 || true
    systemctl disable nginx >/dev/null 2>&1 || true
    rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray /etc/nginx/sites-enabled/acme_temp
    rm -rf /var/www/html/* /var/www/html/.[!.]* 2>/dev/null || true
    log_ok "Nginx 业务配置与站点文件已清理。"
}

driver_nginx_purge_package() {
    log_info "正在物理清退 Nginx、系统包依赖与历史日志..."
    driver_nginx_clean_site
    if command -v nginx >/dev/null 2>&1 || [[ -f /lib/systemd/system/nginx.service ]]; then
        apt-get purge -yqq nginx nginx-common socat >/dev/null 2>&1 || true
        apt-get autoremove -yqq >/dev/null 2>&1
    fi
    rm -rf /etc/nginx /var/www /var/log/nginx 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    log_ok "Nginx 软件包与系统配置已连根拔除。"
}

# --- [Driver: Xray Core 代理引擎] ---
driver_xray_install() {
    log_info "正在识别系统架构并下载 Xray 核心文件..."
    local arch_xray="64"
    [[ "${CTX[arch]}" == "arm64" ]] && arch_xray="arm64-v8a"

    local tmp_xray="/tmp/xray_build_$(date +%s)"
    CLEANUP_LIST+=("$tmp_xray")
    mkdir -p "$tmp_xray" && cd "$tmp_xray"

    local zip_name="Xray-linux-${arch_xray}.zip"
    echo -e "${C_BLUE}--- 下载 Xray 核心 ---${C_RESET}"
    fetch_asset "https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}" "$zip_name" 120 || log_err "Xray 核心下载失败。"
    unzip -qo "$zip_name" || log_err "Xray 核心解压失败。"
    log_ok "Xray 核心文件下载成功。"
    echo "----------------------"

    mv -f xray "$XRAY_BIN" && chmod +x "$XRAY_BIN"
    mkdir -p "$XRAY_SHARE_DIR" "$XRAY_CONF_DIR"
    mv -f geoip.dat geosite.dat "$XRAY_SHARE_DIR/" 2>/dev/null || true

    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Environment="XRAY_LOCATION_ASSET=$XRAY_SHARE_DIR"
ExecStart=$XRAY_BIN run -config $XRAY_CONFIG
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/xray.service
    systemctl daemon-reload
    cd "$HOME" && rm -rf "$tmp_xray"
    log_ok "Xray 系统服务配置完成。"
}

driver_xray_configure() {
    local domain="${CTX[domain]}"
    log_info "正在生成 Xray 配置文件和加密密钥..."

    if [[ -f "$XRAY_CONFIG" ]]; then
        CTX[uuid]=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        CTX[priv_key]=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        CTX[short_id]=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
    fi

    [[ -z "${CTX[uuid]}" || "${CTX[uuid]}" == "null" ]] && CTX[uuid]=$($XRAY_BIN uuid)
    [[ -z "${CTX[short_id]}" || "${CTX[short_id]}" == "null" ]] && CTX[short_id]=$(openssl rand -hex 8)

    if [[ -n "${CTX[priv_key]}" && "${CTX[priv_key]}" != "null" ]]; then
        CTX[pub_key]=$($XRAY_BIN x25519 -i "${CTX[priv_key]}" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
    fi

    if [[ -z "${CTX[priv_key]}" || "${CTX[priv_key]}" == "null" || -z "${CTX[pub_key]}" || "${CTX[pub_key]}" == "null" ]]; then
        local key_re="$($XRAY_BIN x25519 | tr -d '\r')"
        mapfile -t KEYS < <(echo "$key_re" | grep -iE "Private|Public|Password" | grep -oE '[A-Za-z0-9_-]{43}')
        CTX[priv_key]=""
        CTX[pub_key]=""
        for p_priv in "${KEYS[@]}"; do
            local calc_pub
            calc_pub=$($XRAY_BIN x25519 -i "$p_priv" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
            for p_pub in "${KEYS[@]}"; do
                if [[ "$calc_pub" == "$p_pub" && "$p_priv" != "$p_pub" ]]; then
                    CTX[priv_key]="$p_priv"
                    CTX[pub_key]="$p_pub"
                    break 2
                fi
            done
        done
    fi
    log_ok "安全加密密钥生成成功。"

    local dest_addr="127.0.0.1:8443"
    local server_names_json
    if [[ "${CTX[mode]}" == "2" ]]; then
        dest_addr="${CTX[public_sni]}:443"
        server_names_json="[\"${CTX[public_sni]}\"]"
    else
        local domains
        domains=$(get_domain_info "$domain")
        server_names_json=$(echo "$domains" | sed 's/ /", "/g; s/^/["/; s/$/"]/')
    fi

    local port="${CTX[port]}"
    local uuid="${CTX[uuid]}"
    local priv="${CTX[priv_key]}"
    local sid="${CTX[short_id]}"

    cat > "$XRAY_CONFIG" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "queryStrategy": "UseIP",
    "disableFallback": false,
    "hosts": {
      "dns.cloudflare.com": [
        "1.1.1.1",
        "1.0.0.1"
      ],
      "dns.google": [
        "8.8.8.8",
        "8.8.4.4"
      ]
    },
    "servers": [
      "https://dns.cloudflare.com/dns-query",
      "https://dns.google/dns-query"
    ]
  },
  "inbounds": [
    {
      "listen": "::",
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$dest_addr",
          "xver": 0,
          "serverNames": $server_names_json,
          "privateKey": "$priv",
          "shortIds": [
            "$sid"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {
        "domainStrategy": "UseIP"
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" },
      { "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" },
      { "type": "field", "domain": ["geosite:geolocation-cn"], "outboundTag": "block" },
      { "type": "field", "ip": ["geoip:cn"], "outboundTag": "block" }
    ]
  }
}
EOF
    chmod 700 "$XRAY_CONF_DIR"
    chmod 600 "$XRAY_CONFIG"

    local test_res
    if ! test_res=$("$XRAY_BIN" run -test -config "$XRAY_CONFIG" 2>&1); then
        echo -e "${C_RED}=================== XRAY 配置语法测试报错 ===================${C_RESET}"
        echo -e "${test_res}"
        echo -e "${C_RED}============================================================${C_RESET}"
        log_err "Xray 配置文件验证失败，错误详情已打印在上方。"
    fi

    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray || log_err "Xray 服务启动失败，请使用 journalctl -u xray -e 查看底层日志。"
    log_ok "Xray 路由规则配置成功。"
}

driver_xray_purge() {
    unit_purge "xray.service"
    rm -f "$XRAY_BIN"
    rm -rf "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR"
}

# --- [Driver: Hysteria 2 协议栈] ---
driver_hysteria_install() {
    local domain="${CTX[domain]}"
    log_info "正在配置 Hysteria2 服务组件..."
    local tmp_hy2="/tmp/hy2_$(date +%s)"
    CLEANUP_LIST+=("$tmp_hy2")
    mkdir -p "$tmp_hy2"

    fetch_asset "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${CTX[arch]}" "$tmp_hy2/hysteria" 120 || log_err "Hysteria2 核心下载失败。"
    chmod +x "$tmp_hy2/hysteria"
    mv -f "$tmp_hy2/hysteria" "$HY2_BIN"

    mkdir -p "$HY2_CONF_DIR"
    CTX[hy2_pass]=$(openssl rand -hex 16)

    cat > "$HY2_CONFIG" <<EOF
listen: ":${CTX[port]}"
tls:
  cert: /etc/nginx/ssl/${domain}_ecc.cer
  key:  /etc/nginx/ssl/${domain}_ecc.key
auth:
  type: password
  password: ${CTX[hy2_pass]}
masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:8444
    rewriteHost: true
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  ignorePacketLoss: false
bandwidth:
  up: 300 mbps
  down: 300 mbps
EOF
    chmod 700 "$HY2_CONF_DIR"
    chmod 600 "$HY2_CONFIG"

    cat > /etc/systemd/system/hysteria-cert-watcher.path <<EOF
[Unit]
Description=Watch TLS certificate changes for Hysteria2

[Path]
PathChanged=/etc/nginx/ssl/${domain}_ecc.cer
PathChanged=/etc/nginx/ssl/${domain}_ecc.key

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p "$SCRIPT_DIR"
    cat > "$SCRIPT_DIR/hysteria-cert-restart.sh" <<EOF
#!/bin/bash
cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
key_file="/etc/nginx/ssl/${domain}_ecc.key"
exec 9>/run/hysteria-cert.lock
flock -n 9 || exit 0
valid=0
for i in \$(seq 1 10); do
    if [[ -s "\$cert_file" && -s "\$key_file" ]] && openssl x509 -in "\$cert_file" -noout >/dev/null 2>&1; then
        valid=1
        break
    fi
    sleep 1
done
if [[ \$valid -eq 1 ]]; then
    systemctl is-active --quiet nginx && systemctl reload nginx || systemctl start nginx
    systemctl restart hysteria-server
fi
EOF
    chmod 755 "$SCRIPT_DIR/hysteria-cert-restart.sh"

    cat > /etc/systemd/system/hysteria-cert-watcher.service <<EOF
[Unit]
Description=Reload Nginx and Restart Hysteria2 on certificate change
ConditionPathExists=$HY2_CONFIG
ConditionPathExists=/etc/nginx/ssl/${domain}_ecc.cer
ConditionPathExists=/etc/nginx/ssl/${domain}_ecc.key

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/hysteria-cert-restart.sh
EOF

    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server Service
After=network.target
ConditionPathExists=$HY2_CONFIG
ConditionPathExists=/etc/nginx/ssl/${domain}_ecc.cer
ConditionPathExists=/etc/nginx/ssl/${domain}_ecc.key

[Service]
Type=simple
ExecStart=$HY2_BIN server -c $HY2_CONFIG
Environment=HYSTERIA_LOG_LEVEL=warn
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now hysteria-cert-watcher.path >/dev/null 2>&1
    systemctl enable --now hysteria-server >/dev/null 2>&1 || log_err "Hysteria2 启动失败，请检查端口占用。"
    log_ok "Hysteria2 服务部署成功。"
}

driver_hysteria_purge() {
    unit_purge "hysteria-server.service" "hysteria-cert-watcher.path" "hysteria-cert-watcher.service"
    rm -f "$HY2_BIN" "$SCRIPT_DIR/hysteria-cert-restart.sh" /run/hysteria-cert.lock
    rm -rf "$HY2_CONF_DIR" /tmp/hy2_* 2>/dev/null || true
}

# --- [Driver: 路由分流规则自动化更新] ---
driver_rules_dat_setup() {
    log_info "正在配置自动更新任务..."
    mkdir -p "$SCRIPT_DIR"
    cat > "$SCRIPT_DIR/update-dat.sh" <<'EOF'
#!/bin/bash
exec 9> /var/lock/xray-dat.lock
flock -n 9 || exit 0
SHARE_DIR="/usr/local/share/xray"
changed=0

update_file() {
    local f=$1; local u=$2
    local target_tmp="$SHARE_DIR/${f}.new"
    if curl -fL --max-time 300 --connect-timeout 60 --retry 5 --retry-delay 3 --retry-connrefused -o "$target_tmp" "$u" && [[ -s "$target_tmp" ]]; then
        local f_size
        f_size=$(stat -c%s "$target_tmp" 2>/dev/null || wc -c < "$target_tmp" 2>/dev/null | tr -d ' ' || echo 0)
        if [[ "$f_size" -ge 512000 ]] && ! cmp -s "$target_tmp" "$SHARE_DIR/$f"; then
            mv -f "$target_tmp" "$SHARE_DIR/$f"
            changed=1
            return 0
        fi
    fi
    rm -f "$target_tmp"
    return 1
}

update_file "geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
update_file "geosite.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

[[ $changed -eq 1 ]] && systemctl restart xray >/dev/null 2>&1 || true
EOF
    chmod 755 "$SCRIPT_DIR/update-dat.sh"

    echo -e "${C_BLUE}--- 路由分流资源热同步 ---${C_RESET}"
    bash "$SCRIPT_DIR/update-dat.sh" || true
    echo "--------------------------"

    cat > /etc/systemd/system/xray-dat.service <<EOF
[Unit]
Description=Xray Dat Database Updater

[Service]
Type=oneshot
User=root
ExecStart=$SCRIPT_DIR/update-dat.sh
LimitNOFILE=1048576
EOF

    cat > /etc/systemd/system/xray-dat.timer <<EOF
[Unit]
Description=Timer for Xray Dat Update (SGT)

[Timer]
OnCalendar=Mon *-*-* 03:00:00 Asia/Singapore
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-dat.timer >/dev/null 2>&1
    log_ok "自动更新任务配置完成。"
}

driver_rules_dat_purge() {
    unit_purge "xray-dat.timer" "xray-dat.service"
    rm -f "$SCRIPT_DIR/update-dat.sh" /var/lock/xray-dat.lock
}

# ------------------------------------------------------------------------------
# LAYER 4: 业务交互与流程编排 (Workflow Orchestration & Prompts)
# ------------------------------------------------------------------------------
workflow_fetch_host_ips() {
    CTX[ipv4]=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me || true)
    CTX[ipv6]=$(curl -s6m 5 icanhazip.com || curl -s6m 5 ifconfig.me || true)
}

workflow_select_port() {
    while true; do
        read -rp "请设置 Xray 监听端口 (范围 1-65535) [默认 443]: " PORT_INPUT
        CTX[port]=${PORT_INPUT:-443}
        if ! [[ "${CTX[port]}" =~ ^[0-9]+$ ]] || [[ "${CTX[port]}" -lt 1 ]] || [[ "${CTX[port]}" -gt 65535 ]]; then
            log_warn "输入的端口无效，请输入 1-65535 之间的数字。"
            continue
        fi

        if [[ "${CTX[mode]}" =~ ^[13]$ ]] && [[ "${CTX[port]}" =~ ^(80|8443|8444)$ ]]; then
            log_warn "端口冲突：当前模式下，端口 80/8443/8444 已被本地 Web/伪装回落服务占用，请换一个端口。"
            continue
        fi

        if ss -tln | grep -qE ":${CTX[port]}\b"; then
            log_warn "端口占用：端口 ${CTX[port]} (TCP) 已被其他程序占用，请重新分配。"
            continue
        fi

        if [[ "${CTX[mode]}" == "3" ]] && ss -uln | grep -qE ":${CTX[port]}\b"; then
            log_warn "端口占用：端口 ${CTX[port]} (UDP) 已被占用。Hysteria2 需要 UDP 支持，请重新分配。"
            continue
        fi

        log_ok "端口 ${CTX[port]} 可以使用。\n"
        break
    done
}

workflow_get_inputs() {
    echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 1/3] 选择部署模式 ---${C_RESET}"
    echo -e "  1. Web 回落模式 (推荐) - 自动申请证书 + 搭建本地伪装网站，极其稳定安全。"
    echo -e "  2. 纯净直连模式        - 借用大厂域名 (如 Apple) 伪装，不需要自己的域名，简单轻量。"
    echo -e "  3. 全能共存模式        - 融合 Web 回落架构，并同步拉起 Hysteria2 协议栈 (端口复用)。"
    read -rp "请选择 [1/2/3, 默认 1]: " MODE_INPUT
    CTX[mode]=${MODE_INPUT:-1}

    workflow_fetch_host_ips

    if [[ "${CTX[mode]}" =~ ^[13]$ ]]; then
        read -rp "请输入已解析到本服务器的域名 (例如 my.domain.com): " DOMAIN_INPUT
        CTX[domain]=$(echo "$DOMAIN_INPUT" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        [[ -z "${CTX[domain]}" ]] && log_err "域名不能为空或格式错误。"

        echo -e "\n${C_BLUE}正在测试域名解析状态 (双栈智能检测)...${C_RESET}"
        local domain_ipv4="" domain_ipv6=""
        if command -v jq >/dev/null 2>&1; then
            domain_ipv4=$(curl -sm 5 -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=${CTX[domain]}&type=A" 2>/dev/null | jq -r '.Answer[]? | select(.type == 1) | .data' 2>/dev/null | head -n1)
            domain_ipv6=$(curl -sm 5 -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=${CTX[domain]}&type=AAAA" 2>/dev/null | jq -r '.Answer[]? | select(.type == 28) | .data' 2>/dev/null | head -n1)
        fi
        [[ -z "$domain_ipv4" ]] && domain_ipv4=$(getent ahostsv4 "${CTX[domain]}" 2>/dev/null | awk '{print $1}' | head -n1)
        [[ -z "$domain_ipv6" ]] && domain_ipv6=$(getent ahostsv6 "${CTX[domain]}" 2>/dev/null | awk '{print $1}' | grep -v '^::ffff:' | head -n1)

        echo -e "  本机 IPv4 : ${C_YELLOW}${CTX[ipv4]:-"无或超时"}${C_RESET} | 解析 IPv4 : ${C_YELLOW}${domain_ipv4:-"未生效"}${C_RESET}"
        echo -e "  本机 IPv6 : ${C_YELLOW}${CTX[ipv6]:-"无或超时"}${C_RESET} | 解析 IPv6 : ${C_YELLOW}${domain_ipv6:-"未生效"}${C_RESET}"

        if [[ (-n "${CTX[ipv4]}" && "${CTX[ipv4]}" == "$domain_ipv4") || (-n "${CTX[ipv6]}" && "${CTX[ipv6]}" == "$domain_ipv6") ]]; then
            echo -e "${C_GREEN}  [OK] IP 匹配成功，域名解析已生效。${C_RESET}\n"
        else
            echo -e "${C_RED}  [WARN] 警告：解析 IP 与本机 IP 不匹配 (可能开了 CDN 或尚未生效)。${C_RESET}\n"
        fi

        workflow_select_port

        echo -e "${C_BOLD}${C_BLUE}--- [步骤 2/3] 选择证书验证方式 ---${C_RESET}"
        echo -e "  1. DNS API 验证机制 (推荐) - 静默验证，支持泛域名，无惧端口被封。"
        echo -e "  2. HTTP Webroot 机制       - 依赖 Nginx 80 端口无感验证。"
        read -rp "请选择 [1/2, 默认 1]: " VERIFY_TYPE
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            CTX[dns_api]="webroot"
        else
            echo -e "\n  1. Cloudflare\n  2. Namesilo"
            read -rp "请选择你的域名服务商 [1/2]: " DNS_TYPE
            if [[ "$DNS_TYPE" == "1" ]]; then
                CTX[dns_api]="dns_cf"
                read -rp "输入 Cloudflare API Token: " CTX[cf_token]
                read -rp "输入 Cloudflare Zone ID: " CTX[cf_zone_id]
                export CF_Token=${CTX[cf_token]}
                export CF_Zone_ID=${CTX[cf_zone_id]}
            else
                CTX[dns_api]="dns_namesilo"
                read -rp "输入 Namesilo API Key: " CTX[namesilo_key]
                export Namesilo_Key=${CTX[namesilo_key]}
            fi
        fi

        echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 3/3] 选择证书申请环境 ---${C_RESET}"
        echo -e "  1. Production (生产环境) - 颁发正规信任证书 (有频次限制)。"
        echo -e "  2. Staging    (测试环境) - 无次数限制，专用于调试排错。"
        read -rp "请选择 [1/2, 默认 1]: " CERT_MODE_INPUT
        if [[ "$CERT_MODE_INPUT" == "2" ]]; then
            CTX[cert_mode]="--staging"
            log_warn "当前选择：Staging 测试环境。"
        else
            CTX[cert_mode]="--server letsencrypt"
            log_info "当前选择：Production 生产环境。"
        fi
    else
        echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 1/2] 设置伪装域名 (SNI) ---${C_RESET}"
        read -rp "请输入用于伪装的公共域名 [默认 www.apple.com]: " PUBLIC_SNI_INPUT
        local sni_val=${PUBLIC_SNI_INPUT:-"www.apple.com"}
        CTX[public_sni]=$(echo "$sni_val" | sed 's|^https\?://||; s|/$||' | tr -d '[:space:]')
        workflow_select_port
        echo -e "  本机 IPv4 : ${C_YELLOW}${CTX[ipv4]:-"无或超时"}${C_RESET}"
        echo -e "  本机 IPv6 : ${C_YELLOW}${CTX[ipv6]:-"无或超时"}${C_RESET}\n"
    fi
}

workflow_align_modes() {
    log_info "正在根据目标模式执行环境对齐与无关资产物理擦除..."
    [[ "${CTX[mode]}" != "3" ]] && driver_hysteria_purge >/dev/null 2>&1
    if [[ "${CTX[mode]}" == "2" ]]; then
        driver_cert_purge >/dev/null 2>&1
        driver_nginx_purge_package >/dev/null 2>&1
    fi
    log_ok "无关异构资产物理擦除完毕，环境已恢复初装基线。"
}

workflow_deploy() {
    cd "$HOME" || safe_terminate 1
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    dpkg --configure -a >/dev/null 2>&1 || true

    systemctl stop xray hysteria-server >/dev/null 2>&1 || true
    command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1 || true

    # 预检必要解析与网络工具，配合可视化输出消除盲等感
    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        log_info "正在初始化预检环境并同步基础软件源，请稍候..."
        apt-get update -yqq >/dev/null 2>&1
        apt-get install -yqq --no-install-recommends curl jq >/dev/null 2>&1
    fi

    local arch_raw
    arch_raw=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch_raw" in
        amd64|x86_64)  CTX[arch]="amd64" ;;
        arm64|aarch64) CTX[arch]="arm64" ;;
        *)             CTX[arch]="amd64" ;;
    esac

    workflow_get_inputs
    workflow_align_modes

    sys_setup_journald

    local install_pkgs="curl unzip openssl jq qrencode"
    [[ "${CTX[mode]}" =~ ^[13]$ ]] && install_pkgs="$install_pkgs nginx socat"

    log_info "正在安装模式所需的基础软件..."
    local apt_log="/tmp/apt_install_$$.log"
    CLEANUP_LIST+=("$apt_log")

    # 针对 Ubuntu 环境自动确保 universe 软件源处于激活状态（解决 qrencode / socat 依赖源缺失）
    if [[ -f /etc/os-release ]] && grep -qi "ubuntu" /etc/os-release; then
        local need_refresh=0
        if command -v add-apt-repository >/dev/null 2>&1; then
            if ! grep -qE "^deb .*universe" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
                add-apt-repository -y universe >/dev/null 2>&1
                need_refresh=1
            fi
        else
            if ! grep -qE "(universe|Components:.*universe)" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
                sed -i '/^deb .* main/ { /universe/! s/$/ universe/ }' /etc/apt/sources.list 2>/dev/null || true
                sed -i '/^Components:/ { /universe/! s/$/ universe/ }' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
                need_refresh=1
            fi
        fi
        [[ $need_refresh -eq 1 ]] && apt-get update -yqq >/dev/null 2>&1
    fi

    # 执行基础包安装，如果因源缓存或并发锁偶发未命中则自动拉取一次 update 静默重试
    if ! apt-get install -yqq --no-install-recommends \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        $install_pkgs > "$apt_log" 2>&1; then

        log_warn "基础包初次匹配未通过，正在同步软件源并重试..."
        apt-get update -yqq >/dev/null 2>&1
        apt-get install -yqq --no-install-recommends \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            $install_pkgs > "$apt_log" 2>&1
    fi

    local missing_pkgs=()
    for pkg in $install_pkgs; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1 || ! dpkg -s "$pkg" | grep -qw "Status: install ok installed"; then
            missing_pkgs+=("$pkg")
        fi
    done

    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        echo -e "${C_RED}=================== APT 安装底层报错详情 ===================${C_RESET}"
        grep -iE "E:|Err:|Error|dpkg:|failed" "$apt_log" 2>/dev/null || tail -n 15 "$apt_log"
        echo -e "${C_RED}============================================================${C_RESET}"
        rm -f "$apt_log"
        log_err "基础软件安装未通过！未就绪的依赖组件: [ ${missing_pkgs[*]} ]，请根据上方红框内的错误原因修复系统环境。"
    fi
    rm -f "$apt_log"

    log_ok "基础软件及目录准备完毕 (已就绪: $(echo $install_pkgs | tr ' ' ', '))。"
    mkdir -p "$SCRIPT_DIR"

    sys_setup_bbr

    if [[ "${CTX[mode]}" =~ ^[13]$ ]]; then
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
        driver_cert_install
        driver_nginx_install
        driver_cert_setup_timer
    fi

    driver_xray_install
    driver_xray_configure

    [[ "${CTX[mode]}" == "3" ]] && driver_hysteria_install

    driver_rules_dat_setup
    sys_clean_apt_cache
    workflow_show_result
}

workflow_show_result() {
    echo -e "\n${C_GREEN}------------------------------------------------------------------${C_RESET}"
    echo -e "${C_BOLD}${C_GREEN}[OK] Xray 部署全部完成！(DEPLOYMENT SUCCESS)${C_RESET}"
    echo -e "${C_GREEN}------------------------------------------------------------------${C_RESET}"

    local client_sni="${CTX[domain]}"
    [[ "${CTX[mode]}" == "2" ]] && client_sni="${CTX[public_sni]}"

    local query="?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${CTX[pub_key]}&sid=${CTX[short_id]}&type=tcp#Reality_${client_sni}"

    echo -e "${C_BOLD}[Xray Reality 节点参数]${C_RESET}"
    echo -e " 监听端口   : ${C_YELLOW}${CTX[port]} (TCP)${C_RESET}"
    echo -e " UUID 标识  : ${C_YELLOW}${CTX[uuid]}${C_RESET}"
    echo -e " Public Key : ${C_YELLOW}${CTX[pub_key]}${C_RESET}"
    echo -e " Short ID   : ${C_YELLOW}${CTX[short_id]}${C_RESET}"
    echo -e " 伪装 SNI   : ${C_BLUE}$client_sni${C_RESET}"
    echo -e "------------------------------------------------------------------"

    if [[ "${CTX[mode]}" =~ ^[13]$ ]]; then
        local vless_link="vless://${CTX[uuid]}@${CTX[domain]}:${CTX[port]}${query}"
        echo -e "${C_BOLD}客户端分享链接 (域名自适应版):${C_RESET}\n${C_GREEN}${vless_link}${C_RESET}\n"
        echo "$vless_link" | qrencode -t ansiutf8
    else
        echo -e "${C_BOLD}客户端分享链接 (双栈独立节点):${C_RESET}\n"
        local qr_target=""
        if [[ -n "${CTX[ipv4]}" ]]; then
            local v4_link="vless://${CTX[uuid]}@${CTX[ipv4]}:${CTX[port]}${query}"
            echo -e " [1] IPv4 节点:\n${C_GREEN}${v4_link}${C_RESET}\n"
            qr_target="$v4_link"
        fi
        if [[ -n "${CTX[ipv6]}" ]]; then
            local v6_link="vless://${CTX[uuid]}@[${CTX[ipv6]}]:${CTX[port]}${query}"
            echo -e " [2] IPv6 节点:\n${C_GREEN}${v6_link}${C_RESET}\n"
            [[ -z "$qr_target" ]] && qr_target="$v6_link"
        fi

        if [[ -z "${CTX[ipv4]}" && -z "${CTX[ipv6]}" ]]; then
            local fallback_link="vless://${CTX[uuid]}@你的VPS_IP:${CTX[port]}${query}"
            echo -e " [!] 默认节点 (获取公网IP超时，请手动替换为实际IP):\n${C_YELLOW}${fallback_link}${C_RESET}\n"
            qr_target="$fallback_link"
        fi

        [[ -n "$qr_target" ]] && echo "$qr_target" | qrencode -t ansiutf8
    fi

    if [[ "${CTX[mode]}" == "3" ]]; then
        local hy2_link="hy2://${CTX[hy2_pass]}@${CTX[domain]}:${CTX[port]}/?sni=${CTX[domain]}&alpn=h3&insecure=0#Hysteria2_${CTX[domain]}"
        echo -e "\n------------------------------------------------------------------"
        echo -e "${C_BOLD}[Hysteria2 节点参数]${C_RESET}"
        echo -e " 网络端口   : ${C_YELLOW}${CTX[port]} (UDP)${C_RESET}"
        echo -e " 认证密码   : ${C_YELLOW}${CTX[hy2_pass]}${C_RESET}"
        echo -e " 本地回落   : ${C_BLUE}Nginx (127.0.0.1:8444)${C_RESET}"
        echo -e "------------------------------------------------------------------"
        echo -e "${C_BOLD}客户端分享链接:${C_RESET}\n${C_GREEN}$hy2_link${C_RESET}\n"
    fi
}

workflow_uninstall() {
    echo -e "\n${C_BLUE}[INFO]${C_RESET} 正在回收核心业务与系统服务..."

    driver_xray_purge
    driver_hysteria_purge
    driver_rules_dat_purge
    driver_cert_purge
    driver_nginx_clean_site
    rm -rf "$SCRIPT_DIR"

    echo -e "\n${C_YELLOW}所有核心业务文件与节点配置已彻底回收。${C_RESET}"
    echo -e "${C_RED}[WARN] 是否连带卸载底层工具包 (Nginx, Socat, qrencode, jq, unzip)？${C_RESET}"
    read -rp "如果服务器还承载其他业务，请选 N！[y/N, 默认 N]: " PURGE_SYS
    case "${PURGE_SYS}" in
        [yY][eE][sS]|[yY])
            driver_nginx_purge_package
            local purge_list="socat qrencode jq unzip"
            apt-get purge -yqq $purge_list >/dev/null 2>&1
            sys_clean_apt_cache
            echo -e "${C_GREEN}[OK] 底层运行依赖包已彻底清除 (已保留 curl、BBR 与日志策略)。${C_RESET}"
            ;;
        *)
            echo -e "${C_GREEN}[OK] 已保留底层公共基础软件 (Nginx 服务已停止，未删除系统包)。${C_RESET}"
            ;;
    esac
    read -rp "按回车键返回主菜单..."
}

# ------------------------------------------------------------------------------
# LAYER 5: CLI 入口与调度菜单 (Main Menu & Entrypoint)
# ------------------------------------------------------------------------------
while true; do
    clear
    echo -e "${C_BLUE}"
    echo -e " ----------------------------------------------"
    echo -e "   REALITY AUTOMATION CLI ENGINE"
    echo -e "   Build: $SCRIPT_VERSION"
    echo -e " ----------------------------------------------${C_RESET}\n"

    echo -e "  1. ${C_GREEN}执行部署脚本${C_RESET}"
    echo -e "  2. ${C_YELLOW}卸载服务${C_RESET}"
    echo -e "  3. ${C_BLUE}查看定时任务+证书状态${C_RESET}"
    echo -e "  0. ${C_RED}退出脚本${C_RESET}\n"

    read -rp "请输入数字选择功能 [0-3]: " OPT
    case $OPT in
        1)
            workflow_deploy
            safe_terminate 0
            break
            ;;
        2)
            workflow_uninstall
            ;;
        3)
            echo -e "\n${C_BOLD}${C_BLUE}--- 自动任务运行状态 ---${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "当前没有运行中的定时任务"
            echo -e "\n${C_BOLD}${C_BLUE}--- 已安装证书详情列表 ---${C_RESET}"
            [[ -f "$ACME_BIN" ]] && "$ACME_BIN" --list --home "/root/.acme.sh" || echo "未检测到 acme.sh 证书环境。"
            read -rp "按回车键返回菜单..."
            ;;
        0)
            echo -e "\n已退出。"
            safe_terminate 0
            break
            ;;
        *)
            echo -e "\n${C_RED}[ERROR] 输入无效，请重新选择。${C_RESET}"
            sleep 1
            ;;
    esac
done
