#!/bin/bash
# ==============================================================================
# Xray Reality + Hysteria2 Automation Engine (Stability Edition V1 + Hy2)
# Architecture: VLESS + XTLS-Vision + Reality + Nginx Reverse Proxy + Hysteria2
# ==============================================================================

# 权限与运行环境预检
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ERROR] 权限不足：执行本脚本需要 Root 权限。\e[0m"
    echo -e "\e[33m请执行 'sudo -i' 或 'su -' 获取 Root 权限后重新运行。\e[0m"
    exit 1
fi

# ==============================================================================
# GROUP 1: 全局变量与环境声明 (Globals & Traps)
# ==============================================================================
readonly SCRIPT_VERSION="Pro Final V2 (Stability Edition + Hysteria2)"
readonly LOG_FILE="/dev/null"
readonly XRAY_CONF_DIR="/usr/local/etc/xray"
readonly XRAY_SHARE_DIR="/usr/local/share/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly XRAY_CONFIG="$XRAY_CONF_DIR/config.json"
readonly SCRIPT_DIR="/usr/local/etc/xray-script"

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

GLOBAL_INSTALL_MODE="1"
GLOBAL_DOMAIN=""
GLOBAL_PUBLIC_SNI=""
GLOBAL_DNS_API=""
GLOBAL_CF_TOKEN=""
GLOBAL_CF_ZONE_ID=""
GLOBAL_NAMESILO_KEY=""
GLOBAL_CERT_MODE=""
GLOBAL_PORT=""
HY2_PASSWORD=""

CLEANUP_LIST=()
trap '[[ ${#CLEANUP_LIST[@]} -gt 0 ]] && rm -rf "${CLEANUP_LIST[@]}" 2>/dev/null' EXIT SIGHUP SIGINT SIGTERM

# ==============================================================================
# GROUP 2: 日志与交互展示层 (Loggers & Interactive UI)
# ==============================================================================
log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

get_listen_port() {
    while true; do
        read -rp "请设置主监听端口 (范围 1-65535) [默认 443]: " PORT_INPUT
        GLOBAL_PORT=${PORT_INPUT:-443}
        if ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
            log_warn "输入的端口无效，请输入 1-65535 之间的数字。"
            continue
        fi
        
        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]] && { [ "$GLOBAL_PORT" -eq 80 ] || [ "$GLOBAL_PORT" -eq 8443 ] || [ "$GLOBAL_PORT" -eq 8444 ]; }; then
            log_warn "端口冲突：当前模式下，端口 80/8443/8444 已被本地 Nginx 分流占用，请换一个端口。"
            continue
        fi
        
        if ss -tuln 2>/dev/null | grep -qE ":${GLOBAL_PORT}\b"; then
            log_warn "端口占用：端口 $GLOBAL_PORT 已被其他程序占用，请重新分配。"
        else
            log_ok "端口 $GLOBAL_PORT 可以使用。\n"
            break
        fi
    done
}

module_get_inputs() {
    echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 1/3] 选择部署模式 ---${C_RESET}"
    echo -e "  1. Web 回落模式        - 自动申请证书 + 搭建本地伪装网站，极其稳定安全。"
    echo -e "  2. 纯净直连模式        - 借用大厂域名 (如 Apple) 伪装，不需要自己的域名，简单轻量。"
    echo -e "  3. 全能共存模式 (新增) - 具有模式1所有功能，同时安装配置 Hysteria2 (共用端口)。"
    read -rp "请选择 [1/2/3, 默认 1]: " MODE_INPUT
    GLOBAL_INSTALL_MODE=${MODE_INPUT:-1}

    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        read -rp "请输入已解析到本服务器的域名 (例如 my.domain.com): " GLOBAL_DOMAIN
        GLOBAL_DOMAIN=$(echo "$GLOBAL_DOMAIN" | sed 's/^www\.//g' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        
        [[ -z "$GLOBAL_DOMAIN" ]] && log_err "域名不能为空或格式错误。"
        
        echo -e "\n${C_BLUE}正在测试域名解析状态...${C_RESET}"
        local local_ip
        local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        
        local domain_ip=""
        local py_parser="
import sys, json
try:
    d = json.load(sys.stdin)
    for ans in d.get('Answer', []):
        if ans.get('type') == 1:
            print(ans.get('data', ''))
            break
except:
    pass
"
        if command -v python3 >/dev/null 2>&1; then
            domain_ip=$(curl -sm 5 -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=$GLOBAL_DOMAIN&type=A" 2>/dev/null | python3 -c "$py_parser")
            [[ -z "$domain_ip" ]] && domain_ip=$(curl -sm 5 -H "accept: application/dns-json" "https://dns.google/resolve?name=$GLOBAL_DOMAIN&type=A" 2>/dev/null | python3 -c "$py_parser")
        fi
        
        if [[ -z "$domain_ip" ]]; then
            domain_ip=$(getent ahostsv4 "$GLOBAL_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1)
        fi
        
        echo -e "  本机公网 IP : ${C_YELLOW}${local_ip:-"获取超时"}${C_RESET}"
        echo -e "  域名解析 IP : ${C_YELLOW}${domain_ip:-"解析失败"}${C_RESET}"
        
        if [[ -n "$local_ip" && "$local_ip" == "$domain_ip" ]]; then
            echo -e "${C_GREEN}  [OK] IP 匹配成功，域名解析已生效。${C_RESET}\n"
        else
            echo -e "${C_RED}  [WARN] 警告：域名的解析 IP 与本机 IP 不一致 (可能是开启了 CDN 或解析还没生效)。${C_RESET}\n"
        fi

        get_listen_port
        
        echo -e "${C_BOLD}${C_BLUE}--- [步骤 2/3] 选择证书验证方式 ---${C_RESET}"
        echo -e "  1. DNS API 验证机制 (推荐) - 后台静默验证，支持泛域名，无惧端口被封。"
        echo -e "  2. HTTP Standalone 机制    - 需要暂时占用本地 Web 端口进行验证。"
        read -rp "请选择 [1/2, 默认 1]: " VERIFY_TYPE
        
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            GLOBAL_DNS_API="standalone"
        else
            echo -e "\n  1. Cloudflare\n  2. Namesilo"
            read -rp "请选择你的域名服务商 [1/2]: " DNS_TYPE
            if [[ "$DNS_TYPE" == "1" ]]; then
                GLOBAL_DNS_API="dns_cf"
                read -rp "输入 Cloudflare API Token: " GLOBAL_CF_TOKEN
                read -rp "输入 Cloudflare Zone ID: " GLOBAL_CF_ZONE_ID
                export CF_Token=$GLOBAL_CF_TOKEN
                export CF_Zone_ID=$GLOBAL_CF_ZONE_ID
            else
                GLOBAL_DNS_API="dns_namesilo"
                read -rp "输入 Namesilo API Key: " GLOBAL_NAMESILO_KEY
                export Namesilo_Key=$GLOBAL_NAMESILO_KEY
            fi
        fi

        echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 3/3] 选择证书申请环境 ---${C_RESET}"
        echo -e "  1. Production (生产环境) - 颁发浏览器信任的正规证书 (注意有申请次数限制)。"
        echo -e "  2. Staging    (测试环境) - 无次数限制，专用于测试部署流程是否通畅。"
        read -rp "请选择 [1/2, 默认 1]: " CERT_MODE_INPUT
        if [[ "$CERT_MODE_INPUT" == "2" ]]; then
            GLOBAL_CERT_MODE="--staging"
            log_warn "当前已选择：Staging 测试环境。"
        else
            GLOBAL_CERT_MODE="--server letsencrypt"
            log_info "当前已选择：Production 生产环境。"
        fi

    else
        echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 1/2] 设置伪装域名 (SNI) ---${C_RESET}"
        echo -e "  建议选择当地连通率高且支持 TLS 1.3 的大型公共业务域名。"
        echo -e "  备选范例: www.apple.com / gateway.icloud.com / www.microsoft.com"
        read -rp "请输入用于伪装的公共域名 [默认 www.apple.com]: " PUBLIC_SNI_INPUT
        GLOBAL_PUBLIC_SNI=${PUBLIC_SNI_INPUT:-"www.apple.com"}
        GLOBAL_PUBLIC_SNI=$(echo "$GLOBAL_PUBLIC_SNI" | sed 's/^https:\/\///g' | sed 's/^http:\/\///g' | sed 's/\/$//g' | tr -d '[:space:]')
        get_listen_port
    fi
}

module_show_result() {
    clear
    echo -e "${C_GREEN}------------------------------------------------------------------${C_RESET}"
    echo -e "${C_BOLD}${C_GREEN}[OK] 部署全部完成！(DEPLOYMENT SUCCESS)${C_RESET}"
    echo -e "${C_GREEN}------------------------------------------------------------------${C_RESET}"
    
    local client_addr; local client_sni
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        client_addr="$GLOBAL_DOMAIN"; client_sni="$GLOBAL_DOMAIN"
    else
        local local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        client_addr="${local_ip:-"你的VPS_IP"}"; client_sni="$GLOBAL_PUBLIC_SNI"
    fi
    local vless_link="vless://${UUID}@${client_addr}:${GLOBAL_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${client_sni}"
    
    echo -e "${C_BOLD}[Xray Reality 信息]${C_RESET}"
    echo -e " 网络端点   : ${C_YELLOW}$GLOBAL_PORT (TCP)${C_RESET}"
    echo -e " UUID 标识  : ${C_YELLOW}$UUID${C_RESET}"
    echo -e " Public Key : ${C_YELLOW}$PUB${C_RESET}"
    echo -e " Short ID   : ${C_YELLOW}$SID${C_RESET}"
    echo -e " 路由 SNI   : ${C_BLUE}$client_sni${C_RESET}"
    echo -e "${C_BOLD}客户端分享链接 (URI Format):${C_RESET}\n${C_GREEN}$vless_link${C_RESET}\n"
    
    echo "$vless_link" | qrencode -t ansiutf8

    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        local hy2_link="hy2://${HY2_PASSWORD}@${GLOBAL_DOMAIN}:${GLOBAL_PORT}/?sni=${GLOBAL_DOMAIN}&alpn=h3&insecure=0#Hysteria2_${GLOBAL_DOMAIN}"
        echo -e "\n------------------------------------------------------------------"
        echo -e "${C_BOLD}[Hysteria2 信息]${C_RESET}"
        echo -e " 网络端点   : ${C_YELLOW}$GLOBAL_PORT (UDP)${C_RESET}"
        echo -e " 连接密码   : ${C_YELLOW}$HY2_PASSWORD${C_RESET}"
        echo -e " 伪装回落   : ${C_BLUE}Nginx (127.0.0.1:8444)${C_RESET}"
        echo -e "${C_BOLD}客户端分享链接 (URI Format):${C_RESET}\n${C_GREEN}$hy2_link${C_RESET}\n"
    fi
}

# ==============================================================================
# GROUP 3: 基础环境与网络优化 (System Pre-requisites & BBR)
# ==============================================================================
module_prepare_env() {
    log_info "正在配置系统环境和日志策略..."

    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nMaxRetentionSec=7day\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    log_info "正在更新软件源并检查进程锁..."
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    apt-get update -yqq >/dev/null 2>&1
    
    local common_deps="curl unzip openssl jq qrencode"
    local check_deps=("curl" "unzip" "openssl" "jq" "qrencode")

    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        log_info "正在安装所需的基础软件 (Nginx, Socat)..."
        apt-get install -yqq --no-install-recommends -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps nginx socat >/dev/null 2>&1
        check_deps+=("nginx" "socat")
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    else
        log_info "正在安装模式 2 所需的基础软件..."
        apt-get install -yqq --no-install-recommends -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps >/dev/null 2>&1
    fi
        
    for cmd in "${check_deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "组件 [$cmd] 安装失败，请检查网络或系统软件源。"
        fi
    done
    
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    log_ok "基础软件及目录准备完毕。"
}

module_setup_bbr() {
    log_info "正在检查网络加速 (BBR) 状态..."
    
    local bbr_conf_file="/etc/sysctl.conf"
    local os_info="未知系统"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os_info="${PRETTY_NAME:-"$ID $VERSION_ID"}"
        
        local major_version="${VERSION_ID%%.*}"
        if [[ "$ID" == "debian" ]] && [[ "$major_version" =~ ^[0-9]+$ ]] && [ "$major_version" -ge 13 ]; then
            bbr_conf_file="/etc/sysctl.d/99-custom.conf"
            mkdir -p /etc/sysctl.d
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
        fi
    fi

    log_info "当前系统信息: ${C_YELLOW}${os_info}${C_RESET} | 目标配置路径: ${C_YELLOW}${bbr_conf_file}${C_RESET}"

    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        sed -i '/net.core.default_qdisc/d' "$bbr_conf_file" 2>/dev/null || true
        sed -i '/net.ipv4.tcp_congestion_control/d' "$bbr_conf_file" 2>/dev/null || true
        echo "net.core.default_qdisc=fq" >> "$bbr_conf_file"
        echo "net.ipv4.tcp_congestion_control=bbr" >> "$bbr_conf_file"
        
        if [[ "$bbr_conf_file" == "/etc/sysctl.conf" ]]; then
            sysctl -p >/dev/null 2>&1
        else
            sysctl --system >/dev/null 2>&1
        fi
        log_ok "BBR 网络加速已成功开启。"
    else
        log_ok "网络加速 (BBR) 已处于开启状态，跳过配置。"
    fi
}

# ==============================================================================
# GROUP 4: 证书验证与前置代理网关 (Certificates & Nginx)
# ==============================================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local acme_bin="/root/.acme.sh/acme.sh"

    if [[ ! -s "$cert_file" ]]; then
        log_info "正在向 Let's Encrypt 申请 TLS 证书 ($domain)..."
        
        local tmp_acme="/tmp/acme_$(date +%s)"
        CLEANUP_LIST+=("$tmp_acme")
        mkdir -p "$tmp_acme"
        cd "$tmp_acme" || log_err "创建临时工作目录失败。"
        
        echo -e "${C_BLUE}--- 开始申请证书 ---${C_RESET}"
        if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 60 https://get.acme.sh | sh -s email="admin@${domain}" --nocron && [[ -s "$acme_bin" ]]; then
            log_ok "证书申请工具 (ACME) 安装成功。"
            "$acme_bin" --upgrade --auto-upgrade "$AUTO_UPGRADE" >/dev/null 2>&1
        else
            log_err "证书申请工具安装失败，请检查网络连接。"
        fi
        
        if [[ "$api" == "standalone" ]]; then
            command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1
            "$acme_bin" --issue -d "$domain" -d "www.$domain" --standalone --keylength ec-256 $GLOBAL_CERT_MODE --pre-hook "systemctl stop nginx || true" --post-hook "systemctl start nginx || true"
        else
            "$acme_bin" --issue --dns "$api" -d "$domain" -d "*.$domain" --keylength ec-256 $GLOBAL_CERT_MODE
        fi
        
        # 模式3自动追加 Hysteria2 重启逻辑
        local reload_cmd="systemctl restart nginx || true"
        if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            reload_cmd="systemctl restart nginx; systemctl restart hysteria-server || true"
        fi

        "$acme_bin" --install-cert -d "$domain" --ecc \
            --key-file "/etc/nginx/ssl/${domain}_ecc.key" \
            --fullchain-file "$cert_file" \
            --reloadcmd "$reload_cmd"
        echo -e "${C_BLUE}--------------------${C_RESET}"
            
        cd "$HOME" || true
        
        if [[ -s "$cert_file" ]]; then
            log_ok "TLS 证书申请成功并部署到 Nginx。"
            local acme_conf="/root/.acme.sh/account.conf"
            if [[ -f "$acme_conf" ]]; then
                grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
                grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
                grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
                log_info "证书工具的隐私设置已生效 (不记录日志)。"
            fi
        else
            log_err "证书申请失败，请查看上方报错信息。"
        fi
    else
        log_info "检测到服务器已存在有效证书，跳过申请步骤。"
    fi
}

module_config_nginx() {
    local domain=$1
    log_info "正在配置 Nginx 主程序..."

    cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log notice;
include /etc/nginx/modules-enabled/*.conf;
events { worker_connections 1024; }
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

    log_info "正在配置 Nginx 伪装网站和安全策略..."
    rm -f /etc/nginx/sites-enabled/default
    
    local NGINX_VER
    NGINX_VER=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    log_info "当前 Nginx 版本: ${C_YELLOW}${NGINX_VER}${C_RESET}"
    
    local reject_handshake="ssl_reject_handshake on;"
    if [ "$(printf '%s\n' "1.22.0" "$NGINX_VER" | sort -V | head -n1)" != "1.22.0" ]; then
        reject_handshake=""
    fi
    
    local listen_directive="listen 127.0.0.1:8443 ssl http2;"
    if [ "$(printf '%s\n' "1.25.1" "$NGINX_VER" | sort -V | head -n1)" == "1.25.1" ]; then
        listen_directive="listen 127.0.0.1:8443 ssl;
    http2 on;"
    fi
    
    local tmp_conf="/tmp/xray_nginx.conf"
    cat > "$tmp_conf" <<EOF
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name _;
    ${reject_handshake}
}
server {
    ${listen_directive}
    ssl_certificate /etc/nginx/ssl/${domain}_ecc.cer;
    ssl_certificate_key /etc/nginx/ssl/${domain}_ecc.key;
    server_name $domain www.$domain;
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
server {
    listen 80;
    listen [::]:80;
    server_name $domain www.$domain;
    return 301 https://\$host\$request_uri;
}
EOF

    # 模式3特供：Hysteria2 本地伪装站点回落监听
    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        cat >> "$tmp_conf" <<EOF
server {
    listen 127.0.0.1:8444;
    server_name $domain www.$domain;

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
    
    if ! nginx -t >/dev/null 2>&1; then
        rm -f /etc/nginx/sites-enabled/xray
        log_err "Nginx 配置文件存在错误，启动失败。"
    fi

    log_info "正在下载伪装网页文件..."
    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    CLEANUP_LIST+=("$temp_extract" "/tmp/web_template.zip")
    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* "${target_dir:?}/"..?* 2>/dev/null

    echo -e "${C_BLUE}--- 解压伪装网页 ---${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused --max-time 120 \
   -o /tmp/web_template.zip "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main" \
   && [[ -s /tmp/web_template.zip ]]; then
        mkdir -p "$temp_extract"
        if unzip -qo /tmp/web_template.zip -d "$temp_extract"; then
            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
            cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null
            log_ok "伪装网页部署成功。"
        fi
        rm -rf "$temp_extract" /tmp/web_template.zip 2>/dev/null
    fi
    echo -e "${C_BLUE}--------------------${C_RESET}"

    if [[ ! -s "$target_dir/index.html" ]]; then
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>' > "$target_dir/index.html"
    fi

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx 服务启动失败。"
    log_ok "Nginx 服务启动成功。"
}

# ==============================================================================
# GROUP 5: 代理核心引擎与路由策略 (Xray & Hysteria2)
# ==============================================================================
module_install_xray_core() {
    log_info "正在识别系统架构并下载 Xray 核心文件..."
    local arch
    arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    local tmp_xray="/tmp/xray_build"
    CLEANUP_LIST+=("$tmp_xray")
    mkdir -p "$tmp_xray" && cd "$tmp_xray"
    
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    
    echo -e "${C_BLUE}--- 下载 Xray 核心 ---${C_RESET}"
    curl -fL -# -o "$zip_name" "$zip_url" && unzip -qo "$zip_name" || log_err "Xray核心下载解压失败"
    echo -e "${C_BLUE}----------------------${C_RESET}"
    
    mv -f xray "$XRAY_BIN" && chmod +x "$XRAY_BIN"
    mkdir -p "$XRAY_SHARE_DIR"
    mv -f geoip.dat geosite.dat "$XRAY_SHARE_DIR/" 2>/dev/null || true
    
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
Environment="XRAY_LOCATION_ASSET=$XRAY_SHARE_DIR"
ExecStart=$XRAY_BIN run -config $XRAY_CONFIG
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    cd "$HOME" && rm -rf "$tmp_xray"
    log_ok "Xray 系统服务配置完成。"
}

module_config_xray() {
    local domain=$1
    log_info "正在生成 Xray 配置文件和加密密钥..."
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        PRIV=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
    fi
    
    [[ -z "$UUID" || "$UUID" == "null" ]] && UUID=$($XRAY_BIN uuid)
    [[ -z "$SID" || "$SID" == "null" ]] && SID=$(openssl rand -hex 8)
    
    if [[ -z "$PRIV" || "$PRIV" == "null" ]]; then
        local key_re="$($XRAY_BIN x25519 | tr -d '\r')"
        mapfile -t KEYS < <(echo "$key_re" | grep -iE "Private|Public|Password" | grep -oE '[A-Za-z0-9_-]{43}')
        PRIV=""; PUB=""
        for p_priv in "${KEYS[@]}"; do
            local calc_pub=$($XRAY_BIN x25519 -i "$p_priv" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
            for p_pub in "${KEYS[@]}"; do
                if [[ "$calc_pub" == "$p_pub" && "$p_priv" != "$p_pub" ]]; then
                    PRIV="$p_priv"; PUB="$p_pub"; break 2
                fi
            done
        done
    else
        PUB=$($XRAY_BIN x25519 -i "$PRIV" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
    fi

    log_ok "安全加密密钥生成成功。"
    
    mkdir -p "$XRAY_CONF_DIR"
    local dest_addr="127.0.0.1:8443"; local server_names_json="[\"$domain\", \"www.$domain\"]"
    [[ "$GLOBAL_INSTALL_MODE" == "2" ]] && { dest_addr="$GLOBAL_PUBLIC_SNI:443"; server_names_json="[\"$GLOBAL_PUBLIC_SNI\"]"; }
    
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": { "loglevel": "warning" },
  "dns": {
  "queryStrategy": "UseIPv4",
  "disableFallback": true,
  "hosts": {
    "dns.google": ["8.8.8.8", "8.8.4.4"]
  },
  "servers": [
    { "address": "https://1.1.1.1/dns-query" },
    { "address": "https://1.0.0.1/dns-query" },
    { 
      "address": "https://dns.google/dns-query", 
      "skipFallback": true 
    }
  ]
},

  "inbounds": [{
    "port": $GLOBAL_PORT,
    "protocol": "vless",
    "settings": { "clients": [ { "id": "$UUID", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls"],
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
        "privateKey": "$PRIV",
        "shortIds": ["$SID"]
      },
      "alpn": ["h2", "http/1.1"]
    }
  }],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
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
    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray || log_err "Xray 启动失败，请检查配置文件格式。"
    log_ok "Xray 路由规则配置成功。"
}

module_install_hysteria() {
    local domain=$1
    log_info "正在下载并安装 Hysteria2 核心..."
    
    local arch=$(dpkg --print-architecture)
    local hy2_arch="amd64"
    [[ "$arch" == "arm64" ]] && hy2_arch="arm64"

    local hy2_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${hy2_arch}"
    
    echo -e "${C_BLUE}--- 下载 Hysteria2 核心 ---${C_RESET}"
    curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 \
          -o /usr/local/bin/hysteria "$hy2_url" \
          && [[ -s /usr/local/bin/hysteria ]] \
          && chmod +x /usr/local/bin/hysteria \
          || log_err "Hysteria2 下载失败"
    echo -e "${C_BLUE}---------------------------${C_RESET}"

    mkdir -p /etc/hysteria
    HY2_PASSWORD=$(openssl rand -hex 16)

    log_info "正在生成 Hysteria2 配置文件..."
    cat > /etc/hysteria/config.yaml <<EOF
listen: :$GLOBAL_PORT

tls:
  cert: /etc/nginx/ssl/${domain}_ecc.cer
  key:  /etc/nginx/ssl/${domain}_ecc.key

auth:
  type: password
  password: $HY2_PASSWORD

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

    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Environment=HYSTERIA_LOG_LEVEL=warn
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server || log_err "Hysteria2 启动失败，请检查系统环境。"
    log_ok "Hysteria2 配置与部署成功。"
}

# ==============================================================================
# GROUP 6: 自动化守护与系统清理 (Automation & Cleanup)
# ==============================================================================
module_setup_automation() {
    log_info "正在配置自动更新任务..."
    mkdir -p "$SCRIPT_DIR"

    cat > "$SCRIPT_DIR/update-dat.sh" <<'EOF'
#!/bin/bash
exec 9> /var/lock/xray-dat.lock
flock -n 9 || exit 0
SHARE_DIR="/usr/local/share/xray"
changed=0
update_f() {
    local f=$1; local u=$2
    if curl -fL --connect-timeout 10 --max-time 120 --retry 5 --retry-delay 3 --retry-connrefused -o "$SHARE_DIR/${f}.new" "$u" && [[ -s "$SHARE_DIR/${f}.new" ]]; then
        if ! cmp -s "$SHARE_DIR/${f}.new" "$SHARE_DIR/$f"; then
            mv -f "$SHARE_DIR/${f}.new" "$SHARE_DIR/$f"
            changed=1; return 0
        fi
    fi
    rm -f "$SHARE_DIR/${f}.new"; return 1
}
update_f "geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
update_f "geosite.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
if [[ $changed -eq 1 ]]; then
    systemctl restart xray >/dev/null 2>&1
fi
EOF
    chmod +x "$SCRIPT_DIR/update-dat.sh"

    echo -e "${C_BLUE}--- 路由分流资源热同步 ---${C_RESET}"
    bash "$SCRIPT_DIR/update-dat.sh" 2>&1 | tee -a "$LOG_FILE"
    echo -e "${C_BLUE}--------------------------${C_RESET}"

    cat > /etc/systemd/system/xray-dat.service <<EOF
[Unit]
Description=Xray Dat Update Service
[Service]
Type=oneshot
User=root
ExecStart=$SCRIPT_DIR/update-dat.sh
Restart=on-failure
RestartSec=60
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

    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        cat > /etc/systemd/system/xray-acme.service <<EOF
[Unit]
Description=Acme.sh Certificate Renewal Service
[Service]
Type=oneshot
User=root
ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
Restart=on-failure
RestartSec=60
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
    else
        systemctl stop xray-acme.timer xray-acme.service >/dev/null 2>&1 || true
        systemctl disable xray-acme.timer xray-acme.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/xray-acme.*
    fi

    systemctl daemon-reload
    systemctl enable --now xray-dat.timer >/dev/null 2>&1
    [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]] && systemctl enable --now xray-acme.timer >/dev/null 2>&1
    log_ok "自动更新任务配置完成。"
}

module_cleanup() {
    log_info "正在清理安装过程中产生的系统垃圾..."
    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean -yqq >/dev/null 2>&1
    log_ok "系统垃圾清理完毕。"
}

# ==============================================================================
# GROUP 7: 主控引擎与 CLI 菜单 (Main Scheduler & CLI Menu)
# ==============================================================================
main_install() {
    cd "$HOME" || exit 1
    
    systemctl stop xray >/dev/null 2>&1
    systemctl stop hysteria-server >/dev/null 2>&1
    command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1

    module_get_inputs
    module_prepare_env
    module_setup_bbr
    
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        module_issue_cert "$GLOBAL_DOMAIN" "$GLOBAL_DNS_API"
        module_config_nginx "$GLOBAL_DOMAIN"
    else
        if command -v nginx >/dev/null 2>&1; then
            systemctl stop nginx >/dev/null 2>&1
            systemctl disable nginx >/dev/null 2>&1
        fi
        rm -f /etc/nginx/sites-enabled/xray
    fi
    
    module_install_xray_core
    module_config_xray "$GLOBAL_DOMAIN"

    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        module_install_hysteria "$GLOBAL_DOMAIN"
    fi

    module_setup_automation
    module_cleanup
    module_show_result
}

while true; do
    clear
    echo -e "${C_BLUE}"
    echo -e " ----------------------------------------------"
    echo -e "   REALITY + HYSTERIA2 AUTOMATION CLI ENGINE"
    echo -e "   Build: $SCRIPT_VERSION"
    echo -e " ----------------------------------------------${C_RESET}\n"
    
    echo -e "  1. ${C_GREEN}执行部署脚本${C_RESET}"
    echo -e "  2. ${C_YELLOW}卸载服务${C_RESET}"
    echo -e "  3. ${C_BLUE}查看定时任务+证书状态${C_RESET}"
    echo -e "  0. ${C_RED}退出脚本${C_RESET}\n"
    
    read -rp "请输入数字选择功能 [0-3]: " OPT
    case $OPT in
        1) main_install ; break ;;
        2)
            echo -e "\n${C_BLUE}[INFO]${C_RESET} 正在停止并删除相关服务..."
            systemctl stop xray hysteria-server nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
            systemctl disable xray hysteria-server nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service /etc/systemd/system/hysteria-server.service /usr/local/bin/xray /usr/local/bin/hysteria /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
            systemctl daemon-reload
            rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
            rm -rf /var/www/html/{*,.[!.]*,..?*} "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/hysteria /etc/nginx/ssl /root/.acme.sh 2>/dev/null
            
            echo -e "\n${C_YELLOW}文件清理完毕。(注：已为您保留 BBR 网络加速与日志限制最大100M，保留7天策略)${C_RESET}"
            echo -e "${C_RED}[WARN] 是否连带卸载底层系统软件 (Nginx, Socat, qrencode, jq)？${C_RESET}"
            read -rp "如果你的服务器上还跑了别的网站或程序，请选 N！[y/N, 默认 N]: " SCORCHED_EARTH
            case "${SCORCHED_EARTH}" in
                [yY][eE][sS]|[yY])
                    log_info "正在卸载基础软件 (Nginx, Socat, qrencode, jq)..."
                    apt-get purge -yqq nginx nginx-common socat qrencode jq >/dev/null 2>&1
                    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean >/dev/null 2>&1
                    log_ok "基础软件卸载完毕。" ;;
                *) log_info "已保留基础软件环境。" ;;
            esac
            echo -e "${C_GREEN}[OK] 系统卸载与清理彻底完成。${C_RESET}"
            read -rp "按回车键返回菜单..." ;;
        3)
            echo -e "\n${C_BOLD}${C_BLUE}--- 自动任务运行状态 ---${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "当前没有运行中的定时任务"
            echo -e "\n${C_BOLD}${C_BLUE}--- 证书工具信息 ---${C_RESET}"
            [[ -f "/root/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
            read -rp "按回车键返回菜单..." ;;
        0) echo -e "\n已退出。"; exit 0 ;;
        *) echo -e "\n${C_RED}[ERROR] 输入无效，请重新选择。${C_RESET}" ; sleep 1 ;;
    esac
done
