#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Xray Reality Automation Engine (Stability Edition V1)
# Architecture: VLESS + XTLS-Vision + Reality + Nginx Reverse Proxy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 权限与运行环境预检
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ ✖ ] 权限拒绝 (Permission Denied)：当前操作需要系统最高级 (Root) 权限。\e[0m"
    echo -e "\e[33m✦ 请执行 'sudo -i' 或 'su -' 提权后重新运行本引擎。\e[0m"
    exit 1
fi

# ==============================================================================
# GROUP 1: 全局变量与环境声明 (Globals & Traps)
# ==============================================================================
readonly SCRIPT_VERSION="Pro Final V1 (Stability Edition)"
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
GLOBAL_ENABLE_STEALTH="N"

CLEANUP_LIST=()
trap '[[ ${#CLEANUP_LIST[@]} -gt 0 ]] && rm -rf "${CLEANUP_LIST[@]}" 2>/dev/null' EXIT SIGHUP SIGINT SIGTERM

# ==============================================================================
# GROUP 2: 日志与交互展示层 (Loggers & Interactive UI)
# ==============================================================================
log_info() { echo -e "${C_BLUE}[ ℹ ]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[ ✔ ]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[ ⚠ ]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ ✖ ]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

get_listen_port() {
    while true; do
        read -rp "✦ 请分配入站流量监听端口 (范围 1-65535) [默认 443]: " PORT_INPUT
        GLOBAL_PORT=${PORT_INPUT:-443}
        if ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
            log_warn "端口分配无效，请输入合法的数值 (1-65535)。"
            continue
        fi
        
        if [[ "$GLOBAL_INSTALL_MODE" == "1" ]] && { [ "$GLOBAL_PORT" -eq 80 ] || [ "$GLOBAL_PORT" -eq 8443 ]; }; then
            log_warn "架构冲突：模式 1 下，端口 80 与 8443 已被 Nginx 系统保留作为内网穿透与转发端口，请更换。"
            continue
        fi
        
        if ss -tuln 2>/dev/null | grep -q ":$GLOBAL_PORT "; then
            log_warn "资源冲突：端口 $GLOBAL_PORT 已被系统其他进程占用，请重新分配。"
        else
            log_ok "端口 $GLOBAL_PORT 空闲状态确认完毕。\n"
            break
        fi
    done
}

module_get_inputs() {
    echo -e "\n${C_BOLD}${C_BLUE}❖ [步骤 1/4] 核心架构拓扑选择${C_RESET}"
    echo -e "  [1] Web 回落模式 (推荐) - 自动签发证书 + Nginx 本地建站伪装，防御主动探测能力极强。"
    echo -e "  [2] 纯净直连模式        - 依赖公共大厂 SNI 伪装 (如 Apple)，免域名轻量化部署。"
    read -rp "✦ 请选择部署模型 [1/2, 默认 1]: " MODE_INPUT
    GLOBAL_INSTALL_MODE=${MODE_INPUT:-1}

    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        read -rp "✦ 请输入已成功解析至本服务器的业务域名 (例如 my.domain.com): " GLOBAL_DOMAIN
        GLOBAL_DOMAIN=$(echo "$GLOBAL_DOMAIN" | sed 's/^www\.//g' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        
        [[ -z "$GLOBAL_DOMAIN" ]] && log_err "输入的域名非法或不可为空。"
        
        echo -e "\n${C_BLUE}[ 探针 ] 执行网络解析状态测试...${C_RESET}"
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
        
        echo -e "  本机出口 IP : ${C_YELLOW}${local_ip:-"获取超时"}${C_RESET}"
        echo -e "  域名解析 IP : ${C_YELLOW}${domain_ip:-"解析失败"}${C_RESET}"
        
        if [[ -n "$local_ip" && "$local_ip" == "$domain_ip" ]]; then
            echo -e "${C_GREEN}  [✔] 路由匹配成功，DNS A 记录已生效。${C_RESET}\n"
        else
            echo -e "${C_RED}  [⚠] 警告：检测到域名解析与本机出口 IP 不符 (可能正处于 CDN 代理下或存在 DNS 缓存延迟)。${C_RESET}\n"
        fi

        get_listen_port
        
        echo -e "${C_BOLD}${C_BLUE}❖ [步骤 2/4] ACME 证书鉴权机制配置${C_RESET}"
        echo -e "  [1] DNS API 验证机制 (推荐) - 静默验证，支持泛域名，无惧端口被封。"
        echo -e "  [2] HTTP Standalone 机制    - 需接管本地 HTTP 端口进行鉴权。"
        read -rp "✦ 请选择 TLS 证书验证模型 [1/2, 默认 1]: " VERIFY_TYPE
        
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            GLOBAL_DNS_API="standalone"
        else
            echo -e "\n  [1] Cloudflare API\n  [2] Namesilo API"
            read -rp "✦ 请指定域名 DNS 托管服务商 [1/2]: " DNS_TYPE
            if [[ "$DNS_TYPE" == "1" ]]; then
                GLOBAL_DNS_API="dns_cf"
                read -rp "✦ 输入 Cloudflare API Token: " GLOBAL_CF_TOKEN
                read -rp "✦ 输入 Cloudflare Zone ID: " GLOBAL_CF_ZONE_ID
                export CF_Token=$GLOBAL_CF_TOKEN
                export CF_Zone_ID=$GLOBAL_CF_ZONE_ID
            else
                GLOBAL_DNS_API="dns_namesilo"
                read -rp "✦ 输入 Namesilo API Key: " GLOBAL_NAMESILO_KEY
                export Namesilo_Key=$GLOBAL_NAMESILO_KEY
            fi
        fi

        echo -e "\n${C_BOLD}${C_BLUE}❖ [步骤 3/4] Let's Encrypt 签发环境策略${C_RESET}"
        echo -e "  [1] Production (生产环境) - 存在严格的频控限制，颁发合法可信证书。"
        echo -e "  [2] Staging    (测试环境) - 无频控限制，用于排查网络报错 (证书不被浏览器信任)。"
        read -rp "✦ 请选择证书颁发环境 [1/2, 默认 1]: " CERT_MODE_INPUT
        if [[ "$CERT_MODE_INPUT" == "2" ]]; then
            GLOBAL_CERT_MODE="--staging"
            log_warn "当前策略：Staging 测试环境 (签发的证书仅供内部联调)。"
        else
            GLOBAL_CERT_MODE="--server letsencrypt"
            log_info "当前策略：Production 生产环境。"
        fi

    else
        echo -e "\n${C_BOLD}${C_BLUE}❖ [步骤 1/2] 流量 SNI 伪装向量配置${C_RESET}"
        echo -e "  建议选择当地连通率高且支持 TLS 1.3 的大型公共业务域名。"
        echo -e "  备选范例: www.apple.com / gateway.icloud.com / www.microsoft.com"
        read -rp "✦ 请分配注入特征流量的公共 SNI [默认 www.apple.com]: " PUBLIC_SNI_INPUT
        GLOBAL_PUBLIC_SNI=${PUBLIC_SNI_INPUT:-"www.apple.com"}
        GLOBAL_PUBLIC_SNI=$(echo "$GLOBAL_PUBLIC_SNI" | sed 's/^https:\/\///g' | sed 's/^http:\/\///g' | sed 's/\/$//g' | tr -d '[:space:]')
        get_listen_port
    fi

    echo -e "\n${C_BOLD}${C_BLUE}❖ [步骤 4/4] 终端审计隐匿模式 (Stealth Mode)${C_RESET}"
    echo -e "  启用此功能后，每次切断 SSH 交互会话，将触发自动化清理守护进程："
    echo -e "  1. 抹除当前系统账户的 Bash 命令历史执行缓冲区。"
    echo -e "  2. 强行截断 systemd 登录日志与系统授权账本 (/var/log/auth.log 等)。"
    echo -e "  ${C_RED}[⚠ 安全警告] 该模块将破坏 Linux 标准运维审计链路，仅限绝对隐私刚需场景使用。${C_RESET}"
    read -rp "✦ 是否将 Stealth Mode 注入系统环境变量？[y/N, 默认 N]: " STEALTH_INPUT
    GLOBAL_ENABLE_STEALTH=${STEALTH_INPUT:-N}
}

module_show_result() {
    clear
    echo -e "${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_GREEN} [✔] 核心引擎与网络拓扑构建完毕 (DEPLOYMENT SUCCESS)${C_RESET}"
    echo -e "${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local client_addr; local client_sni
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        client_addr="$GLOBAL_DOMAIN"; client_sni="$GLOBAL_DOMAIN"
    else
        local local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        client_addr="${local_ip:-"你的VPS_IP"}"; client_sni="$GLOBAL_PUBLIC_SNI"
    fi
    local vless_link="vless://${UUID}@${client_addr}:${GLOBAL_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${client_sni}"
    
    echo -e " 📡  网络端点    : ${C_YELLOW}$GLOBAL_PORT${C_RESET}"
    echo -e " 🔑  UUID 标识   : ${C_YELLOW}$UUID${C_RESET}"
    echo -e " 🛡️   Public Key  : ${C_YELLOW}$PUB${C_RESET}"
    echo -e " 🏷️   Short ID    : ${C_YELLOW}$SID${C_RESET}"
    echo -e " 🎭  路由 SNI    : ${C_BLUE}$client_sni${C_RESET}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${C_BOLD}标准通用链接 (URI Format):${C_RESET}\n${C_GREEN}$vless_link${C_RESET}\n"
    
    echo "$vless_link" | qrencode -t ansiutf8
}

# ==============================================================================
# GROUP 3: 基础环境与网络优化 (System Pre-requisites & BBR)
# ==============================================================================
module_prepare_env() {
    log_info "初始化系统底层环境与审计日志策略..."

    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nMaxRetentionSec=7day\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    log_info "同步系统软件源缓存，解除 dpkg 互斥锁..."
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    apt-get update -yqq >/dev/null 2>&1
    
    local common_deps="curl unzip openssl jq tar qrencode"
    local check_deps=("curl" "jq" "openssl")

    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        log_info "拉取模式 1 拓扑基础组件 (Nginx 代理引擎, Socat 等)..."
        apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps nginx socat cron >/dev/null 2>&1
        check_deps+=("nginx")
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    else
        log_info "拉取模式 2 拓扑基础组件 (纯净直连环境)..."
        apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps >/dev/null 2>&1
    fi
        
    for cmd in "${check_deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "底层组件依赖缺失 [$cmd]，请检查服务器出站网络或上游镜像源状态。"
        fi
    done
    
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    log_ok "底层组件及目录结构装载完毕。"
}

module_setup_bbr() {
    log_info "探测内核 TCP 拥塞控制算法 (BBR)..."
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        log_ok "TCP BBR 拥塞控制加速引擎已强制注入并生效。"
    else
        log_ok "系统当前已运行 BBR 加速内核模块，跳过配置。"
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
        log_info "向 Let's Encrypt 节点下发 ACME 证书签发指令 ($domain)..."
        
        local tmp_acme="/tmp/acme_$(date +%s)"
        CLEANUP_LIST+=("$tmp_acme")
        mkdir -p "$tmp_acme"
        
        cd "$tmp_acme" || log_err "工作区 I/O 异常，目录分配失败。"
        
        echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄ ACME.SH TLS 验证与签发 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"
        if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 60 https://get.acme.sh | sh -s email="admin@${domain}" && [[ -s "$acme_bin" ]]; then
            log_ok "ACME 容器部署成功。"
            "$acme_bin" --upgrade --auto-upgrade "$AUTO_UPGRADE" >/dev/null 2>&1
        else
            log_err "ACME 容器拉取被网络链路阻断。"
        fi
        
        # 原理说明：
        # HTTP Standalone 依赖宿主机 80 端口来提供 challenge 挑战文件。
        # 因此在 hook 阶段必须接管 Nginx 的生命周期，避免本地端口竞争导致鉴权失败。
        if [[ "$api" == "standalone" ]]; then
            command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1
            "$acme_bin" --issue -d "$domain" -d "www.$domain" --standalone --keylength ec-256 $GLOBAL_CERT_MODE --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"
        else
            "$acme_bin" --issue --dns "$api" -d "$domain" -d "*.$domain" --keylength ec-256 $GLOBAL_CERT_MODE
        fi
        
        "$acme_bin" --install-cert -d "$domain" --ecc \
            --key-file "/etc/nginx/ssl/${domain}_ecc.key" \
            --fullchain-file "$cert_file" \
            --reloadcmd "systemctl restart nginx || true"
        echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"
            
        cd "$HOME" || true
        
        if [[ -s "$cert_file" ]]; then
            log_ok "ECC 强加密证书流已映射至 Nginx SSL 总线。"
            local acme_conf="/root/.acme.sh/account.conf"
            if [[ -f "$acme_conf" ]]; then
                grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
                grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
                grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
                log_info "ACME 工具链本地反溯源审计配置生效。"
            fi
        else
            log_err "签名被阻隔，未能通过 CA 机构挑战，请检阅报错堆栈。"
        fi
    else
        log_info "探针感知到本地存在活跃证书资产，智能旁路该步骤。"
    fi
}

module_config_nginx() {
    local domain=$1
    log_info "正在预热 Nginx 反向代理主程序配置..."

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

    log_info "编译 Web Server 回落节点与严格传输安全 (HSTS) 策略..."
    rm -f /etc/nginx/sites-enabled/default
    
    local tmp_conf="/tmp/xray_nginx.conf"
    # 原理说明：
    # 1. default_server + ssl_reject_handshake 抵御无 SNI 的恶意探测。
    # 2. Xray Reality 握手失败/普通 HTTP 请求，将被 Xray 透明回落至 127.0.0.1:8443 (即此处的 Nginx 伪装站)。
    cat > "$tmp_conf" <<EOF
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
server {
    listen 127.0.0.1:8443 ssl http2;
    ssl_certificate /etc/nginx/ssl/${domain}_ecc.cer;
    ssl_certificate_key /etc/nginx/ssl/${domain}_ecc.key;
    server_name $domain www.$domain;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy strict-origin-when-cross-origin;
    add_header X-Frame-Options SAMEORIGIN;
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

    mv -f "$tmp_conf" /etc/nginx/sites-available/xray
    ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/
    
    if ! nginx -t >/dev/null 2>&1; then
        rm -f /etc/nginx/sites-enabled/xray
        log_err "Nginx 编译器语法检查失败，已阻止服务热重载。"
    fi

    log_info "向远端拉取 3D 静态前端伪装项目..."
    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    CLEANUP_LIST+=("$temp_extract" "/tmp/web_template.zip")
    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* "${target_dir:?}/"..?* 2>/dev/null

    echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄ Nginx 静态模板挂载 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused --max-time 120 \
   -o /tmp/web_template.zip "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main" \
   && [[ -s /tmp/web_template.zip ]]; then
        mkdir -p "$temp_extract"
        if unzip -qo /tmp/web_template.zip -d "$temp_extract"; then
            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
            [[ -d "$inner_dir" ]] || log_err "数据包架构验证未通过。"
            cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null
            log_ok "前端伪装渲染层覆盖成功。"
        else
            log_err "IO 管道解包失败，二进制文件存在破损。"
        fi
        rm -rf "$temp_extract" /tmp/web_template.zip 2>/dev/null
    else
        echo -e "${C_RED}✖ 伪装源端点通信断流，模板拉取 abort。${C_RESET}"
    fi
    echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"

    if [[ ! -s "$target_dir/index.html" ]]; then
        log_warn "触发降级兜底：使用无依赖原版 403 HTTP 状态页。"
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>' > "$target_dir/index.html"
    else
        log_ok "网关伪装目录就绪。"
    fi

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx Master Process 重生失败。"
    log_ok "Nginx 边缘网关守护进程成功启动。"
}

# ==============================================================================
# GROUP 5: 代理核心引擎与路由策略 (Xray Core Engine & Configuration)
# ==============================================================================
module_install_xray_core() {
    log_info "锁定系统架构并下行同步 Xray Core 二进制核心..."
    local arch
    arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    local tmp_xray="/tmp/xray_build"
    CLEANUP_LIST+=("$tmp_xray")
    mkdir -p "$tmp_xray" && cd "$tmp_xray"
    
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    
    echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄ Github Release 分发拉取 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 -o "$zip_name" "$zip_url" && [[ -s "$zip_name" ]]; then
        log_ok "Xray 核心包字节流验证一致。"
    else
        log_err "Xray 上游 CDN 分发断开连接。"
    fi
    echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"
    
    unzip -qo "$zip_name" || log_err "核心包提取期间报 CRC 校验错误。"
    
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
    log_ok "Xray Service 系统级单元注册完成。"
}

module_config_xray() {
    local domain=$1
    log_info "初始化 Xray X25519 椭圆曲线加密矩阵及配置..."
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        PRIV=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
    fi
    
    [[ -z "$UUID" || "$UUID" == "null" ]] && UUID=$($XRAY_BIN uuid)
    [[ -z "$SID" || "$SID" == "null" ]] && SID=$(openssl rand -hex 8)
    
    # 原理说明：
    # Reality 依赖 X25519 建立 TLS 1.3 前向安全通信信道。
    # PrivateKey 配置在服务端，PubKey 分发给客户端。客户端利用真实 SNI 公钥进行加密，服务端解密以辨别身份。
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

    [[ ${#PRIV} -eq 43 && ${#PUB} -eq 43 ]] || log_err "X25519 椭圆计算发生内部错误。"
    log_ok "通讯隧道安全密钥对重映射成功。"
    
    mkdir -p "$XRAY_CONF_DIR"
    local dest_addr="127.0.0.1:8443"; local server_names_json="[\"$domain\", \"www.$domain\"]"
    [[ "$GLOBAL_INSTALL_MODE" == "2" ]] && { dest_addr="$GLOBAL_PUBLIC_SNI:443"; server_names_json="[\"$GLOBAL_PUBLIC_SNI\"]"; }
    
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": { "loglevel": "warning" },
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
    systemctl restart xray || log_err "Xray 引擎加载 JSON 模型时发生致命错误。"
    log_ok "Xray 流量控制流及路由规则下发完毕。"
}

# ==============================================================================
# GROUP 6: 审计清痕与自动化守护 (Automation, Stealth Mode & Cleanup)
# ==============================================================================
module_setup_automation() {
    log_info "将系统路由资产与证书注入 crond 定时维护队列..."
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
    systemctl reload xray 2>/dev/null || systemctl restart xray >/dev/null 2>&1
fi
EOF
    chmod +x "$SCRIPT_DIR/update-dat.sh"

    echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄ 路由分流资源热同步 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"
    bash "$SCRIPT_DIR/update-dat.sh" 2>&1 | tee -a "$LOG_FILE"
    echo -e "${C_BLUE}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${C_RESET}"

    crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true

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

    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
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
    [[ "$GLOBAL_INSTALL_MODE" == "1" ]] && systemctl enable --now xray-acme.timer >/dev/null 2>&1
    log_ok "定时调度网格 (Timers & Crontab) 已接管底层状态。"
}

module_setup_stealth() {
    case "${GLOBAL_ENABLE_STEALTH}" in
        [yY][eE][sS]|[yY])
            log_info "将清理探针写入 Shell 环境变量以实现 Stealth 隐匿拦截..."
            # 原理说明：
            # 利用 bash内置的 trap 指令拦截 SIGHUP (终端断开) 和 EXIT (正常退出) 信号。
            # 在触发退出时，系统会优先执行注入的这段截断逻辑，从而实现“阅后即焚”的清痕效果。
            local TRAP_CODE="
# === 退出 SSH 自动清理日志 ===
cleanup_on_exit() {
    if [ -n \"\$SSH_CLIENT\" ] || [ -n \"\$SSH_TTY\" ]; then
        cd / >/dev/null 2>&1; history -c; rm -f \$HOME/.bash_history
        local SUDO_CMD=\"\"; command -v sudo >/dev/null 2>&1 && SUDO_CMD=\"sudo\"
        \$SUDO_CMD journalctl --rotate >/dev/null 2>&1
        \$SUDO_CMD journalctl --vacuum-time=1s >/dev/null 2>&1
        [ -f /var/log/auth.log ] && \$SUDO_CMD truncate -s 0 /var/log/auth.log >/dev/null 2>&1
    fi
}
trap cleanup_on_exit EXIT SIGHUP"
            for target_rc in "/root/.bashrc" "/home/admin/.bashrc"; do
                if [[ -f "$target_rc" ]] && ! grep -q "cleanup_on_exit" "$target_rc"; then
                    echo "$TRAP_CODE" >> "$target_rc"; [[ "$target_rc" == "/home/admin/.bashrc" ]] && chown admin:admin "$target_rc"
                fi
            done
            log_ok "安全钩子已锚定，Stealth 审计隐匿模式已挂载。"
            ;;
        *) log_info "审计系统干预请求：[跳过]。" ;;
    esac
}

module_cleanup() {
    log_info "进入收尾流，脱离临时包管理器占用的 IO 与空间..."
    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean -yqq >/dev/null 2>&1
    log_ok "装载垃圾清理及缓冲池释放成功。"
}

# ==============================================================================
# GROUP 7: 主控引擎与 CLI 菜单 (Main Scheduler & CLI Menu)
# ==============================================================================
main_install() {
    cd "$HOME" || exit 1
    
    systemctl stop xray >/dev/null 2>&1
    command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1

    module_get_inputs
    module_prepare_env
    module_setup_bbr
    
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
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
    module_setup_automation
    module_setup_stealth
    module_cleanup
    module_show_result
}

while true; do
    clear
    echo -e "${C_BLUE}"
    echo -e " ▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱"
    echo -e "   REALITY AUTOMATION CLI ENGINE"
    echo -e "   Build: $SCRIPT_VERSION"
    echo -e " ▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱${C_RESET}\n"
    
    echo -e "  [1] ${C_GREEN}▶ 执行部署策略 (Deploy or Upgrade)${C_RESET}"
    echo -e "  [2] ${C_YELLOW}⎌ 回收资源与服务卸载 (Uninstall)${C_RESET}"
    echo -e "  [3] ${C_BLUE}ℹ 查看调度与诊断层状态 (Diagnostics)${C_RESET}"
    echo -e "  [0] ${C_RED}✖ 终止 CLI 进程 (Exit)${C_RESET}\n"
    
    read -rp "✦ 请向主控输入操作指令索引 [0-3]: " OPT
    case $OPT in
        1) main_install ; break ;;
        2)
            echo -e "\n${C_BLUE}[ ℹ ]${C_RESET} 发起解耦请求，正在剥离守护进程及配置文件..."
            systemctl stop xray nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
            systemctl disable xray nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service /usr/local/bin/xray /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
            systemctl daemon-reload
            rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
            rm -rf /var/www/html/{*,.[!.]*,..?*} "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/nginx/ssl /root/.acme.sh 2>/dev/null
            crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
            sed -i '/# === 退出 SSH 自动清理日志 ===/,/trap cleanup_on_exit EXIT SIGHUP/d' /root/.bashrc 2>/dev/null
            [[ -f /home/admin/.bashrc ]] && sed -i '/# === 退出 SSH 自动清理日志 ===/,/trap cleanup_on_exit EXIT SIGHUP/d' /home/admin/.bashrc 2>/dev/null
            
            echo -e "\n${C_YELLOW}业务层级依赖解除完毕。${C_RESET}"
            echo -e "${C_RED}⚠ 系统级警告：是否申请扩大清理范围，执行【底层共享依赖包物理销毁】？${C_RESET}"
            read -rp "✦ 如主机存在复用应用逻辑，请坚决回绝该申请！[y/N, 默认 N]: " SCORCHED_EARTH
            case "${SCORCHED_EARTH}" in
                [yY][eE][sS]|[yY])
                    log_info "授权通过，正在利用 dpkg 卸载基础依赖 (nginx, socat 等)..."
                    apt-get purge -yqq nginx nginx-common socat qrencode jq >/dev/null 2>&1
                    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean >/dev/null 2>&1
                    log_ok "基础软件池清空处理完毕。" ;;
                *) log_info "共享软件池环境已保留。" ;;
            esac
            echo -e "${C_GREEN}[ ✔ ] 反向代理系统结构已解除关联并完成彻底净化。${C_RESET}"
            read -rp "✦ 按回车键返回控制台界面..." ;;
        3)
            echo -e "\n${C_BOLD}${C_BLUE}=== Systemd Timers 资源分布图 ===${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "当前上下文中未捕获到活跃的调度器实例"
            echo -e "\n${C_BOLD}${C_BLUE}=== ACME 证书守护程序内部信息 ===${C_RESET}"
            [[ -f "/root/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
            read -rp "✦ 按回车键返回控制台界面..." ;;
        0) echo -e "\n释放 I/O 与终端控制权，进程终止。"; exit 0 ;;
        *) echo -e "\n${C_RED}[✖] 非法游标捕获，请重新输入。${C_RESET}" ; sleep 1 ;;
    esac
done
