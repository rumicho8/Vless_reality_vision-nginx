#!/bin/bash
# ==============================================================================
# Xray Reality + Hysteria2 Automation Engine (Stability Edition V1 + Hy2)
# Architecture: VLESS + XTLS-Vision + Reality + Nginx Reverse Proxy + Hysteria2
# ==============================================================================

# 权限与运行环境预检
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ERROR] 权限不足：执行本程序需要 Root 权限。\e[0m"
    echo -e "\e[33m请执行 'sudo -i' 或 'su -' 获取 Root 权限后重新运行。\e[0m"
    exit 1
fi

# ==============================================================================
# GROUP 1: 全局变量与环境声明 (Globals & Traps)
# ==============================================================================
readonly SCRIPT_VERSION="Pro Final V2.1 (Stability Edition + Hysteria2)"
readonly LOG_FILE="/dev/null"
readonly LOCK_FILE="/var/run/xray_script.lock"
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

# 进程互斥锁检测
if [[ -f "$LOCK_FILE" ]]; then
    echo -e "${C_RED}[ERROR] 安装程序已在运行中 (PID: $(cat "$LOCK_FILE"))，请勿重复执行。${C_RESET}"
    exit 1
fi
echo $$ > "$LOCK_FILE"

CLEANUP_LIST=("$LOCK_FILE")
trap '[[ ${#CLEANUP_LIST[@]} -gt 0 ]] && rm -rf "${CLEANUP_LIST[@]}" 2>/dev/null' EXIT SIGHUP SIGINT SIGTERM

# ==============================================================================
# GROUP 2: 日志引擎与交互展示层 (Loggers & Interactive UI)
# ==============================================================================
log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

get_listen_port() {
    while true; do
        read -rp "请配置服务主监听端口 (范围 1-65535) [默认 443]: " PORT_INPUT
        GLOBAL_PORT=${PORT_INPUT:-443}
        if ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
            log_warn "端口参数非法，请输入 1-65535 之间的数值。"
            continue
        fi
        
        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]] && { [ "$GLOBAL_PORT" -eq 80 ] || [ "$GLOBAL_PORT" -eq 8443 ] || [ "$GLOBAL_PORT" -eq 8444 ]; }; then
            log_warn "端口冲突：当前模式下，端口 80/8443/8444 已被本地 Nginx 路由模块占用，请重新分配。"
            continue
        fi
        
        # 协议级网络端口检测
        local tcp_occ=$(ss -tln | grep -qE ":${GLOBAL_PORT}\b" && echo "1" || echo "0")
        local udp_occ=$(ss -uln | grep -qE ":${GLOBAL_PORT}\b" && echo "1" || echo "0")

        if [[ "$tcp_occ" == "1" ]]; then
            log_warn "端口 $GLOBAL_PORT (TCP) 已被系统其他进程占用，请重新分配。"
            continue
        fi

        if [[ "$GLOBAL_INSTALL_MODE" == "3" && "$udp_occ" == "1" ]]; then
            log_warn "端口 $GLOBAL_PORT (UDP) 已被占用。Hysteria2 引擎依赖 UDP 协议，请重新分配端口。"
            continue
        fi
        
        log_ok "端口 $GLOBAL_PORT 校验通过。\n"
        break
    done
}

module_get_inputs() {
    echo -e "\n${C_BOLD}${C_BLUE}--- [阶段 1/3] 选择基础架构模式 ---${C_RESET}"
    echo -e "  1. Web 回落模式        - 自动化部署 TLS 证书与本地伪装站点，具备高稳定性与隐蔽性。"
    echo -e "  2. 纯净直连模式        - 采用高信誉公共域名进行 SNI 伪装，无需独立域名，轻量级部署。"
    echo -e "  3. 全能共存模式        - 融合 Web 回落架构，并同步拉起 Hysteria2 协议栈 (端口复用)。"
    read -rp "请输入模式编号 [1/2/3, 默认 1]: " MODE_INPUT
    GLOBAL_INSTALL_MODE=${MODE_INPUT:-1}

    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        read -rp "请输入已解析至当前服务器公网 IP 的域名 (例如 my.domain.com): " GLOBAL_DOMAIN
        # 移除 www 自动清洗逻辑，严格遵守输入
        GLOBAL_DOMAIN=$(echo "$GLOBAL_DOMAIN" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        
        [[ -z "$GLOBAL_DOMAIN" ]] && log_err "域名参数为空或格式异常。"
        
        echo -e "\n${C_BLUE}正在执行 DNS 记录可用性测试...${C_RESET}"
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
        
        echo -e "  实例公网 IP : ${C_YELLOW}${local_ip:-"获取超时"}${C_RESET}"
        echo -e "  域名解析 IP : ${C_YELLOW}${domain_ip:-"解析失败"}${C_RESET}"
        
        if [[ -n "$local_ip" && "$local_ip" == "$domain_ip" ]]; then
            echo -e "${C_GREEN}  [OK] 路由一致性校验通过，DNS 解析已生效。${C_RESET}\n"
        else
            echo -e "${C_RED}  [WARN] 警告：DNS 解析 IP 与实例本地 IP 不一致 (受 CDN 代理或 DNS 缓存影响)。${C_RESET}\n"
        fi

        get_listen_port
        
        echo -e "${C_BOLD}${C_BLUE}--- [阶段 2/3] 配置证书签发验证策略 ---${C_RESET}"
        echo -e "  1. DNS API 验证模式 (推荐) - 纯后台执行验证逻辑，支持泛域名签发，规避端口审查。"
        echo -e "  2. HTTP Standalone 模式    - 需临时接管本地 80 端口处理 ACME 挑战验证。"
        read -rp "请输入验证策略编号 [1/2, 默认 1]: " VERIFY_TYPE
        
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            GLOBAL_DNS_API="standalone"
        else
            echo -e "\n  1. Cloudflare\n  2. Namesilo"
            read -rp "请选择 DNS 服务提供商 [1/2]: " DNS_TYPE
            if [[ "$DNS_TYPE" == "1" ]]; then
                GLOBAL_DNS_API="dns_cf"
                read -rp "请输入 Cloudflare API Token: " GLOBAL_CF_TOKEN
                read -rp "请输入 Cloudflare Zone ID: " GLOBAL_CF_ZONE_ID
                export CF_Token=$GLOBAL_CF_TOKEN
                export CF_Zone_ID=$GLOBAL_CF_ZONE_ID
            else
                GLOBAL_DNS_API="dns_namesilo"
                read -rp "请输入 Namesilo API Key: " GLOBAL_NAMESILO_KEY
                export Namesilo_Key=$GLOBAL_NAMESILO_KEY
            fi
        fi

        echo -e "\n${C_BOLD}${C_BLUE}--- [阶段 3/3] 指定证书签发环境 ---${C_RESET}"
        echo -e "  1. Production (生产环境) - 获取受信任的 CA 证书 (受 API 速率限制)。"
        echo -e "  2. Staging    (测试环境) - 仅供流程调试使用，无 API 速率限制。"
        read -rp "请输入签发环境编号 [1/2, 默认 1]: " CERT_MODE_INPUT
        if [[ "$CERT_MODE_INPUT" == "2" ]]; then
            GLOBAL_CERT_MODE="--staging"
            log_warn "已配置：Staging 测试环境。"
        else
            GLOBAL_CERT_MODE="--server letsencrypt"
            log_info "已配置：Production 生产环境。"
        fi

    else
        echo -e "\n${C_BOLD}${C_BLUE}--- [阶段 1/2] 配置特征伪装域名 (SNI) ---${C_RESET}"
        echo -e "  建议采用目标网络环境下连通率高且支持 TLS 1.3 的大型业务域名。"
        echo -e "  参考规范: www.apple.com / gateway.icloud.com / www.microsoft.com"
        read -rp "请输入目标 SNI 域名 [默认 www.apple.com]: " PUBLIC_SNI_INPUT
        GLOBAL_PUBLIC_SNI=${PUBLIC_SNI_INPUT:-"www.apple.com"}
        GLOBAL_PUBLIC_SNI=$(echo "$GLOBAL_PUBLIC_SNI" | sed 's/^https:\/\///g' | sed 's/^http:\/\///g' | sed 's/\/$//g' | tr -d '[:space:]')
        get_listen_port
    fi
}

module_show_result() {
    clear
    echo -e "${C_GREEN}==================================================================${C_RESET}"
    echo -e "${C_BOLD}${C_GREEN}[OK] 系统架构部署就绪 (SYSTEM DEPLOYMENT SUCCESSFUL)${C_RESET}"
    echo -e "${C_GREEN}==================================================================${C_RESET}"
    
    local client_addr; local client_sni
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        client_addr="$GLOBAL_DOMAIN"; client_sni="$GLOBAL_DOMAIN"
    else
        local local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        client_addr="${local_ip:-"实例公网IP"}"; client_sni="$GLOBAL_PUBLIC_SNI"
    fi
    local vless_link="vless://${UUID}@${client_addr}:${GLOBAL_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${client_sni}"
    
    echo -e "${C_BOLD}[Xray Reality 节点参数]${C_RESET}"
    echo -e " 接入端点   : ${C_YELLOW}$GLOBAL_PORT (TCP)${C_RESET}"
    echo -e " 身份凭证   : ${C_YELLOW}$UUID${C_RESET}"
    echo -e " 公钥 (PUB) : ${C_YELLOW}$PUB${C_RESET}"
    echo -e " 短 ID (SID): ${C_YELLOW}$SID${C_RESET}"
    echo -e " 路由 SNI   : ${C_BLUE}$client_sni${C_RESET}"
    echo -e "${C_BOLD}统一资源标识符 (URI Format):${C_RESET}\n${C_GREEN}$vless_link${C_RESET}\n"
    
    echo "$vless_link" | qrencode -t ansiutf8

    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        local hy2_link="hy2://${HY2_PASSWORD}@${GLOBAL_DOMAIN}:${GLOBAL_PORT}/?sni=${GLOBAL_DOMAIN}&alpn=h3&insecure=0#Hysteria2_${GLOBAL_DOMAIN}"
        echo -e "\n------------------------------------------------------------------"
        echo -e "${C_BOLD}[Hysteria2 节点参数]${C_RESET}"
        echo -e " 接入端点   : ${C_YELLOW}$GLOBAL_PORT (UDP)${C_RESET}"
        echo -e " 认证密钥   : ${C_YELLOW}$HY2_PASSWORD${C_RESET}"
        echo -e " 防火墙回落 : ${C_BLUE}Nginx (127.0.0.1:8444)${C_RESET}"
        echo -e "${C_BOLD}统一资源标识符 (URI Format):${C_RESET}\n${C_GREEN}$hy2_link${C_RESET}\n"
    fi
}

# ==============================================================================
# GROUP 3: 基础环境与网络栈优化 (System Pre-requisites & BBR)
# ==============================================================================
module_prepare_env() {
    log_info "正在初始化系统级依赖与日志轮转策略..."

    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nMaxRetentionSec=7day\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    log_info "正在清理包管理器进程锁并更新软件源..."
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    apt-get update -yqq >/dev/null 2>&1
    
    # 动态构建基础组件安装清单
    local install_list="curl unzip openssl jq qrencode"
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        install_list="$install_list nginx socat"
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    fi

    log_info "正在执行基础组件的并发安装..."
    apt-get install -yqq --no-install-recommends -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        $install_list >/dev/null 2>&1
        
    # 依赖完整性校验
    for cmd in curl unzip openssl jq qrencode; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "核心组件 [$cmd] 部署失败，请排查系统软件源可用性。"
        fi
    done
    
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    log_ok "系统级基础环境预处理完成。"
}

module_setup_bbr() {
    log_info "正在检测底层网络拥塞控制算法 (TCP BBR) 状态..."
    
    local bbr_conf_file="/etc/sysctl.conf"
    local os_info="未知内核"
    
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

    log_info "内核识别: ${C_YELLOW}${os_info}${C_RESET} | 目标配置路由: ${C_YELLOW}${bbr_conf_file}${C_RESET}"

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
        log_ok "TCP BBR 网络加速算法已成功挂载。"
    else
        log_ok "TCP BBR 算法已处于运行状态，无需重复注入。"
    fi
}

# ==============================================================================
# GROUP 4: 证书自动化调度与 Nginx 代理网关 (Certificates & Nginx)
# ==============================================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local acme_bin="/root/.acme.sh/acme.sh"

    if [[ ! -s "$cert_file" ]]; then
        log_info "正在通过 ACME 协议向 Let's Encrypt 发起 TLS 证书签发请求 ($domain)..."
        
        local tmp_acme="/tmp/acme_$(date +%s)"
        CLEANUP_LIST+=("$tmp_acme")
        mkdir -p "$tmp_acme"
        cd "$tmp_acme" || log_err "工作区目录创建异常。"
        
        echo -e "${C_BLUE}--- 初始化 ACME 环境 ---${C_RESET}"
        if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 60 https://get.acme.sh | sh -s email="admin@${domain}" --nocron && [[ -s "$acme_bin" ]]; then
            log_ok "ACME 自动化套件安装成功。"
            "$acme_bin" --upgrade --auto-upgrade "$AUTO_UPGRADE" >/dev/null 2>&1
        else
            log_err "ACME 套件拉取超时，请排查网络出站连通性。"
        fi
        
        # 移除相关强制多域名申请，严格遵照单一输入域名
        if [[ "$api" == "standalone" ]]; then
            command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1
            "$acme_bin" --issue -d "$domain" --standalone --keylength ec-256 $GLOBAL_CERT_MODE --pre-hook "systemctl stop nginx || true" --post-hook "systemctl start nginx || true"
        else
            "$acme_bin" --issue --dns "$api" -d "$domain" --keylength ec-256 $GLOBAL_CERT_MODE
        fi
        
        # 动态构建证书下发后的服务重载指令
        local reload_cmd="systemctl restart nginx || true"
        if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            reload_cmd="systemctl restart nginx; systemctl restart hysteria-server || true"
        fi

        "$acme_bin" --install-cert -d "$domain" --ecc \
            --key-file "/etc/nginx/ssl/${domain}_ecc.key" \
            --fullchain-file "$cert_file" \
            --reloadcmd "$reload_cmd"
        echo -e "${C_BLUE}------------------------${C_RESET}"
            
        cd "$HOME" || true
        
        if [[ -s "$cert_file" ]]; then
            log_ok "TLS 证书签发完成并成功部署至网关层。"
            local acme_conf="/root/.acme.sh/account.conf"
            if [[ -f "$acme_conf" ]]; then
                grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
                grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
                grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
                log_info "已强制覆写 ACME 日志策略以保障隐私。"
            fi
        else
            log_err "证书签发链路失败，请检查上文 API 响应。"
        fi
    else
        log_info "探测到本地存在合规证书凭据，跳过重复签发逻辑。"
    fi
}

module_config_nginx() {
    local domain=$1
    log_info "正在编译 Nginx 全局调度配置..."

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

    log_info "正在配置 Nginx 站点防探测规则..."
    rm -f /etc/nginx/sites-enabled/default
    
    local NGINX_VER
    NGINX_VER=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    log_info "宿主机 Nginx 引擎版本: ${C_YELLOW}${NGINX_VER}${C_RESET}"
    
    local reject_handshake="ssl_reject_handshake on;"
    if [ "$(printf '%s\n' "1.22.0" "$NGINX_VER" | sort -V | head -n1)" != "1.22.0" ]; then
        reject_handshake=""
    fi
    
    local listen_directive="listen 127.0.0.1:8443 ssl http2;"
    if [ "$(printf '%s\n' "1.25.1" "$NGINX_VER" | sort -V | head -n1)" == "1.25.1" ]; then
        listen_directive="listen 127.0.0.1:8443 ssl;
    http2 on;"
    fi
    
    # Nginx 配置文件去除所有的 www.$domain
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
    server_name $domain;
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
    server_name $domain;
    return 301 https://\$host\$request_uri;
}
EOF

    # 针对全能共存模式：配置 Hysteria2 的本地伪装站点回落转发
    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        cat >> "$tmp_conf" <<EOF
server {
    listen 127.0.0.1:8444;
    server_name $domain;

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
        log_err "Nginx 配置语法解析异常，服务重载终止。"
    fi

    log_info "正在拉取远端前端静态资源库..."
    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    CLEANUP_LIST+=("$temp_extract" "/tmp/web_template.zip")
    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* "${target_dir:?}/"..?* 2>/dev/null

    echo -e "${C_BLUE}--- 部署静态资源映射 ---${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused --max-time 120 \
   -o /tmp/web_template.zip "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main" \
   && [[ -s /tmp/web_template.zip ]]; then
        mkdir -p "$temp_extract"
        if unzip -qo /tmp/web_template.zip -d "$temp_extract"; then
            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
            cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null
            log_ok "前端静态资源构建完成。"
        fi
        rm -rf "$temp_extract" /tmp/web_template.zip 2>/dev/null
    fi
    echo -e "${C_BLUE}------------------------${C_RESET}"

    if [[ ! -s "$target_dir/index.html" ]]; then
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>' > "$target_dir/index.html"
    fi

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx 守护进程唤醒失败。"
    log_ok "Nginx 代理网关已上线。"
}

# ==============================================================================
# GROUP 5: 代理核心引擎与路由策略装配 (Xray & Hysteria2)
# ==============================================================================
module_install_xray_core() {
    log_info "正在匹配系统指令集并拉取 Xray 核心..."
    local arch
    arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    local tmp_xray="/tmp/xray_build"
    CLEANUP_LIST+=("$tmp_xray")
    mkdir -p "$tmp_xray" && cd "$tmp_xray"
    
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    
    echo -e "${C_BLUE}--- 下载 Xray 核心 ---${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 -o "$zip_name" "$zip_url" && [[ -s "$zip_name" ]]; then
        log_ok "Xray 核心文件下载成功。"
    else
        log_err "Xray 核心文件下载失败，请检查网络。"
    fi
    echo -e "${C_BLUE}------------------------${C_RESET}"

    unzip -qo "$zip_name" || log_err "压缩包解压失败。"
    
    mv -f xray "$XRAY_BIN" && chmod +x "$XRAY_BIN"
    mkdir -p "$XRAY_SHARE_DIR"
    mv -f geoip.dat geosite.dat "$XRAY_SHARE_DIR/" 2>/dev/null || true
    
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Routing Engine
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
    log_ok "Xray 守护进程实例配置就绪。"
}

module_config_xray() {
    local domain=$1
    log_info "正在生成 Xray 核心路由配置与加密向量..."
    
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

    log_ok "X25519 密钥对生成器执行成功。"
    
    mkdir -p "$XRAY_CONF_DIR"
    # Xray 路由数组彻底移除 www 备用域名
    local dest_addr="127.0.0.1:8443"; local server_names_json="[\"$domain\"]"
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
    systemctl restart xray || log_err "Xray 引擎唤醒失败，请复查 JSON 结构。"
    log_ok "Xray 全局路由及入站规则编译写入完成。"
}

module_install_hysteria() {
    local domain=$1
    log_info "正在获取并装配 Hysteria2 协议栈..."
    
    local arch=$(dpkg --print-architecture)
    local hy2_arch="amd64"
    [[ "$arch" == "arm64" ]] && hy2_arch="arm64"

    local hy2_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${hy2_arch}"
    
    echo -e "${C_BLUE}--- 构建 Hysteria2 二进制 ---${C_RESET}"
    curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 \
          -o /usr/local/bin/hysteria "$hy2_url" \
          && [[ -s /usr/local/bin/hysteria ]] \
          && chmod +x /usr/local/bin/hysteria \
          || log_err "Hysteria2 核心拉取异常。"
    echo -e "${C_BLUE}-----------------------------${C_RESET}"

    mkdir -p /etc/hysteria
    HY2_PASSWORD=$(openssl rand -hex 16)

    log_info "正在编译 Hysteria2 参数矩阵..."
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
Description=Hysteria2 QUIC Engine
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
    systemctl restart hysteria-server || log_err "Hysteria2 引擎唤醒失败，请检查端口占用。"
    log_ok "Hysteria2 服务链配置上线完成。"
}

# ==============================================================================
# GROUP 6: 自动化守护机制与系统垃圾回收 (Automation & Cleanup)
# ==============================================================================
module_setup_automation() {
    log_info "正在注入定时计划与自动化更新策略..."
    mkdir -p "$SCRIPT_DIR"

    cat > "$SCRIPT_DIR/update-dat.sh" <<'EOF'
#!/bin/bash
exec 9> /var/lock/xray-dat.lock
flock -n 9 || exit 0
SHARE_DIR="/usr/local/share/xray"
changed=0
update_f() {
    local f=$1; local u=$2
    # 逻辑优化：移除了 --max-time 限制以兼容大文件传输，仅保留 60 秒连接超时
    if curl -fL --connect-timeout 60 --retry 5 --retry-delay 3 --retry-connrefused -o "$SHARE_DIR/${f}.new" "$u" && [[ -s "$SHARE_DIR/${f}.new" ]]; then
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

    echo -e "${C_BLUE}--- 执行首次路由分流规则拉取 ---${C_RESET}"
    bash "$SCRIPT_DIR/update-dat.sh" 2>&1 | tee -a "$LOG_FILE"
    echo -e "${C_BLUE}--------------------------------${C_RESET}"

    cat > /etc/systemd/system/xray-dat.service <<EOF
[Unit]
Description=Xray Dat Database Updater
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
Description=Acme.sh Certificate Renewal Daemon
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
    log_ok "全局自动化守护策略部署完毕。"
}

module_cleanup() {
    log_info "正在执行系统运行内存与安装缓存清理..."
    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean -yqq >/dev/null 2>&1
    log_ok "临时垃圾数据回收完成。"
}

# ==============================================================================
# GROUP 7: 主干控制流与 CLI 管理终端 (Main Scheduler & CLI Menu)
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
    echo -e " =============================================="
    echo -e "  XR+HY2 ENTERPRISE AUTOMATION CONTROLLER"
    echo -e "  Framework Version: $SCRIPT_VERSION"
    echo -e " ==============================================${C_RESET}\n"
    
    echo -e "  [1] ${C_GREEN}编译并安装核心节点组件${C_RESET}"
    echo -e "  [2] ${C_YELLOW}安全卸载并擦除运行轨迹${C_RESET}"
    echo -e "  [3] ${C_BLUE}巡检守护进程及证书状态${C_RESET}"
    echo -e "  [0] ${C_RED}安全退出控制台${C_RESET}\n"
    
    read -rp "请键入指令对应序号 [0-3]: " OPT
    case $OPT in
        1) main_install ; break ;;
        2)
            echo -e "\n${C_BLUE}[INFO]${C_RESET} 正在阻断关联进程并释放系统资源..."
            systemctl stop xray hysteria-server nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
            systemctl disable xray hysteria-server nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service /etc/systemd/system/hysteria-server.service /usr/local/bin/xray /usr/local/bin/hysteria /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
            systemctl daemon-reload
            rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
            rm -rf /var/www/html/{*,.[!.]*,..?*} "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/hysteria /etc/nginx/ssl /root/.acme.sh 2>/dev/null
            
            echo -e "\n${C_YELLOW}架构级文件已擦除。(备注：系统级网络调优 BBR 与日志限制策略已保留)${C_RESET}"
            echo -e "${C_RED}[WARN] 警告：是否执行深度清理，彻底抹除底层系统依赖 (Nginx, Socat, qrencode, jq)？${C_RESET}"
            read -rp "若当前实例承载其他 Web 业务，请务必输入 N 拒绝！[y/N, 默认 N]: " SCORCHED_EARTH
            case "${SCORCHED_EARTH}" in
                [yY][eE][sS]|[yY])
                    log_info "正在调用包管理器销毁底层依赖组件..."
                    apt-get purge -yqq nginx nginx-common socat qrencode jq >/dev/null 2>&1
                    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean >/dev/null 2>&1
                    log_ok "深度清理与依赖回收已完成。" ;;
                *) log_info "已中止依赖卸载，保留原有底层环境。" ;;
            esac
            echo -e "${C_GREEN}[OK] 逆向回退操作执行完毕，系统状态已恢复。${C_RESET}"
            read -rp "按下回车键返回主控制台..." ;;
        3)
            echo -e "\n${C_BOLD}${C_BLUE}--- 自动化守护服务巡检 ---${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "异常：未检测到挂载的守护任务"
            echo -e "\n${C_BOLD}${C_BLUE}--- TLS 证书颁发机构接口状态 ---${C_RESET}"
            [[ -f "/root/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
            read -rp "按下回车键返回主控制台..." ;;
        0) echo -e "\n进程已终止。"; exit 0 ;;
        *) echo -e "\n${C_RED}[ERROR] 指令无法解析，请重新输入。${C_RESET}" ; sleep 1 ;;
    esac
done
