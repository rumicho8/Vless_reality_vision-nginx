#!/bin/bash
# =========================================================
# Xray Reality 自动化部署引擎 (Advanced Stealth Edition)
# 架构模型: VLESS + XTLS-Vision + Reality + Nginx 反向代理
# =========================================================

# --- 权限与运行环境预检 ---
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ERROR] 权限异常：执行本脚本需要系统 Root 权限。\e[0m"
    echo -e "\e[33m请执行 'sudo -i' 或 'su -' 获取 Root 凭证后重新运行。\e[0m"
    exit 1
fi

# =========================================================
# 模块 0：全局常量与环境变量初始化
# =========================================================
readonly SCRIPT_VERSION="Pro Final V1 (Stability Edition)"
readonly LOG_FILE="/dev/null"
readonly XRAY_CONF_DIR="/usr/local/etc/xray"
readonly XRAY_SHARE_DIR="/usr/local/share/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly XRAY_CONFIG="$XRAY_CONF_DIR/config.json"
readonly SCRIPT_DIR="/usr/local/etc/xray-script"

# 终端输出色彩定义
readonly C_RED="\e[31m"
readonly C_GREEN="\e[32m"
readonly C_YELLOW="\e[33m"
readonly C_BLUE="\e[36m"
readonly C_RESET="\e[0m"

# 设置非交互模式，避免安装过程中弹出确认框
export AUTO_UPGRADE='0'
export LE_NO_LOG=1
export LE_LOG_FILE='/dev/null'
export DEBUG=0
export DEBIAN_FRONTEND="noninteractive"
export APT_LISTCHANGES_FRONTEND="none"

# 初始化全局变量
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

# --- 全局自动清理机制 (确保失败时能自动清理垃圾文件) ---
CLEANUP_LIST=()
trap '[[ ${#CLEANUP_LIST[@]} -gt 0 ]] && rm -rf "${CLEANUP_LIST[@]}" 2>/dev/null' EXIT SIGHUP SIGINT SIGTERM

# =========================================================
# 模块 1：日志输出功能
# =========================================================
log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

# =========================================================
# 模块 2：安装基础环境和依赖
# =========================================================
module_prepare_env() {
    log_info "正在创建系统必备目录..."

    # 限制系统日志大小，防止长期运行占满硬盘
    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    log_info "正在更新软件源并检查基础组件..."
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    
    apt-get update -yqq >/dev/null 2>&1
    
    # 常用依赖列表
    local common_deps="curl unzip openssl jq tar qrencode"
    local check_deps=("curl" "jq" "openssl")

    # 根据选择的模式安装不同依赖
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        log_info "[架构模式 1] 正在安装必备依赖 (nginx, socat, cron)..."
        apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps nginx socat cron >/dev/null 2>&1
        check_deps+=("nginx")
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    else
        log_info "[架构模式 2] 纯净模式，正在安装系统基础依赖..."
        apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps >/dev/null 2>&1
    fi
        
    for cmd in "${check_deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "必备组件 [$cmd] 安装失败，请检查网络或软件源。"
        fi
    done
    
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    
    log_ok "系统基础依赖安装完毕。"
}

module_setup_bbr() {
    log_info "正在检查并开启 BBR 网络加速..."
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        log_ok "BBR 网络加速已成功开启。"
    else
        log_ok "检测到 BBR 加速已处于开启状态。"
    fi
}

# =========================================================
# 模块 3：收集用户输入并验证
# =========================================================
module_get_inputs() {
    echo -e "\n${C_YELLOW}--- 部署架构选择 ---${C_RESET}"
    echo -e "1) Web 回落模式 (自动签发证书 + Nginx 本地伪装，高稳定性)"
    echo -e "2) 纯净直连模式 (依赖公共 SNI 伪装，轻量级部署)"
    read -rp "请选择架构模型 [1/2, 默认 1]: " MODE_INPUT
    GLOBAL_INSTALL_MODE=${MODE_INPUT:-1}

    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        read -rp "请输入已解析至本机的业务域名: " GLOBAL_DOMAIN
        GLOBAL_DOMAIN=$(echo "$GLOBAL_DOMAIN" | sed 's/^www\.//g' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        
        [[ -z "$GLOBAL_DOMAIN" ]] && log_err "域名输入非法或为空。"
        
        echo -e "\n${C_BLUE}执行域名解析状态探针测试...${C_RESET}"
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
        
        echo -e "本机公网 IP : ${C_YELLOW}${local_ip:-"解析异常"}${C_RESET}"
        echo -e "域名解析 IP : ${C_YELLOW}${domain_ip:-"解析异常"}${C_RESET}"
        
        if [[ -n "$local_ip" && "$local_ip" == "$domain_ip" ]]; then
            echo -e "${C_GREEN}[OK] 地址匹配成功，DNS A 记录已生效。${C_RESET}\n"
        else
            echo -e "${C_RED}[WARN] 警告：域名解析与本机 IP 不匹配 (可能受 CDN 或 DNS 缓存影响)。${C_RESET}\n"
        fi

        get_listen_port
        
        echo -e "1) DNS API 验证机制 (推荐，支持通配符证书下发)"
        echo -e "2) HTTP Standalone 机制 (依赖本地端口监听验证)"
        read -rp "请选择证书验证模型 [1/2, 默认 1]: " VERIFY_TYPE
        
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            GLOBAL_DNS_API="standalone"
        else
            echo -e "\n1) Cloudflare\n2) Namesilo"
            read -rp "请指定 DNS 托管服务商 [1/2]: " DNS_TYPE
            if [[ "$DNS_TYPE" == "1" ]]; then
                GLOBAL_DNS_API="dns_cf"
                read -rp "请输入 CF_Token: " GLOBAL_CF_TOKEN
                read -rp "请输入 CF_Zone_ID: " GLOBAL_CF_ZONE_ID
                export CF_Token=$GLOBAL_CF_TOKEN
                export CF_Zone_ID=$GLOBAL_CF_ZONE_ID
            else
                GLOBAL_DNS_API="dns_namesilo"
                read -rp "请输入 Namesilo_Key: " GLOBAL_NAMESILO_KEY
                export Namesilo_Key=$GLOBAL_NAMESILO_KEY
            fi
        fi

        echo -e "\n${C_YELLOW}--- 证书环境配置 ---${C_RESET}"
        echo -e "1) Production 生产环境 (存在服务商签发频率限制)"
        echo -e "2) Staging 测试环境 (无签发限制，适用于验证部署流程)"
        read -rp "请选择证书颁发环境 [1/2, 默认 1]: " CERT_MODE_INPUT
        if [[ "$CERT_MODE_INPUT" == "2" ]]; then
            GLOBAL_CERT_MODE="--staging"
            log_warn "当前处于 Staging 环境，签发的证书在浏览器中将被标记为不受信任。"
        else
            GLOBAL_CERT_MODE="--server letsencrypt"
            log_info "当前处于 Production 生产环境。"
        fi

    else
        echo -e "\n${C_BLUE}--- SNI 伪装参数配置 ---${C_RESET}"
        echo -e "建议采用高连通性的公共域名，例如: www.apple.com, gateway.icloud.com, www.yahoo.com"
        read -rp "请分配用于伪装的公共 SNI (Server Name Indication) [默认 www.apple.com]: " PUBLIC_SNI_INPUT
        GLOBAL_PUBLIC_SNI=${PUBLIC_SNI_INPUT:-"www.apple.com"}
        GLOBAL_PUBLIC_SNI=$(echo "$GLOBAL_PUBLIC_SNI" | sed 's/^https:\/\///g' | sed 's/^http:\/\///g' | sed 's/\/$//g' | tr -d '[:space:]')
        get_listen_port
    fi

    echo -e "\n${C_YELLOW}--- 系统安全审计策略 (Stealth Mode) ---${C_RESET}"
    echo -e "激活后，每次退出 SSH 会话将自动触发以下清理操作：\n 1. 清除当前用户的历史命令缓冲区\n 2. 截断系统日志及访问授权记录\n ${C_RED}安全提示：此策略将限制常规故障排查能力，仅适用于高隐私环境。${C_RESET}"
    read -rp "是否启用 Stealth Mode 审计拦截？[y/N, 默认 N]: " STEALTH_INPUT
    GLOBAL_ENABLE_STEALTH=${STEALTH_INPUT:-N}
}

get_listen_port() {
    while true; do
        read -rp "请分配 Xray 监听端口 (范围 1-65535) [默认 443]: " PORT_INPUT
        GLOBAL_PORT=${PORT_INPUT:-443}
        if ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
            log_warn "输入的端口无效，请输入 1-65535 之间的数字。"
            continue
        fi
        
        # --- 修复 1：硬性排他检查，防止占用 Nginx 保留端口 ---
        if [[ "$GLOBAL_INSTALL_MODE" == "1" ]] && { [ "$GLOBAL_PORT" -eq 80 ] || [ "$GLOBAL_PORT" -eq 8443 ]; }; then
            log_warn "模式 1 下，端口 80 和 8443 已被 Nginx 系统保留，请更换其他端口。"
            continue
        fi
        
        if ss -tuln 2>/dev/null | grep -q ":$GLOBAL_PORT "; then
            log_warn "端口 $GLOBAL_PORT 存在进程占用冲突，请重新分配。"
        else
            log_ok "端口 $GLOBAL_PORT 可用并已确认。\n"
            break
        fi
    done
}

# =========================================================
# 模块 4：申请并部署 TLS 证书
# =========================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local acme_bin="/root/.acme.sh/acme.sh"

    if [[ ! -s "$cert_file" ]]; then
        log_info "正在为域名申请 TLS 证书 ($domain)..."
        
        local tmp_acme="/tmp/acme_$(date +%s)"
        CLEANUP_LIST+=("$tmp_acme")
        mkdir -p "$tmp_acme"
        
        cd "$tmp_acme" || log_err "临时工作目录创建失败。"
        
        echo -e "${C_BLUE}------------------- 申请 TLS 证书 -------------------${C_RESET}"
        # 2. 下载并安装 Acme.sh，确保文件不为空
        if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 60 https://get.acme.sh | sh -s email="admin@${domain}" && [[ -s "$acme_bin" ]]; then
            log_ok "证书申请工具 (Acme.sh) 安装成功。"
            # 只有安装成功才尝试升级
            "$acme_bin" --upgrade --auto-upgrade "$AUTO_UPGRADE" >/dev/null 2>&1
        else
            # 如果下载失败或文件为空，则直接报错退出
            log_err "证书申请工具安装失败，请检查网络连接。"
        fi
        
        # 3. 开始申请证书
        if [[ "$api" == "standalone" ]]; then
            systemctl stop nginx >/dev/null 2>&1
            "$acme_bin" --issue -d "$domain" -d "www.$domain" --standalone --keylength ec-256 $GLOBAL_CERT_MODE --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"
        else
            "$acme_bin" --issue --dns "$api" -d "$domain" -d "*.$domain" --keylength ec-256 $GLOBAL_CERT_MODE
        fi
        
        # 4. 安装证书并重启 Nginx
        "$acme_bin" --install-cert -d "$domain" --ecc \
            --key-file "/etc/nginx/ssl/${domain}_ecc.key" \
            --fullchain-file "$cert_file" \
            --reloadcmd "systemctl restart nginx || true"
        echo -e "${C_BLUE}--------------------------------------------------${C_RESET}"
            
        cd "$HOME" || true
        
        if [[ -s "$cert_file" ]]; then
            log_ok "证书申请成功并已部署到系统。"
            local acme_conf="/root/.acme.sh/account.conf"
            if [[ -f "$acme_conf" ]]; then
                grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
                grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
                grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
                log_info "证书组件隐私配置已生效。"
            fi
        else
            log_err "证书申请失败，请查看上方报错信息。"
        fi
    else
        log_info "检测到有效证书，跳过申请步骤。"
    fi
}

# =========================================================
# 模块 5：配置 Nginx 伪装网站
# =========================================================
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

    log_info "正在配置 Nginx 伪装网站..."
    rm -f /etc/nginx/sites-enabled/default
    
    local tmp_conf="/tmp/xray_nginx.conf"
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
        log_err "Nginx 配置文件有误，服务启动失败。"
    fi

    log_info "正在下载伪装网站网页源码..."
    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    CLEANUP_LIST+=("$temp_extract" "/tmp/web_template.zip")
    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* "${target_dir:?}/"..?* 2>/dev/null

    echo -e "${C_BLUE}------------------- 下载伪装网页 -------------------${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused --max-time 120 \
   -o /tmp/web_template.zip "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main" \
   && [[ -s /tmp/web_template.zip ]]; then
        echo -e "${C_BLUE}------------------- 部署伪装网页 -------------------${C_RESET}"
        mkdir -p "$temp_extract"
        if unzip -qo /tmp/web_template.zip -d "$temp_extract"; then
            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
            [[ -d "$inner_dir" ]] || log_err "网页压缩包格式不正确。"
            cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null
            log_ok "伪装网站源码部署成功。"
        else
            log_err "网页源码解压失败，文件可能已损坏。"
        fi
        rm -rf "$temp_extract" /tmp/web_template.zip 2>/dev/null
    else
        echo -e "${C_RED}✖ 静态模板拉取超时或连接被重置。${C_RESET}"
    fi
    echo -e "${C_BLUE}--------------------------------------------------${C_RESET}"

    if [[ ! -s "$target_dir/index.html" ]]; then
        log_warn "未找到网页首页文件，已启用备用 403 伪装页面。"
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>' > "$target_dir/index.html"
    else
        log_ok "伪装网站页面部署成功。"
    fi

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx 服务启动失败。"
    log_ok "Nginx 服务启动成功。"
}

# =========================================================
# 模块 6：下载并配置 Xray 核心
# =========================================================
module_install_xray_core() {
    log_info "正在下载 Xray 核心程序包..."
    local arch
    arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    local tmp_xray="/tmp/xray_build"
    CLEANUP_LIST+=("$tmp_xray")
    mkdir -p "$tmp_xray" && cd "$tmp_xray"
    
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    
    echo -e "${C_BLUE}------------------- 下载 Xray 核心 -------------------${C_RESET}"
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 -o "$zip_name" "$zip_url" && [[ -s "$zip_name" ]]; then
        log_ok "Xray 核心包下载成功。"
    else
        log_err "Xray 核心包下载失败，无法连接到目标服务器。"
    fi
    echo -e "${C_BLUE}--------------------------------------------------${C_RESET}"
    
    unzip -qo "$zip_name" || log_err "压缩包解压失败，文件可能已损坏。"
    
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
    log_ok "Xray 核心程序安装完成。"
}

module_config_xray() {
    local domain=$1
    log_info "正在生成 Xray 配置文件及加密密钥..."
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        PRIV=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
    fi
    
    # --- 修复 2：使用 Xray 内置命令生成 UUID (剔除 Python3 隐性依赖) ---
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

    [[ ${#PRIV} -eq 43 && ${#PUB} -eq 43 ]] || log_err "密钥生成失败。"
    log_ok "安全密钥对生成成功。"
    
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
    systemctl restart xray || log_err "Xray 服务启动失败。"
    log_ok "Xray 配置文件生成成功。"
}

# =========================================================
# 模块 7：设置定时更新和证书续期任务
# =========================================================
module_setup_automation() {
    log_info "正在配置自动更新和续期定时任务..."
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

    echo -e "\e[36m-------------------- 路由资产同步 --------------------\e[0m"
    bash "$SCRIPT_DIR/update-dat.sh" 2>&1 | tee -a "$LOG_FILE"
    echo -e "\e[36m------------------------------------------------------\e[0m"

    crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true

    # 配置 Xray 自动更新定时任务
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
    log_ok "Xray 及后台定时任务已全部启动。"
}

# =========================================================
# 模块 8：无痕模式 (退出 SSH 时清理痕迹)
# =========================================================
module_setup_stealth() {
    case "${GLOBAL_ENABLE_STEALTH}" in
        [yY][eE][sS]|[yY])
            log_info "正在配置无痕模式 (退出自动清理日志)..."
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
            log_ok "无痕模式配置成功。"
            ;;
        *) log_info "未启用无痕模式，跳过。" ;;
    esac
}

# =========================================================
# 模块 9：清理安装垃圾
# =========================================================
module_cleanup() {
    log_info "正在清理安装过程中产生的垃圾文件..."
    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean -yqq >/dev/null 2>&1
    log_ok "系统垃圾清理完毕。"
}

# =========================================================
# 模块 10：生成分享链接和二维码
# =========================================================
module_show_result() {
    clear; log_ok "部署全部完成！您的连接信息如下："
    local client_addr; local client_sni
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        client_addr="$GLOBAL_DOMAIN"; client_sni="$GLOBAL_DOMAIN"
    else
        local local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        client_addr="${local_ip:-"你的VPS_IP"}"; client_sni="$GLOBAL_PUBLIC_SNI"
    fi
    local vless_link="vless://${UUID}@${client_addr}:${GLOBAL_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${client_sni}"
    echo -e "------------------------------------------------"
    echo -e " 监听端点    : ${C_YELLOW}$GLOBAL_PORT${C_RESET}"
    echo -e " UUID (身份) : ${C_YELLOW}$UUID${C_RESET}"
    echo -e " Public Key  : ${C_YELLOW}$PUB${C_RESET}"
    echo -e " Short ID    : ${C_YELLOW}$SID${C_RESET}"
    echo -e " 路由 SNI    : ${C_BLUE}$client_sni${C_RESET}"
    echo -e "------------------------------------------------"
    echo -e "客户端配置 URI:\n${C_GREEN}$vless_link${C_RESET}\n"
    echo "$vless_link" | qrencode -t ansiutf8
}

# =========================================================
# 主控引擎调度器
# =========================================================
main_install() {
    cd "$HOME" || exit 1
    systemctl stop xray nginx >/dev/null 2>&1
    module_get_inputs
    module_prepare_env
    module_setup_bbr
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        module_issue_cert "$GLOBAL_DOMAIN" "$GLOBAL_DNS_API"; module_config_nginx "$GLOBAL_DOMAIN"
    else
        systemctl stop nginx >/dev/null 2>&1; systemctl disable nginx >/dev/null 2>&1; rm -f /etc/nginx/sites-enabled/xray
    fi
    module_install_xray_core; module_config_xray "$GLOBAL_DOMAIN"; module_setup_automation; module_setup_stealth; module_cleanup; module_show_result
}

# =========================================================
# 交互式主菜单界面
# =========================================================
while true; do
    clear; echo -e "${C_BLUE}    Xray Reality 自动化运维工具 ($SCRIPT_VERSION)${C_RESET}"
    echo "------------------------------------------------"
    echo "1. 执行部署 / 平滑覆盖更新"
    echo "2. 数据回收与服务卸载"
    echo "3. 查看运行状态与调度信息"
    echo "0. 终止进程退出"
    read -rp "请输入指令 [0-3]: " OPT
    case $OPT in
        1) main_install ; break ;;
        2)
            echo -e "\n${C_BLUE}[INFO]${C_RESET} 正在卸载相关服务及清理文件..."
            systemctl stop xray nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
            systemctl disable xray nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service /usr/local/bin/xray /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
            systemctl daemon-reload
            rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
            rm -rf /var/www/html/{*,.[!.]*,..?*} "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/nginx/ssl /root/.acme.sh 2>/dev/null
            crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
            sed -i '/# === 退出 SSH 自动清理日志 ===/,/trap cleanup_on_exit EXIT SIGHUP/d' /root/.bashrc 2>/dev/null
            [[ -f /home/admin/.bashrc ]] && sed -i '/# === 退出 SSH 自动清理日志 ===/,/trap cleanup_on_exit EXIT SIGHUP/d' /home/admin/.bashrc 2>/dev/null
            echo -e "\n${C_YELLOW}业务文件清理完毕。${C_RESET}"
            echo -e "${C_RED}是否申请扩大清理范围，执行【底层依赖物理销毁】？${C_RESET}"
            read -rp "如主机存在复用应用逻辑，请回绝该申请！[y/N, 默认 N]: " SCORCHED_EARTH
            case "${SCORCHED_EARTH}" in
                [yY][eE][sS]|[yY])
                    log_info "正在卸载基础依赖包 (nginx, socat 等)..."
                    # --- 修复 3：移除 cron，防止误杀系统原生调度 ---
                    apt-get purge -yqq nginx nginx-common socat qrencode jq >/dev/null 2>&1
                    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean >/dev/null 2>&1
                    log_ok "基础依赖包卸载成功。" ;;
                *) log_info "已保留基础依赖包。" ;;
            esac
            echo -e "${C_GREEN}[OK] 整个反向代理系统结构已解除关联并清理。${C_RESET}"
            read -rp "按回车键返回主菜单..." ;;
        3)
            echo -e "\n${C_BLUE}--- Systemd Timers 资源分布图 ---${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "当前未匹配到关联调度实例"
            echo -e "\n${C_BLUE}--- ACME 证书守护程序信息 ---${C_RESET}"
            [[ -f "/root/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
            read -rp "按回车键返回主菜单..." ;;
        0) echo "释放连接控制，脚本正常终止。"; exit 0 ;;
        *) echo "无效操作域捕获，拒绝执行。" ; sleep 1 ;;
    esac
done
