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
readonly SCRIPT_VERSION="Pro Final V9 (Stability Edition)"
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

# 锁定非交互式环境变量，确保自动化部署环境稳定
export AUTO_UPGRADE='0'
export LE_NO_LOG=1
export LE_LOG_FILE='/dev/null'
export DEBUG=0
export DEBIAN_FRONTEND="noninteractive"
export APT_LISTCHANGES_FRONTEND="none"

# 全局状态变量声明
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

# =========================================================
# 模块 1：系统级日志输出与标准接口
# =========================================================
log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

# =========================================================
# 模块 2：运行环境初始化与系统依赖装载
# =========================================================
module_prepare_env() {
    log_info "初始化系统环境与核心目录拓扑..."

    # 配置系统日志服务以控制存储占用阈值
    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    log_info "同步本地软件源并验证基础包组件..."
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    
    apt-get update -yqq >/dev/null 2>&1
    
    # 移除 uuid-runtime，改用 python 内部生成
    local common_deps="curl unzip openssl jq tar qrencode"
    local check_deps=("curl" "jq" "openssl")

    # 根据部署模式执行差异化包管理动作
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        log_info "[架构模式 1] 装载公共依赖与 Web 前置代理依赖 (nginx socat cron)..."
        apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps nginx socat cron >/dev/null 2>&1
        check_deps+=("nginx")
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    else
        log_info "[架构模式 2] 纯净代理模式，仅装载系统核心公用依赖..."
        apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            $common_deps >/dev/null 2>&1
    fi
        
    for cmd in "${check_deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "关键组件 [$cmd] 缺失，请检查系统软件源连通性。"
        fi
    done
    
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    
    log_ok "底层运行环境构建完毕。"
}

module_setup_bbr() {
    log_info "检查内核 TCP 拥塞控制模块 (BBR)..."
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        log_ok "TCP BBR 模块注入并激活成功。"
    else
        log_ok "检测到 TCP BBR 已处于启用状态。"
    fi
}

# =========================================================
# 模块 3：参数采集与逻辑前置校验
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
            log_warn "端口分配非法，请求的值越界。"
            continue
        fi
        
        if ss -tuln 2>/dev/null | grep -q ":$GLOBAL_PORT "; then
            log_warn "端口 $GLOBAL_PORT 存在进程占用冲突，请重新分配。"
        else
            log_ok "系统端口 $GLOBAL_PORT 验证通过并保留。\n"
            break
        fi
    done
}

# =========================================================
# 模块 4：TLS 证书生命周期管理
# =========================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local acme_bin="/root/.acme.sh/acme.sh"

    if [[ ! -s "$cert_file" ]]; then
        log_info "调用 Acme.sh 组件请求 ECC 算法证书 ($domain)..."
        
        local tmp_acme="/tmp/acme_$(date +%s)"
        mkdir -p "$tmp_acme"
        # 建立临时目录清理陷阱，防止文件堆积
        trap 'rm -rf "$tmp_acme" 2>/dev/null' EXIT
        
        cd "$tmp_acme" || log_err "工作区目录初始化失败。"
        
        echo -e "${C_BLUE}------------------- 证书下发流 -------------------${C_RESET}"
        curl -sfm 15 https://get.acme.sh | sh -s email="admin@${domain}"
        
        [[ ! -f "$acme_bin" ]] && log_err "Acme.sh 组件拉取异常。"
        
        $acme_bin --upgrade --auto-upgrade "$AUTO_UPGRADE" >/dev/null 2>&1
        
        if [[ "$api" == "standalone" ]]; then
            systemctl stop nginx >/dev/null 2>&1
            $acme_bin --issue -d "$domain" -d "www.$domain" --standalone --keylength ec-256 $GLOBAL_CERT_MODE --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"
        else
            $acme_bin --issue --dns "$api" -d "$domain" -d "*.$domain" --keylength ec-256 $GLOBAL_CERT_MODE
        fi
        
        $acme_bin --install-cert -d "$domain" --ecc \
            --key-file "/etc/nginx/ssl/${domain}_ecc.key" \
            --fullchain-file "$cert_file" \
            --reloadcmd "systemctl restart nginx || true"
        echo -e "${C_BLUE}--------------------------------------------------${C_RESET}"
            
        cd "$HOME"
        
        if [[ -s "$cert_file" ]]; then
            log_ok "ECC 证书颁发及本地部署完成。"
            local acme_conf="/root/.acme.sh/account.conf"
            if [[ -f "$acme_conf" ]]; then
                grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
                grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
                grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
                log_info "证书组件日志脱敏配置已写入。"
            fi
        else
            log_err "证书下发失败，请参考 ACME 运行输出排查 API 状态。"
        fi
    else
        log_info "检测到本地存在有效证书实例，跳过签发阶段。"
    fi
}

# =========================================================
# 模块 5：Web 代理前置与静态资源装载
# =========================================================
module_config_nginx() {
    local domain=$1
    log_info "写入 Nginx 全局配置文件及基础传输优化策略..."

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

    log_info "生成虚拟主机路由配置与请求重定向规则..."
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
        log_err "Nginx 配置语法预检失败，操作已回滚。"
    fi

    log_info "同步前端静态资源模板..."
    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* "${target_dir:?}/"..?* 2>/dev/null

    echo -e "${C_BLUE}------------------- 资源拉取流 -------------------${C_RESET}"
    if curl -sfL -# --connect-timeout 10 --max-time 120 --retry 3 --retry-delay 2 -o /tmp/web_template.zip "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main"; then
        echo -e "${C_BLUE}------------------- 解压部署流 -------------------${C_RESET}"
        mkdir -p "$temp_extract"
        if unzip -qo /tmp/web_template.zip -d "$temp_extract"; then
            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
            [[ -d "$inner_dir" ]] || log_err "模板层级结构解析异常。"
            cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null
            log_ok "静态资源挂载成功。"
        else
            log_err "ZIP 解压失败，数据包可能已损坏。"
        fi
        rm -rf "$temp_extract" /tmp/web_template.zip 2>/dev/null
    else
        echo -e "${C_RED}✖ 静态模板拉取超时或连接被重置。${C_RESET}"
    fi
    echo -e "${C_BLUE}--------------------------------------------------${C_RESET}"

    if [[ ! -s "$target_dir/index.html" ]]; then
        log_warn "未检测到有效的 index 文件，执行 403 兜底注入策略。"
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>' > "$target_dir/index.html"
    else
        log_ok "前端伪装服务结构完整。"
    fi

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx 守护进程唤醒失败。"
    log_ok "Nginx 服务流转就绪。"
}

# =========================================================
# 模块 6：代理核心引擎部署
# =========================================================
module_install_xray_core() {
    log_info "执行 Xray 核心二进制包拉取操作..."
    local arch
    arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    local tmp_xray="/tmp/xray_build"
    mkdir -p "$tmp_xray" && cd "$tmp_xray"
    
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    
    echo -e "${C_BLUE}------------------- 核心下载流 -------------------${C_RESET}"
    if curl -sfL -# --connect-timeout 15 --retry 3 --retry-delay 2 -m 120 -o "$zip_name" "$zip_url"; then
        log_ok "二进制归档包下载成功。"
    else
        log_err "二进制归档包拉取失败，目标地址拒绝连接。"
    fi
    echo -e "${C_BLUE}--------------------------------------------------${C_RESET}"
    
    unzip -qo "$zip_name" || log_err "解压指令执行失败，校验和异常。"
    
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
    log_ok "代理核心组件依赖注册完成。"
}

module_config_xray() {
    local domain=$1
    log_info "生成 Xray 系统配置及安全协议参数..."
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        PRIV=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
    fi
    
    # 移除外部进程 uuidgen，改用原生 Python 接口生成 UUID
    [[ -z "$UUID" || "$UUID" == "null" ]] && UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
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

    [[ ${#PRIV} -eq 43 && ${#PUB} -eq 43 ]] || log_err "密码学参数校验失败。"
    log_ok "密码学密钥对校验通过。"
    
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
    systemctl restart xray || log_err "Xray 进程唤醒异常。"
    log_ok "规则集与路由策略渲染完成。"
}

# =========================================================
# 模块 7：高可用任务调度系统配置 (Systemd Timers)
# =========================================================
module_setup_automation() {
    log_info "定义任务分发单元及原子更新脚本..."
    mkdir -p "$SCRIPT_DIR"

    cat > "$SCRIPT_DIR/update-dat.sh" <<'EOF'
#!/bin/bash
exec 9> /var/lock/xray-dat.lock
flock -n 9 || exit 0
SHARE_DIR="/usr/local/share/xray"
changed=0
update_f() {
    local f=$1; local u=$2
    if curl -sfL --connect-timeout 10 --max-time 120 --retry 3 --retry-delay 5 --retry-connrefused -o "$SHARE_DIR/${f}.new" "$u" && [[ -s "$SHARE_DIR/${f}.new" ]]; then
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

    # 强化 Service 定义，增加 User, RestartSec, LimitNOFILE
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
    log_ok "网络代理引擎主程序上线。"
}

# =========================================================
# 模块 8：系统审计无痕模块 (Stealth Mode)
# =========================================================
module_setup_stealth() {
    case "${GLOBAL_ENABLE_STEALTH}" in
        [yY][eE][sS]|[yY])
            log_info "注入用户空间会话断开自清理逻辑..."
            local TRAP_CODE="
# === System Event Trap: Auto-cleanup Session Traces ===
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
            log_ok "内核事件拦截规则注入完毕。"
            ;;
        *) log_info "Stealth 策略未配置。" ;;
    esac
}

# =========================================================
# 模块 9：包管理缓存释放
# =========================================================
module_cleanup() {
    log_info "执行闲置块回收与 APT 缓存清理流..."
    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean -yqq >/dev/null 2>&1
    log_ok "磁盘空间释放完成。"
}

# =========================================================
# 模块 10：连接串构建与状态输出
# =========================================================
module_show_result() {
    clear; log_ok "配置分发操作完成，全链路状态报告如下："
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
            echo -e "\n${C_BLUE}[INFO]${C_RESET} 初始化核心业务实例销毁进程..."
            systemctl stop xray nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
            systemctl disable xray nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service /usr/local/bin/xray /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
            systemctl daemon-reload
            rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
            rm -rf /var/www/html/{*,.[!.]*,..?*} "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/nginx/ssl /root/.acme.sh 2>/dev/null
            crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
            sed -i '/# === System Event Trap: Auto-cleanup Session Traces ===/,/trap cleanup_on_exit EXIT SIGHUP/d' /root/.bashrc 2>/dev/null
            [[ -f /home/admin/.bashrc ]] && sed -i '/# === System Event Trap: Auto-cleanup Session Traces ===/,/trap cleanup_on_exit EXIT SIGHUP/d' /home/admin/.bashrc 2>/dev/null
            echo -e "\n${C_YELLOW}业务数据集清理周期完毕。${C_RESET}"
            echo -e "${C_RED}是否申请扩大清理范围，执行【底层依赖物理销毁】？${C_RESET}"
            read -rp "如主机存在复用应用逻辑，请回绝该申请！[y/N, 默认 N]: " SCORCHED_EARTH
            case "${SCORCHED_EARTH}" in
                [yY][eE][sS]|[yY])
                    log_info "接收确认指令，释放系统底层依赖库区..."
                    apt-get purge -yqq nginx nginx-common socat qrencode jq cron >/dev/null 2>&1
                    apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean >/dev/null 2>&1
                    log_ok "系统依赖空间重置成功。" ;;
                *) log_info "系统级软件包状态保留。" ;;
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
