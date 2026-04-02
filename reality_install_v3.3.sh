#!/bin/bash
# =========================================================
# Xray Reality 工业级部署脚本 (Advanced Stealth Edition)
# 架构: VLESS + XTLS-Vision + Reality + Nginx 回落 + 防溯源
# =========================================================

# --- 提权与执行检查 ---
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ERROR] 安全拦截：必须使用 Root 权限运行此部署引擎。\e[0m"
    echo -e "\e[33m请先执行 'sudo -i' 或 'su -' 彻底切换到 root 环境后，再次运行本脚本。\e[0m"
    exit 1
fi

# =========================================================
# 模块 0：全局配置与核心变量
# =========================================================
readonly SCRIPT_VERSION="Pro Final V8 (Ultimate HA Edition)"
readonly LOG_FILE="/dev/null"
readonly XRAY_CONF_DIR="/usr/local/etc/xray"
readonly XRAY_SHARE_DIR="/usr/local/share/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly XRAY_CONFIG="$XRAY_CONF_DIR/config.json"
readonly SCRIPT_DIR="/usr/local/etc/xray-script"

# 颜色定义
readonly C_RED="\e[31m"
readonly C_GREEN="\e[32m"
readonly C_YELLOW="\e[33m"
readonly C_BLUE="\e[36m"
readonly C_RESET="\e[0m"

# 环境变量锁死 (Debian 非交互式标准)
export AUTO_UPGRADE='0'
export LE_NO_LOG=1
export LE_LOG_FILE='/dev/null'
export DEBUG=0
export DEBIAN_FRONTEND="noninteractive"
export APT_LISTCHANGES_FRONTEND="none"

# 全局状态变量初始化
GLOBAL_INSTALL_MODE="1"
GLOBAL_DOMAIN=""
GLOBAL_PUBLIC_SNI=""
GLOBAL_DNS_API=""
GLOBAL_CF_TOKEN=""
GLOBAL_CF_ZONE_ID=""
GLOBAL_NAMESILO_KEY=""
GLOBAL_CERT_MODE=""
GLOBAL_PORT=""

# =========================================================
# 模块 1：底层核心工具库
# =========================================================
log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

# =========================================================
# 模块 2：环境准备与基础依赖
# =========================================================
module_prepare_env() {
    log_info "初始化系统环境与核心目录..."

    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    log_info "正在同步软件源并安装基础工具组件..."
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    
    apt-get update -yqq >/dev/null 2>&1
    apt-get install -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        curl nginx openssl uuid-runtime socat tar cron qrencode jq lsof unzip >/dev/null 2>&1
        
    local deps=("curl" "jq" "nginx" "lsof" "openssl")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "关键组件 [$cmd] 安装失败，请检查系统源或网络连通性。"
        fi
    done
    
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    
    log_ok "底层运行环境准备完毕。"
}

module_setup_bbr() {
    log_info "检查系统 BBR 加速状态..."
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        log_ok "BBR 拥塞控制算法已成功开启。"
    else
        log_ok "BBR 已处于开启状态。"
    fi
}

# =========================================================
# 模块 3：交互与参数获取
# =========================================================
module_get_inputs() {
    echo -e "\n${C_YELLOW}--- 架构模式选择 ---${C_RESET}"
    echo -e "1) 闭环回落模式 (需自有域名 + 自动签发证书 + Nginx 本地伪装，最稳定防封)"
    echo -e "2) 纯净无域名模式 (无需域名，直接借用大厂公共 SNI 伪装，极简快速)"
    read -rp "请选择模式 [1/2, 默认 1]: " MODE_INPUT
    GLOBAL_INSTALL_MODE=${MODE_INPUT:-1}

    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        read -rp "请输入解析到本机的域名: " GLOBAL_DOMAIN
        GLOBAL_DOMAIN=$(echo "$GLOBAL_DOMAIN" | sed 's/^www\.//g' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        
        [[ -z "$GLOBAL_DOMAIN" ]] && log_err "域名不能为空！"
        
        echo -e "\n${C_BLUE}正在检测域名解析状态...${C_RESET}"
        local local_ip
        local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        
        local domain_ip=""
        domain_ip=$(curl -sm 5 -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=$GLOBAL_DOMAIN&type=A" 2>/dev/null | jq -r 'if .Answer then [.Answer[] | select(.type == 1) | .data][0] else empty end')
        [[ -z "$domain_ip" ]] && domain_ip=$(curl -sm 5 -H "accept: application/dns-json" "https://dns.google/resolve?name=$GLOBAL_DOMAIN&type=A" 2>/dev/null | jq -r 'if .Answer then [.Answer[] | select(.type == 1) | .data][0] else empty end')
        
        echo -e "本机公网 IP : ${C_YELLOW}${local_ip:-"未获取到"}${C_RESET}"
        echo -e "域名解析 IP : ${C_YELLOW}${domain_ip:-"未获取到解析"}${C_RESET}"
        
        if [[ -n "$local_ip" && "$local_ip" == "$domain_ip" ]]; then
            echo -e "${C_GREEN}[OK] 匹配成功！域名已正确解析到本机 IP。${C_RESET}\n"
        else
            echo -e "${C_RED}[WARN] 警告！域名解析与本机 IP 不匹配。(如果刚改解析可能存在缓存延迟，或使用了 CDN)${C_RESET}\n"
        fi

        get_listen_port
        
        echo -e "1) DNS API 模式 (推荐，需提供 Key，支持通配符证书)"
        echo -e "2) HTTP 独立模式 (免 Key，要求域名必须准确解析到本机)"
        read -rp "选择验证模式 [1/2, 默认1]: " VERIFY_TYPE
        
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            GLOBAL_DNS_API="standalone"
        else
            echo -e "\n1) Cloudflare\n2) Namesilo"
            read -rp "选择 DNS API 提供商 [1/2]: " DNS_TYPE
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

        echo -e "\n${C_YELLOW}--- 证书模式选择 ---${C_RESET}"
        echo -e "1) 真实生产证书 (正常使用，有申请频率限制)"
        echo -e "2) 测试伪证书 (Staging 环境，无频率限制，仅用于测试脚本是否跑通)"
        read -rp "请选择证书模式 [1/2, 默认1]: " CERT_MODE_INPUT
        if [[ "$CERT_MODE_INPUT" == "2" ]]; then
            GLOBAL_CERT_MODE="--staging"
            log_warn "您选择了【测试证书】模式！浏览器访问会提示不安全，但能验证脚本完整性。"
        else
            GLOBAL_CERT_MODE="--server letsencrypt"
            log_info "您选择了【真实生产证书】模式。"
        fi

    else
        echo -e "\n${C_BLUE}--- 无域名模式配置 ---${C_RESET}"
        echo -e "推荐使用连通性好的大厂域名，如: www.apple.com, gateway.icloud.com, www.yahoo.com"
        read -rp "请输入用于伪装的公共 SNI 域名 [默认 www.apple.com]: " PUBLIC_SNI_INPUT
        GLOBAL_PUBLIC_SNI=${PUBLIC_SNI_INPUT:-"www.apple.com"}
        GLOBAL_PUBLIC_SNI=$(echo "$GLOBAL_PUBLIC_SNI" | sed 's/^https:\/\///g' | sed 's/^http:\/\///g' | sed 's/\/$//g' | tr -d '[:space:]')
        get_listen_port
    fi
}

get_listen_port() {
    while true; do
        read -rp "请输入 Xray 监听端口 (1-65535) [默认 443]: " PORT_INPUT
        GLOBAL_PORT=${PORT_INPUT:-443}
        if ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
            log_warn "端口格式错误，请输入 1-65535 之间的数字！"
            continue
        fi
        if lsof -i :"$GLOBAL_PORT" >/dev/null 2>&1; then
            log_warn "端口 $GLOBAL_PORT 已被占用，请更换其他端口！"
        else
            log_ok "选定监听端口: $GLOBAL_PORT\n"
            break
        fi
    done
}

# =========================================================
# 模块 4：证书管理中心
# =========================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local acme_bin="/root/.acme.sh/acme.sh"

    if [[ ! -s "$cert_file" ]]; then
        log_info "启动 Acme.sh 申请 ECC 证书 ($domain)..."
        
        local tmp_acme="/tmp/acme_$(date +%s)"
        mkdir -p "$tmp_acme" && cd "$tmp_acme" || log_err "无法创建临时目录"
        
        echo -e "${C_BLUE}------------------- 证书申请进度 -------------------${C_RESET}"
        curl -sm 15 https://get.acme.sh | sh -s email="admin@${domain}"
        
        [[ ! -f "$acme_bin" ]] && log_err "Acme.sh 核心安装失败！"
        
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
        echo -e "${C_BLUE}----------------------------------------------------${C_RESET}"
            
        cd "$HOME" && rm -rf "$tmp_acme"
        
        if [[ -s "$cert_file" ]]; then
            log_ok "SSL 证书申请并签发成功。"
            # === 注入全局无痕配置 ===
            local acme_conf="/root/.acme.sh/account.conf"
            if [[ -f "$acme_conf" ]]; then
                grep -q "LE_NO_LOG" "$acme_conf" || echo "LE_NO_LOG='1'" >> "$acme_conf"
                grep -q "LE_LOG_FILE" "$acme_conf" || echo "LE_LOG_FILE='/dev/null'" >> "$acme_conf"
                grep -q "DEBUG" "$acme_conf" || echo "DEBUG='0'" >> "$acme_conf"
                log_info "已将极致无痕变量硬编码至 Acme.sh 核心配置。"
            fi
        else
            log_err "SSL 证书申请失败！请检查上方输出的 API 报错信息。"
        fi
    else
        log_info "检测到有效证书，跳过申请步骤。"
    fi
}

# =========================================================
# 模块 5：Nginx Web 防护中心 (包含强制进度与防空物理核验)
# =========================================================
module_config_nginx() {
    local domain=$1
    log_info "应用 Nginx 全局优化配置与安全套件..."

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

    log_info "部署伪装站点与 HTTP 强制重定向..."
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
        log_err "Nginx 配置语法验证失败，可能是证书路径无效，已阻断重启！"
    fi

    log_info "正在从 GitHub 拉取高级伪装站模板..."

    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"

    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* "${target_dir:?}/"..?* 2>/dev/null

    echo -e "${C_BLUE}------------------- 模板拉取进度 -------------------${C_RESET}"

    if curl -fL -# \
        --connect-timeout 10 \
        --max-time 120 \
        --retry 3 \
        --retry-delay 2 \
        --retry-connrefused \
        -o /tmp/web_template.zip \
        "https://codeload.github.com/rumicho8/Nginx-3DCEList/zip/refs/heads/main"; then

        echo -e "${C_BLUE}------------------- 执行解压部署 -------------------${C_RESET}"

        mkdir -p "$temp_extract"

        if unzip -qo /tmp/web_template.zip -d "$temp_extract"; then

            inner_dir=$(find "$temp_extract" -mindepth 1 -maxdepth 1 -type d | head -n1)

            [[ -d "$inner_dir" ]] || log_err "模板目录解析失败"

            cp -a "$inner_dir"/. "$target_dir/" 2>/dev/null

            log_ok "静态资源文件解压归位成功。"
        else
            log_err "解压失败，请检查 unzip 是否安装。"
        fi

        rm -rf "$temp_extract" /tmp/web_template.zip 2>/dev/null

    else
        echo -e "${C_RED}✖ 模板下载失败（重试3次仍失败）${C_RESET}"
    fi

    echo -e "${C_BLUE}----------------------------------------------------${C_RESET}"

    if [[ ! -s "$target_dir/index.html" ]]; then
        log_warn "检测到站点内容缺失，注入 403 页面"
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="background-color:black;color:white;text-align:center;padding-top:20%"><p>403 Forbidden</p><hr><p>nginx</p></body></html>' > "$target_dir/index.html"
    else
        log_ok "伪装站点已上线"
    fi

    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || log_err "Nginx 服务启动异常。"
    log_ok "Web 防护与前置代理就绪 (配置已原子化生效)。"
}

# =========================================================
# 模块 6：Xray 核心调度中心
# =========================================================
module_install_xray_core() {
    log_info "正在拉取 Xray 稳定版核心程序..."
    local arch
    arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    local tmp_xray="/tmp/xray_build"
    mkdir -p "$tmp_xray" && cd "$tmp_xray"
    
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    
    echo -e "${C_BLUE}------------------- 核心下载进度 -------------------${C_RESET}"
    # 使用 15s 握手超时，120s 总任务超时，且失败后自动重试 3 次
    if curl -fL -# \
       --connect-timeout 15 \
       --retry 3 \
       --retry-delay 2 \
       -m 120 \
       -o "$zip_name" "$zip_url"; then
        log_ok "核心下载成功"
    else
        log_err "核心下载失败，请检查网络连通性"
    fi
    echo -e "${C_BLUE}----------------------------------------------------${C_RESET}"
    
    unzip -qo "$zip_name" || log_err "包解压异常，文件可能损坏。"
    
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
    log_ok "Xray 核心装载完毕。"
}

module_config_xray() {
    local domain=$1
    log_info "正在进行身份鉴权与持久化处理..."
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        PRIV=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
    fi
    
    [[ -z "$UUID" || "$UUID" == "null" ]] && UUID=$(uuidgen)
    [[ -z "$SID" || "$SID" == "null" ]] && SID=$(openssl rand -hex 8)
    
# === 终极防御机制：语义锚定 + X25519 单向推导双重校验 ===
    if [[ -z "$PRIV" || "$PRIV" == "null" ]]; then
        local key_re="$($XRAY_BIN x25519 | tr -d '\r')"
        
        # 第一层防御（语义过滤）：只提取带有核心标识的行，将 Hash32 或未来的未知副密钥踢出候选池
        mapfile -t KEYS < <(echo "$key_re" | grep -iE "Private|Public|Password" | grep -oE '[A-Za-z0-9_-]{43}')
        
        PRIV=""
        PUB=""
        
        # 第二层防御（数学验证）：在受信任的集合内，寻找唯一成立的标量乘法关系
        for p_priv in "${KEYS[@]}"; do
            # 利用 Xray 工具自身推导，提取算出的公钥
            local calc_pub=$($XRAY_BIN x25519 -i "$p_priv" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
            
            # 严格判定：推导出的公钥不仅要是 43 位，且必须存在于我们刚才过滤出的 KEYS 集合中！
            for p_pub in "${KEYS[@]}"; do
                if [[ "$calc_pub" == "$p_pub" && "$p_priv" != "$p_pub" ]]; then
                    PRIV="$p_priv"
                    PUB="$p_pub"
                    break 2 # 匹配成功，瞬间击碎双重循环
                fi
            done
        done
        
    else
        # 若已有私钥，则直接推导公钥
        PUB=$($XRAY_BIN x25519 -i "$PRIV" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
    fi

    # 终极底线拦截与 DEBUG 输出
    [[ ${#PRIV} -eq 43 && ${#PUB} -eq 43 ]] || {
        echo -e "\n${C_RED}[DEBUG] 核心输出异常流：\n${key_re}${C_RESET}"
        log_err "密钥解析失败！PRIV:${#PRIV} PUB:${#PUB}"
    }
    
    log_ok "全链路密钥解析成功 (43/43位验证通过)"
    
    mkdir -p "$XRAY_CONF_DIR"
    local dest_addr="127.0.0.1:8443"
    local server_names_json="[\"$domain\", \"www.$domain\"]"
    
    if [[ "$GLOBAL_INSTALL_MODE" == "2" ]]; then
        dest_addr="$GLOBAL_PUBLIC_SNI:443"
        server_names_json="[\"$GLOBAL_PUBLIC_SNI\"]"
    fi
    
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
    systemctl restart xray || log_err "Xray 核心策略写入完毕，但启动失败，请检查端口占用。"
    log_ok "Xray Reality 核心策略写入完毕"
}

# =========================================================
# 模块 7：路由规则与自动化任务 (Systemd Timers 高可用架构)
# =========================================================
module_setup_automation() {
    log_info "配置路由规则原子更新机制与定时任务调度..."
    mkdir -p "$SCRIPT_DIR"

    # === 1. 生成具备状态校验、防重入锁、重试机制的更新脚本 ===
    cat > "$SCRIPT_DIR/update-dat.sh" <<'EOF'
#!/bin/bash

# [高阶防御 1] 文件描述符互斥锁，绝对防止 Timer 与手动执行并发产生 Race Condition
exec 9> /var/lock/xray-dat.lock
flock -n 9 || exit 0

SHARE_DIR="/usr/local/share/xray"
changed=0

update_f() {
    local f=$1
    local u=$2
    # [高阶防御 2] 增加重试退避机制与双重超时，抵抗 GitHub CDN 抖动
    if curl -fL \
        --connect-timeout 10 \
        --max-time 120 \
        --retry 3 \
        --retry-delay 5 \
        --retry-connrefused \
        -o "$SHARE_DIR/${f}.new" "$u" && [[ -s "$SHARE_DIR/${f}.new" ]]; then
        
        # 核心优化：二进制比对，只有真实变化才触发后续重载逻辑
        if ! cmp -s "$SHARE_DIR/${f}.new" "$SHARE_DIR/$f"; then
            mv -f "$SHARE_DIR/${f}.new" "$SHARE_DIR/$f"
            changed=1
            return 0
        fi
    fi
    rm -f "$SHARE_DIR/${f}.new"
    return 1
}

update_f "geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
update_f "geosite.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

# [高阶防御 3] 仅在变更时触发，且优先尝试平滑重载 (Reload) 保护活跃连接，失败才重启
if [[ $changed -eq 1 ]]; then
    systemctl reload xray 2>/dev/null || systemctl restart xray >/dev/null 2>&1
fi
EOF

    # 确保脚本可执行
    chmod +x "$SCRIPT_DIR/update-dat.sh"

    echo -e "\e[36m-------------------- 路由库同步 --------------------\e[0m"
    bash "$SCRIPT_DIR/update-dat.sh" 2>&1 | tee -a "$LOG_FILE"
    echo -e "\e[36m----------------------------------------------------\e[0m"

    # === 清理旧 cron (精准打击，防误杀) ===
    # 修复：使用正则表达式 acme\.sh.*--cron，兼容官方脚本自动带上的双引号问题 (不再清理 CRON_TZ)
    crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true

    # === 部署 Systemd Timers 原子化调度 ===

    # [1] 路由库 Service (加入 TimeoutStartSec 防僵尸进程)
    cat > /etc/systemd/system/xray-dat.service <<EOF
[Unit]
Description=Xray Dat Update Service

[Service]
Type=oneshot
WorkingDirectory=/root
ExecStart=$SCRIPT_DIR/update-dat.sh
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TimeoutStartSec=2min
Restart=on-failure
RestartSec=60
EOF

    # [1] 路由库 Timer（每周一 03:00 新加坡时间）
    cat > /etc/systemd/system/xray-dat.timer <<EOF
[Unit]
Description=Timer for Xray Dat Update (SGT)

[Timer]
OnCalendar=Mon *-*-* 03:00:00 Asia/Singapore
Persistent=true
RandomizedDelaySec=10m
AccuracySec=1m

[Install]
WantedBy=timers.target
EOF

    # [2] ACME 证书续期（每天 02:00 新加坡时间）
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then

        cat > /etc/systemd/system/xray-acme.service <<EOF
[Unit]
Description=Acme.sh Certificate Renewal Service

[Service]
Type=oneshot
WorkingDirectory=/root
ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TimeoutStartSec=5min
Restart=on-failure
RestartSec=60
EOF

        cat > /etc/systemd/system/xray-acme.timer <<EOF
[Unit]
Description=Timer for Acme.sh Renewal (SGT)

[Timer]
OnCalendar=*-*-* 02:00:00 Asia/Singapore
Persistent=true
RandomizedDelaySec=5m
AccuracySec=1m

[Install]
WantedBy=timers.target
EOF
    else
        # [逻辑修正：状态收敛] 如果用户从模式 1 切回模式 2，必须彻底绞杀并拔除上一任的 ACME 定时器
        systemctl stop xray-acme.timer xray-acme.service >/dev/null 2>&1 || true
        systemctl disable xray-acme.timer xray-acme.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/xray-acme.*
    fi

    # === 加载并启用 ===
    systemctl daemon-reload

    systemctl enable --now xray-dat.timer >/dev/null 2>&1

    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        systemctl enable --now xray-acme.timer >/dev/null 2>&1
        log_ok "自动化任务统筹完毕 (SGT：Acme 每天 02:00，路由库每周一 03:00)"
    else
        log_ok "自动化任务统筹完毕 (纯净模式：仅路由库定时器，SGT 周一 03:00)"
    fi

    log_ok "Xray Reality 节点启动成功。"
}

# =========================================================
# 模块 8：极致隐私防护模块 (Stealth Mode)
# =========================================================
module_setup_stealth() {
    echo -e "\n${C_YELLOW}--- 极致隐私模式 (SSH 离场自毁陷阱) ---${C_RESET}"
    echo -e "开启后，每次退出 SSH 窗口将自动物理清空：\n 1. 所有输入的历史命令\n 2. 所有的系统日志和 SSH 登录记录\n ${C_RED}警告：开启后系统将绝对无痕，但节点报错时将无法查看日志进行排错！${C_RESET}"
    read -rp "是否开启极致隐私模式？[y/N]: " enable_stealth
    
    case "${enable_stealth}" in
        [yY][eE][sS]|[yY])
            log_info "正在为系统注入 SSH 断开自动自毁陷阱..."
            local TRAP_CODE="
# === 系统级安全无痕审计防护 (自动注入) ===
cleanup_on_exit() {
    # 仅在 SSH 连接真实断开时触发清理，忽略子 Shell 退出
    if [ -n \"\$SSH_CLIENT\" ] || [ -n \"\$SSH_TTY\" ]; then
        cd / >/dev/null 2>&1
        history -c
        rm -f \$HOME/.bash_history
        local SUDO_CMD=\"\"
        command -v sudo >/dev/null 2>&1 && SUDO_CMD=\"sudo\"
        \$SUDO_CMD journalctl --rotate >/dev/null 2>&1
        \$SUDO_CMD journalctl --vacuum-time=1s >/dev/null 2>&1
        [ -f /var/log/auth.log ] && \$SUDO_CMD truncate -s 0 /var/log/auth.log >/dev/null 2>&1
    fi
}
trap cleanup_on_exit EXIT SIGHUP"

            for target_rc in "/root/.bashrc" "/home/admin/.bashrc"; do
                if [[ -f "$target_rc" ]] && ! grep -q "cleanup_on_exit" "$target_rc"; then
                    echo "$TRAP_CODE" >> "$target_rc"
                    [[ "$target_rc" == "/home/admin/.bashrc" ]] && chown admin:admin "$target_rc"
                fi
            done
            log_ok "审计阻断陷阱注入完毕。"
            ;;
        *)
            log_info "已跳过极致隐私模式配置，保留常规日志以供排错."
            ;;
    esac
}

# =========================================================
# 模块 9：系统清理与垃圾回收
# =========================================================
module_cleanup() {
    log_info "正在执行系统垃圾清理与安装缓存释放..."
    apt-get autoremove -yqq >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1
    log_ok "系统垃圾与缓存已彻底清空。"
}

# =========================================================
# 模块 10：结果展示中心
# =========================================================
module_show_result() {
    clear
    log_ok "部署/更新圆满完成！(已开启全链路优化模式)"
    
    local client_addr client_sni
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        client_addr="$GLOBAL_DOMAIN"
        client_sni="$GLOBAL_DOMAIN"
        if [[ "$GLOBAL_CERT_MODE" == "--staging" ]]; then
            echo -e "${C_YELLOW}================================================${C_RESET}"
            echo -e "${C_YELLOW} ⚠️ 警告：当前使用的是 Staging 测试证书！ ${C_RESET}"
            echo -e "${C_YELLOW} 测试成功后，请使用卸载选项清理，并重新选择真实证书安装。${C_RESET}"
            echo -e "${C_YELLOW}================================================${C_RESET}"
        fi
    else
        local local_ip
        local_ip=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        client_addr="${local_ip:-"你的VPS_IP"}"
        client_sni="$GLOBAL_PUBLIC_SNI"
    fi
    
    local vless_link="vless://${UUID}@${client_addr}:${GLOBAL_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${client_sni}"
    
    echo -e "------------------------------------------------"
    echo -e " 监听端口    : ${C_YELLOW}$GLOBAL_PORT${C_RESET}"
    echo -e " UUID        : ${C_YELLOW}$UUID${C_RESET}"
    echo -e " Public Key  : ${C_YELLOW}$PUB${C_RESET}"
    echo -e " Short ID    : ${C_YELLOW}$SID${C_RESET}"
    echo -e " 伪装 SNI    : ${C_BLUE}$client_sni${C_RESET}"
    echo -e " 路由策略    : ${C_BLUE}IPIfNonMatch + 广告拦截${C_RESET}"
    echo -e "------------------------------------------------"
    echo -e "节点链接:\n${C_GREEN}$vless_link${C_RESET}\n"
    echo "$vless_link" | qrencode -t ansiutf8
}

# =========================================================
# 主控调度引擎
# =========================================================
main_install() {
    cd "$HOME" || exit 1
    systemctl stop xray nginx >/dev/null 2>&1
    
    module_prepare_env
    module_setup_bbr
    module_get_inputs
    
    if [[ "$GLOBAL_INSTALL_MODE" == "1" ]]; then
        module_issue_cert "$GLOBAL_DOMAIN" "$GLOBAL_DNS_API"
        module_config_nginx "$GLOBAL_DOMAIN"
    else
        log_info "纯净无域名模式：跳过 SSL 证书申请与 Nginx 伪装部署。"
    fi
    
    module_install_xray_core
    module_config_xray "$GLOBAL_DOMAIN"
    module_setup_automation
    module_setup_stealth
    module_cleanup
    module_show_result
}

# =========================================================
# 交互式菜单入口
# =========================================================
while true; do
    clear
    echo -e "${C_BLUE}    Xray Reality 工业级管理工具 ($SCRIPT_VERSION)${C_RESET}"
    echo "------------------------------------------------"
    echo "1. 安装 / 无损覆盖更新"
    echo "2.彻底卸载与清理"
    echo "3. 证书与定时任务自检"
    echo "0. 退出"
    read -rp "请选择数字 [0-3]: " OPT
    
    case $OPT in
        1) main_install ; break ;;
        2)
            echo -e "\n${C_BLUE}[INFO]${C_RESET} 开始执行外科手术级卸载..."
            systemctl stop xray nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
            systemctl disable xray nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service /usr/local/bin/xray /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
            systemctl daemon-reload
            
            rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
            rm -rf /var/www/html/{*,.[!.]*,..?*} "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/nginx/ssl /root/.acme.sh 2>/dev/null
            
            # [逻辑修正] 拔除 cron 遗留任务时，同步采用严谨的防误删策略 (-vF 精准剔除，不再清理 CRON_TZ)
            crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
            
            sed -i '/# === 系统级安全无痕审计防护/,/trap cleanup_on_exit EXIT SIGHUP/d' /root/.bashrc 2>/dev/null
            [[ -f /home/admin/.bashrc ]] && sed -i '/# === 系统级安全无痕审计防护/,/trap cleanup_on_exit EXIT SIGHUP/d' /home/admin/.bashrc 2>/dev/null
            
            echo -e "${C_GREEN}[OK] 系统已彻底卸载清理，且已拔除历史记录与伪装站源码。${C_RESET}"
            read -rp "按回车键返回..." ;;
        3)
            echo -e "\n${C_BLUE}--- 定时任务列表 (Systemd Timers) ---${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "无调度任务"
            echo -e "\n${C_BLUE}--- 证书续期服务状态 ---${C_RESET}"
            [[ -f "/root/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
            read -rp "按回车键返回..." ;;
        0) echo "退出脚本。"; exit 0 ;;
        *) echo "输入无效！" ; sleep 1 ;;
    esac
done
