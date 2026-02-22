#!/bin/bash

# =========================================================
# 模块 0：全局配置与字典 (Configuration & Dictionary)
# =========================================================
readonly SCRIPT_VERSION="v12.17 (自定义端口 + 极致隐私版 + 续期防死锁)"
readonly LOG_FILE="/dev/null"
readonly XRAY_CONF_DIR="/usr/local/etc/xray"
readonly XRAY_SHARE_DIR="/usr/local/share/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly XRAY_CONFIG="$XRAY_CONF_DIR/config.json"
readonly SCRIPT_DIR="/usr/local/etc/xray-script"

# 环境变量锁死
export AUTO_UPGRADE='0'
export LE_NO_LOG=1
export LE_LOG_FILE='/dev/null'
export DEBUG=0
export DEBIAN_FRONTEND="noninteractive"

# 全局状态变量
GLOBAL_DOMAIN=""
GLOBAL_DNS_API=""
GLOBAL_CF_TOKEN=""
GLOBAL_CF_ZONE_ID=""
GLOBAL_NAMESILO_KEY=""
GLOBAL_CERT_MODE=""
GLOBAL_PORT=""

# =========================================================
# 模块 1：底层核心工具库 (Core Utilities)
# =========================================================
log_info() { echo -e "\e[34m[INFO]\e[0m $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "\e[32m[OK]\e[0m $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "\e[33m[WARN]\e[0m $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "\e[31m[ERROR]\e[0m $1" | tee -a "$LOG_FILE"; exit 1; }

init_log() {
    > "$LOG_FILE"
    echo "=== Xray Reality Installation Log ($(date)) ===" >> "$LOG_FILE"
}

# =========================================================
# 模块 2：环境优化与基础依赖 (Environment & Dependencies)
# =========================================================
module_prepare_env() {
    [[ $EUID -ne 0 ]] && log_err "请使用 root 用户运行本脚本！"
    log_info "初始化系统环境与核心目录..."

    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald

    log_info "正在同步软件源并安装基础工具组件 (实时进度)..."
    echo -e "\e[36m-------------------- APT 运行日志 --------------------\e[0m"
    apt-get update -y 2>&1 | tee -a "$LOG_FILE"
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        curl nginx openssl uuid-runtime socat tar cron qrencode jq lsof unzip 2>&1 | tee -a "$LOG_FILE"
    echo -e "\e[36m------------------------------------------------------\e[0m"

    if ! command -v jq &> /dev/null || ! command -v nginx &> /dev/null; then
        log_err "关键组件安装失败！请检查上方报错或日志文件: $LOG_FILE"
    fi
    
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    
    log_ok "基础运行环境与底层目录池准备完毕。"
}

module_setup_bbr() {
    log_info "检查系统 BBR 加速状态..."
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >> "$LOG_FILE" 2>&1
        log_ok "BBR 拥塞控制算法已成功开启。"
    else
        log_ok "BBR 已处于开启状态，跳过配置。"
    fi
}

# =========================================================
# 模块 3：交互与参数获取 (Interactive Inputs)
# =========================================================
module_get_inputs() {
    read -p "请输入解析到本机的域名: " GLOBAL_DOMAIN
    
    echo -e "\n\e[36m正在检测域名解析状态...\e[0m"
    local local_ip=$(curl -s4 icanhazip.com 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null)
    local domain_ip=$(getent ahosts "$GLOBAL_DOMAIN" | awk '{ print $1 }' | head -1)
    
    echo -e "本机公网 IP : \e[33m${local_ip:-"未获取到"}\e[0m"
    echo -e "域名解析 IP : \e[33m${domain_ip:-"未获取到解析"}\e[0m"
    
    if [[ "$local_ip" == "$domain_ip" && -n "$local_ip" ]]; then
        echo -e "\e[32m[OK] 匹配成功！域名已正确解析到本机 IP。\e[0m"
    else
        echo -e "\e[31m[WARN] 警告！域名解析与本机 IP 不匹配。(如果刚改解析可能存在缓存延迟，或使用了 CDN)\e[0m"
    fi
    echo ""

    read -p "请输入 Xray 监听端口 (1-65535) [默认 443]: " PORT_INPUT
    GLOBAL_PORT=${PORT_INPUT:-443}
    if [[ "$GLOBAL_PORT" == "80" || "$GLOBAL_PORT" == "8443" ]]; then
        log_warn "端口 $GLOBAL_PORT 与 Nginx 内部组件冲突，已自动回退到默认端口 443"
        GLOBAL_PORT=443
    elif ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
        log_warn "输入的端口无效，已自动回退到默认端口 443"
        GLOBAL_PORT=443
    fi
    echo -e "\e[32m[OK] 选定端口: $GLOBAL_PORT\e[0m\n"

    echo -e "1) DNS API 模式 (推荐，需提供 Key，支持通配符证书)"
    echo -e "2) HTTP 独立模式 (免 Key，要求域名必须准确解析到本机)"
    read -p "选择验证模式 [1/2, 默认1]: " VERIFY_TYPE
    
    if [[ "$VERIFY_TYPE" == "2" ]]; then
        GLOBAL_DNS_API="standalone"
    else
        echo -e "\n1) Cloudflare\n2) Namesilo"
        read -p "选择 DNS API 提供商 [1/2]: " DNS_TYPE
        if [[ "$DNS_TYPE" == "1" ]]; then
            GLOBAL_DNS_API="dns_cf"
            read -p "请输入 CF_Token: " GLOBAL_CF_TOKEN
            read -p "请输入 CF_Zone_ID: " GLOBAL_CF_ZONE_ID
            export CF_Token=$GLOBAL_CF_TOKEN
            export CF_Zone_ID=$GLOBAL_CF_ZONE_ID
        else
            GLOBAL_DNS_API="dns_namesilo"
            read -p "请输入 Namesilo_Key: " GLOBAL_NAMESILO_KEY
            export Namesilo_Key=$GLOBAL_NAMESILO_KEY
        fi
    fi

    echo -e "\n\e[33m--- 证书模式选择 ---\e[0m"
    echo -e "1) 真实生产证书 (正常使用，有申请频率限制)"
    echo -e "2) 测试伪证书 (Staging 环境，无频率限制，仅用于测试脚本是否跑通)"
    read -p "请选择证书模式 [1/2, 默认1]: " CERT_MODE_INPUT
    
    if [[ "$CERT_MODE_INPUT" == "2" ]]; then
        GLOBAL_CERT_MODE="--staging"
        log_warn "您选择了【测试证书】模式！浏览器访问会提示不安全，但能验证脚本完整性。"
    else
        GLOBAL_CERT_MODE="--server letsencrypt"
        log_info "您选择了【真实生产证书】模式。"
    fi
}

# =========================================================
# 模块 4：证书管理中心 (SSL/ACME Management)
# =========================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    if [[ ! -f "/etc/nginx/ssl/${domain}_ecc.cer" ]]; then
        log_info "启动 Acme.sh 申请 ECC 证书 ($domain)..."
        echo -e "\e[36m------------------- 证书申请进度 -------------------\e[0m"
        curl -s https://get.acme.sh | sh -s email=admin@$domain 2>&1 | tee -a "$LOG_FILE"
        /root/.acme.sh/acme.sh --upgrade --auto-upgrade "$AUTO_UPGRADE" 2>&1 | tee -a "$LOG_FILE"
        /root/.acme.sh/acme.sh --install-cronjob 2>&1 | tee -a "$LOG_FILE"
        
        if [[ "$api" == "standalone" ]]; then
            systemctl stop nginx >/dev/null 2>&1
            # 【V12.17 修复】：注入前后置钩子，根治独立模式 60 天后自动续期的端口死锁
            /root/.acme.sh/acme.sh --issue -d "$domain" --standalone --keylength ec-256 $GLOBAL_CERT_MODE \
                --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx" 2>&1 | tee -a "$LOG_FILE"
        else
            /root/.acme.sh/acme.sh --issue --dns $api -d "$domain" -d "*.$domain" --keylength ec-256 $GLOBAL_CERT_MODE 2>&1 | tee -a "$LOG_FILE"
        fi
        
        # 【V12.17 优化】：续期时同步重启 nginx 和 xray，确保证书缓存双端刷新生效
        /root/.acme.sh/acme.sh --install-cert -d "$domain" --ecc \
            --key-file /etc/nginx/ssl/${domain}_ecc.key \
            --fullchain-file /etc/nginx/ssl/${domain}_ecc.cer \
            --reloadcmd "systemctl restart nginx xray" 2>&1 | tee -a "$LOG_FILE"
        echo -e "\e[36m----------------------------------------------------\e[0m"
        log_ok "SSL 证书申请并签发成功。"
    else
        log_info "检测到有效证书，跳过申请步骤。"
    fi
}

# =========================================================
# 模块 5：Nginx Web 防护中心 (Nginx Configurations)
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
events { worker_connections 768; }
http {
	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
    server_tokens off;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers on;
	ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
	access_log off;
	gzip on;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
EOF

    log_info "部署伪装站点与 HTTP 强制重定向..."
    rm -f /etc/nginx/sites-enabled/default

    cat > /etc/nginx/sites-available/xray <<EOF
server {
    listen 127.0.0.1:8443 ssl http2;
    ssl_certificate /etc/nginx/ssl/${domain}_ecc.cer;
    ssl_certificate_key /etc/nginx/ssl/${domain}_ecc.key;
    server_name $domain www.$domain;
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
    ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/
    
    log_info "正在从 GitHub 拉取高级伪装站模板..."
    rm -rf /var/www/html/*
    curl -sL -o /tmp/web_template.zip "https://github.com/rumicho8/Nginx-3DCEList/archive/refs/heads/main.zip"
    
    if [[ -f /tmp/web_template.zip ]]; then
        unzip -qo /tmp/web_template.zip -d /tmp/
        cp -r /tmp/Nginx-3DCEList-main/* /var/www/html/
        rm -rf /tmp/web_template.zip /tmp/*-main
        log_ok "伪装站模板覆盖完成。"
    else
        log_warn "网站模板拉取失败，将使用默认兜底页面。"
        echo "System Ready" > /var/www/html/index.html
    fi

    systemctl restart nginx || log_err "Nginx 启动失败，请检查端口被占情况。"
    log_ok "Web 防护与前置代理就绪 (已清除默认站点冲突)。"
}

# =========================================================
# 模块 6：Xray 核心调度中心 (Xray Core & Persistence)
# =========================================================
module_install_xray_core() {
    log_info "正在拉取 Xray 稳定版核心程序 (实时进度)..."
    local arch=$(dpkg --print-architecture)
    [[ "$arch" == "amd64" ]] && local arch_xray="64" || local arch_xray="arm64-v8a"
    
    mkdir -p /tmp/xray_build && cd /tmp/xray_build
    local latest_json=$(curl -sL --connect-timeout 10 "https://api.github.com/repos/XTLS/Xray-core/releases/latest")
    local zip_name="Xray-linux-${arch_xray}.zip"
    local zip_url=$(echo "$latest_json" | jq -r ".assets[] | select(.name==\"$zip_name\") | .browser_download_url")
    
    echo -e "\e[36m-------------------- 下载解压进度 --------------------\e[0m"
    curl -fL -o "$zip_name" "$zip_url" 2>&1 | tee -a "$LOG_FILE" || log_err "核心下载失败。"
    unzip -qo "$zip_name" 2>&1 | tee -a "$LOG_FILE"
    echo -e "\e[36m------------------------------------------------------\e[0m"
    
    mv -f xray "$XRAY_BIN" && chmod +x "$XRAY_BIN"
    
    mkdir -p "$XRAY_SHARE_DIR"
    mv -f geoip.dat geosite.dat "$XRAY_SHARE_DIR/" 2>/dev/null
    
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target
[Service]
User=root
Environment="XRAY_LOCATION_ASSET=$XRAY_SHARE_DIR"
ExecStart=$XRAY_BIN run -config $XRAY_CONFIG
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log_ok "Xray 核心装载完毕。"
}

module_config_xray() {
    local domain=$1
    log_info "正在进行身份鉴权与持久化处理..."
    
    if [[ -f "$XRAY_
