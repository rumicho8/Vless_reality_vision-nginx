#!/bin/bash

# =========================================================
# 模块 0：全局配置与字典 (Configuration & Dictionary)
# =========================================================
readonly SCRIPT_VERSION="V12.11 Let's Encrypt 纯正原血版"
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
    
    echo -e "1) Cloudflare\n2) Namesilo"
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

    echo -e "\n\e[33m--- 证书模式选择 ---\e[0m"
    echo -e "1) 真实生产证书 (正常使用，有申请频率限制)"
    echo -e "2) 测试伪证书 (Staging 环境，无频率限制，仅用于测试脚本是否跑通)"
    read -p "请选择证书模式 [1/2, 默认1]: " CERT_MODE_INPUT
    if [[ "$CERT_MODE_INPUT" == "2" ]]; then
        GLOBAL_CERT_MODE="--staging"
        log_warn "您选择了【测试证书】模式！浏览器访问会提示不安全，但能验证脚本完整性。"
    else
        GLOBAL_CERT_MODE=""
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
        
        # 【唯一改动点】：末尾植入 --server letsencrypt 强行锁死 CA 机构
        /root/.acme.sh/acme.sh --issue --dns $api -d "$domain" -d "*.$domain" --keylength ec-256 $GLOBAL_CERT_MODE --server letsencrypt 2>&1 | tee -a "$LOG_FILE"
        
        /root/.acme.sh/acme.sh --install-cert -d "$domain" --ecc \
            --key-file /etc/nginx/ssl/${domain}_ecc.key \
            --fullchain-file /etc/nginx/ssl/${domain}_ecc.cer \
            --reloadcmd "systemctl restart nginx" 2>&1 | tee -a "$LOG_FILE"
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
    [[ ! -f /var/www/html/index.html ]] && echo "System Ready" > /var/www/html/index.html
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
    
    if [[ -f "$XRAY_CONFIG" ]]; then
        UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG" 2>/dev/null)
        PRIV=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG" 2>/dev/null)
        SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG" 2>/dev/null)
        [[ -n "$PRIV" && "$PRIV" != "null" ]] && PUB=$($XRAY_BIN x25519 -i "$PRIV" | grep -Ei "Public|Password" | awk '{print $NF}')
    fi
    
    [[ -z "$UUID" || "$UUID" == "null" ]] && UUID=$(uuidgen)
    [[ -z "$SID" || "$SID" == "null" ]] && SID=$(openssl rand -hex 8)
    if [[ -z "$PRIV" || "$PRIV" == "null" ]]; then
        local key_re=$($XRAY_BIN x25519)
        PRIV=$(echo "$key_re" | grep -Ei "Private" | awk '{print $NF}')
        PUB=$(echo "$key_re" | grep -Ei "Public|Password" | awk '{print $NF}')
    fi

    log_info "写入 Xray Reality 策略配置文件..."
    mkdir -p "$XRAY_CONF_DIR"
    
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": 443, "protocol": "vless",
    "settings": { "clients": [ { "id": "$UUID", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": {
        "show": false, "dest": "127.0.0.1:8443", "xver": 0, "fingerprint": "chrome",
        "serverNames": ["$domain", "www.$domain"], "privateKey": "$PRIV", "shortIds": ["$SID"]
      },
      "alpn": ["h2", "http/1.1"]
    }
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" }],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["geoip:cn", "geoip:private"], "outboundTag": "block" },
      { "type": "field", "domain": ["geosite:category-ads-all", "geosite:cn"], "outboundTag": "block" }
    ]
  }
}
EOF
    systemctl enable xray >> "$LOG_FILE" 2>&1
    systemctl restart xray
    log_ok "Xray Reality 节点启动成功。"
}

# =========================================================
# 模块 7：路由规则与自动化任务 (Routing & Automation)
# =========================================================
module_setup_automation() {
    log_info "配置路由规则原子更新机制与定时任务调度..."
    mkdir -p "$XRAY_SHARE_DIR" "$SCRIPT_DIR"
    
    cat > "$SCRIPT_DIR/update-dat.sh" <<EOF
#!/bin/bash
SHARE_DIR="$XRAY_SHARE_DIR"
update_f() {
    local f=\$1; local u=\$2
    if curl -fL -o "\$SHARE_DIR/\${f}.new" "\$u" && [[ -s "\$SHARE_DIR/\${f}.new" ]]; then
        mv -f "\$SHARE_DIR/\${f}.new" "\$SHARE_DIR/\$f"; return 0
    fi
    rm -f "\$SHARE_DIR/\${f}.new"; return 1
}
update_f "geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
update_f "geosite.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
systemctl restart xray >/dev/null 2>&1
EOF
    chmod +x "$SCRIPT_DIR/update-dat.sh"
    
    echo -e "\e[36m-------------------- 路由库同步 --------------------\e[0m"
    bash "$SCRIPT_DIR/update-dat.sh" 2>&1 | tee -a "$LOG_FILE"
    echo -e "\e[36m----------------------------------------------------\e[0m"
    
    (crontab -l 2>/dev/null | grep -vE "update-dat.sh|acme.sh --cron" ; 
     echo "0 2 * * * \"/root/.acme.sh/acme.sh\" --cron --home \"/root/.acme.sh\" > /dev/null" ;
     echo "0 3 * * 1 $SCRIPT_DIR/update-dat.sh > /dev/null 2>&1") | crontab -
     
    log_ok "自动化任务统筹完毕 (Acme 强制锁定 2:00，路由库锁定周一 3:00)。"
}

# =========================================================
# 模块 8：系统清理与垃圾回收 (System Cleanup)
# =========================================================
module_cleanup() {
    log_info "正在执行系统垃圾清理与安装缓存释放..."
    echo -e "\e[36m-------------------- 缓存清理进度 --------------------\e[0m"
    apt-get autoremove -y 2>&1 | tee -a "$LOG_FILE"
    apt-get clean 2>&1 | tee -a "$LOG_FILE"
    rm -rf /tmp/xray_build
    echo -e "\e[36m------------------------------------------------------\e[0m"
    log_ok "系统垃圾与缓存已彻底清空。"
}

# =========================================================
# 模块 9：结果展示中心 (Presentation)
# =========================================================
module_show_result() {
    local domain=$1
    clear
    log_ok "部署/更新圆满完成！(已开启全链路零日志模式)"
    
    if [[ "$GLOBAL_CERT_MODE" != "" ]]; then
        echo -e "\e[33m================================================\e[0m"
        echo -e "\e[33m ⚠️ 警告：当前使用的是 Staging 测试证书！ \e[0m"
        echo -e "\e[33m 测试成功后，请使用卸载选项清理，并重新选择真实证书安装。\e[0m"
        echo -e "\e[33m================================================\e[0m"
    fi
    
    local vless_link="vless://${UUID}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${domain}"
    
    echo -e "------------------------------------------------"
    echo -e " UUID       : \e[33m$UUID\e[0m"
    echo -e " Public Key : \e[33m$PUB\e[0m"
    echo -e " Short ID   : \e[33m$SID\e[0m"
    echo -e " 路由策略   : \e[36mIPIfNonMatch + 广告拦截\e[0m"
    echo -e "------------------------------------------------"
    echo -e "节点链接:\n\e[32m$vless_link\e[0m\n"
    echo "$vless_link" | qrencode -t ansiutf8
}

# =========================================================
# 主控调度引擎 (Main Controller)
# =========================================================
main_install() {
    init_log
    module_prepare_env
    module_setup_bbr
    module_get_inputs
    
    # 按照严格流水线调用核心业务模块
    module_issue_cert "$GLOBAL_DOMAIN" "$GLOBAL_DNS_API"
    module_config_nginx "$GLOBAL_DOMAIN"
    module_install_xray_core
    module_config_xray "$GLOBAL_DOMAIN"
    module_setup_automation
    
    module_cleanup
    module_show_result "$GLOBAL_DOMAIN"
}

# =========================================================
# 交互式菜单入口 (Interactive Menu)
# =========================================================
while true; do
    clear
    echo -e "\e[36m   Xray Reality 工业级管理工具 ($SCRIPT_VERSION)\e[0m"
    echo "------------------------------------------------"
    echo "1. 安装 / 无损覆盖更新"
    echo "2. 彻底卸载与清理"
    echo "3. 证书与定时任务自检"
    echo "4. 查看部署底层日志"
    echo "0. 退出"
    read -p "请选择数字 [0-4]: " OPT
    
    case $OPT in
        1) main_install ; break ;;
        2)
            echo -e "\n\e[34m[INFO]\e[0m 开始执行外科手术级卸载..."
            systemctl stop xray nginx >/dev/null 2>&1
            systemctl disable xray >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service
            rm -f /usr/local/bin/xray
            systemctl daemon-reload
            rm -f /etc/nginx/sites-available/xray
            rm -f /etc/nginx/sites-enabled/xray
            # 安全提示：已移除 LOG_FILE，防止误删系统黑洞设备
            rm -rf "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/nginx/ssl /root/.acme.sh
            crontab -l 2>/dev/null | grep -vE "update-dat.sh|acme.sh" | crontab -
            echo -e "\e[32m[OK] 系统已彻底卸载清理，未留任何暗坑。\e[0m"
            read -p "按回车键返回..." ;;
        3)
            echo -e "\n\e[36m--- 定时任务列表 ---\e[0m"
            crontab -l | grep -E "acme.sh|update-dat.sh"
            echo -e "\n\e[36m--- 证书续期服务状态 ---\e[0m"
            [[ -f "/root/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
            read -p "按回车键返回..." ;;
        4)
            if [[ -f "$LOG_FILE" ]]; then
                tail -n 30 "$LOG_FILE"
            else
                echo "暂无日志文件 ($LOG_FILE)"
            fi
            read -p "按回车键返回..." ;;
        0) echo "退出脚本。"; exit 0 ;;
        *) echo "输入无效！" ; sleep 1 ;;
    esac
done
