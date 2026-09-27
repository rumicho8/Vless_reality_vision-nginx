#!/bin/bash
# ==============================================================================
# Xray Reality Automation Engine (Stability Edition V4.1 - Ultimate Matrix)
# Architecture: VLESS + XTLS-Vision + Reality + Nginx Reverse Proxy + Hysteria2
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m[ERROR] 权限不足：执行本脚本需要 Root 权限。\e[0m"
    echo -e "\e[33m请执行 'sudo -i' 或 'su -' 获取 Root 权限后重新运行。\e[0m"
    exit 1
fi

# ==============================================================================
# GROUP 1: 全局变量与环境声明 (Globals & Traps)
# ==============================================================================
readonly SCRIPT_VERSION="Pro Final V4.1 (Ultimate Matrix)"
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
OLD_CONFIG_PORT=""
HY2_PASSWORD=""
GLOBAL_IPV4=""
GLOBAL_IPV6=""

# 进程互斥锁检测与自愈 (探活破锁)
if [[ -f "$LOCK_FILE" ]]; then
    OLD_PID=$(cat "$LOCK_FILE" 2>/dev/null)
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo -e "${C_RED}[ERROR] 安装程序已在运行中 (PID: $OLD_PID)，请勿重复执行。${C_RESET}"
        exit 1
    else
        rm -f "$LOCK_FILE"
    fi
fi

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo -e "${C_RED}[ERROR] 安装程序锁已被其他进程持有，请勿重复执行。${C_RESET}"
    exit 1
fi
echo $$ > "$LOCK_FILE"

CLEANUP_LIST=()
trap '[[ ${#CLEANUP_LIST[@]} -gt 0 ]] && rm -rf "${CLEANUP_LIST[@]}" 2>/dev/null' EXIT SIGHUP SIGINT SIGTERM

get_domain_info() {
    local domain=$1
    local dot_count=$(echo "$domain" | tr -cd '.' | wc -c)
    
    if [[ "$domain" == www.* ]]; then
        local root_d="${domain#www.}"
        if getent ahostsv4 "$root_d" >/dev/null 2>&1 || getent ahostsv6 "$root_d" >/dev/null 2>&1; then
            echo "$root_d $domain"
        else
            echo "$domain"
        fi
    elif [ "$dot_count" -eq 1 ]; then
        local www_d="www.$domain"
        if getent ahostsv4 "$www_d" >/dev/null 2>&1 || getent ahostsv6 "$www_d" >/dev/null 2>&1; then
            echo "$domain $www_d"
        else
            echo "$domain"
        fi
    else
        echo "$domain"
    fi
}

# ==============================================================================
# GROUP 2: 日志与交互展示层 (Loggers & Interactive UI)
# ==============================================================================
log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_ok()   { echo -e "${C_GREEN}[OK]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" | tee -a "$LOG_FILE"; }
log_err()  { echo -e "${C_RED}[ERROR]${C_RESET} $1" | tee -a "$LOG_FILE"; exit 1; }

get_listen_port() {
    while true; do
        read -rp "请设置 Xray 监听端口 (范围 1-65535) [默认 443]: " PORT_INPUT
        GLOBAL_PORT=${PORT_INPUT:-443}
        if ! [[ "$GLOBAL_PORT" =~ ^[0-9]+$ ]] || [ "$GLOBAL_PORT" -lt 1 ] || [ "$GLOBAL_PORT" -gt 65535 ]; then
            log_warn "输入的端口无效，请输入 1-65535 之间的数字。"
            continue
        fi
        
        # 严禁将外部端口设为本地专属内部端口 (80/8443/8444)
        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]] && { [ "$GLOBAL_PORT" -eq 80 ] || [ "$GLOBAL_PORT" -eq 8443 ] || [ "$GLOBAL_PORT" -eq 8444 ]; }; then
            log_warn "端口冲突：当前模式下，端口 80/8443/8444 已被本地 Web/伪装回落服务占用，请换一个端口。"
            continue
        fi
        
        local tcp_occ=$(ss -tln | grep -qE ":${GLOBAL_PORT}\b" && echo "1" || echo "0")
        local udp_occ=$(ss -uln | grep -qE ":${GLOBAL_PORT}\b" && echo "1" || echo "0")

        if [[ "$tcp_occ" == "1" ]]; then
            log_warn "端口占用：端口 $GLOBAL_PORT (TCP) 已被其他程序占用，请重新分配。"
            continue
        fi

        if [[ "$GLOBAL_INSTALL_MODE" == "3" && "$udp_occ" == "1" ]]; then
            log_warn "端口占用：端口 $GLOBAL_PORT (UDP) 已被占用。Hysteria2 需要 UDP 支持，请重新分配。"
            continue
        fi
        
        log_ok "端口 $GLOBAL_PORT 可以使用。\n"
        break
    done
}

module_get_inputs() {
    if [[ -f "$XRAY_CONFIG" ]]; then
        OLD_CONFIG_PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null)
    fi

    echo -e "\n${C_BOLD}${C_BLUE}--- [步骤 1/3] 选择部署模式 ---${C_RESET}"
    echo -e "  1. Web 回落模式 (推荐) - 自动申请证书 + 搭建本地伪装网站，极其稳定安全。"
    echo -e "  2. 纯净直连模式        - 借用大厂域名 (如 Apple) 伪装，不需要自己的域名，简单轻量。"
    echo -e "  3. 全能共存模式        - 融合 Web 回落架构，并同步拉起 Hysteria2 协议栈 (端口复用)。"
    read -rp "请选择 [1/2/3, 默认 1]: " MODE_INPUT
    GLOBAL_INSTALL_MODE=${MODE_INPUT:-1}

    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        read -rp "请输入已解析到本服务器的域名 (例如 my.domain.com): " GLOBAL_DOMAIN
        GLOBAL_DOMAIN=$(echo "$GLOBAL_DOMAIN" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        
        [[ -z "$GLOBAL_DOMAIN" ]] && log_err "域名不能为空或格式错误。"
        
        echo -e "\n${C_BLUE}正在测试域名解析状态 (双栈智能检测)...${C_RESET}"
        
        GLOBAL_IPV4=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        GLOBAL_IPV6=$(curl -s6m 5 icanhazip.com || curl -s6m 5 ifconfig.me)
        
        local domain_ipv4="" domain_ipv6=""

        if command -v jq >/dev/null 2>&1; then
            domain_ipv4=$(curl -sm 5 -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=$GLOBAL_DOMAIN&type=A" 2>/dev/null | jq -r '.Answer[]? | select(.type == 1) | .data' 2>/dev/null | head -n1)
            domain_ipv6=$(curl -sm 5 -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=$GLOBAL_DOMAIN&type=AAAA" 2>/dev/null | jq -r '.Answer[]? | select(.type == 28) | .data' 2>/dev/null | head -n1)
        fi
        
        if [[ -z "$domain_ipv4" ]]; then
            domain_ipv4=$(getent ahostsv4 "$GLOBAL_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1)
        fi
        if [[ -z "$domain_ipv6" ]]; then
            domain_ipv6=$(getent ahostsv6 "$GLOBAL_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1)
        fi
        
        echo -e "  本机 IPv4 : ${C_YELLOW}${GLOBAL_IPV4:-"无或获取超时"}${C_RESET} | 解析 IPv4 : ${C_YELLOW}${domain_ipv4:-"无或未生效"}${C_RESET}"
        echo -e "  本机 IPv6 : ${C_YELLOW}${GLOBAL_IPV6:-"无或获取超时"}${C_RESET} | 解析 IPv6 : ${C_YELLOW}${domain_ipv6:-"无或未生效"}${C_RESET}"
        
        local match_v4=0 match_v6=0
        [[ -n "$GLOBAL_IPV4" && "$GLOBAL_IPV4" == "$domain_ipv4" ]] && match_v4=1
        [[ -n "$GLOBAL_IPV6" && "$GLOBAL_IPV6" == "$domain_ipv6" ]] && match_v6=1
        
        if [[ $match_v4 -eq 1 || $match_v6 -eq 1 ]]; then
            echo -e "${C_GREEN}  [OK] IP 匹配成功，域名解析已生效。${C_RESET}\n"
        else
            echo -e "${C_RED}  [WARN] 警告：域名的解析 IP 与本机 IP 均不匹配 (可能是开启了 CDN 或解析还没生效)。${C_RESET}\n"
        fi

        get_listen_port
        
        echo -e "${C_BOLD}${C_BLUE}--- [步骤 2/3] 选择证书验证方式 ---${C_RESET}"
        echo -e "  1. DNS API 验证机制 (推荐) - 后台静默验证，支持泛域名，无惧端口被封。"
        echo -e "  2. HTTP Webroot 机制       - 依赖 Nginx 80 端口实现无感验证与零停机续期。"
        read -rp "请选择 [1/2, 默认 1]: " VERIFY_TYPE
        
        if [[ "$VERIFY_TYPE" == "2" ]]; then
            GLOBAL_DNS_API="webroot"
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
        
        echo -e "\n${C_BLUE}正在获取本机公网 IP (双栈智能检测)...${C_RESET}"
        GLOBAL_IPV4=$(curl -s4m 5 icanhazip.com || curl -s4m 5 ifconfig.me)
        GLOBAL_IPV6=$(curl -s6m 5 icanhazip.com || curl -s6m 5 ifconfig.me)
        echo -e "  本机 IPv4 : ${C_YELLOW}${GLOBAL_IPV4:-"无或获取超时"}${C_RESET}"
        echo -e "  本机 IPv6 : ${C_YELLOW}${GLOBAL_IPV6:-"无或获取超时"}${C_RESET}\n"
    fi
}

module_show_result() {
    clear
    echo -e "${C_GREEN}------------------------------------------------------------------${C_RESET}"
    echo -e "${C_BOLD}${C_GREEN}[OK] Xray 部署全部完成！(DEPLOYMENT SUCCESS)${C_RESET}"
    echo -e "${C_GREEN}------------------------------------------------------------------${C_RESET}"
    
    local client_sni
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        client_sni="$GLOBAL_DOMAIN"
    else
        client_sni="$GLOBAL_PUBLIC_SNI"
    fi
    local query_params="?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${client_sni}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality_${client_sni}"
    
    echo -e "${C_BOLD}[Xray Reality 节点参数]${C_RESET}"
    echo -e " 网络端口   : ${C_YELLOW}$GLOBAL_PORT (TCP)${C_RESET}"
    echo -e " UUID 标识  : ${C_YELLOW}$UUID${C_RESET}"
    echo -e " Public Key : ${C_YELLOW}$PUB${C_RESET}"
    echo -e " Short ID   : ${C_YELLOW}$SID${C_RESET}"
    echo -e " 路由 SNI   : ${C_BLUE}$client_sni${C_RESET}"
    echo -e "------------------------------------------------------------------"
    
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        local vless_link="vless://${UUID}@${GLOBAL_DOMAIN}:${GLOBAL_PORT}${query_params}"
        echo -e "${C_BOLD}客户端分享链接 (域名自适应版):${C_RESET}\n${C_GREEN}${vless_link}${C_RESET}\n"
        echo "$vless_link" | qrencode -t ansiutf8
    else
        echo -e "${C_BOLD}客户端分享链接 (纯净直连模式 - 双栈独立节点):${C_RESET}\n"
        local qr_target=""
        if [[ -n "$GLOBAL_IPV4" ]]; then
            local v4_link="vless://${UUID}@${GLOBAL_IPV4}:${GLOBAL_PORT}${query_params}"
            echo -e " [1] IPv4 直连节点 (高兼容性):\n${C_GREEN}${v4_link}${C_RESET}\n"
            qr_target="$v4_link"
        fi
        if [[ -n "$GLOBAL_IPV6" ]]; then
            local v6_link="vless://${UUID}@[${GLOBAL_IPV6}]:${GLOBAL_PORT}${query_params}"
            echo -e " [2] IPv6 直连节点 (专属路由/抗封锁):\n${C_GREEN}${v6_link}${C_RESET}\n"
            [[ -z "$qr_target" ]] && qr_target="$v6_link"
        fi
        
        if [[ -z "$GLOBAL_IPV4" && -z "$GLOBAL_IPV6" ]]; then
            local fallback_link="vless://${UUID}@你的VPS_IP:${GLOBAL_PORT}${query_params}"
            echo -e " [!] 默认节点 (获取公网IP超时，请手动替换为实际IP):\n${C_YELLOW}${fallback_link}${C_RESET}\n"
            qr_target="$fallback_link"
        fi
        
        [[ -n "$qr_target" ]] && echo "$qr_target" | qrencode -t ansiutf8
    fi

    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        local hy2_link="hy2://${HY2_PASSWORD}@${GLOBAL_DOMAIN}:${GLOBAL_PORT}/?sni=${GLOBAL_DOMAIN}&alpn=h3&insecure=0#Hysteria2_${GLOBAL_DOMAIN}"
        echo -e "\n------------------------------------------------------------------"
        echo -e "${C_BOLD}[Hysteria2 节点参数]${C_RESET}"
        echo -e " 网络端口   : ${C_YELLOW}$GLOBAL_PORT (UDP)${C_RESET}"
        echo -e " 认证密码   : ${C_YELLOW}$HY2_PASSWORD${C_RESET}"
        echo -e " 防火墙回落 : ${C_BLUE}Nginx (127.0.0.1:8444 本地)${C_RESET}"
        echo -e "------------------------------------------------------------------"
        echo -e "${C_BOLD}客户端分享链接 (域名自适应版):${C_RESET}\n${C_GREEN}$hy2_link${C_RESET}\n"
    fi
}

# ==============================================================================
# GROUP 3: 模式异构资产物理擦除器 (Mode-Driven Clean Slate Purger)
# ==============================================================================
module_purge_extraneous() {
    log_info "正在根据目标模式执行环境对齐与无关资产物理擦除..."

    # 1. 目标非模式 3 (模式 1 或 模式 2)：彻底拔除 Hysteria 2 全套资产
    if [[ "$GLOBAL_INSTALL_MODE" != "3" ]]; then
        if systemctl is-active --quiet hysteria-server 2>/dev/null || [[ -f /etc/systemd/system/hysteria-server.service ]]; then
            log_info "目标模式无需 Hysteria2，正在彻底清理 Hysteria2 专属资产..."
            systemctl stop hysteria-server hysteria-cert-watcher.path hysteria-cert-watcher.service >/dev/null 2>&1 || true
            systemctl disable hysteria-server hysteria-cert-watcher.path >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-cert-watcher.*
            rm -f /usr/local/bin/hysteria "$SCRIPT_DIR/hysteria-cert-restart.sh"
            rm -rf /etc/hysteria
            systemctl daemon-reload
        fi
    fi

    # 2. 目标为模式 2：彻底拔除 Nginx、Web 伪装、证书与 ACME 工具 (实现 100% 白纸级纯净)
    # 注：模式 1 与模式 3 互切时不会触发此分支，二者共用的证书及 acme.sh 资产自动完整保留并无缝复用！
    if [[ "$GLOBAL_INSTALL_MODE" == "2" ]]; then
        log_info "目标模式为纯净直连，正在物理清退 Nginx、伪装站、证书与 ACME 续签任务..."
        
        systemctl stop xray-acme.timer xray-acme.service >/dev/null 2>&1 || true
        systemctl disable xray-acme.timer xray-acme.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/xray-acme.*

        if command -v nginx >/dev/null 2>&1 || [[ -f /lib/systemd/system/nginx.service ]]; then
            systemctl stop nginx >/dev/null 2>&1 || true
            systemctl disable nginx >/dev/null 2>&1 || true
            apt-get purge -yqq nginx nginx-common socat >/dev/null 2>&1 || true
            apt-get autoremove -yqq >/dev/null 2>&1
        fi

        # 物理抹除证书与 Nginx 残留，彻底不留痕迹
        rm -rf /etc/nginx /var/www/html/* /var/www/html/.[!.]* /etc/nginx/ssl /root/.acme.sh 2>/dev/null || true
        crontab -l 2>/dev/null | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
        systemctl daemon-reload
    fi

    log_ok "无关异构资产物理擦除完毕，环境已恢复初装基线。"
}

# ==============================================================================
# GROUP 4: 基础环境与网络优化 (System Pre-requisites & BBR)
# ==============================================================================
module_prepare_env() {
    log_info "正在配置系统环境和日志策略..."

    mkdir -p /etc/systemd/journald.conf.d/
    echo -e "[Journal]\nSystemMaxUse=100M\nMaxRetentionSec=7day\nForwardToSyslog=no" > /etc/systemd/journald.conf.d/99-prophet.conf
    systemctl restart systemd-journald || true

    local install_list="curl unzip openssl jq qrencode"
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        install_list="$install_list nginx socat"
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html
    fi

    log_info "正在安装模式所需的基础软件..."
    apt-get install -yqq --no-install-recommends -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        $install_list >/dev/null 2>&1
        
    for cmd in curl unzip openssl jq qrencode; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "组件 [$cmd] 安装失败，请检查网络或系统软件源。"
        fi
    done
    
    mkdir -p "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /usr/local/bin
    log_ok "基础软件及目录准备完毕 (已就绪: ${install_list// /, })。"

    # 精准公网放行描述：只放行业务端口和 80，绝不开放 8443/8444 本地端口
    local ports_desc="${GLOBAL_PORT}/tcp"
    [[ "$GLOBAL_INSTALL_MODE" == "3" ]] && ports_desc="${ports_desc}, ${GLOBAL_PORT}/udp"
    [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]] && ports_desc="${ports_desc}, 80/tcp"

    log_info "正在检测系统防火墙环境并配置放行规则..."
    
    # 边缘保护：若之前记录过旧端口且本次变更了端口，先清退传统防火墙中的旧端口残留
    local prune_old=0
    if [[ -n "$OLD_CONFIG_PORT" && "$OLD_CONFIG_PORT" != "$GLOBAL_PORT" ]]; then
        prune_old=1
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw active; then
        log_info "检测到系统已激活 UFW 防火墙。"
        if [[ $prune_old -eq 1 ]]; then
            ufw delete allow "$OLD_CONFIG_PORT"/tcp >/dev/null 2>&1 || true
            ufw delete allow "$OLD_CONFIG_PORT"/udp >/dev/null 2>&1 || true
        fi
        
        ufw allow "$GLOBAL_PORT"/tcp >/dev/null 2>&1
        
        if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            ufw allow "$GLOBAL_PORT"/udp >/dev/null 2>&1
        else
            ufw delete allow "$GLOBAL_PORT"/udp >/dev/null 2>&1 || true
        fi
        
        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            ufw allow 80/tcp >/dev/null 2>&1
        else
            ufw delete allow 80/tcp >/dev/null 2>&1 || true
        fi
        log_ok "防火墙放行成功 (当前生效: ${ports_desc})。"
        
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log_info "检测到系统已激活 Firewalld 防火墙。"
        if [[ $prune_old -eq 1 ]]; then
            firewall-cmd --remove-port="${OLD_CONFIG_PORT}/tcp" --permanent >/dev/null 2>&1 || true
            firewall-cmd --remove-port="${OLD_CONFIG_PORT}/udp" --permanent >/dev/null 2>&1 || true
        fi

        firewall-cmd --add-port="${GLOBAL_PORT}/tcp" --permanent >/dev/null 2>&1
        
        if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            firewall-cmd --add-port="${GLOBAL_PORT}/udp" --permanent >/dev/null 2>&1
        else
            firewall-cmd --remove-port="${GLOBAL_PORT}/udp" --permanent >/dev/null 2>&1 || true
        fi
        
        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            firewall-cmd --add-port=80/tcp --permanent >/dev/null 2>&1
        else
            firewall-cmd --remove-port=80/tcp --permanent >/dev/null 2>&1 || true
        fi
        firewall-cmd --reload >/dev/null 2>&1
        log_ok "防火墙放行成功 (当前生效: ${ports_desc})。"

    elif command -v nft >/dev/null 2>&1; then
        log_info "检测到系统运行原生 nftables，正在挂载独立安全表 (xray_gateway)..."
        nft add table inet xray_gateway 2>/dev/null || true
        # 绝对幂等：清空整张专属表，旧端口与历史残留瞬间抹平，不影响系统其他规则
        nft flush table inet xray_gateway 2>/dev/null || true
        nft 'add chain inet xray_gateway input { type filter hook input priority 0; policy accept; }' 2>/dev/null || true
        
        nft add rule inet xray_gateway input tcp dport "$GLOBAL_PORT" accept 2>/dev/null || true
        
        if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            nft add rule inet xray_gateway input udp dport "$GLOBAL_PORT" accept 2>/dev/null || true
        fi
        
        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            nft add rule inet xray_gateway input tcp dport 80 accept 2>/dev/null || true
        fi
        
        mkdir -p /etc/nftables.d
        nft list table inet xray_gateway > /etc/nftables.d/xray.nft 2>/dev/null || true
        touch /etc/nftables.conf
        if ! grep -F -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf; then
            echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
        fi
        systemctl enable nftables >/dev/null 2>&1 || true
        log_ok "nftables 专属规则已就绪并持久化 (当前生效: ${ports_desc})。"
        
    elif command -v iptables >/dev/null 2>&1; then
        log_info "检测到系统运行原生 iptables/ip6tables。"
        if [[ $prune_old -eq 1 ]]; then
            while iptables -D INPUT -p tcp --dport "$OLD_CONFIG_PORT" -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -p udp --dport "$OLD_CONFIG_PORT" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p tcp --dport "$OLD_CONFIG_PORT" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p udp --dport "$OLD_CONFIG_PORT" -j ACCEPT 2>/dev/null; do :; done
        fi

        iptables -C INPUT -p tcp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null
        ip6tables -C INPUT -p tcp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null

        if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            iptables -C INPUT -p udp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null
            ip6tables -C INPUT -p udp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null
        else
            while iptables -D INPUT -p udp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p udp --dport "$GLOBAL_PORT" -j ACCEPT 2>/dev/null; do :; done
        fi

        if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
            iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
            ip6tables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
        else
            while iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; do :; done
        fi
        log_ok "iptables 双栈防火墙规则已生效 (当前生效: ${ports_desc})。"
    else
        log_warn "未检测到可用的防火墙管理工具，跳过端口配置。"
    fi
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
# GROUP 5: 证书验证与前置代理网关 (Certificates & Nginx)
# ==============================================================================
module_issue_cert() {
    local domain=$1
    local api=$2
    local cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
    local acme_bin="/root/.acme.sh/acme.sh"

    local domains=$(get_domain_info "$domain")
    local primary_domain=$(echo "$domains" | awk '{print $1}')
    local acme_args=""
    for d in $domains; do acme_args="$acme_args -d $d"; done

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
        
        if [[ "$api" == "webroot" ]]; then
            local acme_temp_conf="/etc/nginx/sites-enabled/acme_temp"
            CLEANUP_LIST+=("$acme_temp_conf")
            
            cat > "$acme_temp_conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domains;
    location / { root /var/www/html; }
}
EOF
            systemctl restart nginx >/dev/null 2>&1 || systemctl start nginx >/dev/null 2>&1
            "$acme_bin" --issue $acme_args --webroot /var/www/html --keylength ec-256 $GLOBAL_CERT_MODE
            rm -f "$acme_temp_conf"
        else
            "$acme_bin" --issue --dns "$api" $acme_args --keylength ec-256 $GLOBAL_CERT_MODE
        fi
        
        local reload_cmd="systemctl reload nginx || true"

        "$acme_bin" --install-cert -d "$primary_domain" --ecc \
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
        log_info "检测到服务器已存在有效证书，跳过申请步骤直接复用。"
    fi
}

module_config_nginx() {
    local domain=$1
    local domains=$(get_domain_info "$domain")
    
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
    
    log_info "正在通过语法探针检测 Nginx 核心特性支持..."

    local tmp_probe
    tmp_probe=$(mktemp /tmp/ngx_probe_XXXXXX.conf)
    CLEANUP_LIST+=("$tmp_probe")

    local has_reject_handshake=0
    cat > "$tmp_probe" <<EOF
events {}
http {
    server {
        listen 127.0.0.1:8443 ssl;
        ssl_reject_handshake on;
    }
}
EOF
    if nginx -t -c "$tmp_probe" >/dev/null 2>&1; then
        has_reject_handshake=1
        log_ok "安全特性支持: [ssl_reject_handshake] 校验通过，已启用阻断。"
    else
        log_warn "当前 Nginx 不支持 [ssl_reject_handshake]，自动优雅降级跳过。"
    fi

    local listen_directive="listen 127.0.0.1:8443 ssl http2;"
    cat > "$tmp_probe" <<EOF
events {}
http {
    server {
        http2 on;
    }
}
EOF
    if nginx -t -c "$tmp_probe" >/dev/null 2>&1; then
        listen_directive="listen 127.0.0.1:8443 ssl;
    http2 on;"
        log_ok "HTTP/2 特性模式: 采用现代独立 [http2 on] 语法 (server 作用域校验通过)。"
    else
        log_info "HTTP/2 特性模式: 采用经典 [listen ... http2] 语法。"
    fi
    rm -f "$tmp_probe"

    local default_server_block=""
    if [[ $has_reject_handshake -eq 1 ]]; then
        default_server_block="server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}"
    fi

    local tmp_conf="/tmp/xray_nginx.conf"
    cat > "$tmp_conf" <<EOF
${default_server_block}
server {
    ${listen_directive}
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

    if [[ "$GLOBAL_DNS_API" == "webroot" ]]; then
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

    if [[ "$GLOBAL_INSTALL_MODE" == "3" ]]; then
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
        rm -f /etc/nginx/sites-enabled/xray
        echo -e "${C_RED}${test_err}${C_RESET}"
        log_err "Nginx 配置文件存在错误，启动失败。"
    fi

    log_info "正在下载伪装网页文件..."
    local target_dir="/var/www/html"
    local temp_extract="/tmp/web_temp_$(date +%s)"
    CLEANUP_LIST+=("$temp_extract" "/tmp/web_template.zip")
    mkdir -p "$target_dir"

    rm -rf "${target_dir:?}/"* "${target_dir:?}/".[!.]* 2>/dev/null

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
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx || systemctl restart nginx || log_err "Nginx 服务重载失败。"
    else
        systemctl restart nginx || log_err "Nginx 服务启动失败。"
    fi
    log_ok "Nginx 服务启动成功。"
}

# ==============================================================================
# GROUP 6: 代理核心引擎与路由策略 (Xray Core Engine & Configuration)
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
    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 -o "$zip_name" "$zip_url" && [[ -s "$zip_name" ]]; then
        log_ok "Xray 核心文件下载成功。"
    else
        log_err "Xray 核心文件下载失败，请检查网络。"
    fi
    echo -e "${C_BLUE}----------------------${C_RESET}"

    unzip -qo "$zip_name" || log_err "压缩包解压失败。"
    
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
    
    if [[ -n "$PRIV" && "$PRIV" != "null" ]]; then
        PUB=$($XRAY_BIN x25519 -i "$PRIV" 2>/dev/null | grep -iE "Public|Password" | grep -oE '[A-Za-z0-9_-]{43}' | head -n1)
    fi

    if [[ -z "$PRIV" || "$PRIV" == "null" || -z "$PUB" || "$PUB" == "null" ]]; then
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
    fi

    log_ok "安全加密密钥生成成功。"
    
    mkdir -p "$XRAY_CONF_DIR"

    local domains=$(get_domain_info "$domain")
    local server_names_json=$(echo "$domains" | sed 's/ /", "/g; s/^/["/; s/$/"]/')
    
    local dest_addr="127.0.0.1:8443"
    
    [[ "$GLOBAL_INSTALL_MODE" == "2" ]] && { 
        dest_addr="$GLOBAL_PUBLIC_SNI:443"
        server_names_json="[\"$GLOBAL_PUBLIC_SNI\"]" 
    }
    
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": { "loglevel": "warning" },
  "dns": {
    "queryStrategy": "UseIP",
    "disableFallback": true,
    "hosts": {
      "dns.google": [
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "8.8.8.8", 
        "8.8.4.4"
      ],
      "dns.cloudflare.com": [
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "1.1.1.1", 
        "1.0.0.1"
      ]
    },
    "servers": [
      { "address": "https://dns.cloudflare.com/dns-query" },
      { 
        "address": "https://dns.google/dns-query", 
        "skipFallback": true 
      }
    ]
  },
  "inbounds": [{
    "listen": "::",
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
      }
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
    chmod 700 "$XRAY_CONF_DIR"
    chmod 600 "$XRAY_CONFIG"

    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray || log_err "Xray 启动失败，请检查配置文件格式。"
    log_ok "Xray 路由规则配置成功。"
}

module_install_hysteria() {
    local domain=$1
    log_info "正在下载并配置 Hysteria2 服务..."
    
    local arch=$(dpkg --print-architecture)
    local hy2_arch="amd64"
    [[ "$arch" == "arm64" ]] && hy2_arch="arm64"

    local hy2_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${hy2_arch}"
    
    echo -e "${C_BLUE}--- 下载 Hysteria2 核心 ---${C_RESET}"
    local tmp_hy2="/tmp/hy2_build_$(date +%s)"
    CLEANUP_LIST+=("$tmp_hy2")
    mkdir -p "$tmp_hy2"

    if curl -fL -# --connect-timeout 10 --retry 5 --retry-delay 3 --retry-connrefused -m 120 \
          -o "$tmp_hy2/hysteria" "$hy2_url" \
          && [[ -s "$tmp_hy2/hysteria" ]]; then
        chmod +x "$tmp_hy2/hysteria"
        mv -f "$tmp_hy2/hysteria" /usr/local/bin/hysteria
        log_ok "Hysteria2 核心文件下载成功。"
    else
        log_err "Hysteria2 核心文件下载失败，请检查网络。"
    fi
    echo -e "${C_BLUE}-----------------------------${C_RESET}"

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
    chmod 700 /etc/hysteria
    chmod 600 /etc/hysteria/config.yaml

    cat > /etc/systemd/system/hysteria-cert-watcher.path <<EOF
[Unit]
Description=Watch TLS certificate changes for Hysteria2

[Path]
PathChanged=/etc/nginx/ssl/${domain}_ecc.cer
PathChanged=/etc/nginx/ssl/${domain}_ecc.key

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SCRIPT_DIR/hysteria-cert-restart.sh" <<EOF
#!/bin/bash
cert_file="/etc/nginx/ssl/${domain}_ecc.cer"
key_file="/etc/nginx/ssl/${domain}_ecc.key"

exec 9>/run/hysteria-cert.lock
flock -n 9 || exit 0

valid=0
for i in \$(seq 1 10); do
    if [[ -s "\$cert_file" ]] && openssl x509 -in "\$cert_file" -noout >/dev/null 2>&1; then
        valid=1
        break
    fi
    sleep 1
done

if [[ \$valid -eq 1 ]]; then
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
    else
        systemctl start nginx
    fi
    systemctl restart hysteria-server
else
    echo "证书校验失败或文件未就绪，跳过重启。"
fi
EOF
    chmod +x "$SCRIPT_DIR/hysteria-cert-restart.sh"

    cat > /etc/systemd/system/hysteria-cert-watcher.service <<EOF
[Unit]
Description=Reload Nginx and Restart Hysteria2 on certificate change

ConditionPathExists=/etc/hysteria/config.yaml
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

ConditionPathExists=/etc/hysteria/config.yaml
ConditionPathExists=/etc/nginx/ssl/${domain}_ecc.cer
ConditionPathExists=/etc/nginx/ssl/${domain}_ecc.key

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
    systemctl enable --now hysteria-cert-watcher.path >/dev/null 2>&1
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl start hysteria-server || log_err "Hysteria2 启动失败，请检查端口占用。"
    log_ok "Hysteria2 服务配置完成。"
}

# ==============================================================================
# GROUP 7: 自动化守护与系统清理 (Automation & Cleanup)
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
    local target_tmp="$SHARE_DIR/${f}.new"

    if curl -fL --max-time 300 --connect-timeout 60 --retry 5 --retry-delay 3 --retry-connrefused -o "$target_tmp" "$u" && [[ -s "$target_tmp" ]]; then
        local f_size
        f_size=$(stat -c%s "$target_tmp" 2>/dev/null || wc -c < "$target_tmp" 2>/dev/null | tr -d ' ' || echo 0)
        if [ "$f_size" -ge 512000 ]; then
            if ! cmp -s "$target_tmp" "$SHARE_DIR/$f"; then
                mv -f "$target_tmp" "$SHARE_DIR/$f"
                changed=1
                return 0
            fi
        fi
    fi
    rm -f "$target_tmp"
    return 1
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

    crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true

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

    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        cat > /etc/systemd/system/xray-acme.service <<EOF
[Unit]
Description=Acme.sh Certificate Renewal Daemon
[Service]
Type=oneshot
User=root
ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
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

module_uninstall() {
    echo -e "\n${C_BLUE}[INFO]${C_RESET} 正在回收防火墙端口与服务..."
    
    local old_port=""
    local dest_val=""
    if [[ -f "$XRAY_CONFIG" ]]; then
        old_port=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null)
        dest_val=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$XRAY_CONFIG" 2>/dev/null)
    fi

    local had_nginx=0
    if [[ "$dest_val" == *"127.0.0.1"* ]] || \
       [[ -f /etc/nginx/sites-available/xray ]] || \
       [[ -d /etc/nginx/ssl && -n "$(ls -A /etc/nginx/ssl 2>/dev/null)" ]] || \
       [[ -f /etc/hysteria/config.yaml ]]; then
        had_nginx=1
    fi

    # 1. nftables：整表物理销毁，不留任何残余
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet xray_gateway 2>/dev/null || true
        rm -f /etc/nftables.d/xray.nft
        if [[ -f /etc/nftables.conf ]]; then
            sed -i '\|include "/etc/nftables.d/\*.nft"|d' /etc/nftables.conf 2>/dev/null || true
        fi
    fi

    # 2. 传统依赖端口的工具：严格依据配置文件读取到的端口回收
    if [[ -n "$old_port" && "$old_port" =~ ^[0-9]+$ ]]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw active; then
            ufw delete allow "$old_port"/tcp >/dev/null 2>&1 || true
            ufw delete allow "$old_port"/udp >/dev/null 2>&1 || true
            [[ $had_nginx -eq 1 ]] && ufw delete allow 80/tcp >/dev/null 2>&1 || true
        elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
            firewall-cmd --remove-port="${old_port}/tcp" --permanent >/dev/null 2>&1 || true
            firewall-cmd --remove-port="${old_port}/udp" --permanent >/dev/null 2>&1 || true
            [[ $had_nginx -eq 1 ]] && firewall-cmd --remove-port=80/tcp --permanent >/dev/null 2>&1 || true
            firewall-cmd --reload >/dev/null 2>&1 || true
        elif command -v iptables >/dev/null 2>&1; then
            while iptables -D INPUT -p tcp --dport "$old_port" -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -p udp --dport "$old_port" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p tcp --dport "$old_port" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p udp --dport "$old_port" -j ACCEPT 2>/dev/null; do :; done
            if [[ $had_nginx -eq 1 ]]; then
                while iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; do :; done
                while ip6tables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; do :; done
            fi
        fi
    fi

    systemctl stop xray hysteria-server hysteria-cert-watcher.path hysteria-cert-watcher.service nginx xray-acme.timer xray-acme.service xray-dat.timer xray-dat.service >/dev/null 2>&1
    systemctl disable xray hysteria-server hysteria-cert-watcher.path nginx xray-acme.timer xray-dat.timer >/dev/null 2>&1
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-cert-watcher.* /usr/local/bin/xray /usr/local/bin/hysteria /etc/systemd/system/xray-acme.* /etc/systemd/system/xray-dat.*
    systemctl daemon-reload
    rm -f /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
    rm -rf /var/www/html/* /var/www/html/.[!.]* "$XRAY_CONF_DIR" "$XRAY_SHARE_DIR" "$SCRIPT_DIR" /etc/hysteria /etc/nginx/ssl /root/.acme.sh 2>/dev/null
    crontab -l 2>/dev/null | grep -vF "update-dat.sh" | grep -vE "acme\.sh.*--cron" | crontab - 2>/dev/null || true
    echo -e "\n${C_YELLOW}业务文件清理与端口回收完毕。${C_RESET}"
    
    echo -e "${C_RED}[WARN] 是否连带卸载底层系统基础软件 (Nginx, Socat, qrencode, jq, unzip)？${C_RESET}"
    read -rp "如果你的服务器上还运行了其他网站或程序，请务必选 N！[y/N, 默认 N]: " SCORCHED_EARTH
    case "${SCORCHED_EARTH}" in
        [yY][eE][sS]|[yY])
            local purge_pkgs="nginx nginx-common socat qrencode jq unzip"
            log_info "正在彻底卸载底层依赖组件 (${purge_pkgs// /, })..."
            apt-get purge -yqq $purge_pkgs >/dev/null 2>&1
            apt-get autoremove -yqq >/dev/null 2>&1; apt-get clean >/dev/null 2>&1
            
            echo -e "\n${C_GREEN}====================== 卸载与清理结果详情 ======================${C_RESET}"
            echo -e " ${C_RED}[已彻底清理/卸载项]${C_RESET}:"
            echo -e "   - 核心服务: Xray, Hysteria2, Nginx (包括 Systemd 守护单元)"
            echo -e "   - 部署文件: 核心二进制、TLS 证书、节点配置文件、伪装网站 (/var/www/html)"
            echo -e "   - 运维任务: 路由规则更新 Timer、证书自动续签 Timer、防火墙放行端口回收"
            echo -e "   - 底层组件: nginx, socat, qrencode, jq, unzip"
            echo -e " ${C_BLUE}[已按系统惯例保留]${C_RESET}:"
            echo -e "   - 基础工具: curl (系统关键网络管理依赖，已保留)"
            echo -e "   - 网络优化: BBR 拥塞控制算法 (内核参数，已保留加速状态)"
            echo -e "   - 日志策略: systemd-journald 日志大小限制策略 (最大 100M，保留 7 天)"
            echo -e "${C_GREEN}================================================================${C_RESET}"
            ;;
        *)
            echo -e "\n${C_GREEN}====================== 卸载与清理结果详情 ======================${C_RESET}"
            echo -e " ${C_RED}[已彻底清理/卸载项]${C_RESET}:"
            echo -e "   - 核心服务: Xray, Hysteria2 (包括 Systemd 守护单元)"
            echo -e "   - 部署文件: 核心二进制、TLS 证书、节点配置文件、伪装网站 (/var/www/html)"
            echo -e "   - 运维任务: 路由规则更新 Timer、证书自动续签 Timer、防火墙放行端口回收"
            echo -e " ${C_BLUE}[已完整保留项]${C_RESET}:"
            echo -e "   - 底层组件: Nginx, Socat, qrencode, jq, unzip, curl"
            echo -e "   - 网络优化: BBR 拥塞控制算法 (内核参数)"
            echo -e "   - 日志策略: systemd-journald 日志大小限制策略"
            echo -e "${C_GREEN}================================================================${C_RESET}"
            ;;
    esac
    echo -e "\n${C_GREEN}[OK] 系统卸载与清理彻底完成。${C_RESET}"
    read -rp "按回车键返回菜单..."
}

# ==============================================================================
# GROUP 8: 主控引擎与 CLI 菜单 (Main Scheduler & CLI Menu)
# ==============================================================================
main_install() {
    cd "$HOME" || exit 1
    
    # 释放 APT 锁与停用冲突服务，彻底防止后续 purge/install 卡锁
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    dpkg --configure -a >/dev/null 2>&1 || true

    systemctl stop xray >/dev/null 2>&1
    systemctl stop hysteria-server >/dev/null 2>&1
    command -v nginx >/dev/null 2>&1 && systemctl stop nginx >/dev/null 2>&1

    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        apt-get update -yqq >/dev/null 2>&1
        apt-get install -yqq --no-install-recommends curl jq >/dev/null 2>&1
    fi

    module_get_inputs
    # 依据目标模式执行无关异构资产物理擦除
    module_purge_extraneous
    module_prepare_env
    module_setup_bbr
    
    if [[ "$GLOBAL_INSTALL_MODE" == "1" || "$GLOBAL_INSTALL_MODE" == "3" ]]; then
        module_issue_cert "$GLOBAL_DOMAIN" "$GLOBAL_DNS_API"
        module_config_nginx "$GLOBAL_DOMAIN"
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
    echo -e "   REALITY AUTOMATION CLI ENGINE"
    echo -e "   Build: $SCRIPT_VERSION"
    echo -e " ----------------------------------------------${C_RESET}\n"
    
    echo -e "  1. ${C_GREEN}执行部署脚本${C_RESET}"
    echo -e "  2. ${C_YELLOW}卸载服务${C_RESET}"
    echo -e "  3. ${C_BLUE}查看定时任务+证书状态${C_RESET}"
    echo -e "  0. ${C_RED}退出脚本${C_RESET}\n"
    
    read -rp "请输入数字选择功能 [0-3]: " OPT
    case $OPT in
        1) main_install ; break ;;
        2) module_uninstall ;;
        3)
            echo -e "\n${C_BOLD}${C_BLUE}--- 自动任务运行状态 ---${C_RESET}"
            systemctl list-timers --all | grep -E "xray-acme|xray-dat" || echo "当前没有运行中的定时任务"
            echo -e "\n${C_BOLD}${C_BLUE}--- 已安装证书详情列表 ---${C_RESET}"
            if [[ -f "/root/.acme.sh/acme.sh" ]]; then
                /root/.acme.sh/acme.sh --list --home "/root/.acme.sh"
            else
                echo "未检测到 acme.sh 证书环境。"
            fi
            read -rp "按回车键返回菜单..." ;;
        0) echo -e "\n已退出。"; exit 0 ;;
        *) echo -e "\n${C_RED}[ERROR] 输入无效，请重新选择。${C_RESET}" ; sleep 1 ;;
    esac
done
