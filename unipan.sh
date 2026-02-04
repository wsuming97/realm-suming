#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/wsuming97/realm-suming/main"

# 加载公共库
if [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
    source "$SCRIPT_DIR/lib/common.sh"
elif [ -f "/usr/local/lib/realm/common.sh" ]; then
    source /usr/local/lib/realm/common.sh
else
    TEMP_LIB_DIR="/tmp/realm-install-lib"
    mkdir -p "$TEMP_LIB_DIR"
    if curl -fsSL "$GITHUB_RAW_BASE/lib/common.sh" -o "$TEMP_LIB_DIR/common.sh" 2>/dev/null; then
        source "$TEMP_LIB_DIR/common.sh"
        mkdir -p /usr/local/lib/realm
        cp "$TEMP_LIB_DIR/common.sh" /usr/local/lib/realm/common.sh
    else
        echo "无法加载公共库" >&2
        exit 1
    fi
fi

echo -e "${YELLOW}开始卸载 Realm 面板 ...${RESET}"

echo -e ">>> 正在停止面板服务..."
systemctl stop realm-panel >/dev/null 2>&1
systemctl disable realm-panel >/dev/null 2>&1
rm -f /etc/systemd/system/realm-panel.service
systemctl daemon-reload
echo -e "${GREEN}[1/6] 面板服务已移除${RESET}"

echo -e ">>> 正在清理流量统计防火墙规则..."
# 清理 iptables 规则
iptables -D INPUT -j REALM_IN 2>/dev/null || true
iptables -D OUTPUT -j REALM_OUT 2>/dev/null || true
iptables -F REALM_IN 2>/dev/null || true
iptables -F REALM_OUT 2>/dev/null || true
iptables -X REALM_IN 2>/dev/null || true
iptables -X REALM_OUT 2>/dev/null || true

# 清理 nftables 规则（端口流量狗使用）
if command -v nft &> /dev/null; then
    nft delete table inet port_traffic_monitor 2>/dev/null || true
fi
echo -e "${GREEN}[2/6] 流量统计规则已清理（iptables + nftables）${RESET}"

echo -e ">>> 正在清理程序文件..."
rm -f /usr/local/bin/realm-panel
rm -rf /opt/realm_panel
echo -e "${GREEN}[3/6] 程序文件已删除${RESET}"

echo -e ">>> 正在卸载 Rust 环境..."
if command -v rustup &> /dev/null; then
    rustup self uninstall -y >/dev/null 2>&1
fi
rm -rf "$HOME/.cargo"
rm -rf "$HOME/.rustup"
sed -i '/.cargo\/env/d' "$HOME/.bashrc"
echo -e "${GREEN}[4/6] Rust 环境已移除${RESET}"

echo -e ">>> 正在清理系统编译依赖..."
SYSTEM_TYPE="$(detect_system)"
case "$SYSTEM_TYPE" in
    ubuntu|debian)
        apt-get remove --purge -y build-essential pkg-config libssl-dev >/dev/null 2>&1
        apt-get autoremove -y >/dev/null 2>&1
        ;;
    centos)
        if command -v dnf >/dev/null 2>&1; then
            dnf groupremove -y "Development Tools" >/dev/null 2>&1
            dnf remove -y openssl-devel >/dev/null 2>&1
        else
            yum groupremove -y "Development Tools" >/dev/null 2>&1
            yum remove -y openssl-devel >/dev/null 2>&1
        fi
        ;;
    alpine)
        apk del build-base openssl-dev >/dev/null 2>&1 || true
        ;;
    *)
        echo -e "${YELLOW}未识别发行版，跳过依赖清理。${RESET}"
        ;;
esac
echo -e "${GREEN}[5/6] 系统编译依赖已清理${RESET}"

echo -e ">>> 正在清理临时文件..."
rm -rf /tmp/realm_tmp
echo -e "${GREEN}[6/6] 临时文件已清理${RESET}"

echo -e "\n${GREEN}==========================================${RESET}"
echo -e "${GREEN}    Realm 面板已卸载     ${RESET}"
echo -e "${GREEN}==========================================${RESET}"
