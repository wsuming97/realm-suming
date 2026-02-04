#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/lib/common.sh"
elif [ -f "/usr/local/lib/realm/common.sh" ]; then
    # shellcheck source=/dev/null
    source /usr/local/lib/realm/common.sh
else
    echo "缺少公共库 lib/common.sh" >&2
    exit 1
fi

# =================配置区域=================
PANEL_PORT="4794"
DEFAULT_USER="admin"
DEFAULT_PASS="123456"

# 路径配置
REALM_BIN="/usr/local/bin/realm"
CONFIG_FILE="/etc/realm/config.toml"
SERVICE_FILE="/etc/systemd/system/realm.service"
TMP_DIR="/tmp/realm_install"

WORK_DIR="/opt/realm_panel"
PANEL_BIN="/usr/local/bin/realm-panel"
PANEL_DATA="/etc/realm/panel_data.json"

# =========================================

# 自定义链名称
CHAIN_IN="REALM_IN"
CHAIN_OUT="REALM_OUT"

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -n " "
    while [ -d /proc/$pid ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_step() {
    echo -e -n "${CYAN}>>> $1...${RESET}"
    eval "$2" >/dev/null 2>&1 &
    spinner $!
    echo -e "${GREEN} [完成]${RESET}"
}

prepare_env_and_fix_compilation() {
    echo -e "${CYAN}>>> 正在优化编译环境...${RESET}"
    OS_ARCH=$(uname -m)
    if [ -f /etc/debian_version ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1
        apt-get install -y ca-certificates curl wget tar git build-essential pkg-config libssl-dev iptables >/dev/null 2>&1
        if ! command -v gcc >/dev/null 2>&1; then apt-get install -y gcc >/dev/null 2>&1; fi
        update-ca-certificates >/dev/null 2>&1 || true

    elif [ -f /etc/redhat-release ]; then
        if command -v dnf >/dev/null 2>&1; then PKG=dnf; else PKG=yum; fi
        $PKG -y groupinstall "Development Tools" >/dev/null 2>&1 || true
        $PKG -y install ca-certificates curl wget tar git gcc gcc-c++ make pkgconfig openssl-devel iptables iptables-services glibc-static >/dev/null 2>&1 || true
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo -e -n "${CYAN}>>> 安装 Rust 编译器...${RESET}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1 &
        spinner $!
        source "$HOME/.cargo/env"
        echo -e "${GREEN} [完成]${RESET}"
    else
        echo -e "${GREEN}>>> Rust 已安装${RESET}"
        if [ -f "$HOME/.cargo/env" ]; then source "$HOME/.cargo/env"; fi
    fi
}

get_realm_filename() {
    local arch libc
    arch="$(get_arch)"
    libc="$(get_libc)"
    if [ "$arch" = "unsupported" ]; then return 1; fi
    if [ "$arch" = "armv7" ]; then
        if [ "$libc" = "musl" ]; then
            echo "realm-armv7-unknown-linux-musleabihf.tar.gz"
        else
            echo "realm-armv7-unknown-linux-gnueabihf.tar.gz"
        fi
        return 0
    fi
    echo "realm-${arch}-unknown-linux-${libc}.tar.gz"
}

get_local_realm_version() {
    if [ -f "$REALM_BIN" ]; then
        $REALM_BIN --version 2>/dev/null | awk '{print $2}'
    else
        echo "0.0.0"
    fi
}

get_latest_realm_version_tag() {
    curl -s https://api.github.com/repos/zhboner/realm/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//'
}

get_latest_realm_url() {
    local file
    file="$(get_realm_filename)"
    [ -z "$file" ] && return 1
    curl -s https://api.github.com/repos/zhboner/realm/releases/latest | grep browser_download_url | grep "$file" | cut -d '"' -f 4
}

ensure_config_file() {
    if [ ! -f "$CONFIG_FILE" ]; then
        mkdir -p "$(dirname "$CONFIG_FILE")"
        touch "$CONFIG_FILE"
        echo '[[endpoints]]' > "$CONFIG_FILE"
        echo 'name = "system-keepalive"' >> "$CONFIG_FILE"
        echo 'listen = "127.0.0.1:65534"' >> "$CONFIG_FILE"
        echo 'remote = "127.0.0.1:65534"' >> "$CONFIG_FILE"
    fi
}

install_realm_smart() {
    need_cmd curl
    need_cmd tar
    need_cmd systemctl

    echo -e "${CYAN}>>> 检查 Realm 版本...${RESET}"
    local latest_ver local_ver
    latest_ver=$(get_latest_realm_version_tag)
    local_ver=$(get_local_realm_version)

    if [ -z "$latest_ver" ]; then
        echo -e "${RED}无法获取最新版本号，强制重装${RESET}"
    elif [ "$local_ver" == "0.0.0" ]; then
        echo -e "${GREEN}检测到未安装，准备开始安装 Realm ($latest_ver)...${RESET}"
    elif [ "$latest_ver" == "$local_ver" ]; then
        echo -e "${GREEN}本地 Realm 已是最新版 ($local_ver)，跳过安装${RESET}"
        ensure_config_file
        if [ -f "$SERVICE_FILE" ]; then return 0; fi
    else
        echo -e "${YELLOW}发现新版本: $latest_ver (当前: $local_ver)，准备更新...${RESET}"
    fi

    local url
    url="$(get_latest_realm_url || true)"
    if [ -z "$url" ]; then echo -e "${RED}获取下载链接失败${RESET}"; exit 1; fi

    echo -e "${GREEN}下载地址：$url${RESET}"
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR" || exit 1
    rm -f realm.tar.gz realm

    if ! curl -L -o realm.tar.gz "$url"; then echo -e "${RED}下载失败${RESET}"; exit 1; fi
    
    tar -xzf realm.tar.gz
    if [ ! -f "realm" ]; then echo -e "${RED}解压失败${RESET}"; exit 1; fi

    systemctl stop realm >/dev/null 2>&1
    mv realm "$REALM_BIN"
    chmod +x "$REALM_BIN"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Realm Proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$REALM_BIN -c $CONFIG_FILE
Restart=always
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF

    ensure_config_file
    systemctl daemon-reload
    systemctl enable realm >/dev/null 2>&1 || true
    systemctl restart realm
    echo -e "${GREEN}Realm 安装完成${RESET}"
    cd ~
    rm -rf "$TMP_DIR"
}

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请以 root 用户运行！${RESET}"
    exit 1
fi

clear
echo -e "${GREEN}==================================${RESET}"
echo -e "${GREEN}          Realm 面板 一键部署        ${RESET}"
echo -e "${GREEN}==================================${RESET}"

prepare_env_and_fix_compilation
install_realm_smart

mkdir -p "$(dirname "$PANEL_DATA")"
run_step "生成面板源代码" "
rm -rf '$WORK_DIR'
mkdir -p '$WORK_DIR/src'
"
cd "$WORK_DIR"

cat > Cargo.toml <<EOF
[package]
name = "realm-panel"
version = "3.9.2"
edition = "2021"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
tower-cookies = "0.10"
anyhow = "1.0"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
reqwest = { version = "0.11", features = ["json"] }
rand = "0.8"
EOF

cat > src/main.rs << 'EOF'
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put, delete},
    Json, Router, Form,
};
use serde::{Deserialize, Serialize};
use std::{fs, process::Command, sync::{Arc, Mutex}, path::Path as FilePath, time::Duration, collections::HashMap, cmp};
use tower_cookies::{Cookie, Cookies, CookieManagerLayer};
use chrono::prelude::*;
use reqwest::Client;
use rand::{distributions::Alphanumeric, Rng};

const REALM_CONFIG: &str = "/etc/realm/config.toml";
const DATA_FILE: &str = "/etc/realm/panel_data.json";

// 自定义链名称
const CHAIN_IN: &str = "REALM_IN";
const CHAIN_OUT: &str = "REALM_OUT";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RemoteTarget {
    address: String,
    #[serde(default)]
    label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Rule {
    id: String,
    name: String,
    listen: String,
    remote: String,
    #[serde(default)]
    remote_list: Vec<RemoteTarget>,
    enabled: bool,
    #[serde(default)]
    expire_date: u64,
    #[serde(default)]
    traffic_limit: u64,
    #[serde(default)]
    traffic_used: u64,
    #[serde(default)]
    status_msg: String,
    #[serde(default)]
    bandwidth_limit: String,
    #[serde(default)]
    bandwidth_enabled: bool,
    #[serde(default = "default_billing_mode")]
    billing_mode: String,
    #[serde(default)]
    reset_day: u8,
    #[serde(default)]
    remark: String,
    #[serde(default)]
    last_reset_month: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct AdminConfig {
    username: String,
    pass_hash: String,
    #[serde(default = "default_bg_pc")]
    bg_pc: String,
    #[serde(default = "default_bg_mobile")]
    bg_mobile: String,
}
fn default_bg_pc() -> String { "https://img.inim.im/file/1769439286929_61891168f564c650f6fb03d1962e5f37.jpeg".to_string() }
fn default_bg_mobile() -> String { "https://img.inim.im/file/1764296937373_bg_m_2.png".to_string() }
fn default_billing_mode() -> String { "single".to_string() }
fn default_panel_port() -> u16 { 4794 }
fn default_enabled() -> bool { true }
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct NotificationConfig {
    #[serde(default)]
    telegram_enabled: bool,
    #[serde(default)]
    telegram_bot_token: String,
    #[serde(default)]
    telegram_chat_id: String,
    #[serde(default)]
    wecom_enabled: bool,
    #[serde(default)]
    wecom_webhook_url: String,
    #[serde(default)]
    server_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RemoteNode {
    id: String,
    name: String,
    host: String,
    #[serde(default = "default_panel_port")]
    port: u16,
    #[serde(default)]
    api_token: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AppData {
    admin: AdminConfig,
    rules: Vec<Rule>,
    #[serde(default)]
    remote_nodes: Vec<RemoteNode>,
    #[serde(default)]
    api_token: String,
    #[serde(default)]
    notifications: NotificationConfig,
}
#[derive(Serialize)]
struct RulesResponse {
    rules: Vec<Rule>,
}
#[derive(Serialize)]
struct RealmEndpoint {
    name: String,
    listen: String,
    remote: String,
    #[serde(default)]
    remote_list: Vec<RemoteTarget>,
    #[serde(rename = "type")]
    r#type: String,
}
#[derive(Serialize)]
struct RealmConfig {
    endpoints: Vec<RealmEndpoint>,
}

#[derive(Debug, Clone, Copy)]
struct TrafficStats {
    in_bytes: u64,
    out_bytes: u64,
}

struct AppState {
    data: Mutex<AppData>,
    last_traffic_map: Mutex<HashMap<String, TrafficStats>>,
}

#[tokio::main]
async fn main() {
    init_firewall_chains();

    let initial_data = load_or_init_data();
    let state = Arc::new(AppState {
        data: Mutex::new(initial_data),
        last_traffic_map: Mutex::new(HashMap::new()),
    });
    {
        let data = state.data.lock().unwrap();
        flush_realm_chains(); 
        for rule in &data.rules {
             if rule.enabled {
                 add_iptables_rule(rule);
                 apply_bandwidth_if_needed(rule);
             }
        }
    }

    let monitor_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            update_traffic_and_check(&monitor_state);
        }
    });
    let reset_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            check_monthly_resets(&reset_state);
        }
    });

    let app = Router::new()
        .route("/", get(index_page))
        .route("/login", get(login_page).post(login_action))
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/batch", post(batch_add_rules))
        .route("/api/rules/all", delete(delete_all_rules)) 
        .route("/api/rules/:id", put(update_rule).delete(delete_rule))
        .route("/api/rules/:id/toggle", post(toggle_rule))
        .route("/api/rules/:id/reset_traffic", post(reset_traffic))
        .route("/api/rules/:id/bandwidth", post(update_bandwidth))
        .route("/api/rules/:id/reset_day", put(update_reset_day))
        .route("/api/notifications", get(get_notifications).post(update_notifications))
        .route("/api/notifications/test", post(test_notifications))
        .route("/api/nodes", get(get_nodes).post(add_node))
        .route("/api/nodes/:id", put(update_node).delete(delete_node))
        .route("/api/nodes/:id/rules", get(get_remote_rules).post(add_remote_rule))
        .route("/api/nodes/:id/rules/:rule_id", put(update_remote_rule).delete(delete_remote_rule))
        .route("/api/nodes/:id/rules/:rule_id/toggle", post(toggle_remote_rule))
        .route("/api/token", get(get_api_token).post(regenerate_api_token))
        .route("/api/admin/account", post(update_account))
        .route("/api/admin/bg", post(update_bg))
        .route("/api/backup", get(download_backup))
        .route("/api/rules/:id/targets", get(get_rule_targets).post(add_rule_target))
        .route("/api/rules/:id/targets/:idx", delete(delete_rule_target))
        .route("/api/rules/:id/switch-target", post(switch_rule_target))
        .route("/api/restore", post(restore_backup))
        .route("/logout", post(logout_action))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let port = std::env::var("PANEL_PORT").unwrap_or_else(|_| "4794".to_string());
    println!("Server running on port {}", port);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn init_firewall_chains() {
    let _ = Command::new("iptables").args(["-N", CHAIN_IN]).status();
    let _ = Command::new("iptables").args(["-N", CHAIN_OUT]).status();

    let check_in = Command::new("iptables").args(["-C", "INPUT", "-j", CHAIN_IN]).status();
    if check_in.is_err() || !check_in.unwrap().success() {
        let _ = Command::new("iptables").args(["-I", "INPUT", "-j", CHAIN_IN]).status();
    }

    let check_out = Command::new("iptables").args(["-C", "OUTPUT", "-j", CHAIN_OUT]).status();
    if check_out.is_err() || !check_out.unwrap().success() {
        let _ = Command::new("iptables").args(["-I", "OUTPUT", "-j", CHAIN_OUT]).status();
    }
    
    let check_fwd = Command::new("iptables").args(["-C", "FORWARD", "-j", CHAIN_OUT]).status();
    if check_fwd.is_err() || !check_fwd.unwrap().success() {
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-j", CHAIN_OUT]).status();
    }
}

fn flush_realm_chains() {
    let _ = Command::new("iptables").args(["-F", CHAIN_IN]).status();
    let _ = Command::new("iptables").args(["-F", CHAIN_OUT]).status();
}

fn get_port(listen: &str) -> String {
    listen.split(':').last().unwrap_or("").trim().to_string()
}

fn add_iptables_rule(rule: &Rule) {
    let port = get_port(&rule.listen);
    if port.is_empty() { return; }
    
    for proto in ["tcp", "udp"] {
        let check_in = Command::new("iptables").args(["-C", CHAIN_IN, "-p", proto, "--dport", &port, "-j", "RETURN"]).status();
        if check_in.is_err() || !check_in.unwrap().success() {
            let _ = Command::new("iptables").args(["-A", CHAIN_IN, "-p", proto, "--dport", &port, "-j", "RETURN"]).status();
        }

        let check_out = Command::new("iptables").args([
            "-C", CHAIN_OUT, 
            "-p", proto, 
            "-m", "conntrack", 
            "--ctstate", "ESTABLISHED", 
            "--ctdir", "REPLY", 
            "--ctreplsrcport", &port, 
            "-j", "RETURN"
        ]).status();
        
        if check_out.is_err() || !check_out.unwrap().success() {
            let _ = Command::new("iptables").args([
                "-A", CHAIN_OUT, 
                "-p", proto, 
                "-m", "conntrack", 
                "--ctstate", "ESTABLISHED", 
                "--ctdir", "REPLY", 
                "--ctreplsrcport", &port, 
                "-j", "RETURN"
            ]).status();
        }
    }
}

fn remove_iptables_rule(rule: &Rule) {
    let port = get_port(&rule.listen);
    if port.is_empty() { return; }
    
    for proto in ["tcp", "udp"] {
        loop {
            let s = Command::new("iptables").args(["-D", CHAIN_IN, "-p", proto, "--dport", &port, "-j", "RETURN"]).status();
            if s.is_err() || !s.unwrap().success() { break; }
        }
        loop {
            let s = Command::new("iptables").args([
                "-D", CHAIN_OUT, 
                "-p", proto, 
                "-m", "conntrack", 
                "--ctstate", "ESTABLISHED", 
                "--ctdir", "REPLY", 
                "--ctreplsrcport", &port, 
                "-j", "RETURN"
            ]).status();
            if s.is_err() || !s.unwrap().success() { break; }
        }
    }
}

fn default_server_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "server".to_string())
}

fn normalize_rate(rate: &str) -> String {
    let r = rate.trim().to_lowercase();
    if r.ends_with("kbps") {
        r.replace("kbps", "kbit")
    } else if r.ends_with("mbps") {
        r.replace("mbps", "mbit")
    } else if r.ends_with("gbps") {
        r.replace("gbps", "gbit")
    } else {
        r
    }
}

fn get_default_interface() -> String {
    let output = Command::new("ip")
        .args(["route"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    output
        .lines()
        .find(|l| l.starts_with("default"))
        .and_then(|l| l.split_whitespace().nth(4))
        .unwrap_or("eth0")
        .to_string()
}

fn apply_tc_limit(port: &str, rate: &str) -> Result<(), String> {
    let interface = get_default_interface();
    let rate = normalize_rate(rate);

    let _ = Command::new("tc")
        .args(["qdisc", "add", "dev", &interface, "root", "handle", "1:", "htb", "default", "30"])
        .status();
    let _ = Command::new("tc")
        .args(["class", "add", "dev", &interface, "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit"])
        .status();

    let class_id = format!("1:{:x}", 0x1000 + port.parse::<u16>().unwrap_or(0));
    let _ = Command::new("tc")
        .args(["class", "add", "dev", &interface, "parent", "1:1", "classid", &class_id, "htb", "rate", &rate, "ceil", &rate])
        .status();

    let filter_prio = (port.parse::<u16>().unwrap_or(0) % 1000 + 1).to_string();
    let _ = Command::new("tc")
        .args([
            "filter", "add", "dev", &interface, "protocol", "ip", "parent", "1:0", "prio", &filter_prio, "u32",
            "match", "ip", "protocol", "6", "0xff", "match", "ip", "sport", port, "0xffff", "flowid", &class_id
        ])
        .status();
    Ok(())
}

fn remove_tc_limit(port: &str) -> Result<(), String> {
    let interface = get_default_interface();
    let class_id = format!("1:{:x}", 0x1000 + port.parse::<u16>().unwrap_or(0));
    let _ = Command::new("tc")
        .args(["class", "del", "dev", &interface, "classid", &class_id])
        .status();
    Ok(())
}

fn apply_bandwidth_if_needed(rule: &Rule) {
    let port = get_port(&rule.listen);
    if port.is_empty() { return; }
    if rule.bandwidth_enabled && !rule.bandwidth_limit.trim().is_empty() {
        let _ = apply_tc_limit(&port, &rule.bandwidth_limit);
    } else {
        let _ = remove_tc_limit(&port);
    }
}

async fn send_telegram_notification(config: &NotificationConfig, message: &str) -> Result<(), String> {
    if !config.telegram_enabled || config.telegram_bot_token.trim().is_empty() || config.telegram_chat_id.trim().is_empty() {
        return Ok(());
    }
    let url = format!("https://api.telegram.org/bot{}/sendMessage", config.telegram_bot_token);
    let client = Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "chat_id": config.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("telegram status {}", resp.status()));
    }
    Ok(())
}

async fn send_wecom_notification(config: &NotificationConfig, message: &str) -> Result<(), String> {
    if !config.wecom_enabled || config.wecom_webhook_url.trim().is_empty() {
        return Ok(());
    }
    let client = Client::new();
    let resp = client
        .post(&config.wecom_webhook_url)
        .json(&serde_json::json!({
            "msgtype": "text",
            "text": { "content": message }
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("wecom status {}", resp.status()));
    }
    Ok(())
}

fn spawn_notification(config: NotificationConfig, message: String) {
    if !config.telegram_enabled && !config.wecom_enabled {
        return;
    }
    tokio::spawn(async move {
        let _ = send_telegram_notification(&config, &message).await;
        let _ = send_wecom_notification(&config, &message).await;
    });
}

fn should_reset_today(reset_day: u8, now: DateTime<Utc>) -> bool {
    reset_day > 0 && reset_day <= 31 && now.day() as u8 == reset_day
}

fn check_monthly_resets(state: &Arc<AppState>) {
    let mut data = state.data.lock().unwrap();
    let mut last_map = state.last_traffic_map.lock().unwrap();
    let now = Utc::now();
    let ym = now.format("%Y-%m").to_string();
    let mut changed = false;
    let mut notify_msgs: Vec<String> = Vec::new();
    let notify_cfg = data.notifications.clone();

    for rule in data.rules.iter_mut() {
        if rule.reset_day == 0 { continue; }
        if !should_reset_today(rule.reset_day, now) { continue; }
        if rule.last_reset_month == ym { continue; }

        rule.traffic_used = 0;
        rule.status_msg = String::new();
        rule.last_reset_month = ym.clone();
        changed = true;

        let port = get_port(&rule.listen);
        if rule.enabled {
            remove_iptables_rule(rule);
            add_iptables_rule(rule);
            apply_bandwidth_if_needed(rule);
        }
        if !port.is_empty() {
            last_map.remove(&port);
        }

        notify_msgs.push(format!("规则 {} 已执行月度流量重置。", rule.name));
    }

    if changed {
        save_json(&data);
    }

    drop(data);
    drop(last_map);
    for msg in notify_msgs {
        spawn_notification(notify_cfg.clone(), msg);
    }
}
fn fetch_iptables_counters() -> HashMap<String, TrafficStats> {
    let mut map: HashMap<String, TrafficStats> = HashMap::new();
    
    let output = match Command::new("iptables-save").arg("-t").arg("filter").arg("-c").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return map,
    };

    for line in output.lines() {
        if !line.starts_with('[') { continue; }
        
        let end_bracket = match line.find(']') { Some(i) => i, None => continue };
        let content = &line[1..end_bracket];
        let parts: Vec<&str> = content.split(':').collect();
        if parts.len() != 2 { continue; }
        let bytes: u64 = parts[1].parse().unwrap_or(0);
        
        if bytes == 0 { continue; }

        let is_in = line.contains(&format!("-A {}", CHAIN_IN));
        let is_out = line.contains(&format!("-A {}", CHAIN_OUT));

        if !is_in && !is_out { continue; }

        let port_flag = if is_in { "--dport" } else { "--ctreplsrcport" };
        
        if let Some(pos) = line.find(port_flag) {
            let rest = &line[pos + port_flag.len()..];
            let port = rest.split_whitespace().next().unwrap_or("");
            if !port.is_empty() {
                let entry = map.entry(port.to_string()).or_insert(TrafficStats { in_bytes: 0, out_bytes: 0 });
                if is_in {
                    entry.in_bytes += bytes;
                } else {
                    entry.out_bytes += bytes;
                }
            }
        }
    }
    map
}

fn update_traffic_and_check(state: &Arc<AppState>) {
    let current_counters = fetch_iptables_counters();
    let mut last_map = state.last_traffic_map.lock().unwrap();
    let mut data = state.data.lock().unwrap();

    let now = Utc::now();
    let now_ts = now.timestamp_millis() as u64;
    let mut changed = false;
    let mut notify_msgs: Vec<String> = Vec::new();
    let notify_cfg = data.notifications.clone();

    for rule in data.rules.iter_mut() {
        if !rule.enabled { continue; }
        let port = get_port(&rule.listen);
        if port.is_empty() { continue; }

        let curr = *current_counters.get(&port).unwrap_or(&TrafficStats{in_bytes:0, out_bytes:0});
        let last = *last_map.get(&port).unwrap_or(&TrafficStats{in_bytes:0, out_bytes:0});

        let delta_in = if curr.in_bytes >= last.in_bytes { curr.in_bytes - last.in_bytes } else { curr.in_bytes };
        let delta_out = if curr.out_bytes >= last.out_bytes { curr.out_bytes - last.out_bytes } else { curr.out_bytes };

        let usage_inc = match rule.billing_mode.as_str() {
            "double" => delta_in + delta_out,
            _ => delta_out,
        };

        if usage_inc > 0 {
            rule.traffic_used += usage_inc;
            changed = true;
            last_map.insert(port.clone(), curr);
        } else {
            last_map.insert(port.clone(), curr);
        }

        if rule.expire_date > 0 && now_ts > rule.expire_date {
            rule.enabled = false;
            rule.status_msg = "已过期".to_string();
            changed = true;
            remove_iptables_rule(rule);
            let _ = remove_tc_limit(&port);
            notify_msgs.push(format!("规则 {} 已过期，已自动停用。", rule.name));
        }

        if rule.traffic_limit > 0 && rule.traffic_used >= rule.traffic_limit {
            rule.enabled = false;
            rule.status_msg = "流量耗尽".to_string();
            changed = true;
            remove_iptables_rule(rule);
            let _ = remove_tc_limit(&port);
            notify_msgs.push(format!("规则 {} 流量已耗尽，已自动停用。", rule.name));
        }
    }

    if changed {
        save_json(&data);
        save_config_toml(&data);
    }

    drop(data);
    drop(last_map);
    for msg in notify_msgs {
        spawn_notification(notify_cfg.clone(), msg);
    }
}
fn load_or_init_data() -> AppData {
    if let Ok(content) = fs::read_to_string(DATA_FILE) {
        if let Ok(mut data) = serde_json::from_str::<AppData>(&content) {
            let mut changed = false;
            data.rules.retain(|r| r.name != "system-keepalive");
            for r in data.rules.iter_mut() {
                if r.remark.is_empty() { r.remark = r.name.clone(); }
                if r.billing_mode.is_empty() { r.billing_mode = default_billing_mode(); }
                if r.reset_day > 31 { r.reset_day = 0; }
            }
            if data.notifications.server_name.is_empty() {
                data.notifications.server_name = default_server_name();
                changed = true;
            }
            if data.api_token.trim().is_empty() {
                data.api_token = generate_api_token();
                changed = true;
            }
            for n in data.remote_nodes.iter_mut() {
                if n.port == 0 { n.port = default_panel_port(); changed = true; }
                if n.name.trim().is_empty() && !n.host.trim().is_empty() {
                    n.name = n.host.clone();
                    changed = true;
                }
            }
            if changed { save_json(&data); }
            save_config_toml(&data);
            return data;
        }
    }

    let admin = AdminConfig {
        username: std::env::var("PANEL_USER").unwrap_or("admin".to_string()),
        pass_hash: std::env::var("PANEL_PASS").unwrap_or("123456".to_string()),
        bg_pc: default_bg_pc(),
        bg_mobile: default_bg_mobile(),
    };
    let notifications = NotificationConfig { server_name: default_server_name(), ..Default::default() };
    let data = AppData { admin, rules: Vec::new(), remote_nodes: Vec::new(), api_token: generate_api_token(), notifications };
    save_config_toml(&data);
    save_json(&data);
    data
}
fn save_json(data: &AppData) {
    let json_str = serde_json::to_string_pretty(data).unwrap();
    let _ = fs::write(DATA_FILE, json_str);
}

fn save_config_toml(data: &AppData) {
    let mut endpoints: Vec<RealmEndpoint> = data.rules.iter()
        .filter(|r| r.enabled)
        .map(|r| RealmEndpoint {
            name: r.name.clone(),
            listen: r.listen.clone(),
            remote: r.remote.clone(),
            remote_list: r.remote_list.clone(),
            r#type: "tcp+udp".to_string(),
        })
        .collect();
    
    endpoints.push(RealmEndpoint {
        name: "system-keepalive".to_string(),
        listen: "127.0.0.1:65534".to_string(),
        remote: "127.0.0.1:65534".to_string(),
        remote_list: Vec::new(),
        r#type: "tcp+udp".to_string(),
    });

    let config = RealmConfig { endpoints };
    let toml_str = toml::to_string(&config).unwrap();
    let _ = fs::write(REALM_CONFIG, toml_str);
    
    let _ = Command::new("systemctl").arg("restart").arg("realm").status();
}

fn check_auth(cookies: &Cookies, state: &AppData) -> bool {
    if let Some(cookie) = cookies.get("auth_session") {
        return cookie.value() == state.admin.pass_hash;
    }
    false
}

fn generate_api_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn check_api_token(headers: &HeaderMap, state: &AppData) -> bool {
    if let Some(token) = headers.get("X-API-Token").and_then(|v| v.to_str().ok()) {
        !state.api_token.is_empty() && token == state.api_token
    } else {
        false
    }
}

fn check_auth_or_token(cookies: &Cookies, headers: &HeaderMap, state: &AppData) -> bool {
    check_auth(cookies, state) || check_api_token(headers, state)
}

async fn index_page(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return axum::response::Redirect::to("/login").into_response(); }
    let html = DASHBOARD_HTML
        .replace("{{USER}}", &data.admin.username)
        .replace("{{BG_PC}}", &data.admin.bg_pc)
        .replace("{{BG_MOBILE}}", &data.admin.bg_mobile);
    Html(html).into_response()
}

async fn login_page(State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    let html = LOGIN_HTML
        .replace("{{BG_PC}}", &data.admin.bg_pc)
        .replace("{{BG_MOBILE}}", &data.admin.bg_mobile);
    Html(html).into_response()
}

#[derive(Deserialize)] struct LoginParams { username: String, password: String }
async fn login_action(cookies: Cookies, State(state): State<Arc<AppState>>, Form(form): Form<LoginParams>) -> Response {
    let data = state.data.lock().unwrap();
    if form.username == data.admin.username && form.password == data.admin.pass_hash {
        let mut cookie = Cookie::new("auth_session", data.admin.pass_hash.clone());
        cookie.set_path("/"); cookie.set_http_only(true); 
        cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
        cookies.add(cookie);
        axum::response::Redirect::to("/").into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
async fn logout_action(cookies: Cookies) -> Response {
    let mut cookie = Cookie::new("auth_session", "");
    cookie.set_path("/"); cookies.remove(cookie);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn get_rules(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    Json(RulesResponse { rules: data.rules.clone() }).into_response()
}

#[derive(Deserialize)]
struct AddRuleReq {
    name: String,
    listen: String,
    remote: String,
    #[serde(default)]
    remote_list: Vec<RemoteTarget>,
    expire_date: u64,
    traffic_limit: u64,
    #[serde(default)]
    bandwidth_limit: String,
    #[serde(default)]
    bandwidth_enabled: bool,
    #[serde(default = "default_billing_mode")]
    billing_mode: String,
    #[serde(default)]
    reset_day: u8,
    #[serde(default)]
    remark: String,
}
async fn add_rule(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Json(req): Json<AddRuleReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if req.name.trim().is_empty() || req.listen.trim().is_empty() || req.remote.trim().is_empty() {
        return Json(serde_json::json!({"status":"error", "message": "所有字段都不能为空！"})).into_response();
    }
    let new_port = get_port(&req.listen);
    if new_port.is_empty() { return Json(serde_json::json!({"status":"error", "message": "端口格式错误"})).into_response(); }
    if data.rules.iter().any(|r| get_port(&r.listen) == new_port) {
        return Json(serde_json::json!({"status":"error", "message": "端口已被占用！"})).into_response();
    }
    let billing_mode = if req.billing_mode.is_empty() { default_billing_mode() } else { req.billing_mode.clone() };
    let remark = if req.remark.trim().is_empty() { req.name.clone() } else { req.remark.clone() };
    let reset_day = if req.reset_day > 31 { 0 } else { req.reset_day };

    let rule = Rule {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        listen: req.listen,
        remote: req.remote,
        remote_list: Vec::new(),
        enabled: true,
        expire_date: req.expire_date,
        traffic_limit: req.traffic_limit,
        traffic_used: 0,
        status_msg: String::new(),
        bandwidth_limit: req.bandwidth_limit,
        bandwidth_enabled: req.bandwidth_enabled,
        billing_mode,
        reset_day,
        remark,
        last_reset_month: String::new(),
    };
    add_iptables_rule(&rule);
    apply_bandwidth_if_needed(&rule);
    data.rules.push(rule);
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}
async fn batch_add_rules(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Json(reqs): Json<Vec<AddRuleReq>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let mut added_count = 0;
    for req in reqs {
        let new_port = get_port(&req.listen);
        if new_port.is_empty() { continue; }
        if data.rules.iter().any(|r| get_port(&r.listen) == new_port) { continue; }
        let billing_mode = if req.billing_mode.is_empty() { default_billing_mode() } else { req.billing_mode.clone() };
        let remark = if req.remark.trim().is_empty() { req.name.clone() } else { req.remark.clone() };
        let reset_day = if req.reset_day > 31 { 0 } else { req.reset_day };

        let rule = Rule {
            id: uuid::Uuid::new_v4().to_string(),
            name: req.name,
            listen: req.listen,
            remote: req.remote,
            remote_list: Vec::new(),
            enabled: true,
            expire_date: req.expire_date,
            traffic_limit: req.traffic_limit,
            traffic_used: 0,
            status_msg: String::new(),
            bandwidth_limit: req.bandwidth_limit,
            bandwidth_enabled: req.bandwidth_enabled,
            billing_mode,
            reset_day,
            remark,
            last_reset_month: String::new(),
        };
        add_iptables_rule(&rule);
        apply_bandwidth_if_needed(&rule);
        data.rules.push(rule);
        added_count += 1;
    }
    if added_count > 0 { save_json(&data); save_config_toml(&data); }
    Json(serde_json::json!({"status":"ok", "message": format!("成功添加 {} 条规则", added_count)})).into_response()
}
async fn delete_all_rules(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    for r in &data.rules {
        let port = get_port(&r.listen);
        if !port.is_empty() { let _ = remove_tc_limit(&port); }
    }
    flush_realm_chains();
    data.rules.clear();
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok", "message": "所有规则已清空"})).into_response()
}
async fn download_backup(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let json_str = serde_json::to_string_pretty(&data.rules).unwrap();
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Content-Disposition", "attachment; filename=\"realm_backup.json\"")
        .body(axum::body::Body::from(json_str))
        .unwrap()
}

async fn restore_backup(cookies: Cookies, State(state): State<Arc<AppState>>, Json(backup_rules): Json<Vec<Rule>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if backup_rules.is_empty() { return Json(serde_json::json!({"status": "error", "message": "导入的数据为空"})).into_response(); }
    flush_realm_chains();
    data.rules = backup_rules;
    data.rules.retain(|r| r.name != "system-keepalive");
    for r in data.rules.iter_mut() {
        if r.remark.is_empty() { r.remark = r.name.clone(); }
        if r.billing_mode.is_empty() { r.billing_mode = default_billing_mode(); }
        if r.reset_day > 31 { r.reset_day = 0; }
        if r.enabled {
            add_iptables_rule(r);
            apply_bandwidth_if_needed(r);
        }
    }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok", "message": format!("成功恢复 {} 条规则", data.rules.len())})).into_response()
}
async fn toggle_rule(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        rule.enabled = !rule.enabled;
        let port = get_port(&rule.listen);
        if rule.enabled {
            rule.status_msg = String::new();
            add_iptables_rule(rule);
            apply_bandwidth_if_needed(rule);
        } else {
            remove_iptables_rule(rule);
            let _ = remove_tc_limit(&port);
        }
        save_json(&data); save_config_toml(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}
async fn reset_traffic(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    let mut last_map = state.last_traffic_map.lock().unwrap();

    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }

    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        let port = get_port(&rule.listen);
        rule.traffic_used = 0;
        rule.status_msg = String::new();

        if rule.enabled {
            remove_iptables_rule(rule);
            add_iptables_rule(rule);
            apply_bandwidth_if_needed(rule);
        }

        if !port.is_empty() {
            last_map.remove(&port);
        }

        save_json(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}
async fn delete_rule(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(pos) = data.rules.iter().position(|r| r.id == id) {
        remove_iptables_rule(&data.rules[pos]);
        let port = get_port(&data.rules[pos].listen);
        if !port.is_empty() { let _ = remove_tc_limit(&port); }
        data.rules.remove(pos);
    }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}
#[derive(Deserialize)]
struct UpdateRuleReq {
    name: String,
    listen: String,
    remote: String,
    #[serde(default)]
    remote_list: Vec<RemoteTarget>,
    expire_date: u64,
    traffic_limit: u64,
    #[serde(default)]
    bandwidth_limit: String,
    #[serde(default)]
    bandwidth_enabled: bool,
    #[serde(default = "default_billing_mode")]
    billing_mode: String,
    #[serde(default)]
    reset_day: u8,
    #[serde(default)]
    remark: String,
}
async fn update_rule(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<UpdateRuleReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let new_port = get_port(&req.listen);
    if data.rules.iter().any(|r| r.id != id && get_port(&r.listen) == new_port) {
        return Json(serde_json::json!({"status":"error", "message": "端口已被占用！"})).into_response();
    }
    if let Some(idx) = data.rules.iter().position(|r| r.id == id) {
        let old_port = get_port(&data.rules[idx].listen);
        remove_iptables_rule(&data.rules[idx]);
        if !old_port.is_empty() { let _ = remove_tc_limit(&old_port); }

        let billing_mode = if req.billing_mode.is_empty() { default_billing_mode() } else { req.billing_mode.clone() };
        let remark = if req.remark.trim().is_empty() { req.name.clone() } else { req.remark.clone() };
        let reset_day = if req.reset_day > 31 { 0 } else { req.reset_day };

        let rule = &mut data.rules[idx];
        rule.name = req.name;
        rule.listen = req.listen;
        rule.remote = req.remote;
        rule.expire_date = req.expire_date;
        rule.traffic_limit = req.traffic_limit;
        rule.bandwidth_limit = req.bandwidth_limit;
        rule.bandwidth_enabled = req.bandwidth_enabled;
        rule.billing_mode = billing_mode;
        rule.reset_day = reset_day;
        rule.remark = remark;

        if rule.enabled {
            if rule.status_msg == "流量耗尽" && (req.traffic_limit == 0 || req.traffic_limit > rule.traffic_used) {
                rule.status_msg = String::new();
            }
            add_iptables_rule(rule);
            apply_bandwidth_if_needed(rule);
        }
        save_json(&data); save_config_toml(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}
#[derive(Deserialize)]
struct BandwidthUpdate {
    enabled: bool,
    rate: String,
}

async fn update_bandwidth(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<BandwidthUpdate>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        if req.enabled && req.rate.trim().is_empty() {
            return Json(serde_json::json!({"status":"error", "message": "限速值不能为空"})).into_response();
        }
        rule.bandwidth_enabled = req.enabled;
        rule.bandwidth_limit = req.rate;
        if rule.enabled { apply_bandwidth_if_needed(rule); }
        save_json(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

#[derive(Deserialize)]
struct ResetDayUpdate {
    reset_day: u8,
}

async fn update_reset_day(cookies: Cookies, headers: HeaderMap, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<ResetDayUpdate>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth_or_token(&cookies, &headers, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if req.reset_day > 31 { return Json(serde_json::json!({"status":"error", "message": "重置日必须在 0-31"})).into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        rule.reset_day = req.reset_day;
        save_json(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

#[derive(Deserialize)]
struct NotificationUpdate {
    telegram_enabled: bool,
    telegram_bot_token: String,
    telegram_chat_id: String,
    wecom_enabled: bool,
    wecom_webhook_url: String,
    server_name: String,
}

async fn get_notifications(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    Json(data.notifications.clone()).into_response()
}

async fn update_notifications(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<NotificationUpdate>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    data.notifications.telegram_enabled = req.telegram_enabled;
    data.notifications.telegram_bot_token = req.telegram_bot_token;
    data.notifications.telegram_chat_id = req.telegram_chat_id;
    data.notifications.wecom_enabled = req.wecom_enabled;
    data.notifications.wecom_webhook_url = req.wecom_webhook_url;
    data.notifications.server_name = if req.server_name.trim().is_empty() { default_server_name() } else { req.server_name };
    save_json(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn test_notifications(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let cfg = data.notifications.clone();
    if !cfg.telegram_enabled && !cfg.wecom_enabled {
        return Json(serde_json::json!({"status":"error", "message": "未启用任何通知"})).into_response();
    }
    let server_name = if cfg.server_name.trim().is_empty() { "服务器".to_string() } else { cfg.server_name.clone() };
    let msg = format!("{} 通知测试：端口流量狗面板配置已生效。", server_name);
    drop(data);

    let mut ok = true;
    if let Err(_) = send_telegram_notification(&cfg, &msg).await { ok = false; }
    if let Err(_) = send_wecom_notification(&cfg, &msg).await { ok = false; }

    if ok {
        Json(serde_json::json!({"status":"ok"})).into_response()
    } else {
        Json(serde_json::json!({"status":"error", "message": "发送失败"})).into_response()
    }
}
#[derive(Deserialize)]
struct NodeReq {
    name: String,
    host: String,
    #[serde(default)]
    port: u16,
    api_token: String,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn get_api_token(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    Json(serde_json::json!({"token": data.api_token})).into_response()
}

async fn regenerate_api_token(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    data.api_token = generate_api_token();
    save_json(&data);
    Json(serde_json::json!({"token": data.api_token})).into_response()
}

async fn get_nodes(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    Json(serde_json::json!({"nodes": data.remote_nodes.clone()})).into_response()
}

async fn add_node(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<NodeReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let name = req.name.trim().to_string();
    let host = req.host.trim().to_string();
    let token = req.api_token.trim().to_string();
    if name.is_empty() || host.is_empty() || token.is_empty() {
        return Json(serde_json::json!({"status":"error", "message":"名称、地址和令牌不能为空"})).into_response();
    }
    let port = if req.port == 0 { default_panel_port() } else { req.port };
    if data.remote_nodes.iter().any(|n| n.host == host && n.port == port) {
        return Json(serde_json::json!({"status":"error", "message":"节点已存在"})).into_response();
    }
    let node = RemoteNode {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        host,
        port,
        api_token: token,
        enabled: req.enabled.unwrap_or(true),
    };
    data.remote_nodes.push(node);
    save_json(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn update_node(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<NodeReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let name = req.name.trim().to_string();
    let host = req.host.trim().to_string();
    let token = req.api_token.trim().to_string();
    if name.is_empty() || host.is_empty() || token.is_empty() {
        return Json(serde_json::json!({"status":"error", "message":"名称、地址和令牌不能为空"})).into_response();
    }
    let port = if req.port == 0 { default_panel_port() } else { req.port };
    if let Some(node) = data.remote_nodes.iter_mut().find(|n| n.id == id) {
        node.name = name;
        node.host = host;
        node.port = port;
        node.api_token = token;
        node.enabled = req.enabled.unwrap_or(true);
        save_json(&data);
        return Json(serde_json::json!({"status":"ok"})).into_response();
    }
    Json(serde_json::json!({"status":"error", "message":"节点不存在"})).into_response()
}

async fn delete_node(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(pos) = data.remote_nodes.iter().position(|n| n.id == id) {
        data.remote_nodes.remove(pos);
        save_json(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn call_remote_api(
    node: &RemoteNode,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if !node.enabled {
        return Err("节点已禁用".to_string());
    }
    if node.host.trim().is_empty() {
        return Err("节点地址为空".to_string());
    }
    if node.api_token.trim().is_empty() {
        return Err("节点令牌为空".to_string());
    }
    let base = if node.host.starts_with("http://") || node.host.starts_with("https://") {
        node.host.clone()
    } else {
        format!("http://{}", node.host)
    };
    let url = format!("{}:{}{}", base.trim_end_matches('/'), node.port, path);

    let client = Client::new();
    let mut req = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        _ => return Err("Invalid method".to_string()),
    };

    req = req.header("X-API-Token", &node.api_token)
        .timeout(Duration::from_secs(10));

    if let Some(b) = body {
        req = req.json(&b);
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("远程响应异常: {}", text));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn get_remote_rules(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let node = {
        let data = state.data.lock().unwrap();
        if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
        match data.remote_nodes.iter().find(|n| n.id == id) {
            Some(n) => n.clone(),
            None => return Json(serde_json::json!({"status":"error","message":"节点不存在"})).into_response(),
        }
    };
    match call_remote_api(&node, "GET", "/api/rules", None).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"status":"error","message":e})).into_response(),
    }
}

async fn add_remote_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<serde_json::Value>) -> Response {
    let node = {
        let data = state.data.lock().unwrap();
        if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
        match data.remote_nodes.iter().find(|n| n.id == id) {
            Some(n) => n.clone(),
            None => return Json(serde_json::json!({"status":"error","message":"节点不存在"})).into_response(),
        }
    };
    match call_remote_api(&node, "POST", "/api/rules", Some(req)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"status":"error","message":e})).into_response(),
    }
}

async fn update_remote_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path((id, rule_id)): Path<(String, String)>, Json(req): Json<serde_json::Value>) -> Response {
    let node = {
        let data = state.data.lock().unwrap();
        if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
        match data.remote_nodes.iter().find(|n| n.id == id) {
            Some(n) => n.clone(),
            None => return Json(serde_json::json!({"status":"error","message":"节点不存在"})).into_response(),
        }
    };
    let path = format!("/api/rules/{}", rule_id);
    match call_remote_api(&node, "PUT", &path, Some(req)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"status":"error","message":e})).into_response(),
    }
}

async fn delete_remote_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path((id, rule_id)): Path<(String, String)>) -> Response {
    let node = {
        let data = state.data.lock().unwrap();
        if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
        match data.remote_nodes.iter().find(|n| n.id == id) {
            Some(n) => n.clone(),
            None => return Json(serde_json::json!({"status":"error","message":"节点不存在"})).into_response(),
        }
    };
    let path = format!("/api/rules/{}", rule_id);
    match call_remote_api(&node, "DELETE", &path, None).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"status":"error","message":e})).into_response(),
    }
}

async fn toggle_remote_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path((id, rule_id)): Path<(String, String)>) -> Response {
    let node = {
        let data = state.data.lock().unwrap();
        if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
        match data.remote_nodes.iter().find(|n| n.id == id) {
            Some(n) => n.clone(),
            None => return Json(serde_json::json!({"status":"error","message":"节点不存在"})).into_response(),
        }
    };
    let path = format!("/api/rules/{}/toggle", rule_id);
    match call_remote_api(&node, "POST", &path, None).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"status":"error","message":e})).into_response(),
    }
}
#[derive(Deserialize)] struct AccountUpdate { username: String, password: String }
async fn update_account(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<AccountUpdate>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    data.admin.username = req.username;
    if !req.password.is_empty() { data.admin.pass_hash = req.password; }
    let mut cookie = Cookie::new("auth_session", data.admin.pass_hash.clone());
    cookie.set_path("/"); cookie.set_http_only(true); cookies.add(cookie); save_json(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

#[derive(Deserialize)] struct BgUpdate { bg_pc: String, bg_mobile: String }
async fn update_bg(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<BgUpdate>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    data.admin.bg_pc = req.bg_pc; data.admin.bg_mobile = req.bg_mobile; save_json(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

// 多目标切换 API
async fn get_rule_targets(Path(id): Path<String>, cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter().find(|r| r.id == id) {
        Json(serde_json::json!({"targets": rule.remote_list})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Deserialize)]
struct AddTargetReq { address: String, label: String }

async fn add_rule_target(Path(id): Path<String>, cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<AddTargetReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        rule.remote_list.push(RemoteTarget { address: req.address, label: req.label });
        save_json(&data);
        Json(serde_json::json!({"status":"ok"})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn delete_rule_target(Path((id, idx)): Path<(String, usize)>, cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        if idx < rule.remote_list.len() {
            rule.remote_list.remove(idx);
            save_json(&data);
            Json(serde_json::json!({"status":"ok"})).into_response()
        } else {
            Json(serde_json::json!({"status":"error","message":"索引超出范围"})).into_response()
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Deserialize)]
struct SwitchTargetReq { index: usize }

async fn switch_rule_target(Path(id): Path<String>, cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<SwitchTargetReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        if req.index < rule.remote_list.len() {
            rule.remote = rule.remote_list[req.index].address.clone();
            save_json(&data);
            save_config_toml(&data);
            Json(serde_json::json!({"status":"ok"})).into_response()
        } else {
            Json(serde_json::json!({"status":"error","message":"索引超出范围"})).into_response()
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}


const LOGIN_HTML: &str = r#"
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no"><title>Realm Login</title><style>*{margin:0;padding:0;box-sizing:border-box}body{height:100vh;width:100vw;overflow:hidden;display:flex;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:url('{{BG_PC}}') no-repeat center center/cover;color:#374151}@media(max-width:768px){body{background-image:url('{{BG_MOBILE}}')}}.overlay{position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.05)}.box{position:relative;z-index:2;background:rgba(255,255,255,0.3);backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px);padding:2.5rem;border-radius:24px;border:1px solid rgba(255,255,255,0.4);box-shadow:0 8px 32px rgba(0,0,0,0.05);width:90%;max-width:380px;text-align:center}h2{margin-bottom:2rem;color:#374151;font-weight:600;letter-spacing:1px}input{width:100%;padding:14px;margin-bottom:1.2rem;border:1px solid rgba(255,255,255,0.5);border-radius:12px;outline:none;background:rgba(255,255,255,0.5);transition:0.3s;color:#374151}input:focus{background:rgba(255,255,255,0.9);border-color:#3b82f6}button{width:100%;padding:14px;background:rgba(59,130,246,0.85);color:white;border:none;border-radius:12px;cursor:pointer;font-weight:600;font-size:1rem;transition:0.3s;backdrop-filter:blur(5px)}button:hover{background:#2563eb;transform:translateY(-1px)}</style></head><body><div class="overlay"></div><div class="box"><h2>Realm Panel</h2><form onsubmit="doLogin(event)"><input type="text" id="u" placeholder="Username" required><input type="password" id="p" placeholder="Password" required><button type="submit" id="btn">登 录</button></form></div><script>async function doLogin(e){e.preventDefault();const b=document.getElementById('btn');b.innerText='登录中...';b.disabled=true;const res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`username=${encodeURIComponent(document.getElementById('u').value)}&password=${encodeURIComponent(document.getElementById('p').value)}`});if(res.redirected){location.href=res.url}else if(res.ok){location.href='/'}else{alert('用户名或密码错误');b.innerText='登 录';b.disabled=false}}</script></body></html>
"#;

const DASHBOARD_HTML: &str = r#"
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover"><title>Realm Panel</title><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet"><style>:root{--primary:#3b82f6;--danger:#f87171;--success:#34d399;--text-main:#374151}::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-thumb{background:rgba(0,0,0,0.1);border-radius:10px}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:0;height:100vh;height:100dvh;overflow:hidden;background:url('{{BG_PC}}') no-repeat center center/cover;display:flex;flex-direction:column;color:var(--text-main)}@media(max-width:768px){body{background-image:url('{{BG_MOBILE}}')}}.navbar{flex:0 0 auto;background:rgba(255,255,255,0.3);backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px);border-bottom:1px solid rgba(255,255,255,0.3);padding:0.8rem 2rem;display:flex;justify-content:space-between;align-items:center;z-index:10}.brand{font-weight:700;font-size:1.1rem;color:var(--text-main);display:flex;align-items:center;gap:10px}.container{flex:1;display:flex;flex-direction:column;max-width:1100px;margin:1.5rem auto;width:95%;overflow:hidden}.card-fixed{background:rgba(255,255,255,0.3);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.4);border-radius:18px;padding:1.2rem;margin-bottom:1.5rem;box-shadow:0 4px 15px rgba(0,0,0,0.03)}.card-scroll{flex:1;background:rgba(255,255,255,0.25);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.4);border-radius:18px;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 4px 15px rgba(0,0,0,0.03)}.table-wrapper{flex:1;overflow-y:auto;padding:0 1.5rem 1.5rem}table{width:100%;border-collapse:separate;border-spacing:0 10px}
thead th{position:sticky;top:0;background:rgba(255,255,255,0.4);backdrop-filter:blur(15px);z-index:5;padding:14px 12px;text-align:left;font-size:0.85rem;text-transform:uppercase;letter-spacing:1px;color:#6b7280;border-top:1px solid rgba(255,255,255,0.3);border-bottom:1px solid rgba(255,255,255,0.3)}
thead th:first-child{border-top-left-radius:15px;border-bottom-left-radius:15px;border-left:1px solid rgba(255,255,255,0.3)}
thead th:last-child{border-top-right-radius:15px;border-bottom-right-radius:15px;border-right:1px solid rgba(255,255,255,0.3)}
tbody tr{background:transparent;transition:0.3s}
@media(min-width:768px){tbody tr:hover td{background:rgba(255,255,255,0.7);transform:translateY(-1px);box-shadow:0 4px 10px rgba(0,0,0,0.02)}}
td{background:rgba(255,255,255,0.4);padding:14px 12px;font-size:0.92rem;font-weight:500;color:var(--text-main);border-top:1px solid rgba(255,255,255,0.3);border-bottom:1px solid rgba(255,255,255,0.3)}
td:first-child{border-left:1px solid rgba(255,255,255,0.3);border-top-left-radius:15px;border-bottom-left-radius:15px}
td:last-child{border-right:1px solid rgba(255,255,255,0.3);border-top-right-radius:15px;border-bottom-right-radius:15px}
.btn{padding:8px 12px;border-radius:10px;border:none;cursor:pointer;color:white;transition:0.2s;display:inline-flex;align-items:center;justify-content:center;gap:6px;font-weight:500}.btn-primary{background:var(--primary);opacity:0.9}.btn-danger{background:var(--danger);opacity:0.9}.btn-gray{background:rgba(0,0,0,0.05);color:var(--text-main)}.grid-input{display:grid;grid-template-columns:1.5fr 1fr 2fr auto auto;gap:12px}
.tools-group{display:flex;gap:5px}input{padding:10px 14px;border:1px solid rgba(0,0,0,0.05);background:rgba(255,255,255,0.5);border-radius:10px;outline:none;transition:0.3s;color:var(--text-main);font-weight:500}input:focus{border-color:var(--primary);background:white}.status-dot{height:7px;width:7px;border-radius:50%;display:inline-block;margin-right:8px}.bg-green{background:var(--success);box-shadow:0 0 8px var(--success)}.bg-gray{background:#9ca3af}.bg-red{background:var(--danger)}.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.1);z-index:100;justify-content:center;align-items:center;backdrop-filter:blur(8px)}.modal-box{background:rgba(255,255,255,0.9);width:90%;max-width:420px;padding:2rem;border-radius:20px;box-shadow:0 20px 40px rgba(0,0,0,0.1);animation:pop 0.3s ease}@keyframes pop{from{transform:scale(0.9);opacity:0}to{transform:scale(1);opacity:1}}.tab-header{display:flex;gap:20px;margin-bottom:20px;border-bottom:1px solid rgba(0,0,0,0.05)}.tab-btn{padding:10px 5px;cursor:pointer;font-size:0.9rem;color:#9ca3af}.tab-btn.active{color:var(--primary);border-bottom:2px solid var(--primary);font-weight:600}.tab-content{display:none}.tab-content.active{display:block}label{display:block;margin:12px 0 6px;font-size:0.85rem;color:#6b7280}
.info-row{display:flex;justify-content:space-between;margin-bottom:8px;font-size:0.9rem}.info-val{font-weight:600}
.progress-bar{width:100%;height:10px;background:rgba(0,0,0,0.1);border-radius:5px;overflow:hidden;margin-top:5px}.progress-fill{height:100%;background:var(--primary);width:0%}
.expire-warning{color:var(--danger);font-size:0.8rem;margin-top:2px}
@media(max-width:768px){.grid-input{grid-template-columns:1fr; gap:10px}.navbar{padding:0.8rem 1rem}.nav-text{display:none}thead{display:none}tbody tr{display:flex;flex-direction:column;border-radius:18px!important;margin-bottom:12px;padding:15px;border:1px solid rgba(255,255,255,0.3);background:rgba(255,255,255,0.4)}td{padding:6px 0;display:flex;justify-content:space-between;border-radius:0!important;align-items:center;border:none;background:transparent}td::before{content:attr(data-label);color:#9ca3af;font-size:0.85rem}td[data-label="操作"]{justify-content:flex-end;gap:10px;margin-top:8px;padding-top:10px;border-top:1px solid rgba(0,0,0,0.05)}td[data-label="操作"] .btn{flex:none;width:auto;padding:6px 14px;border-radius:8px;font-size:0.85rem}td[data-label="操作"] .btn-gray{background:transparent;border:1px solid rgba(0,0,0,0.15);color:#555}td[data-label="操作"] .btn-primary{background:var(--primary);color:white}td[data-label="操作"] .btn-danger{background:rgba(239,68,68,0.1);color:var(--danger);border:1px solid rgba(239,68,68,0.2)}.tools-group{width:100%;margin-top:5px}.tools-group .btn{flex:1;justify-content:center;padding:10px 0;font-size:0.85rem}}</style></head><body><div class="navbar"><div class="brand"><i class="fas fa-layer-group"></i> <span class="nav-text">Realm 转发面板</span></div><div class="nav-actions" style="display:flex;gap:15px"><button class="btn btn-gray" onclick="openTrafficDog()" style="background:#f59e0b;color:white"><i class="fas fa-dog"></i> <span class="nav-text">流量狗</span></button><button class="btn btn-gray" onclick="openSettings()"><i class="fas fa-sliders-h"></i> <span class="nav-text">面板设置</span></button><button class="btn btn-danger" onclick="doLogout()"><i class="fas fa-power-off"></i></button></div></div><div class="container"><div class="card card-fixed"><div class="grid-input"><input id="n" placeholder="备注名称"><input id="l" placeholder="监听端口 (如 10000)"><input id="r" placeholder="目标 (例 1.2.3.4:443)"><button class="btn btn-primary" onclick="openAddModal()"><i class="fas fa-plus"></i> 添加</button><div class="tools-group"><button class="btn btn-primary" onclick="openBatch()" style="background:#8b5cf6"><i class="fas fa-paste"></i> 批量</button><button class="btn btn-danger" onclick="delAll()" style="background:#ef4444"><i class="fas fa-trash"></i> 全删</button><button class="btn btn-primary" onclick="downloadBackup()" style="background:#059669"><i class="fas fa-download"></i> 导出</button><button class="btn btn-danger" onclick="openRestore()" style="background:#d97706"><i class="fas fa-upload"></i> 导入</button></div></div></div><div class="card card-scroll"><div style="padding:1.2rem 1.5rem;font-weight:700;font-size:1rem;opacity:0.8">转发规则管理</div><div class="table-wrapper"><table id="ruleTable"><thead><tr><th>状态</th><th>备注</th><th>监听</th><th>目标</th><th>流量 (In/Out)</th><th style="width:180px;text-align:right;padding-right:20px">操作</th></tr></thead><tbody id="list"></tbody></table><div id="emptyView" style="display:none;text-align:center;padding:50px;color:#9ca3af"><i class="fas fa-inbox" style="font-size:2rem;display:block;margin-bottom:10px"></i>暂无规则</div></div></div></div>
<div id="ruleModal" class="modal"><div class="modal-box"><h3 id="modalTitle">添加规则</h3><input type="hidden" id="edit_id"><label>备注</label><input id="mod_n"><label>监听端口</label><input id="mod_l"><label>目标地址</label><input id="mod_r"><div id="targetsSection" style="display:none;margin:15px 0;padding:15px;border:1px dashed #ddd;border-radius:10px;background:rgba(0,0,0,0.02)"><label style="display:flex;justify-content:space-between;align-items:center">备用目标列表 <button type="button" class="btn btn-gray" style="padding:4px 10px;font-size:0.8rem" onclick="addTargetRow()"><i class="fas fa-plus"></i> 添加</button></label><div id="targetsList"></div></div><label>到期时间 (留空不限制)</label><input type="datetime-local" id="mod_e"><label>流量限制 (留空或0不限制)</label><div style="display:flex;gap:10px"><input id="mod_t_val" type="number" placeholder="数值" style="flex:1"><select id="mod_t_unit" style="padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,0.05);background:rgba(255,255,255,0.5)"><option value="MB">MB</option><option value="GB">GB</option></select></div><label>带宽限速</label><div style="display:flex;gap:10px;align-items:center"><input id="mod_bw_en" type="checkbox" style="width:auto"><input id="mod_bw_rate" placeholder="如 100Mbps" style="flex:1"></div><label>计费模式</label><select id="mod_billing" style="padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,0.05);background:rgba(255,255,255,0.5)"><option value="single">单向</option><option value="double">双向</option></select><label>月度重置日 (0=不重置)</label><input id="mod_reset_day" type="number" min="0" max="31"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveRule()">保存</button></div></div></div>
<div id="viewModal" class="modal"><div class="modal-box"><h3 style="margin-bottom:20px;border-bottom:1px solid #eee;padding-bottom:10px">规则详情</h3><div class="info-row"><span>备注</span><span class="info-val" id="view_n"></span></div><div class="info-row"><span>监听</span><span class="info-val" id="view_l"></span></div><div class="info-row"><span>目标</span><span class="info-val" id="view_r"></span></div><div style="margin:15px 0;border-top:1px dashed #ddd;padding-top:10px"></div><div id="view_expire_sec"><div class="info-row"><span>到期时间</span><span class="info-val" id="view_e_date"></span></div><div style="text-align:right;font-size:0.8rem;color:#666" id="view_e_remain"></div></div><div style="margin:15px 0;border-top:1px dashed #ddd;padding-top:10px"></div><div id="view_traffic_sec"><div class="info-row"><span>流量使用 (Max)</span><span class="info-val"><span id="view_t_used"></span> / <span id="view_t_limit"></span></span></div><div class="progress-bar"><div class="progress-fill" id="view_t_bar"></div></div><div style="text-align:right;margin-top:5px"><button class="btn btn-gray" style="font-size:0.7rem;padding:4px 8px" onclick="resetTraffic()">重置流量</button></div></div><div style="margin:15px 0;border-top:1px dashed #ddd;padding-top:10px"></div><div id="view_bw_sec"><div class="info-row"><span>带宽限速</span><span class="info-val" id="view_bw"></span></div><div class="info-row"><span>计费模式</span><span class="info-val" id="view_bill"></span></div><div class="info-row"><span>月度重置</span><span class="info-val" id="view_reset"></span></div></div><div style="margin-top:25px;display:flex;justify-content:flex-end;"><button class="btn btn-primary" onclick="closeModal()">关闭</button></div></div></div>
<div id="setModal" class="modal"><div class="modal-box" style="max-width:720px"><div class="tab-header"><div class="tab-btn active" onclick="switchTab(0)">管理账户</div><div class="tab-btn" onclick="switchTab(1)">个性背景</div><div class="tab-btn" onclick="switchTab(2)">通知设置</div><div class="tab-btn" onclick="switchTab(3)">远程节点</div></div><div class="tab-content active" id="tab0"><label>用户名</label><input id="set_u" value="{{USER}}"><label>重置密码 (留空保持不变)</label><input id="set_p" type="password"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveAccount()">确认修改</button></div></div><div class="tab-content" id="tab1"><label>PC端壁纸 URL</label><input id="bg_pc" value="{{BG_PC}}"><label>手机端壁纸 URL</label><input id="bg_mob" value="{{BG_MOBILE}}"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveBg()">应用背景</button></div></div><div class="tab-content" id="tab2"><label>服务器名称</label><input id="nt_server"><label><input id="nt_tg_en" type="checkbox" style="width:auto;margin-right:6px">Telegram 启用</label><label>Bot Token</label><input id="nt_tg_token"><label>Chat ID</label><input id="nt_tg_chat"><label><input id="nt_wecom_en" type="checkbox" style="width:auto;margin-right:6px">企业微信 启用</label><label>Webhook URL</label><input id="nt_wecom_url"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="testNotify()">发送测试</button><button class="btn btn-primary" onclick="saveNotify()">保存配置</button></div></div><div class="tab-content" id="tab3"><label>本节点 API 令牌</label><div style="display:flex;gap:10px;align-items:center"><input id="local_token" readonly><button class="btn btn-gray" onclick="copyToken()">复制</button><button class="btn btn-primary" onclick="regenerateToken()">重新生成</button></div><div style="margin-top:18px;font-weight:600">远程节点列表</div><button class="btn btn-primary" style="margin-top:10px" onclick="openAddNode()"><i class="fas fa-plus"></i> 添加节点</button><div style="margin-top:10px;max-height:260px;overflow:auto"><table id="nodeTable"><thead><tr><th>名称</th><th>地址</th><th>状态</th><th style="text-align:right">操作</th></tr></thead><tbody id="nodeList"></tbody></table></div></div></div></div><div id="batchModal" class="modal"><div class="modal-box" style="max-width:600px"><h3>批量添加规则</h3><p style="color:#666;font-size:0.85rem;margin-bottom:10px">格式：备注,监听端口,目标地址<br>一行一条，例如：<br>日本落地,10001,1.1.1.1:443</p><textarea id="batch_input" rows="10" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:10px;font-family:monospace" placeholder="备注,监听端口,目标地址"></textarea><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveBatch()">开始导入</button></div></div></div>
<div id="restoreModal" class="modal"><div class="modal-box"><h3>恢复备份</h3><p style="color:#ef4444;font-size:0.9rem;margin-bottom:15px">警告：导入操作将覆盖当前所有规则！</p><textarea id="restore_input" rows="8" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:10px;font-family:monospace;font-size:0.8rem"></textarea><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-danger" onclick="doRestore()">确认覆盖</button></div></div></div>
<div id="nodeModal" class="modal"><div class="modal-box" style="max-width:520px"><h3 id="nodeModalTitle">添加节点</h3><input type="hidden" id="node_id"><label>节点名称</label><input id="node_name"><label>节点地址 (IP/域名)</label><input id="node_host"><label>面板端口</label><input id="node_port" type="number" min="1" max="65535" value="4794"><label>API 令牌</label><input id="node_token"><label><input id="node_enabled" type="checkbox" style="width:auto;margin-right:6px" checked>启用节点</label><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveNode()">保存</button></div></div></div><div id="nodeRulesModal" class="modal"><div class="modal-box" style="max-width:900px"><h3 id="nodeRulesTitle">远程规则</h3><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><div id="nodeRulesHint" style="font-size:0.85rem;color:#6b7280"></div><button class="btn btn-primary" onclick="openRemoteAdd()"><i class="fas fa-plus"></i> 添加规则</button></div><div style="max-height:320px;overflow:auto"><table id="remoteRuleTable"><thead><tr><th>状态</th><th>备注</th><th>监听</th><th>目标</th><th style="text-align:right">操作</th></tr></thead><tbody id="remoteRuleList"></tbody></table><div id="remoteEmpty" style="display:none;text-align:center;padding:30px;color:#9ca3af">暂无规则</div></div><div style="margin-top:20px;display:flex;justify-content:flex-end"><button class="btn btn-gray" onclick="closeModal()">关闭</button></div></div></div><div id="remoteRuleModal" class="modal"><div class="modal-box"><h3 id="remoteRuleTitle">添加远程规则</h3><input type="hidden" id="remote_rule_id"><label>备注</label><input id="remote_rule_name"><label>监听端口</label><input id="remote_rule_listen"><label>目标地址</label><input id="remote_rule_remote"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveRemoteRule()">保存</button></div></div></div><script>
let rules=[];let curId=null;let nodes=[];let curNodeId=null;let remoteRules=[];let curRemoteRuleId=null;
const $=id=>document.getElementById(id);
const fmtBytes=b=>{if(b===0)return'0 B';const k=1024,dm=2,sizes=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(dm))+' '+sizes[i]};
const fmtDate=ts=>{if(!ts)return'永久有效';return new Date(ts).toLocaleString()};
const getRemain=ts=>{
    if(!ts) return '';
    const now=Date.now();
    const diff=ts-now;
    if(diff<0) return '已过期';
    const d = Math.floor(diff / (1000 * 60 * 60 * 24));
    const h = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    return `剩余 ${d}天 ${h}小时`;
};
async function load(){const r=await fetch('/api/rules');if(r.status===401)location.href='/login';const d=await r.json();rules=d.rules;render()}
function render(){const t=$('list');const ev=$('emptyView');const table=$('ruleTable');t.innerHTML='';if(rules.length===0){ev.style.display='block';table.style.display='none'}else{ev.style.display='none';table.style.display='table';rules.forEach(r=>{const row=document.createElement('tr');if(!r.enabled)row.style.opacity='0.6';
let statusHtml=`<span class="status-dot ${r.enabled?'bg-green':'bg-gray'}"></span>${r.enabled?'在线':'暂停'}`;
if(r.status_msg) statusHtml+=` <span style="font-size:0.8rem;color:#ef4444">(${r.status_msg})</span>`;
const btns=`<button class="btn btn-gray" onclick="openView('${r.id}')"><i class="fas fa-eye"></i></button><button class="btn btn-gray" onclick="tog('${r.id}')"><i class="fas ${r.enabled?'fa-pause':'fa-play'}"></i></button><button class="btn btn-primary" onclick="openEdit('${r.id}')"><i class="fas fa-edit"></i></button><button class="btn btn-danger" onclick="del('${r.id}')"><i class="fas fa-trash-alt"></i></button>`;
const isMob=window.innerWidth<768;
let targetHtml=r.remote;if(r.remote_list&&r.remote_list.length>0){const opts=r.remote_list.map((t,i)=>`<option value="${i}" ${t.address===r.remote?'selected':''}>${t.label||t.address}</option>`).join('');targetHtml=`<select onchange="quickSwitch('${r.id}',this.value)" style="padding:4px 8px;border-radius:6px;border:1px solid rgba(0,0,0,0.1);background:rgba(255,255,255,0.8);font-size:0.85rem;max-width:150px"><option value="-1">${r.remote}</option>${opts}</select>`;}
let tfStr = fmtBytes(r.traffic_used);
if(r.traffic_limit > 0) tfStr += ` / ${fmtBytes(r.traffic_limit)}`;
let extra=[];if(r.bandwidth_enabled && r.bandwidth_limit) extra.push(`限速:${r.bandwidth_limit}`);extra.push(`计费:${r.billing_mode==='double'?'双向':'单向'}`);if(r.reset_day && r.reset_day>0) extra.push(`重置:${r.reset_day}日`);if(extra.length) tfStr += `<div style="font-size:0.75rem;color:#6b7280;margin-top:4px">${extra.join(' | ')}</div>`;if(isMob){row.innerHTML=`<td data-label="状态">${statusHtml}</td><td data-label="备注"><strong>${r.name}</strong></td><td data-label="监听">${r.listen}</td><td data-label="目标">${targetHtml}</td><td data-label="流量">${tfStr}</td><td data-label="操作">${btns.replace(/class="btn/g,'class="btn btn-sm')}</td>`;}
else{row.innerHTML=`<td data-label="状态">${statusHtml}</td><td data-label="备注"><strong>${r.name}</strong></td><td data-label="监听">${r.listen}</td><td data-label="目标">${targetHtml}</td><td data-label="流量">${tfStr}</td><td data-label="操作" style="display:flex;gap:6px;justify-content:flex-end;padding-right:15px">${btns}</td>`;}t.appendChild(row)})}}
function openAddModal(){curId=null;$('modalTitle').innerText='添加规则';['n','l','r','e','t_val'].forEach(x=>$('mod_'+x).value='');$('mod_bw_en').checked=false;$('mod_bw_rate').value='';$('mod_billing').value='single';$('mod_reset_day').value='0';const qn=$('n').value.trim();const ql=$('l').value.trim();const qr=$('r').value.trim();if(qn)$('mod_n').value=qn;if(ql)$('mod_l').value=ql;if(qr)$('mod_r').value=qr;$('targetsSection').style.display='none';$('targetsList').innerHTML='';$('ruleModal').style.display='flex'}
function openEdit(id){curId=id;const r=rules.find(x=>x.id===id);$('modalTitle').innerText='编辑规则';$('mod_n').value=r.name;$('mod_l').value=r.listen.replace('0.0.0.0:','');$('mod_r').value=r.remote;if(r.expire_date){const dt=new Date(r.expire_date);dt.setMinutes(dt.getMinutes()-dt.getTimezoneOffset());$('mod_e').value=dt.toISOString().slice(0,16)}else{$('mod_e').value=''}if(r.traffic_limit){if(r.traffic_limit>=1073741824){$('mod_t_val').value=(r.traffic_limit/1073741824).toFixed(2);$('mod_t_unit').value='GB'}else{$('mod_t_val').value=(r.traffic_limit/1048576).toFixed(2);$('mod_t_unit').value='MB'}}else{$('mod_t_val').value=''}$('mod_bw_en').checked=!!r.bandwidth_enabled;$('mod_bw_rate').value=r.bandwidth_limit||'';$('mod_billing').value=r.billing_mode||'single';$('mod_reset_day').value=r.reset_day||0;$('targetsSection').style.display='none';$('targetsList').innerHTML='';$('ruleModal').style.display='flex'}
function openView(id){curId=id;const r=rules.find(x=>x.id===id);$('view_n').innerText=r.name;$('view_l').innerText=r.listen;$('view_r').innerText=r.remote;if(r.expire_date){$('view_expire_sec').style.display='block';$('view_e_date').innerText=fmtDate(r.expire_date);$('view_e_remain').innerText=getRemain(r.expire_date)}else{$('view_expire_sec').style.display='none'}$('view_traffic_sec').style.display='block';$('view_t_used').innerText=fmtBytes(r.traffic_used);if(r.traffic_limit){$('view_t_limit').innerText=fmtBytes(r.traffic_limit);const pct=Math.min(100,(r.traffic_used/r.traffic_limit)*100);$('view_t_bar').style.width=pct+'%';$('view_t_bar').style.background=pct>90?'#ef4444':'#3b82f6'}else{$('view_t_limit').innerText='无限制';$('view_t_bar').style.width='0%'}$('view_bw').innerText=(r.bandwidth_enabled&&r.bandwidth_limit)?r.bandwidth_limit:'未启用';$('view_bill').innerText=r.billing_mode==='double'?'双向':'单向';$('view_reset').innerText=(r.reset_day&&r.reset_day>0)?`每月${r.reset_day}日`:'不重置';$('viewModal').style.display='flex'}
async function saveRule(){
    let [n,l,r,e,tv,tu]=['n','l','r','e','t_val','t_unit'].map(x=>$('mod_'+x).value.trim());
    if(!n||!l||!r) return alert('请填写必填项');
    if(!l.includes(':'))l='0.0.0.0:'+l;
    let ed=0; if(e) ed=new Date(e).getTime();
    let tl=0; if(tv && parseFloat(tv)>0){ tl = parseFloat(tv) * (tu==='GB'?1073741824:1048576); }
    let bw_en=$('mod_bw_en').checked;
    let bw_rate=$('mod_bw_rate').value.trim();
    let billing_mode=$('mod_billing').value||'single';
    let reset_day=parseInt($('mod_reset_day').value||'0');
    const payload={name:n,listen:l,remote:r,expire_date:ed,traffic_limit:Math.floor(tl),bandwidth_enabled:bw_en,bandwidth_limit:bw_rate,billing_mode,reset_day};
    const url = curId ? `/api/rules/${curId}` : '/api/rules';
    const method = curId ? 'PUT' : 'POST';
    const res = await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await res.json();
    if(d.status==='error') alert(d.message); else { closeModal(); load(); $('n').value='';$('l').value='';$('r').value='';}
}
async function resetTraffic(){if(!curId||!confirm('确定重置已用流量统计吗？'))return;await fetch(`/api/rules/${curId}/reset_traffic`,{method:'POST'});closeModal();load()}
async function tog(id){await fetch(`/api/rules/${id}/toggle`,{method:'POST'});load()}
async function del(id){if(confirm('确定删除此规则吗？'))await fetch(`/api/rules/${id}`,{method:'DELETE'});load()}
function openSettings(){$('setModal').style.display='flex';switchTab(0)}
function closeModal(){document.querySelectorAll('.modal').forEach(x=>x.style.display='none')}
function switchTab(idx){document.querySelectorAll('.tab-btn').forEach((b,i)=>b.classList.toggle('active',i===idx));document.querySelectorAll('.tab-content').forEach((c,i)=>c.classList.toggle('active',i===idx));if(idx===2)loadNotify();if(idx===3)loadNodes()}
async function saveAccount(){await fetch('/api/admin/account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('set_u').value,password:$('set_p').value})});alert('账户已更新，请重新登录');location.reload()}
async function saveBg(){await fetch('/api/admin/bg',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bg_pc:$('bg_pc').value,bg_mobile:$('bg_mob').value})});location.reload()}
async function loadNotify(){const r=await fetch('/api/notifications');if(!r.ok)return;const d=await r.json();$('nt_server').value=d.server_name||'';$('nt_tg_en').checked=!!d.telegram_enabled;$('nt_tg_token').value=d.telegram_bot_token||'';$('nt_tg_chat').value=d.telegram_chat_id||'';$('nt_wecom_en').checked=!!d.wecom_enabled;$('nt_wecom_url').value=d.wecom_webhook_url||'';}
async function saveNotify(){const payload={server_name:$('nt_server').value.trim(),telegram_enabled:$('nt_tg_en').checked,telegram_bot_token:$('nt_tg_token').value.trim(),telegram_chat_id:$('nt_tg_chat').value.trim(),wecom_enabled:$('nt_wecom_en').checked,wecom_webhook_url:$('nt_wecom_url').value.trim()};const res=await fetch('/api/notifications',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await res.json();if(d.status==='ok')alert('通知配置已保存');else alert(d.message||'保存失败');}
async function testNotify(){const res=await fetch('/api/notifications/test',{method:'POST'});const d=await res.json();if(d.status==='ok')alert('测试通知已发送');else alert(d.message||'发送失败');}async function loadToken(){const r=await fetch('/api/token');if(!r.ok)return;const d=await r.json();$('local_token').value=d.token||'';}async function regenerateToken(){const r=await fetch('/api/token',{method:'POST'});if(!r.ok)return;const d=await r.json();$('local_token').value=d.token||'';alert('令牌已更新');}function copyToken(){const v=$('local_token').value||'';if(!v)return;if(navigator.clipboard){navigator.clipboard.writeText(v).then(()=>alert('已复制'));}else{const t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);alert('已复制');}}async function loadNodes(){const r=await fetch('/api/nodes');if(!r.ok)return;const d=await r.json();nodes=d.nodes||[];renderNodes();loadToken();}function renderNodes(){const t=$('nodeList');if(!t)return;t.innerHTML='';if(nodes.length===0){t.innerHTML='<tr><td colspan="4" style="text-align:center;color:#9ca3af">暂无节点</td></tr>';return;}nodes.forEach(n=>{const status=n.enabled?'启用':'禁用';const actions=`<button class="btn btn-gray" onclick="openNodeRules('${n.id}')"><i class="fas fa-project-diagram"></i></button><button class="btn btn-gray" onclick="openEditNode('${n.id}')"><i class="fas fa-edit"></i></button><button class="btn btn-danger" onclick="delNode('${n.id}')"><i class="fas fa-trash-alt"></i></button>`;const row=document.createElement('tr');row.innerHTML=`<td>${n.name}</td><td>${n.host}:${n.port}</td><td>${status}</td><td style="text-align:right;display:flex;gap:6px;justify-content:flex-end">${actions}</td>`;t.appendChild(row);});}function openAddNode(){curNodeId=null;$('nodeModalTitle').innerText='添加节点';$('node_id').value='';$('node_name').value='';$('node_host').value='';$('node_port').value='4794';$('node_token').value='';$('node_enabled').checked=true;$('nodeModal').style.display='flex';}function openEditNode(id){curNodeId=id;const n=nodes.find(x=>x.id===id);if(!n)return;$('nodeModalTitle').innerText='编辑节点';$('node_id').value=id;$('node_name').value=n.name;$('node_host').value=n.host;$('node_port').value=n.port||4794;$('node_token').value=n.api_token||'';$('node_enabled').checked=!!n.enabled;$('nodeModal').style.display='flex';}async function saveNode(){const name=$('node_name').value.trim();const host=$('node_host').value.trim();const port=parseInt($('node_port').value||'4794');const api_token=$('node_token').value.trim();const enabled=$('node_enabled').checked;if(!name||!host||!api_token)return alert('名称/地址/令牌不能为空');const payload={name,host,port,api_token,enabled};const url=curNodeId?`/api/nodes/${curNodeId}`:'/api/nodes';const method=curNodeId?'PUT':'POST';const res=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await res.json();if(d.status==='ok'){closeModal();loadNodes();}else alert(d.message||'保存失败');}async function delNode(id){if(!confirm('确定删除该节点？'))return;const res=await fetch(`/api/nodes/${id}`,{method:'DELETE'});const d=await res.json();if(d.status==='ok')loadNodes();else alert(d.message||'删除失败');}async function openNodeRules(id){curNodeId=id;const node=nodes.find(x=>x.id===id);$('nodeRulesTitle').innerText=`远程规则 - ${node?node.name:''}`;$('nodeRulesHint').innerText=node?`${node.host}:${node.port}`:'';const r=await fetch(`/api/nodes/${id}/rules`);if(!r.ok){const d=await r.json().catch(()=>({message:'加载失败'}));return alert(d.message||'加载失败');}const d=await r.json();remoteRules=Array.isArray(d)?d:(d.rules||[]);renderRemoteRules();$('nodeRulesModal').style.display='flex';}function renderRemoteRules(){const t=$('remoteRuleList');const ev=$('remoteEmpty');t.innerHTML='';if(remoteRules.length===0){ev.style.display='block';return;}ev.style.display='none';remoteRules.forEach(r=>{const status=`<span class="status-dot ${r.enabled?'bg-green':'bg-gray'}"></span>${r.enabled?'在线':'暂停'}`;const btns=`<button class="btn btn-gray" onclick="toggleRemoteRule('${r.id}')"><i class="fas ${r.enabled?'fa-pause':'fa-play'}"></i></button><button class="btn btn-gray" onclick="openRemoteEdit('${r.id}')"><i class="fas fa-edit"></i></button><button class="btn btn-danger" onclick="deleteRemoteRule('${r.id}')"><i class="fas fa-trash-alt"></i></button>`;const row=document.createElement('tr');row.innerHTML=`<td>${status}</td><td>${r.name}</td><td>${r.listen}</td><td>${r.remote}</td><td style="text-align:right;display:flex;gap:6px;justify-content:flex-end">${btns}</td>`;t.appendChild(row);});}function openRemoteAdd(){curRemoteRuleId=null;$('remoteRuleTitle').innerText='添加远程规则';$('remote_rule_id').value='';$('remote_rule_name').value='';$('remote_rule_listen').value='';$('remote_rule_remote').value='';$('remoteRuleModal').style.display='flex';}function openRemoteEdit(id){curRemoteRuleId=id;const r=remoteRules.find(x=>x.id===id);if(!r)return;$('remoteRuleTitle').innerText='编辑远程规则';$('remote_rule_id').value=id;$('remote_rule_name').value=r.name;$('remote_rule_listen').value=r.listen.replace('0.0.0.0:','');$('remote_rule_remote').value=r.remote;$('remoteRuleModal').style.display='flex';}async function saveRemoteRule(){const name=$('remote_rule_name').value.trim();let listen=$('remote_rule_listen').value.trim();const remote=$('remote_rule_remote').value.trim();if(!name||!listen||!remote)return alert('请填写必填项');if(!listen.includes(':'))listen='0.0.0.0:'+listen;const base=curRemoteRuleId?remoteRules.find(x=>x.id===curRemoteRuleId):null;const payload={name,listen,remote,expire_date:base?base.expire_date||0:0,traffic_limit:base?base.traffic_limit||0:0,bandwidth_enabled:base?!!base.bandwidth_enabled:false,bandwidth_limit:base?base.bandwidth_limit||'':'',billing_mode:base?base.billing_mode||'single':'single',reset_day:base?base.reset_day||0:0,remark:base?base.remark||name:name};const url=curRemoteRuleId?`/api/nodes/${curNodeId}/rules/${curRemoteRuleId}`:`/api/nodes/${curNodeId}/rules`;const method=curRemoteRuleId?'PUT':'POST';const res=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await res.json();if(d.status==='error'){alert(d.message||'保存失败');}else{$('remoteRuleModal').style.display='none';openNodeRules(curNodeId);}}async function deleteRemoteRule(id){if(!confirm('确定删除该规则？'))return;const res=await fetch(`/api/nodes/${curNodeId}/rules/${id}`,{method:'DELETE'});const d=await res.json();if(d.status==='error')alert(d.message||'删除失败');else openNodeRules(curNodeId);}async function toggleRemoteRule(id){await fetch(`/api/nodes/${curNodeId}/rules/${id}/toggle`,{method:'POST'});openNodeRules(curNodeId);} 
async function doLogout(){await fetch('/logout',{method:'POST'});location.href='/login'}
function openBatch(){$('batchModal').style.display='flex';$('batch_input').value='';}
async function saveBatch(){const raw=$('batch_input').value;if(!raw.trim())return;const lines=raw.split('\n');const payload=[];for(let line of lines){line=line.trim();if(!line)continue;line=line.replace(/，/g,',');const parts=line.split(',');if(parts.length<3)continue;let [n,l,r]=[parts[0].trim(),parts[1].trim(),parts[2].trim()];if(l&&!l.includes(':'))l='0.0.0.0:'+l;if(n&&l&&r){payload.push({name:n,listen:l,remote:r,expire_date:0,traffic_limit:0});}}if(payload.length===0)return alert('格式错误');const res=await fetch('/api/rules/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});alert((await res.json()).message);$('batchModal').style.display='none';load()}
async function delAll(){if(rules.length===0||!confirm('⚠️ 确定清空？'))return;await fetch('/api/rules/all',{method:'DELETE'});load()}
function downloadBackup(){if(rules.length===0)return alert('无数据');window.location.href='/api/backup'}
function openRestore(){$('restoreModal').style.display='flex'}
async function doRestore(){try{const p=JSON.parse($('restore_input').value);if(!Array.isArray(p))throw 1;if(!confirm('确定覆盖？'))return;await fetch('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});location.reload()}catch(e){alert('JSON格式错误')}}

let curTargets=[];
async function loadTargets(id){const r=await fetch(`/api/rules/${id}/targets`);if(!r.ok)return;const d=await r.json();curTargets=d.targets||[];renderTargets();}
function renderTargets(){const t=$('targetsList');t.innerHTML='';curTargets.forEach((tgt,i)=>{const div=document.createElement('div');div.style='display:flex;gap:8px;align-items:center;margin-top:8px';div.innerHTML=`<input value="${tgt.address}" placeholder="目标地址" style="flex:2" onchange="curTargets[${i}].address=this.value"><input value="${tgt.label||''}" placeholder="标签(可选)" style="flex:1" onchange="curTargets[${i}].label=this.value"><button type="button" class="btn btn-danger" style="padding:6px 10px" onclick="removeTarget(${i})"><i class="fas fa-times"></i></button><button type="button" class="btn btn-primary" style="padding:6px 10px" onclick="switchToTarget(${i})" title="切换到此目标"><i class="fas fa-exchange-alt"></i></button>`;t.appendChild(div);});}
function addTargetRow(){curTargets.push({address:'',label:''});renderTargets();}
function removeTarget(idx){curTargets.splice(idx,1);renderTargets();}
async function switchToTarget(idx){if(!curId||idx<0||idx>=curTargets.length)return;const tgt=curTargets[idx];if(!tgt.address){alert('目标地址不能为空');return;}if(!confirm(`确定切换到 ${tgt.label||tgt.address}？`))return;const r=await fetch(`/api/rules/${curId}/switch-target`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})});const d=await r.json();if(d.status==='ok'){alert('切换成功');closeModal();load();}else{alert(d.message||'切换失败');}}
async function saveTargetsForRule(){if(!curId)return;for(const t of curTargets){if(!t.address)continue;await fetch(`/api/rules/${curId}/targets`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:t.address,label:t.label||''})});}}
async function quickSwitch(ruleId,idx){idx=parseInt(idx);if(idx<0)return;const r=await fetch(`/api/rules/${ruleId}/switch-target`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})});const d=await r.json();if(d.status==='ok'){load();}else{alert(d.message||'切换失败');}}
function openTrafficDog(){alert('流量狗功能：请在终端执行 bash port-traffic-dog.sh 进入端口流量监控管理');}

setInterval(load, 3000);
load();window.addEventListener('resize',render);
</script></body></html>
"#;
EOF

echo -e -n "${CYAN}>>> 编译面板程序 (请耐心等待！)...${RESET}"
OS_ARCH=$(uname -m)
if [[ "$OS_ARCH" == "aarch64" ]]; then
    RUST_TRIPLE="aarch64-unknown-linux-gnu"
else
    RUST_TRIPLE="x86_64-unknown-linux-gnu"
fi

mkdir -p .cargo

LD_FLAG=""
if command -v ld.lld >/dev/null 2>&1; then
    LD_FLAG="-fuse-ld=lld"
elif command -v lld >/dev/null 2>&1; then
    LD_FLAG="-fuse-ld=lld"
elif command -v ld.gold >/dev/null 2>&1; then
    LD_FLAG="-fuse-ld=gold"
else
    if gcc -Wl,-fuse-ld=bfd -x c - -o /tmp/.ldtest.$$ >/dev/null 2>&1 <<<'int main(){}'; then
        LD_FLAG="-fuse-ld=bfd"
        rm -f /tmp/.ldtest.$$ >/dev/null 2>&1 || true
    else
        LD_FLAG=""
    fi
fi

if [ -n "$LD_FLAG" ]; then
cat > .cargo/config.toml <<EOF
[target.$RUST_TRIPLE]
linker = "gcc"
rustflags = ["-C", "link-arg=$LD_FLAG"]
EOF
else
cat > .cargo/config.toml <<EOF
[target.$RUST_TRIPLE]
linker = "gcc"
EOF
fi


# 编译并检查
cargo clean >/dev/null 2>&1
cargo build --release > /tmp/realm_build.log 2>&1

if [ $? -eq 0 ] && [ -f "target/release/realm-panel" ]; then
    echo -e "${GREEN} [完成]${RESET}"
    echo -e -n "${CYAN}>>> 正在部署服务...${RESET}"
    mv target/release/realm-panel "$PANEL_BIN"
else
    echo -e "${RED} [失败]${RESET}"
    echo -e "${RED}================ 错误详情 ================${RESET}"
    cat /tmp/realm_build.log
    echo -e "${RED}==========================================${RESET}"
    exit 1
fi

rm -rf "$WORK_DIR"

cat > /etc/systemd/system/realm-panel.service <<EOF
[Unit]
Description=Realm Panel Custom
After=network.target

[Service]
User=root
Environment="PANEL_USER=$DEFAULT_USER"
Environment="PANEL_PASS=$DEFAULT_PASS"
Environment="PANEL_PORT=$PANEL_PORT"
LimitNOFILE=1048576
LimitNPROC=1048576
ExecStart=$PANEL_BIN
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable realm-panel >/dev/null 2>&1
systemctl restart realm-panel >/dev/null 2>&1
echo -e "${GREEN} [完成]${RESET}"

IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
echo -e ""
echo -e "${GREEN}====================================${RESET}"
echo -e "${GREEN}          ✅ Realm 面板部署成功       ${RESET}"
echo -e "${GREEN}====================================${RESET}"
echo -e "访问地址 : ${YELLOW}http://${IP}:${PANEL_PORT}${RESET}"
echo -e "默认用户 : ${YELLOW}${DEFAULT_USER}${RESET}"
echo -e "默认密码 : ${YELLOW}${DEFAULT_PASS}${RESET}"
echo -e "------------------------------------------"
if [ "$DEFAULT_PASS" = "123456" ]; then
    echo -e "${RED}⚠️  安全警告: 检测到使用默认密码!${RESET}"
    echo -e "${YELLOW}   请登录面板后立即修改密码，避免安全风险${RESET}"
    echo -e "------------------------------------------"
fi



