#!/bin/bash

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

# 颜色
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
RESET="\033[0m"
# =========================================

# 自定义链名称
CHAIN_IN="REALM_IN"
CHAIN_OUT="REALM_OUT"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "${RED}错误: 缺少必要命令 '$1'${RESET}"
        exit 1
    fi
}

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

get_arch() {
    case "$(uname -m)" in
        x86_64) echo "x86_64" ;;
        aarch64) echo "aarch64" ;;
        *) echo "unsupported" ;;
    esac
}

get_libc() {
    if ldd --version 2>&1 | grep -q 'musl'; then
        echo "musl"
    else
        echo "gnu"
    fi
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
        echo -e -n "${CYAN}>>> 安装 Rust 编译�?..${RESET}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1 &
        spinner $!
        source "$HOME/.cargo/env"
        echo -e "${GREEN} [完成]${RESET}"
    else
        echo -e "${GREEN}>>> Rust 已安�?{RESET}"
        if [ -f "$HOME/.cargo/env" ]; then source "$HOME/.cargo/env"; fi
    fi
}

get_realm_filename() {
    local arch libc
    arch="$(get_arch)"
    libc="$(get_libc)"
    if [ "$arch" = "unsupported" ]; then return 1; fi
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

    echo -e "${CYAN}>>> 检�?Realm 版本...${RESET}"
    local latest_ver local_ver
    latest_ver=$(get_latest_realm_version_tag)
    local_ver=$(get_local_realm_version)

    if [ -z "$latest_ver" ]; then
        echo -e "${RED}无法获取最新版本号，强制重�?{RESET}"
    elif [ "$local_ver" == "0.0.0" ]; then
        echo -e "${GREEN}检测到未安装，准备开始安�?Realm ($latest_ver)...${RESET}"
    elif [ "$latest_ver" == "$local_ver" ]; then
        echo -e "${GREEN}本地 Realm 已是最新版 ($local_ver)，跳过安�?{RESET}"
        ensure_config_file
        if [ -f "$SERVICE_FILE" ]; then return 0; fi
    else
        echo -e "${YELLOW}发现新版�? $latest_ver (当前: $local_ver)，准备更�?..${RESET}"
    fi

    local url
    url="$(get_latest_realm_url || true)"
    if [ -z "$url" ]; then echo -e "${RED}获取下载链接失败${RESET}"; exit 1; fi

    echo -e "${GREEN}下载地址�?url${RESET}"
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
    echo -e "${RED}请以 root 用户运行�?{RESET}"
    exit 1
fi

clear
echo -e "${GREEN}==================================${RESET}"
echo -e "${GREEN}          Realm 面板 一键部�?       ${RESET}"
echo -e "${GREEN}==================================${RESET}"

prepare_env_and_fix_compilation
install_realm_smart

mkdir -p "$(dirname "$PANEL_DATA")"
run_step "生成面板源代�? "
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
EOF

cat > src/main.rs << 'EOF'
use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, put, delete},
    Json, Router, Form,
};
use serde::{Deserialize, Serialize};
use std::{fs, process::Command, sync::{Arc, Mutex}, path::Path as FilePath, time::Duration, collections::HashMap, cmp};
use tower_cookies::{Cookie, Cookies, CookieManagerLayer};
use chrono::prelude::*;

const REALM_CONFIG: &str = "/etc/realm/config.toml";
const DATA_FILE: &str = "/etc/realm/panel_data.json";

// 自定义链名称
const CHAIN_IN: &str = "REALM_IN";
const CHAIN_OUT: &str = "REALM_OUT";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Rule {
    id: String,
    name: String,
    listen: String,
    remote: String,
    enabled: bool,
    #[serde(default)]
    expire_date: u64,
    #[serde(default)]
    traffic_limit: u64,
    #[serde(default)]
    traffic_used: u64,
    #[serde(default)]
    status_msg: String,
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

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AppData {
    admin: AdminConfig,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct RealmEndpoint {
    name: String,
    listen: String,
    remote: String,
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

    let app = Router::new()
        .route("/", get(index_page))
        .route("/login", get(login_page).post(login_action))
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/batch", post(batch_add_rules))
        .route("/api/rules/all", delete(delete_all_rules)) 
        .route("/api/rules/:id", put(update_rule).delete(delete_rule))
        .route("/api/rules/:id/toggle", post(toggle_rule))
        .route("/api/rules/:id/reset_traffic", post(reset_traffic))
        .route("/api/admin/account", post(update_account))
        .route("/api/admin/bg", post(update_bg))
        .route("/api/backup", get(download_backup))
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
    
    let now = Utc::now().timestamp_millis() as u64;
    let mut changed = false;

    for rule in data.rules.iter_mut() {
        if !rule.enabled { continue; }
        let port = get_port(&rule.listen);
        if port.is_empty() { continue; }

        let curr = *current_counters.get(&port).unwrap_or(&TrafficStats{in_bytes:0, out_bytes:0});
        let last = *last_map.get(&port).unwrap_or(&TrafficStats{in_bytes:0, out_bytes:0});

        let delta_in = if curr.in_bytes >= last.in_bytes { curr.in_bytes - last.in_bytes } else { curr.in_bytes };
        let delta_out = if curr.out_bytes >= last.out_bytes { curr.out_bytes - last.out_bytes } else { curr.out_bytes };

        let usage_inc = cmp::max(delta_in, delta_out);

        if usage_inc > 0 {
            rule.traffic_used += usage_inc;
            changed = true;
            last_map.insert(port.clone(), curr);
        } else {
            last_map.insert(port.clone(), curr);
        }

        if rule.expire_date > 0 && now > rule.expire_date {
            rule.enabled = false;
            rule.status_msg = "已过�?.to_string();
            changed = true;
            remove_iptables_rule(rule);
        }

        if rule.traffic_limit > 0 && rule.traffic_used >= rule.traffic_limit {
            rule.enabled = false;
            rule.status_msg = "流量耗尽".to_string();
            changed = true;
            remove_iptables_rule(rule);
        }
    }

    if changed {
        save_json(&data);
        save_config_toml(&data);
    }
}

fn load_or_init_data() -> AppData {
    if let Ok(content) = fs::read_to_string(DATA_FILE) {
        if let Ok(mut data) = serde_json::from_str::<AppData>(&content) {
            data.rules.retain(|r| r.name != "system-keepalive");
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
    let data = AppData { admin, rules: Vec::new() };
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
            r#type: "tcp+udp".to_string(), 
        })
        .collect();
    
    endpoints.push(RealmEndpoint {
        name: "system-keepalive".to_string(),
        listen: "127.0.0.1:65534".to_string(),
        remote: "127.0.0.1:65534".to_string(),
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

async fn get_rules(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    Json(data.clone()).into_response()
}

#[derive(Deserialize)] struct AddRuleReq { name: String, listen: String, remote: String, expire_date: u64, traffic_limit: u64 }
async fn add_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<AddRuleReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if req.name.trim().is_empty() || req.listen.trim().is_empty() || req.remote.trim().is_empty() {
        return Json(serde_json::json!({"status":"error", "message": "所有字段都不能为空�?})).into_response();
    }
    let new_port = get_port(&req.listen);
    if new_port.is_empty() { return Json(serde_json::json!({"status":"error", "message": "端口格式错误"})).into_response(); }
    if data.rules.iter().any(|r| get_port(&r.listen) == new_port) {
        return Json(serde_json::json!({"status":"error", "message": "端口已被占用�?})).into_response();
    }
    let rule = Rule { 
        id: uuid::Uuid::new_v4().to_string(), 
        name: req.name, listen: req.listen, remote: req.remote, enabled: true,
        expire_date: req.expire_date, traffic_limit: req.traffic_limit, traffic_used: 0, status_msg: String::new()
    };
    add_iptables_rule(&rule);
    data.rules.push(rule);
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn batch_add_rules(cookies: Cookies, State(state): State<Arc<AppState>>, Json(reqs): Json<Vec<AddRuleReq>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let mut added_count = 0;
    for req in reqs {
        let new_port = get_port(&req.listen);
        if new_port.is_empty() { continue; }
        if data.rules.iter().any(|r| get_port(&r.listen) == new_port) { continue; }
        let rule = Rule { 
            id: uuid::Uuid::new_v4().to_string(), 
            name: req.name, listen: req.listen, remote: req.remote, enabled: true,
            expire_date: 0, traffic_limit: 0, traffic_used: 0, status_msg: String::new()
        };
        add_iptables_rule(&rule);
        data.rules.push(rule);
        added_count += 1;
    }
    if added_count > 0 { save_json(&data); save_config_toml(&data); }
    Json(serde_json::json!({"status":"ok", "message": format!("成功添加 {} 条规�?, added_count)})).into_response()
}

async fn delete_all_rules(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
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
    if backup_rules.is_empty() { return Json(serde_json::json!({"status": "error", "message": "导入的数据为�?})).into_response(); }
    flush_realm_chains();
    data.rules = backup_rules;
    data.rules.retain(|r| r.name != "system-keepalive");
    for r in &data.rules { if r.enabled { add_iptables_rule(r); } }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok", "message": format!("成功恢复 {} 条规�?, data.rules.len())})).into_response()
}

async fn toggle_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) { 
        rule.enabled = !rule.enabled;
        if rule.enabled { 
            rule.status_msg = String::new(); 
            add_iptables_rule(rule);
        } else {
            remove_iptables_rule(rule);
        }
        save_json(&data); save_config_toml(&data); 
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn reset_traffic(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    let mut last_map = state.last_traffic_map.lock().unwrap();

    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) { 
        let port = get_port(&rule.listen);
        rule.traffic_used = 0;
        rule.status_msg = String::new(); 

        if rule.enabled {
             remove_iptables_rule(rule);
             add_iptables_rule(rule);
        }

        if !port.is_empty() {
            last_map.remove(&port);
        }
        
        save_json(&data); 
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn delete_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(pos) = data.rules.iter().position(|r| r.id == id) {
        remove_iptables_rule(&data.rules[pos]);
        data.rules.remove(pos);
    }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

#[derive(Deserialize)] struct UpdateRuleReq { name: String, listen: String, remote: String, expire_date: u64, traffic_limit: u64 }
async fn update_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<UpdateRuleReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let new_port = get_port(&req.listen);
    if data.rules.iter().any(|r| r.id != id && get_port(&r.listen) == new_port) {
        return Json(serde_json::json!({"status":"error", "message": "端口已被占用�?})).into_response();
    }
    if let Some(idx) = data.rules.iter().position(|r| r.id == id) {
        remove_iptables_rule(&data.rules[idx]);
        let rule = &mut data.rules[idx];
        rule.name = req.name; 
        rule.listen = req.listen; 
        rule.remote = req.remote;
        rule.expire_date = req.expire_date;
        rule.traffic_limit = req.traffic_limit;
        if rule.enabled {
             if rule.status_msg == "流量耗尽" && (req.traffic_limit == 0 || req.traffic_limit > rule.traffic_used) {
                 rule.status_msg = String::new();
             }
             add_iptables_rule(rule);
        }
        save_json(&data); save_config_toml(&data); 
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
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

const LOGIN_HTML: &str = r#"
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no"><title>Realm Login</title><style>*{margin:0;padding:0;box-sizing:border-box}body{height:100vh;width:100vw;overflow:hidden;display:flex;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:url('{{BG_PC}}') no-repeat center center/cover;color:#374151}@media(max-width:768px){body{background-image:url('{{BG_MOBILE}}')}}.overlay{position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.05)}.box{position:relative;z-index:2;background:rgba(255,255,255,0.3);backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px);padding:2.5rem;border-radius:24px;border:1px solid rgba(255,255,255,0.4);box-shadow:0 8px 32px rgba(0,0,0,0.05);width:90%;max-width:380px;text-align:center}h2{margin-bottom:2rem;color:#374151;font-weight:600;letter-spacing:1px}input{width:100%;padding:14px;margin-bottom:1.2rem;border:1px solid rgba(255,255,255,0.5);border-radius:12px;outline:none;background:rgba(255,255,255,0.5);transition:0.3s;color:#374151}input:focus{background:rgba(255,255,255,0.9);border-color:#3b82f6}button{width:100%;padding:14px;background:rgba(59,130,246,0.85);color:white;border:none;border-radius:12px;cursor:pointer;font-weight:600;font-size:1rem;transition:0.3s;backdrop-filter:blur(5px)}button:hover{background:#2563eb;transform:translateY(-1px)}</style></head><body><div class="overlay"></div><div class="box"><h2>Realm Panel</h2><form onsubmit="doLogin(event)"><input type="text" id="u" placeholder="Username" required><input type="password" id="p" placeholder="Password" required><button type="submit" id="btn">�?�?/button></form></div><script>async function doLogin(e){e.preventDefault();const b=document.getElementById('btn');b.innerText='登录�?..';b.disabled=true;const res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`username=${encodeURIComponent(document.getElementById('u').value)}&password=${encodeURIComponent(document.getElementById('p').value)}`});if(res.redirected){location.href=res.url}else if(res.ok){location.href='/'}else{alert('用户名或密码错误');b.innerText='�?�?;b.disabled=false}}</script></body></html>
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
@media(max-width:768px){.grid-input{grid-template-columns:1fr; gap:10px}.navbar{padding:0.8rem 1rem}.nav-text{display:none}thead{display:none}tbody tr{display:flex;flex-direction:column;border-radius:18px!important;margin-bottom:12px;padding:15px;border:1px solid rgba(255,255,255,0.3);background:rgba(255,255,255,0.4)}td{padding:6px 0;display:flex;justify-content:space-between;border-radius:0!important;align-items:center;border:none;background:transparent}td::before{content:attr(data-label);color:#9ca3af;font-size:0.85rem}td[data-label="操作"]{justify-content:flex-end;gap:10px;margin-top:8px;padding-top:10px;border-top:1px solid rgba(0,0,0,0.05)}td[data-label="操作"] .btn{flex:none;width:auto;padding:6px 14px;border-radius:8px;font-size:0.85rem}td[data-label="操作"] .btn-gray{background:transparent;border:1px solid rgba(0,0,0,0.15);color:#555}td[data-label="操作"] .btn-primary{background:var(--primary);color:white}td[data-label="操作"] .btn-danger{background:rgba(239,68,68,0.1);color:var(--danger);border:1px solid rgba(239,68,68,0.2)}.tools-group{width:100%;margin-top:5px}.tools-group .btn{flex:1;justify-content:center;padding:10px 0;font-size:0.85rem}}</style></head><body><div class="navbar"><div class="brand"><i class="fas fa-layer-group"></i> <span class="nav-text">Realm 转发面板</span></div><div class="nav-actions" style="display:flex;gap:15px"><button class="btn btn-gray" onclick="openSettings()"><i class="fas fa-sliders-h"></i> <span class="nav-text">面板设置</span></button><button class="btn btn-danger" onclick="doLogout()"><i class="fas fa-power-off"></i></button></div></div><div class="container"><div class="card card-fixed"><div class="grid-input"><input id="n" placeholder="备注名称"><input id="l" placeholder="监听端口 (�?10000)"><input id="r" placeholder="目标 (�?1.2.3.4:443)"><button class="btn btn-primary" onclick="openAddModal()"><i class="fas fa-plus"></i> 添加</button><div class="tools-group"><button class="btn btn-primary" onclick="openBatch()" style="background:#8b5cf6"><i class="fas fa-paste"></i> 批量</button><button class="btn btn-danger" onclick="delAll()" style="background:#ef4444"><i class="fas fa-trash"></i> 全删</button><button class="btn btn-primary" onclick="downloadBackup()" style="background:#059669"><i class="fas fa-download"></i> 导出</button><button class="btn btn-danger" onclick="openRestore()" style="background:#d97706"><i class="fas fa-upload"></i> 导入</button></div></div></div><div class="card card-scroll"><div style="padding:1.2rem 1.5rem;font-weight:700;font-size:1rem;opacity:0.8">转发规则管理</div><div class="table-wrapper"><table id="ruleTable"><thead><tr><th>状�?/th><th>备注</th><th>监听</th><th>目标</th><th>流量 (In/Out)</th><th style="width:180px;text-align:right;padding-right:20px">操作</th></tr></thead><tbody id="list"></tbody></table><div id="emptyView" style="display:none;text-align:center;padding:50px;color:#9ca3af"><i class="fas fa-inbox" style="font-size:2rem;display:block;margin-bottom:10px"></i>暂无规则</div></div></div></div>
<div id="ruleModal" class="modal"><div class="modal-box"><h3 id="modalTitle">添加规则</h3><input type="hidden" id="edit_id"><label>备注</label><input id="mod_n"><label>监听端口</label><input id="mod_l"><label>目标地址</label><input id="mod_r"><label>到期时间 (留空不限�?</label><input type="datetime-local" id="mod_e"><label>流量限制 (留空�?不限�?</label><div style="display:flex;gap:10px"><input id="mod_t_val" type="number" placeholder="数�? style="flex:1"><select id="mod_t_unit" style="padding:10px;border-radius:10px;border:1px solid rgba(0,0,0,0.05);background:rgba(255,255,255,0.5)"><option value="MB">MB</option><option value="GB">GB</option></select></div><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveRule()">保存</button></div></div></div>
<div id="viewModal" class="modal"><div class="modal-box"><h3 style="margin-bottom:20px;border-bottom:1px solid #eee;padding-bottom:10px">规则详情</h3><div class="info-row"><span>备注</span><span class="info-val" id="view_n"></span></div><div class="info-row"><span>监听</span><span class="info-val" id="view_l"></span></div><div class="info-row"><span>目标</span><span class="info-val" id="view_r"></span></div><div style="margin:15px 0;border-top:1px dashed #ddd;padding-top:10px"></div><div id="view_expire_sec"><div class="info-row"><span>到期时间</span><span class="info-val" id="view_e_date"></span></div><div style="text-align:right;font-size:0.8rem;color:#666" id="view_e_remain"></div></div><div style="margin:15px 0;border-top:1px dashed #ddd;padding-top:10px"></div><div id="view_traffic_sec"><div class="info-row"><span>流量使用 (Max)</span><span class="info-val"><span id="view_t_used"></span> / <span id="view_t_limit"></span></span></div><div class="progress-bar"><div class="progress-fill" id="view_t_bar"></div></div><div style="text-align:right;margin-top:5px"><button class="btn btn-gray" style="font-size:0.7rem;padding:4px 8px" onclick="resetTraffic()">重置流量</button></div></div><div style="margin-top:25px;display:flex;justify-content:flex-end;"><button class="btn btn-primary" onclick="closeModal()">关闭</button></div></div></div>
<div id="setModal" class="modal"><div class="modal-box"><div class="tab-header"><div class="tab-btn active" onclick="switchTab(0)">管理账户</div><div class="tab-btn" onclick="switchTab(1)">个性背�?/div></div><div class="tab-content active" id="tab0"><label>用户�?/label><input id="set_u" value="{{USER}}"><label>重置密码 (留空保持不变)</label><input id="set_p" type="password"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveAccount()">确认修改</button></div></div><div class="tab-content" id="tab1"><label>PC端壁�?URL</label><input id="bg_pc" value="{{BG_PC}}"><label>手机端壁�?URL</label><input id="bg_mob" value="{{BG_MOBILE}}"><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveBg()">应用背景</button></div></div></div></div>
<div id="batchModal" class="modal"><div class="modal-box" style="max-width:600px"><h3>批量添加规则</h3><p style="color:#666;font-size:0.85rem;margin-bottom:10px">格式：备�?监听端口,目标地址<br>一行一条，例如�?br>日本落地,10001,1.1.1.1:443</p><textarea id="batch_input" rows="10" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:10px;font-family:monospace" placeholder="备注,监听端口,目标地址"></textarea><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-primary" onclick="saveBatch()">开始导�?/button></div></div></div>
<div id="restoreModal" class="modal"><div class="modal-box"><h3>恢复备份</h3><p style="color:#ef4444;font-size:0.9rem;margin-bottom:15px">警告：导入操作将覆盖当前所有规则！</p><textarea id="restore_input" rows="8" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:10px;font-family:monospace;font-size:0.8rem"></textarea><div style="margin-top:25px;display:flex;justify-content:flex-end;gap:12px"><button class="btn btn-gray" onclick="closeModal()">取消</button><button class="btn btn-danger" onclick="doRestore()">确认覆盖</button></div></div></div>
<script>
let rules=[];let curId=null;
const $=id=>document.getElementById(id);
const fmtBytes=b=>{if(b===0)return'0 B';const k=1024,dm=2,sizes=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(dm))+' '+sizes[i]};
const fmtDate=ts=>{if(!ts)return'永久有效';return new Date(ts).toLocaleString()};
const getRemain=ts=>{
    if(!ts) return '';
    const now=Date.now();
    const diff=ts-now;
    if(diff<0) return '已过�?;
    const d = Math.floor(diff / (1000 * 60 * 60 * 24));
    const h = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    return `剩余 ${d}�?${h}小时`;
};
async function load(){const r=await fetch('/api/rules');if(r.status===401)location.href='/login';const d=await r.json();rules=d.rules;render()}
function render(){const t=$('list');const ev=$('emptyView');const table=$('ruleTable');t.innerHTML='';if(rules.length===0){ev.style.display='block';table.style.display='none'}else{ev.style.display='none';table.style.display='table';rules.forEach(r=>{const row=document.createElement('tr');if(!r.enabled)row.style.opacity='0.6';
let statusHtml=`<span class="status-dot ${r.enabled?'bg-green':'bg-gray'}"></span>${r.enabled?'在线':'暂停'}`;
if(r.status_msg) statusHtml+=` <span style="font-size:0.8rem;color:#ef4444">(${r.status_msg})</span>`;
const btns=`<button class="btn btn-gray" onclick="openView('${r.id}')"><i class="fas fa-eye"></i></button><button class="btn btn-gray" onclick="tog('${r.id}')"><i class="fas ${r.enabled?'fa-pause':'fa-play'}"></i></button><button class="btn btn-primary" onclick="openEdit('${r.id}')"><i class="fas fa-edit"></i></button><button class="btn btn-danger" onclick="del('${r.id}')"><i class="fas fa-trash-alt"></i></button>`;
const isMob=window.innerWidth<768;
let tfStr = fmtBytes(r.traffic_used);
if(r.traffic_limit > 0) tfStr += ` / ${fmtBytes(r.traffic_limit)}`;
if(isMob){row.innerHTML=`<td data-label="状�?>${statusHtml}</td><td data-label="备注"><strong>${r.name}</strong></td><td data-label="监听">${r.listen}</td><td data-label="目标">${r.remote}</td><td data-label="流量">${tfStr}</td><td data-label="操作">${btns.replace(/class="btn/g,'class="btn btn-sm')}</td>`;}
else{row.innerHTML=`<td data-label="状�?>${statusHtml}</td><td data-label="备注"><strong>${r.name}</strong></td><td data-label="监听">${r.listen}</td><td data-label="目标">${r.remote}</td><td data-label="流量">${tfStr}</td><td data-label="操作" style="display:flex;gap:6px;justify-content:flex-end;padding-right:15px">${btns}</td>`;}t.appendChild(row)})}}
function openAddModal(){curId=null;$('modalTitle').innerText='添加规则';['n','l','r','e','t_val'].forEach(x=>$('mod_'+x).value='');
const qn=$('n').value.trim();const ql=$('l').value.trim();const qr=$('r').value.trim();if(qn)$('mod_n').value=qn;if(ql)$('mod_l').value=ql;if(qr)$('mod_r').value=qr;
$('ruleModal').style.display='flex'}
function openEdit(id){curId=id;const r=rules.find(x=>x.id===id);$('modalTitle').innerText='编辑规则';$('mod_n').value=r.name;$('mod_l').value=r.listen.replace('0.0.0.0:','');$('mod_r').value=r.remote;
if(r.expire_date){const dt=new Date(r.expire_date);dt.setMinutes(dt.getMinutes()-dt.getTimezoneOffset());$('mod_e').value=dt.toISOString().slice(0,16)}else{$('mod_e').value=''}
if(r.traffic_limit){if(r.traffic_limit>=1073741824){$('mod_t_val').value=(r.traffic_limit/1073741824).toFixed(2);$('mod_t_unit').value='GB'}else{$('mod_t_val').value=(r.traffic_limit/1048576).toFixed(2);$('mod_t_unit').value='MB'}}else{$('mod_t_val').value=''}
$('ruleModal').style.display='flex'}
function openView(id){curId=id;const r=rules.find(x=>x.id===id);$('view_n').innerText=r.name;$('view_l').innerText=r.listen;$('view_r').innerText=r.remote;
if(r.expire_date){$('view_expire_sec').style.display='block';$('view_e_date').innerText=fmtDate(r.expire_date);$('view_e_remain').innerText=getRemain(r.expire_date)}else{$('view_expire_sec').style.display='none'}
$('view_traffic_sec').style.display='block';$('view_t_used').innerText=fmtBytes(r.traffic_used);
if(r.traffic_limit){$('view_t_limit').innerText=fmtBytes(r.traffic_limit);const pct=Math.min(100,(r.traffic_used/r.traffic_limit)*100);$('view_t_bar').style.width=pct+'%';$('view_t_bar').style.background=pct>90?'#ef4444':'#3b82f6'}else{$('view_t_limit').innerText='无限�?;$('view_t_bar').style.width='0%'}
$('viewModal').style.display='flex'}
async function saveRule(){
    let [n,l,r,e,tv,tu]=['n','l','r','e','t_val','t_unit'].map(x=>$('mod_'+x).value.trim());
    if(!n||!l||!r) return alert('请填写必填项');
    if(!l.includes(':'))l='0.0.0.0:'+l;
    let ed=0; if(e) ed=new Date(e).getTime();
    let tl=0; if(tv && parseFloat(tv)>0){ tl = parseFloat(tv) * (tu==='GB'?1073741824:1048576); }
    const payload={name:n,listen:l,remote:r,expire_date:ed,traffic_limit:Math.floor(tl)};
    const url = curId ? `/api/rules/${curId}` : '/api/rules';
    const method = curId ? 'PUT' : 'POST';
    const res = await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await res.json();
    if(d.status==='error') alert(d.message); else { closeModal(); load(); $('n').value='';$('l').value='';$('r').value='';}
}
async function resetTraffic(){if(!curId||!confirm('确定重置已用流量统计吗？'))return;await fetch(`/api/rules/${curId}/reset_traffic`,{method:'POST'});closeModal();load()}
async function tog(id){await fetch(`/api/rules/${id}/toggle`,{method:'POST'});load()}
async function del(id){if(confirm('确定删除此规则吗�?))await fetch(`/api/rules/${id}`,{method:'DELETE'});load()}
function openSettings(){$('setModal').style.display='flex';switchTab(0)}
function closeModal(){document.querySelectorAll('.modal').forEach(x=>x.style.display='none')}
function switchTab(idx){document.querySelectorAll('.tab-btn').forEach((b,i)=>b.classList.toggle('active',i===idx));document.querySelectorAll('.tab-content').forEach((c,i)=>c.classList.toggle('active',i===idx))}
async function saveAccount(){await fetch('/api/admin/account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('set_u').value,password:$('set_p').value})});alert('账户已更新，请重新登�?);location.reload()}
async function saveBg(){await fetch('/api/admin/bg',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bg_pc:$('bg_pc').value,bg_mobile:$('bg_mob').value})});location.reload()}
async function doLogout(){await fetch('/logout',{method:'POST'});location.href='/login'}
function openBatch(){$('batchModal').style.display='flex';$('batch_input').value='';}
async function saveBatch(){const raw=$('batch_input').value;if(!raw.trim())return;const lines=raw.split('\n');const payload=[];for(let line of lines){line=line.trim();if(!line)continue;line=line.replace(/�?g,',');const parts=line.split(',');if(parts.length<3)continue;let [n,l,r]=[parts[0].trim(),parts[1].trim(),parts[2].trim()];if(l&&!l.includes(':'))l='0.0.0.0:'+l;if(n&&l&&r){payload.push({name:n,listen:l,remote:r,expire_date:0,traffic_limit:0});}}if(payload.length===0)return alert('格式错误');const res=await fetch('/api/rules/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});alert((await res.json()).message);$('batchModal').style.display='none';load()}
async function delAll(){if(rules.length===0||!confirm('⚠️ 确定清空�?))return;await fetch('/api/rules/all',{method:'DELETE'});load()}
function downloadBackup(){if(rules.length===0)return alert('无数�?);window.location.href='/api/backup'}
function openRestore(){$('restoreModal').style.display='flex'}
async function doRestore(){try{const p=JSON.parse($('restore_input').value);if(!Array.isArray(p))throw 1;if(!confirm('确定覆盖�?))return;await fetch('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});location.reload()}catch(e){alert('JSON格式错误')}}
setInterval(load, 3000);
load();window.addEventListener('resize',render);
</script></body></html>
"#;
EOF

echo -e -n "${CYAN}>>> 编译面板程序 (请耐心等待�?...${RESET}"
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


# 编译并检�?cargo clean >/dev/null 2>&1
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
echo -e "${GREEN}          �?Realm 面板部署成功       ${RESET}"
echo -e "${GREEN}====================================${RESET}"
echo -e "访问地址 : ${YELLOW}http://${IP}:${PANEL_PORT}${RESET}"
echo -e "默认用户 : ${YELLOW}${DEFAULT_USER}${RESET}"
echo -e "默认密码 : ${YELLOW}${DEFAULT_PASS}${RESET}"
echo -e "------------------------------------------"
