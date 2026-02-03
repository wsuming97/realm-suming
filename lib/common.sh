#!/bin/bash

export GREEN="\033[32m"
export RED="\033[31m"
export YELLOW="\033[33m"
export CYAN="\033[36m"
export RESET="\033[0m"

log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $*"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; }

run_or_die() {
    local msg="$1"
    shift
    "$@" || {
        log_error "$msg"
        exit 1
    }
}

check_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "${RED}请以 root 用户运行此脚本。${RESET}"
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo -e "${RED}缺少依赖命令：$1，请先安装。${RESET}"
    exit 1
  }
}

get_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    armv7l|armv6l) echo "armv7" ;;
    *) echo "unsupported" ;;
  esac
}

get_libc() {
  if ldd --version 2>&1 | grep -qi musl; then
    echo "musl"
  else
    echo "gnu"
  fi
}

detect_system() {
  # Ubuntu优先检测：避免Debian系统误判
  if [ -f /etc/lsb-release ] && grep -q "Ubuntu" /etc/lsb-release 2>/dev/null; then
    echo "ubuntu"
    return
  fi

  if [ -f /etc/debian_version ]; then
    echo "debian"
    return
  fi

  if [ -f /etc/redhat-release ]; then
    echo "centos"
    return
  fi

  if [ -f /etc/alpine-release ]; then
    echo "alpine"
    return
  fi

  echo "unknown"
}
