# 集成端口流量狗功能到 hia-realm 项目

> 📝 此任务由 Roo Code Architect 模式生成，请�?Codex 中执�?

## 背景

hia-realm 是一个基�?[zhboner/realm](https://github.com/zhboner/realm) �?TCP+UDP 转发管理脚本，包�?Web 面板功能。现需要集�?realm-xwPF 项目�?端口流量�?(Port Traffic Dog) 功能，提供流量监控、带宽限速、流量配额和通知告警能力�?

**项目位置**: `c:/Users/suto/Desktop/hia-realm-main`

**现有文件结构**:
```
hia-realm-main/
├── install.sh       # 主安装脚本（896行）- 包含菜单系统
├── panel.sh         # 自编�?Web 面板脚本
├── quickpanel.sh    # 快速部署面板脚�?
├── unipan.sh        # 卸载面板脚本
├── test.sh          # 测试脚本
├── README.md        # 项目文档
└── plans/           # 规划文档目录
```

## 目标

将端口流量狗功能集成�?hia-realm 项目中，实现�?
1. 添加独立�?`port-traffic-dog.sh` 脚本文件
2. �?`install.sh` 主菜单中添加入口
3. 更新 `README.md` 文档

## 技术要�?

- **编程语言**: Bash Shell Script
- **依赖工具**: nftables, tc, jq, curl, cron
- **目标系统**: Linux (Ubuntu 20.04+, Debian 10+)
- **代码风格**: 与现�?install.sh 保持一�?

## 任务清单

- [ ] 子任�?: 创建 `port-traffic-dog.sh` 文件（使用用户提供的完整代码�?
- [ ] 子任�?: 修改 `install.sh` 添加菜单入口和调用函�?
- [ ] 子任�?: 更新 `README.md` 添加流量狗功能文�?

## 文件结构

修改后的文件结构�?
```
hia-realm-main/
├── install.sh           # 修改：添加菜单选项17和调用函�?
├── port-traffic-dog.sh  # 新建：端口流量狗完整脚本
├── panel.sh
├── quickpanel.sh
├── unipan.sh
├── test.sh
├── README.md            # 修改：添加流量狗文档
└── plans/
```

## 详细修改说明

### 1. 创建 port-traffic-dog.sh

用户已提供完整的 port-traffic-dog.sh 代码（约2500行），直接保存为项目根目录下�?`port-traffic-dog.sh` 文件�?

### 2. 修改 install.sh

**位置1**: �?`main_menu()` 函数中添加菜单选项（约�?69-870行）

```bash
# �?echo "16. Realm 面板管理" 后添�?
echo "17. 端口流量狗管�?
```

**位置2**: 修改用户输入提示（约�?71行）

```bash
# 原来
read -p "请选择一个操�?[0-15]: " OPT
# 改为
read -p "请选择一个操�?[0-17]: " OPT
```

**位置3**: �?case 语句中添加处理分支（约第889行后�?

```bash
# �?16) manage_panel ;; 后添�?
17) require_installed && run_traffic_dog ;;
```

**位置4**: 添加新函�?`run_traffic_dog()`（在 `manage_panel()` 函数后）

```bash
run_traffic_dog() {
    local TRAFFIC_DOG_SCRIPT="/usr/local/bin/port-traffic-dog.sh"
    local TRAFFIC_DOG_URL="https://raw.githubusercontent.com/wsuming97/realm-suming/master/port-traffic-dog.sh"
    
    if [ -f "$TRAFFIC_DOG_SCRIPT" ]; then
        bash "$TRAFFIC_DOG_SCRIPT"
    else
        echo -e "${YELLOW}正在下载端口流量狗脚�?..${RESET}"
        if curl -fsSL "$TRAFFIC_DOG_URL" -o "$TRAFFIC_DOG_SCRIPT"; then
            chmod +x "$TRAFFIC_DOG_SCRIPT"
            bash "$TRAFFIC_DOG_SCRIPT"
        else
            echo -e "${RED}下载失败，请检查网络连�?{RESET}"
        fi
    fi
}
```

### 3. 更新 README.md

�?"## Web 面板（Rust�? 章节后添加：

```markdown
## 端口流量�?

端口流量狗是一个强大的端口流量监控和管理工具，�?[realm-xwPF](https://github.com/zywe03/realm-xwPF) 项目集成�?

### 核心功能

- 🔍 **流量监控**: 基于 nftables 的精确流量统计（支持双向/单向模式�?
- 🚦 **带宽限�?*: 使用 tc 流量控制实现端口级别限�?
- 📊 **流量配额**: 月度流量配额管理，支持自动重�?
- 🔔 **通知告警**: 支持 Telegram 和企业微信通知

### 使用方法

在主菜单选择 **17. 端口流量狗管�?* 进入管理界面�?

首次使用会自动下载脚本并安装依赖�?

### 快捷命令

安装后可直接使用 `dog` 命令启动�?

### 子菜单说�?

| 选项 | 功能 |
|------|------|
| 1 | 添加/删除端口监控 |
| 2 | 端口限制设置管理（带�?配额�?|
| 3 | 流量重置管理 |
| 4 | 一键导�?导入配置 |
| 5 | 安装依赖(更新)脚本 |
| 6 | 卸载脚本 |
| 7 | 通知管理 |
| 0 | 退�?|

### 数据存储

- 配置文件: `/etc/port-traffic-dog/config.json`
- 日志文件: `/etc/port-traffic-dog/logs/traffic.log`
```

## 验收标准

- [ ] `port-traffic-dog.sh` 文件已创建且可执�?
- [ ] `install.sh` 菜单显示选项17
- [ ] 选择17后能正确调用流量狗脚�?
- [ ] `README.md` 包含流量狗功能说�?
- [ ] 所有文件保�?Unix 换行�?(LF)

## 约束条件

- 不修改现有功能逻辑
- 保持与现有代码风格一�?
- 脚本需�?root 权限运行
- 兼容 Ubuntu 20.04+ �?Debian 10+

## 参考资�?

- [realm-suming 项目](https://github.com/wsuming97/realm-suming)
- [realm-xwPF 项目](https://github.com/zywe03/realm-xwPF)
- [端口流量狗集成计划](plans/port-traffic-dog-integration-plan.md)

## 附录：port-traffic-dog.sh 完整代码

用户已在对话中提供完整代码，请直接使用该代码创建文件�?

---

*此任务由 Roo Code Architect 模式生成，请�?Codex 中执�?
