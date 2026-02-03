# TASK: hia-realm 代码优化实施

**创建日期**: 2026-02-03  
**状态**: 待实施  
**模式**: Code

---

## 📋 任务概述

根据 [`plans/OPTIMIZATION-PLAN.md`](OPTIMIZATION-PLAN.md) 中的分析，实施以下代码优化。

---

## ✅ 实施清单

### 🔍 当前识别结果（2026-02-03）
- `panel.sh` BOM 已移除（文件头为 `23 21 2f`）
- 所有 `.sh` 文件已转换为 LF（`HasCR=False`）
- heredoc 内嵌内容（HTML/JSON）保持原格式，不参与缩进统一

### 第一阶段：高优先级修复

#### 1. 修复 panel.sh BOM 字符
- [x] 检查 `panel.sh` 第 1 行是否仍有 BOM 字符 (`﻿`)
- [x] 如有，移除 BOM 字符，确保文件以 `#!/bin/bash` 开头
- [x] 验证修复：`head -c 3 panel.sh | xxd` 应显示 `2321 2f` 而非 `efbb bf`

#### 2. 移除 CRLF 换行符
- [x] 将所有 `.sh` 文件从 CRLF 转换为 LF
- [x] 目标文件：
  - `install.sh`
  - `panel.sh`
  - `quickpanel.sh`
  - `unipan.sh`
  - `port-traffic-dog.sh`
- [x] `build-panel-release.sh` 已为 LF，可跳过或统一处理
- [x] 验证：`file *.sh` 应显示 "ASCII text" 而非 "ASCII text, with CRLF line terminators"

#### 3. ShellCheck 合规修复
- [ ] 运行 ShellCheck 检查所有脚本（当前环境未安装 ShellCheck）
- [x] 修复主要警告（已修复 SC2046 等关键点，待 ShellCheck 全量确认）
- [x] 优先修复可能导致运行时错误的问题

---

### 第二阶段：中优先级优化

#### 4. 创建公共函数库
- [x] 创建 `lib/common.sh` 文件
- [x] 提取以下公共函数：
  ```bash
  # 颜色定义
  GREEN="\033[32m"
  RED="\033[31m"
  YELLOW="\033[33m"
  CYAN="\033[36m"
  RESET="\033[0m"
  
  # 通用函数
  check_root()
  get_arch()
  get_libc()
  need_cmd()
  detect_system()
  ```
- [x] 在各脚本中引入：`source "$(dirname "$0")/lib/common.sh" 2>/dev/null || source /usr/local/lib/realm/common.sh`

#### 5. 统一系统检测逻辑
- [x] 将 `port-traffic-dog.sh` 的 `detect_system()` 函数移至 `lib/common.sh`
- [x] 更新 `install.sh` 使用统一的系统检测
- [x] 更新 `quickpanel.sh` 使用统一的系统检测

#### 6. 改进错误处理
- [x] 添加日志函数到 `lib/common.sh`：
  ```bash
  log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*"; }
  log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; }
  log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $*"; }
  ```
- [x] 在关键操作处添加错误处理

#### 7. 添加健康检查功能
- [x] 在 `install.sh` 中添加 `health_check` 菜单选项
- [x] 实现服务状态检查
- [x] 实现端口监听检查
- [x] 实现配置文件验证

---

### 第三阶段：低优先级改进（可选）

#### 8. 添加版本检查
- [ ] 在脚本头部添加版本号常量
- [ ] 实现远程版本检查功能
- [ ] 提示用户更新

#### 9. 统一代码风格
- [x] 创建 `.editorconfig` 文件
- [x] 统一缩进为 4 空格（脚本代码）
- [x] 统一函数命名为 snake_case

---

## 🔧 技术细节

### BOM 字符移除命令
```bash
# 检查是否有 BOM
head -c 3 panel.sh | xxd

# 移除 BOM（如果存在）
sed -i '1s/^\xEF\xBB\xBF//' panel.sh
```
PowerShell 版本：
```powershell
# 检查是否有 BOM
$bytes = [IO.File]::ReadAllBytes("panel.sh")
"{0:X2} {1:X2} {2:X2}" -f $bytes[0], $bytes[1], $bytes[2]

# 移除 BOM（如果存在）
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    [IO.File]::WriteAllBytes("panel.sh", $bytes[3..($bytes.Length - 1)])
}
```

### CRLF 转 LF 命令
```bash
# 使用 sed
sed -i 's/\r$//' *.sh

# 或使用 dos2unix
dos2unix *.sh
```
PowerShell 版本：
```powershell
Get-ChildItem *.sh | ForEach-Object {
    $text = [IO.File]::ReadAllText($_.FullName) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($_.FullName, $text)
}
```

### 公共函数库结构
```
hia-realm-main/
├── lib/
│   └── common.sh      # 公共函数库
├── install.sh
├── panel.sh
├── quickpanel.sh
├── unipan.sh
├── port-traffic-dog.sh
└── ...
```

---

## 📝 验证步骤

1. **语法检查**：`bash -n *.sh`
2. **ShellCheck**：`shellcheck *.sh`
3. **BOM 检查**：`file *.sh | grep -i bom`
4. **换行符检查**：`file *.sh | grep -i crlf`
5. **功能测试**：在测试环境运行各脚本主要功能

Windows/PowerShell 等价检测：
```powershell
# BOM 检查（仅 panel.sh 示例）
$bytes = [IO.File]::ReadAllBytes("panel.sh")
"{0:X2} {1:X2} {2:X2}" -f $bytes[0], $bytes[1], $bytes[2]

# CRLF 检查（HasCR=True 表示包含 CR）
Get-ChildItem *.sh | ForEach-Object {
    $raw = [IO.File]::ReadAllBytes($_.FullName)
    [PSCustomObject]@{ File = $_.Name; HasCR = $raw -contains 13 }
} | Format-Table -AutoSize
```

---

## ⚠️ 注意事项

1. **向后兼容**：修改不应破坏现有安装
2. **测试环境**：建议在测试服务器验证后再推送
3. **备份**：修改前确保有 git 备份
4. **逐步提交**：每个优化项单独提交，便于回滚

---

## 📊 预期成果

- 消除 BOM 和 CRLF 兼容性问题
- 减少约 200 行重复代码
- 提高代码可维护性
- 改善错误诊断能力
