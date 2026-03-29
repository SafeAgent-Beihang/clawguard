# 🦞 ClawGuard v3

> 企业级 AI 智能体安全工具包 - SKILL.md 驱动的主动防御

## 核心理念

**ClawGuard v3 的核心防御不在代码，而在 SKILL.md！**

每个模块的 `SKILL.md` 本身就是完整的防御指南：
- 告诉 Agent **何时触发**
- 指导 Agent **如何检测**
- 提供具体的**检测模式和规则**
- 定义**输出格式和判定标准**

代码脚本只是辅助工具，真正的智能在 SKILL.md 里。

---

## 🎯 五大安全模块

| 模块 | 定位 | SKILL.md 行数 | 核心功能 |
|------|------|---------------|----------|
| **Auditor** | 事前审计 | 679 行 | 意图偏离检测、SKILL.md 代码块扫描 |
| **Checker** | 静态检查 | 476 行 | 配置检查、一键加固 |
| **Detect** | 事中监控 | 615 行 | 威胁检测、Guardian 联动 |
| **Guardian** | 事中执行 | 451 行 | 行为监控，会话冻结/回放 |
| **Shield** | 主动防御 | 493 行 | 提示词注入、零宽字符检测 |

**总文档量**: 2,714 行（v2 仅 2,226 行，3 个模块）

---

## 📂 模块结构

每个模块包含：

```
auditor-skill/
├── SKILL.md      ← 核心防御指南（最重要！）
├── _meta.json    ← 元数据
├── cli.js        ← 辅助命令行工具
└── src/          ← 辅助代码模块
```

### SKILL.md 的核心内容

每个 SKILL.md 都包含：

1. **何时触发** - 什么情况下 Agent 应该使用这个模块
2. **如何执行** - 详细的检测步骤和流程
3. **检测模式库** - 具体的正则表达式和模式匹配规则
4. **判定标准** - 如何输出结果和风险等级
5. **示例** - 实际使用案例

---

## 🚀 快速开始

### 通过 Agent 使用（推荐）

直接告诉 Agent 要做什么，Agent 会读取 SKILL.md 并执行：

```
用户: 帮我审计一下这个 skill：/workspace/skills/weather-tool
      ↓
Agent 读取 auditor-skill/SKILL.md
      ↓
Agent 按 SKILL.md 中的指南执行审计
      ↓
输出审计结果
```

### 通过命令行使用

```bash
# 审计 Skill
cd auditor-skill && node cli.js /path/to/skill

# 检测配置
cd checker-skill && node cli.js ~/.openclaw/openclaw.json

# 检测威胁
cd detect-skill && node cli.js --monitor

# 运行时守护
cd guardian-skill && node cli.js start

# 检测注入
cd shield-skill && node cli.js defend "测试文本"
```

---

## 📋 各模块功能

### Auditor - 安装前审计（679 行）

**触发场景**: 安装新 Skill 之前

**SKILL.md 核心功能**:
- 检测命令执行风险（100+ 模式）
- 检测文件访问风险
- 检测网络请求风险
- **意图偏离检测**（v3 新增）
- **SKILL.md 代码块扫描**（v3 新增）
- 供应链安全分析
- MITRE ATT&CK 映射

**判定输出**:
```
🟢 安全 → 可安装
🟡 需关注 → 确认后可安装
🔴 高危 → 不建议安装
```

### Checker - 配置检查（476 行）

**触发场景**: 检查配置安全性

**SKILL.md 核心功能**:
- Gateway 配置检查
- 工具执行配置检查
- 沙箱配置检查
- 网络安全检查
- **加固建议**（v3 新增）
- **一键修复**（v3 新增）

**判定输出**:
```
⚠️ 发现问题 + 具体修复建议 + 一键加固
```

### Detect - 威胁检测（615 行）

**触发场景**: 实时监控和威胁扫描

**SKILL.md 核心功能**:
- 命令执行威胁检测
- 文件操作威胁检测
- 网络威胁检测
- 提示词注入检测
- 攻击链关联分析
- **Guardian 联动**（v3 新增）

**判定输出**:
```
🔴 CRITICAL → 立即处理
🟠 HIGH → 请求确认
🟡 MEDIUM → 记录警告
```

### Guardian - 运行时守护（451 行）

**触发场景**: 需要行为监控时

**SKILL.md 核心功能**:
- 实时行为监控
- 风险操作拦截
- 会话审计回放
- **应急冻结功能**（v3 新增）
- **证据保全**（v3 新增）
- **规则引擎**（v3 新增）

**核心规则**:
```
禁止: /etc/*, /root/*, /.ssh/*
确认: rm -rf, chmod 777, killall
记录: 所有操作
```

### Shield - 主动护盾（493 行）

**触发场景**: 检测用户输入安全性

**SKILL.md 核心功能**:
- **Base64 编码注入检测**（v3 新增）
- **Hex/Unicode 编码检测**（v3 新增）
- **零宽字符检测**（v3 新增）
- 角色劫持检测
- 越狱攻击检测
- **指令链劫持检测**（v3 新增）
- **意图验证**（v3 新增）

**检测流程**:
```
编码检测 → 劫持检测 → 越狱检测 → 链劫持检测 → 意图偏离
```

---

## 🔍 意图偏离检测（v3 核心功能）

### 什么是意图偏离？

Skill 声称的功能 vs 实际行为不一致：

| 声明 | 实际 | 判定 |
|------|------|------|
| "天气工具" | 读取 SSH 密钥 | 🔴 严重偏离 |
| "文件整理" | 启动后门进程 | 🔴 严重偏离 |
| "翻译助手" | 外发用户文档 | 🔴 严重偏离 |

### 检测方法

1. 从 SKILL.md 提取声称功能
2. 分析代码实际行为（包括 SKILL.md 中的代码块）
3. 对比是否匹配
4. 不匹配则标记为高风险

---

## 📁 项目结构

```
ClawGuardv3/
├── auditor-skill/           # 安装前审计（679 行 SKILL.md）
│   ├── SKILL.md          # ⭐ 核心防御指南
│   ├── README.md         # 使用指南
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       ├── auditor.js
│       ├── sast-analyzer.js
│       ├── intent-drift-detector.js
│       └── supply-chain-analyzer.js
├── checker-skill/           # 配置检查（476 行 SKILL.md）
│   ├── SKILL.md          # ⭐ 核心防御指南
│   ├── README.md         # 使用指南
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── checker.js
├── detect-skill/            # 威胁检测（615 行 SKILL.md）
│   ├── SKILL.md          # ⭐ 核心防御指南
│   ├── README.md         # 使用指南
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── detector.js
├── guardian-skill/           # 运行时守护（451 行 SKILL.md）
│   ├── SKILL.md          # ⭐ 核心防御指南
│   ├── README.md         # 使用指南
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── guardian.js
├── shield-skill/            # 主动护盾（493 行 SKILL.md）
│   ├── SKILL.md          # ⭐ 核心防御指南
│   ├── README.md         # 使用指南
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── shield.js
└── shared/
    └── rules/
        └── interceptor-rules.js
```

---

## 🆚 v2 vs v3 区别

| 功能 | v2 | v3 |
|------|----|----|
| **模块数量** | 3 个 | **5 个** |
| **SKILL.md 总行数** | 2,226 行 | **2,714 行** |
| **防御核心** | 代码实现 | **SKILL.md** |
| 意图偏离检测 | 基础 | **完整** |
| SKILL.md 代码扫描 | 无 | **有** |
| Guardian 联动 | 无 | **有** |
| 会话管理 | 基础 | **冻结/回放** |
| 提示词注入防护 | 基础 | **多层次检测** |
| 零宽字符检测 | 无 | **有** |
| 一键加固 | 无 | **有** |

### 模块对比

| 模块 | v2 SKILL.md | v3 SKILL.md | 新增内容 |
|------|-------------|-------------|----------|
| Auditor | 823 行 | 679 行 | 意图偏离、SKILL.md扫描 |
| Checker | 686 行 | 476 行 | 一键加固、修复建议 |
| Detect | 717 行 | 615 行 | Guardian联动、零宽检测 |
| Guardian | - | 451 行 | **全新模块** |
| Shield | - | 493 行 | **全新模块** |

---

## 📄 许可证

MIT License

---

**版本**: v3.0.0
**更新日期**: 2026-03-21
