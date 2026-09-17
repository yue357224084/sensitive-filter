# sensitive-filter

发给大模型前的本地敏感信息过滤 / Local sensitive-info filter before sending to LLMs

把日志/配置/代码/流量记录等内容发给云端大模型（或贴进上下文）**之前**，先在本地过一遍本工具。零依赖、秒级完成；装了 gitleaks 自动增强密钥识别。

Run logs/config/code before pasting them into a cloud LLM (or your chat context). Zero dependencies, sub-second; gitleaks auto-enhances secret detection when installed.

## 功能 / Features

脱敏 / Masking:

| 类别 Category | 规则 Rule |
|---|---|
| 密钥 Secrets | PEM 私钥、JWT、`sk-`/`sk_`/`pk-`（含 Stripe `sk_live_`）、GitHub `ghp_`/`github_pat_`、GitLab `glpat-`/`glrt-`/`gldt-`/`gloas-`/`glptt-`/`glcbt-`、Slack `xox`/`xapp-`、AWS `AKIA/ASIA/ABIA/ACCA`、Google `AIza`/`GOCSPX-`/`ya29.`、阿里云 `LTAI`、HuggingFace `hf_`、PyPI `pypi-`、age `AGE-SECRET-KEY-1`、Stripe `rk_`、Vault `hvs.`、New Relic `NRAK-`、Databricks `dapi`、Postman `PMAK-`、Linear `lin_api_`、RubyGems `rubygems_`、连接串（mongodb/postgres/mysql/redis/ssh 等）、任意协议 URL 内嵌凭据 `//user:pass@`（socks5 含）、Authorization 头（Bearer/Basic）、`password=`/`"password":`/`token:` 赋值行 |
| 身份证 ID card | 18 位 + GB11643 校验位验证 |
| 手机号 Phone | 中国大陆手机号 |
| 银行卡 Bank card | Luhn 校验位验证（误报极低） |
| 邮箱 Email | 通用邮箱格式 |
| IPv4 | 点分十进制，RFC 5737 保留段不豁免（按需 `--skip ipv4`） |

输出可逆：脱敏为 `[SECRET_2]`/`[IDCARD_1]`/`[PHONE_1]`/`[BANKCARD_1]`/`[EMAIL_1]`/`[IPV4_1]` 形占位符，映射文件仅存本地，LLM 返回后 `--restore` 回填。映射文件名与内容 sha256 绑定，防错配；超过上限自动清理（默认保留 5000 个，从最旧删）。

Reversible: tokens like `[SECRET_2]`/`[IDCARD_1]`/`[PHONE_1]`/`[BANKCARD_1]`/`[EMAIL_1]`/`[IPV4_1]`; the mapping file stays local and `--restore` refills values after the LLM replies. Map filename is hash-bound to content; auto-cleaned by capacity (default keep 5000, oldest first).

## 映射文件位置 / Map file location

默认写在**系统临时目录**：`sensitive_filter_map_<sha8前8位>.json`（Windows 为 `%TEMP%`，如 `C:\Users\<USER>\AppData\Local\Temp\`；类 Unix 为 `$TMPDIR`）。

三端覆盖方式：

| 端 | 方式 |
|---|---|
| Python CLI | `--map-out <目录或文件路径>` |
| Node CLI | `--map-out <目录或文件路径>` |
| opencode 插件 | 环境变量 `SF_MAP_DIR=<目录>`（默认临时目录） |

> 注意：若通过 `SF_MAP_DIR` / `--map-out` 改了目录，插件与 CLI 必须指向**同一目录**，插件的占位符才能被 CLI 的 `--restore` 还原（双向互操作）。插件会自动创建 `SF_MAP_DIR` 目录；创建失败（如权限问题）时按 fail-closed 阻断。

## 用法 / Usage

```bash
# Python (零依赖 / zero-dep)
python sensitive_filter.py 文件.txt            # 脱敏文本 -> stdout, 报告 -> stderr
type app.log | python sensitive_filter.py
python sensitive_filter.py --selftest          # 自检 / self test

# Node.js 等价版 / equivalent (zero-dep)
node sensitive-filter.mjs 文件.txt
cat app.log | node sensitive-filter.mjs
node sensitive-filter.mjs --selftest

# 映射与还原 / map & restore

```bash
# 步骤 1: 脱敏，映射文件写到指定目录
python sensitive_filter.py app.log --map-out ./maps
# stdout = 脱敏文本（贴给 LLM），stderr = 报告
# 映射文件 ./maps/sensitive_filter_map_<sha8>.json 含 {source_sha256, tokens} 双向字典

# 步骤 2: 把脱敏文本贴给大模型，拿到回复
# （LLM 回复里的 [IPV4_1]/[SECRET_1] 等占位符可原样引用）

# 步骤 3: 还原——把 LLM 回复里的占位符换回原值
python sensitive_filter.py --restore llm_reply.txt --map ./maps/sensitive_filter_map_xxxxxxxx.json
# stdout = 还原后的文本

# 如果 LLM 改过占位符附近的内容（sha 配对不匹配），加 --force
python sensitive_filter.py --restore llm_reply.txt --map ./maps/sensitive_filter_map_xxxxxxxx.json --force

# Node.js 等价版同样支持 --map-out / --restore / --map / --force
node sensitive-filter.mjs --restore llm_reply.txt --map ./maps/sensitive_filter_map_xxxxxxxx.json
```

# 类别开关 / category switches
python sensitive_filter.py 文件.txt --only phone,idcard
node sensitive-filter.mjs 文件.txt --skip ipv4
```

- stdout = 脱敏文本；stderr = 报告（计数、映射路径、gitleaks 状态，**永不显示原值**）
- 已是 `********` / `${VAR}` / `<TOKEN>` 形式的值不会二次处理
- `--no-gitleaks` 禁用 gitleaks 补充层


## 原理与部署 / Principle & Deployment

**原理**：所有发往大模型的内容（用户消息、系统提示、工具输出）在出境前替换为占位符（`192.0.2.1`/`sk-AbCdEf0123456789AbCdEf0123456789` 等），映射文件仅存本地。模型只看到占位符，引用时原样保留。工具执行前与回复展示前自动还原为真值。任何环节异常则阻断发送（fail-closed），原文绝不外泄。

### opencode 插件

```bash
mkdir -p ~/.config/opencode/plugins
cp opencode/plugins/sensitive-filter.ts ~/.config/opencode/plugins/
# 重启 opencode 生效
```

每次调用大模型前自动掩码全部消息与系统提示，工具执行前与回复展示前自动还原。核心正则层进程内联，无需 Python；gitleaks 可选增强（`Bun.which` 检测，未装自动跳过）。

> 注意：会话标题生成调用不过插件（opencode issue #46115），首条消息可能明文到达标题模型；如需规避设 `"agent": { "title": { "disable": true } }`。

### Codex CLI 代理

Codex 无原生请求改写钩子，通过本地反向代理接入：

```bash
# 1. 启动代理（后台）
SF_UPSTREAM=https://your-upstream/v1 bun codex/proxy.mjs

# 2. config.toml 指向代理
# [model_providers.openaig]
# base_url = "http://127.0.0.1:3141/v1"

# 3. 重启 codex
```

代理出站掩码 `instructions`/`input` + 注入占位符指令 + 确定性持久映射（与 CLI/插件互操作）；入站 SSE 跨 chunk 还原 + JSON 递归还原。

## 开关 / Configuration

| 变量 | 作用 | 默认 |
|---|---|---|
| `SF_OFF=1` | 全局停用 | — |
| `SF_ONLY=类别` | 只启用指定类别 | 全部 |
| `SF_SKIP=类别` | 跳过指定类别 | 无 |
| `SF_MAP_DIR=目录` | 映射文件目录 | 系统临时目录 |
| `SF_MAP_KEEP=数量` | 映射保留上限（从最旧清理） | 5000 |
| `SF_PROXY_PORT` | Codex 代理监听端口 | 3141 |
| `SF_PROXY_HOST` | Codex 代理监听地址 | 全部接口 |
| `SF_UPSTREAM` | Codex 代理转发上游 | OpenAI 官方 |

配置优先级：同目录 `.env` > 系统环境变量。仓库根有 `.env` 模板（默认全注释，取消注释即生效）。各程序读自身所在目录的 `.env`。

## 层级架构 / Layers

| 层 Layer | 依赖 Dependency | 覆盖 Coverage |
|---|---|---|
| C 层（默认）regex layer | 无 / none | 密钥/连接串/Authorization 头/身份证/手机/银行卡/邮箱/IPv4 |
| gitleaks | 本机已装 / installed | 200+ 密钥格式补充；未安装自动跳过 |

## 已知边界 / Known limits

- 中文语义 PII（人名/地址）当前不覆盖——正则层只抓固定格式
- 带空格/横线分组的银行卡不检测；15 位旧身份证不检测
- 纯格式规则（手机号/IP）有少量误报属正常，宁多勿漏
- 关键名字串匹配（`passwd`/`token`/`secret` 等）区分不了「标识符」与「凭据值」，纯词如 `passwd` 也可能被登记掩码——属宁多勿漏取舍
- 占位符查不到映射时（映射被清理/跨机/跨目录）保持原样并在 stderr 告警一次，不会静默改写
- 脱敏只覆盖「发往模型的那份拷贝」：本地数据库 part 列、临时映射文件（含双向还原表）均为明文，请自行控制目录权限与清理

## 语义 PII 扩展（预留）/ Semantic PII extension (reserved)

如需识别中文人名/地址等语义 PII，可选集成 [GLiNER](https://github.com/urchade/gliner)（零样本 NER）。当前版本未接入，正则层已覆盖身份证/手机/银行卡等高确定性格式。GLiNER 主流 PII 模型 `gliner_multi_pii-v1` 不含中文，中文语义识别需额外中文 NER 模型或 deny-list 补偿。

English: To recognize Chinese names/addresses (semantic PII), optionally integrate GLiNER. Current version uses regex only; GLiNER integration is reserved for future work.

## gitleaks 安装 / Installing gitleaks

gitleaks 是可选增强层（200+ 密钥格式），未安装时自动跳过，不影响核心功能。

### Linux

```bash
# 方式 1: 下载 release 二进制
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64 -O /usr/local/bin/gitleaks
chmod +x /usr/local/bin/gitleaks

# 方式 2: Homebrew
brew install gitleaks

# 验证
gitleaks version
```

### Windows

```powershell
# 方式 1: winget
winget install Gitleaks.Gitleaks

# 方式 2: scoop
scoop install gitleaks

# 方式 3: choco
choco install gitleaks

# 验证
gitleaks version
```

## Credits / 致谢

- **[@rehydra/opencode](https://github.com/rehydra-ai/rehydra-sdk)** (MIT) — 还原闭环设计（`tool.execute.before` 还原工具入参、`experimental.text.complete` 还原 LLM 回复、`system.transform` 注入占位符指令）参考了该项目的实现思路。我们的差异：映射落盘可跨进程还原（其映射纯内存进程重启不可逆）、中文 PII 三件套（身份证 GB11643 / 手机 / 银联 Luhn）、显式 fail-closed、零依赖。

## License

MIT — see [LICENSE](LICENSE).