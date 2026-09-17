# sensitive-filter

发给大模型前的本地敏感信息过滤 / Local sensitive-info filter before sending to LLMs

把日志/配置/代码/流量记录等内容发给云端大模型（或贴进上下文）**之前**，先在本地过一遍本工具。零依赖、秒级完成；装了 betterleaks 或 gitleaks 自动增强密钥识别（两者二选一，betterleaks 优先）。

Run logs/config/code before pasting them into a cloud LLM (or your chat context). Zero dependencies, sub-second; betterleaks or gitleaks auto-enhances secret detection when installed (betterleaks takes precedence).

## 脱敏 / Masking: 

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

# 类别开关 / category switches
python sensitive_filter.py 文件.txt --only phone,idcard
node sensitive-filter.mjs 文件.txt --skip ipv4
```

- stdout = 脱敏文本；stderr = 报告（计数、映射路径、扫描器状态，**永不显示原值**）
- 已是 `********` / `${VAR}` / `<TOKEN>` 形式的值不会二次处理
- `--no-gitleaks` 禁用外部扫描器补充层（betterleaks/gitleaks）


## 原理与部署 / Principle & Deployment

**原理**：所有发往大模型的内容（用户消息、系统提示、工具输出）在出境前替换为占位符（`192.0.2.1`/`sk-AbCdEf0123456789AbCdEf0123456789` 等），映射文件仅存本地。模型只看到占位符，引用时原样保留。工具执行前与回复展示前自动还原为真值。任何环节异常则阻断发送（fail-closed），原文绝不外泄。

### opencode 插件

```bash
# 全局部署（所有项目生效）
mkdir -p ~/.config/opencode/plugins
cp opencode/plugins/sensitive-filter.ts ~/.config/opencode/plugins/

# 或项目级部署
mkdir -p .opencode/plugins
cp opencode/plugins/sensitive-filter.ts .opencode/plugins/
# 重启 opencode 生效
```

用法：装好后无需命令行调用——每次调用大模型前自动掩码全部消息与系统提示，工具执行前与回复展示前自动还原。开关与映射目录写在**插件自身目录**的 `.env`（如 `SF_MAP_DIR`/`SF_MAP_KEEP`）或系统环境变量（`.env` 优先）；若模型把占位符写进了文件，用 CLI `--restore`（必要时 `--force`）兜底还原。核心正则层进程内联，无需 Python；外部扫描器可选增强（betterleaks 优先、回退 gitleaks，未装自动跳过）。

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

## 开关配置 / Configuration  --均可在.env配置中修改

| 变量 | 作用 | 默认 |
|---|---|---|
| `SF_OFF=1` | 全局停用 | — |
| `SF_ONLY=类别` | 只启用指定类别 | 全部 |
| `SF_SKIP=类别` | 跳过指定类别 | 无 |
| `SF_MAP_DIR=目录` | 映射文件目录（CLI 用 `--map-out`） | 系统临时目录 |
| `SF_MAP_KEEP=数量` | 映射保留上限（从最旧清理） | 5000 |
| `SF_PROXY_PORT` | Codex 代理监听端口 | 3141 |
| `SF_PROXY_HOST` | Codex 代理监听地址 | 全部接口 |
| `SF_UPSTREAM` | Codex 代理转发上游 | OpenAI 官方 |

映射文件为 `sensitive_filter_map_<sha8>.json`（`{source_sha256, tokens}` 双向字典，仅存本地）。插件与 CLI 须指向**同一目录**才能互相还原（插件用 `SF_MAP_DIR`，CLI 用 `--map-out`）。

配置优先级：同目录 `.env` > 系统环境变量。仓库根有 `.env.example` 模板：复制为 `.env` 并取消注释即生效（`.env` 已被 `.gitignore` 忽略，不会提交真实密钥）。各程序读自身所在目录的 `.env`。

## 层级架构 / Layers

| 层 Layer | 依赖 Dependency | 覆盖 Coverage |
|---|---|---|
| C 层（默认）regex layer | 无 / none | 密钥/连接串/Authorization 头/身份证/手机/银行卡/邮箱/IPv4 |
| betterleaks / gitleaks | 自动检测（二选一） | 补充密钥/凭据格式识别；betterleaks 优先，未安装自动跳过 |

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

## 外部扫描器安装 / Installing scanner (betterleaks / gitleaks)

外部扫描器是可选增强层（几百种密钥/凭据格式），未安装时自动跳过，不影响核心功能。**两者只需装一个**：同时存在时优先用 betterleaks（gitleaks 原作者的继任实现，CLI 兼容）。
- **betterleaks**   https://github.com/betterleaks/betterleaks
- **gitleaks**  https://github.com/gitleaks/gitleaks/

它的价值（实测结论）：
- **厂商前缀长尾**：SaaS/云厂商 token 的 detector 由上游持续更新（`SG.`、`npm_`、`glsa_`、`.atlasv1.`、Slack webhook 等），规则维护外包给上游。
- **熵启发式**：`generic-api-key`（关键词 + 高熵值）可抓无固定前缀的凭据——本工具为避免对话文本误报，主动不做熵检测。
- **betterleaks 额外能力**：`validate` 联网校验（会把命中的候选 token 发往对应厂商 API 验真，隐私敏感场景勿用；本工具自身从不调用它）、prefilter、自定义配置。
- **边界**：多数规则带熵阈值，hex/低熵字符集的真实厂商 token（dapi/PMAK/rubygems/NRAK- 等）与低熵关键词值会漏报——这类由本项目内置正则兜住；中文 PII、URL userinfo、PEM 等结构型规则为本项目独有。


## Credits / 致谢

- **[gitleaks](https://github.com/gitleaks/gitleaks)** (MIT) — 外部扫描层的第一实现；本项目按其 `dir` 子命令的参数方式调用。
- **[betterleaks](https://github.com/betterleaks/betterleaks)** (MIT) — gitleaks 原作者与社区维护的继任实现（CLI 兼容、规则更多；本项目优先检测并调用）。
- **[@rehydra/opencode](https://github.com/rehydra-ai/rehydra-sdk)** (MIT) — 还原闭环设计参考了该项目的实现思路。我们的差异：映射落盘可跨进程还原（其映射纯内存进程重启不可逆）、中文 PII 三件套（身份证 GB11643 / 手机 / 银联 Luhn）、显式 fail-closed、零依赖。

## License

MIT — see [LICENSE](LICENSE).