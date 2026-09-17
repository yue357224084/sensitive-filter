// 全局敏感信息过滤闸口：所有会话、发大模型前的最后一道本地过滤。
// 过滤核心已进程内联（C 层正则 + 可选 betterleaks/gitleaks 增强），掩码侧不再 spawn python/node 子进程。
// 掩码侧：experimental.chat.messages.transform（全部消息 parts）
//        + experimental.chat.system.transform（系统提示词 + 占位符指令注入）
// 还原侧：tool.execute.before（模型回显占位符→工具执行前还原真值）
//        + experimental.text.complete（LLM 回复展示前还原）
// 映射落盘：os.tmpdir()/sensitive_filter_map_<sha8>.json（默认；SF_MAP_DIR 可改目录。24h 自动清理；
//   与 sensitive_filter.py / sensitive-filter.mjs 的 --restore 双向互操作）
// 失败策略：fail-closed——掩码侧异常阻断发送；还原侧异常阻断工具执行/回复。
// 开关：环境变量 SF_OFF=1 全局停用；SF_ONLY=类别 只启用部分类别；SF_SKIP=类别 跳过部分类别。
import type { Plugin } from "@opencode-ai/plugin"
import { tmpdir } from "node:os"

// 映射目录：默认 os.tmpdir()，可用环境变量 SF_MAP_DIR 覆盖
// （改了必须与本机 CLI 的 --map-out 指到同一目录，双向还原才互操作）
function mapDir(): string {
  const dir = process.env.SF_MAP_DIR || tmpdir()
  try { mkdirSync(dir, { recursive: true }) } catch { /* 权限问题时读写侧按 fail-closed 报错 */ }
  return dir
}
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { createHash } from "node:crypto"

// ---------------------------------------------------------------- .env 注入（脚本同目录；.env 值优先于系统环境变量）
// 与 sensitive-filter.mjs / codex/proxy.mjs 同款实现；.env 不存在则静默跳过。
function loadDotEnv(): void {
  let txt = ""
  try { txt = readFileSync(join(dirname(fileURLToPath(import.meta.url)), ".env"), "utf8") } catch { return }
  for (const line of txt.split(/\r?\n/)) {
    let s = line.trim()
    if (!s || s.startsWith("#")) continue
    if (s.startsWith("export ")) s = s.slice(7)
    const i = s.indexOf("=")
    if (i <= 0) continue
    let v = s.slice(i + 1).trim()
    if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) v = v.slice(1, -1)
    process.env[s.slice(0, i).trim()] = v
  }
}
loadDotEnv()

// 占位符形如 [SECRET_1] / [IPV4_3] ...
const TOKEN_HAS = /\[(?:SECRET|IDCARD|PHONE|BANKCARD|EMAIL|IPV4)_\d+\]/
const TOKEN_ANY = /\[(?:SECRET|IDCARD|PHONE|BANKCARD|EMAIL|IPV4)_\d+\]/g

const SF_INSTRUCTION =
  "[sensitive-filter] 对话里的 [SECRET_n]/[IDCARD_n]/[PHONE_n]/[BANKCARD_n]/[EMAIL_n]/[IPV4_n] 是真实值的本地脱敏占位符：请原样保留引用、不要改写格式、不要编造原值；在 bash/写文件等工具参数里引用时也保持原样（工具执行前会自动还原为真值）。"

// opencode 插件加载约束：模块顶层每个导出值必须是函数（getLegacyPlugins 遍历 Object.values(mod)，
// 数组/对象导出直接抛 "Plugin export is not a function"，具名函数导出会被误当插件实例调用）。
// 因此本文件只保留 export default；内部实现经 Object.assign 挂在插件函数上供 bun test 访问。

function makeSep(): string {
  // 仅字母+连字符，不含数字，保证不命中任何过滤正则；每次调用随机防内容碰撞
  const abc = "abcdefghijklmnopqrstuvwxyz"
  let s = "SFSEP-"
  for (let i = 0; i < 24; i++) s += abc[Math.floor(Math.random() * 26)]
  return s
}

type Slot = { get(): string; set(v: string): void }

function collectPartSlots(p: any, slots: Slot[]): void {
  if (!p || typeof p !== "object") return
  if ((p.type === "text" || p.type === "reasoning") && typeof p.text === "string") {
    slots.push({ get: () => p.text, set: (v) => { p.text = v } })
  } else if (p.type === "subtask" && typeof p.prompt === "string") {
    slots.push({ get: () => p.prompt, set: (v) => { p.prompt = v } })
  } else if (p.type === "tool" && p.state && typeof p.state === "object") {
    const st = p.state
    if (typeof st.output === "string") slots.push({ get: () => st.output, set: (v) => { st.output = v } })
    if (typeof st.error === "string") slots.push({ get: () => st.error, set: (v) => { st.error = v } })
    if (typeof st.raw === "string") slots.push({ get: () => st.raw, set: (v) => { st.raw = v } })
    if (st.input && typeof st.input === "object" && Object.keys(st.input).length > 0) {
      slots.push({
        get: () => JSON.stringify(st.input),
        set: (v) => {
          try {
            const o = JSON.parse(v)
            if (o && typeof o === "object") Object.keys(st.input).forEach((k) => delete st.input[k])
            if (o && typeof o === "object") Object.assign(st.input, o)
            else st.input = { sf_masked: true }
          } catch {
            st.input = { sf_masked: true } // fail-closed：解析失败就不留原文
          }
        },
      })
    }
  }
}

// ---------- 还原：token → 真值（读 os.tmpdir() 映射文件，按 mtime 新者优先） ----------

// 一次扫描得到三张表（tok→值 供还原、值→tok 供跨批次复用编号、各类别最大编号供分配）。
// 缓存键 = 文件数:最新 mtime —— 新写 map 后自动失效重扫。
type MapScan = { tok2val: Map<string, string>; val2tok: Map<string, string>; maxByCat: Record<string, number> }
let scanCache: { key: string; scan: MapScan } | null = null

function scanMaps(): MapScan {
  const dir = mapDir()
  const files: { name: string; m: number }[] = []
  try {
    for (const name of readdirSync(dir)) {
      if (!name.startsWith(MAP_PREFIX) || !name.endsWith(".json")) continue
      try {
        files.push({ name, m: statSync(join(dir, name)).mtimeMs })
      } catch {}
    }
  } catch { /* 目录不可读：返回空表 */ }
  const newest = files.reduce((a, f) => Math.max(a, f.m), 0)
  const key = `${dir}:${files.length}:${newest}`
  if (scanCache?.key === key) return scanCache.scan
  const tok2val = new Map<string, string>()
  const val2tok = new Map<string, string>()
  const maxByCat: Record<string, number> = {}
  const tokRe = /^\[([A-Z][A-Z0-9]*)_(\d+)\]$/  // 类别名可含数字（IPV4）
  // tokens 是双向字典：{[CAT_n]: 原值, 原值: [CAT_n], 类别描述: [CAT_n]}。
  // 按 mtime 降序先到先得（同键冲突时新文件胜出）。
  files.sort((a, b) => b.m - a.m)
  for (const f of files) {
    try {
      const tokens = JSON.parse(readFileSync(join(dir, f.name), "utf8"))?.tokens
      if (!tokens || typeof tokens !== "object") continue
      for (const [k, v] of Object.entries(tokens)) {
        const ks = typeof k === "string" ? k : ""
        const vs = typeof v === "string" ? v : ""
        const kTok = tokRe.exec(ks)
        const vTok = tokRe.exec(vs)
        if (kTok) {
          if (!tok2val.has(ks)) tok2val.set(ks, vs)
          maxByCat[kTok[1]] = Math.max(maxByCat[kTok[1]] ?? 0, Number(kTok[2]))
        }
        if (vTok) {
          if (!tok2val.has(vs)) tok2val.set(vs, ks)
          maxByCat[vTok[1]] = Math.max(maxByCat[vTok[1]] ?? 0, Number(vTok[2]))
        }
        // 原值 → 占位符（供 renumber 跨批次复用编号，避免同值每请求换号后旧号失联）
        if (kTok && vs && !vTok && !val2tok.has(vs)) val2tok.set(vs, ks)
        if (vTok && ks && !kTok && !val2tok.has(ks)) val2tok.set(ks, vs)
      }
    } catch { /* 坏文件跳过 */ }
  }
  const scan = { tok2val, val2tok, maxByCat }
  scanCache = { key, scan }
  return scan
}

function tokenLookup(): Map<string, string> {
  return scanMaps().tok2val
}

// 无映射令牌：把"静默污染"变成可见告警（同一进程内每个编号只报一次）
const auditedMissing = new Set<string>()

function rehydrate(text: string): string {
  if (!text || !TOKEN_HAS.test(text)) return text
  return text.replace(TOKEN_ANY, (t) => {
    const v = tokenLookup().get(t)
    if (v !== undefined) return v
    if (!auditedMissing.has(t)) {
      auditedMissing.add(t)
      console.error(`[sensitive-filter] 未映射占位符 ${t} 保持原样（映射可能已过期/被清理；如需还原用 CLI --restore）`)
    }
    return t
  })
}

function deepRehydrate(v: any): any {
  if (typeof v === "string") return rehydrate(v)
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) v[i] = deepRehydrate(v[i])
    return v
  }
  if (v && typeof v === "object") {
    for (const k of Object.keys(v)) v[k] = deepRehydrate(v[k])
    return v
  }
  return v
}

// ================================================================
// 掩码核心（进程内联；与 sensitive-filter.mjs / sensitive_filter.py 行为对齐）
// ================================================================

// ---- 校验算法 ----

const CN_ID_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const CN_ID_MAP = "10X98765432"

function idcardOk(s: string): boolean {
  // GB 11643 校验位验证（18 位身份证）。
  try {
    if (s.length !== 18) return false
    let sum = 0
    for (let i = 0; i < 17; i++) sum += parseInt(s[i], 10) * CN_ID_W[i]
    return CN_ID_MAP[sum % 11] === s[17].toUpperCase()
  } catch {
    return false
  }
}

function luhnOk(s: string): boolean {
  try {
    let total = 0
    for (let i = 0; i < s.length; i++) {
      const d = parseInt(s[s.length - 1 - i], 10) * (i % 2 ? 2 : 1)
      total += d > 9 ? d - 9 : d
    }
    return total % 10 === 0
  } catch {
    return false
  }
}

// ---- C 层规则 ----
// 顺序即优先级：先命中的 span 占位，后续类别跳过重叠区域。
// 元组: [类别名, 正则, 校验函数|null, 要掩码的 group 序号]
const CATS: [string, RegExp, ((s: string) => boolean) | null, number][] = [
  ["secret", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, null, 0],
  ["secret", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, null, 0],  // JWT
  // sk/pk 前缀：短横线（OpenAI/DeepSeek sk-...）+ 下划线（Stripe sk_live_、cline sk_...）
  ["secret", /\b(?:sk|pk)[_-][A-Za-z0-9_-]{16,}\b/g, null, 0],
  ["secret", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g, null, 0],
  ["secret", /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, null, 0],  // GitHub fine-grained PAT
  ["secret", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, null, 0],
  ["secret", /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, null, 0],  // AWS 前缀族（gitleaks）
  ["secret", /\bAIza[0-9A-Za-z_-]{35}\b/g, null, 0],  // Google API key
  ["secret", /\bglpat-[A-Za-z0-9_-]{20,}\b/g, null, 0],  // GitLab PAT
  ["secret", /\bLTAI[A-Za-z0-9]{12,20}\b/g, null, 0],  // 阿里云 AccessKey ID
  ["secret", /\bhf_[A-Za-z0-9]{34}\b/gi, null, 0],  // HuggingFace token
  ["secret", /\bGOCSPX-[0-9A-Za-z_-]{28}\b/gi, null, 0],  // Google OAuth client secret
  ["secret", /\bya29\.[0-9A-Za-z_-]{50,}\b/gi, null, 0],  // Google OAuth access token
  ["secret", /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}\b/gi, null, 0],  // PyPI token（前缀固定）
  ["secret", /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/gi, null, 0],  // age 私钥
  ["secret", /\bgl(?:rt|dt|oas|ptt|cbt)-[0-9a-zA-Z_-]{20,}\b/gi, null, 0],  // GitLab runner/deploy/OAuth/pipeline-trigger/CI-job token
  ["secret", /\bxapp-\d-[A-Z0-9]+-\d+-[A-Za-z0-9]+\b/gi, null, 0],  // Slack app-level token
  ["secret", /\brk_[a-zA-Z0-9]{10,}\b/gi, null, 0],  // Stripe restricted key
  ["secret", /\bhvs\.[A-Za-z0-9_-]{90,120}\b/gi, null, 0],  // HashiCorp Vault service token
  ["secret", /\bNRAK-[A-Z0-9]{27}\b/gi, null, 0],  // New Relic
  ["secret", /\bdapi[a-f0-9]{32}\b/gi, null, 0],  // Databricks
  ["secret", /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/gi, null, 0],  // Postman
  ["secret", /\blin_api_[a-z0-9]{40}\b/gi, null, 0],  // Linear
  ["secret", /\brubygems_[a-f0-9]{48}\b/gi, null, 0],  // RubyGems
  // 连接串（数据库/消息队列/远程协议，内嵌凭据）— http/https 不含（普通 URL 太常见）
  ["secret", /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|ftp|sftp|ssh):\/\/[^\s"'<>\]]{3,}/g, null, 0],
  // 通用 URL userinfo：任意协议 //user:pass@ —— grp=1 只掩凭据段，协议与 host 保留（socks5://b389:pwd@ip 也被盖住）
  ["secret", /\b[a-z][a-z0-9+.-]*:\/\/([^\s\/@:@]+:[^\s\/@:@]*)@/gid, null, 1],
  // Authorization 头（Bearer/Basic + token）
  ["secret", /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}/g, null, 0],
  // grp=1 的正则带 d flag：用 m.indices[grp] 取捕获组绝对位置，
  // 避免 indexOf 对"值==关键词"（如 password:"[SECRET_553]"）定位到前缀关键词、值泄露
  // 键为子串式（[a-z0-9_-]* 前后缀）：命中 accessSecret/accessKeyId/gitToken/clientSecret/syspw 等复合驼峰键
  ["secret", /"?[a-z0-9_-]*(?:passw(?:or)?d|passwd|pwd|pw|secret|token|api_?key|access_?key|access_?secret|auth_?key|secret_?key)[a-z0-9_-]*"?\s*[=:]\s*(\[\s*"[^\[\]]{6,}?\])/gid, null, 1],  // JSON 字符串数组值: "password": ["a","b"] → [SECRET_n]（内容须引号开头, 不再掩已有占位符→幂等）
  ["secret", /"?[a-z0-9_-]*(?:passw(?:or)?d|passwd|pwd|pw|secret|token|api_?key|access_?key|access_?secret|auth_?key|secret_?key)[a-z0-9_-]*"?\s*[=:]\s*["']?([^\s"'`,;(){}\[\]]{6,})["']?(?![\w.(])(?!\s*[=:])/gid, null, 1],
  ["idcard", /(?<!\d)(\d{17}[\dXx])(?!\d)/gd, idcardOk, 1],
  ["phone", /(?<!\d)1[3-9]\d{9}(?!\d)/g, null, 0],
  ["bankcard", /(?<!\d)\d{16,19}(?!\d)/g, luhnOk, 0],
  ["email", /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, null, 0],
  ["ipv4", /(?<![\d.])(?<![A-Za-z0-9]\/)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g, null, 0],
]

const SKIP_VALUES = new Set(["none", "null", "true", "false", "undefined", "changeme", "change-me", "todo"])

// ---- Session：一次掩码运行的共享状态 ----

class Session {
  taken: [number, number][] = []  // 已掩码区间
  mapping: Record<string, string> = {}  // 原值 -> [TOKEN]（仅存本地，绝不外发）
  counts: Record<string, number> = {}

  free(s: number, e: number): boolean {
    return !this.taken.some(([ts, te]) => s < te && ts < e)
  }

  take(s: number, e: number, cat: string, value: string): void {
    this.taken.push([s, e])
    if (!(value in this.mapping)) {
      let idx = 0
      for (const v of Object.values(this.mapping)) if (v.startsWith(`[${cat.toUpperCase()}_`)) idx++
      this.mapping[value] = `[${cat.toUpperCase()}_${idx + 1}]`
    }
    this.counts[cat] = (this.counts[cat] || 0) + 1
  }
}

function cLayer(text: string, sess: Session, enabled: Set<string>): void {
  for (const [cat, re, valid, grp] of CATS) {
    if (!enabled.has(cat)) continue
    for (const m of text.matchAll(re)) {
      const val = m[grp] as string | undefined
      if (val == null) continue
      if (valid && !valid(val)) continue
      if ([...val].every((c) => c === "*") || SKIP_VALUES.has(val.toLowerCase())) continue
      if (val.startsWith("${") || (val.startsWith("<") && val.endsWith(">"))) continue
      // grp=0: 整段匹配即值；grp>0: d flag 的 m.indices 取捕获组绝对位置
      // （旧 indexOf 对"值==关键词"会定位到前缀关键词，导致关键词被掩码、真值暴露）
      const s = grp === 0 ? m.index! : m.indices![grp][0]
      const e = grp === 0 ? s + val.length : m.indices![grp][1]
      if (sess.free(s, e)) sess.take(s, e, cat, val)
    }
  }
}

// ---- 外部扫描器增强层：betterleaks 优先、回退 gitleaks；Bun.which 检测，未安装自动跳过 ----

function scannerLayer(text: string, sess: Session): string {
  const exe = Bun.which("betterleaks") || Bun.which("gitleaks")
  if (!exe) return "未安装(可选: betterleaks 或 gitleaks)"
  const scanner = /betterleaks/i.test(exe) ? "betterleaks" : "gitleaks"
  const dir = mkdtempSync(join(tmpdir(), "sfilter_gl_"))
  try {
    writeFileSync(join(dir, "input.txt"), text, "utf8")
    const rep = join(dir, "rep.json")
    // ponytail: 同步 spawn 无超时；gitleaks 对小文本毫秒级返回，若遇大输入卡住再换 异步+Promise.race 超时
    // spawn 用 which 解析出的完整路径：裸名会让 Bun 每次做慢速 PATH 探测（实测 ~4s vs ~0.4s）
    // timeout=10s：外部 gitleaks 偶发卡顿（首启/杀软/网络检查）时按 skip 处理，绝不阻塞掩码管线
    const r = Bun.spawnSync(
      [exe, "dir", dir, "--no-banner", "--exit-code", "0",
        "--report-path", rep, "--report-format", "json"],
      { stdout: "pipe", stderr: "pipe", timeout: 10000 },
    )
    if (r.exitCode === null) return "跳过(超时)"  // 超时被 kill，按未安装同语义处理
    let leaks: any[] = []
    if (existsSync(rep) && readFileSync(rep, "utf8").trim()) {
      try { leaks = JSON.parse(readFileSync(rep, "utf8")) } catch { leaks = [] }
    }
    let taken = 0
    for (const leak of leaks) {
      const val = (leak.Secret || leak.secret || leak.Match || leak.match || "").toString().trim()
      if (val) {
        const idx = text.indexOf(val)
        if (idx >= 0 && sess.free(idx, idx + val.length)) {
          sess.take(idx, idx + val.length, "secret", val)
          taken++
        }
      }
    }
    return leaks.length ? `${scanner}: 补掩 ${taken}/${leaks.length}` : `${scanner}: 无命中`
  } catch (e) {
    return `跳过(${(e && (e as any).constructor && (e as any).constructor.name) || "Error"})`
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// ---- 主体 ----

function maskText(text: string, enabled: Set<string>, useGitleaks: boolean): {
  out: string
  sess: Session
  note: string
} {
  const sess = new Session()
  cLayer(text, sess, enabled)
  const note = useGitleaks ? scannerLayer(text, sess) : "禁用"
  let out = text
  const segs = sess.taken
    .map(([s, e]) => [s, e, sess.mapping[text.slice(s, e)]] as [number, number, string])
    .sort((a, b) => b[0] - a[0])
  for (const [s, e, tok] of segs) out = out.slice(0, s) + tok + out.slice(e)
  return { out, sess, note }
}

// ---- 映射落盘（格式与 py/mjs 完全一致，且即使空映射也允许被读取方兼容）----

const MAP_PREFIX = "sensitive_filter_map_"

// 清理策略 = 容量约束（保留最新 N 个，默认 5000，SF_MAP_KEEP 可调），不再按 24h 年龄删。
// 理由：映射寿命必须 ≥ 模型上下文寿命 —— 会话超 24h 或恢复旧会话时，模型上下文里的编号
// 仍需可还原；按龄删除会让旧编号静默失联（占位符字面量落盘）。
function sweepMaps(): void {
  const dir = mapDir()
  let names: string[] = []
  try { names = readdirSync(dir) } catch { return }
  const files: { p: string; m: number }[] = []
  for (const name of names) {
    if (!name.startsWith(MAP_PREFIX) || !name.endsWith(".json")) continue
    const p = join(dir, name)
    try { files.push({ p, m: statSync(p).mtimeMs }) } catch { /* 坏文件跳过 */ }
  }
  const keep = Math.max(1, Number(process.env.SF_MAP_KEEP || 5000) || 5000)
  if (files.length <= keep) return
  files.sort((a, b) => b.m - a.m)  // 新→旧，超出部分从最旧删
  for (const f of files.slice(keep)) {
    try { unlinkSync(f.p) } catch { /* 坏文件跳过 */ }
  }
}

function saveMap(mapping: Record<string, string>, maskedText: string): string {
  const digest = createHash("sha256").update(maskedText, "utf8").digest("hex")
  const p = join(mapDir(), `${MAP_PREFIX}${digest.slice(0, 8)}.json`)
  const bidir: Record<string, string> = { ...mapping }
  for (const [k, v] of Object.entries(mapping)) bidir[v] = k
  writeFileSync(p, JSON.stringify({ source_sha256: digest, tokens: bidir }), "utf8")
  sweepMaps()  // 写后清理：保证目录内文件数不超过 SF_MAP_KEEP
  return p
}

// ---- 类别开关：SF_ONLY 优先于 SF_SKIP（沿用 CLI 语义）----

function enabledSet(): Set<string> {
  const allCats = new Set(CATS.map((c) => c[0]))
  const only = process.env.SF_ONLY
  if (only) {
    return new Set(only.split(",").map((s) => s.trim()).filter((c) => allCats.has(c)))
  }
  const skip = new Set((process.env.SF_SKIP || "").split(",").map((s) => s.trim()))
  return new Set([...allCats].filter((c) => !skip.has(c)))
}

// 按 sess.taken spans 重建原文并分配全局唯一编号；不用字符串 replace（会误伤文本里已有的旧字面 token）
// boundaries：各 slot 在 original 中的区间（拼接分隔符不在任何区间内）。可跨行的规则（PEM、JSON
// 数组值等）会把 slot 间分隔符整体吞进 span → 拆回时分段数错乱触发 fail-closed 误阻断。传
// boundaries 时把跨界 span 裁到各 slot 区间内：分隔符必然存活，各子区间作为独立值掩码/映射/还原
// （还原语义为子区间真值，不会还原出跨 slot 拼接值）。
function renumber(sess: Session, original: string, boundaries?: Array<[number, number]>): { out: string; mapping: Record<string, string> } {
  const { tok2val, val2tok, maxByCat: base } = scanMaps()
  const newMapping: Record<string, string> = {}
  const assigned: Record<string, string> = {}  // 本次批量内 同值同号：sess.taken 每个 span 一条记录，
  // 若逐个 span 分配编号，同一值出现 N 次会拿到 N 个只剩最后一个进映射的编号 → 模型看到的前 N-1 个编号无映射可还原
  const spans: Array<[number, number, string | undefined]> = sess.taken.flatMap(([s, e]) => {
    const oldTok = sess.mapping[original.slice(s, e)]
    if (!boundaries) return [[s, e, oldTok]] as Array<[number, number, string | undefined]>
    return boundaries
      .filter(([bs, be]) => bs < e && s < be)  // 与该 slot 区间相交的子区间（不含区间外的分隔符）
      .map(([bs, be]) => [Math.max(s, bs), Math.min(e, be), oldTok] as [number, number, string | undefined])
  })
  const segs = spans.map(([s, e, oldTok]) => {
    const val = original.slice(s, e)
    let newTok = assigned[val]
    if (!newTok) {
      // 跨批次复用：同值若已有映射编号则沿用（避免同值每请求换号，旧号随映射清理失联）
      const cand = val2tok.get(val)
      if (cand && tok2val.get(cand) === val) newTok = cand  // 反向一致才复用，防跨文件歧义
    }
    if (!newTok) {
      const mm = /^\[([A-Z][A-Z0-9]*)_(\d+)\]$/.exec(oldTok || "")  // 类别名可含数字（IPV4）
      newTok = oldTok
      if (mm) {
        const cat = mm[1]
        if (!(cat in base)) base[cat] = 0
        base[cat]++
        newTok = `[${cat}_${base[cat]}]`
      }
      if (newTok) assigned[val] = newTok
    }
    newMapping[val] = newTok
    return [s, e, newTok] as [number, number, string]
  }).sort((a, b) => b[0] - a[0])  // 倒序插入：从后往前 splice 不影响前面的偏移
  let out = original
  for (const [s, e, tok] of segs) out = out.slice(0, s) + tok + out.slice(e)
  return { out, mapping: newMapping }
}

// ---- 批量掩码：与旧版插件同款 拼装-掩码-拆回 语义（sep 可注入便于测试）----

function maskBatch(slots: Slot[], sep: string = makeSep()): void {
  if (!slots.length) return
  // sep 两端必须带换行：避免相邻 slot 内容粘成同一个词导致 \b 边界失效
  const glue = "\n" + sep + "\n"
  const parts = slots.map((s) => s.get())
  const joined = parts.join(glue)
  // 各 slot 在 joined 中的区间（分隔符不在其中）——可跨行规则（PEM/JSON 数组值）误吞分隔符时供 renumber 裁界
  const boundaries: Array<[number, number]> = []
  let off = 0
  for (const p of parts) { boundaries.push([off, off + p.length]); off += p.length + glue.length }
  const { sess } = maskText(joined, enabledSet(), true)
  // 插件层重编号到全局唯一（修 system/messages 同号冲突）；maskText 的 out 丢弃，
  // 由 renumber 从原文 + taken spans 重建（避免字符串 replace 误伤旧字面 token）
  const { out, mapping } = renumber(sess, joined, boundaries)
  if (Object.keys(mapping).length) saveMap(mapping, out)
  const pieces = out.split(glue)
  if (pieces.length !== slots.length) {
    throw new Error(`[sensitive-filter] 分段数不匹配 ${pieces.length}/${slots.length}，阻断发送(fail-closed)`)
  }
  slots.forEach((s, i) => s.set(pieces[i]))
}

// ================================================================
// 插件
// ================================================================

const SensitiveFilterPlugin: Plugin = async ({ client }) => {
  if (process.env.SF_OFF === "1") return {}

  return {
    "experimental.chat.messages.transform": async (_input, output) => {
      const slots: Slot[] = []
      for (const m of output.messages) for (const p of m.parts) collectPartSlots(p, slots)
      maskBatch(slots)
    },
    "experimental.chat.system.transform": async (_input, output) => {
      const slots: Slot[] = []
      output.system.forEach((s, i) => {
        if (typeof s === "string") {
          slots.push({ get: () => output.system[i], set: (v) => { output.system[i] = v } })
        }
      })
      maskBatch(slots)
      output.system.push(SF_INSTRUCTION)
    },
    "tool.execute.before": async (_input, output) => {
      deepRehydrate(output.args) // 模型回显占位符 → 执行前还原真值
    },
    "experimental.text.complete": async (_input, output) => {
      if (typeof output.text === "string") output.text = rehydrate(output.text)
    },
  }
}

export default SensitiveFilterPlugin

// 测试接口：挂函数属性不影响 opencode 的模块级导出校验（Object.values(mod) 只见 default 一个函数）
Object.assign(SensitiveFilterPlugin, {
  CATS,
  collectPartSlots,
  tokenLookup,
  rehydrate,
  deepRehydrate,
  maskText,
  saveMap,
  maskBatch,
  makeSep,
  renumber,
})