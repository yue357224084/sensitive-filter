#!/usr/bin/env node
// sensitive-filter: 发给大模型前的本地敏感信息过滤（方案 A+C）。
// Node.js 零依赖等价版（与 sensitive_filter.py 行为/CLI/退出码/映射格式全对齐）。
//
// 用法:
//   node sensitive-filter.mjs [文件...]     # 脱敏文本 -> stdout, 报告 -> stderr
//   cat 文件 | node sensitive-filter.mjs
//   node sensitive-filter.mjs --restore 文件 --map 映射.json
//   node sensitive-filter.mjs --selftest
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync,
  statSync, unlinkSync, writeFileSync,
} from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

// ---------------------------------------------------------------- .env 注入（脚本同目录；.env 值优先于系统环境变量）
// 支持格式：KEY=VALUE / export KEY=VALUE / # 注释 / 引号包裹值（去引号）。.env 不存在则静默跳过。
function loadDotEnv() {
  let txt = ""
  try { txt = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), ".env"), "utf8") } catch { return }
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

// ---------------------------------------------------------------- 校验算法

const CN_ID_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const CN_ID_MAP = "10X98765432"

function idcardOk(s) {
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

function luhnOk(s) {
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

// ---------------------------------------------------------------- C 层规则
// 顺序即优先级：先命中的 span 占位，后续类别跳过重叠区域。
// 元组: [类别名, 正则, 校验函数|null, 要掩码的 group 序号]
const CATS = [
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
  // 避免 indexOf 对"值==关键词"（如 password:"[SECRET_555]"）定位到前缀关键词、值泄露
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

// ---------------------------------------------------------------- Session

class Session {
  constructor() {
    this.taken = []      // [[start, end]] 已掩码区间
    this.mapping = {}    // 原值 -> [TOKEN]（仅存本地，绝不外发）
    this.counts = {}
  }

  free(s, e) {
    return !this.taken.some(([ts, te]) => s < te && ts < e)
  }

  take(s, e, cat, value) {
    this.taken.push([s, e])
    if (!(value in this.mapping)) {
      let idx = 0
      for (const v of Object.values(this.mapping)) if (v.startsWith(`[${cat.toUpperCase()}_`)) idx++
      this.mapping[value] = `[${cat.toUpperCase()}_${idx + 1}]`
    }
    this.counts[cat] = (this.counts[cat] || 0) + 1
  }
}

function cLayer(text, sess, enabled) {
  for (const [cat, re, valid, grp] of CATS) {
    if (!enabled.has(cat)) continue
    for (const m of text.matchAll(re)) {
      const val = m[grp]
      if (val == null) continue
      if (valid && !valid(val)) continue
      if ([...val].every((c) => c === "*") || SKIP_VALUES.has(val.toLowerCase())) continue
      if (val.startsWith("${") || (val.startsWith("<") && val.endsWith(">"))) continue
      // grp=0: 整段匹配即值；grp>0: d flag 的 m.indices 取捕获组绝对位置
      // （旧 indexOf 对"值==关键词"会定位到前缀关键词，导致关键词被掩码、真值暴露）
      const s = grp === 0 ? m.index : m.indices[grp][0]
      const e = grp === 0 ? s + val.length : m.indices[grp][1]
      if (sess.free(s, e)) sess.take(s, e, cat, val)
    }
  }
}

// ---------------------------------------------------------------- 外部扫描器增强层（betterleaks 优先，回退 gitleaks）

function findScanner() {
  const names = ["betterleaks", "gitleaks"]  // betterleaks 优先
  const exts = process.platform === "win32"
    ? (process.env.PATHEXT || ".COM;.EXE;.BAT;.CMD").split(";")
    : [""]
  const cands = []
  for (const name of names) {
    for (const dir of (process.env.PATH || "").split(path.delimiter)) {
      if (!dir) continue
      for (const ext of exts) cands.push(path.join(dir, name + ext))
    }
    // winget 便携安装兜底路径(shell PATH 未刷新时生效)
    if (process.env.LOCALAPPDATA) {
      cands.push(path.join(process.env.LOCALAPPDATA, "Microsoft", "WinGet", "Links", name + ".exe"))
    }
  }
  return cands.find((c) => existsSync(c)) || null
}

function scannerLayer(text, sess) {
  const exe = findScanner()
  if (!exe) return "未安装(可选: betterleaks 或 gitleaks)"
  const scanner = /betterleaks/i.test(exe) ? "betterleaks" : "gitleaks"
  const dir = mkdtempSync(path.join(os.tmpdir(), "sfilter_gl_"))
  try {
    writeFileSync(path.join(dir, "input.txt"), text, "utf8")
    const rep = path.join(dir, "rep.json")
    const r = spawnSync(
      exe,
      ["dir", dir, "--no-banner", "--exit-code", "0",
        "--report-path", rep, "--report-format", "json"],
      { shell: false, encoding: "utf8", timeout: 120000, maxBuffer: 64 * 1024 * 1024 },
    )
    let leaks = []
    if (r.error) throw r.error
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
    return `跳过(${(e && e.constructor && e.constructor.name) || "Error"})`
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// ---------------------------------------------------------------- 主体

function maskText(text, enabled, useGitleaks) {
  const sess = new Session()
  cLayer(text, sess, enabled)
  const gitleaksNote = useGitleaks ? scannerLayer(text, sess) : "禁用"
  let out = text
  const segs = sess.taken
    .map(([s, e]) => [s, e, sess.mapping[text.slice(s, e)]])
    .sort((a, b) => b[0] - a[0])
  for (const [s, e, tok] of segs) out = out.slice(0, s) + tok + out.slice(e)
  return { out, sess, gitleaksNote }
}

const MAP_PREFIX = "sensitive_filter_map_"

function readLocal(p, what) {
  try {
    return readFileSync(p, "utf8")
  } catch (e) {
    if (e && e.code === "ENOENT") {
      process.stderr.write(`[错误] ${what}不存在: ${p} (当前目录: ${process.cwd()})\n`)
      process.exit(2)
    }
    throw e
  }
}

// 清理策略 = 容量约束（保留最新 N 个，默认 5000，SF_MAP_KEEP 可调），不再按 24h 年龄删。
// 理由：映射寿命必须 ≥ 模型上下文寿命 —— 按龄删会让旧编号静默失联（占位符字面量落盘）。
function sweepMaps() {
  const dir = os.tmpdir()
  let names = []
  try { names = readdirSync(dir) } catch { return }
  const files = []
  for (const name of names) {
    if (!name.startsWith(MAP_PREFIX) || !name.endsWith(".json")) continue
    const p = path.join(dir, name)
    try { files.push({ p, m: statSync(p).mtimeMs }) } catch { /* 坏文件跳过 */ }
  }
  const keep = Math.max(1, Number(process.env.SF_MAP_KEEP || 5000) || 5000)
  if (files.length <= keep) return
  files.sort((a, b) => b.m - a.m)  // 新→旧，超出部分从最旧删
  for (const f of files.slice(keep)) {
    try { unlinkSync(f.p) } catch { /* 坏文件跳过 */ }
  }
}

function saveMap(mapping, maskedText, mapOut) {
  const digest = createHash("sha256").update(maskedText, "utf8").digest("hex")
  let p
  if (mapOut) {
    p = path.resolve(mapOut)
    let isDir = false
    try { isDir = statSync(p).isDirectory() } catch { /* 不存在 */ }
    if (isDir || (!path.extname(p) && !existsSync(p))) {
      p = path.join(p, `${MAP_PREFIX}${digest.slice(0, 8)}.json`)
    }
  } else {
    p = path.join(os.tmpdir(), `${MAP_PREFIX}${digest.slice(0, 8)}.json`)
  }
  mkdirSync(path.dirname(p), { recursive: true })
  const bidir = { ...mapping }
  for (const [k, v] of Object.entries(mapping)) bidir[v] = k
  writeFileSync(p, JSON.stringify({ source_sha256: digest, tokens: bidir }), "utf8")
  try { chmodSync(p, 0o600) } catch { /* 内容含明文真值；默认目录是 tmpdir，Linux 上 /tmp 全局可读。不支持则忽略 */ }
  if (!mapOut) sweepMaps()  // 写后清理：保证目录内文件数不超过 SF_MAP_KEEP
  return p
}

function doRestore(text, mapPath, force = false) {
  const data = JSON.parse(readLocal(mapPath, "映射文件"))
  const digest = createHash("sha256").update(text, "utf8").digest("hex")
  if (digest !== data.source_sha256) {
    if (!force) {
      process.stderr.write(
        `[错误] 映射文件与待还原内容不匹配 (映射 ${String(data.source_sha256 || "?").slice(0, 8)}, ` +
        `内容 ${digest.slice(0, 8)})；内容若已被修改过且确认映射来源无误, 加 --force\n`)
      process.exit(1)
    }
    process.stderr.write("[警告] 内容与映射不配对, 已按 --force 跳过校验\n")
  }
  const entries = Object.entries(data.tokens)
    .filter(([, tok]) => /^\[(?:SECRET|IDCARD|PHONE|BANKCARD|EMAIL|IPV4)_\d+\]$/.test(tok))
    .sort((a, b) => b[1].length - a[1].length)
  let out = text
  for (const [val, tok] of entries) out = out.split(tok).join(val)
  return out
}

// ---------------------------------------------------------------- CLI

function pyDict(o) {
  return "{" + Object.entries(o).map(([k, v]) => `'${k}': ${v}`).join(", ") + "}"
}

function parseArgs(argv) {
  const args = { inputs: [], skip: "", only: "", noGitleaks: false, mapOut: null, restore: null, mapFile: null, force: false, selftest: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === "-h" || a === "--help") { args.help = true; continue }
    const eq = a.startsWith("--") ? a.indexOf("=") : -1
    const name = eq >= 0 ? a.slice(0, eq) : a
    const inline = eq >= 0 ? a.slice(eq + 1) : null
    const need = () => (inline != null ? inline : (i + 1 < argv.length ? argv[++i] : ""))
    if (name === "--skip") args.skip = need()
    else if (name === "--only") args.only = need()
    else if (name === "--map-out") args.mapOut = need()
    else if (name === "--restore") args.restore = need()
    else if (name === "--map") args.mapFile = need()
    else if (name === "--no-gitleaks") args.noGitleaks = true
    else if (name === "--force") args.force = true
    else if (name === "--selftest") args.selftest = true
    else if (a.startsWith("--")) {
      console.error(`[警告] 未知参数已忽略: ${a}`) // 曾把 --foo 当输入文件名读，报"文件不存在"
    } else args.inputs.push(a)
  }
  return args
}

function usage() {
  return "用法: node sensitive-filter.mjs [文件...] | 管道 | --selftest | --restore"
}

// ---------------------------------------------------------------- 自检（与 py 版 11 项对齐）
// 全部假样本：RFC5737 IP / example.* 邮箱 / 算法合成的身份证与银行卡校验位。
// 占位符不写字面量，运行时拼接，避免与任何占位符文本混淆。

function runSelfTest() {
  const T = (c, n) => "[" + c + "_" + n + "]"
  const body17 = "11010519491231002"
  let sum = 0
  for (let i = 0; i < 17; i++) sum += parseInt(body17[i], 10) * CN_ID_W[i]
  const validId = body17 + CN_ID_MAP[sum % 11]
  let card = "6222021234567890"
  for (let d = 0; d < 10; d++) {
    if (luhnOk("622202123456789" + d)) { card = "622202123456789" + d; break }
  }
  const fakePhone = "1" + "39" + "0000" + "0001"
  const fakeMail = "user" + "@" + "example" + ".com"
  const fakeIp = "192" + ".0" + ".2" + ".1"
  const skKey = "sk-" + "AbCdEf0123456789AbCdEf0123456789"
  const jwt = "eyJ" + "abc".repeat(5) + "." + "def".repeat(5) + "." + "ghi".repeat(5)
  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\n" +
    "MIIBOwIBAAJBAK fake fake fake fake fake fake fake fake\n" +
    "-----END RSA PRIVATE KEY-----"
  const pwVal = "S3cret!" + "x9"
  const sample =
    `contact [${fakePhone}] id=${validId} card=${card}\n` +
    `sk = ${skKey}\n` +
    `password: "${pwVal}"\n` +
    `password: "password"\n` +  // 🔴 回归：值==关键词，须掩码值而非关键词
    `token: ${jwt}\n` +
    `mail ${fakeMail} from ${fakeIp}\n` +
    pem + "\n" +
    "plain 12345678901234567 not-a-card\n" // Luhn 不通过,必须保留
  const { out, sess } = maskText(sample, new Set(CATS.map((c) => c[0])), false)
  const mapFile = saveMap(sess.mapping, out, null)
  const has = (v, cat) => (sess.mapping[v] || "").startsWith("[" + cat + "_")
  const checks = [
    ["phone 掩码", !out.includes(fakePhone) && has(fakePhone, "PHONE")],
    ["idcard 掩码", !out.includes(validId) && has(validId, "IDCARD")],
    ["bankcard 掩码", !out.includes(card) && has(card, "BANKCARD")],
    ["sk key 掩码", !out.includes(skKey) && has(skKey, "SECRET")],
    ["password 赋值掩码", !out.includes(pwVal) && has(pwVal, "SECRET")],
    ["pem 掩码", !out.includes(pem) && has(pem, "SECRET")],
    ["email 掩码", !out.includes(fakeMail) && has(fakeMail, "EMAIL")],
    ["ipv4 掩码", !out.includes(fakeIp) && has(fakeIp, "IPV4")],
    ["luhn 不通过保留", out.includes("12345678901234567")],
    ["idcard/bankcard 不重复掩码", (out.match(/\[IDCARD_/g) || []).length === 1 && (out.match(/\[BANKCARD_/g) || []).length === 1],
    ["🔴 值==关键词: 值掩码/关键词保留", !out.includes('"password"') && out.includes("password:") && !/\[SECRET_\d+\]:/.test(out) && has("password", "SECRET")],
    ["还原闭环", doRestore(out, mapFile) === sample],
  ]
  let ok = true
  for (const [name, passed] of checks) {
    console.log(`  ${passed ? "PASS" : "FAIL"}  ${name}`)
    ok = ok && passed
  }
  console.log(`  计数: ${pyDict(sess.counts)}`)
  return ok ? 0 : 1
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) { console.log(usage()); return 0 }
  if (args.selftest) return runSelfTest()
  if (args.restore) {
    if (!args.mapFile) {
      console.error("[错误] --restore 需要 --map 指定映射文件")
      return 2
    }
    const src = readLocal(args.restore, "待还原文件")
    process.stdout.write(doRestore(src, args.mapFile, args.force))
    return 0
  }

  const allCats = new Set(CATS.map((c) => c[0]))
  let enabled
  if (args.only) {
    enabled = new Set(args.only.split(",").map((s) => s.trim()).filter((c) => allCats.has(c)))
  } else {
    const skip = new Set(args.skip.split(",").map((s) => s.trim()))
    enabled = new Set([...allCats].filter((c) => !skip.has(c)))
  }

  let text
  if (args.inputs.length) {
    text = args.inputs.map((p) => readLocal(p, "输入文件")).join("\n")
  } else if (process.stdin.isTTY) {
    console.error(usage())
    return 2
  } else {
    text = readFileSync(0, "utf8")
  }
  if (!text) return 0

  const { out, sess, gitleaksNote } = maskText(text, enabled, !args.noGitleaks)
  process.stdout.write(out)
  console.error(`\n[命中] ${Object.keys(sess.counts).length ? pyDict(sess.counts) : "未命中"}  [gitleaks] ${gitleaksNote}`)
  if (Object.keys(sess.mapping).length) {
    const mp = saveMap(sess.mapping, out, args.mapOut)
    console.error(`[映射] ${mp}  (还原: --restore 输出文件 --map ${mp})`)
  }
  return 0
}

// ---------------------------------------------------------------- 导出（供 codex/proxy.mjs 复用；不改变直接执行行为）

function enabledSet() {
  const allCats = new Set(CATS.map((c) => c[0]))
  const only = process.env.SF_ONLY
  if (only) {
    return new Set(only.split(",").map((s) => s.trim()).filter((c) => allCats.has(c)))
  }
  const skip = new Set((process.env.SF_SKIP || "").split(",").map((s) => s.trim()))
  return new Set([...allCats].filter((c) => !skip.has(c)))
}

export { CATS, maskText, saveMap, enabledSet }

// 直接执行时跑 CLI；被 import 时不执行（proxy 以模块方式复用核心函数）。
import { pathToFileURL } from "node:url"
const _normUrl = (u) => (process.platform === "win32" ? u.toLowerCase() : u)
if (
  process.argv[1] &&
  _normUrl(import.meta.url) === _normUrl(pathToFileURL(path.resolve(process.argv[1])).href)
) {
  process.exit(main())
}