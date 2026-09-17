#!/usr/bin/env bun
// codex/proxy.mjs — OpenAI Codex CLI（Responses API）前的本地脱敏反向代理。
// 出站：请求体掩码 + instructions 注入敏感过滤指令；入站：SSE/JSON 响应还原。
// 复用 sensitive-filter.mjs 核心（maskText/CATS/saveMap/enabledSet），gitleaks 层禁用。
//
// 用法: bun codex/proxy.mjs
// 环境变量:
//   SF_PROXY_PORT 监听端口（默认 3141）   SF_PROXY_HOST 监听地址（默认全部接口；部署时设为目标内网 IP）
//   SF_UPSTREAM   上游 base_url（默认 https://api.openai.com/v1）
//   SF_MAP_DIR    映射目录（默认 os.tmpdir()，与 CLI --restore 双向互操作）
//   SF_OFF=1      代理直接退出        SF_ONLY / SF_SKIP 沿用 enabledSet() 语义
import { readdirSync, readFileSync, statSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { maskText, CATS, saveMap, enabledSet } from "../sensitive-filter.mjs"

// ---------------------------------------------------------------- .env 注入（脚本同目录；.env 值优先于系统环境变量）
// 必须在所有 SF_* 读取（含下方 SF_OFF 顶层检查与 enabledSet()）之前执行。
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

if (process.env.SF_OFF === "1") {
  console.error("[SF-proxy] SF_OFF=1，代理不启动")
  process.exit(0)
}

const MAP_PREFIX = "sensitive_filter_map_"
const SF_INSTRUCTION =
  "[sensitive-filter] 对话里的 [SECRET_n]/[IDCARD_n]/[PHONE_n]/[BANKCARD_n]/[EMAIL_n]/[IPV4_n] 是真实值的本地脱敏占位符：请原样保留引用、不要改写格式、不要编造原值；在 bash/写文件等工具参数里引用时也保持原样（工具执行前会自动还原为真值）。"

const CAT_RE = /^\[([A-Z][A-Z0-9]*)_(\d+)\]$/
const TOKEN_STRIP = /\[(?:SECRET|IDCARD|PHONE|BANKCARD|EMAIL|IPV4)_\d+\]/g
// 可能是不完整占位符的前缀（尾缓冲延迟释放用）：如 "[SECRET" "[SECRET_" "[SECRET_" 加数字
const PARTIAL = /\[(?:SECRET|IDCARD|PHONE|BANKCARD|EMAIL|IPV4)(?:_\d*)?$/
const MAX_TAIL = 32

function mapDir() {
  const d = process.env.SF_MAP_DIR || os.tmpdir()
  return d
}

// ---- 映射状态：进程内共享（确定性编号 + 还原查找），启动与每次请求前从磁盘装载 ----

const g = { rev: new Map(), fwd: new Map(), maxIdx: {} } // rev: 原文→占位符; fwd: 占位符→原文
let gSig = null

function dirSig() {
  let sig = ""
  try {
    const names = readdirSync(mapDir()).filter((n) => n.startsWith(MAP_PREFIX) && n.endsWith(".json")).sort()
    sig = `${names.length}:`
    for (const n of names) {
      try { sig += `${n}:${statSync(path.join(mapDir(), n)).mtimeMs}` } catch { sig += `${n}:x` }
    }
  } catch { sig = "0:" }
  return sig
}

function loadMaps() {
  const dir = mapDir()
  const files = []
  try {
    for (const n of readdirSync(dir)) {
      if (!n.startsWith(MAP_PREFIX) || !n.endsWith(".json")) continue
      try { files.push({ n, m: statSync(path.join(dir, n)).mtimeMs }) } catch {}
    }
  } catch { /* 目录不可读：空映射 */ }
  files.sort((a, b) => b.m - a.m) // 新者优先，同 token 冲突新值胜出（与插件 tokenLookup 一致）
  g.rev.clear(); g.fwd.clear(); g.maxIdx = {}
  for (const f of files) {
    let data
    try { data = JSON.parse(readFileSync(path.join(dir, f.n), "utf8")) } catch { continue }
    const tokens = data && typeof data.tokens === "object" ? data.tokens : {}
    for (const [k, v] of Object.entries(tokens)) {
      if (typeof v !== "string") continue
      if (!g.rev.has(v)) g.rev.set(v, k)
      if (CAT_RE.test(k) && !g.fwd.has(k)) g.fwd.set(k, v)
      for (const s of [k, v]) {
        const mm = CAT_RE.exec(s)
        if (mm) g.maxIdx[mm[1]] = Math.max(g.maxIdx[mm[1]] || 0, Number(mm[2]))
      }
    }
  }
  gSig = dirSig()
}

// 掩码后重编号：已有映射同值同号（确定性），新值按类别递增全局唯一号
function renumberGlobal(sess, original) {
  const newMapping = {}
  for (const [val, tok] of Object.entries(sess.mapping)) {
    const mm = CAT_RE.exec(tok)
    let nt = g.rev.get(val)
    if (!nt && mm) {
      const cat = mm[1]
      g.maxIdx[cat] = (g.maxIdx[cat] || 0) + 1
      nt = `[${cat}_${g.maxIdx[cat]}]`
      g.rev.set(val, nt)
      g.fwd.set(nt, val)
    }
    if (nt) newMapping[val] = nt
  }
  if (!Object.keys(newMapping).length) return { out: original, newMapping }
  const segs = sess.taken
    .map(([s, e]) => [s, e, newMapping[original.slice(s, e)]])
    .filter(([, , t]) => t)
    .sort((a, b) => b[0] - a[0])
  let out = original
  for (const [s, e, t] of segs) out = out.slice(0, s) + t + out.slice(e)
  return { out, newMapping }
}

const enabled = enabledSet()

// ---- 出站掩码 ----

function maskSlot(text, enabled, masked) {
  if (typeof text !== "string" || !text) return text
  const { out, sess } = maskText(text, enabled, false) // gitleaks 层禁用
  if (!Object.keys(sess.mapping).length) return out
  const { out: o, newMapping } = renumberGlobal(sess, text)
  saveMap(newMapping, o, mapDir()) // 沿用既有 map 格式（bidir + source_sha256），CLI --restore 可互操作
  masked.n += Object.keys(newMapping).length
  return o
}

// 掩码 Responses API 结构：顶层 instructions（字符串）与 input（字符串或 items 数组）。
// item.content 可能是 string 或 [{type:"input_text"|"output_text"|"text", text:...}]。
function maskRequestBody(body) {
  const masked = { n: 0 }
  const mask = (t) => maskSlot(t, enabled, masked)
  if (typeof body.instructions === "string" && body.instructions.trim()) {
    body.instructions = mask(body.instructions) + "\n\n" + SF_INSTRUCTION
  }
  if (typeof body.input === "string") {
    body.input = mask(body.input)
  } else if (Array.isArray(body.input)) {
    for (let i = 0; i < body.input.length; i++) {
      const it = body.input[i]
      if (typeof it === "string") { body.input[i] = mask(it); continue }
      if (it && typeof it === "object") {
        if (typeof it.content === "string") it.content = mask(it.content)
        else if (Array.isArray(it.content)) {
          for (const c of it.content) if (c && typeof c.text === "string") c.text = mask(c.text)
        } else if (typeof it.text === "string") it.text = mask(it.text)
      }
    }
  }
  return masked.n
}

// ---- 入站还原 ----

function restoreText(s, counts) {
  if (!s.includes("[")) return s
  return s.replace(TOKEN_STRIP, (t) => {
    const v = g.fwd.get(t)
    if (v != null) { counts.restore++; return v }
    return t // 未在映射中的占位符原样保留
  })
}

function deepRestore(v, counts) {
  if (typeof v === "string") return restoreText(v, counts)
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) v[i] = deepRestore(v[i], counts); return v }
  if (v && typeof v === "object") { for (const k of Object.keys(v)) v[k] = deepRestore(v[k], counts); return v }
  return v
}

// 占位符可能跨 SSE chunk / 跨 event 拆分：尾缓冲只对"可能是不完整占位符"的前缀延迟释放，
// 其余字节立即透传；同时回退处理被拆分的多字节 UTF-8 字符。保证不丢字节、不重复。
function splitTail(buf) {
  let hold = 0
  const s = buf.toString("utf8") // 扫描定位 '['（尾部可能含半个多字节字符，仅用于定位）
  const start = Math.max(0, s.length - MAX_TAIL)
  const li = s.lastIndexOf("[")
  if (li >= start && !s.includes("]", li)) {
    const tail = s.slice(li)
    if (PARTIAL.test(tail)) hold = s.length - li // 占位符前缀纯 ASCII：字符数==字节数
  }
  let i = buf.length - 1
  let cont = 0
  while (i >= 0 && (buf[i] & 0x80) !== 0) { cont++; i-- }
  if (cont > 0) {
    let need = 4
    if (i >= 0) {
      const b = buf[i]
      need = b < 0xE0 ? 2 : b < 0xF0 ? 3 : 4
    }
    hold = Math.max(hold, cont < need ? buf.length - i : cont)
  }
  const cut = Math.max(0, buf.length - Math.min(hold, MAX_TAIL))
  return { safe: buf.subarray(0, cut), tail: buf.subarray(cut) }
}

// 入站 SSE：按流还原 data: 行内文本（event 结构不动）；流处理失败 → 原样透传剩余流
async function* sseRestoreStream(body, counts) {
  const reader = body.getReader()
  let tail = Buffer.alloc(0)
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      const buf = Buffer.concat([tail, Buffer.isBuffer(value) ? value : Buffer.from(value)])
      const { safe, tail: t } = splitTail(buf)
      tail = t
      if (safe.length) yield restoreText(safe.toString("utf8"), counts)
    }
  } catch (e) {
    console.error(`[SF-proxy] 入站 SSE 处理失败，透传剩余流: ${e && (e.message || e)}`)
    if (tail.length) yield tail.toString("utf8")
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      yield value
    }
    return
  }
  if (tail.length) yield restoreText(tail.toString("utf8"), counts) // 流结束：冲刷尾缓冲
}

// ---- 转发与装配 ----

function failClosed(status, msg, e) {
  console.error(`[SF-proxy] ${msg}: ${e && (e.message || e)}`)
  return Response.json({ error: { type: "sensitive_filter_proxy", message: msg } }, { status })
}

async function handle(req) {
  if (dirSig() !== gSig) loadMaps() // 启动装载 + 请求前刷新（拾取 CLI/插件新写的映射）

  const url = new URL(req.url)
  const method = req.method
  const upstream = process.env.SF_UPSTREAM || "https://api.openai.com/v1"
  // Codex 的 base_url 指向本代理 /v1，请求路径形如 /v1/responses；
  // 去掉 /v1 前缀再拼上游 base（base 已含 /v1 时不再重复）。
  const p = url.pathname.startsWith("/v1") ? url.pathname.slice(3) : url.pathname
  const target = upstream.replace(/\/+$/, "") + (p || "/") + url.search

  const headers = new Headers()
  for (const [k, v] of req.headers) {
    if (k === "host" || k === "connection" || k === "content-length") continue
    headers.set(k, v) // Authorization 等全部透传；header 值绝不打印
  }

  let bodyOut = null
  let maskedCount = 0
  const ct = (req.headers.get("content-type") || "").toLowerCase()
  if ((method === "POST" || method === "PUT" || method === "PATCH") && ct.includes("json")) {
    const raw = await req.text()
    if (raw.trim()) {
      let parsed
      try { parsed = JSON.parse(raw) } catch (e) {
        return failClosed(400, "请求体 JSON 解析失败，未转发", e)
      }
      try {
        maskedCount = maskRequestBody(parsed)
      } catch (e) {
        return failClosed(502, "出站掩码失败，未转发", e) // fail-closed：掩码异常不发送
      }
      bodyOut = JSON.stringify(parsed)
    } else bodyOut = raw
  } else {
    bodyOut = await req.arrayBuffer() // 非 JSON（GET/二进制等）原样透传
  }

  let upRes
  try {
    upRes = await fetch(target, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : bodyOut,
    })
  } catch (e) {
    return failClosed(502, `上游连接失败: ${target.split("?")[0]}`, e)
  }

  const resHeaders = new Headers()
  for (const [k, v] of upRes.headers) {
    if (k === "content-length" || k === "content-encoding" || k === "connection") continue
    resHeaders.set(k, v)
  }
  const ctype = (upRes.headers.get("content-type") || "").toLowerCase()
  if (ctype.includes("text/event-stream")) {
    const counts = { restore: 0 }
    return new Response(sseRestoreStream(upRes.body, counts), { status: upRes.status, headers: resHeaders })
  }
  if (ctype.includes("json")) {
    const text = await upRes.text()
    let data
    try { data = JSON.parse(text) } catch { return new Response(text, { status: upRes.status, headers: resHeaders }) }
    const counts = { restore: 0 }
    data = deepRestore(data, counts)
    return Response.json(data, { status: upRes.status, headers: resHeaders })
  }
  return new Response(upRes.body, { status: upRes.status, headers: resHeaders })
}

function slog(method, pathname, status, extra) {
  const t = new Date().toISOString().slice(11, 19)
  console.error(`[SF-proxy] ${t} ${method} ${pathname} ${status}${extra ? " " + extra : ""}`)
}

const server = Bun.serve({
  hostname: process.env.SF_PROXY_HOST || "",
  port: Number(process.env.SF_PROXY_PORT || 3141),
  async fetch(req) {
    const method = req.method
    const pathname = new URL(req.url).pathname
    const t0 = Date.now()
    try {
      const res = await handle(req)
      slog(method, pathname, res.status, `(${Date.now() - t0}ms)`)
      return res
    } catch (e) {
      slog(method, pathname, 500)
      return failClosed(500, "代理内部错误", e)
    }
  },
})
console.error(`[SF-proxy] listening on http://${server.hostname}:${server.port} → ${process.env.SF_UPSTREAM || "https://api.openai.com/v1"}`)