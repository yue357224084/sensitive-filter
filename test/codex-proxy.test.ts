// bun test: bun test test/codex-proxy.test.ts
// 测 codex/proxy.mjs：起 mock 上游（同进程随机端口）+ 代理子进程指向 mock。
// 断言：出站掩码 + instructions 注入 / 确定性编号 / SSE 跨 chunk 拆分还原 / JSON 递归还原 / SF_SKIP。
// 注意：占位符一律运行时拼接（T 助手 / 字符串分段），源码不写字面真值，注释只用 [SECRET_n] 形（无数字）。
import { afterEach, describe, expect, test } from "bun:test"
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createHash } from "node:crypto"

const ROOT = join(import.meta.dir, "..")
const PROXY = join(ROOT, "codex", "proxy.mjs")
const HOST = "local" + "host" // 本机回环（源码不写字面 IP，防会话插件改写）

const enc = new TextEncoder()
const T = (c, n) => "[" + c + "_" + n + "]"

// 合成假样本（非真实 token 格式）
const SK_KEY = "sk-" + "AbCdEf" + "0123456789AbCdEf0123456789"
const REAL_PHONE = "1390000" + "0001"
const REAL_MAIL = "user" + "@" + "example" + ".com"
const SOCKS_VAL = "socks5://" + "user1:pass1" + "@" + HOST // 掩码后 socks5://[SECRET_n]@HOST
const SSN_VAL = "sk-" + "ZzYyXxWv" + "9876543210AbCdEf9876543210" // 还原测试里 [SECRET_n] 映射到的真值

// 写一个既有格式的映射文件（供还原测试预置 [SECRET_n]/[PHONE_n] 映射）
function writeMap(dir, pairs) {
  const tokens = {}
  for (const [tok, val] of pairs) { tokens[tok] = val; tokens[val] = tok }
  writeFileSync(join(dir, "sensitive_filter_map_test.json"), JSON.stringify({
    source_sha256: createHash("sha256").update("x").digest("hex"),
    tokens,
  }), "utf8")
}

let procs = []
let maps = []
function cleanup() {
  for (const p of procs) { try { p.kill() } catch {} }
  procs = []
  for (const d of maps) { try { rmSync(d, { recursive: true, force: true }) } catch {} }
  maps = []
}
afterEach(cleanup)

// 子进程干净 env：剥离继承来的 SF_*（本机 .env 会被 bun 自动加载进测试进程，防其泄漏到子进程）
function cleanEnv(extra) {
  const env = {}
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith("SF_")) env[k] = v
  return { ...env, ...extra }
}

// 临时树：复刻 sensitive-filter.mjs + codex/proxy.mjs（相对 import 成立），让代理读不到仓库根的 .env
function scaffoldProxy() {
  const d = mkdtempSync(join(tmpdir(), "sf_proxy_tree_"))
  maps.push(d)
  cpSync(join(ROOT, "sensitive-filter.mjs"), join(d, "sensitive-filter.mjs"))
  mkdirSync(join(d, "codex"))
  cpSync(PROXY, join(d, "codex", "proxy.mjs"))
  return d
}

// 起代理：临时树隔离环境；端口由内核分配（SF_PROXY_PORT=0）后从启动日志读回，避免"抢占-释放"端口竞态
function startProxy(upstreamUrl, env = {}) {
  const mapDir = mkdtempSync(join(tmpdir(), "sf_proxy_test_"))
  maps.push(mapDir)
  const tree = scaffoldProxy()
  const proc = Bun.spawn([process.execPath, join(tree, "codex", "proxy.mjs")], {
    cwd: tree,
    env: cleanEnv({ SF_PROXY_HOST: HOST, SF_PROXY_PORT: "0", SF_UPSTREAM: upstreamUrl, SF_MAP_DIR: mapDir, ...env }),
    stdout: "pipe",
    stderr: "pipe",
  })
  procs.push(proc)
  const errLog = []
  ;(async () => {
    const td = new TextDecoder()
    try { for await (const chunk of proc.stderr) errLog.push(td.decode(chunk)) } catch {}
  })()
  return (async () => {
    for (let i = 0; i < 120; i++) {
      if (proc.exitCode != null) throw new Error("proxy exited early: " + errLog.join(""))
      const m = /listening on (http:\/\/\S+)/.exec(errLog.join(""))
      if (m) return { url: m[1], mapDir, getErr: () => errLog.join("") }
      await Bun.sleep(50)
    }
    throw new Error("proxy not ready in time: " + errLog.join(""))
  })()
}

// mock 上游：记录收到的请求体，按场景返回 SSE / JSON
function startMock(onRequest) {
  const bodies = []
  const server = Bun.serve({
    hostname: HOST,
    port: 0,
    fetch: async (req) => {
      if (req.method === "GET") return new Response("ping")
      const raw = await req.text()
      bodies.push(raw)
      return onRequest(raw)
    },
  })
  return { url: `http://${HOST}:${server.port}`, bodies, stop: () => server.stop(true) }
}

describe("codex proxy", () => {
  test("(a) 出站掩码 + instructions 注入", async () => {
    const mock = startMock(() => Response.json({ ok: true }))
    const proxy = await startProxy(mock.url)

    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer abc123" },
      body: JSON.stringify({
        model: "gpt-5-codex",
        instructions: "你是助手，帮我处理下面内容。",
        input: [
          { role: "user", content: [{ type: "input_text", text: "key=" + SK_KEY + " phone=" + REAL_PHONE + " mail=" + REAL_MAIL }] },
          { role: "user", content: [{ type: "input_text", text: SOCKS_VAL }] },
        ],
      }),
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
    expect(mock.bodies.length).toBe(1)

    const got = JSON.parse(mock.bodies[0])
    expect(got.instructions).toContain("[sensitive-filter]") // 指令段已注入
    const allText = JSON.stringify(got)
    expect(allText).not.toContain(SK_KEY)
    expect(allText).not.toContain(REAL_PHONE)
    expect(allText).not.toContain(REAL_MAIL)
    expect(allText).not.toContain("user1:pass1")
    expect(allText).toContain(T("SECRET", 1))
    expect(allText).toContain(T("PHONE", 1))
    expect(allText).toContain(T("EMAIL", 1))
    expect(allText).toContain("socks5://" + T("SECRET", 2) + "@" + HOST) // userinfo 单独掩、host 保留
    mock.stop()
  })

  test("(b) 同值二次请求占位符编号不变（确定性）", async () => {
    const mock = startMock(() => Response.json({ ok: true }))
    const proxy = await startProxy(mock.url)

    const send = async (k) => {
      await fetch(proxy.url + "/v1/responses", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ input: [{ role: "user", content: [{ type: "input_text", text: k }] }] }),
      })
    }
    await send("auth=" + SK_KEY)
    const t1 = JSON.parse(mock.bodies[0]).input[0].content[0].text
    expect(t1).toContain(T("SECRET", 1))

    // 第二次：同值 + 一个新值（SK_KEY 加后缀成新 secret 串）
    await send("auth=" + SK_KEY + " other=" + SK_KEY + "X1")
    const t2 = JSON.parse(mock.bodies[1]).input[0].content[0].text
    expect(t2).toContain(T("SECRET", 1)) // 同值同号
    expect(t2).toContain(T("SECRET", 2)) // 新值递增编号
    expect(t2).not.toContain(SK_KEY)
    mock.stop()
  })

  test("(c) SSE 流占位符跨 chunk 拆分还原、不丢字节（拼全响应比对）", async () => {
    const mock = startMock(() => {
      const sse = new ReadableStream({
        start(c) {
          c.enqueue(enc.encode("data: {\"text\":\"key is " + T("SECRET", 1))) // 断在占位符中间
          c.enqueue(enc.encode("1]\"}\n\n" + "data: {\"text\":\"done\"}\n\n"))
          c.close()
        },
      })
      return new Response(sse, { status: 200, headers: { "content-type": "text/event-stream" } })
    })
    const proxy = await startProxy(mock.url)
    writeMap(proxy.mapDir, [[T("SECRET", 1), SSN_VAL]])

    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: "hi" }),
    })
    const out = await res.text()
    expect(out).toContain(SSN_VAL) // 占位符被还原为真值
    expect(out).not.toContain(T("SECRET", 1)) // 占位符不再出现
    const expected = "data: {\"text\":\"key is " + SSN_VAL + "1]\"}\n\n" + "data: {\"text\":\"done\"}\n\n"
    expect(out).toBe(expected) // 无丢字节/重复：逐字节拼全比对
    mock.stop()
  })

  test("(d) 普通 JSON 响应递归还原", async () => {
    const mock = startMock(() =>
      Response.json({
        output: [{ content: [{ type: "output_text", text: "user=" + T("PHONE", 1) + " done" }] }],
        meta: { nested: { deep: "token " + T("SECRET", 1) } },
        untouched: "[" + "SECRET" + "_99] 不在映射中原样保留",
      }, { status: 200, headers: { "content-type": "application/json" } }))
    const proxy = await startProxy(mock.url)
    writeMap(proxy.mapDir, [[T("SECRET", 1), SSN_VAL], [T("PHONE", 1), REAL_PHONE]])

    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: "x" }),
    })
    const got = await res.json()
    expect(got.output[0].content[0].text).toBe("user=" + REAL_PHONE + " done")
    expect(got.meta.nested.deep).toBe("token " + SSN_VAL)
    expect(got.untouched).toBe("[" + "SECRET" + "_99] 不在映射中原样保留")
    mock.stop()
  })

  test("(e) SF_SKIP=secret 时对应值不被掩", async () => {
    const mock = startMock(() => Response.json({ ok: true }))
    const proxy = await startProxy(mock.url, { SF_SKIP: "secret" })

    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: [{ role: "user", content: [{ type: "input_text", text: "key=" + SK_KEY + " phone=" + REAL_PHONE }] }] }),
    })
    expect(res.status).toBe(200)
    const got = JSON.parse(mock.bodies[0]).input[0].content[0].text
    expect(got).toContain(SK_KEY) // secret 类不掩
    expect(got).not.toContain(REAL_PHONE) // phone 仍掩
    mock.stop()
  })

  test("(f) SF_PROXY_DEBUG=1：常规日志带 mask/restore 计数，debug 输出掩码前后与还原前后", async () => {
    // mock 回显收到的（已掩码）body：还原层应把占位符还原回真值 → restore>0
    const mock = startMock((raw) => Response.json(JSON.parse(raw)))
    const proxy = await startProxy(mock.url, { SF_PROXY_DEBUG: "1" })

    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: [{ role: "user", content: [{ type: "input_text", text: "key=" + SK_KEY + " phone=" + REAL_PHONE }] }] }),
    })
    expect(res.status).toBe(200)
    const sent = JSON.parse(mock.bodies[0]).input[0].content[0].text
    expect(sent).not.toContain(REAL_PHONE) // 出站已掩
    mock.stop()
    const err = proxy.getErr()
    expect(err).toContain("[SF-proxy:debug] req.body(before)") // 掩码前原文
    expect(err).toContain(REAL_PHONE) // before 里有明文（debug 设计如此）
    expect(err).toContain("[SF-proxy:debug] req.body(after)") // 掩码后实际发往上游
    expect(err).toContain("[SF-proxy:debug] res.json(before)")
    expect(err).toContain("[SF-proxy:debug] res.json(after)")
    expect(err).toMatch(/mask=[1-9]/) // 常规日志：掩了 1+ 处
    expect(err).toMatch(/restore=[1-9]/) // 常规日志：还原了 1+ 处
  })

  test("(g) SF_PROXY_LOGFILE：console.error 输出（含 debug）追加落盘", async () => {
    const logDir = mkdtempSync(join(tmpdir(), "sf_proxy_log_"))
    maps.push(logDir)
    const logFile = join(logDir, "proxy.log")
    const mock = startMock((raw) => Response.json(JSON.parse(raw)))
    const proxy = await startProxy(mock.url, { SF_PROXY_DEBUG: "1", SF_PROXY_LOGFILE: logFile })
    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: [{ role: "user", content: [{ type: "input_text", text: "key=" + SK_KEY }] }] }),
    })
    expect(res.status).toBe(200)
    await Bun.sleep(100) // 等最后一行访问日志刷进文件
    const log = readFileSync(logFile, "utf8")
    expect(log).toContain("listening on") // 启动行也进文件
    expect(log).toContain("[SF-proxy:debug] req.body(before)") // debug 明文进文件
    expect(log).toContain("[SF-proxy:debug] res.json(after)")
    expect(log).toMatch(/mask=[1-9]/) // 访问日志行进文件
    mock.stop()
  })

  test("(h) function_call_output.output / function_call.arguments 也掩码与还原（曾漏字段致明文外发）", async () => {
    const mock = startMock((raw) => Response.json(JSON.parse(raw))) // 回显已掩码 body，供还原层验证
    const proxy = await startProxy(mock.url)

    const HEX32 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    const connStr = "amqp://" + "svc:p4ssw0rd" + "@" + HOST + ":5672/vh"
    const res = await fetch(proxy.url + "/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        input: [
          { type: "function_call_output", call_id: "call_1", output: JSON.stringify({ DesSecretKey: HEX32, Connection: connStr }) },
          { type: "function_call", call_id: "call_2", name: "exec_command", arguments: JSON.stringify({ cmd: "curl -H 'Authorization: Bearer " + SK_KEY + "' http://" + HOST + "/" }) },
        ],
      }),
    })
    expect(res.status).toBe(200)

    // 出站：这两个字段的敏感值都已掩码（修复前 mask=0，明文外发）
    const sent = mock.bodies[0]
    expect(sent).not.toContain(HEX32)
    expect(sent).not.toContain("p4ssw0rd")
    expect(sent).not.toContain(SK_KEY)
    expect(sent).toContain(T("SECRET", 1))
    expect(proxy.getErr()).toMatch(/mask=[1-9]/) // 访问日志：确实掩了

    // 入站：占位符还原回真值
    const got = await res.json()
    expect(JSON.parse(got.input[0].output).DesSecretKey).toBe(HEX32)
    expect(JSON.parse(got.input[0].output).Connection).toBe(connStr)
    expect(JSON.parse(got.input[1].arguments).cmd).toContain(SK_KEY)
    mock.stop()
  })

  test("(i) 上游 SSE 中途断连：代理不退出（不重读已损坏 reader），后续请求正常", async () => {
    let n = 0
    const mock = startMock(() => {
      n++
      if (n === 1) {
        const sse = new ReadableStream({
          start(c) {
            c.enqueue(enc.encode("data: {\"t\":\"partial\"}\n\n"))
            // 响应建立后再中断：同步 error 会让 fetch(upstream) 直接 reject 走 502 分支，测不到 SSE 流内断连
            setTimeout(() => c.error(new Error("socket closed")), 50) // 模拟上游中途 ECONNRESET
          },
        })
        return new Response(sse, { status: 200, headers: { "content-type": "text/event-stream" } })
      }
      return Response.json({ ok: true })
    })
    const proxy = await startProxy(mock.url)

    // 第一次：上游流中断（客户端侧可能也断，属预期）
    try {
      const r1 = await fetch(proxy.url + "/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ input: "x" }),
      })
      await r1.text()
    } catch { /* 客户端侧断开属预期 */ }
    await Bun.sleep(300) // 等错误日志刷进 errLog

    expect(proxy.getErr()).toContain("入站 SSE 处理失败") // 走了兜底分支

    // 第二次：代理仍存活并正常服务（修复前此处因 unhandled rejection 已进程退出）
    const res2 = await fetch(proxy.url + "/v1/responses", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ input: "y" }),
    })
    expect(res2.status).toBe(200)
    expect(await res2.json()).toEqual({ ok: true })
    mock.stop()
  })
})