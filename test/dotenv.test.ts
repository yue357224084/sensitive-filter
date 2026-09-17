// bun test: bun test test/dotenv.test.ts
// 测 .env 注入：脚本同目录 .env 覆盖系统环境变量（用户约定 .env 优先）、解析特性（注释/引号/export 前缀）、
// 无 .env 时系统 env 正常生效、proxy.mjs 的 SF_OFF/SF_PROXY_PORT/SF_PROXY_HOST/SF_UPSTREAM 来自 .env。
// SF_ONLY/SF_SKIP 只在 proxy/enabledSet 路径生效（CLI 管线不用），故全部经 proxy 子进程验证。
// 子进程隔离：tmp 内复刻 tmp根/sensitive-filter.mjs + tmp根/codex/proxy.mjs（相对 import 成立），不污染项目根。
// 源码不写字面占位符/IP。根 .env 由 mjs 的 loadDotEnv 读，codex/.env 由 proxy 的 loadDotEnv 读（后者后加载、优先）。
import { afterAll, describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, cpSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const ROOT = join(import.meta.dir, "..")
const HOST = "127" + ".0.0" + ".1"
const T = (c: string, n: number) => "[" + c + "_" + n + "]"
const PHONE = "1390000" + "0001"
const IP = "10.0.0." + "1"
const SK = "sk-" + "AbCdEf" + "0123456789AbCdEf0123456789"
const MAIL = "user" + "@" + "example" + ".com"

const dirs: string[] = []
const procs: Bun.Subprocess[] = []
function tmp(name: string) {
  const d = mkdtempSync(join(tmpdir(), "sfdotenv_" + name + "_"))
  dirs.push(d)
  return d
}
function cleanup() {
  for (const p of procs) { try { p.kill() } catch {} }
  procs.length = 0
  for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }) } catch {} /* win32 句柄延迟：残留无害 */ }
  dirs.length = 0
}
afterAll(cleanup)

// 子进程干净 env：剥离 SF_*（防本机系统残留干扰），再按需注入"系统侧"变量
function cleanEnv(extra: Record<string, string> = {}) {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith("SF_")) env[k] = v
  return { ...env, ...extra }
}

// tmp 树：sensitive-filter.mjs（根 .env 的加载者）+ codex/proxy.mjs（codex/.env 的加载者）
function scaffold(d: string, rootEnv?: string, codexEnv?: string) {
  cpSync(join(ROOT, "sensitive-filter.mjs"), join(d, "sensitive-filter.mjs"))
  mkdirSync(join(d, "codex"))
  cpSync(join(ROOT, "codex", "proxy.mjs"), join(d, "codex", "proxy.mjs"))
  if (rootEnv !== undefined) writeFileSync(join(d, ".env"), rootEnv, "utf8")
  if (codexEnv !== undefined) writeFileSync(join(d, "codex", ".env"), codexEnv, "utf8")
}

function startMock() {
  const bodies: string[] = []
  const server = Bun.serve({
    hostname: HOST, port: 0,
    fetch: async (req) => {
      if (req.method === "GET") return new Response("ping") // 健康检查不记录
      bodies.push(await req.text())
      return Response.json({ ok: true })
    },
  })
  return { bodies, url: "http://" + HOST + ":" + server.port, stop: () => server.stop(true) }
}

// 起代理并读回真实监听地址：端口由内核分配（SF_PROXY_PORT=0），从启动日志解析，避免"抢占-释放"端口竞态
async function listenUrl(proc: Bun.Subprocess, tries = 100) {
  let log = ""
  ;(async () => {
    const td = new TextDecoder()
    try { for await (const c of proc.stderr as ReadableStream<Uint8Array>) log += td.decode(c) } catch {}
  })()
  for (let i = 0; i < tries; i++) {
    if (proc.exitCode != null) throw new Error("proxy exited early: " + log)
    const m = /listening on (http:\/\/\S+)/.exec(log)
    if (m) return m[1]
    await Bun.sleep(50)
  }
  throw new Error("proxy not ready: " + log)
}

// 起代理并发一个请求，返回 mock 收到的 body
async function probeProxy(opts: {
  dir: string
  mockUrl: string
  sysEnv: Record<string, string>
  body: string
}) {
  // 端口必须传给子进程（系统 env 方式）；0 = 内核分配，真实端口从启动日志读回
  const proc = Bun.spawn(["bun", "codex/proxy.mjs"], {
    cwd: opts.dir,
    env: cleanEnv({ ...opts.sysEnv, SF_PROXY_PORT: "0", SF_PROXY_HOST: HOST }),
    stdout: "pipe", stderr: "pipe",
  })
  procs.push(proc)
  const proxyUrl = await listenUrl(proc)
  const res = await fetch(proxyUrl + "/v1/responses", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ input: opts.body }),
  })
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({ ok: true })
  return proc
}

const SAMPLE = "pw=" + SK + " ip=" + IP + " phone=" + PHONE

describe("dotenv 注入（.env 优先于系统环境变量）", () => {
  test("(a) 根 .env 覆盖系统 env：注释行+引号值解析，SF_SKIP=phone 生效", async () => {
    const d = tmp("a"); const mock = startMock()
    scaffold(d, "# sf 测试配置\nSF_SKIP=\"phone\"\n\n")
    await probeProxy({ dir: d, mockUrl: mock.url, sysEnv: { SF_SKIP: "ipv4", SF_UPSTREAM: mock.url }, body: SAMPLE })
    const got = mock.bodies[0]
    expect(got).toContain(PHONE) // .env 的 skip=phone 覆盖系统 ipv4 → 手机号未掩
    expect(got).not.toContain(IP)
    expect(got).toMatch(/\[IPV4_\d+\]/)
    expect(got).not.toContain(SK)
    expect(got).toMatch(/\[SECRET_\d+\]/)
    mock.stop()
  })

  test("(b) 无 .env 时系统 env 正常生效", async () => {
    const d = tmp("b"); const mock = startMock()
    scaffold(d)
    await probeProxy({ dir: d, mockUrl: mock.url, sysEnv: { SF_SKIP: "phone", SF_UPSTREAM: mock.url }, body: SAMPLE })
    const got = mock.bodies[0]
    expect(got).toContain(PHONE) // 系统 skip=phone
    expect(got).not.toContain(IP)
    mock.stop()
  })

  test("(c) export 前缀解析 + .env 优先（SF_ONLY 覆盖）", async () => {
    const d = tmp("c"); const mock = startMock()
    scaffold(d, "export SF_ONLY=email\n")
    await probeProxy({
      dir: d, mockUrl: mock.url, sysEnv: { SF_ONLY: "ipv4", SF_UPSTREAM: mock.url },
      body: "ip=" + IP + " mail=" + MAIL,
    })
    const got = mock.bodies[0]
    expect(got).toContain(IP) // .env 的 only=email 覆盖系统 ipv4 → IP 放行
    expect(got).not.toContain(MAIL)
    expect(got).toMatch(/\[EMAIL_\d+\]/)
    mock.stop()
  })

  test("(d) proxy.mjs：SF_OFF=1 来自 codex/.env 直接退出", () => {
    const d = tmp("d")
    scaffold(d, undefined, "SF_OFF=1\n")
    const p = Bun.spawnSync(["bun", "codex/proxy.mjs"], { cwd: d, env: cleanEnv(), stdout: "pipe", stderr: "pipe" })
    expect(p.exitCode).toBe(0)
    expect(p.stderr.toString()).toContain("代理不启动")
  })

  test("(e) codex/.env 提供端口/host/upstream 且覆盖根 .env 的 SF_SKIP", async () => {
    const d = tmp("e"); const mock = startMock()
    // 根 .env：skip=phone；codex/.env：skip=ipv4 + 端口/host/upstream → proxy 侧 codex 优先
    scaffold(
      d,
      "SF_SKIP=\"phone\"\n",
      "SF_PROXY_PORT=\nSF_PROXY_HOST=" + HOST + "\nSF_UPSTREAM=" + mock.url + "\nSF_SKIP=ipv4\n",
    )
    // 端口 0 = 内核分配（.env 需具体值，0 合法），真实端口从启动日志读回
    writeFileSync(join(d, "codex", ".env"),
      "SF_PROXY_HOST=" + HOST + "\nSF_PROXY_PORT=0\nSF_UPSTREAM=" + mock.url + "\nSF_SKIP=ipv4\n", "utf8")
    const proc = Bun.spawn(["bun", "codex/proxy.mjs"], { cwd: d, env: cleanEnv(), stdout: "pipe", stderr: "pipe" })
    procs.push(proc)
    const proxyUrl = await listenUrl(proc)
    expect(Number(new URL(proxyUrl).port)).not.toBe(3141) // 端口确实来自 codex/.env（0 → 随机分配），而非默认 3141
    const res = await fetch(proxyUrl + "/v1/responses", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: SAMPLE }),
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
    const got = mock.bodies[0]
    expect(got).toContain(IP) // codex/.env 的 skip=ipv4 优先于根 .env 的 phone
    expect(got).not.toContain(SK)
    expect(got).toMatch(/\[SECRET_\d+\]/)
    expect(got).not.toContain(PHONE)
    expect(got).toMatch(/\[PHONE_\d+\]/)
    mock.stop()
  })
})
