// bun test: bun test test/sse-restore.test.ts
// 覆盖 opencode V2 流式(SSE)还原：跨帧撕裂占位符、JSON 转义安全、非占位符字节透传、不丢字节。
// 注意：所有占位符与样本运行时拼接，源码不写字面形态。
import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import SensitiveFilterPlugin from "../opencode/plugins/sensitive-filter.ts"
const { SseRehydrator, sseRehydrateStream } = SensitiveFilterPlugin as any

const T = (c: string, n: number) => "[" + c + "_" + n + "]"
const frame = (o: unknown) => "data: " + JSON.stringify(o) + "\n\n"
const delta = (content: string) => frame({ choices: [{ delta: { content } }] })
const DONE = "data: [DONE]\n\n"

let prevDir: string | undefined
let dir = ""

function writeMap(pairs: Array<[string, string]>): void {
  const bidir: Record<string, string> = {}
  for (const [tok, val] of pairs) { bidir[tok] = val; bidir[val] = tok }
  writeFileSync(
    join(dir, "sensitive_filter_map_ssetest.json"),
    JSON.stringify({ source_sha256: createHash("sha256").update("z").digest("hex"), tokens: bidir }),
    "utf8",
  )
}

function run(chunks: string[]): string {
  const r = new SseRehydrator()
  let out = ""
  for (const c of chunks) out += r.push(c)
  out += r.flush()
  return out
}

// 取出所有 choices[0].delta.content，拼成"用户实际看到的文本"
function visible(out: string): string {
  return out.split("\n\n").filter(Boolean).map((f) => {
    try { return JSON.parse(f.replace(/^data: /, "")) } catch { return null }
  }).filter((o: any) => o && o.choices?.[0]?.delta?.content !== undefined)
    .map((o: any) => o.choices[0].delta.content as string).join("")
}

beforeEach(() => {
  prevDir = process.env.SF_MAP_DIR
  dir = mkdtempSync(join(tmpdir(), "sf_sse_"))
  process.env.SF_MAP_DIR = dir
})
afterEach(() => {
  if (prevDir === undefined) delete process.env.SF_MAP_DIR
  else process.env.SF_MAP_DIR = prevDir
  try { rmSync(dir, { recursive: true, force: true }) } catch { /* win32 偶发 EBUSY，无害 */ }
})

describe("SSE 流式还原", () => {
  test("跨 2 帧撕裂的占位符能还原", () => {
    const tok = T("IPV4", 1)
    const real = "192.0.2." + "77"
    writeMap([[tok, real]])
    const out = run([delta("The IP is " + tok.slice(0, 4)), delta(tok.slice(4)), DONE])
    expect(out).toContain(real)
    expect(out).not.toContain(tok)
    expect(visible(out)).toBe("The IP is " + real)
  })

  test("跨 3+ 帧撕裂（含分类名内切开）能还原", () => {
    const tok = T("SECRET", 3)
    const real = "sk-" + "AbCdEf0123456789AbCdEf0123456789"
    writeMap([[tok, real]])
    // 在 "[SE" / "CRET_" 处切开，模拟 provider 按 token 切片
    const out = run([delta("[SE"), delta("CRET_"), delta("3]"), DONE])
    expect(out).toContain(real)
    expect(visible(out)).toBe(real)
  })

  test("真值含换行/引号/反斜杠时仍输出合法 JSON 且值正确", () => {
    const tok = T("SECRET", 1)
    const real = "line1\nline2 \"q\" \\ end"
    writeMap([[tok, real]])
    const out = run([delta("key=" + tok), DONE])
    // 每个 JSON 帧都必须是合法 JSON（转义由 JSON.stringify 负责）
    for (const f of out.split("\n\n").filter((x) => x.startsWith("data: {"))) expect(() => JSON.parse(f.slice(6))).not.toThrow()
    expect(visible(out)).toBe("key=" + real)
  })

  test("无占位符的流逐字节透传", () => {
    const chunks = [delta("hello "), delta("world"), DONE]
    expect(run(chunks)).toBe(chunks.join(""))
  })

  test("[DONE] 保留且在末尾", () => {
    const tok = T("PHONE", 1)
    writeMap([[tok, "1390000000" + "1"]])
    const out = run([delta("call " + tok), DONE])
    expect(out.endsWith(DONE)).toBe(true)
    expect((out.match(/data: \[DONE\]/g) || []).length).toBe(1)
  })

  test("CRLF 分帧同样能立即输出并还原（网关规范化换行）", () => {
    const tok = T("IPV4", 6)
    const real = "192.0.2." + "6"
    writeMap([[tok, real]])
    const crlf = (c: string) => "data: " + JSON.stringify({ choices: [{ delta: { content: c } }] }) + "\r\n\r\n"
    const r = new SseRehydrator()
    const o1 = r.push(crlf("ip " + tok)) // 首帧推入后必须立即有输出（不能攒到流结束）
    const o2 = r.push("data: [DONE]\r\n\r\n")
    const o3 = r.flush()
    const all = o1 + o2 + o3
    expect(o1.length).toBeGreaterThan(0)
    expect(all).toContain(real)
    expect(all).not.toContain(tok)
  })

  test("流结束时残留半截占位符不丢字节", () => {
    writeMap([[T("IPV4", 9), "198.51.100." + "9"]])
    const chunks = [delta("The IP is ["), delta("IPV")]
    const out = run(chunks)
    expect(visible(out)).toBe("The IP is [IPV")
  })

  test("非 JSON 的 data 帧与 event: 行原样保留（Anthropic 形态）", () => {
    const out = run(["event: ping\ndata: {\"type\":\"ping\"}\n\n", "data: [DONE]\n\n"])
    expect(out).toBe("event: ping\ndata: {\"type\":\"ping\"}\n\n" + "data: [DONE]\n\n")
  })

  test("tool_call.arguments 等其它字符串字段同样还原", () => {
    const tok = T("IPV4", 2)
    const real = "203.0.113." + "5"
    writeMap([[tok, real]])
    const out = run([frame({ choices: [{ delta: { tool_calls: [{ function: { arguments: "{\"host\":\"" + tok + "\"}" } }] } }] }), DONE])
    expect(out).toContain(real)
  })

  test("多字节字符被切到两个 chunk 也能正确还原（走流包装）", async () => {
    const tok = T("IPV4", 4)
    const real = "192.0.2." + "4"
    writeMap([[tok, real]])
    const text = delta("主机 " + tok + " 完成") + DONE
    const bytes = new TextEncoder().encode(text)
    // 从中间切开（故意切在多字节字符中间）
    const cut = bytes.indexOf(0xe4) + 1 // "主" 的首字节之后
    const chunks = [bytes.slice(0, cut), bytes.slice(cut)]
    const src = new ReadableStream<Uint8Array>({
      start(c) { for (const b of chunks) c.enqueue(b); c.close() },
    })
    const out = await new Response(sseRehydrateStream(src)).text()
    expect(out).toContain(real)
    expect(out).toContain("主机")
    expect(out.endsWith(DONE)).toBe(true)
  })
})
