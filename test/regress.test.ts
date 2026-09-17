// bun test: bun test test/regress.test.ts
// 回归测试（任务9 缺陷修复）：
//  1) opencode 插件 renumber 同值多 span 曾分配多个编号、映射只留最后一个 → 已发出的编号无映射可还原
//  2) ipv4 规则误伤产品/版本号（Chrome/、Edg/ 后四段 ≤255）
//  3) 键值规则误伤代码右值（值是更大表达式前缀 / 链式赋值）
// 注意：所有占位符与样本运行时拼接，源码不写字面形态。
import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import SensitiveFilterPlugin from "../opencode/plugins/sensitive-filter.ts"
const { CATS, maskText, rehydrate, renumber, saveMap } = SensitiveFilterPlugin as any

const T = (c: string, n: number) => "[" + c + "_" + n + "]"
const TOK_IPV4 = new RegExp("\\[IPV4_\\d+\\]")
const allCats = () => new Set(CATS.map((c: any) => c[0]))

const realIp = "192.0.2." + "77"
const urlIp = "198.51.100." + "24"
// UA 形态：四段数字各段 ≤255（修复前会被 ipv4 整段命中）
const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/" + "1.2" + "." + "3.4" + " Edg/" + "5.6" + "." + "7.8"

let prevMapDir: string | undefined
let prevMapKeep: string | undefined
let mapDir = ""

beforeEach(() => {
  prevMapDir = process.env.SF_MAP_DIR
  prevMapKeep = process.env.SF_MAP_KEEP
  mapDir = mkdtempSync(join(tmpdir(), "sf_regress_"))
  process.env.SF_MAP_DIR = mapDir
})
afterEach(() => {
  if (prevMapDir === undefined) delete process.env.SF_MAP_DIR
  else process.env.SF_MAP_DIR = prevMapDir
  if (prevMapKeep === undefined) delete process.env.SF_MAP_KEEP
  else process.env.SF_MAP_KEEP = prevMapKeep
  try { rmSync(mapDir, { recursive: true, force: true }) } catch { /* win32 偶发 EBUSY，残留无害 */ }
})

describe("regress: 同值多 span 编号与映射", () => {
  test("同一值三处 → 同一占位符，映射完整可还原（旧实现必败）", () => {
    const sep = "SFSEP-REGRESS"
    const glue = "\n" + sep + "\n"
    const parts = ["a=" + realIp, "b=" + realIp, "c=" + realIp]
    const text = parts.join(glue)
    const spans: [number, number][] = []
    for (let i = text.indexOf(realIp); i >= 0; i = text.indexOf(realIp, i + 1)) {
      spans.push([i, i + realIp.length])
    }
    expect(spans.length).toBe(3)
    const { out, mapping } = renumber({ taken: spans, mapping: { [realIp]: T("IPV4", 1) } }, text)
    expect(Object.keys(mapping)).toEqual([realIp]) // 映射按唯一值写入
    const pieces = out.split(glue)
    expect(pieces.length).toBe(3)
    const toks = pieces.map((p: string) => (TOK_IPV4.exec(p) || [])[0])
    expect(toks[0]).toBeTruthy()
    expect(toks[1]).toBe(toks[0]) // 旧实现每个 span 一个新编号 → 此处必败
    expect(toks[2]).toBe(toks[0])
    saveMap(mapping, out)
    for (let i = 0; i < 3; i++) expect(rehydrate(pieces[i])).toBe(parts[i])
  })
})

describe("regress: ipv4 边界", () => {
  test("UA 版本号（Chrome/、Edg/ 后四段 ≤255）不被掩码", () => {
    const { sess } = maskText(ua, allCats(), false)
    expect(sess.taken.length).toBe(0)
  })

  test("URL 中的 IP 仍被掩码（凭据与 IP 掩、协议与端口保留）", () => {
    const userinfo = "user1" + ":" + "pass1"
    const sample = "socks5://" + userinfo + "@" + urlIp + ":1080"
    const { out } = maskText(sample, allCats(), false)
    expect(out).not.toContain("pass1")
    expect(out).not.toContain(urlIp)
    expect(out).toContain("socks5://")
    expect(out).toContain(":1080")
    expect(out).toMatch(/\[SECRET_\d+\]/)
    expect(out).toMatch(/\[IPV4_\d+\]/)
  })
})

describe("regress: 键值规则不误伤代码", () => {
  test("值是更大表达式前缀（后接括号）不被掩码", () => {
    const line = "const tokens = " + "abcJSON.parse" + "(f.name), 'utf8'))"
    const { sess } = maskText(line, allCats(), false)
    expect(sess.taken.length).toBe(0)
  })

  test("链式赋值（值后接 = …）不被掩码", () => {
    const line = 'pwd = "' + "passwd = '(.+?)'" + '", s)'
    const { sess } = maskText(line, allCats(), false)
    expect(sess.taken.length).toBe(0)
  })

  test("真实键值仍被掩码：裸值 / JSON 引号值", () => {
    const pwVal = "hunter2" + "secret"
    const { sess: s1 } = maskText("password: " + pwVal, allCats(), false)
    expect(s1.mapping[pwVal]).toMatch(/^\[SECRET_\d+\]$/)

    const { sess: s2 } = maskText('{"token": "abc.def123"}', allCats(), false)
    expect(s2.mapping["abc.def123"]).toMatch(/^\[SECRET_\d+\]$/)
  })
})

describe("regress: 跨批次编号复用（映射寿命 ≥ 上下文寿命）", () => {
  test("同一值第二次请求沿用同一编号（旧实现每批次换号）", () => {
    const val = "203.0.113." + "9"
    const span = (t: string) => {
      const i = t.indexOf(val)
      return [[i, i + val.length]] as [number, number][]
    }
    const t1 = "x=" + val
    const r1 = renumber({ taken: span(t1), mapping: { [val]: T("IPV4", 1) } }, t1)
    expect(r1.mapping[val]).toMatch(TOK_IPV4)
    saveMap(r1.mapping, r1.out)  // 落盘后 scanMaps 才能看到该值 → 复用
    const t2 = "y=" + val
    const r2 = renumber({ taken: span(t2), mapping: { [val]: T("IPV4", 1) } }, t2)
    expect(r2.mapping[val]).toBe(r1.mapping[val])  // 旧实现会分配 +1 的新号 → 此处必败
    expect(rehydrate(r2.out)).toBe(t2)  // 复用的编号可还原
  })
})

describe("regress: 映射清理按容量而非按龄", () => {
  test("超 24h 但仍在保留数内的映射不被删；只删超出容量的最旧者", () => {
    process.env.SF_MAP_KEEP = "3"
    const mk = (name: string, ageDays: number) => {
      const p = join(mapDir, "sensitive_filter_map_" + name + ".json")
      const old = "202.0.113." + "1"
      writeFileSync(p, JSON.stringify({ source_sha256: "x", tokens: { [old]: T("IPV4", 1) } }), "utf8")
      const t = Date.now() / 1000 - ageDays * 86400
      utimesSync(p, t, t)
      return p
    }
    const p3 = mk("old3", 3)
    const p2 = mk("old2", 2)
    const p1 = mk("old1", 1)
    saveMap({ a: T("SECRET", 1) }, "masked-1")
    saveMap({ b: T("SECRET", 2) }, "masked-2")
    expect(existsSync(p1)).toBe(true)  // 超 24h 但在容量内 → 保留（旧实现按龄删，此处必败）
    expect(existsSync(p2)).toBe(false)  // 仅保留最新 3 个
    expect(existsSync(p3)).toBe(false)
    expect(readdirSync(mapDir).filter((n) => n.endsWith(".json")).length).toBe(3)
  })
})

describe("regress: 无映射占位符告警", () => {
  test("映射缺失时保持原样并记一次告警（同编号去重）", () => {
    const tok = T("SECRET", 987654)
    const logs: string[] = []
    const orig = console.error
    console.error = (...a: any[]) => { logs.push(a.join(" ")) }
    try {
      expect(rehydrate("x " + tok + " y")).toBe("x " + tok + " y")
      rehydrate("again " + tok)
    } finally {
      console.error = orig
    }
    expect(logs.length).toBe(1)  // 旧实现无告警 → 必败
    expect(logs[0]).toContain(tok)
  })
})
