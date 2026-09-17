// bun test: bun test test/failclosed.test.ts
// 回归测试（任务18）：可跨行规则（PEM 等）在 maskBatch 拼装文本上跨 slot 匹配时，
// 会把 slot 间分隔符整体吞进 span → 拆回分段数错乱 → fail-closed 误阻断发送。
// 修复：renumber 增加 boundaries（各 slot 区间），跨界 span 裁到各 slot 区间内（分隔符存活），
// 子区间作为独立值掩码/映射/还原。
// 注意：所有占位符与样本运行时拼接，源码不写字面形态。
import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import SensitiveFilterPlugin from "../opencode/plugins/sensitive-filter.ts"
const { CATS, maskText, renumber, saveMap, rehydrate, maskBatch } = SensitiveFilterPlugin as any

const T = (c: string, n: number) => "[" + c + "_" + n + "]"
const allCats = () => new Set(CATS.map((c: any) => c[0]))

// PEM 样本（合法形态，规则锚 -----BEGIN/END ... PRIVATE KEY-----）
const pemBody = "MIIEx" + "abcDEF"
const partA = "-----BEGIN " + "PRIVATE KEY" + "-----" + "\n" + pemBody
const partB = pemBody + "\n-----END " + "PRIVATE KEY" + "-----"
const mid = "plain text without secrets"
const sep = "SFSEP-FC-TEST"
const glue = "\n" + sep + "\n"
const parts = [partA, mid, partB]
const joined = parts.join(glue)

let prevMapDir: string | undefined
let mapDir = ""

beforeEach(() => {
  prevMapDir = process.env.SF_MAP_DIR
  mapDir = mkdtempSync(join(tmpdir(), "sf_failclosed_"))
  process.env.SF_MAP_DIR = mapDir
})
afterEach(() => {
  if (prevMapDir === undefined) delete process.env.SF_MAP_DIR
  else process.env.SF_MAP_DIR = prevMapDir
  try { rmSync(mapDir, { recursive: true, force: true }) } catch { /* win32 偶发 EBUSY，残留无害 */ }
})

describe("fail-closed 误阻断修复", () => {
  test("复现对照：不传 boundaries 时跨界 span 吞分隔符（拆回段数错误）", () => {
    const { sess } = maskText(joined, allCats(), false)
    expect(sess.taken.length).toBe(1)  // PEM 从 partA 的 BEGIN 吞到 partB 的 END，一个大 span
    const { out } = renumber(sess, joined)  // 旧调用形态（无 boundaries）
    expect(out.split(glue).length).not.toBe(parts.length)  // 分隔符被吞 → 旧代码在此 fail-closed 阻断
  })

  test("修复后：boundaries 裁界 → 分隔符存活、各槽掩码且可还原", () => {
    const { sess } = maskText(joined, allCats(), false)
    const boundaries: Array<[number, number]> = []
    let off = 0
    for (const p of parts) { boundaries.push([off, off + p.length]); off += p.length + glue.length }
    const { out, mapping } = renumber(sess, joined, boundaries)
    const pieces = out.split(glue)
    expect(pieces.length).toBe(parts.length)  // 分隔符存活（旧代码必败处）
    expect(mapping[partA]).toMatch(/^\[SECRET_\d+\]$/)  // 子区间作为独立值进映射
    expect(mapping[mid]).toMatch(/^\[SECRET_\d+\]$/)
    expect(mapping[partB]).toMatch(/^\[SECRET_\d+\]$/)
    expect(out).not.toContain(pemBody)  // 敏感内容仍被掩（fail-closed 精神不变）
    saveMap(mapping, out)
    for (let i = 0; i < 3; i++) expect(rehydrate(pieces[i])).toBe(parts[i])  // 还原为子区间真值
  })

  test("maskBatch 端到端：PEM 跨 slot 不再阻断发送", () => {
    const slots = parts.map((v) => {
      const o: any = { v, get: () => o.v, set: (x: string) => { o.v = x } }
      return o
    })
    maskBatch(slots, sep)  // 旧代码此处 throw「分段数不匹配 1/3」
    for (let i = 0; i < 3; i++) {
      expect(slots[i].v).not.toBe(parts[i])  // 已掩码
      expect(rehydrate(slots[i].v)).toBe(parts[i])  // 可完整还原
    }
  }, 30000)
})
