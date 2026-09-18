// bun test: py↔mjs 掩码输出对拍纳入自动化测试（原本只有手动脚本 test/parity/parity.mjs）。
// 复用 parity.mjs：样本缺失时用 gen_samples.py 现场生成，再逐字节比对 python 与 node 输出。
// 三份实现（py / mjs / ts 插件）各自独立，此测试用于自动捕获 py↔mjs 漂移；py↔ts 由 plugin.test.ts 覆盖。
import { describe, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..")

describe("py/mjs 对拍（parity.mjs 纳入 bun test）", () => {
  test("掩码输出逐字节一致", () => {
    const r = spawnSync(process.execPath, [join(ROOT, "test", "parity", "parity.mjs")], {
      encoding: "utf8",
      timeout: 180000,
    })
    expect(r.error).toBeUndefined()
    // 成功仅打印 PARITY_OK；失败打印 PARITY_ERR / PARITY_DIFF（见 parity.mjs）
    expect(r.stdout.trim()).toMatch(/^PARITY_OK/)
    expect(r.status).toBe(0)
  }, 180000)
})
