#!/usr/bin/env node
// parity: 对拍 py 与 mjs 的掩码输出。只输出结论与差异行号，不打印样本内容。
// 用法: node test/parity/parity.mjs
import { spawnSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..")
const samplesPath = path.join(root, "test", "parity", "samples.txt")
// 样本不入库（含 token 形态，会被 GitHub Push Protection 误报）：缺则现场生成
if (!existsSync(samplesPath)) {
  const g = spawnSync("python", [path.join(root, "test", "parity", "gen_samples.py")], { encoding: "utf8", timeout: 120000 })
  if (g.status !== 0 || !existsSync(samplesPath)) {
    console.log(`PARITY_ERR 生成 samples.txt 失败: ${g.error || (g.stderr || "").slice(0, 200) || "unknown"}`)
    process.exit(1)
  }
}
const sample = readFileSync(samplesPath, "utf8")

function run(cmd, args) {
  const r = spawnSync(cmd, args, { input: sample, encoding: "utf8", timeout: 120000 })
  if (r.error) return { err: String(r.error) }
  if (r.status !== 0) return { err: `exit ${r.status}: ${(r.stderr || "").slice(0, 200)}` }
  return { out: r.stdout }
}

const py = run("python", [path.join(root, "sensitive_filter.py"), "--no-gitleaks"])
const mjs = run("node", [path.join(root, "sensitive-filter.mjs"), "--no-gitleaks"])

if (py.err || mjs.err) {
  console.log(`PARITY_ERR py=${py.err || "ok"} mjs=${mjs.err || "ok"}`)
  process.exit(1)
}
if (py.out === mjs.out) {
  console.log(`PARITY_OK bytes=${Buffer.byteLength(py.out, "utf8")}`)
  process.exit(0)
}
const a = py.out.split("\n")
const b = mjs.out.split("\n")
for (let i = 0; i < Math.max(a.length, b.length); i++) {
  if (a[i] !== b[i]) {
    console.log(`PARITY_DIFF line=${i + 1} len_py=${(a[i] || "").length} len_mjs=${(b[i] || "").length}`)
    break
  }
}
process.exit(1)