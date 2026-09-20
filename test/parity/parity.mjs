#!/usr/bin/env node
// parity: 对拍 py 与 mjs 的掩码输出。只输出结论与差异行号，不打印样本内容。
// 覆盖三组 env：默认（私网豁免/无自定义规则）、SF_MASK_VALUES+SF_MASK_KEYS、SF_MASK_PRIVATE_IP=1。
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

// 子进程 env：剥离 SF_MASK_* 残留再按需注入（确定性对拍）
function envOf(extra = {}) {
  const e = { ...process.env }
  delete e.SF_MASK_PRIVATE_IP
  delete e.SF_MASK_VALUES
  delete e.SF_MASK_KEYS
  return { ...e, ...extra }
}

function run(cmd, args, env) {
  const r = spawnSync(cmd, args, { input: sample, encoding: "utf8", timeout: 120000, env })
  if (r.error) return { err: String(r.error) }
  if (r.status !== 0) return { err: `exit ${r.status}: ${(r.stderr || "").slice(0, 200)}` }
  return { out: r.stdout }
}

const pyPath = path.join(root, "sensitive_filter.py")
const mjsPath = path.join(root, "sensitive-filter.mjs")
const py = run("python", [pyPath, "--no-gitleaks"], envOf())
const mjs = run("node", [mjsPath, "--no-gitleaks"], envOf())

function compare(name, a, b) {
  if (a.err || b.err) {
    console.log(`PARITY_ERR ${name} py=${a.err || "ok"} mjs=${b.err || "ok"}`)
    return false
  }
  if (a.out === b.out) {
    console.log(`PARITY_OK ${name} bytes=${Buffer.byteLength(a.out, "utf8")}`)
    return true
  }
  const x = a.out.split("\n")
  const y = b.out.split("\n")
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if (x[i] !== y[i]) {
      console.log(`PARITY_DIFF ${name} line=${i + 1} len_py=${(x[i] || "").length} len_mjs=${(y[i] || "").length}`)
      break
    }
  }
  return false
}

let ok = compare("base", py, mjs)
const extra = [
  ["values+keys", envOf({ SF_MASK_VALUES: "777777", SF_MASK_KEYS: "pss" })],
  ["mask-private", envOf({ SF_MASK_PRIVATE_IP: "1" })],
]
for (const [name, env] of extra) {
  ok = compare(name, run("python", [pyPath, "--no-gitleaks"], env), run("node", [mjsPath, "--no-gitleaks"], env)) && ok
}
process.exit(ok ? 0 : 1)