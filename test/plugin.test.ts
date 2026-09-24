// bun test: bun test test/plugin.test.ts
// 测 plugin/sensitive-filter.ts 的内联核心（拼装/掩码/还原/槽）+ py(spawn) 对拍。
// 注意：所有 token 字符串运行时拼接，源码不写字面占位符。
import { afterAll, describe, expect, test } from "bun:test"
import { readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
// opencode 插件约束：模块只允许 export default；内部实现挂在 default 函数的属性上
import SensitiveFilterPlugin from "../opencode/plugins/sensitive-filter.ts"
const {
  CATS,
  collectPartSlots,
  deepRehydrate,
  makeSep,
  maskBatch,
  maskText,
  rehydrate,
  saveMap,
  tokenLookup,
} = SensitiveFilterPlugin as any

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, "..")

const T = (c, n) => "[" + c + "_" + n + "]"
const phoneTok = T("PHONE", 1)
const realPhone = "1390000000" + "1"
const mapPath = join(tmpdir(), "sensitive_filter_map_paritytest.json")

// 映射文件 tokens 是双向字典: {token: 原值, 原值: token}（与部署插件契约一致）
function writeMap(p, pairs) {
  const tokens = {}
  for (const [tok, val] of pairs) { tokens[tok] = val; tokens[val] = tok }
  writeFileSync(p, JSON.stringify({
    source_sha256: createHash("sha256").update("x").digest("hex"),
    tokens,
  }), "utf8")
}

// ---- 确定性假样本（RFC5737 IP / example 邮箱 / 算法合成身份证与银行卡校验位）----

const CN_ID_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const CN_ID_MAP = "10X98765432"

function luhnCheck(s) {
  let total = 0
  for (let i = 0; i < s.length; i++) {
    const d = parseInt(s[s.length - 1 - i], 10) * (i % 2 ? 2 : 1)
    total += d > 9 ? d - 9 : d
  }
  return total % 10 === 0
}

function paritySample() {
  const body17 = "11010519491231002"
  let sum = 0
  for (let i = 0; i < 17; i++) sum += parseInt(body17[i], 10) * CN_ID_W[i]
  const validId = body17 + CN_ID_MAP[sum % 11]
  let card = ""
  for (let d = 0; d < 10; d++) {
    if (luhnCheck("622202123456789" + d)) { card = "622202123456789" + d; break }
  }
  const phone = "1" + "39" + "0000" + "0001"
  const skKey = "sk-" + "AbCdEf0123456789AbCdEf0123456789"
  const jwt = "eyJ" + "abc".repeat(5) + "." + "def".repeat(5) + "." + "ghi".repeat(5)
  const email = "user" + "@" + "example" + ".com"
  const ip = "192" + "." + "0" + "." + "2" + "." + "16"
  const pwVal = "S3cret!" + "x9"
  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\n" +
    "A".repeat(64) + "\n" +
    "A".repeat(64) + "\n" +
    "-----END RSA PRIVATE KEY-----\n"
  const sample =
    "contact 张三 " + phone + "\n" +
    "id=" + validId + " card=" + card + "\n" +
    "sk = " + skKey + "\n" +
    "token: " + jwt + "\n" +
    'password: "' + pwVal + '"\n' +
    "mail " + email + " from " + ip + "\n" +
    pem + "\n" +
    "plain 12345678901234567 not-a-card\n" +
    "pwd: " + "change" + "me\n" +
    "key = " + "${HOME_" + "PATH}\n" +
    "token = " + "<TO" + "KEN>\n" +
    'password: "' + "*".repeat(6) + '"\n'
  return { sample, validId, card, phone, skKey, jwt, email, ip, pwVal }
}

const allCats = () => new Set(CATS.map((c) => c[0]))

afterAll(() => {
  try { unlinkSync(mapPath) } catch { /* 已清理 */ }
})

describe("makeSep", () => {
  test("格式: SFSEP- 前缀 + 24 个小写字母, 无数字", () => {
    const s = makeSep()
    expect(s.startsWith("SFSEP-")).toBe(true)
    expect(s.length).toBe(6 + 24)
    expect(/^SFSEP-[a-z]{24}$/.test(s)).toBe(true)
    expect(/\d/.test(s)).toBe(false)
  })
  test("两次调用不同(随机化防内容碰撞)", () => {
    expect(makeSep()).not.toBe(makeSep())
  })
})

describe("collectPartSlots", () => {
  test("text part: 收集并可写回", () => {
    const part = { type: "text", text: "hello" }
    const slots = []
    collectPartSlots(part, slots)
    expect(slots.length).toBe(1)
    expect(slots[0].get()).toBe("hello")
    slots[0].set("world")
    expect(part.text).toBe("world")
  })
  test("subtask part: 收集 prompt", () => {
    const part = { type: "subtask", prompt: "do thing" }
    const slots = []
    collectPartSlots(part, slots)
    expect(slots.length).toBe(1)
    slots[0].set("done")
    expect(part.prompt).toBe("done")
  })
  test("tool part: output/error/raw 槽", () => {
    const part = { type: "tool", state: { output: "o", error: "e", raw: "r" } }
    const slots = []
    collectPartSlots(part, slots)
    expect(slots.length).toBe(3)
    slots[0].set("O")
    slots[1].set("E")
    slots[2].set("R")
    expect(part.state.output).toBe("O")
    expect(part.state.error).toBe("E")
    expect(part.state.raw).toBe("R")
  })
  test("tool input: JSON 往返, 键删除重建; 坏 JSON fail-closed", () => {
    const part = { type: "tool", state: { input: { a: 1, b: "x" } } }
    const slots = []
    collectPartSlots(part, slots)
    expect(slots.length).toBe(1)
    slots[0].set(JSON.stringify({ a: 2, c: true }))
    expect(part.state.input).toEqual({ a: 2, c: true })
    slots[0].set("not-json{")
    expect(part.state.input).toEqual({ sf_masked: true })
  })
  test("非文本 part 与空对象: 无槽", () => {
    const slots = []
    collectPartSlots({ type: "weird", x: 1 }, slots)
    collectPartSlots(null, slots)
    expect(slots.length).toBe(0)
  })
})

describe("rehydrate / tokenLookup", () => {
  test("映射文件 -> token 还原为真值; 未知 token 保持", () => {
    const masked = `sms code ${phoneTok} ok`
    writeMap(mapPath, [[phoneTok, realPhone]])
    expect(rehydrate(masked)).toBe(`sms code ${realPhone} ok`)
    // 编号取超大值: 本机 tmpdir 有真实使用残留的映射文件, 小编号(如 EMAIL_9)可能撞上已知映射
    expect(rehydrate(T("EMAIL", 900001) + " unknown")).toBe(T("EMAIL", 900001) + " unknown")
    expect(rehydrate("")).toBe("")
    expect(rehydrate("no token here")).toBe("no token here")
  })
  test("deepRehydrate: 嵌套对象/数组", () => {
    const obj = { a: [phoneTok, { b: phoneTok }], c: 1 }
    const out = deepRehydrate(obj)
    expect(out.a[0]).toBe(realPhone)
    expect(out.a[1].b).toBe(realPhone)
    expect(out.c).toBe(1)
  })
  test("tokenLookup 至少包含测试映射的 token(双向)", () => {
    const L = tokenLookup()
    expect(L.get(phoneTok)).toBe(realPhone)
  })
})

describe("掩码核心（内联）", () => {
  test("maskText: 各类别占位符 + distractor 保留", () => {
    const { sample, validId, card, phone, skKey, jwt, email, ip, pwVal } = paritySample()
    const { out, sess } = maskText(sample, allCats(), false)
    // 全部类别按 C 层顺序编号
    expect(out).toContain(T("SECRET", 1))   // PEM
    expect(out).toContain(T("SECRET", 2))   // JWT
    expect(out).toContain(T("SECRET", 3))   // sk 前缀
    expect(out).toContain(T("SECRET", 4))   // password 赋值
    expect(out).toContain(T("IDCARD", 1))
    expect(out).toContain(T("PHONE", 1))
    expect(out).toContain(T("BANKCARD", 1))
    expect(out).toContain(T("EMAIL", 1))
    expect(out).toContain(T("IPV4", 1))
    // 原值不再出现
    expect(out).not.toContain(validId)
    expect(out).not.toContain(card)
    expect(out).not.toContain(phone)
    expect(out).not.toContain(skKey)
    expect(out).not.toContain(jwt)
    expect(out).not.toContain(email)
    expect(out).not.toContain(ip)
    expect(out).not.toContain(pwVal)
    // distractor 保留
    expect(out).toContain("12345678901234567") // Luhn 不通过
    expect(out).toContain("changeme")          // SKIP_VALUES
    expect(out).toContain("${HOME_PATH}")      // 环境变量引用
    expect(out).toContain("<TOKEN>")           // 尖括号占位符
    expect(out).toContain("*".repeat(6))       // 全星号
    // 计数：secret 4 + 其余各 1
    expect(sess.counts).toEqual({ secret: 4, idcard: 1, phone: 1, bankcard: 1, email: 1, ipv4: 1 })
  })

  test("SF_ONLY/SF_SKIP: 类别开关生效", () => {
    const { sample } = paritySample()
    const onlyPhone = maskText(sample, new Set(["phone"]), false)
    expect(onlyPhone.out).toContain(T("PHONE", 1))
    expect(onlyPhone.out).not.toContain(T("EMAIL", 1))
    const noSecret = maskText(sample, new Set([...allCats()].filter((c) => c !== "secret")), false)
    expect(noSecret.out).not.toContain(T("SECRET", 1))
  })

  test("二次过闸幂等（核心层）", () => {
    const { sample } = paritySample()
    const first = maskText(sample, allCats(), false)
    const second = maskText(first.out, allCats(), false)
    expect(second.out).toBe(first.out)
  })

  test("🔴 回归: 值==关键词时掩码值而非关键词（grp 偏移 bug）", () => {
    // 修复前: m[0].indexOf(val) 对"值==关键词"定位到前缀关键词 → 关键词被掩码、值暴露（不在 mapping）
    for (const [kw, val] of [["password", "password"], ["secret", "secret"], ["api_key", "api_key"]] as const) {
      const text = `${kw}: "${val}"`
      const { out, sess } = maskText(text, new Set(["secret"]), false)
      expect(sess.mapping[val]).toMatch(/^\[SECRET_\d+\]$/)  // 值被掩码
      expect(out).not.toContain(`"${val}"`)                   // 引号包裹的值不残留
      expect(out).toContain(`${kw}:`)                         // 关键词保留（未被掩码）
    }
  })

  test("新规则: URL userinfo / JSON 引号键 / sk_ 下划线 / 云厂商前缀", () => {
    const skUnderscore = "sk_" + "b" + "0".repeat(63)
    const sample = [
      "urlcred https://" + "usr1" + ":" + "Pw123456" + "@example.com/path",
      "socks socks5://" + "b389" + ":" + "111111111" + "@192.0.2." + "16" + ":20001",
      '"apiKey": "' + skUnderscore + '"',
      "stripe sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
      "gcp " + "AIza" + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU4v",
      "ghpat github_pat_" + "a1B2c3D4e5".repeat(8) + "a1B2c3",
      "gitlab glpat-" + "Ab0123456789CdEfGhIj",
      "aliyun " + "LTAI" + "5tExampleKey00",
      // 负例: 普通无凭据 URL / @用户路径 / 无点域名 — 全部保留
      "negative https://example.com/path and https://example.com/@user and plainuser@host",
    ].join("\n")
    const { out, sess } = maskText(sample, allCats(), false)
    // URL userinfo: 凭据段被掩, host/path 保留
    expect(out).not.toContain("usr1:Pw123456@")
    expect(out).toContain("example.com/path")
    expect(out).not.toContain("b389:111111111")
    expect(out).toContain("socks5://")  // 协议保留
    expect(out).toContain(":20001")
    expect(sess.mapping["b389:111111111"]).toMatch(/^\[SECRET_\d+\]$/)
    // JSON 引号键: "apiKey": "sk_..." 整值被掩
    expect(out).toMatch(/"apiKey": "\[SECRET_\d+\]"/)
    expect(out).not.toContain(skUnderscore)
    // 前缀族
    expect(out).not.toContain("sk_live_a1B2c3D4e5")
    expect(out).not.toContain("AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU4v")
    expect(out).not.toContain("github_pat_")
    expect(out).not.toContain("glpat-Ab0123456789")
    expect(out).not.toContain("LTAI5tExampleKey00")
    // 负例整行保留
    expect(out).toContain("negative https://example.com/path and https://example.com/@user and plainuser@host")
  })

  test("新规则: JSON 子串式键（accessSecret/syspw/gitToken）+ 数组值", () => {
    const sample = [
      '"accessKeyId": "LTAIXXXg6J4TEfWQruFV54uo",',
      '"accessSecret": "USt4urHUjheXH4iHe74ahlodQiGrBBNiLxtkXXXX",',
      '"password": [',
      '    "Y3XQBHeXXXXXXbAz",',
      '    "OC0pBXXXuV"',
      '],',
      '"syspw": [',
      '    "OXIXXXXXXXXo6",',
      '    "CpXXXXXXXXXX"',
      '],',
      '"gitToken": "ghsample123456",',
      '"clientSecret": "csXXXX12345678",',
      // 负例: 无关键词键整行保留
      '"updatedAt": "2026-01-01T00:00:00Z",',
    ].join("\n")
    const { out } = maskText(sample, allCats(), false)
    // 全部敏感值不再出现
    expect(out).not.toContain("USt4urHUjheXH4iHe74ahlodQiGrBBNiLxtkXXXX")
    expect(out).not.toContain("Y3XQBHeXXXXXXbAz")
    expect(out).not.toContain("OC0pBXXXuV")
    expect(out).not.toContain("OXIXXXXXXXXo6")
    expect(out).not.toContain("ghsample123456")
    expect(out).not.toContain("csXXXX12345678")
    // 标量: 键保留、值被掩
    expect(out).toMatch(/"accessSecret": "\[SECRET_\d+\]"/)
    expect(out).toMatch(/"gitToken": "\[SECRET_\d+\]"/)
    expect(out).toMatch(/"clientSecret": "\[SECRET_\d+\]"/)
    // 数组: 括号内整段掩成一个 token, 键与外括号结构保留
    expect(out).toMatch(/"password": \[SECRET_\d+\]/)
    expect(out).toMatch(/"syspw": \[SECRET_\d+\]/)
    // 负例保留
    expect(out).toContain('"updatedAt": "2026-01-01T00:00:00Z"')
  })
})

describe("新前缀 14 条（HuggingFace/Google/PyPI/age/GitLab/Slack/Stripe/Vault/NewRelic/Databricks/Postman/Linear/RubyGems）", () => {
  const secretOnly = () => new Set(["secret"])
  const cases: [string, string][] = [
    ["hf", "hf_" + "AbCdEf0123456789".repeat(3).slice(0, 34)],
    ["gocspx", "GOCSPX-" + "AbCdEf0123456789".repeat(2).slice(0, 28)],
    ["ya29", "ya29." + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_".repeat(2).slice(0, 60)],
    ["pypi", "pypi-AgEIcHlwaS5vcmc" + "aBcDeFgH0123456789_".repeat(4).slice(0, 60)],  // 填充≥50且不含'-': 35<50不命中、结尾-会被\b截断
    ["age", "AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2).slice(0, 58)],
    ["glrt", "glrt-" + "AbCdEf0123456789_-".repeat(2).slice(0, 24)],
    ["xapp", "xapp-" + "1-" + "A1B2C3D4E5" + "-6-" + "a1b2c3d4e5f6"],
    ["rk", "rk_" + "a1B2c3D4e5F6g7H8"],
    ["hvs", "hvs." + "AbCdEf0123456789_".repeat(6).slice(0, 100)],
    ["nrak", "NRAK-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N"],
    ["dapi", "dapi" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6".slice(0, 32)],
    ["pmak", "PMAK-" + "a1b2c3d4e5f6".repeat(2).slice(0, 24) + "-" + "a1b2c3d4e5f6".repeat(3).slice(0, 34)],
    ["lin", "lin_api_" + "a1b2c3d4e5f6a7b8c9d0".repeat(2).slice(0, 40)],
    ["rubygems", "rubygems_" + "a1b2c3d4e5f6".repeat(4).slice(0, 48)],
  ]
  for (const [name, val] of cases) {
    test(`前缀 ${name}: 值掩码为 [SECRET_n]`, () => {
      const { out, sess } = maskText(name + "=" + val + "\n", secretOnly(), false)
      expect(sess.mapping[val]).toMatch(/^\[SECRET_\d+\]$/)
      expect(out).not.toContain(val)
      expect(out).toMatch(/\[SECRET_\d+\]/)
    })
  }
})

describe("py/ts 对拍（同一样本，spawn py vs 内联核心）", () => {
  test("掩码输出一致 + 映射字典一致", () => {
    const { sample } = paritySample()
    const outDir = mkdtempSync(join(tmpdir(), "sf_parity_"))
    try {
      const r = spawnSync("python", [join(ROOT, "sensitive_filter.py"), "--no-gitleaks", "--map-out", outDir], {
        input: sample,
        encoding: "utf8",
        timeout: 120000,
      })
      expect(r.error).toBeUndefined()
      expect(r.status).toBe(0)
      const { out, sess } = maskText(sample, allCats(), false)
      // 1) 掩码输出逐字节一致
      expect(out).toBe(r.stdout)
      // 2) 映射字典一致（py 写双向，ts sess.mapping 是单向子集——逐条验证）
      const maps = readdirSync(outDir).filter((n) => n.startsWith("sensitive_filter_map_") && n.endsWith(".json"))
      expect(maps.length).toBe(1)
      const map = JSON.parse(readFileSync(join(outDir, maps[0]), "utf8"))
      for (const [val, tok] of Object.entries(sess.mapping)) {
        expect(map.tokens[val]).toBe(tok)  // 原值 -> 占位符
        expect(map.tokens[tok]).toBe(val)  // 反向条目也在（双向字典）
      }
      // 3) source_sha256 与 ts 计算值一致
      expect(map.source_sha256).toBe(createHash("sha256").update(out, "utf8").digest("hex"))
      // 4) 映射可还原（类 py --restore 语义：token -> 原值替换）
      for (const [val, tok] of Object.entries(sess.mapping)) {
        expect(out.split(tok).join(val)).toBe(out.replace(tok, val)) // 占位符唯一出现
      }
    } finally {
      rmSync(outDir, { recursive: true, force: true })
    }
  })
})

describe("钩子级 e2e（掩码→还原闭环 / fail-closed）", () => {
  const hookMap = join(tmpdir(), "sensitive_filter_map_hooktest.json")
  const ipTok = T("IPV", 9) + ""
  const ipTokFull = "[" + "IPV4" + "_9]"
  const secTok = "[" + "SECRET" + "_9]"
  const fakeIp = "192.0.2." + "16"
  const fakeSec = "hook2secret"
  let plugin: any

  const fakeClient = { app: { log: async () => {} } }

  test("初始化并写入钩子测试映射", async () => {
    writeMap(hookMap, [[ipTokFull, fakeIp], [secTok, fakeSec]])
    plugin = await (SensitiveFilterPlugin as any).server({ client: fakeClient } as any)
    expect(typeof plugin["experimental.chat.messages.transform"]).toBe("function")
  })

  test("text.complete: 回复展示前还原占位符", async () => {
    const out: any = { text: "host is " + ipTokFull + " key " + secTok + " unknown [" + "IPV4" + "_99] stays" }
    await plugin["experimental.text.complete"]({} as any, out)
    expect(out.text).toContain(fakeIp)
    expect(out.text).toContain(fakeSec)
    expect(out.text).toContain("[" + "IPV4" + "_99]")
  })

  test("tool.execute.before: 工具执行前深还原嵌套 args", async () => {
    const out: any = { args: { command: "echo " + ipTokFull, nested: { deep: [secTok] } } }
    await plugin["tool.execute.before"]({} as any, out)
    expect(out.args.command).toBe("echo " + fakeIp)
    expect(out.args.nested.deep[0]).toBe(fakeSec)
  })

  test("system.transform: 掩码并注入占位符指令", async () => {
    const out: any = { system: ["You are an agent. proxy is " + fakeIp] }
    await plugin["experimental.chat.system.transform"]({} as any, out)
    expect(out.system[0]).not.toContain(fakeIp)
    const last = out.system[out.system.length - 1]
    expect(String(last)).toContain("sensitive-filter")
  }, 30000)

  test("二次过闸幂等：transform 跑两遍结果不变", async () => {
    const mk = () => [{ info: {}, parts: [{ type: "text", text: "phone " + realPhone + " ip " + fakeIp }] }]
    const msgs: any = mk()
    await plugin["experimental.chat.messages.transform"]({} as any, { messages: msgs })
    const snap = JSON.stringify(msgs)
    await plugin["experimental.chat.messages.transform"]({} as any, { messages: msgs })
    expect(JSON.stringify(msgs)).toBe(snap)
  }, 30000)

  test("fail-closed: 掩码分段数不匹配即阻断发送", () => {
    const sep = makeSep()
    const glue = "\n" + sep + "\n"
    // 槽内容自身包含分隔符 → 拆分段数 > 槽数 → maskBatch 抛错阻断
    const slots: { get(): string; set(v: string): void }[] = [
      { get: () => "a" + glue + "b", set: () => {} },
    ]
    let threw = false
    try {
      maskBatch(slots, sep)
    } catch (e: any) {
      threw = String(e).includes("sensitive-filter")
    }
    expect(threw).toBe(true)
  }, 30000)

  afterAll(() => {
    try { unlinkSync(hookMap) } catch {}
  })
})