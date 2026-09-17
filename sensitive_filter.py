#!/usr/bin/env python3
"""sensitive-filter: 发给大模型前的本地敏感信息过滤（方案 A+C）。

C 层（零依赖，默认）：正则 + 校验算法（身份证 mod-11、银行卡 Luhn），密钥/手机号/身份证/银行卡/邮箱/IPv4。
gitleaks / betterleaks：已安装则补充扫描密钥格式（betterleaks 优先），未安装自动跳过。

用法:
  python sensitive_filter.py [文件...]        # 脱敏文本 -> stdout，报告 -> stderr
  cat 文件 | python sensitive_filter.py
  python sensitive_filter.py --restore 文件 --map 映射.json
  python sensitive_filter.py --selftest
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# ---------------------------------------------------------------- .env 注入（脚本同目录；.env 值优先于系统环境变量）
def load_dotenv() -> None:
    """支持 KEY=VALUE / export KEY=VALUE / # 注释 / 引号包裹值；.env 不存在则静默跳过。"""
    p = Path(__file__).resolve().parent / ".env"
    try:
        txt = p.read_text(encoding="utf-8")
    except OSError:
        return
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:]
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        os.environ[k] = v


load_dotenv()

# ---------------------------------------------------------------- 校验算法

_CN_ID_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_CN_ID_MAP = "10X98765432"


def idcard_ok(s: str) -> bool:
    """GB 11643 校验位验证（18 位身份证）。"""
    try:
        return _CN_ID_MAP[sum(int(c) * w for c, w in zip(s[:17], _CN_ID_W)) % 11] == s[17].upper()
    except (ValueError, IndexError):
        return False


def luhn_ok(s: str) -> bool:
    try:
        total = 0
        for i, ch in enumerate(reversed(s)):
            d = int(ch) * (2 if i % 2 else 1)
            total += d - 9 if d > 9 else d
        return total % 10 == 0
    except ValueError:
        return False


# ---------------------------------------------------------------- C 层规则
# 顺序即优先级：先命中的 span 占位，后续类别跳过重叠区域。
# 元组: (类别名, 正则, 校验函数|None, 要掩码的 group 序号)
_CATS = [
    ("secret", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----", None, 0),
    ("secret", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", None, 0),  # JWT
    # sk/pk 前缀：短横线（OpenAI/DeepSeek sk-...）+ 下划线（Stripe sk_live_、cline sk_...）
    ("secret", r"\b(?:sk|pk)[_-][A-Za-z0-9_-]{16,}\b", None, 0),
    ("secret", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b", None, 0),
    ("secret", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", None, 0),  # GitHub fine-grained PAT
    ("secret", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", None, 0),
    ("secret", r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", None, 0),  # AWS 前缀族（gitleaks）
    ("secret", r"\bAIza[0-9A-Za-z_-]{35}\b", None, 0),  # Google API key
    ("secret", r"\bglpat-[A-Za-z0-9_-]{20,}\b", None, 0),  # GitLab PAT
    ("secret", r"\bLTAI[A-Za-z0-9]{12,20}\b", None, 0),  # 阿里云 AccessKey ID
    ("secret", r"(?i)\bhf_[A-Za-z0-9]{34}\b", None, 0),  # HuggingFace token
    ("secret", r"(?i)\bGOCSPX-[0-9A-Za-z_-]{28}\b", None, 0),  # Google OAuth client secret
    ("secret", r"(?i)\bya29\.[0-9A-Za-z_-]{50,}\b", None, 0),  # Google OAuth access token
    ("secret", r"(?i)\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}\b", None, 0),  # PyPI token（前缀固定）
    ("secret", r"(?i)\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b", None, 0),  # age 私钥
    ("secret", r"(?i)\bgl(?:rt|dt|oas|ptt|cbt)-[0-9a-zA-Z_-]{20,}\b", None, 0),  # GitLab runner/deploy/OAuth/pipeline-trigger/CI-job token
    ("secret", r"(?i)\bxapp-\d-[A-Z0-9]+-\d+-[A-Za-z0-9]+\b", None, 0),  # Slack app-level token
    ("secret", r"(?i)\brk_[a-zA-Z0-9]{10,}\b", None, 0),  # Stripe restricted key
    ("secret", r"(?i)\bhvs\.[A-Za-z0-9_-]{90,120}\b", None, 0),  # HashiCorp Vault service token
    ("secret", r"(?i)\bNRAK-[A-Z0-9]{27}\b", None, 0),  # New Relic
    ("secret", r"(?i)\bdapi[a-f0-9]{32}\b", None, 0),  # Databricks
    ("secret", r"(?i)\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", None, 0),  # Postman
    ("secret", r"(?i)\blin_api_[a-z0-9]{40}\b", None, 0),  # Linear
    ("secret", r"(?i)\brubygems_[a-f0-9]{48}\b", None, 0),  # RubyGems
    # 连接串（数据库/消息队列/远程协议，内嵌凭据）— http/https 不含（普通 URL 太常见）
    ("secret", r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|ftp|sftp|ssh)://[^\s\"'<>\]]{3,}", None, 0),
    # 通用 URL userinfo：任意协议 //user:pass@ —— grp=1 只掩凭据段，协议与 host 保留（socks5://b389:pwd@ip 也被盖住）
    ("secret", r"(?i)\b[a-z][a-z0-9+.-]*://([^\s/@:@]+:[^\s/@:@]*)@", None, 1),
    # Authorization 头（Bearer/Basic + token）
    ("secret", r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}", None, 0),
    # 键为子串式（[a-z0-9_-]* 前后缀）：命中 accessSecret/accessKeyId/gitToken/clientSecret/syspw 等复合驼峰键
    ("secret", r"(?i)\"?[a-z0-9_-]*(?:passw(?:or)?d|passwd|pwd|pw|secret|token|api_?key|access_?key|access_?secret|auth_?key|secret_?key)[a-z0-9_-]*\"?\s*[=:]\s*(\[\s*\"[^\[\]]{6,}?\])", None, 1),  # JSON 字符串数组值（内容须引号开头→幂等）
    ("secret", r"(?i)\"?[a-z0-9_-]*(?:passw(?:or)?d|passwd|pwd|pw|secret|token|api_?key|access_?key|access_?secret|auth_?key|secret_?key)[a-z0-9_-]*\"?\s*[=:]\s*[\"']?([^\s\"'`,;(){}\[\]]{6,})[\"']?(?![\w.(])(?!\s*[=:])", None, 1),
    ("idcard", r"(?<!\d)(\d{17}[\dXx])(?!\d)", idcard_ok, 1),
    ("phone", r"(?<!\d)1[3-9]\d{9}(?!\d)", None, 0),
    ("bankcard", r"(?<!\d)\d{16,19}(?!\d)", luhn_ok, 0),
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", None, 0),
    ("ipv4", r"(?<![\d.])(?<![A-Za-z0-9]\/)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])", None, 0),
]

_SKIP_VALUES = {"none", "null", "true", "false", "undefined", "changeme", "change-me", "todo"}


class Session:
    """一次脱敏运行的共享状态：已占位区间、值->token 映射、计数。"""

    def __init__(self):
        self.taken = []          # [(start, end)] 已掩码区间
        self.mapping = {}        # 原值 -> [TOKEN]（仅存本地，绝不外发）
        self.counts = {}

    def free(self, s, e):
        return not any(s < te and ts < e for ts, te in self.taken)

    def take(self, s, e, cat, value):
        self.taken.append((s, e))
        if value not in self.mapping:
            idx = sum(1 for v in self.mapping.values() if v.startswith(f"[{cat.upper()}_"))
            self.mapping[value] = f"[{cat.upper()}_{idx + 1}]"
        self.counts[cat] = self.counts.get(cat, 0) + 1


def c_layer(text: str, sess: Session, enabled: set):
    for cat, pattern, valid, grp in _CATS:
        if cat not in enabled:
            continue
        for m in re.finditer(pattern, text):
            val = m.group(grp)
            if val is None:
                continue
            if valid and not valid(val):
                continue
            if set(val) <= {"*"} or val.lower() in _SKIP_VALUES:
                continue  # 已是 ******** 脱敏值或明显占位符，不二次处理
            if val.startswith("${") or (val.startswith("<") and val.endswith(">")):
                continue  # 环境变量引用 / <TOKEN> 占位符
            s, e = m.span(grp)
            if sess.free(s, e):
                sess.take(s, e, cat, val)


def _find_scanner() -> str | None:
    for name in ("betterleaks", "gitleaks"):  # betterleaks 优先
        exe = shutil.which(name)
        if exe:
            return exe
        # winget 便携安装兜底路径(shell PATH 未刷新时生效)
        p = Path(os.environ.get("LOCALAPPDATA", "")) / f"Microsoft/WinGet/Links/{name}.exe"
        if p.is_file():
            return str(p)
    return None


def scanner_layer(text: str, sess: Session):
    """外部扫描器密钥规则补充（betterleaks 优先，回退 gitleaks）。未安装/失败仅提示，不阻断。"""
    exe = _find_scanner()
    if not exe:
        return "未安装(可选: betterleaks 或 gitleaks)"
    scanner = "betterleaks" if "betterleaks" in exe.lower() else "gitleaks"
    tmpdir = Path(tempfile.mkdtemp(prefix="sfilter_gl_"))
    try:
        (tmpdir / "input.txt").write_text(text, encoding="utf-8")
        rep = tmpdir / "rep.json"
        r = subprocess.run(
            [exe, "dir", str(tmpdir), "--no-banner", "--exit-code", "0",
             "--report-path", str(rep), "--report-format", "json"],
            capture_output=True, timeout=120)
        leaks = []
        if rep.exists() and rep.read_text(encoding="utf-8").strip():
            leaks = json.loads(rep.read_text(encoding="utf-8"))
        taken = 0
        for leak in leaks:
            val = (leak.get("Secret") or leak.get("secret") or leak.get("Match") or leak.get("match") or "").strip()
            if val:
                idx = text.find(val)
                if idx >= 0 and sess.free(idx, idx + len(val)):
                    sess.take(idx, idx + len(val), "secret", val)
                    taken += 1
        return f"{scanner}: 补掩 {taken}/{len(leaks)}" if leaks else f"{scanner}: 无命中"
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return f"跳过({type(exc).__name__})"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------- 主体

def mask_text(text: str, enabled: set, use_gitleaks: bool):
    sess = Session()
    c_layer(text, sess, enabled)
    gitleaks_note = scanner_layer(text, sess) if use_gitleaks else "禁用"
    out = text
    for s, e, tok in sorted(((s, e, sess.mapping[text[s:e]]) for s, e in sess.taken),
                            key=lambda x: -x[0]):
        out = out[:s] + tok + out[e:]
    return out, sess, gitleaks_note


_MAP_PREFIX = "sensitive_filter_map_"


def read_local(path: str, what: str) -> str:
    """带友好报错的本地文件读取（相对路径基于当前目录解析）。"""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        sys.stderr.write(f"[错误] {what}不存在: {path} (当前目录: {os.getcwd()})\n")
        raise SystemExit(2)


def _sweep_maps() -> None:
    """保留最新 N 个映射文件（默认 5000，SF_MAP_KEEP 可调）；按容量而非按龄。

    映射寿命必须 ≥ 模型上下文寿命：按龄删除会让旧编号静默失联（占位符字面量落盘）。
    """
    files = []
    for f in Path(tempfile.gettempdir()).glob(f"{_MAP_PREFIX}*.json"):
        try:
            files.append((f.stat().st_mtime, f))
        except OSError:
            pass
    try:
        keep = max(1, int(os.environ.get("SF_MAP_KEEP", "5000")))
    except ValueError:
        keep = 5000
    if len(files) <= keep:
        return
    files.sort(key=lambda x: -x[0])  # 新→旧，超出部分从最旧删
    for _, f in files[keep:]:
        try:
            f.unlink()
        except OSError:
            pass


def save_map(mapping: dict, masked_text: str, map_out: str | None) -> Path:
    """映射文件与脱敏内容 sha256 绑定：文件名带指纹，还原时校验防错配。"""
    digest = hashlib.sha256(masked_text.encode("utf-8")).hexdigest()
    if map_out:
        p = Path(map_out)
        # 传目录形式(已存在目录,或无后缀且不存在)时自动拼指纹文件名
        if p.is_dir() or (not p.suffix and not p.exists()):
            p = p / f"{_MAP_PREFIX}{digest[:8]}.json"
    else:
        p = Path(tempfile.gettempdir()) / f"{_MAP_PREFIX}{digest[:8]}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    bidir = {**mapping}
    for k, v in mapping.items():
        bidir[v] = k
    p.write_text(json.dumps({"source_sha256": digest, "tokens": bidir},
                            ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(p, 0o600)  # 内容含明文真值；默认目录是 tmpdir，Linux 上 /tmp 全局可读
    except OSError:
        pass  # Windows 等不支持时忽略（chmod 仅切只读位，0o600 含写位=no-op）
    if not map_out:
        _sweep_maps()  # 写后清理：保证目录内文件数不超过 SF_MAP_KEEP
    return p


def do_restore(text: str, map_path: str, force: bool = False) -> str:
    data = json.loads(read_local(map_path, "映射文件"))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest != data.get("source_sha256"):
        if not force:
            sys.stderr.write(
                f"[错误] 映射文件与待还原内容不匹配 (映射 {data.get('source_sha256', '?')[:8]}, "
                f"内容 {digest[:8]})；内容若已被修改过且确认映射来源无误, 加 --force\n")
            raise SystemExit(1)
        sys.stderr.write("[警告] 内容与映射不配对, 已按 --force 跳过校验\n")
    for val, tok in sorted(((k, v) for k, v in data["tokens"].items()
                            if re.match(r"\[(?:SECRET|IDCARD|PHONE|BANKCARD|EMAIL|IPV4)_\d+\]", v)),
                           key=lambda kv: -len(kv[1])):
        text = text.replace(tok, val)
    return text


def run_selftest() -> int:
    body17 = "11010519491231002"
    chk = _CN_ID_MAP[sum(int(c) * w for c, w in zip(body17, _CN_ID_W)) % 11]
    valid_id = body17 + chk
    fake_phone = "13812345678"
    fake_mail = "foo.bar@corp.example.com"
    fake_ip = "192.0.2.10"
    sk_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
    pw_val = "Sup3rSecret!!"
    card = "4111111111111111"
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOGfakecontent\n-----END RSA PRIVATE KEY-----"
    sample = (
        f"contact 张三 {fake_phone} id={valid_id} card={card}\n"
        f"key = {sk_key}\n"
        f'password: "{pw_val}"\n'
        'password: "password"\n'  # 🔴 回归：值==关键词，须掩码值而非关键词
        f"mail {fake_mail} from {fake_ip}\n"
        f"{pem}\n"
        "plain 12345678901234567 not-a-card\n"  # Luhn 不通过,必须保留
    )
    out, sess, _ = mask_text(sample, {c for c, *_ in _CATS}, use_gitleaks=False)

    def has(v, cat):
        return sess.mapping.get(v, "").startswith("[" + cat + "_")

    checks = [
        ("phone 掩码", fake_phone not in out and has(fake_phone, "PHONE")),
        ("idcard 掩码", valid_id not in out and has(valid_id, "IDCARD")),
        ("bankcard 掩码", card not in out and has(card, "BANKCARD")),
        ("sk key 掩码", sk_key not in out and has(sk_key, "SECRET")),
        ("password 赋值掩码", pw_val not in out and has(pw_val, "SECRET")),
        ("pem 掩码", pem not in out and has(pem, "SECRET")),
        ("email 掩码", fake_mail not in out and has(fake_mail, "EMAIL")),
        ("ipv4 掩码", fake_ip not in out and has(fake_ip, "IPV4")),
        ("luhn 不通过保留", "12345678901234567" in out),
        ("idcard/bankcard 不重复掩码", out.count("[IDCARD_") == 1 and out.count("[BANKCARD_") == 1),
        ("🔴 值==关键词: 值掩码/关键词保留", '"password"' not in out and "password:" in out and not re.search(r"\[SECRET_\d+\]:", out) and has("password", "SECRET")),
        ("还原闭环", do_restore(out, str(save_map(sess.mapping, out, None))) == sample),
    ]
    ok = True
    for name, passed in checks:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
        ok = ok and passed
    print(f"  计数: {sess.counts}")
    return 0 if ok else 1


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace", newline="")
    if sys.stdin is not None and not sys.stdin.isatty():
        sys.stdin.reconfigure(encoding="utf-8", errors="replace", newline="")
    ap = argparse.ArgumentParser(description="发给大模型前的本地敏感信息过滤 (方案A+C)")
    ap.add_argument("inputs", nargs="*", help="输入文件；省略则读 stdin")
    ap.add_argument("--skip", default="", help="禁用的类别, 逗号分隔: secret,idcard,phone,bankcard,email,ipv4")
    ap.add_argument("--only", default="", help="仅启用的类别(优先于 --skip)")
    ap.add_argument("--no-gitleaks", action="store_true", help="跳过 gitleaks")
    ap.add_argument("--map-out", default=None, help="映射文件输出路径(默认写入系统临时目录)")
    ap.add_argument("--restore", metavar="FILE", help="用映射文件还原已脱敏文本")
    ap.add_argument("--map", dest="map_file", help="还原所用的映射文件路径")
    ap.add_argument("--force", action="store_true", help="还原时跳过内容配对校验(内容被 LLM 修改过时使用)")
    ap.add_argument("--selftest", action="store_true", help="内置自检")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()
    if args.restore:
        if not args.map_file:
            print("[错误] --restore 需要 --map 指定映射文件", file=sys.stderr)
            return 2
        src = read_local(args.restore, "待还原文件")
        sys.stdout.write(do_restore(src, args.map_file, args.force))
        return 0

    all_cats = {c for c, *_ in _CATS}
    if args.only:
        enabled = {c.strip() for c in args.only.split(",")} & all_cats
    else:
        enabled = all_cats - {c.strip() for c in args.skip.split(",")}

    if args.inputs:
        text = "\n".join(read_local(p, "输入文件") for p in args.inputs)
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print("用法: python sensitive_filter.py [文件...] | 管道 | --selftest | --restore", file=sys.stderr)
        return 2
    if not text:
        return 0

    out, sess, gitleaks_note = mask_text(text, enabled, not args.no_gitleaks)
    sys.stdout.write(out)
    print(f"\n[命中] {sess.counts or '未命中'}  [gitleaks] {gitleaks_note}",
          file=sys.stderr)
    if sess.mapping:
        mp = save_map(sess.mapping, out, args.map_out)
        print(f"[映射] {mp}  (还原: --restore 输出文件 --map {mp})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
