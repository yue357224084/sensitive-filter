#!/usr/bin/env python3
"""Generate fake parity samples deterministically (RFC5737 IPs, example.* mail,
algorithm-built idcard/bankcard). Writes test/parity/samples.txt.
No literal placeholder text in source: every sample value is built by
concatenation so nothing here can collide with a real secret.
"""

_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_M = "10X98765432"


def idcard(body17):
    return body17 + _M[sum(int(c) * w for c, w in zip(body17, _W)) % 11]


def luhn_digit(prefix):
    for d in range(10):
        s = prefix + str(d)
        t = 0
        for i, ch in enumerate(reversed(s)):
            dd = int(ch) * (2 if i % 2 else 1)
            t += dd - 9 if dd > 9 else dd
        if t % 10 == 0:
            return d
    return -1


def sk(n):
    return "sk-" + ("AbCdEf0123456789" * 2)[:n]


def pk(n):
    return "pk-" + ("AbCdEf0123456789" * 2)[:n]


def ghp(n):
    return "ghp_" + ("aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")[:n]


def xox(n):
    return "xoxb-" + "AbCdEf0123456789"[:(n - 5)]


def jwt():
    part = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    return part + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature0123456789sign"


def pem():
    return (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-"
        "fake0nly0for0selftest0parity0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "-----END PRIVATE KEY-----\n"
    )


def hf():
    return "hf_" + ("AbCdEf0123456789" * 3)[:34]


def gocspx():
    return "GOCSPX-" + ("AbCdEf0123456789" * 2)[:28]


def ya29():
    return "ya29." + ("aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_" * 2)[:60]


def pypi():
    return "pypi-AgEIcHlwaS5vcmc" + ("aBcDeFgH0123456789_" * 4)[:60]


def age():
    return "AGE-SECRET-KEY-1" + ("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2)[:58]


def glrt():
    return "glrt-" + ("AbCdEf0123456789_-" * 2)[:24]


def xapp():
    return "xapp-" + "1-" + "A1B2C3D4E5" + "-6-" + "a1b2c3d4e5f6"


def rk():
    return "rk_" + "a1B2c3D4e5F6g7H8"


def hvs():
    return "hvs." + ("AbCdEf0123456789_" * 6)[:100]


def nrak():
    return "NRAK-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N"


def dapi():
    return "dapi" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"[:32]


def pmak():
    return "PMAK-" + ("a1b2c3d4e5f6" * 2)[:24] + "-" + ("a1b2c3d4e5f6" * 3)[:34]


def lin():
    return "lin_api_" + ("a1b2c3d4e5f6a7b8c9d0" * 2)[:40]


def rubygems():
    return "rubygems_" + ("a1b2c3d4e5f6" * 4)[:48]


if __name__ == "__main__":
    id1 = idcard("11010520000101001")
    id2 = idcard("11010519491231002")
    card1 = "622202123456789" + str(luhn_digit("622202123456789"))
    card2 = "621700121234567" + str(luhn_digit("621700121234567"))
    assert idcard(id1[:17]) == id1 and idcard(id2[:17]) == id2
    assert (len(card1) == 16 or len(card1) == 19) and (len(card2) == 16 or len(card2) == 19)

    fake_phone1 = "1" + "39" + "0000" + "0001"
    fake_phone2 = "1" + "59" + "1234" + "5678"
    fake_mail1 = "user" + "@" + "example" + ".com"
    fake_mail2 = "test" + "@" + "example" + ".net"
    ip1 = "192" + ".0" + ".2" + ".1"
    ip2 = "198" + ".51" + ".100" + ".7"
    ip3 = "203" + ".0" + ".113" + ".9"
    # 私网段（默认豁免；SF_MASK_PRIVATE_IP=1 时掩码）：10/8、172.16/12、100.64/10 CGNAT
    ip4 = "10" + ".0" + ".0" + ".1"
    ip5 = "172" + ".16" + ".0" + ".1"
    ip6 = "100" + ".64" + ".0" + ".1"
    # 自定义字面值 / 自定义键名（SF_MASK_VALUES / SF_MASK_KEYS 生效时掩码）
    custom_literal = "77" + "77" + "77"

    sample = (
        "===== parity sample (all values fake) =====\n"
        f"phone1={fake_phone1} phone2={fake_phone2}\n"
        f"id1={id1} id2={id2}\n"
        f"card1={card1} card2={card2}\n"
        f"mail1={fake_mail1} mail2={fake_mail2}\n"
        f"ip1={ip1} ip2={ip2} ip3={ip3}\n"
        f"ip4={ip4} ip5={ip5} ip6={ip6} (private, exempt by default)\n"
        f"pss={custom_literal} v={custom_literal}\n"
        f"sk1={sk(32)} sk2={pk(32)}\n"
        f"ghp={ghp(40)} xox={xox(20)} akia=AKIAIOSFODNN7EXAMPLE\n"
        f"jwt={jwt()}\n"
        f"pw1: supersecretvalue99\n"
        f"pw2 = anothersecret123\n"
        f"pem:\n{pem()}"
        f"plain 12345678901234567 not-a-card\n"
        f"star ******** keep\n"
        f"env ${{{id1}}} and <{card1}>\n"
        f"tokens: {fake_phone1} {id2} {card2} {fake_mail1} {ip3}\n"
        f"hf={hf()} gocspx={gocspx()} ya29={ya29()} pypi={pypi()} age={age()}\n"
        f"glrt={glrt()} xapp={xapp()} rk={rk()} hvs={hvs()} nrak={nrak()}\n"
        f"dapi={dapi()} pmak={pmak()} lin={lin()} rubygems={rubygems()}\n"
    )

    from pathlib import Path

    out = Path(__file__).parent / "samples.txt"
    out.write_bytes(sample.encode("utf-8"))
    print(f"wrote {out} ({len(sample.encode('utf-8'))} bytes)")