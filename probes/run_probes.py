#!/usr/bin/env python3
"""验收探针：TLS 套件与版本策略审计（6 条契约）。纯离线，按 IANA 名称判定。"""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from tlslite.audit import audit_cipher_suites, audit_versions
    return audit_cipher_suites, audit_versions

@probe("P01 批量入口与合规套件")
def p01():
    a, _ = api(); out = a(["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for k in ("index", "name", "ok", "reason", "bits", "forward_secrecy", "issues"):
        assert k in item, f"item 缺字段 {k}"
    assert item["ok"] and item["reason"] == "ok", f"合规套件应 ok，实际 {item['reason']}"
    assert item["forward_secrecy"] is True and item["bits"] == 128, "应识别前向保密与强度"

@probe("P02 弱套件")
def p02():
    a, _ = api(); out = a(["TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
    assert out.items[0]["reason"] == "weak_cipher", f"应为 weak_cipher，实际 {out.items[0]['reason']}"
    assert out.items[1]["ok"], "弱套件之后应继续"

@probe("P03 无前向保密")
def p03():
    a, _ = api(); item = a(["TLS_RSA_WITH_AES_128_GCM_SHA256"]).items[0]
    assert item["forward_secrecy"] is False, "纯 RSA 密钥交换应判无前向保密"
    assert "no_forward_secrecy" in item["issues"], f"应报 no_forward_secrecy：{item['issues']}"

@probe("P04 未知名称与重复")
def p04():
    a, _ = api(); out = a(["NOT_A_REAL_SUITE", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                           "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
    assert out.items[0]["reason"] == "unknown", f"应为 unknown，实际 {out.items[0]['reason']}"
    assert out.items[2]["reason"] == "duplicate" and out.items[2].get("duplicate_of") == 1, \
        f"应报 duplicate 并指向首次，实际 {out.items[2]}"

@probe("P05 版本策略")
def p05():
    _, v = api(); out = v(["TLSv1_3", "TLSv1_0", "SSLv3"], min_version="TLSv1_2")
    assert out.items[0]["ok"], "TLSv1_3 应合规"
    assert out.items[1]["reason"] == "weak_version", f"TLSv1_0 应 weak_version，实际 {out.items[1]['reason']}"
    assert out.items[2]["reason"] == "weak_version" and out.items[2]["ok"] is False

@probe("P06 统计、空输入与批量性能")
def p06():
    a, _ = api()
    out = a(["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
             "BOGUS_SUITE"])
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("weak_cipher") == 1 and st["by_reason"].get("unknown") == 1, st["by_reason"]
    empty = a([]); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    names = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] * 200
    t0 = time.perf_counter(); out2 = a(names); cost = time.perf_counter() - t0
    assert len(out2.items) == 200 and cost < 1.0, f"200 条耗时 {cost:.2f}s 超过 1s"

def main():
    print("=" * 60); print("验收探针：TLS 套件与版本策略审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
