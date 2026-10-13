#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
腾讯云 SSL 证书管理小工具（与续期脚本分离，避免误操作影响自动化）

  --list-all            列出账号下全部证书及风险字段
  --delete-all          删除全部证书（默认跳过「已绑定云资源」的证书）
  --delete-all --force  连绑定资源的也删（危险，只在明确知道后果时用）
  --delete <证书ID>     删除指定证书

安全策略：删除前逐个检查 BoundResource / HostingStatus，
凡是绑定了腾讯云资源的一律跳过并高亮提示 —— 删掉正在被 CDN/CLB 使用的证书会直接打断线上服务。
"""
import importlib.util
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tca", os.path.join(BASE, "tc-cert-auto.py"))
tca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tca)

RISK_FIELDS = ("BoundResource", "HostingStatus", "HostingResourceTypes",
               "Deployable", "IsDNSPODResolve", "IsWildcard", "IsVip",
               "PackageType", "PackageTypeName", "VerifyType", "StatusName")


def fetch_all(sid, skey):
    out, offset = [], 0
    while True:
        r = tca.tc_call("DescribeCertificates", {"Limit": 100, "Offset": offset}, sid, skey)
        batch = r.get("Certificates") or []
        out.extend(batch)
        if len(batch) < 100:
            break
        offset += len(batch)
    return out


def is_bound(c):
    br = c.get("BoundResource")
    if isinstance(br, list) and len(br) > 0:
        return True
    if isinstance(br, str) and br.strip():
        return True
    hs = c.get("HostingStatus")
    if isinstance(hs, str) and hs.strip() and hs not in ("0", ""):
        return True
    return False


def show(certs):
    print(f"共 {len(certs)} 张证书\n")
    for i, c in enumerate(certs, 1):
        bound = is_bound(c)
        flag = "  ⚠ 已绑定云资源" if bound else ""
        print(f"[{i}] {c.get('CertificateId')}  {c.get('Domain')}{flag}")
        for k in RISK_FIELDS:
            if k in c and c[k] not in (None, "", [], "0"):
                print(f"      {k:22} = {c[k]}")
        san = c.get("CertSANs") or c.get("SubjectAltName")
        if san:
            print(f"      {'SAN':22} = {san}")
        print(f"      {'CertEndTime':22} = {c.get('CertEndTime')}")


def main():
    args = sys.argv[1:]
    sid, skey = tca.load_credentials()
    certs = fetch_all(sid, skey)

    if "--list-all" in args or not args:
        show(certs)
        return

    if "--delete" in args:
        cid = args[args.index("--delete") + 1]
        tca.tc_call("DeleteCertificate", {"CertificateId": cid}, sid, skey)
        print(f"已删除 {cid}")
        return

    if "--delete-all" in args:
        force = "--force" in args
        show(certs)
        print("\n=== 开始删除 ===")
        deleted, skipped = [], []
        for c in certs:
            cid, dom = c.get("CertificateId"), c.get("Domain")
            if is_bound(c) and not force:
                skipped.append((cid, dom))
                print(f"  ⚠ 跳过 {cid} ({dom}): 已绑定云资源，删除会打断线上服务")
                continue
            try:
                tca.tc_call("DeleteCertificate", {"CertificateId": cid}, sid, skey)
                deleted.append((cid, dom))
                print(f"  ✓ 已删除 {cid} ({dom})")
            except RuntimeError as e:
                print(f"  ✗ 删除失败 {cid} ({dom}): {e}")
        print(f"\n删除 {len(deleted)} 张，跳过 {len(skipped)} 张")
        return

    print(__doc__)


if __name__ == "__main__":
    main()
