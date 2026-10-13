#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
签名一致性测试：把【本项目的自研 TC3 签名实现】与【腾讯云官方 Python SDK】逐字节对比。

为什么值得做：TC3 签名只要有一个字节不对，自动化就会**静默失败** ——
现象只是 "AuthFailure.SignatureFailure"，很难定位，而后果是证书不续期、
站点在 90 天后直接挂掉。用官方实现做交叉验证可以一次性排除这个风险。

依赖（仅测试需要，运行时不依赖）：
    pip3 install --target <项目根>/pylibs tencentcloud-sdk-python-common

跑法：
    python3 tests/test_signature_parity.py
未安装 SDK 时会优雅跳过（退出码 0），不会让 CI 误判失败。
"""
import importlib.util
import json
import os
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))   # tests/
ROOT = os.path.dirname(BASE)                        # 项目根

sys.path.insert(0, os.path.join(ROOT, "pylibs"))

try:
    import tencentcloud.common.abstract_client as ac                     # noqa: E402
    from tencentcloud.common.credential import Credential               # noqa: E402
    from tencentcloud.common.http.request import RequestInternal        # noqa: E402
except ModuleNotFoundError:
    print("跳过：未找到腾讯云官方 SDK（仅签名测试需要）。安装方法：")
    print(f"  pip3 install --target {ROOT}/pylibs tencentcloud-sdk-python-common")
    sys.exit(0)

# 载入本项目实现
spec = importlib.util.spec_from_file_location("tca", os.path.join(ROOT, "tc-cert-auto.py"))
tca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tca)

# 固定时间戳即可复现；密钥用占位值，只比较签名算法本身
SECRET_ID = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3EXAMPLE"
SECRET_KEY = "Gu5t9xGARNpq86cd98joQYCN3EXAMPLE"
FIXED_TS = 1551113065
HOST = "ssl.tencentcloudapi.com"


class FakeSslClient(ac.AbstractClient):
    """只为拿到官方签名实现，不发起网络请求。

    该版本 SDK 把业务参数放在【类属性】上：_service / _apiVersion / _endpoint。
    """

    _service = "ssl"
    _apiVersion = "2019-12-05"
    _endpoint = HOST
    _default_content_type = "application/json"

    def __init__(self, cred):
        super().__init__(cred, "")


# 需要比对的请求头。这里【不能只比 Authorization】：
# 本项目曾出现「工具版本常量覆盖了 TC_API_VERSION」导致 X-TC-Version 发成 "1.0.0" 的真实 bug，
# 而当时只比 Authorization 的测试完全没有发现它（腾讯云返回的是 InvalidAction）。
COMPARE_KEYS = ("Authorization", "Content-Type", "Host",
                "X-TC-Action", "X-TC-Version", "X-TC-Timestamp")


def sdk_headers(action, params, ts):
    """用官方 SDK 生成完整请求头（时间戳固定）。"""
    ac.time.time = lambda: ts
    client = FakeSslClient(Credential(SECRET_ID, SECRET_KEY, ""))
    req = RequestInternal(host=HOST, method="POST", uri="/")
    client._build_req_with_tc3_signature(action, params, req)
    return req.header


CASES = [
    ("DescribeCertificates", {"Limit": 1}),
    ("DescribeCertificates", {"SearchKey": "tv.example.com", "Limit": 100}),
    ("ApplyCertificate", {"DomainName": "tv.example.com", "DvAuthMethod": "DNS_AUTO", "PackageType": "83"}),
    ("DownloadCertificate", {"CertificateId": "a9TsmZkL"}),
    ("DescribeCertificate", {"CertificateId": "a9TsmZkL"}),
    ("ApplyCertificate", {"DomainName": "example.com", "DvAuthMethod": "DNS_AUTO",
                          "OldCertificateId": "abc123", "Alias": "auto-example.com"}),
]


def main():
    ts = FIXED_TS
    time.time = lambda: ts          # 全局固定，双方一致
    ok = fail = 0
    print(f"对比 {len(CASES)} 个用例（固定时间戳 {ts}）\n")
    for action, params in CASES:
        # 官方 SDK 内部用 json.dumps(params) 作为请求体，这里给出一模一样的字符串
        body = json.dumps(params)
        mine, _ = tca.build_signed_headers(action, body, SECRET_ID, SECRET_KEY,
                                           host=HOST, ts=ts)
        try:
            theirs = sdk_headers(action, params, ts)
        except Exception as e:                                  # noqa: BLE001
            print(f"  [SKIP] {action}: 官方 SDK 调用异常 {type(e).__name__}: {e}")
            continue

        diffs = [(k, mine.get(k), theirs.get(k)) for k in COMPARE_KEYS
                 if mine.get(k) != theirs.get(k)]
        if not diffs:
            ok += 1
            print(f"  [PASS] {action:<22} {len(COMPARE_KEYS)} 个请求头字段全一致 "
                  f"(签名 {mine['Authorization'][-16:]})")
        else:
            fail += 1
            print(f"  [FAIL] {action:<22} 有 {len(diffs)} 个字段不一致")
            for k, a, b in diffs:
                print(f"           {k}:\n             本项目 = {a}\n             官方   = {b}")

    print(f"\n结果: {ok} 通过 / {fail} 失败")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
