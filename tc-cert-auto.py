#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
腾讯云免费 SSL 证书全自动管理（申请 -> 验证 -> 轮询 -> 下载 -> 部署 -> reload nginx）

设计要点
  * 证书由【腾讯云 SSL 证书服务】签发（TrustAsia DV 免费证书，90 天）。
  * 零第三方依赖：TC3-HMAC-SHA256 签名用 Python 标准库实现，不需要装任何 SDK。
  * 幂等：先查现有证书剩余天数，未进入续签窗口就直接跳过，可安全地频繁运行。
  * 免费证书是【单域名】，所以每个域名各自一张证书、各自部署到自己的文件。

用法
  tc-cert-auto.py --check-auth        # 只验证密钥/网络/签名链路是否通
  tc-cert-auto.py --list              # 列出配置里各域名当前证书与到期时间
  tc-cert-auto.py --domain app.example.com    # 只处理某个域名
  tc-cert-auto.py                     # 处理 config.json 里的全部域名
  tc-cert-auto.py --force             # 忽略剩余天数, 强制走一遍(排障用)
"""

import base64
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
CRED_PATH = os.path.join(BASE_DIR, "credentials")

# ---- 腾讯云 SSL API 常量 ----
HOST = "ssl.tencentcloudapi.com"          # 中国站; 国际站是 ssl.intl.tencentcloudapi.com
SERVICE = "ssl"
TC_API_VERSION = "2019-12-05"             # 腾讯云 API 版本（注意：这不是本工具的版本号）
ALGORITHM = "TC3-HMAC-SHA256"
TOOL_VERSION = "1.0.0"                    # 本工具自身版本


def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def die(msg):
    log(msg, "ERROR")
    sys.exit(1)


# --------------------------------------------------------------------------
# 凭据与配置
# --------------------------------------------------------------------------
def load_credentials():
    """从 credentials 文件读取 SecretId / SecretKey。

    也兼容形如:
        SecretId=xxx
        SecretKey=yyy
    或 JSON:  {"SecretId": "...", "SecretKey": "..."}
    """
    path = os.environ.get("TC_CREDENTIALS", CRED_PATH)
    if not os.path.isfile(path):
        die(f"找不到凭据文件 {path}（请从 credentials.template 复制并填入）")
    raw = open(path, "r", encoding="utf-8").read()

    if raw.strip().startswith("{"):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            die(f"凭据文件 JSON 解析失败: {e}")
        sid, skey = obj.get("SecretId", ""), obj.get("SecretKey", "")
    else:
        sid = skey = ""
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "secretid":
                sid = v
            elif k == "secretkey":
                skey = v

    if not sid or not skey or "REPLACE_ME" in sid or "REPLACE_ME" in skey:
        die(f"凭据文件 {path} 里的 SecretId/SecretKey 还没填（或仍是占位值）")
    return sid, skey


def load_config():
    """读取 config.json；不存在时退回 config.example.json 并提示。"""
    for name in ("config.json", "config.example.json"):
        path = os.path.join(BASE_DIR, name)
        if os.path.isfile(path):
            if name != "config.json":
                log(f"未找到 config.json，暂用 {name} —— 请复制成 config.json 并按需修改", "WARN")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    die("找不到 config.json 或 config.example.json")


def usage():
    print(f"""腾讯云免费 SSL 证书自动化 v{TOOL_VERSION}（零第三方依赖）

用法:
  tc-cert-auto.py                  处理 config.json 里的全部域名
  tc-cert-auto.py --list           只列出各域名现有证书与剩余天数（只读）
  tc-cert-auto.py --check-auth     只验证密钥与签名链路（只读）
  tc-cert-auto.py --domain <域名>   只处理指定域名
  tc-cert-auto.py --force          忽略剩余天数阈值，强制走一遍（排障用）
  tc-cert-auto.py --no-reload      更新证书但不 reload nginx
  tc-cert-auto.py -h, --help       显示本帮助
  tc-cert-auto.py --version        显示版本

文件:
  config.json      域名、证书路径、required_sans（从 config.example.json 复制）
  credentials      腾讯云 CAM 子账号密钥（chmod 600，切勿提交）

定时器:
  systemd tc-cert.timer（由 install.sh 安装；每天检查，剩余 <30 天才续签）
""")


# --------------------------------------------------------------------------
# TC3-HMAC-SHA256 签名 + 调用（标准库实现）
# --------------------------------------------------------------------------
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


JSON_CONTENT_TYPE = "application/json"


def build_signed_headers(action, body, secret_id, secret_key,
                         host=HOST, region="", ts=None, content_type=JSON_CONTENT_TYPE):
    """按 TC3-HMAC-SHA256 构造请求头。body 必须是【最终原样发送】的字符串。

    刻意与官方 Python SDK 的 _build_req_with_tc3_signature 逐字节对齐：
    Content-Type 用 application/json（不带 charset）—— 官方 SDK 即如此，
    避免服务端对 Content-Type 做归一化后与签名里的值不一致导致鉴权失败。
    """
    ts = int(ts if ts is not None else time.time())
    date = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")

    # 1) 规范请求串（canonical_headers 自带结尾换行，拼接后 headers 与 signed_headers 之间是空行）
    canonical_headers = f"content-type:{content_type}\nhost:{host}\n"
    signed_headers = "content-type;host"
    hashed_payload = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_request = "\n".join([
        "POST", "/", "", canonical_headers, signed_headers, hashed_payload,
    ])

    # 2) 待签名字符串
    credential_scope = f"{date}/{SERVICE}/tc3_request"
    string_to_sign = "\n".join([
        ALGORITHM, str(ts), credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    # 3) 计算签名（TC3 派生密钥链）
    secret_date = _hmac(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = _hmac(secret_date, SERVICE)
    secret_signing = _hmac(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "Authorization": (
            f"{ALGORITHM} Credential={secret_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
        "Content-Type": content_type,
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Version": TC_API_VERSION,
        "X-TC-Timestamp": str(ts),
    }
    if region:
        headers["X-TC-Region"] = region
    return headers, ts


def tc_call(action, payload, secret_id, secret_key, host=HOST, region=""):
    """调用腾讯云 API 3.0，返回 Response 字典。"""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    headers, _ = build_signed_headers(action, body, secret_id, secret_key,
                                      host=host, region=region)

    req = urllib.request.Request(
        f"https://{host}/", data=body.encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        # HTTP 层错误里也可能是结构化的腾讯云错误
        try:
            data = json.loads(detail)
        except json.JSONDecodeError:
            die(f"{action} HTTP {e.code}: {detail[:400]}")
    except Exception as e:
        die(f"{action} 请求失败: {e}")

    r = data.get("Response", {})
    if "Error" in r:
        err = r["Error"]
        raise RuntimeError(f"{action} 失败: {err.get('Code')} - {err.get('Message')}")
    return r


# --------------------------------------------------------------------------
# 业务逻辑
# --------------------------------------------------------------------------
def parse_time(s):
    """腾讯云返回 2026-10-13 08:18:59，转成 datetime(UTC)。"""
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def list_certs(domain, secret_id, secret_key):
    """取出该域名下所有【已签发】的证书，按到期时间倒序。"""
    r = tc_call("DescribeCertificates",
                {"SearchKey": domain, "Limit": 100},
                secret_id, secret_key)
    out = []
    for c in r.get("Certificates", []) or []:
        if c.get("Domain") != domain:
            continue
        if c.get("Status") != 1:          # 1 = 已签发
            continue
        end = parse_time(c.get("CertEndTime"))
        if end is None:
            continue
        out.append({"id": c.get("CertificateId"), "end": end,
                    "alias": c.get("Alias"), "status": c.get("Status")})
    out.sort(key=lambda x: x["end"], reverse=True)
    return out


def wait_issued(cert_id, secret_id, secret_key, timeout=1800, interval=20):
    """轮询直到签发完成。免费 DV 通常几分钟; 文件验证需等 CA 爬虫。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = tc_call("DescribeCertificate", {"CertificateId": cert_id},
                    secret_id, secret_key)
        status = r.get("Status")
        if status == 1:
            return r
        # 0=审核中 1=已签发 2=审核失败 3=已过期 4=已添加DNS记录 5=企业证书待提交 6=订单已取消 ...
        if status in (2, 3, 6):
            hint = r.get("StatusMsg") or ""
            raise RuntimeError(f"证书 {cert_id} 状态异常 status={status} msg={hint}")
        state = f"status={status} msg={r.get('StatusMsg')}"
        if state != last:
            log(f"  等待签发… {state}")
            last = state
        time.sleep(interval)
    raise RuntimeError(f"证书 {cert_id} 在 {timeout}s 内未签发完成（可能卡在域名验证）")


def write_dcv_file(dcv_dir, dv_detail):
    """FILE 验证：把 CA 要求的验证文件写到站点目录。

    需要的信息来自 DescribeCertificate 的 DvAuthDetail:
      DvAuthPath (如 /.well-known/pki-validation/)
      DvAuthKey  (文件名)
      DvAuthValue(文件内容)
    """
    path = dv_detail.get("DvAuthPath") or "/.well-known/pki-validation/"
    key = dv_detail.get("DvAuthKey")
    val = dv_detail.get("DvAuthValue")
    if not key or not val:
        log(f"  无法解析验证文件信息, DvAuthDetail={json.dumps(dv_detail, ensure_ascii=False)}", "WARN")
        return None
    rel = path.lstrip("/")
    target_dir = os.path.join(dcv_dir, rel)
    os.makedirs(target_dir, exist_ok=True)
    target = os.path.join(target_dir, key)
    with open(target, "w", encoding="utf-8") as f:
        f.write(val)
    os.chmod(target, 0o644)
    log(f"  已放置验证文件: {target}")
    return target


def download_and_extract(cert_id, secret_id, secret_key):
    """下载证书 zip 并挑出 nginx 需要的 crt / key。"""
    r = tc_call("DownloadCertificate", {"CertificateId": cert_id},
                secret_id, secret_key)
    content = r.get("Content")
    if not content:
        raise RuntimeError("DownloadCertificate 未返回 Content")
    blob = base64.b64decode(content)

    zf = zipfile.ZipFile(io.BytesIO(blob))
    names = zf.namelist()

    def pick(ext, prefer_bundle=False):
        cands = [n for n in names if n.lower().endswith(ext) and not n.endswith("/")]
        # 优先 nginx 目录
        ng = [n for n in cands if "nginx" in n.lower()]
        pool = ng or cands
        if not pool:
            return None, None
        if prefer_bundle:
            b = [n for n in pool if "bundle" in os.path.basename(n).lower()]
            if b:
                pool = b
        # 证书链通常体积最大, 取最大者
        best = max(pool, key=lambda n: zf.getinfo(n).file_size)
        return best, zf.read(best).decode("utf-8", "replace")

    crt_name, crt = pick(".crt", prefer_bundle=True)
    if crt is None:
        crt_name, crt = pick(".pem", prefer_bundle=True)
    key_name, key = pick(".key")
    if not crt or not key:
        raise RuntimeError(f"zip 内未找到 crt/key, 实际内容: {names}")
    log(f"  从 zip 取出: {crt_name} + {key_name}")
    return crt, key


def cert_sans_from_pem(crt_pem):
    """解析 PEM 证书里的全部 DNS 名（CN + SubjectAltName）。"""
    p = subprocess.run(["openssl", "x509", "-noout", "-text"],
                       input=crt_pem, capture_output=True, text=True)
    text = p.stdout
    names = set()
    m = re.search(r"Subject:.*?CN\s*=\s*([^,\n/]+)", text, re.S)
    if m:
        names.add(m.group(1).strip())
    m = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", text)
    if m:
        for item in m.group(1).split(","):
            item = item.strip()
            if item.lower().startswith("dns:"):
                names.add(item[4:].strip())
    return names


def deploy(cfg, item, crt, key):
    """把证书写到 nginx 使用的路径（先备份旧文件）。

    部署前先做 SAN 覆盖校验：腾讯云免费证书申请根域名会赠送 www，
    但这个行为一旦变化（或换成子域名申请），天真地覆盖旧文件会让 www 直接掉证书。
    因此这里必须在【改动任何文件之前】确认新证书覆盖了 required_sans 里的每个域名。
    """
    required = item.get("required_sans") or [item["domain"]]
    have = cert_sans_from_pem(crt)
    missing = [n for n in required if n not in have]
    if missing:
        raise RuntimeError(
            f"新证书的 SAN 缺少必需域名 {missing}（实际 SAN: {sorted(have)}）—— "
            f"已拒绝部署，旧证书保持原样，请人工确认腾讯云的 www 赠送策略后重试"
        )
    log(f"  SAN 校验通过: {sorted(have)} ⊇ {required}")

    crt_path, key_path = item["crt_path"], item["key_path"]
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    for p in (crt_path, key_path):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p):
            bak = f"{p}.bak-{stamp}"
            subprocess.run(["cp", "-p", p, bak], check=True)
            log(f"  已备份旧文件 -> {bak}")
    with open(crt_path, "w", encoding="utf-8") as f:
        f.write(crt if crt.endswith("\n") else crt + "\n")
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(key if key.endswith("\n") else key + "\n")
    os.chmod(crt_path, 0o644)
    os.chmod(key_path, 0o600)

    # 自检：证书与私钥是否匹配。必须用「公钥比对」而不是 -modulus ——
    # -modulus 只对 RSA 有效，certbot 等签发的 ECDSA 证书会让 openssl rsa 直接失败。
    def openssl(*args):
        return subprocess.run(["openssl", *args], capture_output=True, text=True).stdout

    crt_pub = openssl("x509", "-noout", "-pubkey", "-in", crt_path).strip()
    key_pub = openssl("pkey", "-pubout", "-in", key_path).strip()
    if not crt_pub or not key_pub:
        raise RuntimeError("部署后自检失败：无法提取公钥（证书或私钥格式异常）")
    if crt_pub != key_pub:
        raise RuntimeError("部署后自检失败：证书与私钥不匹配！")
    subject = openssl("x509", "-noout", "-subject", "-in", crt_path).strip()
    dates = openssl("x509", "-noout", "-dates", "-in", crt_path).strip().replace("\n", " ")
    log(f"  部署完成: {crt_path}")
    log(f"  自检: {subject} | {dates}")


def nginx_reload(cfg):
    ng = cfg.get("nginx_bin", "/usr/sbin/nginx")
    if not os.path.exists(ng):
        ng = "nginx"
    t = subprocess.run([ng, "-t"], capture_output=True, text=True)
    if t.returncode != 0:
        raise RuntimeError(f"nginx -t 失败, 拒绝 reload:\n{t.stderr}")
    subprocess.run(["systemctl", "reload", "nginx"], check=True)
    log("  nginx 配置校验通过并已 reload")


def process_domain(cfg, item, secret_id, secret_key, force=False):
    domain = item["domain"]
    renew_before = int(cfg.get("renew_before_days", 30))
    dv_method = item.get("dv_auth_method") or cfg.get("dv_auth_method", "DNS_AUTO")
    log(f"== {domain} ==")

    existing = list_certs(domain, secret_id, secret_key)
    old_id = None
    if existing:
        newest = existing[0]
        left = (newest["end"] - datetime.datetime.now(datetime.timezone.utc)).days
        log(f"  现有证书 {newest['id']} 到期 {newest['end']:%Y-%m-%d} (剩 {left} 天)")
        if left > renew_before and not force:
            log(f"  剩余 {left} 天 > 阈值 {renew_before} 天, 跳过")
            return "skipped"
        # OldCertificateId 官方文档限定「有效期在 30 天以内且未过期」，超出窗口时不能传，
        # 否则可能被 API 拒绝；此时按「申请新证书」处理（额度 50 张足够）。
        if 0 < left <= 30:
            old_id = newest["id"]
    else:
        log("  未找到已签发证书, 将申请新证书")

    payload = {
        "DomainName": domain,
        "DvAuthMethod": dv_method,
        "PackageType": "83",              # 83 = trustasia c1 dv free
        "Alias": item.get("alias") or f"auto-{domain}",
    }
    if old_id:
        payload["OldCertificateId"] = old_id
        log(f"  以续期方式申请 (OldCertificateId={old_id})")
    r = tc_call("ApplyCertificate", payload, secret_id, secret_key)
    cert_id = r.get("CertificateId")
    log(f"  已提交申请: CertificateId={cert_id} (验证方式 {dv_method})")

    # FILE 验证需要把验证文件放出去；DNS_AUTO 由腾讯云自动加解析
    if dv_method == "FILE":
        d = tc_call("DescribeCertificate", {"CertificateId": cert_id}, secret_id, secret_key)
        write_dcv_file(cfg.get("dcv_dir", "/var/www/pki-validation"), d.get("DvAuthDetail") or {})
        log("  等待 CA 爬虫校验（约 1-15 分钟）…")

    info = wait_issued(cert_id, secret_id, secret_key,
                       timeout=int(cfg.get("issue_timeout_seconds", 1800)))
    log(f"  签发成功, 有效期至 {info.get('CertEndTime')}")

    crt, key = download_and_extract(cert_id, secret_id, secret_key)
    deploy(cfg, item, crt, key)
    return "renewed"


def main():
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        usage()
        return
    if "--version" in args:
        print(TOOL_VERSION)
        return
    cfg = load_config()
    sid, skey = load_credentials()

    if "--check-auth" in args:
        log(f"用 {HOST} 验证凭据与签名链路 …")
        try:
            r = tc_call("DescribeCertificates", {"Limit": 1}, sid, skey)
        except RuntimeError as e:
            log(f"✗ 调用失败: {e}", "ERROR")
            log("  提示: 若错误码是 AuthFailure.SecretIdNotFound / AuthFailure.SignatureFailure，")
            log("        说明请求格式与签名链路本身是通的，只是密钥不对（签名已与官方 SDK 逐字节对齐）。")
            sys.exit(2)
        log(f"✓ 凭据有效, 账号下证书总数 = {r.get('TotalCount', '?')}")
        return

    domains = cfg.get("domains", [])
    if "--domain" in args:
        want = args[args.index("--domain") + 1]
        domains = [d for d in domains if d["domain"] == want]
        if not domains:
            die(f"config.json 里没有域名 {want}")

    if "--list" in args:
        for d in domains:
            certs = list_certs(d["domain"], sid, skey)
            if not certs:
                log(f"  {d['domain']:<20} 无已签发证书")
            for c in certs[:3]:
                left = (c["end"] - datetime.datetime.now(datetime.timezone.utc)).days
                log(f"  {d['domain']:<20} {c['id']:<12} 到期 {c['end']:%Y-%m-%d} 剩 {left} 天")
        return

    force = "--force" in args
    changed = False
    for d in domains:
        try:
            res = process_domain(cfg, d, sid, skey, force=force)
            if res == "renewed":
                changed = True
        except Exception as e:
            log(f"  {d['domain']} 处理失败: {e}", "ERROR")

    if not changed:
        log("没有任何证书被更新, 无需 reload nginx")
    elif "--no-reload" in args:
        log("证书已更新, 但按 --no-reload 要求跳过 reload nginx", "WARN")
    else:
        nginx_reload(cfg)


if __name__ == "__main__":
    main()
