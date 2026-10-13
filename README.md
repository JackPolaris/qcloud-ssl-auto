# 腾讯云免费 SSL 证书自动化

用自己的服务器 + 腾讯云签发的**免费 DV 证书**，实现 **全自动申请 / 续期 / 部署 / reload nginx**。

## 为什么需要它

腾讯云的免费 SSL 证书**本身能自动续期**，但它的「自动托管」只支持**腾讯云自有资源**
（CLB、CDN、WAF、对象存储等 14 种）。如果你的站点跑在**自建服务器 / 其它云厂商的 VPS** 上，
官方控制台帮不到你 —— 只能每 90 天手工「申请 → 等签发 → 下载 zip → 解压 → 上传到服务器 → 重载 nginx」。

本项目就是把这一串手工流程自动化，并且**不引入任何第三方依赖**。

> 顺带说明：为什么不干脆用 Let's Encrypt？两条路都可行，本项目面向的是
> **明确希望证书由腾讯云签发**的场景（例如统一在腾讯云控制台管理、审计、或团队规范要求）。

## 特性

| 特性 | 说明 |
| --- | --- |
| 零第三方依赖 | TC3-HMAC-SHA256 签名用 Python **标准库**手写，不装 SDK、不装 CLI |
| 幂等 | 每天跑都安全：证书剩余有效期 > 阈值时立刻退出，不做任何改动 |
| 安全阀 ① | 部署前逐字校验新证书 **SAN 必须覆盖 `required_sans`**，缺失则**拒绝部署并保留旧证书**（判定发生在改动任何文件之前） |
| 安全阀 ② | 部署后做**证书/私钥公钥比对**自检，不匹配立即报错（用公钥而非 `-modulus`，RSA/ECDSA 通吃） |
| 签名经交叉验证 | 与**腾讯云官方 Python SDK** 做固定时间戳逐字节对比，6 个用例 × 6 个请求头字段全部一致 |
| systemd 加固 | `ProtectSystem=full` + `ReadWritePaths=/etc/nginx/ssl`，脚本**只**能写证书目录 |
| 凭据隔离 | 密钥文件权限 600 且被 `.gitignore` 忽略；实际配置 `config.json` 同样不入库 |

## 工作原理

```
systemd timer（每天一次，带随机延迟）
        │
        ▼
tc-cert-auto.py
        │
        ├─ DescribeCertificates      查现有证书，算剩余天数
        │     └─ 剩余 > 30 天 → 直接退出（幂等）
        │
        ├─ ApplyCertificate          申请新证书（DNS_AUTO 由腾讯云自动加解析记录）
        │
        ├─ DescribeCertificate       轮询直到签发完成（status 0→1）
        │
        ├─ DownloadCertificate       拿到 base64 的 zip
        │     └─ 解压取 Nginx/*_bundle.crt + *.key
        │
        ├─ SAN 校验  ★安全阀①         不覆盖 required_sans 就中止，旧证书原样保留
        ├─ 备份旧文件 → 写入新文件
        ├─ 公钥比对自检  ★安全阀②      证书与私钥必须配套
        │
        └─ nginx -t && systemctl reload nginx
```

腾讯云免费证书的几个事实（会直接影响用法）：

- **有效期 90 天**，续期 = 申请一张新证书（不能原地续），额度 **50 张/账号**
- **不支持泛域名**，只支持单域名
- 申请**根域名会自动赠送 `www.<根域名>`**（本项目用 `required_sans` 兜底这个平台行为）

## 快速开始

### 1. 建一个 CAM 子账号（不要用主账号密钥）

打开 <https://console.cloud.tencent.com/cam> → 用户 → 用户列表 → **新建用户** → **自定义创建**：

1. 「访问方式」只勾 **编程访问**（不要给控制台登录密码）
2. 「设置用户权限」**不要勾任何预设策略**（尤其别勾 `QcloudSSLFullAccess`）→
   点「新建自定义策略」→「按策略语法创建」→ 粘贴本仓库的
   [`cam-policy-minimal.json`](cam-policy-minimal.json) → 命名如 `ssl-auto-renew-minimal` → 保存并勾选
3. 创建完成后页面会显示 **SecretId / SecretKey —— 只显示这一次**，当场复制

所需权限说明（`resource` 只能是 `*`，因为 `ApplyCertificate` 是创建类接口，没有具体资源可限定）：

```
ssl:ApplyCertificate            申请免费证书
ssl:DescribeCertificates        列出现有证书（判断是否临近到期）
ssl:DescribeCertificate         轮询签发状态 / FILE 模式取验证信息
ssl:DescribeCertificateDetail   详情
ssl:DownloadCertificate         下载证书 zip
ssl:DeleteCertificate           可选，本脚本不删旧证书，可按需去掉这项
```

### 2. 配置

```bash
cp config.example.json config.json     # 改成你的域名与证书路径
cp credentials.template credentials
chmod 600 credentials                  # 填入 SecretId / SecretKey
```

`config.json` 关键字段：

| 字段 | 说明 |
| --- | --- |
| `dv_auth_method` | `DNS_AUTO` = 域名解析在该账号的「云解析 DNS」里，腾讯自动加记录，**全自动无需人工**；`FILE` = 在站点放验证文件（需 CA 爬虫可达该域名） |
| `renew_before_days` | 剩余有效期小于此值才续签，默认 30 |
| `domains[].crt_path` / `key_path` | 证书与私钥要部署到哪（nginx 里 `ssl_certificate` 指向的路径） |
| `domains[].required_sans` | **安全阀**：新证书必须覆盖的域名清单，缺一个就拒绝部署 |

### 3. 安装

```bash
sudo bash install.sh
```

脚本会：校验凭据与签名链路 → 用模板生成并安装 systemd 单元（把 `__WORKDIR__`
替换成本项目实际路径）→ 启用 `tc-cert.timer` → 试跑一次。

## 命令参考

```bash
python3 tc-cert-auto.py                 # 处理 config.json 里全部域名
python3 tc-cert-auto.py --list          # 只列出现有证书与剩余天数（只读）
python3 tc-cert-auto.py --check-auth    # 只验证密钥与签名链路（只读）
python3 tc-cert-auto.py --domain <域名>  # 只处理某个域名
python3 tc-cert-auto.py --force         # 忽略阈值强制走一遍（排障用）
python3 tc-cert-auto.py --no-reload     # 部署但不 reload nginx

python3 tc-cert-admin.py --list-all     # 列出账号下全部证书（含绑定资源风险字段）
python3 tc-cert-admin.py --delete <ID>  # 删除指定证书
python3 tc-cert-admin.py --delete-all   # 删除全部（默认跳过已绑定云资源的证书，防止打断线上服务）

python3 tests/test_signature_parity.py  # 与官方 SDK 交叉验证签名

systemctl list-timers tc-cert.timer     # 下次触发时间
journalctl -u tc-cert -n 50             # 运行日志
```

## ⚠️ 安全说明（请务必读）

1. **这个密钥能读取你账号下任意证书的私钥。**
   `ssl:DownloadCertificate` 的权限范围是整个账号，不分域名。因此：
   - 一定用**子账号**密钥，不要用主账号
   - 不要给子账号勾控制台登录
   - `credentials` 保持 `chmod 600`，且已被 `.gitignore` 忽略

2. **不要把密钥贴进任何聊天/issue/日志。** 本项目的报错信息不会打印密钥内容，
   但你自己操作时要注意。

3. **想进一步降低风险**：把本脚本放在服务器之外运行（如 CI 定时任务、
   另一台跳板机），只把签好的证书推送到目标服务器 —— 这样目标服务器上完全不需要云 API 密钥。
   为此可以把 `config.json` 里的 `crt_path`/`key_path` 指向一个中转目录，
   再用 `--no-reload` 配合你自己的分发脚本。

4. **`.gitignore` 已排除**：`credentials`、`config.json`、`pylibs/`、`__pycache__/`、`*.bak-*`。
   提交前建议自己再核一遍：`git status` 与 `git diff --cached`。

## 常见问题

**Q：`--check-auth` 报 `AuthFailure.SignatureFailure`？**
签名算法本身已与官方 SDK 逐字节对齐（可跑 `tests/test_signature_parity.py` 复验），
该错误通常意味着 SecretKey 填错或有多余空格/换行。

**Q：`FailedOperation.ExceedsFreeLimit` / `MainDomainCertificateCountLimit`？**
免费证书额度用尽（50 张/账号），或同一主域名下申请过多。可先用
`tc-cert-admin.py --list-all` 看看是否堆积了大量历史证书并清理。

**Q：签发卡在 `status=4`（已添加 DNS 记录）很久？**
`DNS_AUTO` 依赖域名解析在本账号的「云解析 DNS」里且与该域名同账号。
若不是，请改用 `FILE` 验证，并确保 CA 爬虫能访问到验证文件
（腾讯云给出的爬虫 IP 白名单：`64.78.193.238`、`216.168.247.9`、`216.168.249.9`、`54.189.196.217`）。
另外注意：若 80 端口做了「全局 301 跳 HTTPS」，务必为该域名的
`/.well-known/pki-validation/` 路径单独放行，否则爬虫会被跳走、永远验证不过。

**Q：`FILE` 模式验证目录是哪个？**
`config.json` 的 `dcv_dir`（默认 `/var/www/pki-validation`），你需要在自己的
nginx 里把该目录映射到 `http://<域名>/.well-known/pki-validation/`。

**Q：为什么不用官方 SDK 而要手写签名？**
为了**零依赖** —— 目标环境是一台只装了 python3 的服务器，装 SDK 会拖进
`requests`/`certifi`/`urllib3` 等一串包，且需要联网 pip。手写 TC3 签名约 40 行，
并且用官方 SDK 做了逐字节交叉验证（见 `tests/`）。若你更想用 SDK，把
`tc_call()` 里那段换成 SDK 调用即可。

**Q：改了 `config.json` 需要重新安装吗？**
不需要。`config.json` 是运行时读取的，下次定时任务就用新配置。改了
`systemd/*.service.in` 才需要重跑 `install.sh`。

## 已验证

- 签名一致性：与 `tencentcloud-sdk-python-common` 固定时间戳对比，
  **6 个用例 × 6 个请求头字段全部逐字节一致**（含 `Authorization`、`X-TC-Version` 等）
- 真实环境跑通：申请 → DNS_AUTO 自动验证 → 下载 → 部署 → `nginx -t` → reload 全链路
- SAN 安全阀：用不含 `www` 的证书冒充根域名证书时**正确拦截，且未改动任何文件**
- systemd 加固：确认脚本可写证书目录、可 reload nginx，而越界写
  `/etc/nginx/sites-available` 被拒绝

## License

MIT，见 [LICENSE](LICENSE)。
