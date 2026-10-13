#!/bin/bash
# 安装腾讯云免费 SSL 证书自动续期（systemd service + timer）
#
# 需要写 /etc → 必须提权运行：
#   sudo bash install.sh
# 幂等：可重复执行。
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======== 1/4 检查前置条件 ========"
if [ ! -f "$SRC/credentials" ]; then
  echo "  ✗ 缺少 $SRC/credentials"
  echo "    请复制模板并填入腾讯云 CAM 子账号密钥："
  echo "      cp $SRC/credentials.template $SRC/credentials && chmod 600 $SRC/credentials"
  exit 1
fi
if [ ! -f "$SRC/config.json" ]; then
  echo "  ✗ 缺少 $SRC/config.json"
  echo "    请复制示例并按你的域名/路径修改："
  echo "      cp $SRC/config.example.json $SRC/config.json"
  exit 1
fi
chmod 600 "$SRC/credentials"
echo "  ✓ 配置与凭据就位"

echo "======== 2/4 校验凭据与签名链路 ========"
python3 "$SRC/tc-cert-auto.py" --check-auth

echo "======== 3/4 生成并安装 systemd 单元 ========"
# 把单元模板里的 __WORKDIR__ 替换成本项目实际路径，避免把绝对路径写死在仓库里
sed "s|__WORKDIR__|$SRC|g" "$SRC/systemd/tc-cert.service.in" > /etc/systemd/system/tc-cert.service
install -m 644 "$SRC/systemd/tc-cert.timer" /etc/systemd/system/tc-cert.timer
systemctl daemon-reload
systemctl enable --now tc-cert.timer
echo "  tc-cert.timer: enabled=$(systemctl is-enabled tc-cert.timer) active=$(systemctl is-active tc-cert.timer)"
echo "  下次触发: $(systemctl list-timers tc-cert.timer --no-pager 2>/dev/null | sed -n 2p | awk '{print $1,$2,$3}')"

echo "======== 4/4 试跑一次（幂等；未到续签窗口会直接跳过）========"
systemctl start tc-cert.service
sleep 2
journalctl -u tc-cert -n 20 --no-pager 2>/dev/null | sed 's/^/  /'

cat <<EOF

安装完成。之后每天自动检查一次，仅当证书剩余 < 30 天时才真正续签并 reload nginx。

常用命令：
  python3 $SRC/tc-cert-auto.py --list        # 查看各域名证书剩余天数
  python3 $SRC/tc-cert-auto.py --force       # 忽略阈值强制走一遍
  python3 $SRC/tc-cert-admin.py --list-all   # 列出账号下全部证书
  systemctl list-timers tc-cert.timer        # 下次触发时间
  journalctl -u tc-cert -n 50                # 运行日志
EOF
