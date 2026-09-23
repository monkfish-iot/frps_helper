#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Monkfish
#
#
# gen-device-cert.sh
#
# 为 frps_helper 设备管理服务器（默认 HTTPS）生成 ECDSA(P-256) 自签证书。
# 与 frpc/tls.go 中 resolveDeviceTLS/generateSelfSignedCert 的自签逻辑等价，
# 可在不想依赖运行时自动生成时手动产出证书，或用于生产环境替换为更长期的证书。
#
# 默认产出位置（相对项目根）：
#   certs/device-server.crt
#   certs/device-server.key
#
# 默认 SANs：DNS:localhost, IP:127.0.0.1, IP:::1
# 可通过参数追加额外的 host/IP（例如公网域名或 IP），自动识别为 DNS 或 IP。
#
# 用法：
#   ./scripts/gen-device-cert.sh                       # 仅含默认 SANs
#   ./scripts/gen-device-cert.sh device.example.com    # 追加 DNS
#   ./scripts/gen-device-cert.sh 117.72.8.94 device.example.com  # 追加 IP + DNS
#   DAYS=730 ./scripts/gen-device-cert.sh device.example.com     # 自定义有效期 730 天
#
# 前置：需安装 openssl（Windows 可用 Git Bash / WSL / OpenSSL for Windows）。
#
set -e

# ---- 配置 ----
CERT_DIR="certs"
CERT_FILE="${CERT_DIR}/device-server.crt"
KEY_FILE="${CERT_DIR}/device-server.key"
DAYS="${DAYS:-365}"
ORG="frps-helper"
CN="frps-helper-device-server"

# ---- 校验 openssl ----
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl 未安装。请先安装 openssl（Windows 可用 Git Bash / WSL / OpenSSL for Windows）。" >&2
  exit 1
fi

# ---- 解析额外 SAN host 参数 ----
EXTRA_DNS=()
EXTRA_IP=()
for arg in "$@"; do
  if [[ "$arg" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    EXTRA_IP+=("$arg")
  elif [[ "$arg" =~ ^\[?([0-9a-fA-F:]+)\]?$ ]]; then
    EXTRA_IP+=("$arg")
  else
    EXTRA_DNS+=("$arg")
  fi
done

# ---- 组装 subjectAltName ----
SAN="DNS:localhost,IP:127.0.0.1,IP:::1"
for d in "${EXTRA_DNS[@]}"; do
  SAN="${SAN},DNS:${d}"
done
for ip in "${EXTRA_IP[@]}"; do
  SAN="${SAN},IP:${ip}"
done

# ---- 创建目录 ----
mkdir -p "${CERT_DIR}"

# ---- 生成 EC P-256 私钥 ----
echo "Generating ECDSA(P-256) private key: ${KEY_FILE}"
openssl ecparam -name prime256v1 -genkey -noout -out "${KEY_FILE}"
chmod 600 "${KEY_FILE}"

# ---- 生成自签证书（含 SANs）----
echo "Generating self-signed certificate: ${CERT_FILE} (valid ${DAYS} days)"
openssl req -new -x509 \
  -key "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -days "${DAYS}" \
  -subj "/O=${ORG}/CN=${CN}" \
  -addext "subjectAltName=${SAN}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

chmod 644 "${CERT_FILE}"

# ---- 输出证书信息供核对 ----
echo ""
echo "=== Certificate info ==="
openssl x509 -in "${CERT_FILE}" -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || \
  openssl x509 -in "${CERT_FILE}" -noout -subject -issuer -dates

echo ""
echo "Done. 配置参考（config.yaml）："
echo "  frpc:"
echo "    device_tls: true"
echo "    device_cert_file: \"${CERT_FILE}\""
echo "    device_key_file:  \"${KEY_FILE}\""
