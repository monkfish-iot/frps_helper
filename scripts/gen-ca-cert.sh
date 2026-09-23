#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Monkfish
#
#
# gen-ca-cert.sh
#
# 生成 CA 根证书（RSA 2048，PKCS#8 格式），用于 frps_helper 的 CA 服务。
# 产出文件：
#   ca/ca_key.pem   — RSA 私钥
#   ca/ca_cert.pem  — 自签名证书（含公钥，有效期 10 年）
#
# 用法：
#   ./scripts/gen-ca-cert.sh
#   DAYS=3650 ./scripts/gen-ca-cert.sh
#
# 前置：需安装 openssl。
#
set -e

# ---- 配置 ----
CA_DIR="ca"
KEY_FILE="${CA_DIR}/ca_key.pem"
CERT_FILE="${CA_DIR}/ca_cert.pem"
DAYS="${DAYS:-3650}"
CN="${CN:-FRPS-HELPER-CA}"

# ---- 校验 openssl ----
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl 未安装。请先安装 openssl。" >&2
  exit 1
fi

# ---- 创建目录 ----
mkdir -p "${CA_DIR}"

# ---- 1. 生成 2048 位 RSA 私钥（PKCS#8 格式）----
echo "Generating RSA private key: ${KEY_FILE}"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY_FILE}"
chmod 600 "${KEY_FILE}"

# ---- 2. 生成自签名证书（有效期 10 年）----
echo "Generating self-signed CA certificate: ${CERT_FILE} (valid ${DAYS} days)"
openssl req -new -x509 -key "${KEY_FILE}" -out "${CERT_FILE}" -days "${DAYS}" -subj "/CN=${CN}" -sha256
chmod 644 "${CERT_FILE}"

# ---- 输出证书信息 ----
echo ""
echo "=== CA certificate info ==="
openssl x509 -in "${CERT_FILE}" -noout -subject -issuer -dates

echo ""
echo "Done. CA 密钥对已生成："
echo "  私钥: ${KEY_FILE}"
echo "  证书: ${CERT_FILE}"
