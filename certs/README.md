# certs/ 证书生成说明

本目录用于存放 **设备管理服务器（HTTPS 6999）** 的自签证书。发布包**不包含任何真实证书文件**，本目录仅保留此说明文件，部署时需按以下步骤自行生成。

---

## 一、需要哪些证书

| 用途 | 文件 | 说明 |
|------|------|------|
| 设备管理服务器 TLS（6999/HTTPS） | `certs/device-server.crt`、`certs/device-server.key` | 设备对接管理服务器用的自签证书，`device_tls: true` 时加载 |
| CA 密钥对（加密/签名） | `ca/ca_key.pem`、`ca/ca_cert.pem` | 设备密码 RSA-OAEP 加密、响应签名的 CA 密钥对，见 `ca/readme.txt` |

> 证书文件为敏感私密信息，切勿纳入版本库/发布包；`.gitignore` 中请忽略 `certs/*.crt`、`certs/*.key`、`ca/ca_key.pem`。

---

## 二、生成设备服务器证书（推荐：脚本）

项目提供了现成脚本：

```bash
./scripts/gen-device-cert.sh                       # 仅默认 SANs: localhost/127.0.0.1/::1
./scripts/gen-device-cert.sh device.example.com   # 追加公网域名
./scripts/gen-device-cert.sh xx.xx.xx.xx device.example.com   # 追加公网 IP + 域名
DAYS=730 ./scripts/gen-device-cert.sh device.example.com      # 自定义有效期
```

产出：`certs/device-server.crt`、`certs/device-server.key`（ECDSA P-256 自签，含 SANs）。

手动等价命令：

```bash
mkdir -p certs
openssl ecparam -name prime256v1 -genkey -noout -out certs/device-server.key
chmod 600 certs/device-server.key
openssl req -new -x509 \
  -key certs/device-server.key -out certs/device-server.crt \
  -days 365 -subj "/O=frps-helper/CN=frps-helper-device-server" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1,DNS:device.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"
chmod 644 certs/device-server.crt
```

> 必须把设备实际访问的**公网域名/IP** 加入 SAN（`-addext subjectAltName`），否则设备端证书校验会失败。

---

## 三、生成 CA 密钥对（推荐：脚本）

```bash
./scripts/gen-ca-cert.sh            # 有效期默认 3650 天
DAYS=3650 ./scripts/gen-ca-cert.sh
```

产出：`ca/ca_key.pem`（RSA 2048，PKCS#8）、`ca/ca_cert.pem`（自签，10 年）。

手动等价命令：

```bash
mkdir -p ca
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca/ca_key.pem
chmod 600 ca/ca_key.pem
openssl req -new -x509 -key ca/ca_key.pem -out ca/ca_cert.pem \
  -days 3650 -subj "/CN=FRPS-HELPER-CA" -sha256
chmod 644 ca/ca_cert.pem
```

---

## 四、配置引用

在 `configs/config.yaml` 中配置：

```yaml
frpc:
  device_tls: true
  device_cert_file: "certs/device-server.crt"
  device_key_file:  "certs/device-server.key"
```

---

## 五、检查与校验

```bash
# 查看设备服务器证书信息
openssl x509 -in certs/device-server.crt -noout -subject -issuer -dates -ext subjectAltName

# 校验 CA 证书
openssl x509 -in ca/ca_cert.pem -noout -subject -dates
```

---

## 前置要求

- 需安装 `openssl`（Windows 下可用 Git Bash / WSL / OpenSSL for Windows）。
- 生产环境建议使用有效期更长、由正规 CA 签发的证书替换自签证书。