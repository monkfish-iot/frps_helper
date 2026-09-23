# CA 证书服务

## 一、生成密钥对

# 1. 生成 2048 位 RSA 私钥（PKCS#8 格式）
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca/ca_key.pem

# 2. 提取公钥到自签名证书（有效期 10 年）
openssl req -new -x509 -key ca/ca_key.pem -out ca/ca_cert.pem -days 3650 -subj "/CN=FRPS-HELPER-CA" -sha256

# 3. 设置私钥文件权限
chmod 600 ca/ca_key.pem

# 或直接运行脚本：
#   ./scripts/gen-ca-cert.sh


## 二、目录结构

ca/
├── ca_key.pem    # RSA 私钥（PKCS#8 PEM，必须存在）
├── ca_cert.pem   # 自签名证书（含公钥，必须存在）
└── readme.txt    # 本文件


## 三、API 调用文档

### 初始化

在程序启动时调用一次，dir 传空字符串则默认读取项目根目录下的 ca/。

    ca.Init("")

初始化后通过 ca.Get() 获取单例。

### 函数列表

#### 1. GetPublicKey() *rsa.PublicKey

返回 RSA 公钥对象。

    pub := ca.Get().GetPublicKey()

#### 2. GetPublicKeyPEM() []byte

返回证书的 PEM 原始内容（包含公钥），可直接发给客户端或写入响应。

    pemBytes := ca.Get().GetPublicKeyPEM()

#### 3. Sign(content []byte) (string, error)

用 CA 私钥对 content 进行 SHA256 + PKCS1v15 签名，返回 Base64 编码的签名字符串。

#### 4. Decrypt(ciphertextB64 string) ([]byte, error)

用 CA 私钥解密 Base64 编码的 RSA-OAEP(SHA256) 密文，返回明文字节。


## 四、客户端加密/验签对应方式

客户端（设备侧）需持有 CA 公钥（ca_cert.pem），对应操作：

- 验签：对原始内容做 SHA256 摘要，用公钥按 PKCS1v15 验证 Base64 签名
- 加密：用公钥以 RSA-OAEP(SHA256) 加密数据，Base64 编码后发给服务端

OpenSSL 命令行测试：

# 用公钥加密（服务端 Decrypt 可解密）
echo -n "secret" | openssl pkeyutl -encrypt -pubin -inkey <(openssl x509 -in ca/ca_cert.pem -pubkey -noout) -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64

# 用公钥验签（对应服务端 Sign 的输出）
echo -n "hello world" | openssl dgst -sha256 -verify <(openssl x509 -in ca/ca_cert.pem -pubkey -noout) -signature <(echo "签名Base64" | base64 -d)
