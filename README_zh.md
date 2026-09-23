# frps_helper

**[English](README.md)** / **中文**

[`xfrpc_loader`](https://github.com/monkfish-iot/xfrpc_loader) 的云端配套服务端。用于**批量、安全地**让 OpenWrt 设备接入 frps 并**集中管理**，同时为它们的 HTTP/HTTPS Web（LuCI）登录提供**集中用户鉴权**——分散的设备管理密码被安全集中托管，而不再硬编码在每台盒子上。

> - 语言：Go
> - 许可：Apache-2.0
> - 依赖：`xfrpc_loader` 设备端（需 xfrpc 5.x 及以上）
> - 设备端守护进程：[`xfrpc_loader`](https://github.com/monkfish-iot/xfrpc_loader)
> - OpenWrt 包：[`openwrt-xfrpc_loader`](https://github.com/monkfish-iot/openwrt-xfrpc_loader)

---

## 功能概览

`frps_helper` 在一个进程中提供三组隔离的 HTTP 服务：

| 方向 | 服务 | 端口 | 用途 |
|------|------|------|------|
| 南向 | 设备对接服务器（HTTPS） | 6999 | 设备加入（join）、状态上报、登录认证、健康检查 |
| frpc 认证 | FRPS 认证服务器（HTTP） | 8089 | FRPS 第三方认证（原 frps-authd 功能），设备接入隧道时鉴权 |
| 北向 | 独立管理服务器（HTTPS） | 7443 | 设备查询（分页+条件）、手动注册/批准、自动注册开关配置 |

## 核心特性

- **加入与会话管理** — 设备 `join` 获得 `session_id`，状态上报续期，空闲会话过期（默认 180s），单设备单会话。
- **自动/白名单注册** — `auto_register` 可运行时调整；关闭时未授权设备 join 被拒并记录为 `pending`。
- **FRPS 第三方认证** — 实现 frps `httpPlugins`（`Login` / `Ping`），校验设备会话并替换 `run_id` 为 `session_id`。
- **北向管理接口** — 设备分页查询与条件过滤、手动注册/批准、配置查看/修改；可选明文凭证查询 `GET /api/v1/credentials/{device_id}`（默认关闭，支持 Bearer token）。
- **存储** — 默认 SQLite，可选 PostgreSQL。
- **安全** — 设备/管理接口默认 HTTPS（自签证书自动生成），统一响应信封 `{error_code, msg, body}`；设备 join 注册的密码使用 CA 公钥加密（RSA-OAEP-SHA256）后入库。
- **日志审计** — 结构化日志（logrus），join 拒绝原因、认证失败均完整记录。

---

## 快速开始

### 构建

要求 Go 1.21+（模块声明 `go 1.26.1`，建议使用相近或更新的工具链）。

```bash
cd frps_helper
go build -o frps_helper .
```

### 运行

```bash
# 使用默认配置（configs/config.yaml）
./frps_helper

# 指定配置文件
./frps_helper -config path/to/config.yaml
```

启动后日志应出现：

```
[FRPC] auth server starting on :8089 (HTTP)
[FRPC] device server starting on :6999 (HTTPS)
[FRPC] manage server starting on :7443 (HTTPS)
```

### 配置

编辑 [configs/config.yaml](configs/config.yaml)（或参考 [config.example.yaml](configs/config.example.yaml)）：

```yaml
frpc:
  enable: true          # 必须为 true 才启动三个服务
  auto_register: true   # 是否允许设备首次 join 自动注册
  port: 8089            # FRPS 认证 HTTP 端口
  device_port: 6999     # 设备对接 HTTPS 端口
  manage_port: 7443     # 独立管理 HTTPS 端口
  xfrpc_server_addr: "127.0.0.1"  # 下发给设备的 xfrpc(frps) 地址
  xfrpc_server_port: 7000         # 下发给设备的 xfrpc(frps) 端口
  credential_query: false          # 是否开放明文凭证查询接口（默认关闭）
  # credential_token: "xxxx"       # 可选，设置后查询接口需带 Bearer 令牌
```

> 证书：设备/管理服务器共用自签证书 `certs/device-server.{crt,key}`，SANs 需覆盖访问 IP/域名。可用 `scripts/gen-device-cert.sh <host>` 生成，或删除证书让服务启动时自动生成。详见 [certs/README.md](certs/README.md)。

### FRPS 侧对接（frpc 认证）

frps 配置片段（详见 [docs/frpc认证接口规范.md](docs/frpc认证接口规范.md)）：

```ini
[[httpPlugins]]
name = "my-auth"
addr = "127.0.0.1:8089"
path = "/handler"
ops = ["Login", "Ping"]
```

---

## 接口文档

| 文档 | 方向 | 内容 |
|------|------|------|
| [docs/南向接口规范.md](docs/南向接口规范.md) | 南向（设备） | join / status / auth / health，报文格式、会话管理、错误码 |
| [docs/frpc认证接口规范.md](docs/frpc认证接口规范.md) | frpc 认证 | FRPS 第三方认证（/handler、/clients、/health），鉴权规则 |
| [docs/北向接口规范.md](docs/北向接口规范.md) | 北向（管理） | 设备查询/批准、auto_register 配置，分页与条件过滤 |
| [docs/接口测试指南.md](docs/接口测试指南.md) | 使用示例 | 按场景组合调用接口的 curl 示例 |
| [docs/客户端适配规范.md](docs/客户端适配规范.md) | 客户端契约 | xfrpc_loader 客户端适配契约与变更记录 |
| [docs/相关系统的安装说明.md](docs/相关系统的安装说明.md) | 安装 | 整套系统的安装/运行说明 |

---

## 目录结构

```
frps_helper/
├── main.go               # 入口
├── config/               # 配置加载
├── configs/              # 配置文件（config.yaml / config.example.yaml）
├── database/             # 数据库初始化（SQLite / PostgreSQL）
├── frpc/                 # 三个服务实现（device/device_manage/auth）
├── models/               # 数据模型（devices 表）
├── api/                  # 统一响应封装
├── pkg/                  # ca / logger / util 工具
├── scripts/              # 证书生成脚本
├── certs/                # 运行期证书（自动生成）
├── docs/                 # 接口规范与使用文档
└── data/                 # SQLite 数据库文件
```

---

## 相关仓库

- [`xfrpc_loader`](https://github.com/monkfish-iot/xfrpc_loader) — 设备端 C 守护进程
- [`openwrt-xfrpc_loader`](https://github.com/monkfish-iot/openwrt-xfrpc_loader) — OpenWrt 包
- [`xfrpc5`](https://github.com/monkfish-iot/xfrpc5) — 预编译 xfrpc 客户端包（需 5.x）

---

## 开源许可

基于 **Apache License 2.0** 发布。详见随附的 [LICENSE](LICENSE) 与 [NOTICE](NOTICE) 文件，或 [Apache 2.0 官方文本](https://www.apache.org/licenses/LICENSE-2.0)。
