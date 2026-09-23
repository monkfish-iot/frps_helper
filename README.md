# frps_helper

**English** / **[中文](README_zh.md)**

The cloud-side companion server for [`xfrpc_loader`](https://github.com/monkfish-iot/xfrpc_loader). It lets you **batch-onboard and centrally manage OpenWrt devices** to frps, and provides **centralized user authentication** for their HTTP/HTTPS web (LuCI) logins — so scattered device admin passwords are safely held in one place instead of hardcoded on each box.

> - Language: Go
> - License: Apache-2.0
> - Requires: `xfrpc_loader` devices (xfrpc 5.x or later)
> - Device-side daemon: [`xfrpc_loader`](https://github.com/monkfish-iot/xfrpc_loader)
> - OpenWrt package feed: [`openwrt-xfrpc_loader`](https://github.com/monkfish-iot/openwrt-xfrpc_loader)

---

## What It Does

`frps_helper` runs three isolated HTTP services in a single process:

| Direction | Service | Port | Purpose |
|-----------|---------|------|---------|
| Southbound | Device server (HTTPS) | 6999 | Device join / status report / login auth / health check |
| frpc auth | FRPS auth server (HTTP) | 8089 | FRPS third-party authentication (former `frps-authd`), authenticates devices joining tunnels |
| Northbound | Manage server (HTTPS) | 7443 | Device query (pagination + filters), manual register/approve, auto-register toggle |

## Key Features

- **Join & session management** — devices `join` to get a `session_id`; status reports renew the session; idle sessions expire (default 180 s); one session per device.
- **Auto / whitelist registration** — `auto_register` can be toggled at runtime; when off, unauthorized joins are rejected and recorded as `pending`.
- **FRPS third-party auth** — implements frps `httpPlugins` (`Login` / `Ping`), validates the device session, and replaces `run_id` with `session_id`.
- **Northbound manage API** — paginated device queries with filters, manual register/approve, config view/modify; optional plaintext credential query `GET /api/v1/credentials/{device_id}` (off by default, Bearer-token guarded).
- **Storage** — SQLite by default, PostgreSQL optional.
- **Security** — device/manage servers default to HTTPS (self-signed certs auto-generated); unified response envelope `{error_code, msg, body}`; join-registered passwords encrypted with the CA public key (RSA-OAEP-SHA256) before storage.
- **Audit logging** — structured logs (logrus); join rejection reasons and auth failures are fully recorded.

---

## Getting Started

### Build

Requires Go 1.21+ (module declares `go 1.26.1`; use a recent toolchain).

```bash
cd frps_helper
go build -o frps_helper .
```

### Run

```bash
# Default config (configs/config.yaml)
./frps_helper

# Explicit config
./frps_helper -config path/to/config.yaml
```

On startup the logs should show:

```
[FRPC] auth server starting on :8089 (HTTP)
[FRPC] device server starting on :6999 (HTTPS)
[FRPC] manage server starting on :7443 (HTTPS)
```

### Configuration

Edit [configs/config.yaml](configs/config.yaml) (or see [config.example.yaml](configs/config.example.yaml)):

```yaml
frpc:
  enable: true          # must be true to start the three services
  auto_register: true   # allow devices to self-register on first join
  port: 8089            # FRPS auth HTTP port
  device_port: 6999     # device HTTPS port
  manage_port: 7443     # manage HTTPS port
  xfrpc_server_addr: "127.0.0.1"  # xfrpc(frps) address handed to devices
  xfrpc_server_port: 7000         # xfrpc(frps) port handed to devices
  credential_query: false          # open plaintext credential query API (off by default)
  # credential_token: "xxxx"       # optional; requires Bearer token for the query API
```

> Certificates: device/manage servers share the self-signed cert `certs/device-server.{crt,key}`; SANs must cover the access IP/hostname. Generate with `scripts/gen-device-cert.sh <host>`, or delete the certs to let the server auto-generate them at startup. See [certs/README.md](certs/README.md).

### FRPS integration (frpc auth)

frps config snippet (details in [docs/frpc认证接口规范.md](docs/frpc认证接口规范.md)):

```ini
[[httpPlugins]]
name = "my-auth"
addr = "127.0.0.1:8089"
path = "/handler"
ops = ["Login", "Ping"]
```

---

## Documentation

| Doc | Direction | Contents |
|-----|-----------|----------|
| [docs/南向接口规范.md](docs/南向接口规范.md) | Southbound (device) | join / status / auth / health, message formats, session handling, error codes |
| [docs/frpc认证接口规范.md](docs/frpc认证接口规范.md) | frpc auth | FRPS third-party auth (/handler, /clients, /health), auth rules |
| [docs/北向接口规范.md](docs/北向接口规范.md) | Northbound (manage) | device query/approve, auto_register config, pagination & filters |
| [docs/接口测试指南.md](docs/接口测试指南.md) | Usage examples | curl examples combining the APIs per scenario |
| [docs/客户端适配规范.md](docs/客户端适配规范.md) | Client contract | adaptation contract & changelog for xfrpc_loader clients |
| [docs/相关系统的安装说明.md](docs/相关系统的安装说明.md) | Setup | install/run notes for the whole system |

---

## Repository Layout

```
frps_helper/
├── main.go               # entry point
├── config/               # config loading
├── configs/              # config files (config.yaml / config.example.yaml)
├── database/             # DB init (SQLite / PostgreSQL)
├── frpc/                 # the three services (device / device_manage / auth)
├── models/               # data models (devices table)
├── api/                  # unified response envelope
├── pkg/                  # ca / logger / util helpers
├── scripts/              # certificate generation scripts
├── certs/                # runtime certs (auto-generated)
├── docs/                 # interface specifications & guides
└── data/                 # SQLite database file
```

---

## Related Repos

- [`xfrpc_loader`](https://github.com/monkfish-iot/xfrpc_loader) — device-side C daemon
- [`openwrt-xfrpc_loader`](https://github.com/monkfish-iot/openwrt-xfrpc_loader) — OpenWrt package feed
- [`xfrpc5`](https://github.com/monkfish-iot/xfrpc5) — prebuilt xfrpc client package (requires 5.x)

---

## License

Licensed under **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE), or the [official Apache-2.0 text](https://www.apache.org/licenses/LICENSE-2.0).
