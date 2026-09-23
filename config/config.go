// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Monkfish
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	FRPC     FRPCConfig     `mapstructure:"frpc"`
	Log      LogConfig      `mapstructure:"log"`
}

type DatabaseConfig struct {
	Type         string `mapstructure:"type"`     // sqlite | postgres，默认 sqlite
	File         string `mapstructure:"file"`     // SQLite 文件路径
	Host         string `mapstructure:"host"`     // PostgreSQL 主机
	Port         int    `mapstructure:"port"`     // PostgreSQL 端口
	Username     string `mapstructure:"username"` // PostgreSQL 用户名
	Password     string `mapstructure:"password"` // PostgreSQL 密码
	Database     string `mapstructure:"database"` // PostgreSQL 数据库名
	SSLMode      string `mapstructure:"sslmode"`  // PostgreSQL SSL 模式
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
}

type FRPCConfig struct {
	Enable          bool     `mapstructure:"enable"`            // 是否启用
	AutoRegister    bool     `mapstructure:"auto_register"`     // 是否允许设备首次 join 时自动注册
	Port            int      `mapstructure:"port"`              // FRPS 认证 HTTP 端口
	AuthBind        string   `mapstructure:"auth_bind"`         // 认证端口绑定地址，默认 127.0.0.1
	AuthWhitelist   []string `mapstructure:"auth_whitelist"`    // 认证端口访问白名单（IP/CIDR），默认 127.0.0.1
	FrpsAdmin       string   `mapstructure:"frps_admin"`        // FRPS 管理用户名
	FrpsPassword    string   `mapstructure:"frps_password"`     // FRPS 管理密码
	FrpsPort        int      `mapstructure:"frps_port"`         // FRPS 端口
	DevicePort      int      `mapstructure:"device_port"`       // 设备管理 HTTPS 端口
	ManagePort      int      `mapstructure:"manage_port"`       // 独立管理 HTTPS 端口
	ManageBind      string   `mapstructure:"manage_bind"`       // 管理端口绑定地址，默认 127.0.0.1
	ManageWhitelist []string `mapstructure:"manage_whitelist"`  // 管理端口访问白名单（IP/CIDR），默认 127.0.0.1
	CredentialQuery bool     `mapstructure:"credential_query"`  // 是否开放北向明文凭证查询接口（默认 false=关闭）
	CredentialToken string   `mapstructure:"credential_token"`  // 查询接口可选 Bearer 令牌，为空则不校验
	DeviceTLS       bool     `mapstructure:"device_tls"`        // 是否启用 HTTPS
	DeviceCertFile  string   `mapstructure:"device_cert_file"`  // TLS 证书文件路径
	DeviceKeyFile   string   `mapstructure:"device_key_file"`   // TLS 私钥文件路径
	XfrpcServerAddr string   `mapstructure:"xfrpc_server_addr"` // 下发给设备的 xfrpc 服务端地址
	XfrpcServerPort int      `mapstructure:"xfrpc_server_port"` // 下发给设备的 xfrpc 服务端端口
	StatusInterval  int      `mapstructure:"status_interval"`   // 设备状态上报周期（秒）
	SessionTTL      int      `mapstructure:"session_ttl"`       // 会话超时（秒）
	OfflineTimeout  int      `mapstructure:"offline_timeout"`   // 心跳超时阈值（秒）：超过此时间未收到心跳则标记离线，默认取 session_ttl
}

type LogConfig struct {
	Level      string `mapstructure:"level"`
	Output     string `mapstructure:"output"`
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

var Cfg *Config

func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	Cfg = &config
	return &config, nil
}

func Get() *Config {
	return Cfg
}
