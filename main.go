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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"frps_helper/config"
	"frps_helper/database"
	"frps_helper/frpc"
	"frps_helper/pkg/ca"
	"frps_helper/pkg/logger"
)

// appVersion 产品版本号（与仓库发布标签保持一致）
const appVersion = "0.0.1"

// applyBaseDir 将进程工作目录切换到 dir。
// dir 为空时不切换，沿用当前目录；指定时，配置中的相对路径
// （configs/、ca/、certs/、data/、logs/ 等）均以 dir 为基准。
func applyBaseDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve base dir %q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("create base dir %q: %w", abs, err)
	}
	if err := os.Chdir(abs); err != nil {
		return fmt.Errorf("chdir %q: %w", abs, err)
	}
	return nil
}

func main() {
	baseDir := flag.String("d", "", "运行目录：configs/ca/data/certs/logs 等相对路径均以此为基准（默认当前工作目录）")
	configPath := flag.String("config", "configs/config.yaml", "配置文件路径（相对运行目录）")
	flag.Parse()

	// 0. 应用运行目录（-d 未指定时保持当前目录，相对路径行为不变）
	if err := applyBaseDir(*baseDir); err != nil {
		panic("failed to apply base dir: " + err.Error())
	}

	// 1. 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	// 2. 初始化日志
	logConfig := &logger.LogConfig{
		Level:      cfg.Log.Level,
		Output:     cfg.Log.Output,
		FilePath:   cfg.Log.FilePath,
		MaxSize:    cfg.Log.MaxSize,
		MaxBackups: cfg.Log.MaxBackups,
		MaxAge:     cfg.Log.MaxAge,
	}
	if logConfig.Level == "" {
		logConfig.Level = "info"
	}
	logger.InitLogger(logConfig)
	logger.Infof("=== frps_helper v%s starting ===", appVersion)
	if wd, err := os.Getwd(); err == nil {
		logger.Infof("base dir: %s (config: %s)", wd, *configPath)
	}

	// 3. 初始化数据库
	dbCfg := &database.DatabaseConfig{
		Type:         cfg.Database.Type,
		File:         cfg.Database.File,
		Host:         cfg.Database.Host,
		Port:         cfg.Database.Port,
		Username:     cfg.Database.Username,
		Password:     cfg.Database.Password,
		Database:     cfg.Database.Database,
		SSLMode:      cfg.Database.SSLMode,
		MaxIdleConns: cfg.Database.MaxIdleConns,
		MaxOpenConns: cfg.Database.MaxOpenConns,
	}
	db, err := database.InitDB(dbCfg)
	if err != nil {
		logger.Fatalf("failed to init database: %v", err)
	}
	logger.Infof("database initialized: type=%s", func() string {
		if dbCfg.Type == "" {
			return "sqlite"
		}
		return dbCfg.Type
	}())

	// 4. 初始化 CA（best-effort，不阻断启动）
	if err := ca.Init(""); err != nil {
		logger.Warnf("[CA] certificate service not available: %v (skip if ca/ directory not needed)", err)
	}

	// 5. 启动 FRPC 服务
	if !cfg.FRPC.Enable {
		logger.Warn("frpc service is disabled, skipping startup")
		// 即使禁用也保持进程运行（便于仅作为数据库管理工具）
	} else {
		frpcCfg := frpc.Config{
			Enable:          cfg.FRPC.Enable,
			AutoRegister:    cfg.FRPC.AutoRegister,
			Port:            cfg.FRPC.Port,
			AuthBind:        cfg.FRPC.AuthBind,
			AuthWhitelist:   cfg.FRPC.AuthWhitelist,
			FrpsAdmin:       cfg.FRPC.FrpsAdmin,
			FrpsPassword:    cfg.FRPC.FrpsPassword,
			FrpsPort:        cfg.FRPC.FrpsPort,
			DevicePort:      cfg.FRPC.DevicePort,
			ManagePort:      cfg.FRPC.ManagePort,
			ManageBind:      cfg.FRPC.ManageBind,
			ManageWhitelist: cfg.FRPC.ManageWhitelist,
			CredentialQuery: cfg.FRPC.CredentialQuery,
			CredentialToken: cfg.FRPC.CredentialToken,
			DeviceTLS:       cfg.FRPC.DeviceTLS,
			DeviceCertFile:  cfg.FRPC.DeviceCertFile,
			DeviceKeyFile:   cfg.FRPC.DeviceKeyFile,
			XfrpcServerAddr: cfg.FRPC.XfrpcServerAddr,
			XfrpcServerPort: cfg.FRPC.XfrpcServerPort,
			StatusInterval:  cfg.FRPC.StatusInterval,
			SessionTTL:      cfg.FRPC.SessionTTL,
			OfflineTimeout:  cfg.FRPC.OfflineTimeout,
		}

		server := frpc.New(frpcCfg, db)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := server.Start(ctx); err != nil {
			logger.Fatalf("failed to start frpc server: %v", err)
		}
	}

	// 6. 等待退出信号
	_ = db // keep db reference
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Infof("received signal %v, shutting down...", sig)
	logger.Info("=== frps_helper stopped ===")
}
