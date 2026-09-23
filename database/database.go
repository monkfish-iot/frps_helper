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

package database

import (
	"fmt"
	"os"
	"path/filepath"

	"frps_helper/models"
	"frps_helper/pkg/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type DatabaseConfig struct {
	Type         string
	File         string
	Host         string
	Port         int
	Username     string
	Password     string
	Database     string
	SSLMode      string
	MaxIdleConns int
	MaxOpenConns int
}

var DB *gorm.DB

func InitDB(config *DatabaseConfig) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	dbType := config.Type
	if dbType == "" {
		dbType = "sqlite"
	}

	switch dbType {
	case "sqlite":
		dbFile := config.File
		if dbFile == "" {
			dbFile = "./data/frps_helper.db"
		}
		// 确保目录存在
		if dir := filepath.Dir(dbFile); dir != "" && dir != "." {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				return nil, fmt.Errorf("create db directory %s: %w", dir, mkErr)
			}
		}
		db, err = gorm.Open(sqlite.Open(dbFile), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Warn),
		})
	case "postgres":
		dsn := fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Host, config.Port, config.Username,
			config.Password, config.Database, config.SSLMode,
		)
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
			Logger:      gormlogger.Default.LogMode(gormlogger.Warn),
			PrepareStmt: true,
		})
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	if err != nil {
		return nil, err
	}

	sqlDB, _ := db.DB()
	if config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	}
	if config.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	}

	// 自动迁移表结构（幂等，只增不减）
	if err := db.AutoMigrate(&models.Device{}); err != nil {
		logger.Errorf("Failed to auto-migrate database schema: %v", err)
	} else {
		logger.Info("Database schema migrated successfully")
	}

	DB = db
	return db, nil
}

func GetDB() *gorm.DB {
	return DB
}
