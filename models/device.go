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

package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Device 设备表模型，保留原始表结构。
// additional_data 字段移除了 type:jsonb tag 以兼容 SQLite（SQLite 中 JSON 存为 TEXT）。
type Device struct {
	ID               uint           `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantOrgID      string         `json:"tenant_org_id" gorm:"column:tenant_org_id;not null;size:64"`
	DeviceID         string         `json:"device_id" gorm:"column:device_id;not null;size:64;uniqueIndex:idx_devices_device_id,where:deleted_at IS NULL"`
	ExtPort          int64          `json:"ext_port" gorm:"column:ext_port;default:0"`
	ExtIPAddress     string         `json:"ext_ip_address" gorm:"column:ext_ip_address;size:64"`
	SessionID        string         `json:"session_id" gorm:"column:session_id;size:64;uniqueIndex:idx_devices_session_id,where:deleted_at IS NULL AND session_id != ''"`
	PortalUuid       string         `json:"portal_uuid" gorm:"column:portal_uuid;size:64;uniqueIndex:idx_devices_portal_uuid,where:deleted_at IS NULL AND portal_uuid != ''"`
	DeviceName       string         `json:"device_name" gorm:"column:device_name;size:128"`
	Model            string         `json:"model" gorm:"column:model;size:32"`
	Version          string         `json:"version" gorm:"column:version;size:64"`
	Vendor           string         `json:"vendor" gorm:"column:vendor;size:32"`
	ACAddress        string         `json:"ac_address" gorm:"column:ac_address;size:64"`
	MACAddress       string         `json:"mac_address" gorm:"column:mac_address;size:17"`
	PubKey           string         `json:"pub_key" gorm:"column:pub_key;size:512"`
	UMac             uint64         `json:"umac" gorm:"column:umac;default:0;uniqueIndex:idx_devices_umac,where:deleted_at IS NULL AND umac != 0"`
	Class            int            `json:"class" gorm:"column:class;default:0"`
	Status           string         `json:"status" gorm:"column:status;default:offline;size:20"`
	UserName         string         `json:"user_name" gorm:"column:user_name;size:256"`
	Password         string         `json:"-" gorm:"column:password;size:256"` // 密码不回传，防泄露
	AssignmentStatus string         `json:"assignment_status" gorm:"column:assignment_status;default:unassigned;size:20"`
	AdditionalData   datatypes.JSON `json:"additional_data" gorm:"column:additional_data"`
	LastHeartbeat    *time.Time     `json:"last_heartbeat" gorm:"column:last_heartbeat"`
	OnlineSince      *time.Time     `json:"online_since" gorm:"column:online_since"`
	FirstSeen        time.Time      `json:"first_seen" gorm:"column:first_seen;autoCreateTime"`
	CreatedAt        time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt        time.Time      `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt        gorm.DeletedAt `json:"deleted_at" gorm:"column:deleted_at;index"`
}

func (Device) TableName() string {
	return "devices"
}
