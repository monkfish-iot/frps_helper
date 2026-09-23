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

package frpc

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"frps_helper/models"
	"frps_helper/pkg/ca"
	"frps_helper/pkg/logger"
	"frps_helper/pkg/util"
)

// 设备查询默认分页参数
const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// startManageServer 启动独立管理服务器（HTTPS）。
// 仅暴露管理接口，与设备对接接口（6999）物理隔离。
// 绑定地址由 frpc.manage_bind 决定（默认 127.0.0.1），
// 并强制校验来源 IP 白名单 frpc.manage_whitelist（默认 127.0.0.1）。
func (s *Server) startManageServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/devices", s.handleDevices)
	mux.HandleFunc("/api/v1/devices/pre-register", s.handlePreRegisterDevice)
	mux.HandleFunc("/api/v1/devices/session/", s.handleDeviceBySession)
	mux.HandleFunc("/api/v1/credentials/", s.handleQueryCredential)
	mux.HandleFunc("/api/v1/config/auto_register", s.handleAutoRegisterConfig)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	port := s.config.ManagePort
	if port <= 0 {
		port = defaultManagePort
	}
	bind := strings.TrimSpace(s.config.ManageBind)
	if bind == "" {
		bind = defaultLocalBind
	}
	addr := net.JoinHostPort(bind, strconv.Itoa(port))

	whitelist := effectiveWhitelist(s.config.ManageWhitelist)
	acl := newIPACL(whitelist)
	s.manageServer = &http.Server{Addr: addr, Handler: acl.middleware(mux, "manage")}

	certFile, keyFile, useTLS := resolveDeviceTLS(s.config)

	go func() {
		if useTLS {
			logger.Infof("[FRPC] manage server starting on %s (HTTPS, whitelist=%v)", addr, whitelist)
			if err := s.manageServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Errorf("[FRPC] manage server (TLS) error: %v", err)
			}
		} else {
			logger.Infof("[FRPC] manage server starting on %s (HTTP, whitelist=%v)", addr, whitelist)
			if err := s.manageServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Errorf("[FRPC] manage server error: %v", err)
			}
		}
	}()

	return nil
}

// handleDevices GET 列表(分页+条件) / POST 手动注册(批准)
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListDevices(w, r)
	case http.MethodPost:
		s.handleCreateDevice(w, r)
	default:
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
	}
}

// handleListDevices 分页查询设备，支持按条件过滤
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	if page <= 0 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	dbq := s.db.Model(&models.Device{}).Where("deleted_at IS NULL")

	status := strings.TrimSpace(q.Get("status"))
	if status != "" {
		dbq = dbq.Where("status = ?", status)
	}
	deviceID := strings.TrimSpace(q.Get("device_id"))
	if deviceID != "" {
		dbq = dbq.Where("device_id LIKE ?", "%"+deviceID+"%")
	}
	mac := strings.TrimSpace(q.Get("mac"))
	if mac != "" {
		dbq = dbq.Where("mac_address LIKE ?", "%"+mac+"%")
	}
	model := strings.TrimSpace(q.Get("model"))
	if model != "" {
		dbq = dbq.Where("model LIKE ?", "%"+model+"%")
	}
	keyword := strings.TrimSpace(q.Get("keyword"))
	if keyword != "" {
		kw := "%" + keyword + "%"
		dbq = dbq.Where("(device_id LIKE ? OR device_name LIKE ? OR mac_address LIKE ?)", kw, kw, kw)
	}

	var total int64
	if err := dbq.Count(&total).Error; err != nil {
		logger.Errorf("[FRPC DEVICE] list count failed: %v", err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}

	var items []models.Device
	if err := dbq.Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		logger.Errorf("[FRPC DEVICE] list failed: %v", err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}

	logger.Infof("[FRPC DEVICE] list devices: total=%d page=%d page_size=%d filters={status:%s device_id:%s mac:%s model:%s keyword:%s}",
		total, page, pageSize, status, deviceID, mac, model, keyword)

	s.writeDeviceResp(w, codeOK, "ok", map[string]interface{}{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"items":     items,
	})
}

// handleDeviceBySession 北向按 session_id 精确查询单个设备。
// 路径风格与 /api/v1/credentials/{device_id} 一致：GET /api/v1/devices/session/{session_id}
func (s *Server) handleDeviceBySession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
		return
	}

	sessionID := strings.TrimPrefix(r.URL.Path, "/api/v1/devices/session/")
	sessionID = strings.Trim(strings.TrimSpace(sessionID), "/")
	if sessionID == "" {
		s.writeDeviceResp(w, codeBadParam, "session_id is required", nil)
		return
	}
	if !sessionIDPattern.MatchString(sessionID) {
		s.writeDeviceResp(w, codeBadParam, "session_id format invalid", nil)
		return
	}

	dev, err := s.getDeviceBySessionID(sessionID)
	if err != nil {
		logger.Errorf("[FRPC DEVICE] query by session DB error: session_id=%s err=%v", sessionID, err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}
	if dev == nil {
		s.writeDeviceResp(w, codeBadParam, "device not found by session_id", nil)
		return
	}

	logger.Infof("[FRPC DEVICE] queried device by session: session_id=%s device_id=%s", sessionID, dev.DeviceID)
	s.writeDeviceResp(w, codeOK, "ok", dev)
}

// handleQueryCredential 北向查询指定设备的明文登录账号/密码。
// 默认关闭；配置 frpc.credential_query=true 时开放。
// 可选 frpc.credential_token 作为 Bearer 令牌，非空则强制校验。
// 密码在库中为 CA 公钥加密的密文，此处用私钥解密后返回明文。
// 路径风格与其他接口一致：GET /api/v1/credentials/{device_id}
func (s *Server) handleQueryCredential(w http.ResponseWriter, r *http.Request) {
	if !s.config.CredentialQuery {
		s.writeDeviceResp(w, codeNotAuthorized, "credential query disabled", nil)
		return
	}

	// 可选 Bearer 令牌保护
	if token := s.config.CredentialToken; token != "" {
		if r.Header.Get("Authorization") != "Bearer "+token {
			s.writeDeviceResp(w, codeNotAuthorized, "unauthorized", nil)
			return
		}
	}

	deviceID := strings.TrimPrefix(r.URL.Path, "/api/v1/credentials/")
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		s.writeDeviceResp(w, codeBadParam, "device_id is required", nil)
		return
	}

	username, password, found, err := s.getDeviceCredentials(deviceID)
	if err != nil {
		logger.Errorf("[FRPC CRED] query DB error: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}
	if !found {
		s.writeDeviceResp(w, codeBadParam, "device not found", nil)
		return
	}

	plain, err := ca.Get().Decrypt(password)
	if err != nil {
		logger.Errorf("[FRPC CRED] decrypt failed: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}

	logger.Infof("[FRPC CRED] queried plaintext credentials: device_id=%s", deviceID)
	s.writeDeviceResp(w, codeOK, "ok", map[string]interface{}{
		"device_id": deviceID,
		"username":  username,
		"password":  string(plain),
	})
}

// preRegisterDeviceRequest 预注册设备请求（仅需 device_id）
type preRegisterDeviceRequest struct {
	DeviceID   string `json:"device_id"`
	MAC        string `json:"mac"`
	DeviceName string `json:"device_name"`
	Model      string `json:"model"`
}

// handlePreRegisterDevice 预注册设备：仅用 device_id 创建一条占位记录，
// 其余字段（mac、model、hostname、pubkey、凭证等）在设备上线 join 时自动补齐。
// 主要用于 auto_register=false 场景下，管理员提前放行指定设备。
func (s *Server) handlePreRegisterDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
		return
	}

	var req preRegisterDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeDeviceResp(w, codeBadParam, "invalid JSON: "+err.Error(), nil)
		return
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		s.writeDeviceResp(w, codeBadParam, "device_id is required", nil)
		return
	}

	mac := strings.ToLower(strings.TrimSpace(req.MAC))
	if mac != "" && !macPattern.MatchString(mac) {
		s.writeDeviceResp(w, codeBadParam, "mac format invalid (expected 12 lowercase hex)", nil)
		return
	}
	umac := util.StrMac2Uint64(mac)

	device, err := s.getDeviceByDeviceID(deviceID)
	if err != nil {
		logger.Errorf("[FRPC DEVICE] pre-register DB error: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}

	if device == nil {
		newDev := &models.Device{
			TenantOrgID:      "default",
			DeviceID:         deviceID,
			DeviceName:       req.DeviceName,
			Model:            req.Model,
			Vendor:           "frpc",
			MACAddress:       mac,
			UMac:             umac,
			Class:            2,
			Status:           "offline",
			AssignmentStatus: "unassigned",
		}
		if err := s.db.Create(newDev).Error; err != nil {
			if isDuplicateKeyError(err) {
				// 并发或 umac 冲突：fallback 更新
				res := s.db.Model(&models.Device{}).
					Where("device_id = ? AND deleted_at IS NULL", deviceID).
					Updates(map[string]interface{}{
						"device_name": req.DeviceName,
						"model":       req.Model,
						"mac_address": mac,
						"umac":        umac,
					})
				if res.Error != nil {
					logger.Errorf("[FRPC DEVICE] pre-register conflict update failed: device_id=%s err=%v", deviceID, res.Error)
					s.writeDeviceResp(w, codeInternal, "internal error", nil)
					return
				}
			} else {
				logger.Errorf("[FRPC DEVICE] pre-register create failed: device_id=%s err=%v", deviceID, err)
				s.writeDeviceResp(w, codeInternal, "internal error", nil)
				return
			}
		} else {
			logger.Infof("[FRPC DEVICE] pre-registered device: device_id=%s mac=%s", deviceID, mac)
		}
	} else {
		// 已存在 → 仅补充可选字段，不覆盖已有凭证/状态
		updates := map[string]interface{}{}
		if req.DeviceName != "" && device.DeviceName == "" {
			updates["device_name"] = req.DeviceName
		}
		if req.Model != "" && device.Model == "" {
			updates["model"] = req.Model
		}
		if mac != "" && device.MACAddress == "" {
			updates["mac_address"] = mac
			updates["umac"] = umac
		}
		if len(updates) > 0 {
			if err := s.db.Model(&models.Device{}).
				Where("device_id = ? AND deleted_at IS NULL", deviceID).
				Updates(updates).Error; err != nil {
				logger.Errorf("[FRPC DEVICE] pre-register update failed: device_id=%s err=%v", deviceID, err)
			}
		}
		logger.Infof("[FRPC DEVICE] pre-register: device already exists: device_id=%s", deviceID)
	}

	dev, _ := s.getDeviceByDeviceID(deviceID)
	s.writeDeviceResp(w, codeOK, "ok", dev)
}

// createDeviceRequest 手动注册/批准设备请求
type createDeviceRequest struct {
	DeviceID   string `json:"device_id"`
	MAC        string `json:"mac"`
	DeviceName string `json:"device_name"`
	Model      string `json:"model"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Status     string `json:"status"`
}

// handleCreateDevice 手动注册/批准设备（作为加入白名单）
func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	var req createDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeDeviceResp(w, codeBadParam, "invalid JSON: "+err.Error(), nil)
		return
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		s.writeDeviceResp(w, codeBadParam, "device_id is required", nil)
		return
	}

	mac := strings.ToLower(strings.TrimSpace(req.MAC))
	if mac != "" && !macPattern.MatchString(mac) {
		s.writeDeviceResp(w, codeBadParam, "mac format invalid (expected 12 lowercase hex)", nil)
		return
	}

	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "offline"
	}
	switch status {
	case "online", "offline", "pending":
	default:
		s.writeDeviceResp(w, codeBadParam, "invalid status (online|offline|pending)", nil)
		return
	}

	device, err := s.getDeviceByDeviceID(deviceID)
	if err != nil {
		logger.Errorf("[FRPC DEVICE] create/approve DB error: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}

	umac := util.StrMac2Uint64(mac)

	if device == nil {
		now := time.Now()
		newDev := &models.Device{
			TenantOrgID:      "default",
			DeviceID:         deviceID,
			DeviceName:       req.DeviceName,
			Model:            req.Model,
			Vendor:           "frpc",
			MACAddress:       mac,
			UMac:             umac,
			UserName:         req.Username,
			Password:         req.Password,
			Class:            2,
			Status:           status,
			AssignmentStatus: "assigned",
			LastHeartbeat:    &now,
		}
		if err := s.db.Create(newDev).Error; err != nil {
			if isDuplicateKeyError(err) {
				s.updateDeviceFields(deviceID, req, status, umac, mac)
			} else {
				logger.Errorf("[FRPC DEVICE] create device failed: device_id=%s err=%v", deviceID, err)
				s.writeDeviceResp(w, codeInternal, "internal error", nil)
				return
			}
		} else {
			logger.Infof("[FRPC DEVICE] manual registered device: device_id=%s mac=%s status=%s", deviceID, mac, status)
		}
	} else {
		s.updateDeviceFields(deviceID, req, status, umac, mac)
		logger.Infof("[FRPC DEVICE] approved device: device_id=%s mac=%s status=%s", deviceID, mac, status)
	}

	dev, _ := s.getDeviceByDeviceID(deviceID)
	s.writeDeviceResp(w, codeOK, "ok", dev)
}

// updateDeviceFields 按 device_id 更新设备字段
func (s *Server) updateDeviceFields(deviceID string, req createDeviceRequest, status string, umac uint64, mac string) {
	updates := map[string]interface{}{
		"status":            status,
		"assignment_status": "assigned",
		"last_heartbeat":    time.Now(),
	}
	if req.DeviceName != "" {
		updates["device_name"] = req.DeviceName
	}
	if req.Model != "" {
		updates["model"] = req.Model
	}
	if mac != "" {
		updates["mac_address"] = mac
	}
	if umac != 0 {
		updates["umac"] = umac
	}
	if req.Username != "" {
		updates["user_name"] = req.Username
	}
	if req.Password != "" {
		updates["password"] = req.Password
	}
	if err := s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Updates(updates).Error; err != nil {
		logger.Errorf("[FRPC DEVICE] update device failed: device_id=%s err=%v", deviceID, err)
	}
}

// handleAutoRegisterConfig GET 查看 / PUT 修改自动注册开关（运行时生效）
func (s *Server) handleAutoRegisterConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeDeviceResp(w, codeOK, "ok", map[string]interface{}{
			"auto_register": s.autoRegisterEnabled(),
		})
	case http.MethodPut, http.MethodPost:
		var req struct {
			AutoRegister *bool `json:"auto_register"`
		}
		if err := decodeJSON(r, &req); err != nil {
			s.writeDeviceResp(w, codeBadParam, "invalid JSON: "+err.Error(), nil)
			return
		}
		if req.AutoRegister == nil {
			s.writeDeviceResp(w, codeBadParam, "auto_register is required", nil)
			return
		}
		s.setAutoRegister(*req.AutoRegister)
		logger.Infof("[FRPC DEVICE] auto_register set to %v (runtime)", *req.AutoRegister)
		s.writeDeviceResp(w, codeOK, "ok", map[string]interface{}{
			"auto_register": *req.AutoRegister,
		})
	default:
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
	}
}

// recordPendingJoin 记录"请求加入但未授权"的设备（auto_register=false 时被拒绝的 join）
func (s *Server) recordPendingJoin(req joinRequest, deviceID, ip string) {
	mac := strings.ToLower(strings.TrimSpace(req.MAC))
	umac := util.StrMac2Uint64(mac)
	now := time.Now()

	device, err := s.getDeviceByDeviceID(deviceID)
	if err != nil {
		logger.Errorf("[FRPC DEVICE] recordPendingJoin DB error: device_id=%s err=%v", deviceID, err)
		return
	}

	if device == nil {
		newDev := &models.Device{
			TenantOrgID:      "default",
			DeviceID:         deviceID,
			DeviceName:       req.Hostname,
			Model:            req.Model,
			Vendor:           "frpc",
			MACAddress:       mac,
			UMac:             umac,
			PubKey:           req.PubKey,
			Class:            2,
			Status:           "pending",
			AssignmentStatus: "unassigned",
			LastHeartbeat:    &now,
		}
		if err := s.db.Create(newDev).Error; err != nil {
			if !isDuplicateKeyError(err) {
				logger.Errorf("[FRPC DEVICE] recordPendingJoin create failed: device_id=%s err=%v", deviceID, err)
			}
		} else {
			logger.Infof("[FRPC DEVICE] recorded pending join (not approved): device_id=%s mac=%s ip=%s", deviceID, mac, ip)
		}
		return
	}

	// 已存在 → 标记 pending，便于管理员查看
	if err := s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Updates(map[string]interface{}{
			"status":         "pending",
			"mac_address":    mac,
			"device_name":    req.Hostname,
			"model":          req.Model,
			"last_heartbeat": now,
		}).Error; err != nil {
		logger.Errorf("[FRPC DEVICE] recordPendingJoin update failed: device_id=%s err=%v", deviceID, err)
	}
}
