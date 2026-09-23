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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"frps_helper/pkg/ca"
	"frps_helper/pkg/logger"
)

// ---------- 请求/响应类型 ----------

type joinRequest struct {
	DeviceID string `json:"device_id"`
	Board    string `json:"board"`
	Model    string `json:"model"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	LocalIf  string `json:"local_if"`
	PubKey   string `json:"pub_key"`
}

type statusRequest struct {
	CPUTemp    float64 `json:"cpu_temp"`
	MemTotal   uint64  `json:"mem_total"`
	MemFree    uint64  `json:"mem_free"`
	DiskTotal  uint64  `json:"disk_total"`
	DiskFree   uint64  `json:"disk_free"`
	NetRxBytes uint64  `json:"net_rx_bytes"`
	NetTxBytes uint64  `json:"net_tx_bytes"`
}

type authRequest struct {
	DeviceID string `json:"device_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponseBody struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	DeviceID  string `json:"device_id"`
}

const authTokenTTL = 86400 // 24h

// ---------- 设备服务器启动 ----------

func (s *Server) startDeviceServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/join", s.handleJoin)
	mux.HandleFunc("/api/v1/auth", s.handleAuth)
	mux.HandleFunc("/api/v1/health", s.handleDeviceHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/status/"):
			sid := strings.TrimPrefix(r.URL.Path, "/api/v1/status/")
			s.handleStatus(w, r, sid)
		default:
			http.NotFound(w, r)
		}
	})

	addr := fmt.Sprintf(":%d", s.config.DevicePort)
	s.deviceServer = &http.Server{Addr: addr, Handler: mux}

	// 启动会话清理 + 离线检测
	s.deviceCleanupStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.mgr.cleanupExpiredSessions()
				s.markOfflineDevices()
			case <-s.deviceCleanupStop:
				return
			}
		}
	}()

	certFile, keyFile, useTLS := resolveDeviceTLS(s.config)

	go func() {
		if useTLS {
			logger.Infof("[FRPC] device server starting on %s (HTTPS)", addr)
			if err := s.deviceServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Errorf("[FRPC] device server (TLS) error: %v", err)
			}
		} else {
			logger.Infof("[FRPC] device server starting on %s (HTTP)", addr)
			if err := s.deviceServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Errorf("[FRPC] device server error: %v", err)
			}
		}
	}()

	return nil
}

// ---------- handlers ----------

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	if r.Method != http.MethodPost {
		logger.Warnf("[FRPC JOIN] rejected: method not allowed, method=%s ip=%s", r.Method, ip)
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
		return
	}

	if !s.joinLimiter.allow(ip) {
		logger.Warnf("[FRPC JOIN] rejected: rate limit, ip=%s", ip)
		s.writeDeviceResp(w, codeNotAuthorized, "rate limit", nil)
		return
	}

	var req joinRequest
	if err := decodeJSON(r, &req); err != nil {
		logger.Warnf("[FRPC JOIN] rejected: invalid JSON, ip=%s err=%v", ip, err)
		s.writeDeviceResp(w, codeBadParam, "invalid JSON: "+err.Error(), nil)
		return
	}

	req.MAC = strings.ToLower(strings.TrimSpace(req.MAC))
	if req.MAC == "" {
		logger.Warnf("[FRPC JOIN] rejected: mac is required, ip=%s", ip)
		s.writeDeviceResp(w, codeBadParam, "mac is required", nil)
		return
	}
	if !macPattern.MatchString(req.MAC) {
		logger.Warnf("[FRPC JOIN] rejected: invalid mac format, mac=%s ip=%s", req.MAC, ip)
		s.writeDeviceResp(w, codeBadParam, "mac format invalid (expected 12 lowercase hex)", nil)
		return
	}

	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = req.MAC
	}

	// auto_register=false 时检查设备是否已存在
	if !s.autoRegisterEnabled() {
		device, err := s.getDeviceByDeviceID(deviceID)
		if err != nil {
			logger.Errorf("[FRPC JOIN] rejected: DB error, device_id=%s err=%v", deviceID, err)
			s.writeDeviceResp(w, codeInternal, "internal error", nil)
			return
		}
		if device == nil {
			// 记录"请求加入但未授权"的设备，便于管理员查看并手动批准
			s.recordPendingJoin(req, deviceID, ip)
			logger.Warnf("[FRPC JOIN] rejected: device not authorized (auto_register=false), device_id=%s ip=%s", deviceID, ip)
			s.writeDeviceResp(w, codeNotAuthorized, "device not authorized", nil)
			return
		}
	}

	// 创建新会话
	ttl := time.Duration(s.config.SessionTTLVal()) * time.Second
	sessionID := s.mgr.CreateSession(deviceID, req.MAC, ttl)

	// 创建或更新设备记录
	if err := s.upsertDeviceOnJoin(req, sessionID); err != nil {
		logger.Errorf("[FRPC JOIN] upsert device failed: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeInternal, "internal error", nil)
		return
	}

	interval := s.config.StatusInterval
	if interval <= 0 {
		interval = defaultStatusInterval
	}

	// 返回 CA 公钥（base64 编码的 PEM）
	var caPubKey string
	if caService := ca.Get(); caService != nil {
		caPubKey = base64.StdEncoding.EncodeToString(caService.GetPublicKeyPEM())
	}

	body := map[string]interface{}{
		"session_id": sessionID,
		"xfrpc": map[string]interface{}{
			"server_addr": s.config.XfrpcServerAddr,
			"server_port": s.config.XfrpcServerPort,
		},
		"interval":   interval,
		"ca_pub_key": caPubKey,
	}

	logger.Infof("[FRPC JOIN] device joined: device_id=%s mac=%s session_id=%s ip=%s",
		deviceID, req.MAC, sessionID, ip)
	s.writeDeviceResp(w, codeOK, "ok", body)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
		return
	}

	if sessionID == "" {
		s.writeDeviceResp(w, codeBadParam, "session_id is required", nil)
		return
	}

	// 校验并续期会话
	deviceID, code, err := s.mgr.RecordStatus(sessionID)
	if err != nil {
		s.writeDeviceResp(w, code, err.Error(), nil)
		return
	}

	// 解析状态上报数据
	var st statusRequest
	if err := decodeJSON(r, &st); err != nil {
		// 状态体解析失败不阻断会话续期，仅记录
		logger.Warnf("[FRPC STATUS] JSON parse failed (session still renewed): session_id=%s err=%v", sessionID, err)
	} else {
		// 更新设备状态到 DB
		if err := s.updateDeviceStatus(deviceID, st); err != nil {
			logger.Warnf("[FRPC STATUS] DB update failed: device_id=%s err=%v", deviceID, err)
		}
	}

	s.writeDeviceResp(w, codeOK, "ok", map[string]interface{}{
		"session_id": sessionID,
		"timestamp":  time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeDeviceResp(w, codeBadParam, "method not allowed", nil)
		return
	}

	var req authRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeDeviceResp(w, codeAuthInvalidCreds, "invalid JSON: "+err.Error(), nil)
		return
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	username := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)

	if deviceID == "" || username == "" || password == "" {
		s.writeDeviceResp(w, codeAuthInvalidCreds, "device_id, username, password are required", nil)
		return
	}

	dbUser, dbPass, found, err := s.getDeviceCredentials(deviceID)
	if err != nil {
		logger.Errorf("[FRPC AUTH] DB error: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeAuthInternal, "internal error", nil)
		return
	}
	if !found {
		s.writeDeviceResp(w, codeAuthDeviceDenied, "device not found", nil)
		return
	}
	if dbUser != username {
		s.writeDeviceResp(w, codeAuthInvalidCreds, "invalid credentials", nil)
		return
	}
	// 库中 password 为 CA 公钥加密后的密文，用私钥解密后与请求明文比对
	decrypted, err := ca.Get().Decrypt(dbPass)
	if err != nil {
		logger.Errorf("[FRPC AUTH] decrypt stored password failed: device_id=%s err=%v", deviceID, err)
		s.writeDeviceResp(w, codeAuthInternal, "internal error", nil)
		return
	}
	if string(decrypted) != password {
		s.writeDeviceResp(w, codeAuthInvalidCreds, "invalid credentials", nil)
		return
	}

	token := generateAuthToken()
	logger.Infof("[FRPC AUTH] device authenticated: device_id=%s token=%s", deviceID, maskToken(token))

	s.writeDeviceResp(w, codeOK, "ok", authResponseBody{
		Token:     token,
		ExpiresIn: authTokenTTL,
		DeviceID:  deviceID,
	})
}

func (s *Server) handleDeviceHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"time":           time.Now().Format(time.RFC3339),
		"client_cnt":     s.mgr.ClientCount(),
		"online_devices": s.mgr.SessionCount(),
		"uptime":         s.mgr.Uptime(),
	})
}
