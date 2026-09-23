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
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"frps_helper/pkg/logger"
	"frps_helper/pkg/util"
)

// 业务码定义
const (
	codeOK             = 0
	codeNotAuthorized  = -1001 // 设备未授权
	codeDeviceDisabled = -1002 // 设备已被禁用
	codeSessionInvalid = -1003 // 会话不存在或已过期
	codeBadParam       = -1004 // 请求参数错误
	codeInternal       = -2001 // 服务器内部错误
)

// 认证服务器错误码
const (
	codeAuthInvalidCreds = -3001 // 凭证无效
	codeAuthExpired      = -3002 // 凭证过期
	codeAuthNoPermission = -3003 // 权限不足
	codeAuthDeviceDenied = -3004 // 设备未授权
	codeAuthInternal     = -4001 // 内部错误
)

const (
	defaultStatusInterval = 60
	defaultSessionTTL     = 180
	defaultDevicePort     = 6999
	defaultManagePort     = 7443        // 独立管理 HTTPS 端口默认值
	defaultLocalBind      = "127.0.0.1" // 管理/认证端口默认绑定地址，同时作为默认访问白名单
	defaultAuthPort       = 8089        // FRPS 第三方认证 HTTP 端口默认值
	joinRatePerSec        = 1
)

var (
	macPattern       = regexp.MustCompile(`^[0-9a-f]{12}$`)
	sessionIDPattern = regexp.MustCompile(`^[0-9a-zA-Z_\-]{1,128}$`)
)

// session 记录一次设备会话
type session struct {
	sessionID  string
	deviceID   string
	mac        string
	createdAt  time.Time
	lastActive time.Time
	ttl        time.Duration
}

// clientInfo 存储在线 frpc 客户端信息
type clientInfo struct {
	Address string `json:"address"`
	RunID   string `json:"run_id"`
	User    string `json:"user"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// manager 管理 FRPS 认证客户端和设备会话的内存状态
type manager struct {
	mu             sync.RWMutex
	clients        map[string]clientInfo // key = privilege_key
	sessions       map[string]*session   // key = session_id
	deviceSessions map[string]string     // key = deviceID, value = sessionID
	startedAt      time.Time
}

func newManager() *manager {
	return &manager{
		clients:        make(map[string]clientInfo),
		sessions:       make(map[string]*session),
		deviceSessions: make(map[string]string),
		startedAt:      time.Now(),
	}
}

// ---------- FRPS 在线客户端 ----------

func (m *manager) AddClient(key string, info clientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[key] = info
}

func (m *manager) ListClients() map[string]clientInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]clientInfo, len(m.clients))
	for k, v := range m.clients {
		out[k] = v
	}
	return out
}

func (m *manager) ClientCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

// ---------- 设备会话 ----------

// CreateSession 为设备创建新会话，使旧会话失效。返回新的 session_id。
func (m *manager) CreateSession(deviceID, mac string, ttl time.Duration) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 使旧会话失效
	if oldSID, ok := m.deviceSessions[deviceID]; ok {
		delete(m.sessions, oldSID)
	}

	sid := util.GenerateSessionID()
	m.sessions[sid] = &session{
		sessionID:  sid,
		deviceID:   deviceID,
		mac:        mac,
		createdAt:  time.Now(),
		lastActive: time.Now(),
		ttl:        ttl,
	}
	m.deviceSessions[deviceID] = sid
	return sid
}

// RecordStatus 校验会话有效性并续期。返回设备 device_id 用于后续 DB 更新。
func (m *manager) RecordStatus(sessionID string) (string, int, error) {
	if !sessionIDPattern.MatchString(sessionID) {
		return "", codeBadParam, fmt.Errorf("invalid session_id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return "", codeSessionInvalid, fmt.Errorf("session not found")
	}

	now := time.Now()
	if now.Sub(s.lastActive) > s.ttl {
		delete(m.sessions, sessionID)
		delete(m.deviceSessions, s.deviceID)
		return "", codeSessionInvalid, fmt.Errorf("session expired")
	}

	s.lastActive = now
	return s.deviceID, codeOK, nil
}

// ValidateSession 校验设备会话在内存中仍有效（未过期）。
// 用于 FRPS 第三方认证：DB 中残留的 session_id 若在内存中已失效，则返回 false。
func (m *manager) ValidateSession(deviceID, sessionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sessionID == "" {
		return false
	}
	s, ok := m.sessions[sessionID]
	if !ok {
		return false
	}
	// 会话与设备必须匹配（防止张冠李戴）
	if s.deviceID != deviceID {
		return false
	}
	now := time.Now()
	if now.Sub(s.lastActive) > s.ttl {
		delete(m.sessions, sessionID)
		delete(m.deviceSessions, s.deviceID)
		logger.Infof("[FRPC] session expired: device_id=%s session_id=%s", s.deviceID, sessionID)
		return false
	}
	// 认证通过视为活跃，续期会话
	s.lastActive = now
	return true
}

func (m *manager) SessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *manager) Uptime() int {
	return int(time.Since(m.startedAt).Seconds())
}

func (m *manager) cleanupExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for sid, s := range m.sessions {
		if now.Sub(s.lastActive) > s.ttl {
			delete(m.sessions, sid)
			delete(m.deviceSessions, s.deviceID)
			logger.Infof("[FRPC] session expired: device_id=%s session_id=%s", s.deviceID, sid)
		}
	}
}

// ---------- join 限频器 ----------

type joinRateLimiter struct {
	mu       sync.Mutex
	lastTime map[string]time.Time
}

func newJoinRateLimiter() *joinRateLimiter {
	return &joinRateLimiter{lastTime: make(map[string]time.Time)}
}

func (l *joinRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	interval := time.Second / time.Duration(joinRatePerSec)
	if last, ok := l.lastTime[ip]; ok && now.Sub(last) < interval {
		return false
	}
	l.lastTime[ip] = now
	if len(l.lastTime) > 10000 {
		for k, t := range l.lastTime {
			if now.Sub(t) > time.Minute {
				delete(l.lastTime, k)
			}
		}
	}
	return true
}

// ---------- 工具函数 ----------

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}
