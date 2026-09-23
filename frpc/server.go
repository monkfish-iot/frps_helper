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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"frps_helper/api"
	"frps_helper/models"
	"frps_helper/pkg/ca"
	"frps_helper/pkg/logger"
	"frps_helper/pkg/util"

	"gorm.io/gorm"
)

// Config FRPC 服务配置
type Config struct {
	Enable          bool
	AutoRegister    bool
	Port            int // FRPS 认证 HTTP 端口
	FrpsAdmin       string
	FrpsPassword    string
	FrpsPort        int
	DevicePort      int // 设备管理 HTTPS 端口
	ManagePort      int // 独立管理 HTTPS 端口
	ManageBind      string
	ManageWhitelist []string
	AuthBind        string
	AuthWhitelist   []string
	CredentialQuery bool
	CredentialToken string
	DeviceTLS       bool
	DeviceCertFile  string
	DeviceKeyFile   string
	XfrpcServerAddr string
	XfrpcServerPort int
	StatusInterval  int
	SessionTTL      int
	OfflineTimeout  int // 心跳超时阈值（秒），超时标记离线
}

func (c Config) SessionTTLVal() int {
	if c.SessionTTL > 0 {
		return c.SessionTTL
	}
	if c.StatusInterval <= 0 {
		return defaultSessionTTL
	}
	return c.StatusInterval * 3
}

// OfflineTimeoutVal 返回离线判定阈值（秒）。
// 未配置时取 SessionTTLVal，即与内存会话过期保持一致。
func (c Config) OfflineTimeoutVal() int {
	if c.OfflineTimeout > 0 {
		return c.OfflineTimeout
	}
	return c.SessionTTLVal()
}

// Server FRPC 服务，包含 FRPS 认证和设备管理两个 HTTP 服务器
type Server struct {
	config            Config
	db                *gorm.DB
	mgr               *manager
	authServer        *http.Server
	deviceServer      *http.Server
	manageServer      *http.Server
	deviceCleanupStop chan struct{}
	joinLimiter       *joinRateLimiter
	mu                sync.Mutex
	cfgMu             sync.RWMutex // 保护运行时可变配置（auto_register 等）
	running           bool
}

func New(cfg Config, db *gorm.DB) *Server {
	return &Server{
		config:      cfg,
		db:          db,
		mgr:         newManager(),
		joinLimiter: newJoinRateLimiter(),
	}
}

// autoRegisterEnabled 读取运行时自动注册开关
func (s *Server) autoRegisterEnabled() bool {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.config.AutoRegister
}

// setAutoRegister 设置运行时自动注册开关（重启后恢复为 YAML 配置值）
func (s *Server) setAutoRegister(v bool) {
	s.cfgMu.Lock()
	s.config.AutoRegister = v
	s.cfgMu.Unlock()
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	// 1. FRPS 认证服务器 (HTTP)
	authMux := http.NewServeMux()
	authMux.HandleFunc("/handler", s.eventHandler)
	authMux.HandleFunc("/clients", s.listClientsHandler)
	authMux.HandleFunc("/health", s.healthHandler)

	authPort := s.config.Port
	if authPort <= 0 {
		authPort = defaultAuthPort
	}
	authBind := strings.TrimSpace(s.config.AuthBind)
	if authBind == "" {
		authBind = defaultLocalBind
	}
	authWhitelist := effectiveWhitelist(s.config.AuthWhitelist)
	authAddr := net.JoinHostPort(authBind, strconv.Itoa(authPort))
	s.authServer = &http.Server{
		Addr:    authAddr,
		Handler: newIPACL(authWhitelist).middleware(authMux, "auth"),
	}
	logger.Infof("[FRPC] auth server starting on %s (HTTP, whitelist=%v)", authAddr, authWhitelist)

	go func() {
		if err := s.authServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("[FRPC] auth server error: %v", err)
		}
	}()

	// 2. 设备管理服务器 (HTTPS)
	if err := s.startDeviceServer(ctx); err != nil {
		logger.Errorf("[FRPC] device server start failed: %v", err)
	}

	// 3. 独立管理服务器 (HTTPS)
	if err := s.startManageServer(ctx); err != nil {
		logger.Errorf("[FRPC] manage server start failed: %v", err)
	}

	// 等待 ctx 取消
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.authServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.authServer.Shutdown(ctx)
		s.authServer = nil
	}

	s.stopDeviceServerLocked()
	s.stopManageServerLocked()

	if s.running {
		s.running = false
		logger.Info("[FRPC] servers stopped")
	}
}

func (s *Server) stopDeviceServerLocked() {
	if s.deviceCleanupStop != nil {
		close(s.deviceCleanupStop)
		s.deviceCleanupStop = nil
	}
	if s.deviceServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.deviceServer.Shutdown(ctx)
		s.deviceServer = nil
		logger.Info("[FRPC] device server stopped")
	}
}

func (s *Server) stopManageServerLocked() {
	if s.manageServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.manageServer.Shutdown(ctx)
		s.manageServer = nil
		logger.Info("[FRPC] manage server stopped")
	}
}

// ---------- DB 方法 ----------

// getSessionIDByUser 通过 device_id 查询设备的 session_id
func (s *Server) getSessionIDByUser(user string) (string, error) {
	if user == "" {
		return "", nil
	}
	var device models.Device
	err := s.db.Where("device_id = ? AND deleted_at IS NULL", user).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return device.SessionID, nil
}

// getDeviceCredentials 按 device_id 查询设备登录凭证
func (s *Server) getDeviceCredentials(deviceID string) (username, password string, found bool, err error) {
	var device models.Device
	err = s.db.Where("device_id = ? AND deleted_at IS NULL", deviceID).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	return device.UserName, device.Password, true, nil
}

// getDeviceByDeviceID 按 device_id 查询设备
func (s *Server) getDeviceByDeviceID(deviceID string) (*models.Device, error) {
	var device models.Device
	err := s.db.Where("device_id = ? AND deleted_at IS NULL", deviceID).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

// getDeviceByUMac 按 umac 查询设备（用于 join 时 umac 冲突后找到已存在记录）
func (s *Server) getDeviceByUMac(umac uint64) (*models.Device, error) {
	var device models.Device
	err := s.db.Where("umac = ? AND deleted_at IS NULL", umac).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

// getDeviceBySessionID 按 session_id 精确查询设备（未删除）。
// 未找到返回 (nil, nil)；数据库错误返回 (nil, err)。
func (s *Server) getDeviceBySessionID(sessionID string) (*models.Device, error) {
	var device models.Device
	err := s.db.Where("session_id = ? AND deleted_at IS NULL", sessionID).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

// genDeviceJoinPassword 生成设备默认登录凭证：
//   - user_name 固定为 "root"
//   - password 为 16 位随机字符串（大小写字母、数字、!@#）
//   - password 使用 CA 公钥加密后入库（RSA-OAEP-SHA256，Base64）
//
// 返回 user_name 与已加密的 password，错误时返回 err。
func genDeviceJoinPassword() (userName, encPassword string, err error) {
	const (
		pwdLen    = 16
		charset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#"
		charsetSz = 64 // 字符集含 62 个字母数字 + 3 个符号 = 64，正好 2^6
	)
	buf := make([]byte, pwdLen)
	for i := range buf {
		b, err := rand.Int(rand.Reader, big.NewInt(charsetSz))
		if err != nil {
			return "", "", err
		}
		buf[i] = charset[b.Int64()]
	}

	caService := ca.Get()
	if caService == nil {
		return "", "", errors.New("CA service not initialized")
	}
	enc, err := caService.Encrypt(buf)
	if err != nil {
		return "", "", fmt.Errorf("encrypt device password: %w", err)
	}
	return "root", enc, nil
}

// upsertDeviceOnJoin 设备 join 时创建或更新设备记录
func (s *Server) upsertDeviceOnJoin(req joinRequest, sessionID string) error {
	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = req.MAC
	}
	umac := util.StrMac2Uint64(req.MAC)

	device, err := s.getDeviceByDeviceID(deviceID)
	if err != nil {
		return err
	}

	now := time.Now()
	if device == nil {
		// 自动注册新设备：生成默认登录凭证（root + CA 公钥加密的随机密码）
		userName, encPassword, err := genDeviceJoinPassword()
		if err != nil {
			logger.Errorf("[FRPC JOIN] gen device credentials failed: device_id=%s err=%v", deviceID, err)
			return err
		}
		device = &models.Device{
			TenantOrgID:      "default",
			DeviceID:         deviceID,
			SessionID:        sessionID,
			DeviceName:       req.Hostname,
			Model:            req.Model,
			Vendor:           "frpc",
			MACAddress:       req.MAC,
			UMac:             umac,
			PubKey:           req.PubKey,
			UserName:         userName,
			Password:         encPassword,
			Class:            2,
			Status:           "online",
			AssignmentStatus: "unassigned",
			LastHeartbeat:    &now,
			OnlineSince:      &now,
		}
		if err := s.db.Create(device).Error; err != nil {
			// 唯一冲突 → fallback 更新。
			// 注意：冲突可能来自 device_id 或 umac。典型场景是设备 device_id
			// 格式变化（如去掉 MAC 后缀）但 MAC/umac 不变，此时新 device_id
			// 查不到记录，但 Create 因 umac 唯一约束失败。需按 umac 找到已
			// 存在记录并更新其 device_id，否则 join 返回成功但 DB 无对应
			// device_id 记录，后续 AUTH 会查不到。
			if isDuplicateKeyError(err) {
				// 找到冲突的现有记录：优先按 device_id，其次按 umac
				var existing *models.Device
				if dev, e := s.getDeviceByDeviceID(deviceID); e == nil && dev != nil {
					existing = dev
				} else if umac != 0 {
					existing, _ = s.getDeviceByUMac(umac)
				}

				updates := map[string]interface{}{
					"device_id":      deviceID,
					"session_id":     sessionID,
					"status":         "online",
					"last_heartbeat": now,
					"mac_address":    req.MAC,
					"online_since": gorm.Expr(
						"CASE WHEN online_since IS NULL OR status = 'offline' THEN ? ELSE online_since END", now),
				}
				if req.Hostname != "" {
					updates["device_name"] = req.Hostname
				}
				if req.Model != "" {
					updates["model"] = req.Model
				}
				if req.PubKey != "" {
					updates["pub_key"] = req.PubKey
				}
				// 若现有记录无凭证，补齐（预注册场景）
				if existing == nil || existing.UserName == "" || existing.Password == "" {
					if userName, encPassword, ge := genDeviceJoinPassword(); ge == nil {
						updates["user_name"] = userName
						updates["password"] = encPassword
					} else {
						logger.Errorf("[FRPC JOIN] gen credentials on conflict failed: device_id=%s err=%v", deviceID, ge)
					}
				}
				// 优先按 device_id 更新（device_id 冲突场景）；
				// 若 0 行受影响，则按 umac 更新（umac 冲突场景）。
				res := s.db.Model(&models.Device{}).
					Where("device_id = ? AND deleted_at IS NULL", deviceID).
					Updates(updates)
				if res.Error != nil {
					return res.Error
				}
				if res.RowsAffected == 0 && umac != 0 {
					res = s.db.Model(&models.Device{}).
						Where("umac = ? AND deleted_at IS NULL", umac).
						Updates(updates)
					if res.Error != nil {
						return res.Error
					}
				}
				if res.RowsAffected > 0 {
					logger.Infof("[FRPC] join upsert on conflict: device_id=%s (rows=%d)", deviceID, res.RowsAffected)
				} else {
					logger.Warnf("[FRPC] join upsert on conflict affected 0 rows: device_id=%s umac=%d", deviceID, umac)
				}
				return nil
			}
			return err
		}
		logger.Infof("[FRPC] auto-registered new device: device_id=%s mac=%s", deviceID, req.MAC)
		return nil
	}

	// 更新已有设备
	updates := map[string]interface{}{
		"session_id":     sessionID,
		"status":         "online",
		"last_heartbeat": now,
		"online_since": gorm.Expr(
			"CASE WHEN online_since IS NULL OR status = 'offline' THEN ? ELSE online_since END", now),
	}
	if req.Hostname != "" {
		updates["device_name"] = req.Hostname
	}
	if req.Model != "" {
		updates["model"] = req.Model
	}
	if req.PubKey != "" {
		updates["pub_key"] = req.PubKey
	}
	if req.MAC != "" {
		updates["mac_address"] = req.MAC
	}
	if umac != 0 {
		updates["umac"] = umac
	}

	// 预注册的设备可能没有凭证（username/password 为空），
	// 上线时补齐，否则后续 LuCI 登录认证失败。
	if device.UserName == "" || device.Password == "" {
		userName, encPassword, err := genDeviceJoinPassword()
		if err != nil {
			logger.Errorf("[FRPC JOIN] gen credentials on join failed: device_id=%s err=%v", deviceID, err)
		} else {
			updates["user_name"] = userName
			updates["password"] = encPassword
		}
	}

	return s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Updates(updates).Error
}

// markOfflineDevices 扫描 devices 表，将心跳超时的在线设备标记为离线。
// 超时阈值 = OfflineTimeoutVal() 秒。标记离线时同时清除 online_since。
func (s *Server) markOfflineDevices() {
	timeout := time.Duration(s.config.OfflineTimeoutVal()) * time.Second
	threshold := time.Now().Add(-timeout)

	result := s.db.Model(&models.Device{}).
		Where("status = ? AND deleted_at IS NULL AND last_heartbeat < ?", "online", threshold).
		Updates(map[string]interface{}{
			"status":       "offline",
			"online_since": nil,
		})
	if result.Error != nil {
		logger.Errorf("[FRPC] markOfflineDevices failed: %v", result.Error)
		return
	}
	if result.RowsAffected > 0 {
		logger.Infof("[FRPC] %d device(s) marked offline (heartbeat older than %ds)",
			result.RowsAffected, int(timeout.Seconds()))
	}
}

// updateDeviceHeartbeat 更新设备心跳（FRPS Ping 调用）
func (s *Server) updateDeviceHeartbeat(deviceID, sessionID string) error {
	now := time.Now()
	updates := map[string]interface{}{
		"status":         "online",
		"last_heartbeat": now,
		// 仅当之前离线或 online_since 为空时重置，实现"重新计算在线时间"
		"online_since": gorm.Expr(
			"CASE WHEN online_since IS NULL OR status = 'offline' THEN ? ELSE online_since END", now),
	}
	if sessionID != "" {
		updates["session_id"] = sessionID
	}
	result := s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		logger.Warnf("[FRPC] updateDeviceHeartbeat affected 0 rows: device_id=%s", deviceID)
	}
	return nil
}

// updateDeviceExtIP 认证成功后更新设备 ext_ip_address
func (s *Server) updateDeviceExtIP(deviceID, extIP, sessionID string) error {
	now := time.Now()
	updates := map[string]interface{}{
		"ext_ip_address": extIP,
		"status":         "online",
		"last_heartbeat": now,
		"online_since": gorm.Expr(
			"CASE WHEN online_since IS NULL OR status = 'offline' THEN ? ELSE online_since END", now),
	}
	if sessionID != "" {
		updates["session_id"] = sessionID
	}
	return s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Updates(updates).Error
}

// clearDeviceSessionID 清空设备在 devices 表中残留的失效会话 ID（内存会话已过期时调用）
func (s *Server) clearDeviceSessionID(deviceID string) {
	result := s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Update("session_id", "")
	if result.Error != nil {
		logger.Warnf("[FRPC AUTH] clear stale session_id failed: device_id=%s err=%v", deviceID, result.Error)
		return
	}
	logger.Infof("[FRPC AUTH] cleared stale session_id: device_id=%s", deviceID)
}

// updateDeviceStatus 设备状态上报后更新设备信息
func (s *Server) updateDeviceStatus(deviceID string, st statusRequest) error {
	now := time.Now()
	additional := map[string]interface{}{
		"source":       "frpc",
		"cpu_temp":     st.CPUTemp,
		"mem_total":    st.MemTotal,
		"mem_free":     st.MemFree,
		"disk_total":   st.DiskTotal,
		"disk_free":    st.DiskFree,
		"net_rx_bytes": st.NetRxBytes,
		"net_tx_bytes": st.NetTxBytes,
		"reported_at":  now.Format(time.RFC3339),
	}
	additionalJSON, _ := json.Marshal(additional)

	return s.db.Model(&models.Device{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Updates(map[string]interface{}{
			"status":         "online",
			"last_heartbeat": now,
			"online_since": gorm.Expr(
				"CASE WHEN online_since IS NULL OR status = 'offline' THEN ? ELSE online_since END", now),
			"additional_data": additionalJSON,
		}).Error
}

func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "23505") ||
		strings.Contains(s, "duplicate key value violates unique constraint") ||
		strings.Contains(s, "UNIQUE constraint failed")
}

// ---------- 响应工具 ----------

func (s *Server) writeDeviceResp(w http.ResponseWriter, code int, msg string, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.NewResponse(code, msg, body))
}

func (s *Server) writeAuthResp(w http.ResponseWriter, resp authResp) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func generateAuthToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "***(" + strconv.Itoa(len(token)) + " chars)"
}

func maskKeyLog(s string) string {
	if s == "" {
		return "(empty)"
	}
	if idx := strings.Index(s, " "); idx > 0 {
		return s[:idx] + " ***(" + strconv.Itoa(len(s)) + " chars)"
	}
	return "***(" + strconv.Itoa(len(s)) + " chars)"
}

// listClientsHandler 返回在线客户端列表
func (s *Server) listClientsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.mgr.ListClients())
}

// healthHandler FRPS 认证服务器健康检查
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"time":           time.Now().Format(time.RFC3339),
		"client_cnt":     s.mgr.ClientCount(),
		"online_devices": s.mgr.SessionCount(),
	})
}

// ---------- 来源 IP 白名单 ----------

// effectiveWhitelist 返回生效的白名单条目，未配置（或全为空串）时默认 127.0.0.1。
func effectiveWhitelist(entries []string) []string {
	for _, e := range entries {
		if strings.TrimSpace(e) != "" {
			return entries
		}
	}
	return []string{defaultLocalBind}
}

// ipACL 来源 IP 白名单，条目支持单个 IP 与 CIDR
// （如 127.0.0.1、192.168.1.0/24、::1/128）。
type ipACL struct {
	ips  []net.IP
	nets []*net.IPNet
}

func newIPACL(entries []string) *ipACL {
	acl := &ipACL{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, ipNet, err := net.ParseCIDR(e)
			if err != nil {
				logger.Warnf("[FRPC] whitelist: invalid CIDR %q, skipped", e)
				continue
			}
			acl.nets = append(acl.nets, ipNet)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			logger.Warnf("[FRPC] whitelist: invalid IP %q, skipped", e)
			continue
		}
		acl.ips = append(acl.ips, ip)
	}
	// 配置全部非法时回退默认值，避免误放开端口
	if len(acl.ips) == 0 && len(acl.nets) == 0 {
		logger.Warnf("[FRPC] whitelist: no valid entry, fallback to %s", defaultLocalBind)
		acl.ips = append(acl.ips, net.ParseIP(defaultLocalBind))
	}
	return acl
}

func (a *ipACL) allowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, want := range a.ips {
		if want.Equal(ip) {
			return true
		}
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// middleware 拒绝不在白名单内的来源地址，name 用于日志区分端口
func (a *ipACL) middleware(next http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.allowed(remoteIP(r)) {
			logger.Warnf("[FRPC] %s access denied by whitelist: remote=%s method=%s path=%s",
				name, r.RemoteAddr, r.Method, r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// remoteIP 提取请求来源 IP（去除端口）
func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}
