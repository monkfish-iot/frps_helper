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
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"frps_helper/pkg/logger"
	"frps_helper/pkg/util"
)

// authResp 是 FRPS 第三方认证的响应格式
type authResp struct {
	Reject       bool        `json:"reject"`
	Unchange     bool        `json:"unchange,omitempty"`
	RejectReason string      `json:"reject_reason,omitempty"`
	Content      interface{} `json:"content,omitempty"`
}

// eventHandler 处理 FRPS 发来的第三方认证请求
func (s *Server) eventHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Warnf("[FRPC AUTH] 读取请求体失败: %v", err)
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "read body error"})
		return
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		logger.Warnf("[FRPC AUTH] JSON 解析失败: %v", err)
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "parse error"})
		return
	}

	op, _ := raw["op"].(string)
	content, _ := raw["content"].(map[string]interface{})

	switch op {
	case "Login":
		s.handleLogin(w, content)
	case "Ping":
		s.handlePing(w, content)
	default:
		logger.Warnf("[FRPC AUTH] 未知 op: %s", op)
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "unknown op: " + op})
	}
}

// handleLogin 处理 FRPS Login 认证请求
func (s *Server) handleLogin(w http.ResponseWriter, content map[string]interface{}) {
	if content == nil {
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "invalid request"})
		return
	}

	privilegeKey, _ := content["privilege_key"].(string)
	clientAddr, _ := content["client_address"].(string)
	user, _ := content["user"].(string)
	clientIP := clientAddr
	if host, _, err := net.SplitHostPort(clientAddr); err == nil && host != "" {
		clientIP = host
	}
	version, _ := content["version"].(string)
	osName, _ := content["os"].(string)
	arch, _ := content["arch"].(string)
	runID, _ := content["run_id"].(string)
	uMac := util.StrMac2Uint64(runID)
	if uMac == 0 {
		logger.Warnf("[FRPC AUTH] 认证失败: 无效的 run_id %s", runID)
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "invalid run_id"})
		return
	}

	// 通过 device_id 从 devices 表反查 session_id
	var sessionByUser string
	sid, lookupErr := s.getSessionIDByUser(user)
	if lookupErr != nil {
		logger.Warnf("[FRPC AUTH] session lookup failed: user=%s err=%v", user, lookupErr)
	} else {
		sessionByUser = sid
	}

	if sessionByUser == "" {
		logger.Warnf("[FRPC AUTH] 认证失败: 无有效会话 user=%s", user)
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "no valid session"})
		return
	}

	// 校验内存会话仍有效（未过期）。DB 中可能残留已过期的 session_id，
	// 此时拒绝认证并清空 DB 中的残留会话，避免离线设备继续接入隧道。
	if !s.mgr.ValidateSession(user, sessionByUser) {
		logger.Warnf("[FRPC AUTH] 认证失败: 会话已过期/无效 user=%s session_id=%s", user, sessionByUser)
		s.clearDeviceSessionID(user)
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "no valid session"})
		return
	}

	logger.Infof("[FRPC AUTH] session resolved: user=%s session_id=%s", user, sessionByUser)

	// 计算 timestamp MD5（用于日志诊断）
	var timestampStr string
	var keyMD5 string
	if ts, ok := content["timestamp"]; ok {
		tsBytes, err := json.Marshal(ts)
		if err == nil {
			timestampStr = string(tsBytes)
			sum := md5.Sum([]byte(timestampStr))
			keyMD5 = hex.EncodeToString(sum[:])
		}
	}

	var metasToken string
	if metas, ok := content["metas"].(map[string]interface{}); ok {
		if token, ok := metas["token"].(string); ok {
			metasToken = token
		}
	}

	// 认证逻辑：有 privilege_key 即放行
	if privilegeKey != "" {
		s.mgr.AddClient(privilegeKey, clientInfo{
			Address: clientAddr, RunID: runID, User: user,
			Version: version, OS: osName, Arch: arch,
		})

		// 认证成功后更新 devices 表的 ext_ip_address
		if err := s.updateDeviceExtIP(user, clientIP, sessionByUser); err != nil {
			logger.Warnf("[FRPC AUTH] update ext_ip_address failed: device_id=%s err=%v", user, err)
		}

		newContent := make(map[string]interface{})
		for k, v := range content {
			newContent[k] = v
		}
		newContent["run_id"] = sessionByUser
		logger.Infof("[FRPC AUTH] 授权客户端: addr=%s ip=%s run_id=%s privilege_key=%s timestamp=%s key_md5=%s",
			clientAddr, clientIP, runID, privilegeKey, timestampStr, keyMD5)
		s.writeAuthResp(w, authResp{Reject: false, Unchange: false, Content: newContent})
		return
	}

	// 兼容新版协议：user + metas.token
	if user != "" && metasToken != "" {
		s.mgr.AddClient(user, clientInfo{
			Address: clientAddr, RunID: runID, User: user,
			Version: version, OS: osName, Arch: arch,
		})

		if err := s.updateDeviceExtIP(user, clientIP, sessionByUser); err != nil {
			logger.Warnf("[FRPC AUTH] update ext_ip_address failed: device_id=%s err=%v", user, err)
		}

		newContent := make(map[string]interface{})
		for k, v := range content {
			newContent[k] = v
		}
		newContent["run_id"] = sessionByUser
		logger.Infof("[FRPC AUTH] 授权客户端(新版): addr=%s ip=%s user=%s run_id=%s→%s",
			clientAddr, clientIP, user, runID, sessionByUser)
		s.writeAuthResp(w, authResp{Reject: false, Unchange: false, Content: newContent})
		return
	}

	logger.Warnf("[FRPC AUTH] 认证失败: 无有效凭证 addr=%s", clientAddr)
	s.writeAuthResp(w, authResp{Reject: true, RejectReason: "no valid credentials"})
}

// handlePing 处理 FRPS Ping 心跳请求
func (s *Server) handlePing(w http.ResponseWriter, content map[string]interface{}) {
	if content == nil {
		s.writeAuthResp(w, authResp{Reject: true, RejectReason: "invalid request"})
		return
	}

	// 解析 user / run_id
	var userStr string
	var rawRunID string
	if userMap, ok := content["user"].(map[string]interface{}); ok {
		if v, ok := userMap["user"].(string); ok {
			userStr = v
		}
		if v, ok := userMap["run_id"].(string); ok {
			rawRunID = v
		}
	}
	if rawRunID == "" {
		if v, ok := content["run_id"].(string); ok {
			rawRunID = v
		}
	}
	sessionID := strings.TrimSpace(rawRunID)

	logger.Infof("[FRPC AUTH] recv Ping: session_id=%s user=%s", sessionID, userStr)

	// 更新 devices 表心跳
	if userStr != "" {
		if err := s.updateDeviceHeartbeat(userStr, sessionID); err != nil {
			logger.Warnf("[FRPC AUTH] Ping heartbeat update failed: device_id=%s err=%v", userStr, err)
		}
	} else {
		logger.Warnf("[FRPC AUTH] Ping skipped: session_id=%s cannot resolve device_id", sessionID)
	}

	s.writeAuthResp(w, authResp{Reject: false, Unchange: true})
}
