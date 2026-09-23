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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"frps_helper/pkg/logger"
)

const (
	defaultCertDir      = "certs"
	defaultCertFile     = "certs/device-server.crt"
	defaultKeyFile      = "certs/device-server.key"
	defaultCertValidity = 365 * 24 * time.Hour
)

// resolveDeviceTLS 根据配置准备 TLS 证书文件。
// 1. DeviceTLS=false → HTTP
// 2. DeviceTLS=true 且配置路径非空且文件存在 → 使用用户证书
// 3. DeviceTLS=true 且路径未配置或文件缺失 → 自动生成自签证书
func resolveDeviceTLS(cfg Config) (certFile, keyFile string, useTLS bool) {
	if !cfg.DeviceTLS {
		return "", "", false
	}

	cert := strings.TrimSpace(cfg.DeviceCertFile)
	key := strings.TrimSpace(cfg.DeviceKeyFile)

	if cert != "" && key != "" && fileExists(cert) && fileExists(key) {
		dumpCertInfo(cert, cfg.XfrpcServerAddr)
		return cert, key, true
	}

	if err := os.MkdirAll(defaultCertDir, 0o755); err != nil {
		logger.Errorf("[FRPC] failed to create cert dir %s: %v", defaultCertDir, err)
		return "", "", false
	}

	hosts := buildDefaultCertHosts(cfg.XfrpcServerAddr)
	if err := generateSelfSignedCert(defaultCertFile, defaultKeyFile, hosts); err != nil {
		logger.Errorf("[FRPC] auto-generate TLS cert failed: %v", err)
		return "", "", false
	}

	logger.Infof("[FRPC] auto-generated self-signed TLS cert (valid %s → %s)",
		time.Now().Format("2006-01-02"), time.Now().Add(defaultCertValidity).Format("2006-01-02"))
	dumpCertInfo(defaultCertFile, cfg.XfrpcServerAddr)
	return defaultCertFile, defaultKeyFile, true
}

func buildDefaultCertHosts(xfrpcServerAddr string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	s := strings.TrimSpace(xfrpcServerAddr)
	if s == "" {
		return hosts
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if s == "" {
		return hosts
	}
	set := make(map[string]struct{}, len(hosts)+1)
	for _, h := range hosts {
		set[h] = struct{}{}
	}
	if _, ok := set[s]; !ok {
		hosts = append(hosts, s)
	}
	return hosts
}

func generateSelfSignedCert(certPath, keyPath string, hosts []string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	notBefore := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"frps-helper"},
			CommonName:   "frps-helper-device-server",
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(defaultCertValidity),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if dir := filepath.Dir(certPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(certPath, certPem, 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0o600); err != nil {
		_ = os.Remove(certPath)
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

func dumpCertInfo(certPath, targetHost string) {
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		logger.Warnf("[FRPC] read cert %s failed: %v", certPath, err)
		return
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		logger.Warnf("[FRPC] invalid PEM in %s", certPath)
		return
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Warnf("[FRPC] parse cert %s failed: %v", certPath, err)
		return
	}
	var sans []string
	sans = append(sans, crt.DNSNames...)
	for _, ip := range crt.IPAddresses {
		sans = append(sans, ip.String())
	}
	logger.Infof("[FRPC] TLS: Subject=%q SANs=%v valid_from=%s valid_to=%s",
		crt.Subject.String(), sans,
		crt.NotBefore.Format("2006-01-02 15:04:05"),
		crt.NotAfter.Format("2006-01-02 15:04:05"))

	if th := strings.TrimSpace(targetHost); th != "" {
		if h, _, err := net.SplitHostPort(th); err == nil {
			th = h
		}
		if !certCovers(crt, th) {
			logger.Warnf("[FRPC] TLS: target host %q NOT covered by certificate SANs %v", th, sans)
		}
	}
	_ = tls.VersionTLS13
}

func certCovers(crt *x509.Certificate, host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, ip2 := range crt.IPAddresses {
			if ip.Equal(ip2) {
				return true
			}
		}
		return false
	}
	for _, dn := range crt.DNSNames {
		if matchDNSName(dn, host) {
			return true
		}
	}
	if crt.Subject.CommonName != "" && matchDNSName(crt.Subject.CommonName, host) {
		return true
	}
	return false
}

func matchDNSName(pattern, host string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, host)
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:]
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
