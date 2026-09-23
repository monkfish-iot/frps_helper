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

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"frps_helper/pkg/logger"
)

const defaultCADir = "ca"

const (
	keyFile  = "ca_key.pem"
	certFile = "ca_cert.pem"
)

// Service 全局证书服务，加载 ca 目录下的 RSA 密钥对。
type Service struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	certPEM    []byte
}

var (
	instance *Service
	once     sync.Once
)

// Init 初始化证书服务，dir 为空时使用默认目录 ca/。
func Init(dir string) error {
	var initErr error
	once.Do(func() {
		instance, initErr = loadFromDir(dir)
		if initErr != nil {
			logger.Errorf("[CA] failed to load certificates: %v", initErr)
			return
		}
		logger.Info("[CA] certificate service initialized")
	})
	return initErr
}

func Get() *Service {
	return instance
}

func loadFromDir(dir string) (*Service, error) {
	if dir == "" {
		dir = defaultCADir
	}

	keyPath := filepath.Join(dir, keyFile)
	certPath := filepath.Join(dir, certFile)

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", keyPath, err)
	}
	privKey, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}

	pubKey, err := extractPublicKey(certData)
	if err != nil {
		logger.Warnf("[CA] extract public key from cert failed, fallback to private key: %v", err)
		pubKey = &privKey.PublicKey
	}

	return &Service{
		privateKey: privKey,
		publicKey:  pubKey,
		certPEM:    certData,
	}, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from private key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

func extractPublicKey(certData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not RSA")
	}
	return pubKey, nil
}

func (s *Service) GetPublicKeyPEM() []byte {
	return s.certPEM
}

func (s *Service) GetPublicKey() *rsa.PublicKey {
	return s.publicKey
}

// Sign 用私钥对 content 进行 SHA256 + PKCS1v15 签名，返回 Base64 编码。
func (s *Service) Sign(content []byte) (string, error) {
	if s.privateKey == nil {
		return "", errors.New("CA private key not loaded")
	}
	hashed := sha256.Sum256(content)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Decrypt 解密 Base64 编码的 RSA-OAEP(SHA256) 密文。
func (s *Service) Decrypt(ciphertextB64 string) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("CA private key not loaded")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decrypt failed: %w", err)
	}
	return plaintext, nil
}

// Encrypt 用 CA 公钥以 RSA-OAEP(SHA256) 加密明文，返回 Base64 编码。
// 与 Decrypt 对称，供服务端本地生成需加密存储的机密（如设备默认密码）。
func (s *Service) Encrypt(plaintext []byte) (string, error) {
	if s.publicKey == nil {
		return "", errors.New("CA public key not loaded")
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, s.publicKey, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("encrypt failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
