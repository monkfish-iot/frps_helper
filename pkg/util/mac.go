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

package util

import (
	"strconv"
	"strings"
)

// StrMac2Uint64 将字符串形式的 MAC 地址转换为 uint64。
// 兼容 MAC-48（12位hex）和 EUI-64（16位hex），支持冒号/连字符/点分隔。
// 返回 0 表示输入非法。
func StrMac2Uint64(strMac string) uint64 {
	if strMac == "" {
		return 0
	}
	s := strings.ToLower(strings.TrimSpace(strMac))
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	switch len(s) {
	case 12, 16:
	default:
		return 0
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return v
}
