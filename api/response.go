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

package api

// Response 统一响应信封
type Response struct {
	ErrorCode int         `json:"error_code"`
	Msg       string      `json:"msg"`
	Body      interface{} `json:"body"`
}

func NewResponse(errorCode int, msg string, body interface{}) *Response {
	return &Response{
		ErrorCode: errorCode,
		Msg:       msg,
		Body:      body,
	}
}
