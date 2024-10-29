/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package utils

import (
	"net/http"
	"strings"
)

// GetIPAddress retrieves the sourceIP from request
func GetIPAddress(r *http.Request) string {
	// first fetch from X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For may have multiple ips
		ips := strings.Split(xff, ",")
		// return the first ip and trim it
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// use RemoteAddr instead
	ip := r.RemoteAddr
	// remove the port if existed
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}
