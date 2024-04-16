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

// Package httpserver defines the httpserver options and middlewares
package httpserver

import (
	"net/http"
	"oauth-server/pkg/zlog"
	"time"
)

// responseLogger 是一个自定义的响应记录器，用于记录响应状态码和大小
type responseLogger struct {
	http.ResponseWriter
	status int
	size   int
}

// WriteHeader 重写 http.ResponseWriter 的 WriteHeader 方法
func (rl *responseLogger) WriteHeader(code int) {
	rl.status = code
	rl.ResponseWriter.WriteHeader(code)
}

// Write 重写 http.ResponseWriter 的 Write 方法
func (rl *responseLogger) Write(b []byte) (int, error) {
	size, err := rl.ResponseWriter.Write(b)
	rl.size += size
	return size, err
}

// AccessLoggingMiddleware logs the access entries
func AccessLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建一个新的 responseLogger
		rl := &responseLogger{
			ResponseWriter: w,
			status:         http.StatusOK, // 默认状态码为 200
		}

		// 执行下一个处理器
		next.ServeHTTP(rl, r)

		// 记录访问日志
		if rl.status >= http.StatusBadRequest {
			zlog.Warnf(
				`%s - - [%s] %dms "%s %s %s" status:%d length:%d referer:"%s" "%s"`,
				r.RemoteAddr,
				start.Format("02/Jan/2006:15:04:05 -0700"),
				time.Since(start)/time.Millisecond,
				r.Method,
				r.RequestURI,
				r.Proto,
				rl.status,
				rl.size,
				r.Header.Get("Referer"),
				r.UserAgent(),
			)
		} else {
			zlog.Infof(
				`%s - - [%s] %dms "%s %s %s" status:%d length:%d referer:"%s" "%s"`,
				r.RemoteAddr,
				start.Format("02/Jan/2006:15:04:05 -0700"),
				time.Since(start)/time.Millisecond,
				r.Method,
				r.RequestURI,
				r.Proto,
				rl.status,
				rl.size,
				r.Header.Get("Referer"),
				r.UserAgent(),
			)
		}
	})
}
