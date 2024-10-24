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

package audit

import (
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"openfuyao/oauth-server/pkg/utils"
	"openfuyao/oauth-server/pkg/zlog"
)

// Auditor defines the user operation auditor
type Auditor struct {
	Logger *zap.SugaredLogger
}

var (
	instance *Auditor
	once     sync.Once
)

// NewAuditor 初始化 Auditor，并确保只创建一个实例
func NewAuditor() *Auditor {
	once.Do(func() {
		instance = &Auditor{Logger: zlog.GetLogger(zlog.GetDefaultAuditConf())}
	})
	return instance
}

// LogSucceedOperation audit succeed operations
func (a *Auditor) LogSucceedOperation(username, action string, req *http.Request) {
	sourceIP := utils.GetIPAddress(req)
	userAgent := req.Header.Get("User-Agent")
	timeStamp := time.Now().Format("2006-01-02T15:04:05Z")
	a.Logger.Infof("[%s] user=%s action=%s status=succeed ip=%s userAgent=%s",
		timeStamp, username, action, sourceIP, userAgent)
	return
}

// LogFailOperation audit failed operations
func (a *Auditor) LogFailOperation(username, action, reason string, req *http.Request) {
	sourceIP := utils.GetIPAddress(req)
	userAgent := req.Header.Get("User-Agent")
	timeStamp := time.Now().Format("2006-01-02T15:04:05Z")
	a.Logger.Infof("[%s] user=%s action=%s status=fail ip=%s reason=%s userAgent=%s",
		timeStamp, username, action, sourceIP, reason, userAgent)
	return
}
