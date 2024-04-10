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

package protector

import (
	"container/list"
	"time"
)

type failedLoginTracker struct {
	locked   bool
	lockTime time.Time
	queue    *list.List
}

type LoginIPProtector struct {
	ipProtector  map[string]*failedLoginTracker
	lockDuration time.Duration
	failTimes    int
	failDuration time.Duration
}

func (p *LoginIPProtector) AddFailedLogin(ip string, timestamp time.Time) {
	_, ok := p.ipProtector[ip]
	if !ok {
		p.ipProtector[ip] = &failedLoginTracker{locked: false}
	}
	p.ipProtector[ip].queue.PushBack(timestamp)

	// Remove events older than failDuration
	p.squeezeTracker(ip)

	// determine whether blocking the ip
	if p.ipProtector[ip].queue.Len() >= p.failTimes {
		p.ipProtector[ip].lockTime = time.Now()
	}
}

func (p *LoginIPProtector) Unlock(ip string) {
	p.ipProtector[ip].locked = false
	p.ipProtector[ip].lockTime = time.Time{}
}

func (p *LoginIPProtector) IsLocked(ip string) bool {
	// Remove events older than failDuration
	isLocked := p.ipProtector[ip].locked
	return isLocked && p.ipProtector[ip].lockTime.Add(p.lockDuration).After(time.Now())
}

func (p *LoginIPProtector) squeezeTracker(ip string) {
	// Remove events older than failDuration
	failStartTime := time.Now().Add(p.failDuration)

	for p.ipProtector[ip].queue.Len() > 0 {
		first := p.ipProtector[ip].queue.Front().Value.(time.Time)
		if first.Before(failStartTime) {
			p.ipProtector[ip].queue.Remove(p.ipProtector[ip].queue.Front())
		} else {
			break
		}
	}
}
