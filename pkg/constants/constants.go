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

// Package constants define different genres of constants
package constants

// Constants for parameters
const (
	ThenParam     = "then"
	CSRFParam     = "csrf_token"
	UsernameParam = "username"
	PasswordParam = "password"
	ErrorParam    = "error"

	NewPasswordParam      = "new_password"
	OriginalPasswordParam = "original_password"
)

// FuyaoIdpProvider Constants for identity provider
const (
	FuyaoIdpProvider = "fuyaoPasswordProvider"
)

// Constants for cookie-names
// 这里openshift加了一个expire time
const (
	UserName     = "user.name"
	UserUID      = "user.uid"
	UserGroups   = "user.groups"
	UserExtra    = "user.extra"
	CookieExpiry = "cookie.expiry"
)

// Constants for code, access, refresh token prefixes
const (
	CodePrefix    = "code-"
	AccessPrefix  = "access-"
	RefreshPrefix = "refresh-"
)

// Constants for access token extension fields
const (
	TokenUserID = "user_id"
)

// Constants for url redirect templates
const (
	LoginRedirectTemplate           = "/auth/login/%s"
	PasswordConfirmRedirectTemplate = "/auth/password/confirm/%s"
)

// Constants for url form templates
const (
	LoginFormTemplate           = "loginForm"
	PasswordConfirmFormTemplate = "passwordConfirmForm"
)

// Constants for password complexity check
const (
	PasswordMinLen = 8
	PasswordMaxLen = 32
)

// Constants for http port range
const (
	MinHttpPort = 0
	MaxHttpPort = 65536
)

// LoginStatus stands for when status when checking the auth session
type LoginStatus int

// Constants for the LoginStatuses
const (
	FirstLogin LoginStatus = iota
	LoggedIn
	LoginFailed
)

// Constants for decimal value
const (
	Decimal = 10
)
