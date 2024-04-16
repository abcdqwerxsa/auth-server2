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

// Package configs defines the overall configurations for OAuthServerAPIServer
package configs

import (
	"oauth-server/pkg/configs"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/httpserver"
	"time"
)

// OAuthServerAPIServerConfig stores the necessary configuration options for OAuth server
type OAuthServerAPIServerConfig struct {
	// configs for http httpserver
	HttpServerConfig *httpserver.ServerOptions `json:"HttpServerConfig"`

	// idpLoginStore configs
	IDPLoginStoreConfig *IDPLoginStoreConfig `json:"IDPLoginStoreConfig"`

	// ipprotector configs
	IPProtectorConfig *IPProtectorConfig `json:"IPProtectorConfig"`

	// k8s configs
	K8sConfig *configs.KubernetesConfig `json:"K8SConfig"`

	// login configs
	LoginConfig *LoginConfig `json:"LoginConfig"`

	// OAuthAPIServerConfig for the inner oauth server options
	OAuthServerConfig *OAuthServerConfig `json:"OAuthServerConfig"`
}

// NewDefaultOAuthAPIServerServerConfig inits the config
func NewDefaultOAuthAPIServerServerConfig() *OAuthServerAPIServerConfig {
	return &OAuthServerAPIServerConfig{
		HttpServerConfig:    httpserver.NewDefaultHttpServerOptions(),
		K8sConfig:           configs.NewKubernetesConfig(),
		LoginConfig:         newDefaultLoginConfig(),
		IPProtectorConfig:   newDefaultIPProtectorConfig(),
		IDPLoginStoreConfig: newIDPLoginStoreConfig(),
		OAuthServerConfig:   newOAuthServerConfig(),
	}
}

// Validate validates the config
func (c *OAuthServerAPIServerConfig) Validate() []error {
	var errs []error
	if c.HttpServerConfig == nil {
		errs = append(errs, fuyaoerrors.ErrHttpServerConfigMissing)
	}
	// TODO: Validate 这里不应该这么简单地校验，可能需要每个config进行单独的校验
	return errs
}

// Complete ensures the completeness of the config
func (c *OAuthServerAPIServerConfig) Complete() *OAuthServerAPIServerConfig {
	defaultConfig := NewDefaultOAuthAPIServerServerConfig()

	if c.HttpServerConfig == nil {
		c.HttpServerConfig = defaultConfig.HttpServerConfig
	}
	if c.K8sConfig == nil {
		c.K8sConfig = defaultConfig.K8sConfig
	}
	if c.LoginConfig == nil {
		c.LoginConfig = defaultConfig.LoginConfig
	}
	if c.IPProtectorConfig == nil {
		c.IPProtectorConfig = defaultConfig.IPProtectorConfig
	}
	if c.IDPLoginStoreConfig == nil {
		c.IDPLoginStoreConfig = defaultConfig.IDPLoginStoreConfig
	}
	if c.OAuthServerConfig == nil {
		c.OAuthServerConfig = defaultConfig.OAuthServerConfig
	}

	return c
}

// TODO: 每个config是否要有自己的 Complete 和 Validate 呢

// LoginConfig defines all configs used by fuyao login provider
type LoginConfig struct {
	Provider      string `json:"Provider"`
	UserNamespace string `json:"UserNamespace"`
}

func newDefaultLoginConfig() *LoginConfig {
	return &LoginConfig{
		Provider:      "fuyaoPaswordProvider",
		UserNamespace: "oauth-user",
	}
}

// IPProtectorConfig defines all configs used by ipprotector
type IPProtectorConfig struct {
	FailTimes    int           `json:"FailTimes"`
	FailDuration time.Duration `json:"FailDuration"`
	LockDuration time.Duration `json:"LockDuration"`
}

func newDefaultIPProtectorConfig() *IPProtectorConfig {
	const (
		failDurationMins = 5
		lockDurationMins = 30
	)
	return &IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * failDurationMins,
		LockDuration: time.Minute * lockDurationMins,
	}
}

// IDPLoginStoreConfig configures the store that temporally saves the user info
type IDPLoginStoreConfig struct {
	SessionName   string `json:"SessionName"`
	SessionMaxAge int    `json:"SessionMaxAge"`
	SigningKey    string `json:"SigningKey"`
	EncryptionKey string `json:"EncryptionKey"`
}

func newIDPLoginStoreConfig() *IDPLoginStoreConfig {
	return &IDPLoginStoreConfig{
		SessionName:   "idpLogin",
		SessionMaxAge: 300,
		SigningKey:    "auth",
		EncryptionKey: "encrypt123123123",
	}
}

// OAuthServerConfig configures the inner oauth2 server
type OAuthServerConfig struct {
	CodeTokenNamespace string            `json:"CodeTokenNamespace"`
	AuthCodeExp        time.Duration     `json:"AuthCodeExp"`
	AccessTokenExp     time.Duration     `json:"AccessTokenExp"`
	RefreshTokenExp    time.Duration     `json:"RefreshTokenExp"`
	IsGenerateRefresh  bool              `json:"IsGenerateRefresh"`
	JWTKeyID           string            `json:"JWTKeyID"`
	JWTPrivateKey      string            `json:"JWTPrivateKey"`
	ClientMapper       map[string]string `json:"ClientMapper"`
}

func newOAuthServerConfig() *OAuthServerConfig {
	const (
		authCodeExpMins      = 5
		accessTokenExpHours  = 2
		refreshTokenExpHours = 2
	)
	return &OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Minute * authCodeExpMins,
		AccessTokenExp:     time.Hour * accessTokenExpHours,
		RefreshTokenExp:    time.Hour * refreshTokenExpHours,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console": "console-password",
		},
	}
}
