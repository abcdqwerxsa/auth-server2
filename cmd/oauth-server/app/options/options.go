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

// Package options store the configfile and will possibly extend other datastructures (genericapiserver) in the future
package options

import (
	"encoding/base64"
	"github.com/spf13/viper"
	"openfuyao/oauth-server/pkg/zlog"
	"os"

	"openfuyao/oauth-server/cmd/oauth-server/app/config"
	"openfuyao/oauth-server/pkg/fuyaoerrors"
)

// OAuthServerOption stores the overall configfile and its loading method for the whole oauthserver service
type OAuthServerOption struct {
	ConfigFile string `json:"ConfigFile"`
}

// NewOAuthServerOption inits the option
func NewOAuthServerOption() *OAuthServerOption {
	return &OAuthServerOption{}
}

// Validate validates the options is legal to use
func (o *OAuthServerOption) Validate() error {
	if len(o.ConfigFile) == 0 {
		return fuyaoerrors.ErrOAuthServerConfigFileMissing
	}

	return nil
}

// ReadConfig loads the configfile from disk
func (o *OAuthServerOption) ReadConfig() (*config.OAuthServerAPIServerConfig, error) {
	v := viper.New()
	v.SetConfigFile(o.ConfigFile)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var oAuthServerConfig config.OAuthServerAPIServerConfig
	if err := v.Unmarshal(&oAuthServerConfig); err != nil {
		return nil, err
	}

	// manually add secret keys
	jwtPrivateKeyDecoded, err := readFromSecret("/oauth-jwt.key")
	if err != nil {
		return nil, err
	}
	oAuthServerConfig.OAuthServerConfig.JWTPrivateKey = jwtPrivateKeyDecoded

	signKeyDecoded, err := readFromSecret("/oauth-cookie-sign.key")
	if err != nil {
		return nil, err
	}
	oAuthServerConfig.IDPLoginStoreConfig.SigningKey = signKeyDecoded

	encryptKeyDecoded, err := readFromSecret("/oauth-cookie-encrypt.key")
	if err != nil {
		return nil, err
	}
	oAuthServerConfig.IDPLoginStoreConfig.EncryptionKey = encryptKeyDecoded

	return &oAuthServerConfig, nil

}

func readFromSecret(filePath string) (string, error) {
	b64Key, err := os.ReadFile(filePath)
	if err != nil {
		zlog.LogErrorf("read secret failed")
		return "", err
	}

	keyDecoded, err := base64.StdEncoding.DecodeString(string(b64Key))
	if err != nil {
		zlog.LogWarnf("Error decoding base64: %v, use it directly", err)
		return string(b64Key), err
	} else {
		return string(keyDecoded), err
	}
}
