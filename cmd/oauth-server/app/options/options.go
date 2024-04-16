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

package options

import (
	"github.com/spf13/viper"
	"oauth-server/cmd/oauth-server/app/configs"
	"oauth-server/pkg/fuyaoerrors"
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
func (o *OAuthServerOption) ReadConfig() (*configs.OAuthServerAPIServerConfig, error) {
	v := viper.New()
	v.SetConfigFile(o.ConfigFile)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var oAuthServerConfig configs.OAuthServerAPIServerConfig
	if err := v.Unmarshal(&oAuthServerConfig); err != nil {
		return nil, err
	}

	return &oAuthServerConfig, nil

}
