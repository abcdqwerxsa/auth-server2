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
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"oauth-server/pkg/constants"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/zlog"
)

// ServerOptions defines the configs for httpserver
type ServerOptions struct {
	HttpPort          int    `json:"HttpPort"`
	HttpsPort         int    `json:"HttpsPort"`
	TlsCertFile       string `json:"TlsCertFile"`
	TlsPrivateKeyFile string `json:"TlsPrivateKeyFile"`
	MasterCAFile      string `json:"MasterCAFile"`
}

// NewDefaultHttpServerOptions inits the default httpserver option
func NewDefaultHttpServerOptions() *ServerOptions {
	return &ServerOptions{
		HttpPort:          9095,
		HttpsPort:         0,
		TlsCertFile:       "",
		TlsPrivateKeyFile: "",
		MasterCAFile:      "",
	}
}

// Validate assures the httpserver option is valid
func (s *ServerOptions) Validate() []error {
	var errs []error
	if s.HttpsPort == constants.MinHttpPort && s.HttpPort == constants.MinHttpPort {
		errs = append(errs, fuyaoerrors.ErrInvalidHttpAndHttpsPort)
	}

	if s.HttpsPort > constants.MinHttpPort && s.HttpsPort < constants.MaxHttpPort {
		if s.TlsCertFile == "" {
			errs = append(errs, fuyaoerrors.ErrEmptyCertFile)
		} else {
			if _, err := os.Stat(s.TlsCertFile); err != nil {
				errs = append(errs, err)
			}
		}

		if s.TlsPrivateKeyFile == "" {
			errs = append(errs, fuyaoerrors.ErrEmptyPrivateKeyFile)
		} else {
			if _, err := os.Stat(s.TlsPrivateKeyFile); err != nil {
				errs = append(errs, err)
			}
		}

		if s.MasterCAFile != "" {
			errs = append(errs, fuyaoerrors.ErrEmptyMasterCAFile)
		} else {
			if _, err := os.Stat(s.MasterCAFile); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errs
}

// NewHttpServer inits the httpserver with the httpserveroption
func NewHttpServer(options *ServerOptions) (*http.Server, error) {
	server := &http.Server{Addr: fmt.Sprintf(":%d", options.HttpPort)}

	if options.HttpsPort != 0 {
		certificate, err := tls.LoadX509KeyPair(options.TlsCertFile, options.TlsPrivateKeyFile)
		if err != nil {
			zlog.Errorf("%s, err: %v", fuyaoerrors.ErrStrFailToLoadCert, err)
			return nil, fuyaoerrors.ErrFailToLoadCert
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
		}
		server.Addr = fmt.Sprintf(":%d", options.HttpsPort)

		// TODO: set root CA
	}

	return server, nil
}
