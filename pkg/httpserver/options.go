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

// Package httpserver defines the httpserver options, middlewares and responses
package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"k8s.io/apimachinery/pkg/apis/meta/v1"

	"openfuyao/oauth-server/pkg/config"
	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaoerrors"
	"openfuyao/oauth-server/pkg/zlog"
)

// ServerOptions defines the config for httpserver
type ServerOptions struct {
	HttpPort  int `json:"HttpPort"`
	HttpsPort int `json:"HttpsPort"`
}

// NewDefaultHttpServerOptions inits the default httpserver option
func NewDefaultHttpServerOptions() *ServerOptions {
	return &ServerOptions{
		HttpPort:  9095,
		HttpsPort: 0,
	}
}

// Validate assures the httpserver option is valid
func (s *ServerOptions) Validate() []error {
	var errs []error
	if s.HttpsPort == constants.MinHttpPort && s.HttpPort == constants.MinHttpPort {
		errs = append(errs, fuyaoerrors.ErrInvalidHttpAndHttpsPort)
	}

	return errs
}

// NewHttpServer inits the httpserver with the httpserveroption
func NewHttpServer(options *ServerOptions) (*http.Server, error) {
	server := &http.Server{Addr: fmt.Sprintf(":%d", options.HttpPort)}

	if options.HttpsPort != 0 {
		tlsStuff, err := loadX509KeyPairAndCA(constants.TlsSecretName, constants.TlsSecretNamespace)
		if err != nil {
			zlog.LogErrorf(fuyaoerrors.ErrStrFailToLoadCert)
			return nil, fuyaoerrors.ErrFailToLoadCert
		}

		certificate, err := tls.X509KeyPair(tlsStuff.crt, tlsStuff.key)
		if err != nil {
			zlog.LogErrorf(fuyaoerrors.ErrStrFailToLoadCert)
			return nil, fuyaoerrors.ErrFailToLoadCert
		}

		// create the cert pool
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(tlsStuff.ca)

		// configure the tls
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
			ClientCAs:    caCertPool,
		}
		server.Addr = fmt.Sprintf(":%d", options.HttpsPort)
	}

	return server, nil
}

type tlsStruct struct {
	crt []byte
	key []byte
	ca  []byte
}

func loadX509KeyPairAndCA(secretName, namespace string) (tlsStruct, error) {
	k8sClient := config.GetKubernetesClient(nil)
	secret, err := k8sClient.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, v1.GetOptions{})
	if err != nil {
		return tlsStruct{}, fuyaoerrors.ErrFailToLoadCert
	}

	cert, ok1 := secret.Data["tls.crt"]
	key, ok2 := secret.Data["tls.key"]
	ca, ok3 := secret.Data["ca.crt"]

	if !ok1 || !ok2 || !ok3 {
		return tlsStruct{}, fuyaoerrors.ErrFailToLoadCert
	}

	return tlsStruct{crt: cert, key: key, ca: ca}, nil
}
